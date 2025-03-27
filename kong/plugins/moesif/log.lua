local cjson = require "cjson"

local _M = {}

local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local ngx_timer_at = ngx.timer.at
local ngx_timer_every = ngx.timer.every
local config_hashes = {}
local has_events = false
local regex_config_helper = require "kong.plugins.moesif.regex_config_helpers"
local connect = require "kong.plugins.moesif.connection"
local socket = require "socket"
local gc = 0
local health_check = 0
local rec_event = 0
local sent_event = 0
local sent_success = 0
local sent_failure = 0
local merge_config = 0
local timer_wakeup_seconds = 1.5
local gr_helpers = require "kong.plugins.moesif.governance_helpers"
entity_rules_hashes = {}
local http = require "resty.http"
local zlib = require 'zlib'

-- Function to log the total memory in use by Lua, measured in kilobytes.
-- This includes all memory allocated for Lua objects, such as tables, strings, and functions.
local function get_memory_usage(stage)
  local total_memory = collectgarbage("count")
  ngx_log(ngx.DEBUG, "[moesif] Memory Usage, " .. stage .. " is - " .. total_memory .. " Kb")
  return total_memory
end

-- Function to send http request
local function send_request(conf, body, isCompressed)

  if conf.debug then
    ngx_log(ngx.DEBUG, "[moesif] Body Length - ".. tostring(#body) .. " when isCompressed is - " .. tostring(isCompressed) .." for pid - ".. ngx.worker.pid())
  end

  -- Create http client
  local httpc = connect.get_client(conf)

  local start_req_time = socket.gettime()*1000
  -- Perform the POST request
  local res, err = connect.post_request(httpc, conf, "/v1/events/batch", body, isCompressed)
  local end_req_time = socket.gettime()*1000
  if conf.debug then
    ngx_log(ngx.DEBUG, "[moesif] Send HTTP request took time - ".. tostring(end_req_time - start_req_time).." for pid - ".. ngx.worker.pid())
  end

  if not res then
      ngx_log(ngx_log_ERR, "[moesif] failed to send request: ", err)
  end
  return res, err
end

-- Function to compress payload using zlib deflate
local function compress_data(input_string)
  local compressor = zlib.deflate()
  local compressed_data, eof, bytes_in, bytes_out = compressor(input_string, "finish")
  return compressed_data
end

-- Function to prepare request and send to moesif
local function prepare_request(conf, batch_events, debug)

  -- Encode batch_events
  local start_encode_time = socket.gettime()*1000
  local body = cjson.encode(batch_events)
  local end_encode_time = socket.gettime()*1000
  if debug then 
    ngx_log(ngx.DEBUG, "[moesif] Json Encode took time - ".. tostring(end_encode_time - start_encode_time).." for pid - ".. ngx.worker.pid())
  end

  local payload = nil
  local isCompressed = conf.enable_compression

  if conf.enable_compression then 
    local start_compress_time = socket.gettime()*1000
    local ok, compressed_body = pcall(compress_data, body)
    local end_compress_time = socket.gettime()*1000
    if debug then 
      ngx_log(ngx.DEBUG, "[moesif] zlib deflate compression took time - ".. tostring(end_compress_time - start_compress_time).." for pid - ".. ngx.worker.pid())
    end 

    if not ok then
      if debug then 
        ngx_log(ngx_log_ERR, "[moesif] failed to compress body: ", compressed_body)
      end
      payload = body
      isCompressed = false -- if failed to compress, send uncompressed data
    else 
      if debug then 
        ngx_log(ngx.DEBUG, " [moesif] successfully compressed body")
      end
      payload = compressed_body
    end
  else 
    payload = body
  end

  return send_request(conf, payload, isCompressed)
end

-- Send Payload
-- @param `batch_events`  Events Batch
-- @param `conf`  Configuration table, holds http endpoint details
local function send_payload(batch_events, conf)
  local debug = conf.debug
  local eventsSentSuccessfully = false

  local start_send_time = socket.gettime()*1000

  local start_post_req_time = socket.gettime()*1000
  -- Send post request
  local resp, err = prepare_request(conf, batch_events, debug)
  local end_post_req_time = socket.gettime()*1000
  if conf.debug then
    ngx_log(ngx.DEBUG, "[moesif] send request took time - ".. tostring(end_post_req_time - start_post_req_time).." for pid - ".. ngx.worker.pid())
  end

  if not (resp) or (resp.status ~= 201) then
    sent_failure = sent_failure + #batch_events
    eventsSentSuccessfully = false
    local msg = "unavailable"
    if resp then 
      msg = tostring(resp.status)
    end
    ngx_log(ngx.DEBUG, "[moesif] failed to send " .. tostring(#batch_events) .. " events with response status - " .. msg .. " in this batch for pid - " .. ngx.worker.pid())
  else
    eventsSentSuccessfully = true
    sent_success = sent_success + #batch_events
    ngx_log(ngx.DEBUG, "[moesif] Events sent successfully. Total number of events send - " ..  tostring(#batch_events) .. " in this batch for pid - ".. ngx.worker.pid())
  end
  
  if conf.debug then
    local end_send_time = socket.gettime()*1000
    ngx_log(ngx.DEBUG, "[moesif] send payload function took time - ".. tostring(end_send_time - start_send_time).." for pid - ".. ngx.worker.pid())
  end
  if eventsSentSuccessfully ~= true then
    error("failed to send events successfully")
  end
end


-- Get App Config function
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
function get_config_internal(conf)

  -- Create http client
  local httpc = connect.get_client(conf)

  -- Send the request to fetch config
  local config_response, config_response_error = connect.get_request(httpc, conf, "/v1/config")

  if config_response_error == nil then 
    -- Update the application configuration
    if config_response ~= nil then

      -- Read the response body
      local raw_config_response = config_response.body

      if raw_config_response ~= nil then
        local response_body = cjson.decode(raw_config_response)

        -- Fetch the config etag from header
        local config_tag =  config_response.headers["x-moesif-config-etag"]
        if config_tag ~= nil then
          conf["ETag"] = config_tag
        end

        -- Check if the governance rule is updated
        local response_rules_etag = config_response.headers["x-moesif-rules-tag"]
          if response_rules_etag ~= nil then
          conf["rulesETag"] = response_rules_etag
        end

        -- Hash key of the config application Id
        local hash_key = string.sub(conf.application_id, -10)

        local entity_rules = {}
        -- Create empty table for user/company rules
        entity_rules[hash_key] = {}

        -- Get governance rules
        if (governance_rules_etags[hash_key] == nil or (conf["rulesETag"] ~= governance_rules_etags[hash_key])) then
          gr_helpers.get_governance_rules(hash_key, conf)
        end

        if (response_body["user_rules"] ~= nil) then
          entity_rules[hash_key]["user_rules"] = response_body["user_rules"]
        end

        if (response_body["company_rules"] ~= nil) then
            entity_rules[hash_key]["company_rules"] = response_body["company_rules"]
        end

        -- generate entity merge tag values mapping
        entity_rules_hashes[hash_key] = generate_entity_rule_values_mapping(hash_key, entity_rules)

        if (conf["sample_rate"] ~= nil) and (response_body ~= nil) then
          if (response_body["user_sample_rate"] ~= nil) then
            conf["user_sample_rate"] = response_body["user_sample_rate"]
          end

          if (response_body["company_sample_rate"] ~= nil) then
            conf["company_sample_rate"] = response_body["company_sample_rate"]
          end

          if (response_body["regex_config"] ~= nil) then
            conf["regex_config"] = response_body["regex_config"]
          end

          if (response_body["sample_rate"] ~= nil) then
            conf["sample_rate"] = response_body["sample_rate"]
          end
        end
        ngx_log(ngx.DEBUG, "[moesif] received app config response successfully ")
      else
        if conf.debug then
          ngx_log(ngx.DEBUG, "[moesif] raw config response is nil so could not decode it, the config response is - " .. tostring(config_response))
        end
      end
    else
      ngx_log(ngx.DEBUG, "[moesif] application config is nil ")
    end
  else
    ngx_log(ngx.DEBUG,"[moesif] error while reading response after fetching app config - ", config_response_error)
  end
  return config_response

end

-- Get App Config function
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
function get_config(premature, hash_key)
  if premature then
    return
  end

  -- Fetch the config
  local conf = config_hashes[hash_key]

  local ok, err = pcall(get_config_internal, conf)
  if not ok then
    if conf.debug then
      ngx_log(ngx_log_ERR, "[moesif] failed to get config internal ", err)
    end
  else
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] get config internal success " , ok)
    end
  end

  local sok, serr = ngx_timer_at(60, get_config, hash_key)
  if not sok then
    if conf.debug then
      ngx_log(ngx.ERR, "[moesif] Error when scheduling the get config : ", serr)
    end
  else
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] success when scheduling the get config ")
    end
  end
end

-- Send Events in batch
-- @param `premature`
local function send_events_batch(premature)
  local prv_events = sent_event
  local start_time = socket.gettime()*1000
  if premature then
    return
  end

  -- Compute memory before the batch is processed
  -- get_memory_usage("Before Processing batch")

  -- Temp hash key for debug
  local temp_hash_key
  local batch_events = {}
  repeat
    for key, queue in pairs(queue_hashes) do
      local configuration = config_hashes[key]
      if not configuration then
        ngx_log(ngx.DEBUG, "[moesif] Skipping sending events to Moesif, since no configuration is available yet")
        return
      end
      -- Temp hash key
      temp_hash_key = key
      if #queue > 0 and ((socket.gettime()*1000 - start_time) <= math.min(configuration.max_callback_time_spent, timer_wakeup_seconds * 500)) then
        if configuration.debug then
          ngx_log(ngx.DEBUG, "[moesif] Sending events to Moesif")
        end
        -- Getting the configuration for this particular key
        
        local counter = 0
        repeat
          local event = table.remove(queue)
          counter = counter + 1
          table.insert(batch_events, event)

          -- TODO: Figure out how to make it into a single function

          if (#batch_events == configuration.batch_size) then
            local start_pay_time = socket.gettime()*1000
              if pcall(send_payload, batch_events, configuration) then
              sent_event = sent_event + #batch_events
              else
              if configuration.debug then
                ngx_log(ngx.DEBUG, "[moesif] send payload pcall failed while sending events when events in batch is equal to config batch size, " .. " for pid - ".. ngx.worker.pid())
              end
              -- insert events back to actual queue and return, we ll send events again in next cycle
              repeat
                local event = table.remove(batch_events)
                table.insert(queue, event)
              until next(batch_events) == nil
              return
              end
              local end_pay_time = socket.gettime()*1000
              if configuration.debug then
              ngx_log(ngx.DEBUG, "[moesif] send payload with event count - " .. tostring(#batch_events) .. " took time - ".. tostring(end_pay_time - start_pay_time).." for pid - ".. ngx.worker.pid())
              end
              batch_events = {}
          else if(#queue ==0 and #batch_events > 0) then
              local start_pay1_time = socket.gettime()*1000
              if pcall(send_payload, batch_events, configuration) then
                sent_event = sent_event + #batch_events
              else
                if configuration.debug then
                  ngx_log(ngx.DEBUG, "[moesif] send payload pcall failed while sending events when events in batch is greather than 0, " .. " for pid - ".. ngx.worker.pid())
                end
                -- insert events back to actual queue and return, we ll send events again in next cycle
                repeat
                  local event = table.remove(batch_events)
                  table.insert(queue, event)
                until next(batch_events) == nil
                return
              end
              local end_pay1_time = socket.gettime()*1000
              if configuration.debug then
                ngx_log(ngx.DEBUG, "[moesif] send payload with event count - " .. tostring(#batch_events) .. " took time - ".. tostring(end_pay1_time - start_pay1_time).." for pid - ".. ngx.worker.pid())
              end
              batch_events = {}
            end
          end
        until counter == configuration.batch_size or next(queue) == nil

        if #queue > 0 then
          has_events = true
        else
          has_events = false
        end
        
        if configuration.debug then
          ngx.log(ngx.DEBUG, "[moesif] Received Event - "..tostring(rec_event).." and Sent Event - "..tostring(sent_event).." for pid - ".. ngx.worker.pid())
        end
      else
        has_events = false
        if #queue <= 0 then
          if configuration.debug then
            ngx_log(ngx.DEBUG, "[moesif] Queue is empty, no events to send " .. " for pid - ".. ngx.worker.pid())
          end
        else
          if configuration.debug then
            ngx_log(ngx.DEBUG, "[moesif] Max callback time exceeds, skip sending events now ")
          end
        end
      end
    end
  until has_events == false

  if not has_events then
    ngx_log(ngx.DEBUG, "[moesif] No events to read from the queue")
  end

  -- Manually garbage collect every 8th cycle
  gc = gc + 1
  if gc == 8 then
    ngx_log(ngx.INFO, "[moesif] Calling GC at - "..tostring(socket.gettime()*1000).." in pid - ".. ngx.worker.pid())
    collectgarbage()
    gc = 0
  end

  -- Periodic health check
  health_check = health_check + 1
  if health_check == 150 then
    if rec_event ~= 0 then
      local event_perc = sent_event / rec_event
      ngx_log(ngx.INFO, "[moesif] heartbeat - "..tostring(rec_event).."/"..tostring(sent_event).."/"..tostring(sent_success).."/"..tostring(sent_failure).."/"..tostring(event_perc).." in pid - ".. ngx.worker.pid())
    end
    health_check = 0
  end

  local endtime = socket.gettime()*1000

  -- Event queue size
  local length = 0
  if queue_hashes[temp_hash_key] ~= nil then
    length = #queue_hashes[temp_hash_key]
  end
  local sent_event_delta = (sent_event - prv_events)
  if sent_event_delta > 0 then 
    ngx_log(ngx.DEBUG, "[moesif] send events batch took time - ".. tostring(endtime - start_time) .. " and sent event delta - " .. tostring(sent_event_delta) .. " with queue size - " .. tostring(length) .." for pid - ".. ngx.worker.pid())
  end

  -- Compute memory after the batch is processed
  -- get_memory_usage("After processing batch")
end

-- Log to a Http end point.
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
-- @param `hash_key` Hash key of the config application Id
local function log(conf, message, hash_key)
  -- Sampling Events
  local random_percentage = math.random() * 100
  local user_sampling_rate = nil
  local company_sampling_rate = nil
  local regex_sampling_rate = nil
  local sampling_rate = 100

  if conf.sample_rate == nil then
    conf.sample_rate = 100
  end

  -- calculate user level sample rate
  if type(conf.user_sample_rate) == "table" and next(conf.user_sample_rate) ~= nil and message["user_id"] ~= nil and conf.user_sample_rate[message["user_id"]] ~= nil then
    user_sampling_rate = conf.user_sample_rate[message["user_id"]]
  end

  -- calculate company level sample rate
  if type(conf.company_sample_rate) == "table" and next(conf.company_sample_rate) ~= nil and message["company_id"] ~= nil and conf.company_sample_rate[message["company_id"]] ~= nil then
    company_sampling_rate = conf.company_sample_rate[message["company_id"]]
  end

  -- calculate regex sample rate
  if type(conf.regex_config) == "table" and next(conf.regex_config) ~= nil then
    local config_mapping = regex_config_helper.prepare_config_mapping(message, hash_key)
    local ok, sample_rate, _ = pcall(regex_config_helper.fetch_sample_rate_block_request_on_regex_match, conf.regex_config, config_mapping)
    if ok then
      regex_sampling_rate = sample_rate
    end
  end

  -- sampling rate will be the minimum of all specific sample rates if any of them are defined
  if user_sampling_rate ~= nil or company_sampling_rate  ~= nil or regex_sampling_rate  ~= nil then
    sampling_rate = math.min((user_sampling_rate or 100), (company_sampling_rate or 100), (regex_sampling_rate or 100))
  else
    -- no specific sample rates defined, use the global sampling rate
    sampling_rate = conf.sample_rate
  end

  if sampling_rate > random_percentage then
    message["weight"] = (sampling_rate == 0 and 1 or math.floor(100 / sampling_rate))
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] Event added to the queue" .. " for pid - ".. ngx.worker.pid())
    end
    rec_event = rec_event + 1
    table.insert(queue_hashes[hash_key], message)
  else
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] Skipped Event", " due to sampling percentage: " .. tostring(sampling_rate) .. " and random number: " .. tostring(random_percentage) .. "user:company:regex sampling rate are: " .. tostring(user_sampling_rate) .. ":"
      .. tostring(company_sampling_rate) .. ":" .. tostring(regex_sampling_rate))
    end
  end
end

function _M.execute(conf, message)
  -- Hash key of the config application Id
  local hash_key = string.sub(conf.application_id, -10)

  if config_hashes[hash_key] == nil then
    local app_configs = {}
    app_configs["sample_rate"] = 100
    app_configs["user_sample_rate"] = {}
    app_configs["company_sample_rate"] = {}
    app_configs["regex_config"] = {}
    app_configs["ETag"] = nil
    app_configs["user_rules"] = {}
    app_configs["company_rules"] = {}
    config_hashes[hash_key] = app_configs
    queue_hashes[hash_key] = {}
    local ok, err = ngx_timer_at(0, get_config, hash_key)
    if not ok then
      if conf.debug then
        ngx_log(ngx_log_ERR, "[moesif] failed to get application config, setting the sample_rate to default ", err)
      end
    else
      if conf.debug then
        ngx_log(ngx.DEBUG, "[moesif] successfully fetched the application configuration " , ok)
      end
    end
    for k,v in pairs(conf) do
      config_hashes[hash_key][k] = v
    end
  end

  -- Merge user-defined and moesif configs as user-defined config could be change at any time
  merge_config = merge_config + 1
  if merge_config == 100 then
    for k,v in pairs(conf) do
      config_hashes[hash_key][k] = v
    end
    merge_config = 0
  end
  -- Log event to moesif
  log(config_hashes[hash_key], message, hash_key)
end

-- Schedule Events batch job
function _M.start_background_thread()

  ngx.log(ngx.DEBUG, "[moesif] Scheduling Events batch job every ".. tostring(timer_wakeup_seconds).." seconds")

  local ok, err = ngx_timer_every(timer_wakeup_seconds, send_events_batch)
  if not ok then
      ngx.log(ngx.ERR, "[moesif] Error when scheduling the job: "..err)
  end
end

return _M
