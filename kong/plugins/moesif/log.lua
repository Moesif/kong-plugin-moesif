local cjson = require "cjson"

local _M = {}

local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local ngx_timer_at = ngx.timer.at
local string_format = string.format
local ngx_timer_every = ngx.timer.every
local config_hashes = {}
local has_events = false
local compress = require "kong.plugins.moesif.lib_deflate"
local helper = require "kong.plugins.moesif.helpers"
local connect = require "kong.plugins.moesif.connection"
local regex_config_helper = require "kong.plugins.moesif.regex_config_helpers"
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
entity_rules = {}

-- Generates http payload .
-- @param `method` http method to be used to send data
-- @param `parsed_url` contains the host details
-- @param `message`  Message to be logged
-- @return `payload` http payload
local function generate_post_payload(parsed_url, access_token, message, application_id, debug)
  local payload = nil
  local body = cjson.encode(message)
  local ok, compressed_body = pcall(compress["CompressDeflate"], compress, body)
  if not ok then
    if debug then 
      ngx_log(ngx_log_ERR, "[moesif] failed to compress body: ", compressed_body)
    end
    payload = string_format(
      "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\nUser-Agent: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
      "POST", parsed_url.path, parsed_url.host, application_id, "kong-plugin-moesif/"..plugin_version, #body, body)
    return payload
  else
    if debug then 
      ngx_log(ngx.DEBUG, " [moesif]  ", "successfully compressed body")
    end
    payload = string_format(
      "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\nUser-Agent: %s\r\nContent-Encoding: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
      "POST", parsed_url.path, parsed_url.host, application_id, "kong-plugin-moesif/"..plugin_version, "deflate", #compressed_body, compressed_body)
    return payload
  end
end

-- Send Payload
-- @param `sock`  Socket object
-- @param `parsed_url`  Parsed Url
-- @param `batch_events`  Events Batch
local function send_payload(sock, parsed_url, batch_events, conf)
  local application_id = conf.application_id
  local access_token = conf.access_token
  local debug = conf.debug
  local eventsSentSuccessfully = false

  local start_send_time = socket.gettime()*1000
  sock:settimeout(conf.send_timeout)
  local ok, err = sock:send(generate_post_payload(parsed_url, access_token, batch_events, application_id, debug) .. "\r\n")
  if not ok then
    sent_failure = sent_failure + #batch_events
    ngx_log(ngx.DEBUG, "[moesif] failed to send " .. tostring(#batch_events) .." events to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
  else
    eventsSentSuccessfully = true
    sent_success = sent_success + #batch_events
    ngx_log(ngx.DEBUG, "[moesif] Events sent successfully. Total number of events send - " ..  tostring(#batch_events) .. " in this batch for pid - ".. ngx.worker.pid() .. " ", ok)
  end

  if conf.enable_reading_send_event_response then
    ngx_log(ngx.DEBUG, "[moesif] As reading send event response is enabled, we are reading the response " .. " for pid - ".. ngx.worker.pid())
    local send_event_response, send_event_response_error = helper.read_socket_data(sock, conf)
    if conf.debug then
      if send_event_response_error == nil then
        if send_event_response ~= nil then
          if string.match(send_event_response, "200") or string.match(send_event_response, "201") then
            eventsSentSuccessfully = true
          else
            eventsSentSuccessfully = false
          end
          ngx_log(ngx.DEBUG,"[moesif] send event response after sending " .. tostring(#batch_events) ..  " event - ", send_event_response)
        else
          eventsSentSuccessfully = false
          ngx_log(ngx.DEBUG,"[moesif] send event response is nil ")
        end
      else
        eventsSentSuccessfully = false
        ngx_log(ngx.DEBUG,"[moesif] error while reading response after sending " .. tostring(#batch_events) ..  " event - ", send_event_response_error)
      end
    end
  end
  local end_send_time = socket.gettime()*1000
  ngx_log(ngx.DEBUG, "[moesif] send payload took time - ".. tostring(end_send_time - start_send_time).." for pid - ".. ngx.worker.pid())
  if eventsSentSuccessfully ~= true then
    error("failed to send events successfully")
  end
end


-- Get App Config function
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
function get_config_internal(conf)

  local config_socket = ngx.socket.tcp()
  config_socket:settimeout(conf.connect_timeout)

  local sock, parsed_url = connect.get_connection("https://api.moesif.net", "/v1/config", conf, config_socket)

  if type(parsed_url) == "table" and next(parsed_url) ~= nil and type(config_socket) == "table" and next(config_socket) ~= nil then

    -- Prepare the payload
    local payload = string_format(
      "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\n",
      "GET", parsed_url.path, parsed_url.host, conf.application_id)

    -- Send the request
    local ok, err = config_socket:send(payload .. "\r\n")
    if not ok then
      if conf.debug then 
        ngx_log(ngx_log_ERR, "[moesif] failed to send data to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
      end
    else
      if conf.debug then
        ngx_log(ngx.DEBUG, "[moesif] Successfully send request to fetch the application configuration " , ok)
      end
    end

    -- Read the response
    local config_response, config_response_error = helper.read_socket_data(config_socket, conf)

    if config_response_error == nil then 
      -- Update the application configuration
      if config_response ~= nil then

        local ok_config, err_config = config_socket:setkeepalive(conf.keepalive)
        if not ok_config then
          if conf.debug then
            ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err_config)
          end
          local close_ok, close_err = config_socket:close()
          if not close_ok then
              if conf.debug then
                  ngx_log(ngx_log_ERR,"[moesif] Failed to manually close socket connection ", close_err)
              end
          else
              if conf.debug then
                  ngx_log(ngx.DEBUG,"[moesif] success closing socket connection manually ")
              end
          end
        else
          if conf.debug then
            ngx_log(ngx.DEBUG,"[moesif] success keep-alive", ok_config)
          end
        end

        local raw_config_response = config_response:match("(%{.*})")
        if raw_config_response ~= nil then
          local response_body = cjson.decode(raw_config_response)
          local config_tag = string.match(config_response, "ETag%s*:%s*(.-)\n")

          if config_tag ~= nil then
            conf["ETag"] = config_tag
          end

          -- Check if the governance rule is updated
          local response_rules_etag = string.match(config_response, "Tag%s*:%s*(.-)\n")
            if response_rules_etag ~= nil then
            conf["rulesETag"] = response_rules_etag
          end

          -- Hash key of the config application Id
          local hash_key = string.sub(conf.application_id, -10)

          -- Create empty table for user/company rules
          if entity_rules[hash_key] == nil then
            entity_rules[hash_key] = {}
          end

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

  local send_events_socket = ngx.socket.tcp()
  local global_socket_timeout = 10000
  send_events_socket:settimeout(global_socket_timeout)
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
        ngx_log(ngx.DEBUG, "[moesif] Sending events to Moesif")
        -- Getting the configuration for this particular key
        local start_con_time = socket.gettime()*1000
        local sock, parsed_url = connect.get_connection(configuration.api_endpoint, "/v1/events/batch", configuration, send_events_socket)
        local end_con_time = socket.gettime()*1000
        if configuration.debug then
          ngx_log(ngx.DEBUG, "[moesif] get connection took time - ".. tostring(end_con_time - start_con_time).." for pid - ".. ngx.worker.pid())
        end
        if type(parsed_url) == "table" and next(parsed_url) ~= nil and type(send_events_socket) == "table" and next(send_events_socket) ~= nil then
          local counter = 0
          repeat
            local event = table.remove(queue)
            counter = counter + 1
            table.insert(batch_events, event)

            if (#batch_events == configuration.batch_size) then
              local start_pay_time = socket.gettime()*1000
               if pcall(send_payload, send_events_socket, parsed_url, batch_events, configuration) then 
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
                if pcall(send_payload, send_events_socket, parsed_url, batch_events, configuration) then
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

          local ok, err = send_events_socket:setkeepalive()
          if not ok then
            if configuration.debug then 
              ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
            end
            local close_ok, close_err = send_events_socket:close()
            if not close_ok then
              if configuration.debug then
                ngx_log(ngx_log_ERR,"[moesif] Failed to manually close socket connection ", close_err)
              end
            else
              if configuration.debug then
                ngx_log(ngx.DEBUG,"[moesif] success closing socket connection manually ")
              end
            end
          else
            ngx_log(ngx.DEBUG,"[moesif] success keep-alive", ok)
          end
        else 
          if configuration.debug then 
            ngx_log(ngx.DEBUG, "[moesif] Failure to create socket connection for sending event to Moesif ")
          end
        end
        if configuration.debug then 
          ngx.log(ngx.DEBUG, "[moesif] Received Event - "..tostring(rec_event).." and Sent Event - "..tostring(sent_event).." for pid - ".. ngx.worker.pid())
        end        
      else
        has_events = false
        if #queue <= 0 then 
          ngx_log(ngx.DEBUG, "[moesif] Queue is empty, no events to send " .. " for pid - ".. ngx.worker.pid())
        else
          ngx_log(ngx.DEBUG, "[moesif] Max callback time exceeds, skip sending events now ")
        end
      end
    end
  until has_events == false

  if not has_events then
    ngx_log(ngx.DEBUG, "[moesif] No events to read from the queue")
  end

  -- Manually garbage collect every alternate cycle
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
  ngx_log(ngx.DEBUG, "[moesif] send events batch took time - ".. tostring(endtime - start_time) .. " and sent event delta - " .. tostring(sent_event - prv_events).." for pid - ".. ngx.worker.pid().. " with queue size - ".. tostring(length))
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
    local config_mapping = regex_config_helper.prepare_config_mapping(message)
    local ok, sample_rate, block_rule = pcall(regex_config_helper.fetch_sample_rate_block_request_on_regex_match, conf.regex_config, config_mapping)
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
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] Event added to the queue" .. " for pid - ".. ngx.worker.pid())
    end
    message["weight"] = (sampling_rate == 0 and 1 or math.floor(100 / sampling_rate))
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
