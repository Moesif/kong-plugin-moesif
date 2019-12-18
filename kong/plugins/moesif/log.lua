local cjson = require "cjson"

local _M = {}

local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local ngx_timer_at = ngx.timer.at
local string_format = string.format
local ngx_timer_every = ngx.timer.every
local configuration = nil
local config_hashes = {}
local queue_hashes = {}
local moesif_events = "moesif_events_"
local has_events = false
local ngx_md5 = ngx.md5
local compress = require "kong.plugins.moesif.lib_deflate"
local helper = require "kong.plugins.moesif.helpers"
local connect = require "kong.plugins.moesif.connection"
local sampling_rate = 100

-- Generates http payload .
-- @param `method` http method to be used to send data
-- @param `parsed_url` contains the host details
-- @param `message`  Message to be logged
-- @return `payload` http payload
local function generate_post_payload(parsed_url, access_token, message, application_id, debug)
  local body = cjson.encode(message)
  if debug then 
    ngx_log(ngx.DEBUG, "[moesif] application_id: ", application_id)
  end
  local ok, compressed_body = pcall(compress["CompressDeflate"], compress, body)
  if not ok then
    if debug then 
      ngx_log(ngx_log_ERR, "[moesif] failed to compress body: ", compressed_body)
    end
  else
    if debug then 
      ngx_log(ngx.DEBUG, " [moesif]  ", "successfully compressed body")
    end
    body = compressed_body
  end

  local payload = string_format(
    "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\nUser-Agent: %s\r\nContent-Encoding: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
    "POST", parsed_url.path, parsed_url.host, application_id, "kong-plugin-moesif/"..plugin_version, "deflate", #body, body)
  return payload
end

-- Send Payload
-- @param `sock`  Socket object
-- @param `parsed_url`  Parsed Url
-- @param `batch_events`  Events Batch
local function send_payload(sock, parsed_url, batch_events)
  local application_id = configuration.application_id
  local access_token = configuration.access_token
  local debug = configuration.debug

  local ok, err = sock:send(generate_post_payload(parsed_url, access_token, batch_events, application_id, debug) .. "\r\n")
  if not ok then
    ngx_log(ngx_log_ERR, "[moesif] failed to send data to " .. host .. ":" .. tostring(port) .. ": ", err)
  else
    ngx_log(ngx.DEBUG, "[moesif] Events sent successfully " , ok)
  end

  -- Read the response
  local send_event_response = helper.read_socket_data(sock)

  -- Check if the application configuration is updated
  local response_etag = string.match(send_event_response, "ETag%s*:%s*(.-)\n")
  if (response_etag ~= nil) and (configuration["ETag"] ~= nil) and (configuration["ETag"] ~= response_etag) and (os.time() > configuration["last_updated_time"] + 300) then
    local resp =  get_config(false, configuration)
    if not resp then
      if debug then 
        ngx_log(ngx_log_ERR, "[moesif] failed to get application config, setting the sample_rate to default ", err)
      end
    else
      if debug then 
        ngx_log(ngx.DEBUG, "[moesif] successfully fetched the application configuration " , ok)
      end
    end
  end
end


-- Get App Config function
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
function get_config(premature, conf)
  if premature then
    return
  end

  local sock, parsed_url = connect.get_connection("/v1/config", conf)

  -- Prepare the payload
  local payload = string_format(
    "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\n",
    "GET", parsed_url.path, parsed_url.host, conf.application_id)

  -- Send the request
  local ok, err = sock:send(payload .. "\r\n")
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
  local config_response = helper.read_socket_data(sock)

  ok, err = sock:setkeepalive(conf.keepalive)
  if not ok then
    if conf.debug then
      ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
    end
    return
   else
    if conf.debug then
      ngx_log(ngx.DEBUG,"[moesif] success keep-alive", ok)
    end
  end

  -- Update the application configuration
  if config_response ~= nil then
    local response_body = cjson.decode(config_response:match("(%{.*})"))
    local config_tag = string.match(config_response, "ETag%s*:%s*(.-)\n")

    if config_tag ~= nil then
     conf["ETag"] = config_tag
    end

    if (conf["sample_rate"] ~= nil) and (response_body ~= nil) then
      if (response_body["user_sample_rate"] ~= nil) then
        conf["user_sample_rate"] = response_body["user_sample_rate"]
      else 
        conf["sample_rate"] = response_body["sample_rate"]
      end
    end

    if conf["last_updated_time"] ~= nil then
     conf["last_updated_time"] = os.time()
    end
  end
  return config_response
end

-- Send Events in batch
-- @param `premature`
local function send_events_batch(premature)
  if premature then
    return
  end

  repeat
    for key, queue in pairs(queue_hashes) do
      if #queue > 0 then
        ngx_log(ngx.DEBUG, "[moesif] Sending events to Moesif")
        -- Getting the configuration for this particular key
        configuration = config_hashes[key]
        local sock, parsed_url = connect.get_connection("/v1/events/batch", configuration)
        local batch_events = {}
        repeat
          local event = table.remove(queue)
          table.insert(batch_events, event)
          if (#batch_events == configuration.batch_size) then
            send_payload(sock, parsed_url, batch_events)
          else if(#queue ==0 and #batch_events > 0) then
              send_payload(sock, parsed_url, batch_events)
            end
          end
        until #batch_events == configuration.batch_size or next(queue) == nil

        if #queue > 0 then
          has_events = true
        else
          has_events = false
        end

        local ok, err = sock:setkeepalive(configuration.keepalive)
        if not ok then
          if configuration.debug then 
            ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
          end
          return
         else
           ngx_log(ngx.DEBUG,"[moesif] success keep-alive", ok)
        end
      else
        has_events = false
      end
    end
  until has_events == false

  if not has_events then
    ngx_log(ngx.DEBUG, "[moesif] No events to read from the queue")
  end
end

-- Log to a Http end point.
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
-- @param `hash_key` Hash key of the config application Id
local function log(premature, conf, message, hash_key)
  if premature then
    return
  end

  -- Sampling Events
  local random_percentage = math.random() * 100

  if conf.sample_rate == nil then
    conf.sample_rate = 100
  end

  if next(conf.user_sample_rate) ~= nil and message["user_id"] ~= nil and conf.user_sample_rate[message["user_id"]]~= nil then 
    sampling_rate = conf.user_sample_rate[message["user_id"]]
  else 
    sampling_rate = conf.sample_rate
  end

  if sampling_rate >= random_percentage then
    if conf.debug then 
      ngx_log(ngx.DEBUG, "[moesif] Event added to the queue")
    end
    message["weight"] = (sampling_rate == 0 and 1 or math.floor(100 / sampling_rate))
    table.insert(queue_hashes[hash_key], message)
  else
    if conf.debug then 
      ngx_log(ngx.DEBUG, "[moesif] Skipped Event", " due to sampling percentage: " .. tostring(sampling_rate) .. " and random number: " .. tostring(random_percentage))
    end
  end
end

function _M.execute(conf, message)
  -- Hash key of the config application Id
  local hash_key = ngx_md5(conf.application_id)

  if message["user_id"] ~= nil then 
    conf["user_id"] = message["user_id"]
  else 
    conf["user_id"] = nil
  end

  if config_hashes[hash_key] == nil then
    local ok, err = ngx_timer_at(0, get_config, conf)
    if not ok then
      if conf.debug then 
        ngx_log(ngx_log_ERR, "[moesif] failed to get application config, setting the sample_rate to default ", err)
      end
    else
      if conf.debug then 
        ngx_log(ngx.DEBUG, "[moesif] successfully fetched the application configuration " , ok)
      end
    end
    conf["sample_rate"] = 100
    conf["user_sample_rate"] = {}
    conf["last_updated_time"] = os.time()
    conf["ETag"] = nil
    config_hashes[hash_key] = conf
    local create_new_table = moesif_events..hash_key
    create_new_table = {}
    queue_hashes[hash_key] = create_new_table
  end

  local ok, err = ngx_timer_at(0, log, conf, message, hash_key)
  if not ok then
    if conf.debug then 
      ngx_log(ngx_log_ERR, "[moesif] failed to create timer: ", err)
    end
  end
end

-- Schedule Events batch job
function _M.start_background_thread()
  ngx.log(ngx.DEBUG, "[moesif] Scheduling Events batch job every 5 seconds")
  local ok, err = ngx_timer_every(5, send_events_batch)
  if not ok then
      ngx.log(ngx.ERR, "[moesif] Error when scheduling the job: "..err)
  end
end

return _M
