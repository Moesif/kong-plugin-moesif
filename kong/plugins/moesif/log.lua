local cjson = require "cjson"
local url = require "socket.url"

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

-- Generates http payload .
-- @param `method` http method to be used to send data
-- @param `parsed_url` contains the host details
-- @param `message`  Message to be logged
-- @return `payload` http payload
local function generate_post_payload(parsed_url, access_token, message,application_id)
  local body = cjson.encode(message) 
  ngx_log(ngx.DEBUG, " application_id: ", application_id)
  local payload = string_format(
    "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\nContent-Type: application/json\r\nContent-Length: %s\r\n\r\n%s",
    "POST", parsed_url.path, parsed_url.host, application_id, #body, body)
  return payload
end

-- Parse host url
-- @param `url`  host url
-- @return `parsed_url`  a table with host details like domain name, port, path etc
local function parse_url(host_url)
  local parsed_url = url.parse(host_url)
  if not parsed_url.port then
    if parsed_url.scheme == "http" then
      parsed_url.port = 80
     elseif parsed_url.scheme == HTTPS then
      parsed_url.port = 443
     end
  end
  if not parsed_url.path then
    parsed_url.path = "/"
  end
  return parsed_url
end

-- Send Payload
-- @param `sock`  Socket object
-- @param `parsed_url`  Parsed Url
-- @param `batch_events`  Events Batch
local function send_payload(sock, parsed_url, batch_events)
  local application_id = configuration.application_id
  local access_token = configuration.access_token

  ok, err = sock:send(generate_post_payload(parsed_url, access_token, batch_events, application_id) .. "\r\n")
  if not ok then
    ngx_log(ngx_log_ERR, "[moesif] failed to send data to " .. host .. ":" .. tostring(port) .. ": ", err)
  else
    ngx_log(ngx.DEBUG, "Events sent successfully " , ok)
  end
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
        ngx_log(ngx.DEBUG, "Sending events to Moesif")
        -- Getting the configuration for this particular key
        configuration = config_hashes[key]
        local parsed_url = parse_url(configuration.api_endpoint)
        local host = parsed_url.host
        local port = tonumber(parsed_url.port)
        local sock = ngx.socket.tcp()

        sock:settimeout(configuration.timeout)
        local api_version = configuration.api_version
        ngx.ctx.api_version = api_version
        ok, err = sock:connect(host, port)
        if not ok then
          ngx_log(ngx_log_ERR, "[moesif] failed to connect to " .. host .. ":" .. tostring(port) .. ": ", err)
          return
        else
          ngx_log(ngx.DEBUG, "Successfully created connection" , ok)
        end

        if parsed_url.scheme == HTTPS then
          local _, err = sock:sslhandshake(true, host, false)
          if err then
            ngx_log(ngx_log_ERR, "[moesif] failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", err)
          end
        end

        local batch_events = {}
        repeat
          event = table.remove(queue)
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

        ok, err = sock:setkeepalive(configuration.keepalive)
        if not ok then
          ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. host .. ":" .. tostring(port) .. ": ", err)
          return
         else
           ngx_log(ngx.DEBUG,"success keep-alive", ok)
        end
      else
        has_events = false
      end
    end
  until has_events == false

  if not has_events then
    ngx_log(ngx.DEBUG, "No events to read from the queue")
  end
end

-- Log to a Http end point.
-- @param `premature`
-- @param `conf`     Configuration table, holds http endpoint details
-- @param `message`  Message to be logged
local function log(premature, conf, message)
  if premature then
    return
  end

  -- Sampling Events
  local random_percentage = math.random() * 100

  if conf.sampling_percentage >= random_percentage then
    ngx_log(ngx.DEBUG, "Event added to the queue")
    table.insert(queue_hashes[hash_key], message)
  else
    ngx_log(ngx.DEBUG, "Skipped Event", " due to sampling percentage: " .. tostring(conf.sampling_percentage) .. " and random number: " .. tostring(random_percentage))
  end
end

function _M.execute(conf, message)
  -- Hash Key of the config object
  hash_key = ngx_md5(cjson.encode(conf))

  if config_hashes[hash_key] == nil then
    config_hashes[hash_key] = conf
    local create_new_table = moesif_events..hash_key
    create_new_table = {}
    queue_hashes[hash_key] = create_new_table
  end

  local ok, err = ngx_timer_at(0, log, conf, message)
  if not ok then
    ngx_log(ngx_log_ERR, "[moesif] failed to create timer: ", err)
  end
end

-- Schedule Events batch job
function _M.start_background_thread()
  ngx.log(ngx.DEBUG, "Scheduling Events batch job every 5 seconds")
  local ok, err = ngx_timer_every(5, send_events_batch)
  if not ok then
      ngx.log(ngx.ERR, "Error when scheduling the job: "..err)
  end
end

return _M
