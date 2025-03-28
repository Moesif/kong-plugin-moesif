local serializer = require "kong.plugins.moesif.moesif_ser"
local governance = require "kong.plugins.moesif.moesif_gov"
local MoesifLogHandler = {
  VERSION  = "2.1.1",
  PRIORITY = 5,
}
local log = require "kong.plugins.moesif.log"
local req_set_header = ngx.req.set_header
local string_find = string.find
local req_read_body = ngx.req.read_body
local req_get_headers = ngx.req.get_headers
local req_get_body_data = ngx.req.get_body_data
local socket = require "socket"
queue_hashes = {}


-- local random = math.random	
local function uuid()	
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'	
    return string.gsub(template, '[xy]', function (c)	
        local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)	
        return string.format('%x', v)	
    end)	
end

function MoesifLogHandler:access(conf)

  local start_access_phase_time = socket.gettime()*1000

  local headers = req_get_headers()
  -- Add Transaction Id to the request header	
  if not conf.disable_transaction_id then	
    if headers["X-Moesif-Transaction-Id"] ~= nil then	
      local req_trans_id = headers["X-Moesif-Transaction-Id"]	
      if req_trans_id ~= nil and req_trans_id:gsub("%s+", "") ~= "" then	
        ngx.ctx.transaction_id = req_trans_id	
      else	
        ngx.ctx.transaction_id = uuid()	
      end	
    else	
      ngx.ctx.transaction_id = uuid()	
    end	
  -- Add Transaction Id to the request header	
  req_set_header("X-Moesif-Transaction-Id", ngx.ctx.transaction_id)	
  end


  local req_body, res_body = "", ""
  local req_post_args = {}
  local err = nil
  local mimetype = nil
  -- Only capture the request body if conf.disable_capture_request_body is false
  if not conf.disable_capture_request_body then
    local content_length = headers["content-length"]
    -- Hash key of the config application Id
    local hash_key = string.sub(conf.application_id, -10)
    if (queue_hashes[hash_key] == nil) or 
          (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then

      -- Read request body
      req_read_body()
      local read_request_body = req_get_body_data()
      if (content_length == nil and read_request_body ~= nil and string.len(read_request_body) <= conf.request_max_body_size_limit) or (content_length ~= nil and tonumber(content_length) <= conf.request_max_body_size_limit) then 
        req_body = read_request_body
        local content_type = headers["content-type"]
        if content_type and string_find(content_type:lower(), "application/x-www-form-urlencoded", nil, true) then
          req_post_args, err, mimetype = kong.request.get_body()
        end
      end
    end
  end
    ngx.ctx.api_version = conf.api_version
-- keep in memory the bodies for this request
  ngx.ctx.moesif = {
    req_body = req_body,
    res_body = res_body,
    req_post_args = req_post_args,
    res_body_exceeded_max_size = false
  }

  -- Check if need to block incoming request based on user-specified governance rules
  local block_req = governance.govern_request(ngx, conf, start_access_phase_time)
  if block_req == nil then 
    if conf.debug then
      ngx.log(ngx.DEBUG, '[moesif] No need to block incoming request.')
    end
    local end_access_phase_time = socket.gettime()*1000
    ngx.log(ngx.DEBUG, "[moesif] access phase took time for non-blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. ngx.worker.pid())
  end
end

-- function MoesifLogHandler:body_filter(conf)
--   -- Only capture the response body if conf.disable_capture_response_body is false
--   if not conf.disable_capture_response_body then

--     local headers = ngx.resp.get_headers()
--     local content_length = headers["content-length"]

--     -- Hash key of the config application Id
--     local hash_key = string.sub(conf.application_id, -10)

--     -- Only capture the response body if it meets the conditions
--     if (queue_hashes[hash_key] == nil) or 
--           (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then

--         if (content_length == nil) or (tonumber(content_length) <= conf.response_max_body_size_limit) then
--             local chunk = ngx.arg[1]
--             -- Process the chunks incrementally
--             if chunk and #chunk > 0 then
--                 -- Store only the first few KBs of the response body
--                 local moesif_data = ngx.ctx.moesif or {res_body = ""}
--                 if #moesif_data.res_body < conf.response_max_body_size_limit then
--                     moesif_data.res_body = moesif_data.res_body .. chunk
--                 end
--                 ngx.ctx.moesif = moesif_data
--             end
--         end
--      end
--   end
-- end

-- function MoesifLogHandler:body_filter(conf)
--   -- Only capture the response body if conf.disable_capture_response_body is false
--   if not conf.disable_capture_response_body then

--     -- ngx.log(ngx.DEBUG, '[moesif] Processing response body.')

--     local headers = ngx.resp.get_headers()
--     local content_length = headers["content-length"]

--     -- Hash key of the config application Id
--     local hash_key = string.sub(conf.application_id, -10)

--     -- Only capture the response body if it meets the conditions
--     if (queue_hashes[hash_key] == nil) or 
--           (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then

--         -- Initialize the response body buffer in the Nginx context
--         local moesif_data = ngx.ctx.moesif or {res_body = ""}

--         -- Process the chunks incrementally
--         local chunk = ngx.arg[1]

--         -- Check if Content-Length is set
--         if content_length then
--             -- ngx.log(ngx.DEBUG, '[moesif] Content-Length is set')
--             -- Only capture the response body if it is within the size limit
--             if tonumber(content_length) <= conf.response_max_body_size_limit then
--                 if chunk and #chunk > 0 then
--                     -- Append the chunk to the buffer
--                     if #moesif_data.res_body < conf.response_max_body_size_limit then
--                         -- ngx.log(ngx.DEBUG, '[moesif] Append the chunk to the buffer with content length set') 
--                         moesif_data.res_body = moesif_data.res_body .. chunk
--                     end
--                 end
--             else 
--               -- ngx.log(ngx.DEBUG, '[moesif] Setting response body to empty string when content length is defined') 
--               moesif_data.res_body_exceeded_max_size = true
--             end
--         else
--             -- Handle Transfer-Encoding: chunked
--             -- ngx.log(ngx.DEBUG, '[moesif] Handle Transfer-Encoding: chunked - ' .. tostring(#chunk) .. " and accumulated - " .. tostring(#moesif_data.res_body) .. " and moesif_data.res_body_exceeded_max_size -" .. tostring(moesif_data.res_body_exceeded_max_size))
--             if chunk and #chunk > 0 then
--                 -- Append the chunk to the buffer only if within the size limit
--                 if (not moesif_data.res_body_exceeded_max_size) and (#moesif_data.res_body < conf.response_max_body_size_limit) then
--                     local remaining_limit = conf.response_max_body_size_limit - #moesif_data.res_body
--                     if #chunk < remaining_limit then
--                         -- ngx.log(ngx.DEBUG, '[moesif] Accumulating chunks with Encoding ')
--                         moesif_data.res_body = moesif_data.res_body .. chunk
--                     else
--                     --     -- Truncate the chunk to fit within the size limit
--                     --     -- ngx.log(ngx.DEBUG, '[moesif] Truncate the chunk to fit within the size limit')
--                     --     -- chunk = string.sub(chunk, 1, remaining_limit)
--                         -- ngx.log(ngx.DEBUG, '[moesif] Setting res_body_exceeded_max_size to true as chunk < remaining_limit ')
--                         moesif_data.res_body_exceeded_max_size = true
--                     --     -- moesif_data.res_body = ""
--                     end
--                     -- ngx.log(ngx.DEBUG, '[moesif] Accumulating chunks with Encoding ')
--                     -- moesif_data.res_body = moesif_data.res_body .. chunk
--                 else
--                     -- ngx.log(ngx.DEBUG, '[moesif] Setting response body to empty string and no longer reading chunks') 
--                     moesif_data.res_body_exceeded_max_size = true
--                     moesif_data.res_body = ""
--                 end
--             end
--         end
--     end
--   -- else
--   --   ngx.log(ngx.DEBUG, '[moesif] Not processing response body.')
--   end
-- end

 -- Function to ensure response body size is less than conf.response_max_body_size_limit
function ensure_body_size_under_limit(ngx, conf)
  local moesif_ctx = ngx.ctx.moesif or {}

  if moesif_ctx.res_body ~= nil and (string.len(moesif_ctx.res_body) >= conf.response_max_body_size_limit) then
    moesif_ctx.res_body = nil
  end
end

function log_event(ngx, conf)
  local start_log_phase_time = socket.gettime()*1000
  -- Ensure that the response body size is less than conf.response_max_body_size_limit incase content-lenght header is not set
  ensure_body_size_under_limit(ngx, conf)
  local message = serializer.serialize(ngx, conf)
  log.execute(conf, message)
  local end_log_phase_time = socket.gettime()*1000
  ngx.log(ngx.DEBUG, "[moesif] log phase took time - ".. tostring(end_log_phase_time - start_log_phase_time).." for pid - ".. ngx.worker.pid())
end

function MoesifLogHandler:log(conf)
  ngx.log(ngx.DEBUG, '[moesif] Log phase called for the new event ' .." for pid - ".. ngx.worker.pid())

  -- Hash key of the config application Id
  local hash_key = string.sub(conf.application_id, -10)
  if (queue_hashes[hash_key] == nil) or 
        (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then
    if conf.debug then
      if (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table") then 
        ngx.log(ngx.DEBUG, '[moesif] logging new event where the current number of events in the queue is '.. tostring(#queue_hashes[hash_key]) .. " for pid - ".. ngx.worker.pid())
      else 
        ngx.log(ngx.DEBUG, '[moesif] logging new event when queue hash is nil ' .." for pid - ".. ngx.worker.pid())
      end
    end
    log_event(ngx, conf)
  else
    if conf.debug then
      ngx.log(ngx.DEBUG, '[moesif] Queue is full, do not log new events '.." for pid - ".. ngx.worker.pid())
    end
  end
end

function MoesifLogHandler:header_filter(conf)

    if not conf.disable_transaction_id then
      ngx.header["X-Moesif-Transaction-Id"] = ngx.ctx.transaction_id
    end
end

function MoesifLogHandler:init_worker()
  log.start_background_thread()
end

-- Plugin version
plugin_version = MoesifLogHandler.VERSION

return MoesifLogHandler
