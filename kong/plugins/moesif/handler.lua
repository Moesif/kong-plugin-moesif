local serializer = require "kong.plugins.moesif.moesif_ser"
local governance = require "kong.plugins.moesif.moesif_gov"
local BasePlugin = require "kong.plugins.base_plugin"
local log = require "kong.plugins.moesif.log"
local helpers = require "kong.plugins.moesif.helpers"
local req_set_header = ngx.req.set_header
local string_find = string.find
local req_read_body = ngx.req.read_body
local req_get_headers = ngx.req.get_headers
local req_get_body_data = ngx.req.get_body_data
local socket = require "socket"
local MoesifLogHandler = BasePlugin:extend()
queue_hashes = {}


function MoesifLogHandler:new()
  MoesifLogHandler.super.new(self, "moesif")
end

function MoesifLogHandler:access(conf)
  MoesifLogHandler.super.access(self)

  local start_access_phase_time = socket.gettime()*1000

  local headers = req_get_headers()

  local req_body, res_body = "", ""
  local req_post_args = {}
  local err = nil
  local mimetype = nil
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
    ngx.ctx.api_version = conf.api_version
-- keep in memory the bodies for this request
  ngx.ctx.moesif = {
    req_body = req_body,
    res_body = res_body,
    req_post_args = req_post_args
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

 function MoesifLogHandler:body_filter(conf)
 MoesifLogHandler.super.body_filter(self)

    local headers = ngx.resp.get_headers()
    local content_length = headers["content-length"]

    -- Hash key of the config application Id
    local hash_key = string.sub(conf.application_id, -10)
    if (queue_hashes[hash_key] == nil) or 
          (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then

      if (content_length == nil) or (tonumber(content_length) <= conf.response_max_body_size_limit) then
        local chunk = ngx.arg[1]
        local moesif_data = ngx.ctx.moesif or {res_body = ""} -- minimize the number of calls to ngx.ctx while fallbacking on default value
        moesif_data.res_body = moesif_data.res_body .. chunk
        ngx.ctx.moesif = moesif_data
      end
    end
 end

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
  MoesifLogHandler.super.log(self)

  -- Hash key of the config application Id
  local hash_key = string.sub(conf.application_id, -10)
  if (queue_hashes[hash_key] == nil) or 
        (queue_hashes[hash_key] ~= nil and type(queue_hashes[hash_key]) == "table" and #queue_hashes[hash_key] < conf.event_queue_size) then
    log_event(ngx, conf)
  else
    if conf.debug then
      ngx.log(ngx.DEBUG, '[moesif] Queue is full, do not log new events ')
    end
  end
end

function MoesifLogHandler:header_filter(conf)
MoesifLogHandler.super.header_filter(self)

    if not conf.disable_transaction_id then
      ngx.header["X-Moesif-Transaction-Id"] = helpers.uuid()
    end
end

function MoesifLogHandler:init_worker()
  MoesifLogHandler.super.init_worker(self)
  log.start_background_thread()
end

MoesifLogHandler.PRIORITY = 5
MoesifLogHandler.VERSION = "0.2.28"

-- Plugin version
plugin_version = MoesifLogHandler.VERSION

return MoesifLogHandler
