local serializer = require "kong.plugins.moesif.moesif_ser"
local BasePlugin = require "kong.plugins.base_plugin"
local log = require "kong.plugins.moesif.log"
local req_set_header = ngx.req.set_header
local string_find = string.find
local req_read_body = ngx.req.read_body
local req_get_headers = ngx.req.get_headers
local req_get_body_data = ngx.req.get_body_data

local MoesifLogHandler = BasePlugin:extend()

-- function to generate uuid
local random = math.random
local function uuid()
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and random(0, 0xf) or random(8, 0xb)
        return string.format('%x', v)
    end)
end

function MoesifLogHandler:new()
  MoesifLogHandler.super.new(self, "moesif")
end

function MoesifLogHandler:access(conf)
  MoesifLogHandler.super.access(self)

  local headers = req_get_headers()
  -- Add Transaction Id to the request header
  if not conf.disable_transaction_id then
    if headers["X-Moesif-Transaction-Id"] ~= nil then
      req_trans_id = headers["X-Moesif-Transaction-Id"]
      if req_trans_id ~= nil and req_trans_id:gsub("%s+", "") ~= "" then
        transaction_id = req_trans_id
      else
        transaction_id = uuid()
      end
    else
      transaction_id = uuid()
    end
  -- Add Transaction Id to the request header
  req_set_header("X-Moesif-Transaction-Id", transaction_id)
  end

  local req_body, res_body = "", ""
  local req_post_args = {}

    req_read_body()
    req_body = req_get_body_data()
    local content_type = headers["content-type"]
    if content_type and string_find(content_type:lower(), "application/x-www-form-urlencoded", nil, true) then
      req_post_args, err, mimetype = kong.request.get_body()
    end
    ngx.ctx.api_version = conf.api_version
-- keep in memory the bodies for this request
  ngx.ctx.moesif = {
    req_body = req_body,
    res_body = res_body,
    req_post_args = req_post_args
  }
end

 function MoesifLogHandler:body_filter(conf)
 MoesifLogHandler.super.body_filter(self)

    local chunk = ngx.arg[1]
    local moesif_data = ngx.ctx.moesif or {res_body = ""} -- minimize the number of calls to ngx.ctx while fallbacking on default value
    moesif_data.res_body = moesif_data.res_body .. chunk
    ngx.ctx.moesif = moesif_data
 end

function MoesifLogHandler:log(conf)
  MoesifLogHandler.super.log(self)
  local message = serializer.serialize(ngx, conf)
  log.execute(conf, message)
end

function MoesifLogHandler:header_filter(conf)
MoesifLogHandler.super.header_filter(self)

    if not conf.disable_transaction_id and transaction_id ~= nil then
     ngx.header["X-Moesif-Transaction-Id"] = transaction_id
    end
end

function MoesifLogHandler:init_worker()
  MoesifLogHandler.super.init_worker(self)
  log.start_background_thread()
end

MoesifLogHandler.PRIORITY = 5
MoesifLogHandler.VERSION = "0.1.9"

-- Plugin version
plugin_version = MoesifLogHandler.VERSION

return MoesifLogHandler
