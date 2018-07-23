local serializer = require "kong.plugins.moesif.moesif_ser"
local BasePlugin = require "kong.plugins.base_plugin"
local log = require "kong.plugins.moesif.log"
local public_utils = require "kong.tools.public"

local string_find = string.find
local req_read_body = ngx.req.read_body
local req_get_headers = ngx.req.get_headers
local req_get_body_data = ngx.req.get_body_data

local MoesifLogHandler = BasePlugin:extend()

function MoesifLogHandler:new()
  MoesifLogHandler.super.new(self, "moesif")
end

function MoesifLogHandler:access(conf)
  MoesifLogHandler.super.access(self)

  local req_body, res_body = "", ""
  local req_post_args = {}

    req_read_body()
    req_body = req_get_body_data()
    local headers = req_get_headers()
    local content_type = headers["content-type"]
    if content_type and string_find(content_type:lower(), "application/x-www-form-urlencoded", nil, true) then
      req_post_args = public_utils.get_body_args()
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
  local message = serializer.serialize(ngx)
  log.execute(conf, message)
end

MoesifLogHandler.PRIORITY = 5
MoesifLogHandler.VERSION = "0.1.0"

return MoesifLogHandler
