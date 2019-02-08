local _M = {}
local helper = require "kong.plugins.moesif.helpers"
local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR

-- Create new connection
-- @param `url_path`  api endpoint
-- @param `conf`  Configuration table, holds http endpoint details
-- @return `sock` Socket object
-- @return `parsed_url` a table with host details like domain name, port, path etc
function _M.get_connection(url_path, conf)
  local parsed_url = helper.parse_url(conf.api_endpoint..url_path)
  local host = parsed_url.host
  local port = tonumber(parsed_url.port)
  local sock = ngx.socket.tcp()

  sock:settimeout(conf.timeout)
  local api_version = conf.api_version
  ngx.ctx.api_version = api_version
  ok, err = sock:connect(host, port)
  if not ok then
    ngx_log(ngx_log_ERR, "[moesif] failed to connect to " .. host .. ":" .. tostring(port) .. ": ", err)
    return
  else
    ngx_log(ngx.DEBUG, "[moesif] Successfully created connection " , ok)
  end

  if parsed_url.scheme == HTTPS then
    local _, err = sock:sslhandshake(true, host, false)
    if err then
      ngx_log(ngx_log_ERR, "[moesif] failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", err)
    end
  end
  return sock, parsed_url
end

return _M
