local _M = {}
local helper = require "kong.plugins.moesif.helpers"
local HTTPS = "https"
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local session 
local sessionerr

-- Create new connection
-- @param `api_endpoint` The base API
-- @param `url_path`  The path like /events
-- @param `conf`  Configuration table, holds http endpoint details
-- @return `sock` Socket object
-- @return `parsed_url` a table with host details like domain name, port, path etc
function _M.get_connection(api_endpoint, url_path, conf, sock)
  local parsed_url = helper.parse_url(api_endpoint..url_path)
  local host = parsed_url.host
  local port = tonumber(parsed_url.port)

  sock:settimeout(conf.connect_timeout)
  local ok, err = sock:connect(host, port)
  if not ok then
    if conf.debug then 
      ngx_log(ngx_log_ERR, "[moesif] failed to connect to " .. host .. ":" .. tostring(port) .. ": ", err)
    end
    return
  else
    if conf.debug then
      ngx_log(ngx.DEBUG, "[moesif] Successfully created connection " , ok)
    end
  end

  if parsed_url.scheme == HTTPS then
    if session ~= nil then 
      session, sessionerr = sock:sslhandshake(session, host, false)
    else 
      session, sessionerr = sock:sslhandshake(true, host, false)
    end

    if sessionerr then
      if conf.debug then 
        ngx_log(ngx_log_ERR, "[moesif] failed to do SSL handshake with " .. host .. ":" .. tostring(port) .. ": ", sessionerr)
      end
      session = nil
      return nil, nil
    end
  end
  return sock, parsed_url
end

return _M
