local _M = {}
local url = require "socket.url"
local HTTPS = "https"

-- Read data from the socket
-- @param `socket`  socket
-- @return `response` a string with the api call response details
function _M.read_socket_data(socket, conf)
  socket:settimeout(conf.timeout)
  local response, err, partial = socket:receive("*a")
  if (not response) and (err ~= 'timeout')  then
    return nil, err
  end
  response = response or partial
  if not response then return nil, 'timeout' end
  return response
end

-- Parse host url
-- @param `url`  host url
-- @return `parsed_url`  a table with host details like domain name, port, path etc
function _M.parse_url(host_url)
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

-- Prepare request URI
-- @param `ngx`  Nginx object
-- @param `conf`     Configuration table, holds http endpoint details
-- @return `url` Request URI
function _M.prepare_request_uri(ngx, conf)

  local request_uri = ngx.var.request_uri
  if next(conf.request_query_masks) ~= nil then 
    for _, value in ipairs(conf.request_query_masks) do
      request_uri = request_uri:gsub(value.."=[^&]*([^&])", value.."=*****", 1)
    end
  end
  return ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. request_uri
end

-- function to generate uuid
local random = math.random
function _M.uuid()
    local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
    return string.gsub(template, '[xy]', function (c)
        local v = (c == 'x') and random(0, 0xf) or random(8, 0xb)
        return string.format('%x', v)
    end)
end

return _M
