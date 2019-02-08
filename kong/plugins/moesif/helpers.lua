local _M = {}
local url = require "socket.url"
local HTTPS = "https"

-- Read data from the socket
-- @param `socket`  socket
-- @return `response` a string with the api call response details
function _M.read_socket_data(socket)
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

return _M
