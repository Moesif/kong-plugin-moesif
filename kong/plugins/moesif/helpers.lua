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

-- Fetch entity id from the event
-- @param `message`      Message to be logged
-- @param `entity_name`  Entity name to be fetch user_id, company_id etc
-- @return `entity_id`   Return the fetched entity id if found
function _M.fetch_entity_id(message, entity_name)
  if message[entity_name] ~= nil then 
    return message[entity_name]
  end
  return nil
end

-- Prepare request URI
-- @param `ngx`  Nginx object
-- @return `url` Request URI
function _M.prepare_request_uri(ngx)
  return ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. ngx.var.request_uri
end

return _M
