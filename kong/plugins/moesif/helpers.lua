local _M = {}
local url = require "socket.url"
local HTTPS = "https"
local cjson = require "cjson"
local base64 = require "kong.plugins.moesif.base64"

-- Prepare request URI
-- @param `ngx`  Nginx object
-- @param `conf`     Configuration table, holds http endpoint details
-- @return `url` Request URI
function _M.prepare_request_uri(ngx, conf)

  local request_uri = ngx.var.request_uri
  if next(conf.request_query_masks) ~= nil and request_uri ~= nil then
    for _, value in ipairs(conf.request_query_masks) do
      request_uri = request_uri:gsub(value.."=[^&]*([^&])", value.."=*****", 1)
    end
  end
  if request_uri == nil then
    request_uri = "/"
  end
  return ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. request_uri
end

-- function to parse user id from authorization/user-defined headers
function _M.parse_authorization_header(token, user_id, company_id)
  local user_id_entity = nil
  local company_id_entity = nil
  
  -- Decode the payload
  local base64_decode_ok, payload = pcall(base64.decode, token)
  if base64_decode_ok then
    -- Convert the payload into table
    local json_decode_ok, decoded_payload = pcall(cjson.decode, payload)
    if json_decode_ok then
      -- Fetch the user_id
      if type(decoded_payload) == "table" and next(decoded_payload) ~= nil then 
         -- Convert keys to lowercase
         for k, v in pairs(decoded_payload) do
          decoded_payload[string.lower(k)] = v
        end
        -- Fetch user from the token
        if decoded_payload[user_id] ~= nil then
          user_id_entity = tostring(decoded_payload[user_id])
        end
        -- Fetch company from the token
        if decoded_payload[company_id] ~= nil then
          company_id_entity = tostring(decoded_payload[company_id])
        end
        return user_id_entity, company_id_entity
      end
    end
  end
  return user_id_entity, company_id_entity
end

return _M
