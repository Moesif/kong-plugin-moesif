local ngx_now = ngx.now
local req_get_method = ngx.req.get_method
local req_start_time = ngx.req.start_time
local req_get_headers = ngx.req.get_headers
local res_get_headers = ngx.resp.get_headers
local cjson = require "cjson"
local _M = {}
local ngx_log = ngx.log

-- Function to get the Type of the Ip
function get_ip_type(ip)
  local R = {ERROR = 0, IPV4 = 1, IPV6 = 2, STRING = 3}
  if type(ip) ~= "string" then return R.ERROR end

  -- check for format 1.11.111.111 for ipv4
  local chunks = {ip:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")}
  if #chunks == 4 then
    for _,v in pairs(chunks) do
      if tonumber(v) > 255 then return R.STRING end
    end
    return R.IPV4
  end

  -- check for ipv6 format, should be 8 'chunks' of numbers/letters
  -- without leading/trailing chars
  -- or fewer than 8 chunks, but with only one `::` group
  local chunks = {ip:match("^"..(("([a-fA-F0-9]*):"):rep(8):gsub(":$","$")))}
  if #chunks == 8
  or #chunks < 8 and ip:match('::') and not ip:gsub("::","",1):match('::') then
    for _,v in pairs(chunks) do
      if #v > 0 and tonumber(v, 16) > 65535 then return R.STRING end
    end
    return R.IPV6
  end
  return R.STRING
end

-- Function to get the client Ip from the X-forwarded-for header
function getClientIpFromXForwardedFor(value)
  if value == nil then
    return nil
  end

  if type(value) ~= "string" then
    ngx_log(ngx.DEBUG, " Expected string got type - : ", type(value))
    return nil
  end

  -- x-forwarded-for may return multiple IP addresses in the format:
  -- "client IP, proxy 1 IP, proxy 2 IP"
  -- Therefore, the right-most IP address is the IP address of the most recent proxy
  -- and the left-most IP address is the IP address of the originating client.
  -- source: http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html
  -- Azure Web App's also adds a port for some reason, so we'll only use the first part (the IP)
  forwardedIps = {}

  for word in string.gmatch(value, '([^,]+)') do
    ip = string.gsub(word, "%s+", "")
    table.insert(forwardedIps, ip)
  end

  for index, value in ipairs(forwardedIps) do
    if is_ip(value) then
      return value
    end
  end
end

-- Function to check if it is valid Ip Address
function is_ip(value)
 ip_type = get_ip_type(value)
 if ip_type == 1 or ip_type == 2 then
  return true
 else
  return false
 end
end

-- Function to get the client Ip
function get_client_ip(req_headers)
  -- Standard headers used by Amazon EC2, Heroku, and others.
  if is_ip(req_headers["x-client-ip"]) then
     return req_headers["x-client-ip"]
  end

  -- Load-balancers (AWS ELB) or proxies.
  xForwardedFor = getClientIpFromXForwardedFor(req_headers["x-forwarded-for"]);
  if (is_ip(xForwardedFor)) then
      return xForwardedFor
  end

  -- Cloudflare.
  -- @see https://support.cloudflare.com/hc/en-us/articles/200170986-How-does-Cloudflare-handle-HTTP-Request-headers-
  -- CF-Connecting-IP - applied to every request to the origin.
  if is_ip(req_headers["cf-connecting-ip"]) then
      return req_headers["cf-connecting-ip"]
  end

  -- Fastly and Firebase hosting header (When forwared to cloud function)
  if (is_ip(req_headers["fastly-client-ip"])) then
      return req_headers["fastly-client-ip"]
  end

  -- Akamai and Cloudflare: True-Client-IP.
  if (is_ip(req_headers["true-client-ip"])) then
      return req_headers["true-client-ip"]
  end

  -- Default nginx proxy/fcgi; alternative to x-forwarded-for, used by some proxies.
  if (is_ip(req_headers["x-real-ip"])) then
      return req_headers["x-real-ip"]
  end

  -- (Rackspace LB and Riverbed's Stingray)
  -- http://www.rackspace.com/knowledge_center/article/controlling-access-to-linux-cloud-sites-based-on-the-client-ip-address
  -- https://splash.riverbed.com/docs/DOC-1926
  if (is_ip(req_headers["x-cluster-client-ip"])) then
      return req_headers["x-cluster-client-ip"]
  end

  if (is_ip(req_headers["x-forwarded"])) then
      return req_headers["x-forwarded"]
  end

  if (is_ip(req_headers["forwarded-for"])) then
      return req_headers["forwarded-for"]
  end

  if (is_ip(req_headers.forwarded)) then
      return req_headers.forwarded
  end

  -- Return remote address
  return ngx.var.remote_addr
end

function mask_body(body, masks)
  if masks == nil then return body end
  if body == nil then return body end
  for mask_key, mask_value in pairs(masks) do
    if body[mask_value] then body[mask_value] = nil end
      for body_key, body_value in next, body do
          if type(body_value)=="table" then mask_body(body_value, masks) end
      end
  end
  return body
end

function _M.serialize(ngx, conf)
  local moesif_ctx = ngx.ctx.moesif or {}
  local session_token_entity
  local user_id_entity
  local request_body_entity
  local response_body_entity

  if conf.disable_capture_request_body then
    request_body_entity = nil
  else
    if next(conf.request_masks) == nil then
      request_body_entity = moesif_ctx.req_body
    else
      ok, mask_result = pcall(mask_body, cjson.decode(moesif_ctx.req_body), conf.request_masks)
      if not ok then
        request_body_entity = moesif_ctx.req_body
      else
        request_body_entity = cjson.encode(mask_result)
      end
    end
  end

  if conf.disable_capture_response_body then
    response_body_entity = nil
  else
    if next(conf.response_masks) == nil then
      response_body_entity = moesif_ctx.res_body
    else
      ok, mask_result = pcall(mask_body, cjson.decode(moesif_ctx.res_body), conf.response_masks)
      if not ok then
        response_body_entity = moesif_ctx.res_body
      else
        response_body_entity = cjson.encode(mask_result)
      end
    end
  end

  if ngx.ctx.authenticated_credential ~= nil then
    if ngx.ctx.authenticated_credential.key ~= nil then
      session_token_entity = tostring(ngx.ctx.authenticated_credential.key)
    elseif ngx.ctx.authenticated_credential.id ~= nil then
      session_token_entity = tostring(ngx.ctx.authenticated_credential.id)
    else
      session_token_entity = nil
    end
  else
    session_token_entity = nil
  end

  if req_get_headers()["x-consumer-custom-id"] ~= nil then
    user_id_entity = tostring(req_get_headers()["x-consumer-custom-id"])
  else
    user_id_entity = nil
  end
   return {
    request = {
      uri =  ngx.var.scheme .. "://" .. ngx.var.host .. ":" .. ngx.var.server_port .. ngx.var.request_uri,
      headers = req_get_headers(),
      body = request_body_entity,
      verb = req_get_method(),
      ip_address = get_client_ip(req_get_headers()),
      api_version = ngx.ctx.api_version,
      time = os.date("!%Y-%m-%dT%H:%M:%S.", req_start_time()) .. string.format("%d",(req_start_time()- string.format("%d", req_start_time()))*1000)
    },
    response = {
      time = os.date("!%Y-%m-%dT%H:%M:%S.", ngx_now()) .. string.format("%d",(ngx_now()- string.format("%d",ngx_now()))*1000),
      status = ngx.status,
      ip_address = Nil,
      headers = res_get_headers(),
      body = response_body_entity,
    },
    session_token = session_token_entity,
    user_id = user_id_entity
}
end

return _M
