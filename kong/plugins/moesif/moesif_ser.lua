local ngx_now = ngx.now
local req_get_method = ngx.req.get_method
local req_start_time = ngx.req.start_time
local req_get_headers = ngx.req.get_headers
local res_get_headers = ngx.resp.get_headers
local cjson = require "cjson"
local _M = {}

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
      ip_address = ngx.var.remote_addr,	 
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


