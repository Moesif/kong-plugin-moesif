local ngx_now = ngx.now
local req_get_method = ngx.req.get_method
local req_start_time = ngx.req.start_time
local req_get_headers = ngx.req.get_headers
local res_get_headers = ngx.resp.get_headers

local _M = {}

function _M.serialize(ngx)
  local moesif_ctx = ngx.ctx.moesif or {}
  local session_token_entity
  local user_id_entity

  if ngx.ctx.authenticated_credential.key ~= nil then
    session_token_entity = tostring(ngx.ctx.authenticated_credential.key)
  elseif ngx.ctx.authenticated_credential.id ~= nil then
    session_token_entity = tostring(ngx.ctx.authenticated_credential.id)
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
      body = moesif_ctx.req_body,
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
      body = moesif_ctx.res_body,
    },
    session_token = session_token_entity,
    user_id = user_id_entity
}
end

return _M


