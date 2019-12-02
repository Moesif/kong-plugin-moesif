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
      ngx_log(ngx.DEBUG, " X-Forwarded-For Ip Expected string got type - : ", type(value))
      return nil
    end
  
    -- x-forwarded-for may return multiple IP addresses in the format:
    -- "client IP, proxy 1 IP, proxy 2 IP"
    -- Therefore, the right-most IP address is the IP address of the most recent proxy
    -- and the left-most IP address is the IP address of the originating client.
    -- source: http://docs.aws.amazon.com/elasticloadbalancing/latest/classic/x-forwarded-headers.html
    -- Azure Web App's also adds a port for some reason, so we'll only use the first part (the IP)
    local forwardedIps = {}
  
    for word in string.gmatch(value, '([^,]+)') do
      local ip = string.gsub(word, "%s+", "")
      if #{ip:match("^"..(("([a-fA-F0-9]*):"):rep(8):gsub(":$","$")))} == 8 then
        table.insert(forwardedIps, ip)
       else 
        if string.match(ip, ":") then
            local splitted = string.match(ip, "(.*)%:")
            table.insert(forwardedIps, splitted)
          else
            table.insert(forwardedIps, ip)
        end
      end
    end
  
    for index, value in ipairs(forwardedIps) do
      if is_ip(value) then
        return value
      end
    end
end
  
-- Function to check if it is valid Ip Address
function is_ip(value)
   local ip_type = get_ip_type(value)
   if ip_type == 1 or ip_type == 2 then
    return true
   else
    return false
   end
end
  
-- Function to get the client Ip
function _M.get_client_ip(req_headers)
    -- Standard headers used by Amazon EC2, Heroku, and others.
    if is_ip(req_headers["x-client-ip"]) then
       return req_headers["x-client-ip"]
    end
  
    -- Load-balancers (AWS ELB) or proxies.
    local xForwardedFor = getClientIpFromXForwardedFor(req_headers["x-forwarded-for"]);
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

return _M
