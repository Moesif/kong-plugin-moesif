local _M = {}

local socket = require "socket"
local http = require "resty.http"
local ngx_log = ngx.log
local keepalive_timeout = 600000

function _M.get_client(conf)
    -- Create http client
    local create_client_time = socket.gettime()*1000
    local httpc = http.new()
    local end_client_time = socket.gettime()*1000
    if conf.debug then
        ngx_log(ngx.DEBUG, "[moesif] Create new client took time - ".. tostring(end_client_time - create_client_time).." for pid - ".. ngx.worker.pid())
    end
    return httpc
end

function _M.get_request(httpc, conf, url_path)

    -- Set a timeout for the request (in milliseconds)
    httpc:set_timeout(conf.connect_timeout)

    return httpc:request_uri(conf.api_endpoint..url_path, {
            method = "GET",
            headers = {
                ["Connection"] = "Keep-Alive",
                ["X-Moesif-Application-Id"] = conf.application_id
            },
        })
end

function _M.post_request(httpc, conf, url_path, body, isCompressed)

    local headers = {}
    headers["Connection"] = "Keep-Alive"
    headers["Content-Type"] = "application/json"
    headers["X-Moesif-Application-Id"] = conf.application_id
    headers["User-Agent"] = "kong-plugin-moesif/"..plugin_version
    headers["Content-Length"] = #body
    if isCompressed then 
        headers["Content-Encoding"] = "deflate"
    end

    -- Set a timeout for the request (in milliseconds)
    httpc:set_timeout(conf.send_timeout)

    return httpc:request_uri(conf.api_endpoint..url_path, {
        method = "POST",
        body = body,
        headers = headers,
        keepalive_timeout = keepalive_timeout-- 10min
    })
end

return _M