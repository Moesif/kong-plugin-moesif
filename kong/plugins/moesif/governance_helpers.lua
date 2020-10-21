local _M = {}
local cjson = require "cjson"
local helper = require "kong.plugins.moesif.helpers"
local connect = require "kong.plugins.moesif.connection"
local string_format = string.format
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
governance_rules_etags = {}
governance_rules_hashes = {}
regex_governance_rules_hashes = {}

-- Get Governance Rules function
-- @param hash_key   Hash key of the config application Id
-- @param `conf`     Configuration table, holds http endpoint details
function _M.get_governance_rules(hash_key, conf)

    local rules_socket = ngx.socket.tcp()
    rules_socket:settimeout(conf.connect_timeout)
  
    -- Fetch governance rules
    local sock, parsed_url = connect.get_connection("/v1/rules", conf, rules_socket)

    if type(rules_socket) == "table" and next(rules_socket) ~= nil then

        -- Prepare the payload
        local payload = string_format("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\n",
                                        "GET", parsed_url.path, parsed_url.host, conf.application_id)

        -- Send the request
        local ok, err = rules_socket:send(payload .. "\r\n")
        if not ok then
            if conf.debug then 
                ngx_log(ngx_log_ERR, "[moesif] failed to send data to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
            end
        else
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] Successfully send request to fetch the governance rules " , ok)
            end
        end

        -- Read the response
        local governance_rules_response = helper.read_socket_data(rules_socket, conf)

        if governance_rules_response ~= nil and governance_rules_response ~= '' then 

            ok, err = rules_socket:setkeepalive(conf.keepalive)
            if not ok then
                if conf.debug then
                    ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
                end

                local close_ok, close_err = rules_socket:close()
                if not close_ok then
                    if conf.debug then
                        ngx_log(ngx_log_ERR,"[moesif] Failed to manually close socket connection ", close_err)
                    end
                else
                    if conf.debug then
                        ngx_log(ngx.DEBUG,"[moesif] success closing socket connection manually ")
                    end
                end
            else
                if conf.debug then
                    ngx_log(ngx.DEBUG,"[moesif] success keep-alive", ok)
                end
            end

            -- Get the governance rules
            local governance_rules = {}
            local regex_rules = {}
            local response_body = cjson.decode(governance_rules_response:match("(%[.*])"))
            for k, rule in pairs(response_body) do
                governance_rules[rule["_id"]] = rule
                 -- Filter governance rules of type regex
                 if rule["type"] ~= nil and rule["type"] == "regex" then
                    regex_rules[rule["_id"]] = rule
                end
            end

            -- Save the governance rule in the dictionary
            if type(governance_rules) == "table" and next(governance_rules) ~= nil then
                governance_rules_hashes[hash_key] = governance_rules
                 -- Save the governance rules of type regex in the dictionary
                 regex_governance_rules_hashes[hash_key] = regex_rules
            end

            -- Read the Response tag
            local rules_etag = string.match(governance_rules_response, "Tag%s*:%s*(.-)\n")
            governance_rules_etags[hash_key] = rules_etag
        end
    end
end

return _M
