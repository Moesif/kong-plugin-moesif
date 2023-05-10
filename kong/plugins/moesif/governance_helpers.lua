local _M = {}
local cjson = require "cjson"
local helper = require "kong.plugins.moesif.helpers"
local connect = require "kong.plugins.moesif.connection"
local string_format = string.format
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
governance_rules_hashes = {}
regex_governance_rules_hashes = {}
governance_rules_etags = {}
graphQlRule_hashes = {}

RuleType = {
    USER = "user",
    COMPANY = "company",
    REGEX = "regex"
}

-- Get Governance Rules function
-- @param hash_key   Hash key of the config application Id
-- @param `conf`     Configuration table, holds http endpoint details
function _M.get_governance_rules(hash_key, conf)

    local rules_socket = ngx.socket.tcp()
    rules_socket:settimeout(conf.connect_timeout)
  
    -- Fetch governance rules
    local _, parsed_url = connect.get_connection(conf.api_endpoint, "/v1/rules", conf, rules_socket)

    if type(parsed_url) == "table" and next(parsed_url) ~= nil and type(rules_socket) == "table" and next(rules_socket) ~= nil then

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

            local regex_rules = {}
            local identified_user_rules = {}
            local unidentified_user_rules = {}
            local identified_company_rules = {}
            local unidentified_company_rules = {}
            -- Get the governance rules
            local response_body = cjson.decode(governance_rules_response:match("(%[.*])"))
            local graphQLRule = false
            for _, rule in pairs(response_body) do
                if rule.block then
                    for _, regex_config in pairs(rule.regex_config) do
                        for _, condition in pairs(regex_config.conditions) do
                            if condition.path == 'request.body.query' or condition.path == 'request.body.operationName' then
                                graphQLRule = true
                                break
                            end
                        end
                    end
                end
                -- Filter governance rules of type regex, unidentified user, identified user,
                -- unidentified company, identified company
                if rule["type"] ~= nil then
                    if rule["type"] == RuleType.REGEX then
                        regex_rules[rule["_id"]] = rule
                    elseif rule["type"] == RuleType.USER and rule["applied_to_unidentified"] then
                        unidentified_user_rules[rule["_id"]] = rule
                    elseif rule["type"] == RuleType.USER and not rule["applied_to_unidentified"] then
                        identified_user_rules[rule["_id"]] = rule
                    elseif rule["type"] == RuleType.COMPANY and rule["applied_to_unidentified"] then
                        unidentified_company_rules[rule["_id"]] = rule
                    elseif rule["type"] == RuleType.COMPANY and not rule["applied_to_unidentified"] then
                        identified_company_rules[rule["_id"]] = rule
                    end
                end
            end

            regex_governance_rules_hashes[hash_key] = regex_rules
            governance_rules_hashes[hash_key] = {
                [RuleType.USER] = {
                    unidentified = unidentified_user_rules,
                    identified = identified_user_rules
                },
                [RuleType.COMPANY] = {
                    unidentified = unidentified_company_rules,
                    identified = identified_company_rules
                }
            }

            graphQlRule_hashes[hash_key] = graphQLRule

            -- Read the Response tag
            local rules_etag = string.match(governance_rules_response, "Tag%s*:%s*(.-)\n")
            governance_rules_etags[hash_key] = rules_etag
        end
    end
end

return _M
