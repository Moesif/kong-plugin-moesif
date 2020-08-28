local _M = {}
local governance_rules_hashes = {}
local ngx_timer_at = ngx.timer.at
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local ngx_md5 = ngx.md5
local connect = require "kong.plugins.moesif.connection"
local helper = require "kong.plugins.moesif.helpers"
local log = require "kong.plugins.moesif.log"
local string_format = string.format
local req_get_headers = ngx.req.get_headers
local cjson = require "cjson"
local governance_rules_etags = {}
local fetch_governance_rules = {}
local socket = require "socket"

-- Get Governance Rules function
-- @param `premature`
-- @param hash_key   Hash key of the config application Id
-- @param `conf`     Configuration table, holds http endpoint details
function get_governance_rules(premature, hash_key, conf)
    if premature then
    return
    end

    local sock, parsed_url = connect.get_connection("/v1/rules", conf)

    -- Prepare the payload
    local payload = string_format("%s %s HTTP/1.1\r\nHost: %s\r\nConnection: Keep-Alive\r\nX-Moesif-Application-Id: %s\r\n",
                                  "GET", parsed_url.path, parsed_url.host, conf.application_id)

    -- Send the request
    local ok, err = sock:send(payload .. "\r\n")
    if not ok then
        -- Set fetch_governance_rule to true, to be able to fetch governance rule next time
        fetch_governance_rules[hash_key] = true
        if conf.debug then 
            ngx_log(ngx_log_ERR, "[moesif] failed to send data to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
        end
    else
        if conf.debug then
            ngx_log(ngx.DEBUG, "[moesif] Successfully send request to fetch the governance rules " , ok)
        end
    end

    -- Read the response
    local governance_rules_response = helper.read_socket_data(sock)

    ok, err = sock:setkeepalive(conf.keepalive)
    if not ok then
        -- Set fetch_governance_rule to true, to be able to fetch governance rule next time
        fetch_governance_rules[hash_key] = true
        if conf.debug then
            ngx_log(ngx_log_ERR, "[moesif] failed to keepalive to " .. parsed_url.host .. ":" .. tostring(parsed_url.port) .. ": ", err)
        end

        local close_ok, close_err = sock:close()
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
    local response_body = cjson.decode(governance_rules_response:match("(%[.*])"))
    for k, rule in pairs(response_body) do
        governance_rules[rule["_id"]] = rule
    end

    -- Save the governance rule in the dictionary
    if type(governance_rules) == "table" and next(governance_rules) ~= nil then
        governance_rules_hashes[hash_key] = governance_rules
    end

    -- Read the Response tag
    local rules_etag = string.match(governance_rules_response, "Tag%s*:%s*(.-)\n")
    governance_rules_etags[hash_key] = rules_etag

    -- Get app config
    log.get_config_for_rules(conf)

    -- Set fetch_governance_rule to true, to be able to fetch governance rule next time
    fetch_governance_rules[hash_key] = true
end


-- Fetch governance rule of the entity for which block is true
-- @param `entity_rules`      List of entity rules
-- @param `governance_rules`  List of governance rules
function fetch_entity_governance_rule(entity_rules, governance_rules)
    for _, rule in pairs(entity_rules) do
        local rule_id = rule["rules"]
        if rule_id ~= nil and governance_rules[rule_id] ~= nil then 
            if governance_rules[rule_id]["block"] then 
                return rule
            end
        end
    end
end

-- Replace body value in the response body for the short-circuited request
-- @param `body_table`    Response Body
-- @param `rule_values`   Governance Rule values
function transformValues(body_table, rule_values)
    if type(body_table) == "string" then
        return body_table:gsub("{{%d+}}", rule_values)
    elseif type(body_table) == "table" and next(body_table) ~= nil then 
        local updated_body_table = {}
        for k,v in pairs(body_table) do updated_body_table[k]=v end

        for key, headerValue in pairs(updated_body_table) do 
            if type(headerValue) == "string" then 
                updated_body_table[key] = headerValue:gsub("{{%d+}}", rule_values)
            elseif type(headerValue) == "table" and next(headerValue) ~= nil then 
                local updatedBody = transformValues(headerValue, rule_values)
                updated_body_table[key] = updatedBody
            end
        end
        return updated_body_table
    end
end

-- Check if need to block request based on the governance rule of the entity associated with the request
-- @param `hash_key`    Hash key of the config application Id
-- @param `conf`        Configuration table, holds http endpoint details
-- @param `rule_name`   User or Company 
-- @param `entity_id`   User or Company Id associated with the reqeust
function block_request_based_on_entity_governance_rule(hash_key, conf, rule_name, entity_id, start_access_phase_time)
    if governance_rules_hashes[hash_key] ~= nil and type(governance_rules_hashes[hash_key]) == "table" and next(governance_rules_hashes[hash_key]) ~= nil 
        and conf[rule_name] ~= nil and conf[rule_name][entity_id] ~= nil then 

        -- Fetch all the available governance rules
        local governance_rules = governance_rules_hashes[hash_key]
        -- Fetch all the rules applied to an entity
        local entity_rules = conf[rule_name][entity_id]
        -- Fetch governance rule where block is true
        local entity_rule = fetch_entity_governance_rule(entity_rules, governance_rules)

        if entity_rule ~= nil then 
            local rule_id = entity_rule["rules"]
            local governance_rule = governance_rules[rule_id]
            --local is_block = governance_rule["block"]
            -- is_block and 

            -- Check if response, response status and headers are not nil
            if governance_rule["response"] ~= nil and governance_rule["response"]["status"] ~= nil 
                and governance_rule["response"]["headers"] ~=nil then
                
                -- Response status
                local gr_status = governance_rule["response"]["status"]
                -- Response headers
                local gr_headers = governance_rule["response"]["headers"]
                
                local updated_gr_headers = {}
                if gr_headers ~= nil then 
                    for k,v in pairs(gr_headers) do updated_gr_headers[k]=v end
                end

                -- Response body
                local gr_body
                if governance_rule["response"]["body"] ~= nil then
                    gr_body =governance_rule["response"]["body"]
                end

                local updated_gr_body
                if type(gr_body) == "string" then
                    updated_gr_body = gr_body
                elseif type(gr_body) == "table" and next(gr_body) ~= nil then 
                    updated_gr_body = {}
                    for k,v in pairs(gr_body) do updated_gr_body[k]=v end
                end

                -- Entity rule values
                local rule_values = entity_rule["values"]

                local updated_rule_values = {}
                if rule_values ~= nil then 
                    for k,v in pairs(rule_values) do updated_rule_values["{{"..k.."}}"]=v end
                end

                -- Check if rule_values is table and not empty
                if rule_values ~= nil and type(updated_gr_headers) == "table" and next(updated_gr_headers) ~= nil then
                    -- Replace headers
                    for headerName, headerValue in pairs(updated_gr_headers) do
                        updated_gr_headers[headerName] = headerValue:gsub("{{%d+}}", updated_rule_values)
                    end
                    -- Replace body
                    updated_gr_body = transformValues(updated_gr_body, updated_rule_values)
                end 
                -- Add blocked_by field to the event to determine the rule by which the event was blocked
                conf["blocked_by"] = rule_id

                local end_access_phase_time = socket.gettime()*1000
                ngx.log(ngx.DEBUG, "[moesif] access phase took time for blocking request - ".. tostring(end_access_phase_time - start_access_phase_time))

                return kong.response.exit(gr_status, updated_gr_body, updated_gr_headers)
            else 
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as governance rule response is not set for the entity Id -  "..entity_id)
                end
                return nil
            end
        else 
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as no governance rule found or for none of the governance rule block is set to true for the entity Id - "..entity_id)
            end
            return nil
        end
    else
        if conf.debug then 
            ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as Entity rules are empty or no governance rules defined for entity Id - "..entity_id)
        end
        return nil
    end
end

function _M.govern_request(ngx, conf, start_access_phase_time)

    -- Hash key of the config application Id
    local hash_key = ngx_md5(conf.application_id)
    local user_id_entity
    local company_id_entity
    local request_headers = req_get_headers()

    -- Set fetch_governance_rule to true (default), to be able to fetch governance rule
    if fetch_governance_rules[hash_key] == nil then
        fetch_governance_rules[hash_key] = true
    end

    -- Fetch the governance rules
    if (governance_rules_etags[hash_key] == nil or (conf["rulesETag"] ~= governance_rules_etags[hash_key])) and fetch_governance_rules[hash_key] then
        -- Set fetch_governance_rule to false, to avoid fetching governance rule
        fetch_governance_rules[hash_key] = false

        local gr_ok, gr_err = ngx_timer_at(0, get_governance_rules, hash_key, conf)
        if not gr_ok then
            -- Set fetch_governance_rule to true, to be able to fetch governance rule next time
            fetch_governance_rules[hash_key] = true
            if conf.debug then 
                ngx_log(ngx_log_ERR, "[moesif] failed to get governance rules ", gr_err)
            end
        else
            if conf.debug then 
                ngx_log(ngx.DEBUG, "[moesif] successfully fetched the governance rules " , gr_ok)
            end
        end
    end

    -- Fetch the user details
    if request_headers[conf.user_id_header] ~= nil then
        user_id_entity = tostring(request_headers[conf.user_id_header])
    elseif request_headers["x-consumer-custom-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-custom-id"])
    elseif request_headers["x-consumer-username"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-username"])
    elseif request_headers["x-consumer-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-id"])
    else
        user_id_entity = nil
    end

    -- Fetch the company details
    if request_headers[conf.company_id_header] ~= nil then
        company_id_entity = tostring(request_headers[conf.company_id_header])
    else 
        company_id_entity = nil
    end

    -- Set entity in conf to use downstream
    conf["user_id_entity"] = user_id_entity
    conf["company_id_entity"] = company_id_entity

    if governance_rules_hashes[hash_key] ~= nil and type(governance_rules_hashes[hash_key]) == "table" and next(governance_rules_hashes[hash_key]) ~= nil then
        -- Check if need to block request based on user governance rule
        if user_id_entity ~= nil then 
            local sc_user_req = block_request_based_on_entity_governance_rule(hash_key, conf, "user_rules", user_id_entity, start_access_phase_time)
            if sc_user_req == nil then 
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the user Id - " .. user_id_entity)
                end
            end
        end
        -- Check if need to block request based on company governance rule
        if company_id_entity ~= nil then 
            local sc_company_req = block_request_based_on_entity_governance_rule(hash_key, conf, "company_rules", company_id_entity, start_access_phase_time)
            if sc_company_req == nil then 
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the company Id - " .. company_id_entity)
                end
            end
        end
    end

    if conf.debug then
        ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as no governance rules found for the entity associated with the request.")
    end
    return nil
end

return _M
