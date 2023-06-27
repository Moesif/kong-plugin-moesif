local _M = {}
local req_get_method = ngx.req.get_method
local ngx_log = ngx.log
local helper = require "kong.plugins.moesif.helpers"
local regex_config_helper = require "kong.plugins.moesif.regex_config_helpers"
local client_ip = require "kong.plugins.moesif.client_ip"
local req_get_headers = ngx.req.get_headers
local socket = require "socket"
local base64 = require "kong.plugins.moesif.base64"

-- Split the string by delimiter
-- @param `str`        String
-- @param `character`  Delimiter
local function split(str, character)
    local result = {}
  
    local index = 1
    for s in string.gmatch(str, "[^"..character.."]+") do
      result[index] = s
      index = index + 1
    end
  
    return result
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
function transform_values(body_table, rule_values)
    if type(body_table) == "string" then
        return body_table:gsub("{{%d+}}", rule_values)
    elseif type(body_table) == "table" and next(body_table) ~= nil then 
        local updated_body_table = {}
        for k,v in pairs(body_table) do updated_body_table[k]=v end

        for key, headerValue in pairs(updated_body_table) do 
            if type(headerValue) == "string" then
                updated_body_table[key] = headerValue:gsub("{{%d+}}", rule_values)
            elseif type(headerValue) == "table" and next(headerValue) ~= nil then 
                local updatedBody = transform_values(headerValue, rule_values)
                updated_body_table[key] = updatedBody
            end
        end
        return updated_body_table
    end
end

function get_updated_response_body_and_headers(gr_headers, gr_body, governance_rule, rule_values)
    -- Updated governance rule headers
    local updated_gr_headers = {}
    if gr_headers ~= nil then
        for k,v in pairs(gr_headers) do updated_gr_headers[k]=v end
    end

    -- Updated governance rule body
    local updated_gr_body = {}
    if type(gr_body) == "string" then
        updated_gr_body = gr_body
    elseif type(gr_body) == "table" and next(gr_body) ~= nil then
        updated_gr_body = {}
        for k,v in pairs(gr_body) do updated_gr_body[k]=v end
    end

    -- governance rule variables
    local rule_variables = governance_rule["variables"]

    -- build rule value mapping with UNKNOWN values
    local updated_rule_values = {}
    if rule_values ~= nil and rule_variables ~= nil then
        updated_rule_values = generate_update_rule_values(rule_values, rule_variables, conf)
    end

    -- Check if rule_values is table and not empty
    if rule_values ~= nil and type(updated_gr_headers) == "table" and next(updated_gr_headers) ~= nil then
        updated_gr_headers = transform_values(updated_gr_headers, updated_rule_values)
    end
    -- Replace body
    updated_gr_body = transform_values(updated_gr_body, updated_rule_values)

    return updated_gr_body, updated_gr_headers
end

function generate_update_rule_values(entity_rule_values, rule_variables, conf)
    local updated_rule_values = {}
    local ok, rule_variables_map = pcall(create_rule_variables_map, rule_variables)

    if ok then
        for k, v in pairs(rule_variables_map) do
            if entity_rule_values[k] == nil then
                updated_rule_values["{{"..k.."}}"] = "UNKNOWN"
            else
                updated_rule_values["{{"..k.."}}"] = entity_rule_values[k]
            end
        end
    else
        if conf.debug then
            ngx_log(ngx.DEBUG, "[moesif] Error when pursing governance rule variables "..rule_variables_map)
        end
    end
    return updated_rule_values
end

function create_rule_variables_map(rule_variables)
    local rule_variables_map = {}
    for _, name_and_path in pairs(rule_variables) do
        rule_variables_map[name_and_path["name"]] = name_and_path["path"]
    end
    return rule_variables_map
end

-- Fetch response status, headers, and body from the governance rule
-- @param `governance_rule`          Governance Rule
-- @return `status, headers, body`   Response status, headers, body
function fetch_governance_rule_response_details(governance_rule)
    -- Response status
    local status = governance_rule["response"]["status"]
    -- Response headers
    local headers = governance_rule["response"]["headers"]
    -- Response body
    local body
    if governance_rule["response"]["body"] ~= nil then
        body = governance_rule["response"]["body"]
    end
   return status, headers, body
end

function generate_entity_rule_values_mapping(hash_key, rule_name, entity_id, governance_rules)
    local entity_rule_values = {}
    if entity_id ~= nil then
        if entity_rules[hash_key] ~= nil and type(entity_rules[hash_key]) == "table" and next(entity_rules[hash_key]) ~= nil and
            entity_rules[hash_key][rule_name] ~= nil and entity_rules[hash_key][rule_name][entity_id] ~= nil then
            -- Fetch all the rules applied to an entity
            local entity_rules = entity_rules[hash_key][rule_name][entity_id]

            for _, rule in pairs(entity_rules) do
                local rule_id = rule["rules"]
                if rule_id ~= nil and governance_rules[rule_id] ~= nil then
                    if governance_rules[rule_id]["block"] then
                        entity_rule_values[rule_id] = rule["values"]
                    end
                end
            end
        end
    end
    return entity_rule_values
end

-- Check if need to block request based on the governance rule regex config associated with the request
-- @param `hash_key`                Hash key of the config application Id
-- @param `rule_name`               Type of rules in entity rules config [user_rules, company_rules]
-- @param `rule_id`                 Governance rule id
-- @param `conf`                    Configuration table, holds http endpoint details
-- @param `start_access_phase_time` Access phase start time
function block_request_based_on_governance_rule_regex_config(governance_rules, hash_key, rule_type, rule_id, conf, start_access_phase_time, entity_rule_type, entity_id)
   -- Fetch the governance rule
    local governance_rule = governance_rules[rule_id]
   -- Check if block is set to true
   local is_block = governance_rule["block"]
   if is_block then 
       -- Check if response, response status and headers are not nil
       if governance_rule["response"] ~= nil and governance_rule["response"]["status"] ~= nil 
       and governance_rule["response"]["headers"] ~= nil then

           -- Response status, headers, body
           local gr_status, gr_headers, gr_body = fetch_governance_rule_response_details(governance_rule)

            -- get user mapping value in collector /config rule, if user_id is null, return empty map
            local ok, entity_rule_values = pcall(generate_entity_rule_values_mapping, hash_key, entity_rule_type, entity_id, governance_rules)
            if not ok then
                ngx_log(ngx.DEBUG, "[moesif] Error when purse entity rules and values " .. entity_rule_value)
            end

           local entity_values = entity_rule_values[rule_id]
           if entity_values == nil then
                entity_values = {}
           end
           local updated_gr_body, updated_gr_headers = get_updated_response_body_and_headers(gr_headers, gr_body, governance_rule, entity_values)

           -- Add blocked_by field to the event to determine the rule by which the event was blocked
           ngx.ctx.moesif["blocked_by"] = rule_id

           local end_access_phase_time = socket.gettime()*1000
           ngx.log(ngx.DEBUG, "[moesif] access phase took time for blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. ngx.worker.pid())

           return kong.response.exit(gr_status, updated_gr_body, updated_gr_headers)
       else 
           if conf.debug then
               ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as response is not set for the governance rule with regex config")
           end
           return nil
       end
   else
       if conf.debug then
           ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as block is set to false for the governance rule with regex config")
       end
       return nil
   end
end

-- Check if need to block request based on the governance rule of the entity associated with the request
-- @param `hash_key`                Hash key of the config application Id
-- @param `conf`                    Configuration table, holds http endpoint details
-- @param `rule_name`               User or Company 
-- @param `entity_id`               User or Company Id associated with the reqeust
-- @param `start_access_phase_time` Access phase start time
-- @param `request_config_mapping`  Request config mapping associated with the request
function block_request_based_on_entity_governance_rule(governance_rules, hash_key, conf, rule_name, entity_id, start_access_phase_time, request_config_mapping)

    if governance_rules  ~= nil and type(governance_rules) == "table" and next(governance_rules) ~= nil
        and entity_rules[hash_key] ~= nil and type(entity_rules[hash_key]) == "table" and next(entity_rules[hash_key]) ~= nil and 
        entity_rules[hash_key][rule_name] ~= nil and entity_rules[hash_key][rule_name][entity_id] ~= nil then

        -- Fetch all the rules applied to an entity
        local entity_rules = entity_rules[hash_key][rule_name][entity_id]
        -- Fetch governance rule where block is true
        local entity_rule = fetch_entity_governance_rule(entity_rules, governance_rules)

        if entity_rule ~= nil then 
            local rule_id = entity_rule["rules"]
            local governance_rule = governance_rules[rule_id]

            -- Don't block if entity_rule has regex config and doesn't match
            local ok, gr_match_id = pcall(regex_config_helper.check_event_should_blocked_by_rule, governance_rule, request_config_mapping)

            if not ok then
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as entity governance rule" ..rule_id.. " fetching issue" ..gr_match_id)
                end
            else
                -- If the regex conditions does not match, skip blocking the request
                if gr_match_id == nil then
                    if conf.debug then
                        ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request as entity governance rule" ..rule_id.. " regex conditions does not match")
                    end
                    return nil
                end
            end

            -- Check if response, response status and headers are not nil
            if governance_rule["response"] ~= nil and governance_rule["response"]["status"] ~= nil 
                and governance_rule["response"]["headers"] ~= nil then
                
                -- Response status, headers, body
                local gr_status, gr_headers, gr_body = fetch_governance_rule_response_details(governance_rule)

                -- Entity rule values
                local rule_values = entity_rule["values"]

                local updated_gr_body, updated_gr_headers = get_updated_response_body_and_headers(gr_headers, gr_body, governance_rule, rule_values)

                -- Add blocked_by field to the event to determine the rule by which the event was blocked
                ngx.ctx.moesif["blocked_by"] = rule_id

                local end_access_phase_time = socket.gettime()*1000
                ngx.log(ngx.DEBUG, "[moesif] access phase took time for blocking request - ".. tostring(end_access_phase_time - start_access_phase_time).." for pid - ".. ngx.worker.pid())

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

-- Function to split token by dot(.)
function split_token(token)
    local split_token = {}
    for line in token:gsub("%f[.]%.%f[^.]", "\0"):gmatch"%Z+" do 
        table.insert(split_token, line)
    end
    return split_token
end

function get_rules(hash_key, rule_type, is_applied_to_unidentified, conf)
    local governance_rules = {}
    if rule_type == RuleType.USER or rule_type == RuleType.COMPANY then
        if governance_rules_hashes[hash_key] ~= nil and type(governance_rules_hashes[hash_key]) == "table"
        and governance_rules_hashes[hash_key][rule_type] ~= nil and type(governance_rules_hashes[hash_key][rule_type]) == "table"
        and governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified] ~= nil
        and type(governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified]) == "table" then
            governance_rules = governance_rules_hashes[hash_key][rule_type][is_applied_to_unidentified]
        else
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] No "..rule_type.. " governance rules defined [Hash key: " ..hash_key.. "]")
            end
        end

    elseif rule_type == RuleType.REGEX then
        if regex_governance_rules_hashes[hash_key] ~= nil and type(regex_governance_rules_hashes[hash_key]) == "table" and next(regex_governance_rules_hashes[hash_key]) ~= nil then
            governance_rules = regex_governance_rules_hashes[hash_key]
        else
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] No "..rule_type.. " governance rules defined [Hash key: " ..hash_key.. "]")
            end
        end

    else
        if conf.debug then
            ngx_log(ngx.DEBUG, "[moesif] rule_type " ..rule_type.. " is not defined, should be in [user, company or regex]")
        end
    end
    return governance_rules
end

function _M.govern_request(ngx, conf, start_access_phase_time)

    -- Hash key of the config application Id
    local hash_key = string.sub(conf.application_id, -10)
    local user_id_entity = nil
    local company_id_entity = nil
    local request_uri = helper.prepare_request_uri(ngx, conf)
    local request_verb = req_get_method()
    local request_headers = req_get_headers()
    local request_ip_address = client_ip.get_client_ip(request_headers)
    local request_body = ngx.ctx.moesif.req_body
    local request_config_mapping = regex_config_helper.prepare_config_mapping(regex_config_helper.prepare_request_config_mapping(request_verb, request_uri, request_ip_address, request_headers, request_body), hash_key)

    -- company id
    -- Fetch the company details
    if conf.company_id_header ~= nil and request_headers[conf.company_id_header] ~= nil then
        company_id_entity = tostring(request_headers[conf.company_id_header])
    end

    -- Fetch the user details
    if conf.user_id_header ~= nil and request_headers[conf.user_id_header] ~= nil then
        user_id_entity = tostring(request_headers[conf.user_id_header])
    elseif request_headers["x-consumer-custom-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-custom-id"])
    elseif request_headers["x-consumer-username"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-username"])
    elseif request_headers["x-consumer-id"] ~= nil then
        user_id_entity = tostring(request_headers["x-consumer-id"])
    elseif conf.authorization_header_name ~= nil and (conf.authorization_user_id_field ~= nil or (company_id_entity == nil and conf.authorization_company_id_field ~= "" and conf.authorization_company_id_field ~= nil)) then

        -- Split authorization header name by comma
        local auth_header_names = split(string.lower(conf.authorization_header_name), ",") 
        local token = nil

        -- Fetch the token and field from the config
        for _, name in pairs(auth_header_names) do
            local auth_name = name:gsub("%s+", "")
            if request_headers[auth_name] ~= nil then 
              if type(request_headers[auth_name]) == "table" and (request_headers[auth_name][0] ~= nil or request_headers[auth_name][1] ~= nil) then 
                token = request_headers[auth_name][0] or request_headers[auth_name][1]
              else
                token = request_headers[auth_name]
              end
              break
            end
        end
        local user_id_field = conf.authorization_user_id_field
        local company_id_field = conf.authorization_company_id_field

        if token ~= nil then 
            -- Check if token is of type Bearer
            if string.match(token, "Bearer") then
                -- Fetch the bearer token
                token = token:gsub("Bearer", "")
                
                -- Split the bearer token by dot(.)
                local split_token = split_token(token)
                
                -- Check if payload is not nil
                if split_token[2] ~= nil then 
                    -- Parse and set user Id
                    user_id_entity, company_id_entity = helper.parse_authorization_header(split_token[2], user_id_field, company_id_field)
                else
                    user_id_entity = nil  
                end 
            -- Check if token is of type Basic
            elseif string.match(token, "Basic") then
                -- Fetch the basic token
                token = token:gsub("Basic", "")
                -- Decode the token
                local decoded_token = base64.decode(token)
                -- Fetch the username and password
                local username, _ = decoded_token:match("(.*):(.*)")
                
                -- Set the user_id
                if username ~= nil then
                    user_id_entity = username 
                else
                    user_id_entity = nil 
                end 
            -- Check if token is of user-defined custom type
            else
                -- Split the bearer token by dot(.)
                local split_token = split_token(token)
                                
                -- Check if payload is not nil
                if split_token[2] ~= nil then 
                    -- Parse and set user Id
                    user_id_entity, company_id_entity = helper.parse_authorization_header(split_token[2], user_id_field, company_id_field)
                else
                    -- Parse and set the user_id
                    user_id_entity, company_id_entity = helper.parse_authorization_header(token, user_id_field, company_id_field)
                end 
            end
        else
            user_id_entity = nil
        end
    else
        user_id_entity = nil
    end



    -- Set entity in conf to use downstream
    if ngx.ctx.moesif["user_id_entity"] == nil and user_id_entity ~= nil then 
        ngx.ctx.moesif["user_id_entity"] = user_id_entity
        if conf.debug then
            ngx_log(ngx.DEBUG, "[moesif] User Id from governance info: " .. user_id_entity)
        end
    end
    if ngx.ctx.moesif["company_id_entity"] == nil and company_id_entity ~= nil then 
        ngx.ctx.moesif["company_id_entity"] = company_id_entity
        if conf.debug then
            ngx.log(ngx.DEBUG, "[moesif] Company Id from governance info: " .. company_id_entity)
        end
    end

    local identified_user_gov_rules = get_rules(hash_key, RuleType.USER, "identified", conf)
    -- Check if need to block request based on identified user governance rule
    if user_id_entity ~= nil and identified_user_gov_rules ~= nil and type(identified_user_gov_rules) == "table" and next(identified_user_gov_rules) ~= nil then
        local sc_user_rsp = block_request_based_on_entity_governance_rule(identified_user_gov_rules, hash_key, conf, "user_rules", user_id_entity, start_access_phase_time, request_config_mapping)
        if sc_user_rsp == nil then
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the user Id - " .. user_id_entity)
            end
        end
    end

    local unidentified_user_gov_rules = get_rules(hash_key, RuleType.USER, "unidentified", conf)
    -- Check if need to block request based on unidentified user governance rule
    if unidentified_user_gov_rules ~= nil and type(unidentified_user_gov_rules) == "table" and next(unidentified_user_gov_rules) ~= nil then
        if user_id_entity == nil then
            -- Check if the governance rule regex config matches request config mapping and fetch governance rule id
            local gr_id = regex_config_helper.fetch_governance_rule_id_on_regex_match(unidentified_user_gov_rules, request_config_mapping, conf)
            -- Check if need to block request based on governance rule regex config
            if gr_id ~= nil then
                local sc_user_regex_rsp = block_request_based_on_governance_rule_regex_config(unidentified_user_gov_rules, hash_key, RuleType.USER, gr_id, conf, start_access_phase_time, "user_rules", user_id_entity)
                if sc_user_regex_rsp == nil then
                    if conf.debug then
                        ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the unidentified user governance rule user_id - null")
                    end
                end
            end
        else
            local sc_user_unidentified_rsp = block_request_based_on_entity_governance_rule(unidentified_user_gov_rules, hash_key, conf, "user_rules", user_id_entity, start_access_phase_time, request_config_mapping)
            if sc_user_unidentified_rsp == nil then
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the unidentified user governance rule user_id - " ..user_id_entity)
                end
            end
        end
    end

    local identified_company_gov_rules = get_rules(hash_key, RuleType.COMPANY, "identified", conf)
    -- Check if need to block request based on identified company governance rule
    if company_id_entity ~= nil and identified_company_gov_rules ~= nil and type(identified_company_gov_rules) == "table" and next(identified_company_gov_rules) ~= nil then
        local sc_company_rsp = block_request_based_on_entity_governance_rule(identified_company_gov_rules, hash_key, conf, "company_rules", company_id_entity, start_access_phase_time, request_config_mapping)
        if sc_company_rsp == nil then
            if conf.debug then
                ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the company_id - " .. company_id_entity)
            end
        end
    end

    local unidentified_company_gov_rules = get_rules(hash_key, RuleType.COMPANY, "unidentified", conf)
    -- Check if need to block request based on unidentified company governance rule
    if unidentified_company_gov_rules ~= nil and type(unidentified_company_gov_rules) == "table" and next(unidentified_company_gov_rules) ~= nil then
        if company_id_entity == nil then
            -- Check if the governance rule regex config matches request config mapping and fetch governance rule id
            local gr_id = regex_config_helper.fetch_governance_rule_id_on_regex_match(unidentified_company_gov_rules, request_config_mapping, conf)
            -- Check if need to block request based on governance rule regex config
            if gr_id ~= nil then
                local sc_company_regex_rsp = block_request_based_on_governance_rule_regex_config(unidentified_company_gov_rules, hash_key, RuleType.COMPANY, gr_id, conf, start_access_phase_time, "company_rules", company_id_entity)
                if sc_company_regex_rsp == nil then
                    if conf.debug then
                        ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the unidentified company governance rule company_id - null")
                    end
                end
            end
        else
            local sc_company_unidentified_rsp = block_request_based_on_entity_governance_rule(unidentified_company_gov_rules, hash_key, conf, "company_rules", company_id_entity, start_access_phase_time, request_config_mapping)
            if sc_company_unidentified_rsp == nil then
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the unidentified company governance rule company_id - " ..company_id_entity)
                end
            end
        end
    end

    local regex_gov_rules = get_rules(hash_key, RuleType.REGEX, "unidentified", conf)
    -- Check if need to block request based on the regex governance rule
    if regex_gov_rules ~= nil and type(regex_gov_rules) == "table" and next(regex_gov_rules) ~= nil then
        -- Check if the governance rule regex config matches request config mapping and fetch governance rule id
        local gr_id = regex_config_helper.fetch_governance_rule_id_on_regex_match(regex_gov_rules, request_config_mapping, conf)
        -- Check if need to block request based on governance rule regex config
        if gr_id ~= nil then
            local sc_regex_req = block_request_based_on_governance_rule_regex_config(regex_gov_rules, hash_key, RuleType.REGEX, gr_id, conf, start_access_phase_time, nil, nil)
            if sc_regex_req == nil then
                if conf.debug then
                    ngx_log(ngx.DEBUG, "[moesif] Skipped blocking request based on the regex governance rule")
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
