local _M = {}
local cjson = require "cjson"

AppliedTo = {
    MATCHING = "matching",
    NOT_MATCHING = "not_matching"
}

-- Function to perform the regex matching with event value and condition value
-- @param  `event_value`     Value associated with event (request)
-- @param  `condition_value` Value associated with the regex config condition
-- @return `regex_matched`   Boolean flag to determine if the regex match was successful 
local function regex_match (event_value, condition_value)
    -- Perform regex match between event value and regex config condition value
    return string.match(event_value, condition_value)
end

-- Function to fetch the sample rate and determine if request needs to be block or not
-- @param  `gr_regex_configs`        Regex configs associated with the governance rule
-- @param  `request_config_mapping`  Config associated with the request
-- @return `sample_rate, block`      Sample rate and boolean flag (block or not)
function _M.fetch_sample_rate_block_request_on_regex_match(gr_regex_configs, request_config_mapping)
    -- Iterate through the list of governance rule regex configs
    for _, regex_rule in pairs(gr_regex_configs) do
        -- Fetch the sample rate
        local sample_rate = regex_rule["sample_rate"]
        -- Fetch the conditions
        local conditions = regex_rule["conditions"]
        -- Bool flag to determine if the regex conditions are matched
        local regex_matched = nil 
        -- Create a table to hold the conditions mapping (path and value)
        local condition_table = {}

        -- Iterate through the regex rule conditions and map the path and value
        for _, condition in pairs(conditions) do
            -- Add condition path -> value to the condition table
            condition_table[condition["path"]] = condition["value"]
        end

        -- Iterate through conditions table and perform `and` operation between each conditions
        for path, values in pairs(condition_table) do 
            -- Check if the path exists in the request config mapping
            if request_config_mapping[path] ~= nil then 
                -- Fetch the value of the path in request config mapping
                local event_data = request_config_mapping[path]
                -- Perform regex matching with event value
                regex_matched = regex_match(event_data, values)     
            else 
                -- Path does not exists in request config mapping, so no need to match regex condition rule
                regex_matched = false
            end
            
            -- If one of the rule does not match, skip the condition and avoid matching other rules for the same condition
            if not regex_matched then 
                break
            end
        end

        -- If regex conditions matched, return sample rate and block request (true)
        if regex_matched then 
            return sample_rate, true
        end
    end
    -- If regex conditions are not matched, return default sample rate (nil) and do not block request (false)
    return nil, false
end

-- Function to check if the request config mapping matches governance rule regex condtions
-- @param  `gr_regex_configs`        Regex configs associated with the governance rule
-- @param  `request_config_mapping`  Config associated with the request
-- @param  `governance_rule_id`      Governance rule id
-- @return `governance_rule_id`      Governance rule id
function _M.fetch_governance_rule_id(gr_regex_configs, request_config_mapping, governance_rule_id)
    local ok, sample_rate, block_request = pcall(_M.fetch_sample_rate_block_request_on_regex_match, gr_regex_configs, request_config_mapping)
    if ok then
        -- Check if need to block the request
        if block_request then 
            return governance_rule_id
        end
    end
    return nil
end

-- Function to fetch the governance rule id when the regex config matches mapping associated with the request
-- @param `governance_rules`       Governance rules with regex configs       
-- @param `request_config_mapping` Config associated with the request
-- @param `gr_id`                  Return the governance rule Id if regex config matches else nil
function _M.fetch_governance_rule_id_on_regex_match(governance_rules, request_config_mapping)
    -- Iterate through the governance rules 
    for id, rule in pairs(governance_rules) do
        -- Fetch the regex config from the governance rule
        local gr_regex_configs = rule["regex_config"]
        -- Check if the request config mapping matches governance rule regex condtions
        local gr_id = _M.fetch_governance_rule_id(gr_regex_configs, request_config_mapping, id)
        -- Check if the governance rule is not nil
        if gr_id ~= nil then 
            return gr_id
        end 
    end
    return nil
end

function _M.check_event_should_blocked_by_rule(governance_rule, request_config_mapping)
    local governance_rule_id = governance_rule["_id"]
    local gr_regex_configs = governance_rule["regex_config"]
    local applied_to = governance_rule["applied_to"] or AppliedTo.MATCHING

    local ok, sample_rate, matched = pcall(_M.fetch_sample_rate_block_request_on_regex_match, gr_regex_configs, request_config_mapping)
    local should_block = (matched and applied_to == AppliedTo.MATCHING) or
                        (not matched and applied_to == AppliedTo.NOT_MATCHING)

    if ok then
        -- Check if need to block the request
        if should_block then
            return governance_rule_id
        end
    end
    return nil
end

-- Function to prepare request config mapping 
-- @param  `request_verb`       Request verb
-- @param  `request_uri`        Request uri
-- @param  `request_ip_address` Request ip address
-- @return `config_mapping`     Request config mapping
function _M.prepare_request_config_mapping(request_verb, request_uri, request_ip_address, request_headers, request_body)
    local config_mapping = {
        ["request"] = {
          ["verb"]= request_verb,
          ["uri"] = request_uri,
          ["ip_address"] = request_ip_address,
          ["headers"] = request_headers,
          ["body"] = request_body
        },
        ["response"] = {}
      }
      return config_mapping
end

-- Function to prepare config mapping
-- @param  `message`      Message to be logged
-- @param  `hash_key`    hash_key of the application_id
-- @return `regex_conifg` Regex config mapping
function _M.prepare_config_mapping(message, hash_key)
    local regex_config = {}
    -- Config mapping for request.verb
    if (message["request"]["verb"] ~= nil) then 
        regex_config["request.verb"] = message["request"]["verb"]
    end 
    -- Config mapping for request.uri
    if (message["request"]["uri"] ~= nil) then 
        local extracted = string.match(message["request"]["uri"], "http[s]*://[^/]+(/[^?]+)")
        if extracted == nil then 
            extracted = '/'
        end
        regex_config["request.route"] = extracted
    end 
    -- Config mapping for request.ip_address
    if (message["request"]["ip_address"] ~= nil) then 
        regex_config["request.ip_address"] = message["request"]["ip_address"]
    end
    -- Config mapping for response.status
    if (message["response"]["status"] ~= nil) then 
        regex_config["response.status"] = message["response"]["status"]
    end
    -- graphql regex expression
    if graphQlRule_hashes[hash_key] then
        if (message["request"]["headers"] and message["request"]["headers"]["content-type"] == "application/graphql")
                and message["request"]["body"] ~= nil then
            regex_config["request.body.query"] = message["request"]["body"]
        else
            if message["request"]["body"] ~= nil and message["request"]["body"] ~= ""
                    and message["request"]["headers"]["content-type"] == "application/json" then
                -- only decode body when graphql rule is true
                local body = cjson.decode(message["request"]["body"])
                if body ~= nil and body["operationName"] ~= nil then
                    regex_config["request.body.operationName"] = body["operationName"]
                end
                if body ~= nil and body["query"] ~= nil then
                    regex_config["request.body.query"] = body["query"]
                end
            end
        end
    end

    return regex_config
end 

return _M