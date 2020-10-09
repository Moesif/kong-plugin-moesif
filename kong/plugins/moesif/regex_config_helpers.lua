local _M = {}

-- Function to perform the regex matching with event value and condition value
-- @param  `event_value`     Value associated with event (request)
-- @param  `condition_value` Value associated with the regex config condition
-- @param  `regex_matched`   Boolean flag with regex matched from previous regex config condition
-- @return `regex_matched`   Boolean flag to determine if the regex match was successful 
local function regex_match (event_value, condition_value, regex_matched)
    -- Perform regex match between event value and regex config condition value
    if string.match(event_value, condition_value) then 
        if regex_matched == nil then 
            regex_matched = true
        else
            regex_matched = (regex_matched and true) 
        end 
    else
        if regex_matched == nil then 
            regex_matched = false
        else
            regex_matched = (regex_matched and false)
        end 
    end
    return regex_matched
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
            -- Check if the path does not exists already in the table (when multiple path like request.route exist in the conditions) 
            if condition_table[condition["path"]] ~= nil then 
                -- Create a table to hold the existing values
                local append_value = {}
                -- Check if the path if of type table
                if type(condition_table[condition["path"]]) == "table" then
                    -- Iterate through the path values and append value 
                    for _, value in ipairs(condition_table[condition["path"]]) do 
                        table.insert(append_value, value)
                    end
                else 
                    -- Append existing value to the table
                    table.insert(append_value, condition_table[condition["path"]])
                end
                -- Append new value to the existing values
                table.insert(append_value, condition["value"])
                -- Add condition path -> values (new and existing value) to the condition table
                condition_table[condition["path"]] = append_value
            else
                -- Add condition path -> value to the condition table
                condition_table[condition["path"]] = condition["value"]
            end
        end

        -- Iterate through conditions table and perform `and` operation between each conditions
        for path, values in pairs(condition_table) do 
            -- Check if the path exists in the request config mapping
            if request_config_mapping[path] ~= nil then 
                -- Fetch the value of the path in request config mapping
                local event_data = request_config_mapping[path]
                -- Check if the condition values is of type table and not nil
                if type(values) == 'table' and next(values) ~= nil then 
                    -- Iterate through all the values and perform regex matching with event value
                    for _, value in pairs(values) do 
                        regex_matched = regex_match(event_data, value, regex_matched)
                    end 
                else 
                    -- Perform regex matching with event value
                    regex_matched = regex_match(event_data, values, regex_matched)
                end         
            else 
                -- Path does not exists, so regex condition not matched, performing `and` operation with previous condition
                regex_matched = (regex_matched and false)
            end

            -- If regex conditions matched, return sample rate and block request (true)
            if regex_matched then 
                return sample_rate, true
            end
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

-- Function to prepare request config mapping 
-- @param  `request_verb`       Request verb
-- @param  `request_uri`        Request uri
-- @param  `request_ip_address` Request ip address
-- @return `config_mapping`     Request config mapping
function _M.prepare_request_config_mapping(request_verb, request_uri, request_ip_address)
    local config_mapping = {
        ["request"] = {
          ["verb"]= request_verb,
          ["uri"] = request_uri,
          ["ip_address"] = request_ip_address,
        },
        ["response"] = {}
      }
      return config_mapping
end

-- Function to prepare config mapping
-- @param  `message`      Message to be logged
-- @return `regex_conifg` Regex config mapping
function _M.prepare_config_mapping(message)
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

    return regex_config
end 

return _M
