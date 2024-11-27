local _M = {}
local cjson = require "cjson"
local helper = require "kong.plugins.moesif.helpers"
local connect = require "kong.plugins.moesif.connection"
local string_format = string.format
local ngx_log = ngx.log
local ngx_log_ERR = ngx.ERR
local http = require "resty.http"
governance_rules_hashes = {}
regex_governance_rules_hashes = {}
governance_rules_etags = {}
graphQlRule_hashes = {}

RuleType = {
    USER = "user",
    COMPANY = "company",
    REGEX = "regex"
}

function dump(o)
    if type(o) == 'table' then
       local s = '{ '
       for k,v in pairs(o) do
          if type(k) ~= 'number' then k = '"'..k..'"' end
          s = s .. '['..k..'] = ' .. dump(v) .. ','
       end
       return s .. '} '
    else
       return tostring(o)
    end
  end

-- Get Governance Rules function
-- @param hash_key   Hash key of the config application Id
-- @param `conf`     Configuration table, holds http endpoint details
function _M.get_governance_rules(hash_key, conf)


    -- Fetch governance rules
    local httpc = http.new()

    -- Prepare the payload, Send the request, and Read the response
    local governance_rules_response, governance_rules_error = httpc:request_uri(conf.api_endpoint.."/v1/rules", {
        method = "GET",
        headers = {
            ["Connection"] = "Keep-Alive",
            ["X-Moesif-Application-Id"] = conf.application_id
        },
    })

    ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK GOV RULES REPONSE - " , dump(governance_rules_response))
    ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK GOV RULES REPONSE ERR - " , dump(governance_rules_error))

    if governance_rules_response ~= nil and governance_rules_response ~= '' then 

        local regex_rules = {}
        local identified_user_rules = {}
        local unidentified_user_rules = {}
        local identified_company_rules = {}
        local unidentified_company_rules = {}
        -- Get the governance rules
        local response_body = cjson.decode(governance_rules_response.body) -- governance_rules_response:match("(%[.*])")
        
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK GOV RULES REPONSE BODY - " , dump(response_body))

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
        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK GOV RULES HEADERS  - " , dump(governance_rules_response.headers))
        local rules_etag =  governance_rules_response.headers["x-moesif-rules-tag"] -- string.match(governance_rules_response, "Tag%s*:%s*(.-)\n")

        ngx_log(ngx.DEBUG, "[moesif] MEMORYLEAK GOV RULES ETAG  - " , dump(rules_etag))

        governance_rules_etags[hash_key] = rules_etag
    end

end

return _M
