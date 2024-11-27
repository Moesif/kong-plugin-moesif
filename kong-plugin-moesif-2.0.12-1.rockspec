package = "kong-plugin-moesif"  -- TODO: rename, must match the info in the filename of this rockspec!
                                -- as a convention; stick to the prefix: `kong-plugin-`
version = "2.0.12-1"        -- TODO: renumber, must match the info in the filename of this rockspec!
-- The version '2.0.12' is the source code version, the trailing '1' is the version of this rockspec.
-- whenever the source version changes, the rockspec should be reset to 1. The rockspec version is only
-- updated (incremented) when this file changes, but the source remains the same.

-- TODO: This is the name to set in the Kong configuration `custom_plugins` setting.
-- Here we extract it from the package name.
local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "moesif"

supported_platforms = {"linux", "macosx"}
source = {
  url = "git://github.com/Moesif/kong-plugin-moesif/",
  tag = "2.0.12"
}

description = {
  summary = "Moesif plugin for kong",
  homepage = "http://moesif.com",
  license = "MIT"
}

dependencies = {
  "lua-resty-http",
  "lua-zlib"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.moesif.handler"] = "kong/plugins/moesif/handler.lua",
    ["kong.plugins.moesif.governance_helpers"] = "kong/plugins/moesif/governance_helpers.lua",
    ["kong.plugins.moesif.moesif_gov"] = "kong/plugins/moesif/moesif_gov.lua",
    ["kong.plugins.moesif.schema"] = "kong/plugins/moesif/schema.lua",
    ["kong.plugins.moesif.regex_config_helpers"] = "kong/plugins/moesif/regex_config_helpers.lua",
    ["kong.plugins.moesif.log"] = "kong/plugins/moesif/log.lua",
    ["kong.plugins.moesif.moesif_ser"] = "kong/plugins/moesif/moesif_ser.lua",
    ["kong.plugins.moesif.helpers"] = "kong/plugins/moesif/helpers.lua",
    ["kong.plugins.moesif.connection"] = "kong/plugins/moesif/connection.lua",
    ["kong.plugins.moesif.client_ip"] = "kong/plugins/moesif/client_ip.lua",
    ["kong.plugins.moesif.zzlib"] = "kong/plugins/moesif/zzlib.lua",
    ["kong.plugins.moesif.base64"] = "kong/plugins/moesif/base64.lua"
  }
}
