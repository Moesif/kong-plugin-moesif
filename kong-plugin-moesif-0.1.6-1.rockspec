package = "kong-plugin-moesif"  -- TODO: rename, must match the info in the filename of this rockspec!
                                  -- as a convention; stick to the prefix: `kong-plugin-`
version = "0.1.6-1"               -- TODO: renumber, must match the info in the filename of this rockspec!
-- The version '0.1.6' is the source code version, the trailing '1' is the version of this rockspec.
-- whenever the source version changes, the rockspec should be reset to 1. The rockspec version is only
-- updated (incremented) when this file changes, but the source remains the same.

-- TODO: This is the name to set in the Kong configuration `custom_plugins` setting.
-- Here we extract it from the package name.
local pluginName = package:match("^kong%-plugin%-(.+)$")  -- "moesif"

supported_platforms = {"linux", "macosx"}
source = {
  url = "git://github.com/Moesif/kong-plugin-moesif/",
  tag = "0.1.6"
}

description = {
  summary = "Moesif plugin for kong",
  homepage = "http://moesif.com",
  license = "MIT"
}

dependencies = {
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.moesif.handler"] = "kong/plugins/moesif/handler.lua",
    ["kong.plugins.moesif.schema"] = "kong/plugins/moesif/schema.lua",
    ["kong.plugins.moesif.log"] = "kong/plugins/moesif/log.lua",
    ["kong.plugins.moesif.moesif_ser"] = "kong/plugins/moesif/moesif_ser.lua"
  }
}
