// Per-site settings through the control plane (F10): an allowlist of named, typed
// resource limits, each moving within a ceiling the root-owned configuration sets
// ([control] site_limits). One table drives what site-create/site-update accept, what the
// catalogue advertises (`settings`, the MCP tool site_settings_list) and the MCP schema,
// so the three cannot drift. Nothing here can widen a site's authority: no ini map, no
// open_basedir, no path; those stay in the file, root's.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "services/json.hpp"

namespace agensio::control {

struct SettingDef {
    const char* key;      // as passed to site-update's `settings`
    const char* type;     // "size" | "int" | "enum"
    const char* unit;     // "bytes" | "seconds" | "count" | ""
    const char* meaning;  // one line
    const char* applies;  // what changing it costs
    const char* derives;  // what is computed from it ("" = nothing)
    std::vector<const char*> options;  // enum values
    bool pool = true;     // a generated-pool key: needs a site with its own user
};

const std::vector<SettingDef>& setting_defs();

// Reads `given` (an object {key: value}) against the table and the ceilings: "" and
// `out` filled with normalised values (sizes as canonical strings such as "200MB",
// counts as numbers, enums lower-case) or the first refusal, naming the key, the value
// and the ceiling. Unknown keys are refused by name.
std::string apply_settings(const json::Value& given, const Config& cfg, bool has_user, json::Value& out);

// The catalogue: every setting with type, unit, meaning, default, minimum, maximum,
// applies, derives, and, with a site, its effective value and where it comes from.
json::Value settings_catalog(const Config& cfg, const SiteConfig* site);

// {key: {"value": ..., "source": "site" | "server" | "default"}} for site-show.
json::Value effective_settings(const SiteConfig& site, const Config& cfg);

// A size as the control plane prints it: "200MB", "512KB", "1GB", or bytes.
std::string size_text(std::size_t bytes);

}  // namespace agensio::control
