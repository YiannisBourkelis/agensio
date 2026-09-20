#include "control/settings.hpp"

#include <algorithm>
#include <cctype>
#include <stdexcept>

namespace agensio::control {

const std::vector<SettingDef>& setting_defs() {
    static const std::vector<SettingDef> defs = {
        {"max_body_size", "size", "bytes", "The largest request body this site accepts (413 above); what a media upload may be.",
         "agensio reload (the request limit) and a php-fpm reload (the pool's upload sizes)", "upload_max_filesize, post_max_size", {}, false},
        {"memory_limit", "size", "bytes", "PHP memory_limit of the site's pool.", "agensio reload and a php-fpm reload", "", {}, true},
        {"max_execution_time", "int", "seconds", "PHP max_execution_time of the site's pool.", "agensio reload and a php-fpm reload", "", {}, true},
        {"max_input_time", "int", "seconds", "PHP max_input_time of the site's pool (how long an upload may take to arrive).", "agensio reload and a php-fpm reload", "", {}, true},
        {"children", "int", "count", "pm.max_children: how many PHP requests run at once for this site.", "agensio reload and a php-fpm reload", "the FastCGI connection budget per worker", {}, true},
        {"pm", "enum", "", "php-fpm process manager: static keeps every child, dynamic and ondemand start them as needed.", "agensio reload and a php-fpm reload", "", {"static", "dynamic", "ondemand"}, true},
        {"max_requests", "int", "count", "pm.max_requests: a child is recycled after this many requests (0 = never).", "agensio reload and a php-fpm reload", "", {}, true},
    };
    return defs;
}

std::string size_text(std::size_t bytes) {
    const std::size_t kb = 1024, mb = kb * 1024, gb = mb * 1024;
    if (bytes >= gb && bytes % gb == 0) return std::to_string(bytes / gb) + "GB";
    if (bytes >= mb && bytes % mb == 0) return std::to_string(bytes / mb) + "MB";
    if (bytes >= kb && bytes % kb == 0) return std::to_string(bytes / kb) + "KB";
    return std::to_string(bytes);
}

namespace {

struct Bounds {
    std::size_t min = 0, max = 0;  // sizes in bytes, counts as numbers
    std::size_t built_in = 0;      // the value a site gets without setting it
};

Bounds bounds_of(const SettingDef& d, const Config& cfg) {
    const auto& lim = cfg.control.site_limits;
    const std::string_view k = d.key;
    if (k == "max_body_size") return {1, lim.max_body_size, cfg.max_body_size};
    if (k == "memory_limit") return {16u * 1024 * 1024, lim.memory_limit, parse_size(PhpPool{}.memory_limit)};
    if (k == "max_execution_time") return {1, lim.max_execution_time, PhpPool{}.max_execution_time};
    if (k == "max_input_time") return {1, lim.max_input_time, PhpPool{}.max_input_time};
    if (k == "children") return {1, lim.children, PhpPool{}.children};
    if (k == "max_requests") return {0, lim.max_requests, PhpPool{}.max_requests};
    return {};
}

bool parse_number(const json::Value& v, std::size_t& out) {
    if (v.type() == json::Value::Type::number) {
        if (v.num() < 0 || v.num() != static_cast<double>(static_cast<long long>(v.num()))) return false;
        out = static_cast<std::size_t>(v.num());
        return true;
    }
    if (v.is_string()) {
        const std::string& s = v.str();
        if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) return false;
        out = static_cast<std::size_t>(std::stoull(s));
        return true;
    }
    return false;
}

bool parse_size_value(const json::Value& v, std::size_t& out) {
    if (v.type() == json::Value::Type::number) return parse_number(v, out);
    if (!v.is_string()) return false;
    try {
        out = parse_size(v.str());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

std::string value_text(const SettingDef& d, std::size_t n) {
    return std::string_view(d.type) == "size" ? size_text(n) : std::to_string(n);
}

}  // namespace

std::string apply_settings(const json::Value& given, const Config& cfg, bool has_user, json::Value& out) {
    if (given.is_null()) return "";
    if (!given.is_object()) return "settings must be an object {key: value}; `settings` (agensio ctl settings) lists the keys";
    out = json::Value::object();
    for (const auto& m : given.members()) {
        const SettingDef* def = nullptr;
        for (const auto& d : setting_defs())
            if (m.first == d.key) def = &d;
        if (!def) return "unknown setting '" + m.first + "': only the keys `settings` lists can be set through the control plane; anything else stays in the configuration file";
        if (def->pool && !has_user) return "settings." + m.first + " needs a site with its own user (it belongs to the generated php-fpm pool)";
        if (std::string_view(def->type) == "enum") {
            if (!m.second.is_string()) return "settings." + m.first + " must be one of the listed values";
            std::string v = m.second.str();
            std::transform(v.begin(), v.end(), v.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (std::find(def->options.begin(), def->options.end(), v) == def->options.end()) {
                std::string opts;
                for (const char* o : def->options) opts += (opts.empty() ? "" : ", ") + std::string(o);
                return "settings." + m.first + ": '" + m.second.str() + "' is not one of " + opts;
            }
            out.set(m.first, v);
            continue;
        }
        const Bounds b = bounds_of(*def, cfg);
        std::size_t n = 0;
        const bool ok = std::string_view(def->type) == "size" ? parse_size_value(m.second, n) : parse_number(m.second, n);
        if (!ok) return "settings." + m.first + ": not a " + (std::string_view(def->type) == "size" ? "size (e.g. \"200MB\", \"512M\")" : "whole number");
        if (n < b.min) return "settings." + m.first + ": " + value_text(*def, n) + " is below the minimum " + value_text(*def, b.min);
        if (n > b.max) return "settings." + m.first + ": " + value_text(*def, n) + " is above the ceiling " + value_text(*def, b.max) + " set by [control] site_limits (root raises it in the configuration file)";
        if (std::string_view(def->type) == "size") out.set(m.first, size_text(n));
        else out.set(m.first, static_cast<double>(n));
    }
    return "";
}

json::Value effective_settings(const SiteConfig& site, const Config& cfg) {
    json::Value out = json::Value::object();
    const PhpPool defaults;
    auto put = [&](const char* key, json::Value value, const char* source) {
        out.set(key, json::Value::object().set("value", std::move(value)).set("source", source));
    };
    put("max_body_size", size_text(body_limit_of(site, cfg)), site.max_body_size ? "site" : "server");
    if (!site.pool.generated) return out;  // the pool keys exist only with a generated pool
    const PhpPool& p = site.pool;
    put("memory_limit", size_text(parse_size(p.memory_limit)), p.memory_limit != defaults.memory_limit ? "site" : "default");
    put("max_execution_time", static_cast<double>(p.max_execution_time), p.max_execution_time != defaults.max_execution_time ? "site" : "default");
    put("max_input_time", static_cast<double>(p.max_input_time), p.max_input_time != defaults.max_input_time ? "site" : "default");
    put("children", static_cast<double>(p.children), p.children != defaults.children ? "site" : "default");
    put("pm", p.pm, p.pm != defaults.pm ? "site" : "default");
    put("max_requests", static_cast<double>(p.max_requests), p.max_requests != defaults.max_requests ? "site" : "default");
    return out;
}

json::Value settings_catalog(const Config& cfg, const SiteConfig* site) {
    json::Value list = json::Value::array();
    const json::Value current = site ? effective_settings(*site, cfg) : json::Value();
    for (const auto& d : setting_defs()) {
        json::Value v = json::Value::object().set("key", d.key).set("type", d.type).set("unit", d.unit).set("meaning", d.meaning);
        if (std::string_view(d.type) == "enum") {
            json::Value opts = json::Value::array();
            for (const char* o : d.options) opts.push(o);
            v.set("options", opts).set("default", PhpPool{}.pm);
        } else {
            const Bounds b = bounds_of(d, cfg);
            const bool size = std::string_view(d.type) == "size";
            v.set("default", size ? json::Value(size_text(b.built_in)) : json::Value(static_cast<double>(b.built_in)))
                .set("default_from", std::string_view(d.key) == "max_body_size" ? "[server] max_body_size" : "built in")
                .set("minimum", size ? json::Value(size_text(b.min)) : json::Value(static_cast<double>(b.min)))
                .set("maximum", size ? json::Value(size_text(b.max)) : json::Value(static_cast<double>(b.max)))
                .set("maximum_from", "[control] site_limits");
            if (size) v.set("spellings", "\"200MB\", \"512M\", \"1GB\" or bytes");
        }
        v.set("applies", d.applies).set("derives", d.derives).set("needs_user", d.pool);
        if (site && !current[d.key].is_null()) v.set("current", current[d.key]["value"]).set("source", current[d.key]["source"]);
        list.push(std::move(v));
    }
    json::Value out = json::Value::object().set("settings", std::move(list))
                          .set("note", "site-create and site-update take these as settings = {key: value}; every value moves within the ceiling [control] site_limits sets, which only the configuration file changes. PHP ini keys outside this list (extra, open_basedir, ...) are never settable through the control plane.");
    if (site) out.set("site", site->server_names.front());
    return out;
}

}  // namespace agensio::control
