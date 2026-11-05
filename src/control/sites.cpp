#include "control/sites.hpp"

#include "core/access.hpp"
#include "core/refuse.hpp"
#include "core/site_fields.hpp"

#include "control/commands.hpp"

#include "control/settings.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "services/appenv.hpp"
#include "services/php_runtimes.hpp"
#include "services/pools.hpp"
#include "services/tasks.hpp"

namespace agensio::control {

namespace fs = std::filesystem;

namespace {

json::Value strings(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

std::vector<std::string> string_list(const json::Value& v) {
    std::vector<std::string> out;
    if (v.is_string()) out.emplace_back(v.str());
    for (const auto& i : v.items())
        if (i.is_string()) out.emplace_back(i.str());
    return out;
}

std::string toml_string(std::string_view s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"' || c == '\\') out.push_back('\\');
        out.push_back(c);
    }
    return out + "\"";
}

std::string toml_list(const std::vector<std::string>& v) {
    std::string out = "[";
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? ", " : "") + toml_string(v[i]);
    return out + "]";
}

bool has_key(const json::Value& v, std::string_view key) { return !v[key].is_null(); }
// A key given at all, null included (trusted_proxies: null goes back to the server's list).
bool given(const json::Value& v, std::string_view key) {
    for (const auto& [k, value] : v.members())
        if (k == key) return true;
    return false;
}

}  // namespace

json::Value SiteSpec::to_json() const {
    json::Value v = json::Value::object();
    v.set("domain", domain).set("aliases", strings(aliases)).set("https", https);
    if (https == "manual") v.set("cert", cert).set("key", key);
    v.set("redirect_http", redirect_http);
    if (!hsts.empty()) v.set("hsts", hsts);
    else if (hsts_application) v.set("hsts", "application");
    else if (hsts_decided) v.set("hsts", "none");
    if (hsts_subdomains) v.set("hsts_subdomains", true);
    if (hsts_held_until > 0) v.set("hsts_held_until", static_cast<double>(hsts_held_until));
    if (hsts_since > 0) v.set("hsts_since", static_cast<double>(hsts_since));
    v.set("hsts_decided", hsts_decided).set("user", user).set("no_user", user.empty()).set("group", group);
    if (encoded_slashes == "allow") v.set("encoded_slashes", encoded_slashes);
    if (!canonical.empty()) v.set("canonical", canonical);
    if (own_trusted_proxies) v.set("trusted_proxies", strings(trusted_proxies));
    v.set("app", app).set("root", root);
    if (!upstream.empty()) v.set("upstream", upstream);
    if (!project.empty()) v.set("project", project);
    if (!entry.empty()) v.set("entry", entry);
    if (!served_dir.empty()) v.set("served_dir", served_dir);
    if (!env_file.empty()) v.set("env_file", env_file);
    if (!php_socket.empty()) v.set("php_socket", php_socket);
    if (php_children) v.set("php_children", php_children);
    if (!php_version.empty()) v.set("php_version", php_version);
    if (settings.is_object() && !settings.members().empty()) v.set("settings", settings);
    if (rules.is_object() && !rules.members().empty()) v.set("rules", rules);
    if (!redirects.items().empty()) v.set("redirects", redirects);
    if (!response_headers.items().empty()) v.set("response_headers", response_headers);
    if (response_headers_baseline) v.set("response_headers_baseline", *response_headers_baseline);
    if (!response_headers_offer_declined.empty()) v.set("response_headers_offer_declined", strings(response_headers_offer_declined));
    if (response_compression.is_object() && !response_compression.members().empty()) v.set("response_compression", response_compression);
    if (!login_paths.empty()) v.set("login_paths", strings(login_paths));
    if (!public_archives.empty()) v.set("public_archives", strings(public_archives));
    if (!mime_types.empty()) v.set("mime_types", mime_types_json(mime_types));
    if (!access_log.empty()) v.set("access_log", access_log);
    if (!access_log_exclude_paths.empty()) v.set("access_log_exclude_paths", strings(access_log_exclude_paths));
    if (access_log_keep_days) v.set("access_log_keep_days", access_log_keep_days);
    if (!listen_plain.empty()) v.set("listen_plain", listen_plain);
    if (!listen_tls.empty()) v.set("listen_tls", listen_tls);
    return v;
}

bool SiteSpec::from_json(const json::Value& v, SiteSpec& out) {
    if (!v.is_object() || v.get("domain").empty()) return false;
    out = SiteSpec{};
    out.domain = v.get("domain");
    out.aliases = string_list(v["aliases"]);
    out.https = v.get("https");
    out.cert = v.get("cert");
    out.key = v.get("key");
    if (has_key(v, "redirect_http")) out.redirect_http = v["redirect_http"].boolean();
    if (v["hsts"].is_string()) {  // the lifetime as given, or one of the two decisions without one
        const std::string_view given = v.get("hsts");
        if (given == "application") out.hsts_application = true;
        else if (given != "none") out.hsts = given;
    }
    out.hsts_unnamed = v["hsts"].type() == json::Value::Type::boolean && v["hsts"].boolean();  // an earlier version's true
    out.hsts_subdomains = v["hsts_subdomains"].boolean();
    if (v["hsts_held_until"].type() == json::Value::Type::number && v["hsts_held_until"].num() > 0 && v["hsts_held_until"].num() < 1e15)
        out.hsts_held_until = static_cast<std::int64_t>(v["hsts_held_until"].num());
    if (v["hsts_since"].type() == json::Value::Type::number && v["hsts_since"].num() > 0 && v["hsts_since"].num() < 1e15)
        out.hsts_since = static_cast<std::int64_t>(v["hsts_since"].num());
    out.hsts_decided = v["hsts_decided"].boolean() || v["hsts"].is_string();
    // A decided no an earlier version wrote (hsts false, or none written beside hsts_decided) let the
    // application's own field through: that is "application" now (0.1.0-alpha.104), so the next
    // rendering, health's repair of a file set aside included, writes what the site did.
    if (out.hsts_decided && !v["hsts"].is_string() && !out.hsts_unnamed) out.hsts_application = true;
    out.encoded_slashes = v.get("encoded_slashes") == "allow" ? "allow" : "";
    out.canonical = v.get("canonical");
    out.own_trusted_proxies = has_key(v, "trusted_proxies");
    out.trusted_proxies = string_list(v["trusted_proxies"]);
    out.user = v.get("user");
    out.user_decided = true;
    out.no_user = out.user.empty();
    out.group = v.get("group");
    out.app = v.get("app");
    out.root = v.get("root");
    out.upstream = v.get("upstream");
    out.project = v.get("project");
    out.entry = v.get("entry");
    out.served_dir = v.get("served_dir");
    out.env_file = v.get("env_file");
    out.php_socket = v.get("php_socket");
    out.php_children = static_cast<int>(v["php_children"].num());
    out.php_version = v.get("php_version");
    if (v["settings"].is_object()) out.settings = v["settings"];
    if (v["rules"].is_object()) out.rules = v["rules"];
    if (v["redirects"].is_array()) out.redirects = v["redirects"];
    if (v["response_headers"].is_array()) out.response_headers = v["response_headers"];
    if (v["response_headers_baseline"].type() == json::Value::Type::boolean) out.response_headers_baseline = v["response_headers_baseline"].boolean();
    out.response_headers_offer_declined = string_list(v["response_headers_offer_declined"]);
    if (v["response_compression"].is_object()) out.response_compression = v["response_compression"];
    out.login_paths = string_list(v["login_paths"]);
    out.public_archives = string_list(v["public_archives"]);
    if (v["mime_types"].type() == json::Value::Type::object) (void)load_mime_types(v["mime_types"], out.mime_types, true);  // the TOML below is judged by the load
    if (out.settings["children"].type() == json::Value::Type::number) out.php_children = static_cast<int>(out.settings["children"].num());
    out.access_log = v.get("access_log");
    out.access_log_exclude_paths = string_list(v["access_log_exclude_paths"]);
    out.access_log_keep_days = static_cast<int>(v["access_log_keep_days"].num());
    if (has_key(v, "listen_plain")) out.listen_plain = v.get("listen_plain");
    if (has_key(v, "listen_tls")) out.listen_tls = v.get("listen_tls");
    return true;
}

bool valid_domain(std::string_view name) {
    if (name.empty() || name.size() > 253 || name.front() == '.' || name.back() == '.') return false;
    std::size_t label = 0;
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        if (c == '.') {
            if (label == 0 || name[i - 1] == '-') return false;
            label = 0;
            continue;
        }
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
        if (label == 0 && c == '-') return false;
        if (++label > 63) return false;
    }
    return label > 0 && name[name.size() - 1] != '-' && name.find('.') != std::string_view::npos;
}

bool valid_account(std::string_view name, std::string& why) {
    static const char* sentinels[] = {"null", "none", "nil", "undefined", "false", "true", "~", "nan", "n/a"};
    static const char* reserved[] = {"root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail", "news",
                                     "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody", "nogroup",
                                     "systemd-network", "systemd-resolve", "messagebus", "sshd", "admin", "wheel", "sudo"};
    if (name.empty()) {
        why = "empty";
        return false;
    }
    for (const char* s : sentinels)
        if (name == s) {
            why = "'" + std::string(name) + "' is a word for \"none\", not an account name; to run the site without its own account pass no_user: true (or --no-user)";
            return false;
        }
    if (name.size() > 32) {
        why = "longer than 32 characters";
        return false;
    }
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || c == '_' || (i > 0 && ((c >= '0' && c <= '9') || c == '-'));
        if (!ok) {
            why = "'" + std::string(name) + "' is not a valid account name (lower-case letters, digits, _ and -, starting with a letter or _)";
            return false;
        }
    }
    for (const char* r : reserved)
        if (name == r) {
            why = "'" + std::string(name) + "' is a system account; a site needs its own";
            return false;
        }
    return true;
}

bool safe_path(std::string_view path, std::string& why) {
    if (path.empty() || path.front() != '/') {
        why = "must be an absolute path";
        return false;
    }
    if (path.size() > 512) {
        why = "longer than 512 characters";
        return false;
    }
    for (char c : path) {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/' ||
                        c == '.' || c == '_' || c == '-';
        if (!ok) {
            why = "contains a character that is not a letter, digit, '.', '_', '-' or '/'";
            return false;
        }
    }
    if (path.find("/../") != std::string_view::npos || path.ends_with("/..") || path.find("//") != std::string_view::npos ||
        (path.size() > 1 && path.back() == '/')) {
        why = "must be normalised: no '..', no '//', no trailing '/'";
        return false;
    }
    return true;
}

std::string suggest_user(std::string_view domain) {
    if (domain.starts_with("www.")) domain.remove_prefix(4);
    std::string out;
    for (char c : domain.substr(0, domain.find('.'))) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out.push_back(c);
        if (out.size() == 24) break;
    }
    if (out.empty() || std::isdigit(static_cast<unsigned char>(out[0]))) out = "web" + out;
    return out;
}

std::string suggest_project(std::string_view domain) {
    if (domain.starts_with("www.")) domain.remove_prefix(4);
    std::string out;
    for (char c : domain.substr(0, domain.find('.'))) {
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out.push_back(c);
        else if (c == '-') out.push_back('_');
        if (out.size() == 32) break;
    }
    if (out.empty() || std::isdigit(static_cast<unsigned char>(out[0]))) out = "site" + out;
    if (!check_project_name(out).empty()) out += "_site";
    return out;
}

std::string detect_app(const fs::path& root) {
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return {};
    if (fs::is_regular_file(root / "manage.py", ec)) {
        // wagtail start's requirements.txt names wagtail.
        std::ifstream req(root / "requirements.txt");
        std::string line;
        while (req && std::getline(req, line))
            if (line.starts_with("wagtail") || line.starts_with("Wagtail")) return "wagtail";
        return "django";
    }
    if (fs::exists(root / "artisan", ec) || fs::exists(root.parent_path() / "artisan", ec)) return "laravel";
    if (fs::exists(root / "bin" / "grav", ec) && fs::exists(root / "system" / "defines.php", ec)) return "grav";
    if (fs::exists(root / "core" / "lib" / "Drupal.php", ec) || fs::exists(root / "web" / "core" / "lib" / "Drupal.php", ec)) return "drupal";
    if (fs::exists(root / "wp-config.php", ec) || fs::is_directory(root / "wp-includes", ec)) return "wordpress";
    if (fs::exists(root / "index.php", ec)) return "php";
    if (fs::exists(root / "Gemfile", ec)) return "proxy";
    if (fs::exists(root / "package.json", ec)) return "node";
    return "static";
}

std::string detect_app_marker(const std::string& app) {
    if (app == "laravel") return "artisan";
    if (app == "grav") return "bin/grav and system/defines.php";
    if (app == "drupal") return "core/lib/Drupal.php";
    if (app == "wordpress") return "wp-config.php or wp-includes/";
    if (app == "php") return "index.php";
    if (app == "wagtail") return "manage.py and wagtail in requirements.txt";
    if (app == "django") return "manage.py";
    if (app == "node") return "package.json";
    return "Gemfile";
}

namespace {

// A rule's path: a URL path below the root, plain characters, normalised, never "/" alone.
std::string rule_path(const json::Value& v, std::string& out) {
    if (!v.is_string()) return "a rule's path must be a string";
    const std::string p(v.str());
    if (p.empty() || p[0] != '/') return "'" + p.substr(0, 80) + "' must start with '/'";
    if (p.size() > 255) return "'" + p.substr(0, 80) + "...' is longer than 255 characters";
    if (p.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-/") != std::string::npos)
        return "'" + p + "' holds a character that is not a letter, digit, '.', '_', '-' or '/'";
    if (p.find("//") != std::string::npos || p.find("/../") != std::string::npos || p.ends_with("/..") || p.find("/./") != std::string::npos || p.ends_with("/."))
        return "'" + p + "' must be a normalised path: no '//', no '.' or '..' segments";
    if (p == "/") return "'/' cannot be a rule: it is the whole site";
    out = p;
    return "";
}

bool php_ending(const std::string& p) {
    for (const auto& e : php_suffixes())
        if (p.size() > e.size() && p.ends_with(e)) return true;
    return false;
}

}  // namespace

std::string check_rules(const json::Value& given, const SiteSpec& spec, json::Value& normalised, const Config* cfg) {
    normalised = json::Value::object();
    if (!given.is_object()) return "rules must be an object: {\"private\": [...], \"entry_points\": [...], \"cache\": [...], \"front_controller\": \"/index.php\", \"refuse\": [...], \"restricted\": [...]}";
    for (const auto& m : given.members())
        if (m.first != "private" && m.first != "entry_points" && m.first != "cache" && m.first != "front_controller" && m.first != "restricted" && m.first != "admin" &&
            m.first != "refuse" && m.first != "auth")
            return "rules: unknown key '" + m.first + "' (private, entry_points, cache, front_controller, refuse, restricted, admin, auth)";
    // rules.refuse (2026-10-08, docs/configuration.md 6b): path patterns rendered as the site's
    // `refuse`, on any app; compiled here so a bad one is answered with what it would mean.
    RefuseSet refused;
    json::Value refuse_list = json::Value::array();
    if (!given["refuse"].is_null()) {
        if (!given["refuse"].is_array()) return "rules.refuse must be a list of path patterns, such as [\"/vendor/\", \"*.yaml\", \"/ext/*/Resources/Private/\"]";
        for (const auto& v : given["refuse"].items()) {
            if (!v.is_string()) return "rules.refuse: every pattern is a string";
            RefusePattern p;
            if (const std::string why = refuse::compile(v.str(), p); !why.empty()) return "rules.refuse: " + why;
            const bool seen = std::any_of(refused.patterns.begin(), refused.patterns.end(), [&](const RefusePattern& o) { return o.text == p.text; });
            if (!seen) {
                refuse_list.push(p.text);
                refused.patterns.push_back(std::move(p));
            }
        }
        if (refused.patterns.size() > refuse::kMaxPatterns)
            return "rules.refuse: " + std::to_string(refused.patterns.size()) + " patterns, at most " + std::to_string(refuse::kMaxPatterns);
        refuse::index(refused);
    }
    // Access by client address (2026-10-07, docs/configuration.md 19): rendered as
    // [[site.access]] tables, on any app; like every rule it only narrows the site.
    // One allow list, checked the same for restricted and admin: addresses, ranges, root's
    // sets (@name, which must exist when the configuration is given) or "any" alone.
    auto allow_list = [&](const json::Value& list, const std::string& what, json::Value& out) -> std::string {
        if (!list.is_array() || list.items().empty())
            return what + " needs allow, a non-empty list of addresses, ranges, sets (\"@office\") or [\"any\"]";
        out = json::Value::array();
        std::size_t count = 0;
        bool any = false;
        for (const auto& e : list.items()) {
            if (!e.is_string()) return "every allow entry of " + what + " is a string";
            const std::string text(e.str());
            if (text == "any") any = true;
            else if (!text.empty() && text[0] == '@') {
                const std::string name = text.substr(1);
                bool ok = !name.empty() && name.size() <= 32;
                for (const char c : name) ok = ok && ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-');
                if (!ok) return "'" + text + "' is not a set name (lower-case letters, digits, '_', '-')";
                if (cfg) {
                    const auto it = cfg->address_sets.find(name);
                    if (it == cfg->address_sets.end()) {
                        std::string known;
                        for (const auto& [n, l] : cfg->address_sets) known += (known.empty() ? "" : ", ") + ("@" + n);
                        return "no address set '" + text + "' in [addresses]; " + (known.empty() ? std::string("none is defined") : "the sets are " + known) +
                               " (root defines them in the main configuration; config_reference, key addresses, lists their entries)";
                    }
                    count += it->second.size();
                }
            } else {
                Cidr c;
                std::string err;
                if (!parse_cidr(text, c, err)) return what + ": " + err;
                ++count;
            }
            out.push(text);
        }
        if (any && out.items().size() > 1) return what + ": \"any\" admits everyone, so it stands alone";
        if (count > 64) return what + " allows " + std::to_string(count) + " addresses and ranges, at most 64; a longer list belongs in the firewall";
        return "";
    };
    json::Value restricted = json::Value::array();
    std::vector<std::pair<std::string, bool>> seen;
    if (!given["restricted"].is_null()) {
        const char* shape = "rules.restricted must be a list of {\"path\": \"/wp-admin\", \"allow\": [\"203.0.113.7\", \"2001:db8:5::/64\", \"@office\"]} (optional \"match\": \"exact\", \"mode\": \"report\")";
        if (!given["restricted"].is_array()) return shape;
        if (given["restricted"].items().size() > 32) return "rules.restricted: at most 32 rules";
        for (const auto& r : given["restricted"].items()) {
            if (!r.is_object()) return shape;
            for (const auto& m : r.members())
                if (m.first != "path" && m.first != "allow" && m.first != "match" && m.first != "mode")
                    return "rules.restricted: unknown key '" + m.first + "' (path, allow, match, mode)";
            if (!r["path"].is_string()) return "rules.restricted: each rule needs a path, such as \"/wp-admin\", or \"/\" for the whole site";
            std::string path(r["path"].str());
            if (const std::string why = check_access_path(path); !why.empty()) return "rules.restricted: " + why;
            const std::string match = r["match"].is_string() ? std::string(r["match"].str()) : "prefix";
            if (match != "prefix" && match != "exact") return "rules.restricted: match for " + path + " must be \"prefix\" or \"exact\"";
            const std::string mode = r["mode"].is_string() ? std::string(r["mode"].str()) : "enforce";
            if (mode != "enforce" && mode != "report") return "rules.restricted: mode for " + path + " must be \"enforce\" or \"report\"";
            if (match == "prefix" && path.size() > 1 && path.back() == '/') path.pop_back();
            for (const auto& [p, exact] : seen)
                if (exact == (match == "exact") && p.size() == path.size() && access::iequal_prefix(p, path)) return "rules.restricted: a second rule for " + path;
            seen.emplace_back(path, match == "exact");
            json::Value allow;
            if (const std::string why = allow_list(r["allow"], path, allow); !why.empty()) return "rules.restricted: " + why;
            json::Value rule = json::Value::object().set("path", path).set("allow", std::move(allow));
            if (match == "exact") rule.set("match", "exact");
            if (mode == "report") rule.set("mode", "report");
            restricted.push(std::move(rule));
        }
    }
    // rules.admin (2026-10-07): the preset's administration paths (preset_admin_paths) in one
    // field, restricted only because the user asked; the login page joins with login: true,
    // Drupal's language prefixes with languages.
    json::Value admin;
    if (!given["admin"].is_null()) {
        const json::Value& a = given["admin"];
        if (!a.is_object()) return "rules.admin must be {\"allow\": [\"@office\"]} with optional \"login\": true, \"languages\": [\"fr\"] (Drupal), \"mode\": \"report\"";
        for (const auto& m : a.members())
            if (m.first != "allow" && m.first != "login" && m.first != "languages" && m.first != "mode")
                return "rules.admin: unknown key '" + m.first + "' (allow, login, languages, mode)";
        if (preset_admin_paths(spec.app).empty())
            return "rules.admin restricts a preset's administration and applies to app = wordpress or drupal; for another application name its paths with rules.restricted";
        json::Value allow;
        if (const std::string why = allow_list(a["allow"], "rules.admin", allow); !why.empty()) return "rules.admin: " + why;
        admin = json::Value::object().set("allow", std::move(allow));
        if (!a["login"].is_null()) {
            if (a["login"].type() != json::Value::Type::boolean) return "rules.admin: login is true (the login page too) or false";
            if (a["login"].boolean()) admin.set("login", true);
        }
        if (!a["languages"].is_null()) {
            if (spec.app != "drupal") return "rules.admin: languages are Drupal's URL prefixes (/fr/admin); WordPress's admin has none";
            if (!a["languages"].is_array() || a["languages"].items().size() > 16) return "rules.admin: languages is a list of at most 16 language codes, such as [\"fr\", \"pt-br\"]";
            json::Value langs = json::Value::array();
            for (const auto& l : a["languages"].items()) {
                const std::string code = l.is_string() ? std::string(l.str()) : std::string();
                bool ok = code.size() >= 2 && code.size() <= 12 && code[0] >= 'a' && code[0] <= 'z';
                for (const char c : code) ok = ok && ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-');
                if (!ok) return "rules.admin: '" + code + "' is not a language prefix as Drupal writes it (lower case: fr, pt-br, zh-hans)";
                langs.push(code);
            }
            if (!langs.items().empty()) admin.set("languages", std::move(langs));
        }
        const std::string mode = a["mode"].is_string() ? std::string(a["mode"].str()) : "enforce";
        if (mode != "enforce" && mode != "report") return "rules.admin: mode must be \"enforce\" or \"report\"";
        if (mode == "report") admin.set("mode", "report");
        // The paths it renders must not be named by rules.restricted as well, and all the
        // rules together stay within the loader's 32.
        SiteSpec probe = spec;
        probe.rules = json::Value::object().set("admin", admin);
        const json::Value expanded = admin_rules(probe);
        for (const auto& r : expanded.items()) {
            const std::string path(r.get("path"));
            for (const auto& [p, exact] : seen)
                if (exact == (r.get("match") == "exact") && p.size() == path.size() && access::iequal_prefix(p, path))
                    return "rules.admin and rules.restricted both name " + path + "; keep one of them";
        }
        if (restricted.items().size() + expanded.items().size() > 32)
            return "rules.admin and rules.restricted come to " + std::to_string(restricted.items().size() + expanded.items().size()) + " rules, at most 32";
    }
    // rules.auth (2026-10-09, docs/configuration.md 19b, design section 25 step 4c): password rules,
    // rendered as [[site.auth]] tables that read the site's own users file (the control plane's,
    // <config dir>/auth/<site>.users, which site_auth_user_set fills); on any app, and like every
    // rule they only narrow what the site serves.
    json::Value auth = json::Value::array();
    if (!given["auth"].is_null()) {
        const char* shape = "rules.auth must be a list of {\"path\": \"/\"} (optional \"match\": \"exact\", \"realm\", \"skip_for\": [addresses], "
                            "\"plain_http\": true; or \"open\": true for a path below a protected one that needs no password)";
        if (!given["auth"].is_array()) return shape;
        if (given["auth"].items().size() > 16) return "rules.auth: at most 16 rules";
        std::vector<std::pair<std::string, bool>> auth_seen;  // path, exact
        std::vector<std::string> protected_prefixes;
        for (const auto& r : given["auth"].items()) {
            if (!r.is_object()) return shape;
            for (const auto& m : r.members())
                if (m.first != "path" && m.first != "match" && m.first != "open" && m.first != "realm" && m.first != "skip_for" && m.first != "plain_http")
                    return "rules.auth: unknown key '" + m.first + "' (path, match, open, realm, skip_for, plain_http)" +
                           (m.first == "users" ? std::string("; the users are the site's own file, which site_auth_user_set fills") : std::string());
            if (!r["path"].is_string()) return "rules.auth: each rule needs a path, such as \"/\" for the whole site or \"/staging\"";
            std::string path(r["path"].str());
            if (const std::string why = check_access_path(path); !why.empty()) return "rules.auth: " + why;
            const std::string match = r["match"].is_null() ? std::string("prefix") : r["match"].is_string() ? std::string(r["match"].str()) : std::string();
            if (match != "prefix" && match != "exact") return "rules.auth: match for " + path + " must be \"prefix\" or \"exact\"";
            if (match == "prefix" && path.size() > 1 && path.back() == '/') path.pop_back();
            for (const auto& [p, exact] : auth_seen)
                if (exact == (match == "exact") && p.size() == path.size() && access::iequal_prefix(p, path)) return "rules.auth: a second rule for " + path;
            auth_seen.emplace_back(path, match == "exact");
            if (!r["open"].is_null() && r["open"].type() != json::Value::Type::boolean) return "rules.auth: open is true or false";
            json::Value rule = json::Value::object().set("path", path);
            if (match == "exact") rule.set("match", "exact");
            if (r["open"].boolean()) {
                if (!r["realm"].is_null() || !r["skip_for"].is_null() || !r["plain_http"].is_null())
                    return "rules.auth: " + path + " is open, so it asks for nothing: no realm, skip_for or plain_http";
                rule.set("open", true);
                auth.push(std::move(rule));
                continue;
            }
            if (!r["realm"].is_null()) {
                const std::string realm = r["realm"].is_string() ? std::string(r["realm"].str()) : std::string();
                bool ok = !realm.empty() && realm.size() <= 64;
                for (const char c : realm) ok = ok && static_cast<unsigned char>(c) >= 0x20 && c != 0x7f && c != '"' && c != '\\';
                if (!ok) return "rules.auth: the realm of " + path + " is 1 to 64 characters without quotes, backslashes or control characters (the browser shows it)";
                rule.set("realm", realm);
            }
            if (!r["skip_for"].is_null()) {
                if (!r["skip_for"].is_array() || r["skip_for"].items().empty())
                    return "rules.auth: skip_for of " + path + " is a list of addresses, ranges or sets (\"@office\") let in without a password";
                json::Value list;
                if (const std::string why = allow_list(r["skip_for"], "skip_for of " + path, list); !why.empty()) return "rules.auth: " + why;
                for (const auto& e : list.items())
                    if (e.str() == "any") return "rules.auth: skip_for of " + path + " cannot be \"any\": that is no password at all (remove the rule, or make a path open)";
                rule.set("skip_for", std::move(list));
            }
            if (!r["plain_http"].is_null()) {
                if (r["plain_http"].type() != json::Value::Type::boolean) return "rules.auth: plain_http is true (ask over plain HTTP too, when the user asks for it) or false";
                if (r["plain_http"].boolean()) rule.set("plain_http", true);
            }
            if (match == "prefix") protected_prefixes.push_back(path);
            auth.push(std::move(rule));
        }
        // An open rule frees a path below a password rule; on its own it means nothing.
        for (const auto& r : auth.items()) {
            if (!r["open"].boolean()) continue;
            const std::string p(r.get("path"));
            bool below = false;
            for (const auto& q : protected_prefixes)
                below = below || q == "/" || (p.size() > q.size() && access::iequal_prefix(p, q) && p[q.size()] == '/');
            if (!below) return "rules.auth: the open rule " + p + " lies below no password rule; an open rule frees a path inside a protected one";
        }
    }
    const bool php = php_app(spec.app), static_site = spec.app.empty() || spec.app == "static";
    std::vector<std::string> priv, entries;
    std::string why, p;
    if (!given["private"].is_null()) {
        if (!given["private"].is_array()) return "rules.private must be a list of paths";
        if (given["private"].items().size() > 64) return "rules.private: at most 64 paths";
        for (const auto& v : given["private"].items()) {
            if (!(why = rule_path(v, p)).empty()) return "rules.private: " + why;
            if (std::find(priv.begin(), priv.end(), p) == priv.end()) priv.push_back(p);
        }
    }
    if (!given["entry_points"].is_null()) {
        if (!given["entry_points"].is_array()) return "rules.entry_points must be a list of .php paths";
        if (given["entry_points"].items().size() > 16) return "rules.entry_points: at most 16 files";
        if (!given["entry_points"].items().empty() && !php)
            return "rules.entry_points name the .php files that run: they apply to a PHP preset (app = php, laravel, drupal, wordpress, grav), not to app = \"" +
                   (spec.app.empty() ? std::string("static") : spec.app) + "\"";
        for (const auto& v : given["entry_points"].items()) {
            if (!(why = rule_path(v, p)).empty()) return "rules.entry_points: " + why;
            if (p.back() == '/' || !php_ending(p)) return "rules.entry_points: '" + p + "' is not a .php file";
            if (std::find(entries.begin(), entries.end(), p) == entries.end()) entries.push_back(p);
        }
    }
    for (const auto& e : entries)
        for (const auto& pr : priv)
            if (e == pr || (pr.back() == '/' && e.starts_with(pr))) return "rules: the entry point " + e + " lies under the private path " + pr;
    json::Value cache = json::Value::array();
    if (!given["cache"].is_null()) {
        if (!given["cache"].is_array()) return "rules.cache must be a list of {\"path\": \"/assets/\", \"max_age\": 604800}";
        if (given["cache"].items().size() > 16) return "rules.cache: at most 16 directories";
        if (!given["cache"].items().empty() && !php && !static_site)
            return "rules.cache serves a directory from disk: it applies to a PHP or static preset, never to app = \"" + spec.app +
                   "\", whose root is the application's directory";
        for (const auto& c : given["cache"].items()) {
            if (!c.is_object()) return "rules.cache: each entry is {\"path\": \"/assets/\", \"max_age\": 604800}";
            if (!(why = rule_path(c["path"], p)).empty()) return "rules.cache: " + why;
            if (p.back() != '/') return "rules.cache: '" + p + "' must be a directory (ending in '/')";
            const json::Value& age = c["max_age"];
            if (age.type() != json::Value::Type::number || age.num() < 0 || age.num() > 31536000 || age.num() != static_cast<double>(static_cast<long>(age.num())))
                return "rules.cache: max_age for " + p + " must be a whole number of seconds, 0 to 31536000";
            // A field nobody reads is refused, naming the nearest (before 0.1.0-alpha.101 it was dropped:
            // "immutable" answered ok and the file carried no such thing).
            for (const auto& [k, _] : c.members())
                if (k != "path" && k != "max_age" && k != "immutable") {
                    const std::string near = nearest_name(k, {"path", "max_age", "immutable"});
                    return "rules.cache: an entry takes path, max_age and immutable, not '" + k + "'" + (near.empty() ? std::string() : " (did you mean '" + near + "'?)");
                }
            // immutable (RFC 8246): no revalidation while the answer is fresh, so a browser's reload asks
            // nothing (Firefox, Safari); only for names that change with their content (1), and only
            // with a lifetime, the one time it holds (2).
            const json::Value& imm = c["immutable"];
            if (!imm.is_null() && imm.type() != json::Value::Type::boolean) return "rules.cache: immutable for " + p + " is true or false";
            const bool immutable = imm.type() == json::Value::Type::boolean && imm.boolean();
            if (immutable && age.num() == 0)
                return "rules.cache: immutable for " + p + " needs a max_age: it holds only while the answer is fresh (RFC 8246 2), so with 0 a browser "
                       "revalidates as before";
            for (const auto& pr : priv)
                if (p == pr || (pr.back() == '/' && p.starts_with(pr))) return "rules: the cached directory " + p + " lies under the private path " + pr;
            // Below a directory the preset never answers (Grav's logs/, cache/, backup/) nothing is served,
            // cached or not: refused here with the reason, where the loader would refuse the rendered
            // location (2026-11-02). Below a shield (Grav's user/, wp-content/uploads/) the directory is
            // taken: the loader keeps the shield's refusals on it.
            for (const std::string& d : preset_never_dirs(spec.app))
                if (p == d || p.starts_with(d))
                    return "rules.cache: the directory " + p + " lies under " + d + ", which the " + spec.app +
                           " preset never answers (logs, caches, backups): nothing there is served, so nothing there is cached";
            json::Value entry = json::Value::object().set("path", p).set("max_age", age.num());
            if (immutable) entry.set("immutable", true);
            cache.push(std::move(entry));
        }
    }
    std::string front;
    if (!given["front_controller"].is_null()) {
        if (given["front_controller"].is_string() && given["front_controller"].str().empty()) {
        } else {
            if (!(why = rule_path(given["front_controller"], front)).empty()) return "rules.front_controller: " + why;
            if (!php) return "rules.front_controller routes missing paths to a .php file: it applies to a PHP preset, not to app = \"" +
                             (spec.app.empty() ? std::string("static") : spec.app) + "\"";
            if (std::find(entries.begin(), entries.end(), front) == entries.end())
                return "rules.front_controller must be one of rules.entry_points (" + front + " is not), so a missing path never reaches a script the rules do not name";
        }
    }
    // What the rules themselves name as running may not be refused; the preset's own index and
    // front controller are checked by the loader when the change is validated.
    for (const auto& e : entries)
        if (const RefusePattern* p = refuse::match(refused, e))
            return "rules.refuse: '" + p->text + "' refuses the entry point " + e + "; name what to refuse more narrowly";
    json::Value pv = json::Value::array(), ev = json::Value::array();
    for (const auto& x : priv) pv.push(x);
    for (const auto& x : entries) ev.push(x);
    if (!priv.empty()) normalised.set("private", pv);
    if (!entries.empty()) normalised.set("entry_points", ev);
    if (!cache.items().empty()) normalised.set("cache", cache);
    if (!front.empty()) normalised.set("front_controller", front);
    if (!refuse_list.items().empty()) normalised.set("refuse", refuse_list);
    if (!restricted.items().empty()) normalised.set("restricted", restricted);
    if (admin.is_object()) normalised.set("admin", admin);
    if (!auth.items().empty()) normalised.set("auth", auth);
    return "";
}

json::Value admin_rules(const SiteSpec& spec) {
    json::Value out = json::Value::array();
    if (!spec.rules.is_object() || !spec.rules["admin"].is_object()) return out;
    const json::Value& a = spec.rules["admin"];
    const bool login = a["login"].boolean(), report = a.get("mode") == "report";
    for (const auto& p : preset_admin_paths(spec.app)) {
        if (p.login && !login) continue;
        std::vector<std::string> paths = {p.path};
        if (!p.exact)  // Drupal's routes answer under every language prefix too; its PHP files do not
            for (const auto& l : a["languages"].items()) paths.push_back("/" + std::string(l.str()) + p.path);
        for (const auto& path : paths) {
            json::Value r = json::Value::object().set("path", path).set("allow", a["allow"]);
            if (p.exact) r.set("match", "exact");
            if (report) r.set("mode", "report");
            out.push(std::move(r));
        }
    }
    return out;
}

std::vector<RuleLocation> rule_locations(const SiteSpec& spec) {
    std::vector<RuleLocation> out;
    const json::Value& r = spec.rules;
    if (!r.is_object()) return out;
    for (const auto& p : r["private"].items()) out.push_back({RuleLocation::Kind::private_, std::string(p.str()), p.str().back() != '/', false, 0});
    for (const auto& e : r["entry_points"].items()) out.push_back({RuleLocation::Kind::entry, std::string(e.str()), true, false, 0});
    if (!r["entry_points"].items().empty()) out.push_back({RuleLocation::Kind::no_other_php, ".php", false, true, 0});
    for (const auto& c : r["cache"].items())
        out.push_back({RuleLocation::Kind::cache, std::string(c.get("path")), false, false, static_cast<long>(c["max_age"].num()),
                       c["immutable"].type() == json::Value::Type::boolean && c["immutable"].boolean()});
    return out;
}

// "a\", \"b": the inside of a TOML list in a one-line hint.
static std::string join_list(const std::vector<std::string>& v) {
    std::string out;
    for (std::size_t i = 0; i < v.size(); ++i) out += (i ? "\", \"" : "") + v[i];
    return out;
}

// The addresses the site would listen on (docs/configuration.md 1c): its own where given, in the
// stored spelling, else the server's; a TLS site's plain ones likewise. `given` says whether any is
// the site's own.
std::vector<std::string> spec_listen(const SiteSpec& spec, const Config& cfg, std::vector<std::string>& plain, bool& by_default) {
    auto canonical = [](const std::string& a) {
        try {
            return normalise_listen(a);
        } catch (const std::exception&) {
            return a;  // the loader refuses it with its own words
        }
    };
    const bool tls = spec.https != "none";
    by_default = (tls ? spec.listen_tls : spec.listen_plain).empty();
    std::vector<std::string> own;
    if (tls) {
        own = spec.listen_tls.empty() ? cfg.listen_tls : std::vector<std::string>{canonical(spec.listen_tls)};
        if (!spec.listen_plain.empty()) plain = {canonical(spec.listen_plain)};
        else if (spec.listen_tls.empty()) plain = cfg.listen_plain;
        else
            for (const auto& l : own)
                if (l.ends_with(":443")) plain.push_back(l.substr(0, l.size() - 3) + "80");  // what the loader derives
    } else {
        own = spec.listen_plain.empty() ? cfg.listen_plain : std::vector<std::string>{canonical(spec.listen_plain)};
    }
    return own;
}

std::vector<AccessNotice> access_notices_for(const SiteSpec& spec, const Config& cfg) {
    const json::Value admin = admin_rules(spec);
    Config view;  // the running sets and proxies, and this site as the request would write it
    view.trusted_proxies = cfg.trusted_proxies;
    view.address_sets = cfg.address_sets;
    view.listen_tls = cfg.listen_tls;
    view.listen_plain = cfg.listen_plain;
    view.listen_tls_explicit = cfg.listen_tls_explicit;
    view.listen_plain_explicit = cfg.listen_plain_explicit;
    view.reuse_port = cfg.reuse_port;
    SiteConfig site;
    site.server_names = {spec.domain};
    site.listen = spec_listen(spec, cfg, site.http_listen, site.listen_default);
    site.managed = true;  // the file this request writes: the notices' way is the site's command (the alpha.122 report: the dry run said "remove the line in ")
    site.source = site_file(cfg, spec.domain).string();
    // The other sites' addresses, so a listen of this site's own beside theirs is judged (1c:
    // listen_family_split, listen_ipv6_only); their names, listeners and files only.
    for (const SiteConfig& o : cfg.sites) {
        if (std::find(o.server_names.begin(), o.server_names.end(), spec.domain) != o.server_names.end()) continue;  // the site itself, being updated
        SiteConfig c;
        c.server_names = o.server_names;
        c.listen = o.listen;
        c.http_listen = o.http_listen;
        c.listen_default = o.listen_default;
        c.managed = o.managed;
        c.source = o.source;
        view.sites.push_back(std::move(c));
    }
    json::Value all = json::Value::array();
    for (const auto& r : spec.rules["restricted"].items()) all.push(r);
    for (const auto& r : admin.items()) all.push(r);
    for (const auto& r : all.items()) {
        AccessRule rule;
        rule.path = std::string(r.get("path"));
        rule.exact = r.get("match") == "exact";
        rule.report = r.get("mode") == "report";
        for (const auto& e : r["allow"].items()) {
            (void)access_entry(e.str(), cfg, rule.allow, rule.any);  // checked by check_rules already
            rule.allow_text.emplace_back(e.str());
        }
        site.access.push_back(std::move(rule));
    }
    view.sites.push_back(std::move(site));
    std::vector<AccessNotice> out;
    for (auto& n : access_notices(view))
        if (n.site == spec.domain) out.push_back(std::move(n));  // this site's; the copies carry nothing else to say
    return out;
}

const std::vector<std::string_view>& site_request_fields() {
    static const std::vector<std::string_view> fields = {
        "domain", "aliases", "canonical", "https", "redirect_http", "hsts", "encoded_slashes", "app", "root", "served_dir", "env_file", "upstream", "project", "entry", "user",
        "no_user", "group", "php_socket", "php_children", "php_version", "settings", "rules", "redirects", "response_headers",
        "response_headers_baseline", "response_headers_offer_declined", "response_compression", "login_paths", "public_archives", "mime_types", "trusted_proxies",
        "access_log_exclude_paths", "access_log_keep_days", "listen_plain", "listen_tls", "confirm", "reason", "dry_run", "cut_requests", "ignore_requirements"};
    return fields;
}

std::string utc_minute(std::time_t t) {
    char buf[32] = {};
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm);
    return buf;
}

// The site as the loader sees what the fail2ban jails count (check_log_exclusions), built from the
// request: its app and login paths, the address rules (rules.restricted and the admin rules), the
// password rules (rules.auth), the front controller (rules.front_controller, or the preset's), the
// rules longest first as finalize_site sorts them. So a dry run refuses what the reload would (the
// alpha.128 report, P3), and no change waits for a person's code only to fail.
static SiteConfig log_view_of(const SiteSpec& spec, const Config& cfg) {
    SiteConfig site;
    site.server_names = {spec.domain};
    site.app = spec.app;
    site.login_paths = spec.login_paths;
    site.access_log_exclude = spec.access_log_exclude_paths;
    const json::Value admin = admin_rules(spec);  // a value of its own: items() borrows from it
    json::Value all = json::Value::array();
    for (const auto& r : spec.rules["restricted"].items()) all.push(r);
    for (const auto& r : admin.items()) all.push(r);
    // A prefix rule's path as the loader stores it: without its trailing slash (access::covers reads
    // the boundary itself), which check_rules strips before a file is written.
    const auto rule_path = [](const json::Value& r) {
        std::string path(r.get("path"));
        if (r.get("match") != "exact" && path.size() > 1 && path.back() == '/') path.pop_back();
        return path;
    };
    for (const auto& r : all.items()) {
        AccessRule rule;
        rule.path = rule_path(r);
        rule.exact = r.get("match") == "exact";
        rule.report = r.get("mode") == "report";
        for (const auto& e : r["allow"].items()) (void)access_entry(e.str(), cfg, rule.allow, rule.any);  // checked by check_rules already
        site.access.push_back(std::move(rule));
    }
    for (const auto& r : spec.rules["auth"].items()) {
        AuthRule rule;
        rule.path = rule_path(r);
        rule.exact = r.get("match") == "exact";
        rule.open = r["open"].boolean();
        site.auth.push_back(std::move(rule));
    }
    const auto longest_first = [](auto& rules) {
        std::stable_sort(rules.begin(), rules.end(), [](const auto& a, const auto& b) { return a.path.size() > b.path.size(); });
    };
    longest_first(site.access);
    longest_first(site.auth);
    std::string front;
    if (spec.rules["front_controller"].is_string()) front = std::string(spec.rules["front_controller"].str());
    else if (preset_front_controller(spec.app)) front = "/index.php";
    if (!front.empty()) site.try_files = parse_try_files({"$uri", "$uri/", front + "?$query_string"});
    return site;
}

std::vector<Decision> apply_request(const json::Value& body, const Config& cfg, SiteSpec& spec, std::string& error) {
    ApplyContext ctx;
    ctx.now = std::time(nullptr);
    return apply_request(body, cfg, spec, error, ctx);
}

std::vector<Decision> apply_request(const json::Value& body, const Config& cfg, SiteSpec& spec, std::string& error, ApplyContext& ctx) {
    std::vector<Decision> needs;
    // The lifetime browsers that visit take from the site now, before this change (docs/redirects.md
    // 4.5); an earlier version's true meant a year.
    std::uint64_t sent = 0;
    if (!spec.https.empty() && spec.https != "none") {
        if (spec.hsts_unnamed) sent = 31536000;
        else if (!spec.hsts.empty()) (void)hsts_duration(spec.hsts, 315360000, sent);
    }
    // A field nobody reads is refused, naming the nearest (the alpha.98 report: "public_archive" and the
    // old "archives_accepted" were dropped and the change answered ok).
    for (const auto& [key, value] : body.members()) {
        const auto& fields = site_request_fields();
        if (std::find(fields.begin(), fields.end(), key) != fields.end()) continue;
        if (key == "access_log") {  // a field until 0.1.0-alpha.129 (docs/configuration.md 8c)
            error = "access_log is not a field: a site with its own account logs to <log directory>/sites/<domain>.log, which site_create gives it; "
                    "a log elsewhere is root's to name in a hand-written site file (docs/configuration.md 8c)";
            return needs;
        }
        const std::string nearest = nearest_name(key, fields);
        error = "unknown field '" + key + "'" + (nearest.empty() ? std::string() : " (did you mean '" + nearest + "'?)") + "; the fields are";
        for (std::size_t i = 0; i < fields.size(); ++i) error += (i ? ", " : " ") + std::string(fields[i]);
        return needs;
    }
    if (has_key(body, "domain")) spec.domain = body.get("domain");
    if (!valid_domain(spec.domain)) {
        error = "domain must be a host name such as example.com (lower-case letters, digits, hyphens, dots)";
        return needs;
    }
    if (has_key(body, "aliases")) spec.aliases = string_list(body["aliases"]);
    for (const auto& a : spec.aliases)
        if (!valid_domain(a)) {
            error = "alias '" + a + "' is not a host name";
            return needs;
        }
    // canonical (docs/redirects.md 3): the domain or one of the aliases, checked again whenever the
    // aliases change, so an alias removed never leaves a canonical name the site does not have.
    if (has_key(body, "canonical")) {
        spec.canonical = std::string(body.get("canonical"));
        for (auto& c : spec.canonical) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    if (!spec.canonical.empty() && spec.canonical != spec.domain && std::find(spec.aliases.begin(), spec.aliases.end(), spec.canonical) == spec.aliases.end()) {
        error = "canonical must be the site's domain or one of its aliases (the name the others redirect to); '" + spec.canonical + "' is neither"
                + std::string(has_key(body, "canonical") ? "" : ": an alias it named was removed, so give canonical again or \"\" for none");
        return needs;
    }
    if (has_key(body, "https")) {
        const json::Value& h = body["https"];
        if (h.is_object()) {
            spec.https = "manual";
            spec.cert = h.get("cert");
            spec.key = h.get("key");
        } else {
            spec.https = h.is_string() ? h.str() : std::string();
        }
    }
    if (has_key(body, "redirect_http")) spec.redirect_http = body["redirect_http"].boolean();
    // hsts: the lifetime itself (RFC 6797 11.2: set willfully, never by default): a duration ("1w",
    // "1y") or seconds, 0 to have browsers forget it, a {max_age, subdomains} object for
    // includeSubDomains, or false, a decided no (docs/redirects.md 4.2). At most two years here, what
    // applications publish and hstspreload's longest step; true, which named no lifetime, is refused.
    if (has_key(body, "hsts")) {
        const json::Value& h = body["hsts"];
        const std::string forms = "hsts is the lifetime browsers commit to: \"1w\" or \"1y\" (s, m, h, d, w, y; or seconds, 604800), 0 to have browsers "
                                  "forget it, {\"max_age\": \"2y\", \"subdomains\": true} for every subdomain too, \"application\" to leave it to the "
                                  "application (its own field goes out unchanged), or \"none\" for none on any answer (an application's own removed)";
        json::Value age = h;
        bool sub = false;
        // The way back (docs/redirects.md 4.5): a browser holds the field it received last over HTTPS,
        // its max-age counted from that answer (RFC 6797 8.1, 6.1.1), until it ends, so the latest moment
        // one may still hold what the site sent until now is kept across changes. That is agensio's own
        // lifetime, and the application's only where its field went out (no hsts line, "application"):
        // behind agensio's lifetime, or removed by "none", no browser received it (the alpha.104 report).
        // A field browsers ignore (no valid max-age, 8.1) counts for nothing.
        const bool app_passed = spec.hsts.empty() && !spec.hsts_unnamed && (!spec.hsts_decided || spec.hsts_application);
        std::uint64_t app_sent = 0;
        if (app_passed && !ctx.application_hsts.empty())
            if (const HstsValue v = parse_hsts(ctx.application_hsts); v.valid) app_sent = std::min<std::uint64_t>(v.max_age, 315360000);
        auto hold = [&] {
            if (sent > 0) spec.hsts_held_until = std::max<std::int64_t>(spec.hsts_held_until, ctx.now + static_cast<std::int64_t>(sent));
            if (app_sent > 0) spec.hsts_held_until = std::max<std::int64_t>(spec.hsts_held_until, ctx.now + static_cast<std::int64_t>(app_sent));
        };
        std::uint64_t now_sent = 1;  // what the spec gives from here on; 0 while clearing
        if (!spec.hsts.empty() && !spec.hsts_unnamed) (void)hsts_duration(spec.hsts, 315360000, now_sent);
        const bool clearing = !spec.hsts.empty() && !spec.hsts_unnamed && now_sent == 0;
        auto off = [&] {  // agensio sends none; "none" keeps it so (hsts_application false), "application" sets it after
            spec.hsts.clear();
            spec.hsts_subdomains = false;
            spec.hsts_decided = true;  // a decision is kept (docs/redirects.md 4.2)
            spec.hsts_application = false;
            spec.hsts_unnamed = false;
            spec.hsts_since = 0;
        };
        // agensio ctl sends --hsts's value as text (the alpha.104 and .105 reports): "true" and "false"
        // get the answers the booleans get.
        auto word = [&](std::string_view w) {
            if (!h.is_string() || h.str().size() != w.size()) return false;
            for (std::size_t i = 0; i < w.size(); ++i)
                if (std::tolower(static_cast<unsigned char>(h.str()[i])) != w[i]) return false;
            return true;
        };
        if (h.type() == json::Value::Type::boolean || word("true") || word("false")) {
            if (h.type() == json::Value::Type::boolean ? h.boolean() : word("true")) {
                error = "hsts: true named no lifetime (it meant a year): give the lifetime, \"1y\" (or \"1w\" first); " + forms;
                return needs;
            }
            error = "hsts: false is gone: it sent none of agensio's and let the application's own through, which is now hsts: \"application\"; "
                    "hsts: \"none\" removes the application's too, for none on any answer";
            return needs;
        } else if (h.is_string() && h.str() == "none") {
            // None on any answer, an application's own removed (0.1.0-alpha.104). What browsers hold,
            // agensio's or the application's, is cleared first with max-age=0, which replaces the
            // application's field too; a site already at none stays so.
            const bool none_already = spec.hsts.empty() && spec.hsts_decided && !spec.hsts_application && !spec.hsts_unnamed;
            if (clearing) {
                if (ctx.now < spec.hsts_held_until) {
                    error = "hsts: the site sends max-age=0 so that each browser that visits forgets its HSTS, and one that saw a lifetime may hold it "
                            "until " + utc_minute(spec.hsts_held_until) + ": turned off before then, nothing would end it for the browsers that "
                            "have not come back; hsts: \"none\" turns it off after that date (health says hsts_cleared), a lifetime sends one again, "
                            "hsts: \"application\" leaves it to the application at once";
                    return needs;
                }
                off();
            } else if (!none_already && (sent > 0 || app_sent > 0 || spec.hsts_held_until > ctx.now)) {
                hold();
                spec.hsts = "0";
                spec.hsts_subdomains = false;
                spec.hsts_decided = true;
                spec.hsts_application = false;
                spec.hsts_unnamed = false;
                spec.hsts_since = 0;
                ctx.note = "every HTTPS answer of the site now carries Strict-Transport-Security: max-age=0" +
                           (ctx.application_hsts.empty() ? std::string() : ", the application's own " + ctx.application_hsts + " replaced too") +
                           ", so each browser that visits forgets its HSTS (RFC 6797 6.1.1); one that saw it may hold it until " +
                           utc_minute(spec.hsts_held_until) + ", the end of the lifetime it was sent. After that date hsts: \"none\" turns it off, "
                           "none on any answer (health says hsts_cleared); before it, it is refused";
            } else {
                off();
            }
        } else if (h.is_string() && h.str() == "application") {
            // The application decides (0.1.0-alpha.104): agensio sends none of its own and passes the
            // application's on, at once, during a clearing too, since its own field keeps browsers to HTTPS.
            hold();
            if (sent > 0 || clearing)
                ctx.note = ctx.application_hsts.empty()
                               ? "the application sends no Strict-Transport-Security (its answer to / was asked): browsers that saw the site's keep it "
                                 "until " + utc_minute(spec.hsts_held_until) + ", with nothing renewing it; hsts: 0 has them forget it sooner"
                               : "the application's own Strict-Transport-Security: " + ctx.application_hsts + " now goes out unchanged, so browsers "
                                 "keep to HTTPS for its lifetime; to end HSTS for the site, the application's own setting changes too, then "
                                 "hsts: \"none\" clears what browsers hold";
            off();
            spec.hsts_application = true;
        } else {
            if (h.is_object()) {
                for (const auto& [k, _] : h.members())
                    if (k != "max_age" && k != "subdomains") {
                        error = "hsts: an object takes max_age and subdomains, not '" + k + "'; " + forms;
                        return needs;
                    }
                if (!h["subdomains"].is_null() && h["subdomains"].type() != json::Value::Type::boolean) {
                    error = "hsts.subdomains is true or false";
                    return needs;
                }
                age = h["max_age"];
                sub = h["subdomains"].type() == json::Value::Type::boolean && h["subdomains"].boolean();
            }
            std::string text;
            if (age.type() == json::Value::Type::number && age.num() >= 0 && age.num() < 1e15 && age.num() == std::floor(age.num()))
                text = std::to_string(static_cast<std::uint64_t>(age.num()));
            else if (age.is_string())
                text = age.str();
            std::uint64_t seconds = 0;
            if (text.empty() || !hsts_duration(text, 63072000, seconds)) {
                error = "hsts: '" + (text.empty() ? std::string("?") : text) + "' is no lifetime of at most two years; " + forms;
                return needs;
            }
            hold();
            // The ramp (docs/redirects.md 4.4): since when this lifetime has been sent; the same value
            // given again (another spelling of it included) keeps the date.
            const bool same = !spec.hsts.empty() && !spec.hsts_unnamed && now_sent == seconds && spec.hsts_subdomains == sub;
            const bool subdomains_new = sub && (!spec.hsts_subdomains || spec.hsts.empty() || clearing);
            if (!same) spec.hsts_since = seconds > 0 ? ctx.now : 0;
            spec.hsts = text;
            spec.hsts_subdomains = sub;
            spec.hsts_decided = true;
            spec.hsts_application = false;
            spec.hsts_unnamed = false;
            if (subdomains_new && seconds > 300)
                ctx.note = "includeSubDomains binds every subdomain of " + spec.domain + ", on this server or another, to HTTPS for the whole "
                           "lifetime, in every browser that saw it: the usual way is a ramp, \"5m\" first, then a week, a month and a year, "
                           "each once the stage before has run its whole lifetime with nothing broken (hstspreload.org); health's hsts_ramp "
                           "names each next stage";
            if (seconds == 0 && spec.hsts_held_until > ctx.now)
                ctx.note = "every HTTPS answer of the site now carries Strict-Transport-Security: max-age=0, so each browser that visits forgets "
                           "its HSTS (RFC 6797 6.1.1); one that saw it may hold it until " + utc_minute(spec.hsts_held_until) +
                           ". After that date hsts: \"none\" turns it off (health says hsts_cleared)";
        }
    }
    if (spec.hsts_unnamed) {  // rendered again without a lifetime, the site would drop the HSTS browsers hold
        error = "this site's file says hsts = true, an earlier version's form that named no lifetime (it meant a year), refused since "
                "0.1.0-alpha.101: name it with this change, hsts: \"1y\" (agensio ctl --hsts 1y) to keep what browsers were told, or hsts: \"none\"";
        return needs;
    }
    if (has_key(body, "encoded_slashes")) {
        const std::string_view es = body.get("encoded_slashes");
        if (es != "deny" && es != "allow") {
            error = "encoded_slashes must be \"deny\" (a %2F or %5C in the path is 404 on the site's files) or \"allow\" (decoded and looked up, for an application that encodes a slash inside a path segment)";
            return needs;
        }
        spec.encoded_slashes = es == "allow" ? "allow" : "";
    }
    if (has_key(body, "app")) spec.app = body.get("app");
    if (has_key(body, "root")) spec.root = body.get("root");
    if (has_key(body, "upstream")) spec.upstream = body.get("upstream");
    if (has_key(body, "project")) spec.project = body.get("project");
    if (has_key(body, "entry")) spec.entry = body.get("entry");
    if (has_key(body, "served_dir")) spec.served_dir = body.get("served_dir");
    if (has_key(body, "env_file")) spec.env_file = body.get("env_file");
    if (has_key(body, "group")) spec.group = body.get("group");
    if (has_key(body, "php_socket")) spec.php_socket = body.get("php_socket");
    if (has_key(body, "php_children")) spec.php_children = static_cast<int>(body["php_children"].num());
    if (has_key(body, "php_version")) spec.php_version = body.get("php_version");
    // The allowlisted limits (control/settings.hpp): merged into what the site has,
    // each value checked against the ceiling; a key not in the table is refused by name.
    if (has_key(body, "settings")) {
        json::Value given = body["settings"];
        if (spec.php_children && given.is_object() && given["children"].is_null()) given.set("children", static_cast<double>(spec.php_children));
        json::Value normalised;
        const bool will_have_user = has_key(body, "no_user") ? !body["no_user"].boolean()
                                    : has_key(body, "user") ? body["user"].is_string() && !body["user"].str().empty()
                                                            : !spec.user.empty();
        // The pool keys exist only where a pool will: a PHP site with its own user and no
        // socket of its own; an undecided app passes here and meets the decision form below.
        const bool php_site = spec.app != "static" && !proxy_app(spec.app);
        const std::string bad = apply_settings(given, cfg, php_site && will_have_user && spec.php_socket.empty() && body.get("php_socket").empty(), normalised);
        if (!bad.empty()) {
            error = bad;
            return needs;
        }
        if (!spec.settings.is_object()) spec.settings = json::Value::object();
        for (const auto& m : normalised.members()) spec.settings.set(m.first, m.second);
        if (!spec.settings["children"].is_null()) spec.php_children = static_cast<int>(spec.settings["children"].num());
    } else if (has_key(body, "php_children") && spec.php_children) {
        if (!spec.settings.is_object()) spec.settings = json::Value::object();
        spec.settings.set("children", static_cast<double>(spec.php_children));
    }
    // The application's own rules: given whole (an empty object clears them), checked against
    // the preset as it stands after this request; kept rules are checked again below, so an app
    // change can never leave a rule that would widen the site.
    if (has_key(body, "rules")) {
        json::Value normalised;
        if (const std::string bad = check_rules(body["rules"], spec, normalised, &cfg); !bad.empty()) {
            error = bad;
            return needs;
        }
        spec.rules = normalised;
    }
    // Path redirects (docs/redirects.md 5, alpha.83): the whole list ([] or null clears it), judged
    // by the loader's own parse and checks on the site's names; the reload judges them again with
    // the site's refuse patterns, ports and protections, and undoes a refused change.
    if (has_key(body, "redirects")) {
        const json::Value& given = body["redirects"];
        if (given.is_null() || (given.is_array() && given.items().empty())) {
            spec.redirects = json::Value();
        } else {
            SiteConfig probe;
            probe.server_names = {spec.domain};
            for (const auto& a : spec.aliases) probe.server_names.push_back(a);
            if (const std::string why = load_redirect_rules(given, probe); !why.empty()) {
                error = why;
                return needs;
            }
            spec.redirects = given;
        }
    }
    // The preset's response headers baseline (docs/headers.md 4): false turns it off, true or null
    // keeps the default (on).
    if (given(body, "response_headers_baseline")) {  // null included: back to the default
        const json::Value& b = body["response_headers_baseline"];
        if (b.is_null()) {
            spec.response_headers_baseline.reset();
        } else if (b.type() == json::Value::Type::boolean) {
            if (b.boolean()) spec.response_headers_baseline.reset();
            else spec.response_headers_baseline = false;
        } else {
            error = "response_headers_baseline must be true or false (the preset's baseline of response fields, docs/headers.md 4), or null for the default (on)";
            return needs;
        }
    }
    // Response headers (docs/headers.md 6, alpha.94; the test host's request: a managed site could not
    // carry them): the whole list ([] or null clears it), judged by the loader's own parse and checks
    // on the site's app (a CSP set over an application's own is noted); the reload judges the endings
    // against the preset's locations again, and undoes a refused change.
    if (given(body, "response_headers")) {  // null included: clears them, as []
        const json::Value& rules = body["response_headers"];
        if (rules.is_null() || (rules.is_array() && rules.items().empty())) {
            spec.response_headers = json::Value();
        } else {
            SiteConfig probe;
            probe.server_names = {spec.domain};
            probe.app = spec.app.empty() ? "static" : spec.app;
            probe.response_headers_baseline = spec.response_headers_baseline;  // its fields count toward the 64
            if (const std::string why = load_response_header_rules(rules, probe); !why.empty()) {
                error = why;
                return needs;
            }
            spec.response_headers = rules;
        }
    }
    // The offered fields the owner declined (docs/headers.md 7): given whole, each one of the fields
    // path_check offers, in any case; [] or null clears them.
    if (given(body, "response_headers_offer_declined")) {
        const json::Value& list = body["response_headers_offer_declined"];
        std::vector<std::string> names;
        if (!list.is_null() && !list.is_array()) {
            error = "response_headers_offer_declined must be a list of field names: [\"X-Frame-Options\"] ([] clears it)";
            return needs;
        }
        for (const auto& e : list.items()) {
            const std::string name = e.is_string() ? offered_response_field(e.str()) : std::string();
            if (name.empty()) {
                error = "response_headers_offer_declined: '" + (e.is_string() ? e.str() : std::string("?")) + "' is not one of the fields offered (" +
                        std::string(kOfferedResponseFields) + "); HSTS is declined with hsts: \"application\" or \"none\"";
                return needs;
            }
            if (std::find(names.begin(), names.end(), name) == names.end()) names.push_back(name);
        }
        spec.response_headers_offer_declined = names;
    }
    // The site's own response compression (docs/design-compression.md 9): merged field by field into
    // what the site set before, so a later change of the main file still reaches every field it leaves
    // out. true or false sets enabled alone; in an object a field given null goes back to the main
    // file's and [] clears exclude_paths; null drops them all. Judged by the loader's own parse.
    if (given(body, "response_compression")) {
        const json::Value& g = body["response_compression"];
        json::Value own = spec.response_compression.is_object() ? spec.response_compression : json::Value::object();
        const auto without = [](const json::Value& o, std::string_view key) {
            json::Value out = json::Value::object();
            for (const auto& [k, v] : o.members())
                if (k != key) out.set(k, v);
            return out;
        };
        if (g.is_null()) {
            own = json::Value::object();
        } else if (g.type() == json::Value::Type::boolean) {
            own.set("enabled", g.boolean());
        } else if (g.is_object()) {
            for (const auto& [k, v] : g.members()) {
                if (k == "levels" || k == "min_size" || k == "extra_types") {
                    error = "response_compression." + k + " is the host's tuning, the main file's [response_compression] (root's file, docs/configuration.md 20); a managed site sets enabled, exclude_paths, compress_signed_in and codings";
                    return needs;
                }
                if (k == "offload" || k == "compress_event_streams") {
                    error = "response_compression." + k + " is not offered on a managed site yet: it acts once agensio compresses streamed answers (docs/configuration.md 20)";
                    return needs;
                }
                if (k != "enabled" && k != "exclude_paths" && k != "compress_signed_in" && k != "codings") {
                    error = "response_compression has no field '" + k + "'; a managed site sets enabled, exclude_paths, compress_signed_in and codings";
                    return needs;
                }
                if (v.is_null() || (k == "exclude_paths" && v.is_array() && v.items().empty())) own = without(own, k);
                else own.set(k, v);
            }
        } else {
            error = "response_compression must be true, false, an object such as {\"enabled\": true, \"codings\": [\"br\", \"zstd\", \"gzip\"]}, or null to follow the main file";
            return needs;
        }
        SiteConfig probe;
        if (const std::string why = load_site_compression(own, cfg.compression, probe); !why.empty()) {
            error = why;
            return needs;
        }
        spec.response_compression = own.members().empty() ? json::Value() : own;
    }
    // The login paths (2026-10-02): given whole, each a plain URL path (check_login_path), at
    // most 16, [] or null clears them. They change no location: the fail2ban jail counts attempts there.
    if (given(body, "login_paths") && body["login_paths"].is_null()) spec.login_paths.clear();
    else if (has_key(body, "login_paths")) {
        if (!body["login_paths"].is_array()) {
            error = "login_paths must be a list of URL paths: [\"/login\"] ([] clears them)";
            return needs;
        }
        if (body["login_paths"].items().size() > 16) {
            error = "login_paths: at most 16 paths";
            return needs;
        }
        std::vector<std::string> lp;
        for (const auto& p : body["login_paths"].items()) {
            if (!p.is_string()) {
                error = "login_paths: each entry is a string path (\"/login\")";
                return needs;
            }
            if (const std::string why = check_login_path(std::string(p.str())); !why.empty()) {
                error = "login_paths: " + why;
                return needs;
            }
            if (std::find(lp.begin(), lp.end(), std::string(p.str())) == lp.end()) lp.emplace_back(p.str());
        }
        spec.login_paths = lp;
    }
    // The archives and dumps served on purpose (2026-10-17): given whole, each a path as served
    // (check_public_archive), at most 64, [] or null clears them (null answered ok and kept the list
    // until the alpha.97 report). Health's archives_in_root alone reads them.
    if (given(body, "public_archives") && body["public_archives"].is_null()) spec.public_archives.clear();
    else if (has_key(body, "public_archives")) {
        if (!body["public_archives"].is_array() || body["public_archives"].items().size() > 64) {
            error = "public_archives must be a list of at most 64 paths as served from the site's root: [\"/downloads/world.sql.gz\"], a directory ending in / ([] clears them)";
            return needs;
        }
        std::vector<std::string> aa;
        for (const auto& p : body["public_archives"].items()) {
            if (!p.is_string()) {
                error = "public_archives: each entry is a string path (\"/downloads/world.sql.gz\")";
                return needs;
            }
            if (const std::string why = check_public_archive(std::string(p.str())); !why.empty()) {
                error = "public_archives: " + why;
                return needs;
            }
            if (std::find(aa.begin(), aa.end(), std::string(p.str())) == aa.end()) aa.emplace_back(p.str());
        }
        spec.public_archives = aa;
    }
    // The site's content types (0.1.0-alpha.100, docs/configuration.md 6c): given whole, judged as the
    // load judges a site file's (load_mime_types: a type a browser runs scripts in only for an ending
    // that has one already); {} or null clears them.
    if (given(body, "mime_types") && body["mime_types"].is_null()) spec.mime_types = MimeTypes{};
    else if (has_key(body, "mime_types")) {
        MimeTypes t;
        if (const std::string why = load_mime_types(body["mime_types"], t, true); !why.empty()) {
            error = why;
            return needs;
        }
        spec.mime_types = std::move(t);
    }
    // The proxies that speak for this site (2026-10-13, docs/redirects.md 2.4): given whole, each an
    // address, a range or an [addresses] set within [server] trusted_proxies (checked here as the load
    // does), at most 32; [] believes no proxy, null goes back to the server's list.
    if (given(body, "trusted_proxies")) {
        const json::Value& tp = body["trusted_proxies"];
        if (tp.is_null()) {
            spec.own_trusted_proxies = false;
            spec.trusted_proxies.clear();
        } else if (!tp.is_array() || tp.items().size() > 32) {
            error = "trusted_proxies must be a list of at most 32 addresses, ranges or @sets within [server] trusted_proxies ([] believes no proxy, null goes back to the server's list)";
            return needs;
        } else {
            std::vector<std::string> list;
            for (const auto& e : tp.items()) {
                if (!e.is_string()) {
                    error = "trusted_proxies: each entry is a string: an address, a range or an @set";
                    return needs;
                }
                std::vector<Cidr> got;
                if (const std::string why = site_trusted_entry(std::string(e.str()), cfg, got); !why.empty()) {
                    error = "trusted_proxies: " + why;
                    return needs;
                }
                if (std::find(list.begin(), list.end(), std::string(e.str())) == list.end()) list.emplace_back(e.str());
            }
            spec.own_trusted_proxies = true;
            spec.trusted_proxies = list;
        }
    }
    // What the site keeps out of its logs (0.1.0-alpha.128, docs/configuration.md 8b): given whole, each
    // a plain path from / (never / itself, no query), at most 16, [] or null clears them; the overlap
    // with the paths the fail2ban jails count is the load's (check_log_exclusions), which knows the rules.
    if (given(body, "access_log_exclude_paths") && body["access_log_exclude_paths"].is_null()) spec.access_log_exclude_paths.clear();
    else if (has_key(body, "access_log_exclude_paths")) {
        const json::Value& list = body["access_log_exclude_paths"];
        if (!list.is_array() || list.items().size() > 16) {
            error = "access_log_exclude_paths must be a list of at most 16 URL paths: [\"/api/notices/\"] ([] clears them)";
            return needs;
        }
        std::vector<std::string> ex;
        for (const auto& p : list.items()) {
            if (!p.is_string()) {
                error = "access_log_exclude_paths: each entry is a string path (\"/api/notices/\")";
                return needs;
            }
            if (const std::string why = check_log_exclude_path(std::string(p.str())); !why.empty()) {
                error = "access_log_exclude_paths: " + why;
                return needs;
            }
            if (std::find(ex.begin(), ex.end(), std::string(p.str())) == ex.end()) ex.emplace_back(p.str());
        }
        spec.access_log_exclude_paths = ex;
    }
    // The days the rotated lines of the site's own log are kept: 1 to 14, null or 0 for logrotate's own.
    if (given(body, "access_log_keep_days")) {
        const json::Value& d = body["access_log_keep_days"];
        if (d.is_null()) spec.access_log_keep_days = 0;
        else if (d.type() != json::Value::Type::number || d.num() != static_cast<double>(static_cast<int>(d.num())) || d.num() < 0 || d.num() > 14) {
            error = "access_log_keep_days must be a whole number of days from 1 to 14 (null or 0: logrotate's own, 14 as shipped)";
            return needs;
        } else {
            spec.access_log_keep_days = static_cast<int>(d.num());
        }
    }
    // One address each, as the loader stores it, checked here so a dry run says what the real call
    // would and nothing that did not parse reaches a warning or listen_unbound's run_as_root (the
    // alpha.123 report: "nonsense" passed the dry run, and "[::]:443,203.0.113.5:443" was written into
    // the main file's line as "[[::]:443,203.0.113.5]:443"). "" is the server's addresses.
    for (const char* key : {"listen_plain", "listen_tls"}) {
        if (!has_key(body, key)) continue;
        std::string value(body.get(key));
        if (!value.empty()) {
            try {
                value = normalise_listen(value);
            } catch (const std::exception& e) {
                error = std::string(key) + ": one address, host:port with an IP host (0.0.0.0:80, [::]:443, 203.0.113.5:443), or \"\" for the server's addresses; " + e.what();
                return needs;
            }
        }
        (std::string_view(key) == "listen_tls" ? spec.listen_tls : spec.listen_plain) = value;
    }
    // "user": absent = undecided; JSON null or "" = deliberately none; `no_user: true` says
    // the same in a way every client can send. Both given and disagreeing: refused.
    bool user_given = false;
    if (body.is_object())
        for (const auto& m : body.members())
            if (m.first == "user") {
                user_given = true;
                spec.user_decided = true;
                spec.user = m.second.is_string() ? m.second.str() : std::string();
                spec.no_user = spec.user.empty();
            }
    if (has_key(body, "no_user")) {
        const bool none = body["no_user"].boolean();
        if (none && user_given && !spec.user.empty()) {
            error = "no_user is true but user is also given (" + spec.user + "); send one of them";
            return needs;
        }
        if (none) {
            spec.user.clear();
            spec.no_user = true;
            spec.user_decided = true;
        } else if (!user_given && !spec.user_decided) {
            spec.user_decided = false;  // no_user: false alone decides nothing
        }
    }
    // Every value that ends up in a root command is checked here, before any command exists.
    std::string why;
    if (!spec.user.empty() && !valid_account(spec.user, why)) {
        error = "user: " + why;
        return needs;
    }
    if (!spec.group.empty() && !valid_account(spec.group, why)) {
        error = "group: " + why;
        return needs;
    }
    if (!spec.root.empty() && !safe_path(spec.root, why)) {
        error = "root: " + why;
        return needs;
    }
    if (!spec.project.empty()) {
        if (!python_app(spec.app) && !spec.app.empty()) {
            error = "project names a Django project's package: it goes with app = \"django\" or \"wagtail\"";
            return needs;
        }
        if (const std::string bad = check_project_name(spec.project); !bad.empty()) {
            error = bad;
            return needs;
        }
    }
    if (!spec.entry.empty()) {
        if (!node_app(spec.app) && !spec.app.empty()) {
            error = "entry names the file node runs: it goes with app = \"node\"";
            return needs;
        }
        if (const std::string bad = check_entry(spec.entry); !bad.empty()) {
            error = bad;
            return needs;
        }
    }
    if (!spec.served_dir.empty()) {
        if (spec.app != "php" && !spec.app.empty()) {
            error = "served_dir names the project's directory that is served: it goes with app = \"php\" (the other PHP presets know their own); "
                    "send served_dir: \"\" with the change of app";
            return needs;
        }
        if (const std::string bad = check_served_dir(spec.served_dir); !bad.empty()) {
            error = bad;
            return needs;
        }
    }
    if (!spec.env_file.empty()) {  // the loader judges where it lies against the served directory
        if (!schedule_app(spec.app) && !spec.app.empty()) {
            error = "env_file names a Laravel application's .env: it goes with app = \"laravel\" or app = \"php\"; send env_file: \"\" with the change of app";
            return needs;
        }
        if (const std::string bad = check_env_file(spec.env_file); !bad.empty()) {
            error = bad;
            return needs;
        }
    }
    for (const auto& f : {spec.cert, spec.key})
        if (!f.empty() && !safe_path(f, why)) {
            error = "https cert/key: " + why;
            return needs;
        }
    if (spec.rules.is_object() && !spec.rules.members().empty()) {
        json::Value again;
        if (const std::string bad = check_rules(spec.rules, spec, again, &cfg); !bad.empty()) {
            error = "the site's rules no longer fit its app: " + bad + " (send rules: {} to clear them)";
            return needs;
        }
    }
    const bool user_decided = spec.user_decided || !spec.user.empty();
    // A site with its own user gets its own access log next to the server's: sites of
    // different users never share a log (rule 5), and the file is made theirs to read. Always
    // that one file (docs/configuration.md 8c): the managed file is the server account's, and the
    // loader lets such a file name no other log; a path a request chose before 0.1.0-alpha.129 is
    // replaced by it here, so a site_update repairs a file set aside for it.
    spec.access_log = spec.user.empty() ? std::string() : (fs::path(log_directory(cfg)) / "sites" / (spec.domain + ".log")).string();

    if (spec.https != "auto" && spec.https != "none" && spec.https != "manual") {
        Decision d{"https", "Should the site be served over HTTPS?", "", {"auto", "none", "{\"cert\": ..., \"key\": ...}"}};
        d.suggestion = cfg.acme.enabled ? "auto" : "auto (needs [server] acme = { email = \"...\" } in the main configuration first)";
        needs.push_back(d);
    } else if (spec.https == "auto" && !cfg.acme.enabled) {
        error = "https = \"auto\" needs [server] acme = { email = \"...\" } in the main configuration";
        return needs;
    } else if (spec.https == "manual" && (spec.cert.empty() || spec.key.empty())) {
        error = "https as a table needs cert and key";
        return needs;
    }
    std::uint64_t hsts_seconds = 0;
    if (spec.hsts_application && spec.app == "static") {  // nothing would send it (the alpha.104 report), refused at load too
        error = "hsts: \"application\" leaves HSTS to the site's application, and a static site has no application: nothing would send it; "
                "hsts: \"none\" is the decided no here, or a lifetime (\"1y\")";
        return needs;
    }
    if (spec.https != "none" && !spec.hsts.empty() && hsts_duration(spec.hsts, 63072000, hsts_seconds) && hsts_seconds > 0 &&
        !spec.redirect_http) {  // http = "serve" with hsts, refused at load too
        error = "hsts with redirect_http false: HSTS tells browsers to use only HTTPS, which contradicts serving plain HTTP on purpose; drop one of them";
        return needs;
    }
    // A Rails application lives in app/ beside web/ (docs/design-site-operations.md 2b): its
    // directory holds config/master.key and the databases, and is never a document root.
    if (spec.root.empty() && spec.app != "proxy")
        needs.push_back(Decision{"root", rails_app(spec.app)    ? "Where is the Rails application? (its project directory: tasks run there, nothing is served from it)"
                                         : python_app(spec.app) ? "Where is the Django project? (its directory, where manage.py lives: tasks run there; only "
                                                                  "its static/ and media/ are served)"
                                         : node_app(spec.app) ? "Where is the Node application? (its project directory, where package.json lives: npm runs "
                                                                "there, nothing is served from it)"
                                                                : "Where are the site's files? (the document root; for Laravel the project directory)",
                                 (cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root) + "/" + spec.domain +
                                     (service_app(spec.app) ? "/app" : "/web"), {}});
    if (python_app(spec.app) && spec.project.empty())
        needs.push_back(Decision{"project", "What is the project's Python package called? (NAME/settings and NAME/wsgi.py; a new project is created "
                                            "under this name, an installed one must match its own)",
                                 suggest_project(spec.domain), {}});
    const std::vector<std::string> apps = app_presets();
    if (spec.app.empty()) {
        const std::string detected = spec.root.empty() ? std::string() : detect_app(spec.root);
        needs.push_back(Decision{"app", "What runs there? A preset sets the routing and PHP rules.",
                                 detected.empty() ? "static" : detected + " (found under root)", apps});
    } else if (std::find(apps.begin(), apps.end(), spec.app) == apps.end()) {
        error = "app must be one of: ";
        for (std::size_t i = 0; i < apps.size(); ++i) error += (i ? ", " : "") + apps[i];
        return needs;
    }
    if (proxy_app(spec.app) && spec.upstream.empty())
        needs.push_back(Decision{"upstream", "Where does the application listen? (http://host:port)", "http://127.0.0.1:3000", {}});
    if (!user_decided)
        needs.push_back(Decision{"user", "Run this site under its own system account? It isolates it from other sites. Answer with user: \"<name>\", or no_user: true for none.",
                                 suggest_user(spec.domain), {}});
    const bool php = php_app(spec.app);
    if (php && spec.user.empty() && spec.php_socket.empty() && user_decided)
        needs.push_back(Decision{"php_socket", "Without a site user no pool is generated: which php-fpm socket serves this site?",
                                 "unix:/run/php/php-fpm.sock", {}});
    // What the site keeps out of its logs (docs/configuration.md 8b), judged here as the loader will
    // (the alpha.128 report, P3: a change the reload refuses waited for a person's code and failed after
    // it): the jails' paths against the rules as the file would hold them, and the days against the
    // site's own log, which a site with its own account has.
    if (!spec.access_log_exclude_paths.empty())
        if (const std::string why = check_log_exclusions(log_view_of(spec, cfg)); !why.empty()) {
            error = "access_log_exclude_paths: " + why;
            return needs;
        }
    if (spec.access_log_keep_days && spec.access_log.empty()) {
        error = "access_log_keep_days needs the site's own access log, which a site with its own account (user) has; this site writes the server-wide "
                "[log] access, which holds other sites' lines too";
        return needs;
    }
    return needs;
}

std::string render_site(const SiteSpec& spec, std::string_view stamp) {
    std::string out;
    out += std::string(kManagedMarker) + spec.to_json().dump() + "\n";
    out += "# " + spec.domain + ": written by agensio ctl on " + std::string(stamp) +
           ". `agensio ctl site-update` rewrites it from the line above; edit by hand and\n"
           "# remove that line to take it over.\n";
    std::vector<std::string> names{spec.domain};
    names.insert(names.end(), spec.aliases.begin(), spec.aliases.end());
    const bool tls = spec.https != "none";
    auto site_body = [&](std::string& s) {
        if (proxy_app(spec.app)) {
            s += "app = " + toml_string(spec.app) + "\nupstream = " + toml_string(spec.upstream) + "\n";
            if (!spec.root.empty()) s += "root = " + toml_string(spec.root) + "\n";
            if (python_app(spec.app) && !spec.project.empty()) s += "project = " + toml_string(spec.project) + "\n";
            if (node_app(spec.app) && !spec.entry.empty()) s += "entry = " + toml_string(spec.entry) + "\n";
        } else {
            s += "root = " + toml_string(spec.root) + "\n";
            if (spec.app == "php" && !spec.served_dir.empty()) s += "served_dir = " + toml_string(spec.served_dir) + "   # served; root is the project directory\n";
            if (schedule_app(spec.app) && !spec.env_file.empty()) s += "env_file = " + toml_string(spec.env_file) + "   # the application's .env, root's: site_env_set writes it\n";
            // Named for a static site too (alpha.94): a site with app gets its preset's security
            // baseline (docs/headers.md 4), which a file without the line would not.
            s += "app = " + toml_string(spec.app.empty() ? std::string("static") : spec.app) + "\n";
        }
        if (!spec.user.empty()) s += "user = " + toml_string(spec.user) + "\n";
        if (!spec.group.empty()) s += "group = " + toml_string(spec.group) + "\n";
        if (!spec.user.empty() && !spec.access_log.empty()) s += "access_log = " + toml_string(spec.access_log) + "\n";
        if (!spec.access_log_exclude_paths.empty())
            s += "access_log_exclude_paths = " + toml_list(spec.access_log_exclude_paths) + "   # no access-log line and no client address in the error log here\n";
        if (spec.access_log_keep_days)
            s += "access_log_keep_days = " + std::to_string(spec.access_log_keep_days) + "   # the site's rotated lines are deleted after " +
                 std::to_string(spec.access_log_keep_days) + (spec.access_log_keep_days == 1 ? " day" : " days") + " (logrotate keeps 14)\n";
        if (!spec.login_paths.empty()) s += "login_paths = " + toml_list(spec.login_paths) + "   # fail2ban counts login attempts here (agensio ctl protection)\n";
        if (!spec.public_archives.empty())
            s += "public_archives = " + toml_list(spec.public_archives) + "   # served on purpose: health's archives_in_root accepts them\n";
        if (!spec.mime_types.empty())
            s += "mime_types = " + mime_types_toml(spec.mime_types) + "   # over [mime_types] and the built-in table (docs/configuration.md 6c)\n";
        if (spec.encoded_slashes == "allow") s += "encoded_slashes = \"allow\"   # a %2F in the path is decoded and looked up (Apache's NoDecode), not 404\n";
        if (spec.own_trusted_proxies) s += "trusted_proxies = " + toml_list(spec.trusted_proxies) + "   # the proxies that speak for this site, within [server] trusted_proxies\n";
        if (spec.rules.is_object() && !spec.rules["refuse"].items().empty()) {
            std::vector<std::string> patterns;
            for (const auto& p : spec.rules["refuse"].items()) patterns.emplace_back(p.str());
            s += "refuse = " + toml_list(patterns) + "   # rules: refused with 404 whichever location would serve them\n";
        }
        const bool php = php_app(spec.app);
        if (spec.settings.is_object() && spec.settings["max_body_size"].is_string()) s += "max_body_size = " + toml_string(spec.settings.get("max_body_size")) + "\n";
        if (const std::string fc(spec.rules.get("front_controller")); !fc.empty())
            s += "try_files = [\"$uri\", \"$uri/\", " + toml_string(fc + "?$query_string") + "]   # rules: nice URLs\n";
        if (php) {
            if (!spec.php_socket.empty()) s += "php = { socket = " + toml_string(spec.php_socket) + " }\n";
            else if (spec.php_children || !spec.php_version.empty() || (spec.settings.is_object() && !spec.settings.members().empty())) {
                std::string keys;
                auto add = [&](const std::string& text) { keys += (keys.empty() ? "" : ", ") + text; };
                const int children = spec.php_children ? spec.php_children
                                     : spec.settings.is_object() && spec.settings["children"].type() == json::Value::Type::number ? static_cast<int>(spec.settings["children"].num()) : 0;
                if (children) add("children = " + std::to_string(children));
                if (!spec.php_version.empty()) add("version = " + toml_string(spec.php_version));
                for (const auto& m : spec.settings.members()) {
                    if (m.first == "max_body_size" || m.first == "children") continue;  // written above / as children
                    add(m.first + " = " + (m.second.is_string() ? toml_string(m.second.str()) : std::to_string(static_cast<long long>(m.second.num()))));
                }
                s += "php = { " + keys;
                s += " }\n";
            }
        }
    };
    // The application's rules as locations (2026-10-01): deny for the private paths (final
    // prefixes, so nothing below them reaches PHP), fastcgi for the named entry points with
    // every other .php denied, a static shield for each cached directory where no PHP spelling
    // and no backup ending is served. Hand-written in the file's terms, so the loader needs
    // nothing new; the comments say where they come from.
    auto rules_locations = [&](std::string& s) {
        for (const RuleLocation& rl : rule_locations(spec)) switch (rl.kind) {
                case RuleLocation::Kind::private_:
                    s += "\n[[site.location]]   # rules: private\npath = " + toml_string(rl.path) + "\n" + (rl.exact ? "match = \"exact\"\n" : "final = true\n") + "handler = \"deny\"\n";
                    break;
                case RuleLocation::Kind::entry:
                    s += "\n[[site.location]]   # rules: an entry point\npath = " + toml_string(rl.path) + "\nmatch = \"exact\"\nhandler = \"fastcgi\"\n";
                    break;
                case RuleLocation::Kind::no_other_php:
                    s += "\n[[site.location]]   # rules: no other PHP runs\npath = \".php\"\nmatch = \"suffix\"\nhandler = \"deny\"\n";
                    break;
                case RuleLocation::Kind::cache: {
                    std::vector<std::string> deny = php_suffixes();
                    for (const auto& b : source_backup_suffixes())
                        if (std::find(deny.begin(), deny.end(), b) == deny.end()) deny.push_back(b);
                    s += "\n[[site.location]]   # rules: cached, nothing runs here\npath = " + toml_string(rl.path) + "\nfinal = true\ndeny_suffixes = " + toml_list(deny) +
                         "\nadd_headers = { \"Cache-Control\" = \"public, max-age=" + std::to_string(rl.max_age) + (rl.immutable ? ", immutable" : "") + "\" }\n";
                    break;
                }
            }
        // Access by client address: rules.restricted as [[site.access]] tables.
        if (spec.rules.is_object())
            for (const auto& r : spec.rules["restricted"].items()) {
                std::vector<std::string> allow;
                for (const auto& e : r["allow"].items()) allow.emplace_back(e.str());
                s += "\n[[site.access]]   # rules: restricted\npath = " + toml_string(r.get("path")) + "\n";
                if (r.get("match") == "exact") s += "match = \"exact\"\n";
                s += "allow = " + toml_list(allow) + "\n";
                if (r.get("mode") == "report") s += "mode = \"report\"\n";
            }
        // rules.auth: password rules reading the site's own users file, which lives beside sites.d
        // (<config dir>/auth/<site>.users) and is written by the control plane's user tools.
        if (spec.rules.is_object())
            for (const auto& r : spec.rules["auth"].items()) {
                const bool open = r["open"].boolean();
                s += std::string("\n[[site.auth]]   # rules: auth") + (open ? ", open" : "") + "\npath = " + toml_string(r.get("path")) + "\n";
                if (r.get("match") == "exact") s += "match = \"exact\"\n";
                if (open) {
                    s += "open = true\n";
                    continue;
                }
                if (!r.get("realm").empty()) s += "realm = " + toml_string(r.get("realm")) + "\n";
                s += "users = " + toml_string("../auth/" + spec.domain + ".users") + "\n";
                if (!r["skip_for"].items().empty()) {
                    std::vector<std::string> skip;
                    for (const auto& e : r["skip_for"].items()) skip.emplace_back(e.str());
                    s += "skip_for = " + toml_list(skip) + "\n";
                }
                if (r["plain_http"].boolean()) s += "plain_http = \"allow\"\n";
            }
        // rules.admin: the preset's administration paths, as the user asked them restricted.
        const json::Value admin = admin_rules(spec);  // kept alive for the loop: items() refers into it
        for (const auto& r : admin.items()) {
            std::vector<std::string> allow;
            for (const auto& e : r["allow"].items()) allow.emplace_back(e.str());
            s += "\n[[site.access]]   # rules: admin\npath = " + toml_string(r.get("path")) + "\n";
            if (r.get("match") == "exact") s += "match = \"exact\"\n";
            s += "allow = " + toml_list(allow) + "\n";
            if (r.get("mode") == "report") s += "mode = \"report\"\n";
        }
    };
    // One block for both schemes (docs/redirects.md 2, alpha.76): an HTTPS site answers its plain
    // port by its http key, which is left out for the port 80 beside 443 that redirects.
    out += "\n[[site]]\nserver_name = " + toml_list(names) + "\n";
    if (const std::string& own = tls ? spec.listen_tls : spec.listen_plain; !own.empty()) out += "listen = " + toml_list({own}) + "\n";
    else out += "# listens on the server's addresses ([server] listen_tls / listen_plain, docs/configuration.md 1c)\n";
    if (!spec.canonical.empty()) out += "canonical = " + toml_string(spec.canonical) + "   # the other names redirect here (docs/redirects.md 3)\n";
    site_body(out);
    if (tls) {
        if (spec.https == "auto") out += "tls = \"auto\"\n";
        else out += "tls = { cert = " + toml_string(spec.cert) + ", key = " + toml_string(spec.key) + " }\n";
        // The plain port: the server's listen_plain, or port 80 beside a TLS address of the site's own on
        // 443, is what the loader gives without a line; any other plain address of the site's own is named.
        const bool beside_443 = spec.listen_plain.empty() ||
                                (spec.listen_tls.ends_with(":443") && spec.listen_plain == spec.listen_tls.substr(0, spec.listen_tls.size() - 3) + "80");
        if (!beside_443)
            out += "http = { listen = " + toml_list({spec.listen_plain}) + (spec.redirect_http ? "" : ", mode = \"serve\"") + " }\n";
        else if (!spec.redirect_http)
            out += "http = \"serve\"\n";
        if (!spec.hsts.empty()) {
            std::uint64_t secs = 0;
            (void)hsts_duration(spec.hsts, 63072000, secs);
            const bool digits = spec.hsts.find_first_not_of("0123456789") == std::string::npos;
            const std::string age = digits ? spec.hsts : toml_string(spec.hsts);
            out += (spec.hsts_subdomains ? "hsts = { max_age = " + age + ", subdomains = true }" : "hsts = " + age) +
                   "   # Strict-Transport-Security: max-age=" + std::to_string(secs) + (spec.hsts_subdomains ? "; includeSubDomains" : "") +
                   " on every HTTPS answer" +
                   (secs == 0 && spec.hsts_held_until > 0
                        ? ": browsers that visit forget the site's HSTS; one may hold it until " + utc_minute(spec.hsts_held_until) +
                              ", then hsts = \"none\" (docs/redirects.md 4.5)\n"
                        : std::string(" (docs/redirects.md 4)\n"));
        } else if (spec.hsts_application) {
            out += "hsts = \"application\"   # agensio sends no Strict-Transport-Security of its own; the application's goes out unchanged "
                   "(docs/redirects.md 4.2)\n";
        } else if (spec.hsts_decided) {
            out += "hsts = \"none\"   # no Strict-Transport-Security on any answer: an application's own is removed (docs/redirects.md 4.2)\n";
        }
    }
    if (spec.response_headers_baseline && !*spec.response_headers_baseline)
        out += "response_headers_baseline = false   # the preset's baseline of response fields off (docs/headers.md 4)\n";
    if (!spec.response_headers_offer_declined.empty())
        out += "response_headers_offer_declined = " + toml_list(spec.response_headers_offer_declined) +
               "   # offered, declined by the owner: health and path_check no longer suggest them (docs/headers.md 7)\n";
    // The site's own response_compression, only the fields set (load_site_compression judged them):
    // every other comes from the main file's [response_compression].
    if (const json::Value& rc = spec.response_compression; rc.is_object() && !rc.members().empty()) {
        if (rc.members().size() == 1 && rc["enabled"].type() == json::Value::Type::boolean) {
            out += std::string("response_compression = ") + (rc["enabled"].boolean() ? "true" : "false");
        } else {
            out += "response_compression = { ";
            bool first = true;
            for (const char* k : {"enabled", "exclude_paths", "compress_signed_in", "codings"}) {
                const json::Value& v = rc[k];
                if (v.is_null()) continue;
                out += std::string(first ? "" : ", ") + k + " = " +
                       (v.type() == json::Value::Type::boolean ? std::string(v.boolean() ? "true" : "false") : toml_list(string_list(v)));
                first = false;
            }
            out += " }";
        }
        out += "   # this site's own; every other field from the main file's [response_compression] (docs/configuration.md 20)\n";
    }
    rules_locations(out);
    // Path redirects as the site file's own tables; their keys are the reference's (load_redirect_rules
    // refused any other), their values strings or numbers.
    for (const auto& r : spec.redirects.items()) {
        out += "\n[[site.redirect]]\n";
        for (const auto& [k, v] : r.members())
            out += k + " = " + (v.is_string() ? toml_string(v.str()) : std::to_string(static_cast<long long>(v.num()))) + "\n";
    }
    // Response headers as the site file's own tables, in the reference's key order; load_response_header_rules
    // refused any other key and every value it could not hold (a line break, a $, a field the server owns),
    // and toml_string escapes the quotes and backslashes a printable value may have.
    for (const auto& r : spec.response_headers.items()) {
        out += "\n[[site.response_headers]]\n";
        for (const char* k : {"path", "match", "when"})
            if (r[k].is_string()) out += std::string(k) + " = " + toml_string(r[k].str()) + "\n";
        auto list = [&](const json::Value& l) {
            std::vector<std::string> v;
            for (const auto& e : l.items())
                if (e.is_string()) v.push_back(e.str());
            return toml_list(v);
        };
        if (r["endings"].is_array()) out += "endings = " + list(r["endings"]) + "\n";
        for (const char* k : {"set", "default"}) {
            if (!r[k].is_object()) continue;
            std::string fields;
            for (const auto& [name, value] : r[k].members())
                if (value.is_string()) fields += (fields.empty() ? " " : ", ") + toml_string(name) + " = " + toml_string(value.str());
            out += std::string(k) + " = {" + fields + " }\n";
        }
        if (r["remove"].is_array()) out += "remove = " + list(r["remove"]) + "\n";
    }
    return out;
}

bool read_managed(const fs::path& file, SiteSpec& out) {
    std::ifstream in(file);
    std::string line;
    if (!in || !std::getline(in, line) || !line.starts_with(kManagedMarker)) return false;
    json::Value v;
    std::string err;
    return json::parse(line.substr(kManagedMarker.size()), v, err) && SiteSpec::from_json(v, out);
}

fs::path sites_dir(const Config& cfg) { return cfg.config_path.parent_path() / "sites.d"; }

fs::path site_file(const Config& cfg, std::string_view domain) { return sites_dir(cfg) / (std::string(domain) + ".toml"); }

const Config::HeldBack* held_back_named(const Config& cfg, std::string_view name) {
    std::string want(name);
    for (auto& c : want) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const auto& h : cfg.held_back) {
        if (!h.site.empty()) {  // one site of the main file, not every name the file claims
            if (h.site == want) return &h;
            continue;
        }
        const std::vector<std::string> names = claimed_names(h.file);
        if (std::find(names.begin(), names.end(), want) != names.end()) return &h;
    }
    return nullptr;
}

fs::path held_back_managed(const Config& cfg, std::string_view name, std::string* domain) {
    std::string want(name);
    for (auto& c : want) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (const auto& h : cfg.held_back) {
        SiteSpec spec;
        std::error_code ec;
        if (!read_managed(h.file, spec) || !fs::equivalent(h.file, site_file(cfg, spec.domain), ec)) continue;  // the file site_update writes
        if (spec.domain != want && std::find(spec.aliases.begin(), spec.aliases.end(), want) == spec.aliases.end()) continue;
        if (domain) *domain = spec.domain;
        return h.file;
    }
    return {};
}

bool sites_dir_included(const Config& cfg) {
    for (const auto& p : cfg.includes)
        if (p == "sites.d/*.toml" || p == "./sites.d/*.toml" || p.ends_with("/sites.d/*.toml")) return true;
    return false;
}

bool write_site_file(const fs::path& file, const std::string& text, std::string& error) {
    std::error_code ec;
    fs::create_directories(file.parent_path(), ec);
    if (fs::exists(file, ec)) {
        fs::copy_file(file, fs::path(file.string() + ".bak"), fs::copy_options::overwrite_existing, ec);
        if (ec) {
            error = "cannot back up " + file.string() + ": " + ec.message();
            return false;
        }
    }
    const fs::path tmp = file.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            error = "cannot write " + tmp.string() + ": " + std::strerror(errno);
            return false;
        }
        out << text;
    }
    ::chmod(tmp.c_str(), 0640);
    fs::rename(tmp, file, ec);
    if (ec) {
        error = "cannot rename into " + file.string() + ": " + ec.message();
        return false;
    }
    return true;
}

// The layout the hosting rules accept and the server can serve: the site's directories are
// owned by the site user with the server's group and 2750, so the server reads through the
// group bit and files PHP creates inherit the group; the account's home is its state
// directory, never the document root (useradd would fill it with dotfiles).
std::vector<Problem> preflight(const SiteSpec& spec, const Config& cfg, bool privileged) {
    std::vector<Problem> out;
    // Belt and braces: apply_request validated these; a command is never assembled from a
    // value that would not pass again.
    std::string why;
    if ((!spec.user.empty() && !valid_account(spec.user, why)) || (!spec.group.empty() && !valid_account(spec.group, why)) ||
        (!spec.root.empty() && !safe_path(spec.root, why)) || (!spec.cert.empty() && !safe_path(spec.cert, why)) ||
        (!spec.key.empty() && !safe_path(spec.key, why))) {
        out.push_back({"refused", why, "", true, json::Value()});
        return out;
    }
    const HostFacts facts = system_facts();
    const ServerAccount server = server_account(cfg, facts);
    const std::string server_group = server.known ? server.group : (cfg.group.empty() ? cfg.user : cfg.group);
    unsigned uid = 0, gid = 0;
    const bool have_user = !spec.user.empty() && facts.user(spec.user, uid, gid);
    if (!spec.user.empty() && !have_user)
        out.push_back({"missing_account", "the account " + spec.user + " does not exist",
                       "useradd --system --no-create-home --home-dir " + cfg.state_dir + "/" + spec.user +
                           " --shell /usr/sbin/nologin " + spec.user, true,
                       json::Value::object().set("op", "account_add").set("name", spec.user)});
    if (!spec.group.empty()) {
        unsigned g = 0;
        if (!facts.group(spec.group, g))
            out.push_back({"missing_group", "the group " + spec.group + " does not exist",
                           "groupadd " + spec.group + " && usermod -g " + spec.group + " " + spec.user, true, json::Value()});
    }
    std::error_code ec;
    if (!spec.root.empty()) {
        const std::string owner = spec.user.empty() ? (cfg.user.empty() ? "root" : cfg.user) : spec.user;
        const std::string group = server_group;
        FileFacts f;
        const bool exists = facts.stat(spec.root, f) && f.is_dir;
        bool readable = true;
        if (exists && server.uid != 0) {
            readable = f.uid == server.uid ? (f.mode & 0500) == 0500
                       : (server.known && f.gid == server.gid) ? (f.mode & 0050) == 0050
                                                                  : (f.mode & 0005) == 0005;
        }
        // The site's top directory (the domain directory when root is below it) gets the layout too.
        std::string top = spec.root;
        const std::string base = (cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root) + "/" + spec.domain;
        if (spec.root.starts_with(base + "/") || spec.root == base) top = base;
        // Directories only: files keep their owner and group, so a secret such as .env stays
        // the user's (0640 user:user) and is never readable by the server.
        const std::string layout = "find " + top + " -type d -exec chown " + owner + ":" + group + " {} + -exec chmod 2750 {} +";
        // The helper lays out every directory from sites_root down to the root, for a site account only.
        const json::Value fix = spec.user.empty() ? json::Value() : json::Value::object().set("op", "site_layout").set("dir", spec.root).set("owner", spec.user);
        if (!exists)
            out.push_back({"root_missing", "the directory " + spec.root + " does not exist",
                           "mkdir -p " + spec.root + " && chown " + owner + ":" + group + " " + top + " && " + layout, true, fix});
        else if (!readable || (!spec.user.empty() && (f.uid != uid || !(server.known && f.gid == server.gid))))
            out.push_back({"root_unreadable", spec.root + " is not owned " + owner + ":" + group + " with 2750, so the server cannot read it",
                           layout + "   # the server reads the site's directories through its group", true, fix});
    }
    if (spec.https == "manual") {
        if (!fs::is_regular_file(spec.cert, ec))
            out.push_back({"certificate_missing", "no certificate chain at " + spec.cert, "# put the certificate chain at " + spec.cert, true, json::Value()});
        if (!fs::is_regular_file(spec.key, ec))
            out.push_back({"certificate_missing", "no private key at " + spec.key, "# put the private key at " + spec.key + " (mode 0600)", true, json::Value()});
    }
    // The listeners (docs/configuration.md 1c). A reload binds an address the server does not hold
    // yet, unless it is below 1024 and the server has dropped root: then nothing but a restart can,
    // and the change is blocked with the way, rather than promised a restart the reload cannot keep
    // (the alpha.119 IPv6 report). The server's own addresses are open when the main file names them
    // (bound at start) or a site uses them already; an address of the site's own needs the main
    // file, or a port above 1023.
    if (!privileged) {
        std::vector<std::string> plain;
        bool by_default = false;
        std::vector<std::string> addresses = spec_listen(spec, cfg, plain, by_default);
        addresses.insert(addresses.end(), plain.begin(), plain.end());
        for (const std::string& address : addresses) {
            const bool in_tls = std::find(cfg.listen_tls.begin(), cfg.listen_tls.end(), address) != cfg.listen_tls.end();
            const bool in_plain = std::find(cfg.listen_plain.begin(), cfg.listen_plain.end(), address) != cfg.listen_plain.end();
            const bool servers = in_tls || in_plain;
            bool bound = (in_tls && cfg.listen_tls_explicit) || (in_plain && cfg.listen_plain_explicit);  // that key named: open since the start
            for (const auto& s : cfg.sites)
                for (const auto& l : site_addresses(s)) bound = bound || l == address;
            const std::size_t colon = address.rfind(':');
            const int port = colon == std::string::npos ? 0 : std::atoi(address.c_str() + colon + 1);
            if (bound || port <= 0 || port >= 1024) continue;
            if (servers)
                out.push_back({"listen_unbound",
                               "the server's address " + address + " is not open yet (no site uses it and the main file does not name it), and a reload "
                                   "cannot bind a port below 1024 once the server dropped root: name the server's addresses in the main file and restart, "
                                   "then create or update the site",
                               "# in /etc/agensio/agensio.toml under [server]: listen_tls = [\"" + join_list(cfg.listen_tls) + "\"] and listen_plain = [\"" +
                                   join_list(cfg.listen_plain) + "\"], then: systemctl restart agensio",
                               true, json::Value()});
            else
                out.push_back({"listen_unbound",
                               "the site's own address " + address + " is a port below 1024 the server does not hold, and a reload cannot bind one "
                                   "once the server dropped root: put the address in the main file's [server] listen_tls or listen_plain and restart, then "
                                   "create or update the site on the server's addresses (listen_tls and listen_plain left out, or sent as \"\"), or use a port above 1023",
                               "# in /etc/agensio/agensio.toml under [server]: add " + address + " to listen_tls or listen_plain, then: systemctl restart agensio", true,
                               json::Value()});
        }
    }
    return out;
}

std::vector<std::string> prerequisites(const SiteSpec& spec, const Config& cfg) {
    std::vector<std::string> cmds;
    for (const auto& p : preflight(spec, cfg, true))
        if (p.blocks) cmds.push_back(p.run_as_root.empty() ? "# " + p.code + ": " + p.detail : p.run_as_root);
    return cmds;
}

// How the master of a PHP version rereads the pools `agensio pools` wrote: "systemctl reload
// php8.4-fpm" on Debian. `version` "" is the server's default (php_version, else the newest installed).
std::string php_fpm_reload_command(const Config& cfg, const std::string& version) {
    const std::string v = !version.empty() ? version : !cfg.php_version.empty() ? cfg.php_version : cfg.php_newest;
    const auto runtimes = php::discover(cfg, php::system_fs());
    if (const php::Runtime* r = v.empty() ? nullptr : php::find(runtimes, v)) return reload_command(*r);
    return "systemctl reload php" + (v.empty() ? std::string("X.Y") : v) + "-fpm   # (PHP " + (v.empty() ? std::string("X.Y") : v) +
           " is not installed: php_versions lists what is)";
}

TaskSetup task_setup(const Config& cfg, const SiteConfig& site, const tasks::Row& row) {
    TaskSetup out;
    const std::string project = site.project_root.empty() ? site.root : site.project_root;
    out.dir = project;
    if (std::string_view(row.runtime) != "php") return out;
    // The directory: from served_dir up to the project, the first that holds artisan, each level a real
    // directory (never a symlink) and artisan a regular file. The task opens it again without following
    // a symlink, as the site's account, so this only chooses.
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!site.served_dir.empty()) {
        fs::path at = fs::path(project) / site.served_dir;
        while (true) {
            const std::string text = at.lexically_normal().string();
            if (text.size() < project.size()) break;
            bool real = true;  // every level from the project down to here a directory, no symlink
            for (fs::path p = at; real && p.lexically_normal().string().size() >= project.size(); p = p.parent_path()) {
                const fs::file_type type = fs::symlink_status(p, ec).type();
                real = type == fs::file_type::directory;
                if (type == fs::file_type::symlink && out.link.empty()) out.link = p.lexically_normal().lexically_relative(project).string();
                if (p.lexically_normal().string() == project) break;
            }
            if (real && fs::symlink_status(at / "artisan", ec).type() == fs::file_type::regular) {
                out.dir = text;
                break;
            }
            if (text == project) break;
            at = at.parent_path();
        }
    }
    // The interpreter: the site's own PHP version's command-line binary.
    const std::string version = !site.pool.version.empty() ? site.pool.version : !cfg.php_version.empty() ? cfg.php_version : cfg.php_newest;
    if (version.empty()) {
        out.error = "no PHP version is installed or named for this site (php.version, [server] php_version), so its tasks have no interpreter";
        return out;
    }
    const std::vector<php::Runtime> runtimes = php::discover(cfg, php::system_fs());
    const php::Runtime* r = php::find(runtimes, version);
    if (!r || r->cli.empty()) {
        out.error = "PHP " + version + " has no command-line binary on this host, so its tasks cannot run" +
                    (r ? std::string() : std::string(" (and no php-fpm of that version is installed)"));
        if (::access("/usr/bin/apt-get", X_OK) == 0) out.run_as_root = "apt-get install -y php" + version + "-cli";
        else if (::access("/usr/bin/dnf", X_OK) == 0) out.run_as_root = "dnf install -y php-cli";
        return out;
    }
    out.program = r->cli;
    return out;
}

std::string linked_release_note(const TaskSetup& ts) {
    if (ts.link.empty()) return "";
    return ts.link + " is a symbolic link, which the tasks never follow, so the release behind it is not where they look: name the release itself in served_dir "
                     "(releases/<id>/public, below the project; docs/examples/php.md, \"Laravel from release directories\")";
}

std::vector<std::size_t> scheduler_cron_lines(std::string_view text, std::string_view project, bool any_line, std::size_t max) {
    std::vector<std::size_t> out;
    std::size_t at = 0, no = 0;
    while (at < text.size() && out.size() < max) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        const std::string_view line = text.substr(at, end - at);
        at = end + 1;
        ++no;
        const std::size_t first = line.find_first_not_of(" \t");
        if (first == std::string_view::npos || line[first] == '#') continue;
        if (line.find("schedule:run") == std::string_view::npos) continue;
        bool names_project = false;
        for (std::size_t p = project.empty() ? std::string_view::npos : line.find(project); p != std::string_view::npos && !names_project; p = line.find(project, p + 1)) {
            const std::size_t after = p + project.size();
            names_project = after == line.size() || line[after] == '/' || line[after] == ' ';
        }
        if (names_project || any_line) out.push_back(no);
    }
    return out;
}

std::optional<std::string> scheduled_in_background(std::string_view output) {
    constexpr std::string_view mark = "] in background", running = "Running [";
    for (std::size_t at = output.rfind(mark); at != std::string_view::npos; at = at == 0 ? std::string_view::npos : output.rfind(mark, at - 1)) {
        const std::size_t nl = output.rfind('\n', at);
        const std::size_t from = nl == std::string_view::npos ? 0 : nl + 1;
        const std::size_t open = output.substr(from, at - from).find(running);
        if (open == std::string_view::npos) continue;
        // The command may hold brackets of its own; the line's last "] in background" closes it.
        std::string cmd(output.substr(from + open + running.size(), at - from - open - running.size()));
        if (cmd.size() > 160) {
            std::size_t n = 160;
            while (n > 0 && (static_cast<unsigned char>(cmd[n]) & 0xc0) == 0x80) --n;
            cmd.resize(n);
            cmd += "...";
        }
        return cmd;
    }
    return std::nullopt;
}

namespace {

// The path of the agensio binary that runs now, for the scheduler unit's ExecStart.
std::string agensio_binary() {
    char buf[4096];
    const ssize_t n = ::readlink("/proc/self/exe", buf, sizeof buf - 1);
    if (n <= 0) return "/usr/sbin/agensio";
    std::string path(buf, static_cast<std::size_t>(n));
    if (path.ends_with(" (deleted)")) path.erase(path.size() - 10);  // replaced by an upgrade while running: the new file is at the same path
    return path;
}

// The Laravel scheduler (2026-11-04, the grabloop.app report): a timer that every minute starts a
// oneshot service, which asks agensio over its control socket to run the site task schedule_run. The
// task runner resolves the live release and the site's PHP version at each run, so nothing in the
// units names a release and a switch needs nothing of root; root installs them once. The service
// runs as the server's own account (an admin of the control socket), never as the site's: it holds
// no right of the site, and the site's account cannot change what it asks.
json::Value schedule_units(const SiteConfig& site, const Config& cfg) {
    json::Value fail = json::Value::object().set("ok", false);
    const std::string name = site.server_names.empty() ? std::string() : site.server_names.front();
    const tasks::Row* row = tasks::find(site.app.empty() ? "static" : site.app, "schedule_run");
    if (!row) return fail.set("error", "a scheduler is rendered for a Laravel site (app = \"laravel\", or a Laravel application on app = \"php\")");
    const TaskSetup ts = task_setup(cfg, site, *row);
    std::error_code ec;
    if (std::filesystem::symlink_status(std::filesystem::path(ts.dir) / "artisan", ec).type() != std::filesystem::file_type::regular)
        return fail.set("error", "no artisan file in " + ts.dir + " (the directory Laravel's tasks run in, from served_dir up): " +
                                     (ts.link.empty() ? std::string("this is no Laravel application") : linked_release_note(ts)) + ", so no scheduler is rendered");
    if (!cfg.control.enabled || cfg.control.socket.empty())
        return fail.set("error", "the scheduler asks agensio over its control socket, and this server has none: [control] socket in the main file");
    const std::string service = schedule_unit_name(name, false), timer = schedule_unit_name(name, true);
    const std::string account = cfg.user.empty() ? std::string("root") : cfg.user;
    const std::string bin = agensio_binary();
    const std::string socket = cfg.control.socket;
    const std::string socket_dir = std::filesystem::path(socket).parent_path().string();
    const unsigned timeout = std::min(row->timeout, cfg.control.task_timeout) + 120;
    for (const std::string* v : {&name, &account, &bin, &socket, &socket_dir}) {
        if (v->empty() || v->find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/@:+-") != std::string::npos)
            return fail.set("error", "'" + v->substr(0, 80) + "' is not a plain path or name (letters, digits, . _ / @ : + -); the scheduler is not rendered");
    }
    std::string head;
    head += "# agensio: the Laravel scheduler of " + name + ", rendered by `agensio ctl site-unit " + name + "`. As root, once:\n";
    head += "#   agensio ctl site-unit " + name + " --out /etc/systemd/system/" + service + "\n";
    head += "#   agensio ctl site-unit " + name + " --out /etc/systemd/system/" + timer + "\n";
    head += "#   systemctl daemon-reload && systemctl enable --now " + timer + "\n";
    head += "# Every minute agensio runs the site task schedule_run (php artisan schedule:run) as the site's account, in the live release\n";
    head += "# (the site's served_dir), with the site's PHP version: nothing here names a release, so a release switch needs nothing of root.\n";
    std::string s = head;
    s += "[Unit]\nDescription=Laravel scheduler of " + name + ", run by agensio's task runner\nAfter=agensio.service\n\n";
    s += "[Service]\nType=oneshot\n";
    s += "# The server's own account, an admin of the control socket: it only asks agensio, which runs the task as the site's account.\n";
    s += "User=" + account + "\n";
    s += "ExecStart=" + bin + " ctl site-task " + name + " schedule_run --scheduled --yes --reason scheduler --socket " + socket + "\n";
    s += "TimeoutStartSec=" + std::to_string(timeout) + "\n";
    s += "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\nReadWritePaths=" + socket_dir + "\nProtectHome=yes\nRestrictSUIDSGID=yes\n";
    s += "ProtectKernelTunables=yes\nProtectControlGroups=yes\nRestrictRealtime=yes\nLockPersonality=yes\nCapabilityBoundingSet=\n";
    std::string t = head;
    t += "[Unit]\nDescription=Every minute: the Laravel scheduler of " + name + "\n\n";
    t += "[Timer]\nOnCalendar=*-*-* *:*:00\nAccuracySec=1s\nUnit=" + service + "\n\n";
    t += "[Install]\nWantedBy=timers.target\n";
    json::Value units = json::Value::array()
                            .push(json::Value::object().set("name", service).set("path", "/etc/systemd/system/" + service).set("unit", s))
                            .push(json::Value::object().set("name", timer).set("path", "/etc/systemd/system/" + timer).set("unit", t));
    json::Value cmds = json::Value::array()
                           .push("agensio ctl site-unit " + name + " --out /etc/systemd/system/" + service)
                           .push("agensio ctl site-unit " + name + " --out /etc/systemd/system/" + timer)
                           .push("systemctl daemon-reload")
                           .push("systemctl enable --now " + timer);
    return json::Value::object().set("ok", true).set("site", name).set("kind", "scheduler").set("unit_name", timer).set("units", std::move(units))
        .set("run_as_root", std::move(cmds))
        .set("hint", "root installs both once with run_as_root; site_service_status " + name + " says whether a scheduler is installed (this timer, or a cron line "
                     "that runs schedule:run) before anyone makes another, since two would run every scheduled command twice");
}

}  // namespace

json::Value service_unit(const SiteConfig& site, const Config& cfg) {
    if (schedule_app(site.app)) return schedule_units(site, cfg);  // a Laravel site: its scheduler
    json::Value fail = json::Value::object().set("ok", false);
    const std::string name = site.server_names.empty() ? std::string() : site.server_names.front();
    const bool python = python_app(site.app), node = node_app(site.app);
    if (!service_app(site.app))
        return fail.set("error", "a unit is rendered for a Rails, Django or Node site (app = \"rails\", \"redmine\", \"django\", \"wagtail\" or \"node\"); this one "
                                 "has app = \"" + site.app + "\"");
    const char* server = python ? "Gunicorn" : node ? "node" : "Puma";
    if (node && site.entry.empty())
        return fail.set("error", "the site names no entry, the file node runs: site_update with entry (server/server.js; site_install's facts guess it from "
                                 "package.json)");
    if (node && !check_entry(site.entry).empty()) return fail.set("error", "entry: " + check_entry(site.entry));
    if (site.user.empty())
        return fail.set("error", std::string("the site runs under no account of its own: give it one (site_update with user) first; ") + server +
                                     " never runs as the server's account or root");
    const UpstreamAddress& a = site.proxy.address;
    const bool loopback = a.host == "127.0.0.1" || a.host == "::1" || a.host.starts_with("127.");
    if (!site.proxy.configured || a.unix || a.tls || !loopback || a.port == 0)
        return fail.set("error", std::string("the site's upstream must be http://127.0.0.1:PORT (plain HTTP on loopback) for ") + server +
                                     " to bind; site_update with upstream sets it");
    const std::string root = site.project_root.empty() ? site.root : site.project_root;
    const std::string group = site.group.empty() ? site.user : site.group;
    const std::string runtime = runtime_dir(cfg.control, python ? "python3" : node ? "node" : "ruby");
    const std::string home = cfg.state_dir + "/" + site.user;
    const std::string env = appenv::dir_of(cfg.config_path) + "/" + name + ".env";
    const std::string port = std::to_string(a.port);
    const std::string unit_name = "agensio-app-" + site.user + ".service";
    const std::string venv = home + "/venvs/" + name;
    const AppContext ac = app_context(cfg, site);
    // The runtime's directory first, the system's after it, none twice (alpha.35 report, P4 d:
    // /usr/bin:/usr/local/bin:/usr/bin:/bin).
    std::string path = runtime;
    for (const char* d : {"/usr/local/bin", "/usr/bin", "/bin"})
        if (d != runtime) path += std::string(":") + d;
    // Plain paths and names only: a newline, a space or a quote could add a line to the unit.
    for (const std::string* v : {&name, &root, &group, &site.user, &runtime, &home, &env, &venv}) {
        if (v->empty() || v->find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/@:+-") != std::string::npos)
            return fail.set("error", "'" + v->substr(0, 80) + "' is not a plain path or name (letters, digits, . _ / @ : + -); the unit is not rendered");
    }
    if (python && (!check_project_name(site.project).empty() ||
                   (ac.hosts + ac.origins + ac.base_url).find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789.-:/,*") != std::string::npos))
        return fail.set("error", "the site's project or names are not plain names; the unit is not rendered");
    std::string u;
    u += "# agensio: the application service of " + name + " (" + server + "), rendered by `agensio ctl site-unit " + name + "` from the site,\n";
    u += "# [control] runtimes and the site's environment file, until agensio manages it (roadmap F14). As root:\n";
    u += "#   agensio ctl site-unit " + name + " --out /etc/systemd/system/" + unit_name + "   (written whole, 0644)\n";
    u += "#   systemctl daemon-reload && systemctl enable --now " + unit_name + "\n";
    u += "[Unit]\n";
    const std::string what = site.app == "redmine" ? "Redmine" : site.app == "wagtail" ? "Wagtail site" : python ? "Django application"
                             : node                  ? "Node.js application"
                                                     : "Rails application";
    u += "Description=" + what + " of " + name + " (" + server + "), behind agensio\n";
    u += "After=network.target\n\n";
    u += "[Service]\n";
    u += "User=" + site.user + "\nGroup=" + group + "\n";
    u += "WorkingDirectory=" + root + "\n";
    if (node) {
        // Where it listens: the upstream's loopback address, as HOST and PORT (what Express,
        // Uptime Kuma and most servers read); the site's environment cannot override them.
        u += "Environment=HOME=" + home + " TMPDIR=" + home + "/tmp LANG=C.UTF-8 NODE_ENV=production\n";
        u += "Environment=HOST=" + std::string(a.host == "::1" ? "::1" : a.host) + " PORT=" + port + "\n";
        u += "Environment=PATH=" + path + "\n";
        u += "EnvironmentFile=-" + env + "\n";
        u += "# Root's node ([control] runtimes) on the application's entry.\n";
        u += "ExecStart=" + runtime + "/node " + root + "/" + site.entry + "\n";
    } else if (python) {
        u += "Environment=HOME=" + home + " TMPDIR=" + home + "/tmp LANG=C.UTF-8 PYTHONNOUSERSITE=1 PYTHONUNBUFFERED=1 VIRTUAL_ENV=" + venv + "\n";
        u += "# What agensio_settings.py (site task django_settings) reads: the project, the site's names, the served paths.\n";
        u += "Environment=DJANGO_SETTINGS_MODULE=agensio_settings AGENSIO_DJANGO_PROJECT=" + site.project + "\n";
        u += "Environment=AGENSIO_STATIC_ROOT=" + root + "/static AGENSIO_MEDIA_ROOT=" + root + "/media\n";
        if (!ac.hosts.empty()) u += "Environment=AGENSIO_HOSTS=" + ac.hosts + " AGENSIO_ORIGINS=" + ac.origins + " AGENSIO_BASE_URL=" + ac.base_url + "\n";
        if (ac.https_redirect || ac.hsts)
            u += "Environment=" + std::string(ac.https_redirect ? "AGENSIO_HTTPS_REDIRECT=1" : "") + (ac.https_redirect && ac.hsts ? " " : "") +
                 (ac.hsts ? "AGENSIO_HSTS=1" : "") + "\n";
        u += "Environment=PATH=" + path + "\n";
        u += "EnvironmentFile=-" + env + "\n";
        u += "# The admin's password createsuperuser read is never the application's.\n";
        u += "UnsetEnvironment=DJANGO_SUPERUSER_PASSWORD DJANGO_SUPERUSER_USERNAME DJANGO_SUPERUSER_EMAIL\n";
        u += "# Root's python3 ([control] runtimes) started under the name of the site's virtualenv, which makes it that virtualenv's.\n";
        u += "ExecStart=@" + runtime + "/python3 " + venv + "/bin/python -m gunicorn " + site.project + ".wsgi:application --bind 127.0.0.1:" + port +
             " --workers 2 --timeout 60 --forwarded-allow-ips 127.0.0.1\n";
    } else {
        u += "Environment=RAILS_ENV=production HOME=" + home + " TMPDIR=" + home + "/tmp LANG=C.UTF-8\n";
        u += "Environment=BUNDLE_PATH=vendor/bundle BUNDLE_WITHOUT=development:test RAILS_LOG_TO_STDOUT=1\n";
        u += "Environment=GEM_HOME=" + home + "/gems GEM_PATH=" + home + "/gems\n";
        u += "# The Ruby the tasks bundled with ([control] runtimes): first on PATH, its bundle in ExecStart.\n";
        u += "Environment=PATH=" + path + "\n";
        u += "EnvironmentFile=-" + env + "\n";
        const std::string bind = a.host == "::1" ? "tcp://[::1]:" + port : "tcp://" + a.host + ":" + port;
        u += "ExecStart=" + runtime + "/bundle exec puma -e production -b " + bind + "\n";
    }
    u += "Restart=on-failure\nRestartSec=2\nKillMode=mixed\nTimeoutStopSec=30\nUMask=0027\n";
    u += std::string("# Hardening that costs ") + server + " nothing: it writes only below its own directory and its home.\n";
    u += "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n";
    u += "ReadWritePaths=" + root + " " + home + "\n";
    u += "ProtectHome=yes\nRestrictSUIDSGID=yes\nProtectKernelTunables=yes\nProtectControlGroups=yes\nRestrictRealtime=yes\nLockPersonality=yes\n";
    u += "CapabilityBoundingSet=\nMemoryMax=1G\nTasksMax=256\n\n";
    u += "[Install]\nWantedBy=multi-user.target\n";
    json::Value cmds = json::Value::array()
                           .push("agensio ctl site-unit " + name + " --out /etc/systemd/system/" + unit_name)
                           .push("systemctl daemon-reload")
                           .push("systemctl enable --now " + unit_name);
    std::string hint = "root installs it with run_as_root (the unit runs " + std::string(server) + " as " + site.user + ", never as root); after a change to the site's "
                       "environment" + std::string(python ? ", its names (an alias)" : "") + " or its " + (python ? "Python" : "Ruby") +
                       ", root renders it again and runs systemctl restart " + unit_name;
    if (python) hint += "; the tasks it needs first: venv_create, pip_install_requirements, pip_install with packages \"gunicorn\", django_settings, migrate, collectstatic";
    if (node) hint += "; the tasks it needs first: npm_ci, and the application's own post-install scripts through npm_run (Uptime Kuma: download-dist)";
    return json::Value::object().set("ok", true).set("site", name).set("unit_name", unit_name).set("path", "/etc/systemd/system/" + unit_name)
        .set("unit", u).set("run_as_root", cmds).set("hint", hint);
}

std::vector<std::string> next_steps(const SiteSpec& spec, const Config& cfg) {
    std::vector<std::string> cmds;
    const bool php = php_app(spec.app);
    // Two entries, not one `a && b`: `agensio pools` exits 3 when it wrote files, which is
    // exactly when the reload matters (2026-09-20: the && skipped it).
    if (php && !spec.user.empty() && spec.php_socket.empty()) {
        cmds.push_back("agensio pools");
        cmds.push_back(php_fpm_reload_command(cfg, spec.php_version));
    }
    // Only while the certificate is still to come: an update of a site whose certificate is
    // issued said this too, and an agent passed it on as a task (2026-10-02 alpha.44 report).
    if (spec.https == "auto") {
        bool issued = false;
        if (const SiteConfig* existing = find_site(cfg, spec.domain); existing && existing->tls) {
            const CertificateState st = certificate_state(*existing->tls, std::time(nullptr));
            issued = st.present && !st.placeholder;
        }
        if (!issued) cmds.push_back("# make sure " + spec.domain + " resolves to this server and port 80 is reachable; the certificate follows within a minute");
    }
    if (spec.app == "redmine") {
        // Redmine from its release archive (2026-09-27 report: the database.yml and Puma walls),
        // the steps still open by what is on disk (alpha.33 report: an update of an installed
        // Redmine repeated the whole chain from site-install).
        std::error_code ec;
        auto file = [&](const char* rel) { return !spec.root.empty() && std::filesystem::is_regular_file(spec.root + rel, ec); };
        auto dir = [&](const char* rel) { return !spec.root.empty() && std::filesystem::is_directory(spec.root + rel, ec); };
        const bool gemfile = file("/Gemfile");
        const std::string service = "then the service: site-unit " + spec.domain + " renders its unit for root, site-service " + spec.domain + " shows whether it runs";
        const std::string env = "site-env-set " + spec.domain + " --set DATABASE_URL=sqlite3:db/production.sqlite3 (or postgresql://USER:PASSWORD@HOST/NAME)";
        if (!gemfile) {
            cmds.push_back("# Redmine: site-install " + spec.domain + " --version 7.0.1 --sha256 <the value redmine.org publishes>, then " + env + ", then site-task " +
                           spec.domain + " database_config, gemfile_local, bundle_install, db_migrate, load_default_data --param lang=en, assets_precompile; " + service);
        } else if (dir("/vendor/bundle") && dir("/public/assets")) {
            cmds.push_back("# Redmine is in place: site-task " + spec.domain + " db_migrate after an upgrade, plugins_migrate after a plugin (site-install --path "
                           "plugins/NAME --create-path, then bundle_install), assets_precompile after either; restart its service after each");
        } else {
            std::string open;
            auto add = [&](const std::string& step) { open += (open.empty() ? "" : ", ") + step; };
            const bool dbyml = file("/config/database.yml");
            if (!dbyml) add("database_config");
            if (!file("/Gemfile.local")) add("gemfile_local");
            if (!dir("/vendor/bundle")) add("bundle_install");
            add("db_migrate");
            add("load_default_data --param lang=en (once, on a new database)");
            add("assets_precompile");
            cmds.push_back("# Redmine is unpacked: " + (dbyml ? std::string() : env + ", then ") + "site-task " + spec.domain + " " + open + "; " + service);
        }
    }
    if (node_app(spec.app)) {
        // Node (2026-09-28): the steps still open, by what the project directory holds.
        std::error_code ec;
        auto file = [&](const char* rel) { return !spec.root.empty() && std::filesystem::is_regular_file(spec.root + rel, ec); };
        const std::string d = spec.domain;
        const std::string service = "then the service: site-unit " + d + " renders its unit for root (root's node on the entry, bound to " +
                                    (spec.upstream.empty() ? std::string("the upstream") : spec.upstream) + "), site-service " + d + " shows whether it runs";
        const std::string entry = spec.entry.empty() ? "site-update " + d + " --entry FILE (the file node runs: package.json's start script names it; "
                                                                           "site-install's facts guess it), "
                                                     : std::string();
        if (!file("/package.json"))
            cmds.push_back("# a Node application: site-install " + d + " with its release archive (package.json and package-lock.json at its top), "
                           "then site-task " + d + " npm_ci and the post-install scripts it documents with npm_run (Uptime Kuma: download-dist); " + entry +
                           service);
        else if (!std::filesystem::is_directory(spec.root + "/node_modules", ec))
            cmds.push_back("# the application is in place: site-task " + d + " npm_ci, then the post-install scripts it documents with npm_run (Uptime "
                           "Kuma: download-dist); " + entry + service);
        else if (spec.entry.empty())
            cmds.push_back("# its dependencies are installed: " + entry + service);
        else
            cmds.push_back("# the application is in place: site-task " + d + " npm_ci after its lockfile changed (an upgrade), npm_run for the steps "
                           "an upgrade documents; restart its service after each");
    }
    if (python_app(spec.app)) {
        // Django and Wagtail (2026-09-28): the chain still open, by what the project directory
        // holds (the server reads it through its group; the virtualenv in the account's 0700
        // home it cannot see, so venv_create is named whenever the packages are).
        std::error_code ec;
        auto file = [&](const char* rel) { return !spec.root.empty() && std::filesystem::is_regular_file(spec.root + rel, ec); };
        const std::string d = spec.domain;
        const std::string service = "then the service: site-unit " + d + " renders its Gunicorn unit for root, site-service " + d + " shows whether it runs";
        const std::string settings = "site-env-set " + d + " --generate DJANGO_SECRET_KEY, site-task " + d + " django_settings";
        const std::string admin = "site-env-set " + d + " --generate DJANGO_SUPERUSER_PASSWORD, site-task " + d +
                                  " createsuperuser --param username=admin --param email=ADDRESS";
        if (!file("/manage.py")) {
            const std::string framework = spec.app == "wagtail" ? "wagtail" : "django";
            cmds.push_back("# a new " + std::string(spec.app == "wagtail" ? "Wagtail site" : "Django project") + ": site-task " + d +
                           " venv_create, pip_install --param \"packages=" + framework + " gunicorn\" (you confirm it), startproject (it creates the project " +
                           spec.project + "), pip_install_requirements; " + settings + "; site-task " + d + " migrate, collectstatic; " + admin + "; " + service +
                           ". An existing project comes with site-install instead, then venv_create, pip_install_requirements and pip_install gunicorn");
        } else if (!file("/agensio_settings.py")) {
            cmds.push_back("# the project is in place: site-task " + d + " venv_create, pip_install_requirements, pip_install --param packages=gunicorn "
                           "(you confirm it); " + settings + "; site-task " + d + " migrate, collectstatic; " + admin + "; " + service);
        } else if (!std::filesystem::is_directory(spec.root + "/static", ec)) {
            cmds.push_back("# the project and its settings are in place: site-task " + d + " migrate, collectstatic; " + admin + " (once); " + service);
        } else {
            cmds.push_back("# the project is in place: site-task " + d + " migrate after an upgrade, collectstatic after static changes, "
                           "pip_install_requirements after a requirements.txt change; restart its service after each");
        }
    }
    if (spec.app == "rails") {
        // What is on disk decides the chain (2026-09-27 report: an update of a site that held
        // an application repeated "gem_install_rails, then rails_new", which would be refused).
        std::error_code gem_ec, bundle_ec;
        const bool gemfile = !spec.root.empty() && std::filesystem::is_regular_file(spec.root + "/Gemfile", gem_ec);
        const bool bundled = gemfile && std::filesystem::is_directory(spec.root + "/vendor/bundle", bundle_ec);
        std::error_code db_ec;
        const bool dbyml = gemfile && std::filesystem::exists(spec.root + "/config/database.yml", db_ec);
        const std::string puma = "run Puma on " + spec.upstream + " (site-unit " + spec.domain + " renders its unit for root; it loads the site's environment file)";
        if (gemfile && !dbyml && !bundled)
            cmds.push_back("# the application is in place without config/database.yml: site-env-set " + spec.domain + " --set DATABASE_URL=sqlite3:db/production.sqlite3 "
                           "(or postgresql://...), site-task " + spec.domain + " database_config, then bundle_install, db_prepare and assets_precompile; then " + puma);
        else if (gemfile && bundled)
            cmds.push_back("# the application is in place: site-task " + spec.domain + " db_migrate after new migrations, assets_precompile after asset "
                           "changes, bundle_install after a Gemfile change; restart its service after each");
        else if (gemfile)
            cmds.push_back("# the application is in place: site-task " + spec.domain + " bundle_install, then db_prepare and assets_precompile; then " + puma);
        else if (gem_ec && gem_ec != std::errc::no_such_file_or_directory)
            cmds.push_back("# a new application: site-task " + spec.domain + " gem_install_rails, then rails_new --param name=NAME, db_prepare and assets_precompile; "
                           "an application installed from an archive: bundle_install, db_prepare, assets_precompile (site-tasks " + spec.domain + " lists them); then " + puma);
        else
            cmds.push_back("# the application: site-task " + spec.domain + " gem_install_rails, then rails_new --param name=NAME, db_prepare and assets_precompile "
                           "(site-tasks " + spec.domain + " lists them); then " + puma);
    }
    // The body limit, before the first upload meets it (2026-09-27 report: a 2.75 MB cover got
    // 413 on a site nobody had told about the 1 MB default); only while the site has none of
    // its own (alpha.33 report: a site at 100 MB was told how to raise it to 100 MB).
    if (!spec.app.empty() && spec.app != "static" && !(spec.settings.is_object() && spec.settings["max_body_size"].is_string()))
        cmds.push_back("# request bodies (uploads included) above " + size_text(cfg.max_body_size) + ", the server's default, get 413 before the application sees "
                       "them; site-update " + spec.domain + " --set max_body_size=100MB raises it, up to [control] site_limits");
    return cmds;
}

}  // namespace agensio::control
