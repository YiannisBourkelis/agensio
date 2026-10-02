#include "control/sites.hpp"

#include "control/commands.hpp"

#include "control/settings.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include "services/appenv.hpp"
#include "services/pools.hpp"

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

}  // namespace

json::Value SiteSpec::to_json() const {
    json::Value v = json::Value::object();
    v.set("domain", domain).set("aliases", strings(aliases)).set("https", https);
    if (https == "manual") v.set("cert", cert).set("key", key);
    v.set("redirect_http", redirect_http).set("hsts", hsts).set("user", user).set("no_user", user.empty()).set("group", group);
    if (encoded_slashes == "allow") v.set("encoded_slashes", encoded_slashes);
    v.set("app", app).set("root", root);
    if (!upstream.empty()) v.set("upstream", upstream);
    if (!project.empty()) v.set("project", project);
    if (!entry.empty()) v.set("entry", entry);
    if (!php_socket.empty()) v.set("php_socket", php_socket);
    if (php_children) v.set("php_children", php_children);
    if (!php_version.empty()) v.set("php_version", php_version);
    if (settings.is_object() && !settings.members().empty()) v.set("settings", settings);
    if (rules.is_object() && !rules.members().empty()) v.set("rules", rules);
    if (!login_paths.empty()) v.set("login_paths", strings(login_paths));
    if (!access_log.empty()) v.set("access_log", access_log);
    v.set("listen_plain", listen_plain).set("listen_tls", listen_tls);
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
    if (has_key(v, "hsts")) out.hsts = v["hsts"].boolean();
    out.encoded_slashes = v.get("encoded_slashes") == "allow" ? "allow" : "";
    out.user = v.get("user");
    out.user_decided = true;
    out.no_user = out.user.empty();
    out.group = v.get("group");
    out.app = v.get("app");
    out.root = v.get("root");
    out.upstream = v.get("upstream");
    out.project = v.get("project");
    out.entry = v.get("entry");
    out.php_socket = v.get("php_socket");
    out.php_children = static_cast<int>(v["php_children"].num());
    out.php_version = v.get("php_version");
    if (v["settings"].is_object()) out.settings = v["settings"];
    if (v["rules"].is_object()) out.rules = v["rules"];
    out.login_paths = string_list(v["login_paths"]);
    if (out.settings["children"].type() == json::Value::Type::number) out.php_children = static_cast<int>(out.settings["children"].num());
    out.access_log = v.get("access_log");
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

std::string check_rules(const json::Value& given, const SiteSpec& spec, json::Value& normalised) {
    normalised = json::Value::object();
    if (!given.is_object()) return "rules must be an object: {\"private\": [...], \"entry_points\": [...], \"cache\": [...], \"front_controller\": \"/index.php\"}";
    for (const auto& m : given.members())
        if (m.first != "private" && m.first != "entry_points" && m.first != "cache" && m.first != "front_controller")
            return "rules: unknown key '" + m.first + "' (private, entry_points, cache, front_controller)";
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
            for (const auto& pr : priv)
                if (p == pr || (pr.back() == '/' && p.starts_with(pr))) return "rules: the cached directory " + p + " lies under the private path " + pr;
            cache.push(json::Value::object().set("path", p).set("max_age", age.num()));
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
    json::Value pv = json::Value::array(), ev = json::Value::array();
    for (const auto& x : priv) pv.push(x);
    for (const auto& x : entries) ev.push(x);
    if (!priv.empty()) normalised.set("private", pv);
    if (!entries.empty()) normalised.set("entry_points", ev);
    if (!cache.items().empty()) normalised.set("cache", cache);
    if (!front.empty()) normalised.set("front_controller", front);
    return "";
}

std::vector<RuleLocation> rule_locations(const SiteSpec& spec) {
    std::vector<RuleLocation> out;
    const json::Value& r = spec.rules;
    if (!r.is_object()) return out;
    for (const auto& p : r["private"].items()) out.push_back({RuleLocation::Kind::private_, std::string(p.str()), p.str().back() != '/', false, 0});
    for (const auto& e : r["entry_points"].items()) out.push_back({RuleLocation::Kind::entry, std::string(e.str()), true, false, 0});
    if (!r["entry_points"].items().empty()) out.push_back({RuleLocation::Kind::no_other_php, ".php", false, true, 0});
    for (const auto& c : r["cache"].items()) out.push_back({RuleLocation::Kind::cache, std::string(c.get("path")), false, false, static_cast<long>(c["max_age"].num())});
    return out;
}

std::vector<Decision> apply_request(const json::Value& body, const Config& cfg, SiteSpec& spec, std::string& error) {
    std::vector<Decision> needs;
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
    if (has_key(body, "hsts")) spec.hsts = body["hsts"].boolean();
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
        if (const std::string bad = check_rules(body["rules"], spec, normalised); !bad.empty()) {
            error = bad;
            return needs;
        }
        spec.rules = normalised;
    }
    // The login paths (2026-10-02): given whole, each a plain URL path (check_login_path), at
    // most 16, [] clears them. They change no location: the fail2ban jail counts attempts there.
    if (has_key(body, "login_paths")) {
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
    if (has_key(body, "access_log")) spec.access_log = body.get("access_log");
    if (has_key(body, "listen_plain")) spec.listen_plain = body.get("listen_plain");
    if (has_key(body, "listen_tls")) spec.listen_tls = body.get("listen_tls");
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
    for (const auto& f : {spec.cert, spec.key})
        if (!f.empty() && !safe_path(f, why)) {
            error = "https cert/key: " + why;
            return needs;
        }
    if (spec.rules.is_object() && !spec.rules.members().empty()) {
        json::Value again;
        if (const std::string bad = check_rules(spec.rules, spec, again); !bad.empty()) {
            error = "the site's rules no longer fit its app: " + bad + " (send rules: {} to clear them)";
            return needs;
        }
    }
    const bool user_decided = spec.user_decided || !spec.user.empty();
    // A site with its own user gets its own access log next to the server's: sites of
    // different users never share a log (rule 5), and the file is made theirs to read.
    if (!spec.user.empty() && spec.access_log.empty()) {
        const fs::path base = (cfg.log.access.empty() || cfg.log.access == "off") ? fs::path("/var/log/agensio")
                                                                                     : fs::path(cfg.log.access).parent_path();
        spec.access_log = (base / "sites" / (spec.domain + ".log")).string();
    }

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
            if (!spec.app.empty() && spec.app != "static") s += "app = " + toml_string(spec.app) + "\n";
        }
        if (!spec.user.empty()) s += "user = " + toml_string(spec.user) + "\n";
        if (!spec.group.empty()) s += "group = " + toml_string(spec.group) + "\n";
        if (!spec.user.empty() && !spec.access_log.empty()) s += "access_log = " + toml_string(spec.access_log) + "\n";
        if (!spec.login_paths.empty()) s += "login_paths = " + toml_list(spec.login_paths) + "   # fail2ban counts login attempts here (agensio ctl protection)\n";
        if (spec.encoded_slashes == "allow") s += "encoded_slashes = \"allow\"   # a %2F in the path is decoded and looked up (Apache's NoDecode), not 404\n";
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
                         "\nadd_headers = { \"Cache-Control\" = \"public, max-age=" + std::to_string(rl.max_age) + "\" }\n";
                    break;
                }
            }
    };
    if (!tls || !spec.redirect_http) {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_plain}) + "\n";
        site_body(out);
        rules_locations(out);
    } else {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_plain}) +
               "\nredirect = \"https\"\n";
    }
    if (tls) {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_tls}) + "\n";
        site_body(out);
        if (spec.https == "auto") out += "tls = \"auto\"\n";
        else out += "tls = { cert = " + toml_string(spec.cert) + ", key = " + toml_string(spec.key) + " }\n";
        rules_locations(out);
        if (spec.hsts)
            out += "\n[[site.location]]\npath = \"/\"\nadd_headers = { \"Strict-Transport-Security\" = \"max-age=31536000\" }\n";
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
    // A listener the running server does not hold yet: a reload binds it, unless the port is
    // privileged and the server has already dropped root. Then the file is written and the
    // site is served after a restart; saying so here saves the caller a failed reload that
    // looks like a permission problem.
    if (!privileged) {
        for (const std::string& address : {spec.listen_plain, spec.listen_tls}) {
            const bool used = address == spec.listen_plain ? (spec.https == "none" || spec.redirect_http) : spec.https != "none";
            if (!used) continue;
            bool bound = false;
            for (const auto& s : cfg.sites)
                for (const auto& l : s.listen) bound = bound || l == address;
            const std::size_t colon = address.rfind(':');
            const int port = colon == std::string::npos ? 0 : std::atoi(address.c_str() + colon + 1);
            if (!bound && port > 0 && port < 1024)
                out.push_back({"needs_restart", "listener " + address + " is not bound yet and the server no longer runs as root, so this "
                                                "port cannot be added by a reload; the site file is written and the site is served after a restart",
                               "systemctl restart agensio", false, json::Value::object().set("op", "service_restart")});
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

// The php-fpm unit that reads the pool directory `agensio pools` writes into: Debian's
// php8.4-fpm, RHEL's php-fpm, brew's php service.
std::string php_fpm_reload_command(const Config& cfg, const std::string& version) {
    const fs::path dir = pools_dir(cfg, version);
    const std::string d = dir.string();
    if (d.empty()) return "systemctl reload php-fpm   # (pool directory not found: set server.pools)";
    if (d.starts_with("/etc/php/")) {  // /etc/php/8.4/fpm/pool.d
        const std::string v = d.substr(9, d.find('/', 9) - 9);
        return "systemctl reload php" + v + "-fpm";
    }
    if (d.starts_with("/opt/homebrew/") || d.starts_with("/usr/local/")) return "brew services restart php";
    return "systemctl reload php-fpm";
}

json::Value service_unit(const SiteConfig& site, const Config& cfg) {
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
    u += "#   agensio ctl site-unit " + name + " --raw > /etc/systemd/system/" + unit_name + "\n";
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
                           .push("agensio ctl site-unit " + name + " --raw > /etc/systemd/system/" + unit_name)
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
