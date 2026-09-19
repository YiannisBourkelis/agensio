#include "control/sites.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

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
    v.set("app", app).set("root", root);
    if (!upstream.empty()) v.set("upstream", upstream);
    if (!php_socket.empty()) v.set("php_socket", php_socket);
    if (php_children) v.set("php_children", php_children);
    if (!php_version.empty()) v.set("php_version", php_version);
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
    out.user = v.get("user");
    out.user_decided = true;
    out.no_user = out.user.empty();
    out.group = v.get("group");
    out.app = v.get("app");
    out.root = v.get("root");
    out.upstream = v.get("upstream");
    out.php_socket = v.get("php_socket");
    out.php_children = static_cast<int>(v["php_children"].num());
    out.php_version = v.get("php_version");
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

std::string detect_app(const fs::path& root) {
    std::error_code ec;
    if (!fs::is_directory(root, ec)) return {};
    if (fs::exists(root / "artisan", ec) || fs::exists(root.parent_path() / "artisan", ec)) return "laravel";
    if (fs::exists(root / "core" / "lib" / "Drupal.php", ec) || fs::exists(root / "web" / "core" / "lib" / "Drupal.php", ec)) return "drupal";
    if (fs::exists(root / "wp-config.php", ec) || fs::is_directory(root / "wp-includes", ec)) return "wordpress";
    if (fs::exists(root / "index.php", ec)) return "php";
    if (fs::exists(root / "package.json", ec) || fs::exists(root / "Gemfile", ec)) return "proxy";
    return "static";
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
    if (has_key(body, "app")) spec.app = body.get("app");
    if (has_key(body, "root")) spec.root = body.get("root");
    if (has_key(body, "upstream")) spec.upstream = body.get("upstream");
    if (has_key(body, "group")) spec.group = body.get("group");
    if (has_key(body, "php_socket")) spec.php_socket = body.get("php_socket");
    if (has_key(body, "php_children")) spec.php_children = static_cast<int>(body["php_children"].num());
    if (has_key(body, "php_version")) spec.php_version = body.get("php_version");
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
    for (const auto& f : {spec.cert, spec.key})
        if (!f.empty() && !safe_path(f, why)) {
            error = "https cert/key: " + why;
            return needs;
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
    if (spec.root.empty() && spec.app != "proxy")
        needs.push_back(Decision{"root", "Where are the site's files? (the document root; for Laravel the project directory)",
                                 (cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root) + "/" + spec.domain + "/web", {}});
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
    if (spec.app == "proxy" && spec.upstream.empty())
        needs.push_back(Decision{"upstream", "Where does the application listen? (http://host:port)", "http://127.0.0.1:3000", {}});
    if (!user_decided)
        needs.push_back(Decision{"user", "Run this site under its own system account? It isolates it from other sites. Answer with user: \"<name>\", or no_user: true for none.",
                                 suggest_user(spec.domain), {}});
    const bool php = spec.app != "static" && spec.app != "proxy" && !spec.app.empty();
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
        if (spec.app == "proxy") {
            s += "app = \"proxy\"\nupstream = " + toml_string(spec.upstream) + "\n";
            if (!spec.root.empty()) s += "root = " + toml_string(spec.root) + "\n";
        } else {
            s += "root = " + toml_string(spec.root) + "\n";
            if (!spec.app.empty() && spec.app != "static") s += "app = " + toml_string(spec.app) + "\n";
        }
        if (!spec.user.empty()) s += "user = " + toml_string(spec.user) + "\n";
        if (!spec.group.empty()) s += "group = " + toml_string(spec.group) + "\n";
        if (!spec.user.empty() && !spec.access_log.empty()) s += "access_log = " + toml_string(spec.access_log) + "\n";
        const bool php = spec.app != "static" && spec.app != "proxy" && !spec.app.empty();
        if (php) {
            if (!spec.php_socket.empty()) s += "php = { socket = " + toml_string(spec.php_socket) + " }\n";
            else if (spec.php_children || !spec.php_version.empty()) {
                s += "php = { ";
                if (spec.php_children) s += "children = " + std::to_string(spec.php_children);
                if (!spec.php_version.empty()) s += std::string(spec.php_children ? ", " : "") + "version = " + toml_string(spec.php_version);
                s += " }\n";
            }
        }
    };
    if (!tls || !spec.redirect_http) {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_plain}) + "\n";
        site_body(out);
    } else {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_plain}) +
               "\nredirect = \"https\"\n";
    }
    if (tls) {
        out += "\n[[site]]\nserver_name = " + toml_list(names) + "\nlisten = " + toml_list({spec.listen_tls}) + "\n";
        site_body(out);
        if (spec.https == "auto") out += "tls = \"auto\"\n";
        else out += "tls = { cert = " + toml_string(spec.cert) + ", key = " + toml_string(spec.key) + " }\n";
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
std::vector<std::string> prerequisites(const SiteSpec& spec, const Config& cfg) {
    std::vector<std::string> cmds;
    // Belt and braces: apply_request validated these; a command is never assembled from a
    // value that would not pass again.
    std::string why;
    if ((!spec.user.empty() && !valid_account(spec.user, why)) || (!spec.group.empty() && !valid_account(spec.group, why)) ||
        (!spec.root.empty() && !safe_path(spec.root, why)) || (!spec.cert.empty() && !safe_path(spec.cert, why)) ||
        (!spec.key.empty() && !safe_path(spec.key, why)))
        return {"# refused: " + why};
    const HostFacts facts = system_facts();
    const ServerAccount server = server_account(cfg, facts);
    const std::string server_group = server.known ? server.group : (cfg.group.empty() ? cfg.user : cfg.group);
    unsigned uid = 0, gid = 0;
    const bool have_user = !spec.user.empty() && facts.user(spec.user, uid, gid);
    if (!spec.user.empty() && !have_user)
        cmds.push_back("useradd --system --no-create-home --home-dir " + cfg.state_dir + "/" + spec.user +
                       " --shell /usr/sbin/nologin " + spec.user);
    if (!spec.group.empty()) {
        unsigned g = 0;
        if (!facts.group(spec.group, g)) cmds.push_back("groupadd " + spec.group + " && usermod -g " + spec.group + " " + spec.user);
    }
    std::error_code ec;
    if (!spec.root.empty()) {
        const std::string owner = spec.user.empty() ? (cfg.user.empty() ? "root" : cfg.user) : spec.user;
        const std::string group = spec.user.empty() ? server_group : server_group;
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
        if (!exists)
            cmds.push_back("mkdir -p " + spec.root + " && chown " + owner + ":" + group + " " + top + " && " + layout);
        else if (!readable || (!spec.user.empty() && (f.uid != uid || !(server.known && f.gid == server.gid))))
            cmds.push_back(layout + "   # the server reads the site's directories through its group");
    }
    if (spec.https == "manual") {
        if (!fs::is_regular_file(spec.cert, ec)) cmds.push_back("# put the certificate chain at " + spec.cert);
        if (!fs::is_regular_file(spec.key, ec)) cmds.push_back("# put the private key at " + spec.key + " (mode 0600)");
    }
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

std::vector<std::string> next_steps(const SiteSpec& spec, const Config& cfg) {
    std::vector<std::string> cmds;
    const bool php = spec.app != "static" && spec.app != "proxy" && !spec.app.empty();
    if (php && !spec.user.empty() && spec.php_socket.empty())
        cmds.push_back("agensio pools && " + php_fpm_reload_command(cfg, spec.php_version));
    if (spec.https == "auto") cmds.push_back("# make sure " + spec.domain + " resolves to this server and port 80 is reachable; the certificate follows within a minute");
    (void)cfg;
    return cmds;
}

}  // namespace agensio::control
