#include "config.hpp"

#include "handlers/fastcgi.hpp"
#include "path.hpp"
#include "services/pools.hpp"

#include <algorithm>
#include <map>
#include <ostream>
#include <sstream>
#include <cctype>
#include <charconv>
#include <stdexcept>
#include <thread>

#include <toml.hpp>

namespace agensio {

namespace fs = std::filesystem;

std::size_t parse_size(std::string_view text) {
    std::size_t i = 0;
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i])))
        ++i;
    std::size_t start = i;
    while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i])))
        ++i;
    if (start == i) throw std::invalid_argument("size must start with a number: '" + std::string(text) + "'");
    std::uint64_t value = 0;
    auto [ptr, ec] = std::from_chars(text.data() + start, text.data() + i, value);
    if (ec != std::errc()) throw std::invalid_argument("bad size: '" + std::string(text) + "'");
    std::string unit;
    for (; i < text.size(); ++i) {
        char c = text[i];
        if (!std::isspace(static_cast<unsigned char>(c)))
            unit += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    std::uint64_t mult = 1;
    if (unit.empty() || unit == "b") mult = 1;
    else if (unit == "k" || unit == "kb" || unit == "kib") mult = 1024;
    else if (unit == "m" || unit == "mb" || unit == "mib") mult = 1024ull * 1024;
    else if (unit == "g" || unit == "gb" || unit == "gib") mult = 1024ull * 1024 * 1024;
    else throw std::invalid_argument("unknown size unit '" + unit + "' in '" + std::string(text) + "'");
    return static_cast<std::size_t>(value * mult);
}

namespace {

std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

[[noreturn]] void fail(const std::string& msg) {
    throw std::runtime_error(msg);
}

std::size_t size_node(const toml::node_view<const toml::node>& n, std::size_t fallback, const char* what) {
    if (!n) return fallback;
    if (auto v = n.value<std::int64_t>()) {
        if (*v < 0) fail(std::string(what) + " must not be negative");
        return static_cast<std::size_t>(*v);
    }
    if (auto s = n.value<std::string>()) {
        try {
            return parse_size(*s);
        } catch (const std::exception& e) { fail(std::string(what) + ": " + e.what()); }
    }
    fail(std::string(what) + " must be an integer or a size string like \"4MB\"");
}

std::vector<std::string> string_list(const toml::node_view<const toml::node>& n, const char* what) {
    std::vector<std::string> out;
    if (!n) return out;
    if (auto s = n.value<std::string>()) {
        out.push_back(*s);
        return out;
    }
    if (auto arr = n.as_array()) {
        for (auto& e : *arr) {
            if (auto s = e.value<std::string>()) out.push_back(*s);
            else fail(std::string(what) + " must contain only strings");
        }
        return out;
    }
    fail(std::string(what) + " must be a string or an array of strings");
}

// Normalises a listen address to "host:port". Accepts "8080", ":8080",
// "0.0.0.0:8080", "[::]:8080", "127.0.0.1:8080".
std::string normalise_listen(const std::string& in) {
    std::string s = in;
    auto colon = s.rfind(':');
    std::string host, port;
    if (colon == std::string::npos) {
        host = "0.0.0.0";
        port = s;
    } else {
        host = s.substr(0, colon);
        port = s.substr(colon + 1);
        if (host.empty()) host = "0.0.0.0";
        if (host.size() >= 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
    }
    if (port.empty() || !std::all_of(port.begin(), port.end(), [](unsigned char c) { return std::isdigit(c); }))
        fail("listen address '" + in + "' has no valid port");
    int p = std::stoi(port);
    if (p < 1 || p > 65535) fail("listen address '" + in + "' port out of range");
    return host + ":" + std::to_string(p);
}

fs::path resolve(const fs::path& base_dir, const std::string& p) {
    fs::path path(p);
    if (path.is_relative()) path = base_dir / path;
    return path.lexically_normal();
}

std::string resolve_root(const fs::path& base_dir, const std::string& root, const std::string& where) {
    fs::path root_path = resolve(base_dir, root);
    std::error_code ec;
    if (!fs::is_directory(root_path, ec)) fail(where + ": root '" + root_path.string() + "' is not a directory");
    std::string out = fs::canonical(root_path, ec).string();
    if (ec) fail(where + ": cannot resolve root '" + root_path.string() + "'");
    while (out.size() > 1 && out.back() == '/')
        out.pop_back();
    return out;
}

std::vector<std::string> index_list(const toml::node_view<const toml::node>& n, const std::string& where) {
    auto list = string_list(n, (where + ".index").c_str());
    for (auto& i : list)
        if (i.empty() || i.find('/') != std::string::npos) fail(where + ": index names must be plain file names");
    return list;
}

std::vector<TryStep> try_files_of(const toml::node_view<const toml::node>& n, const std::string& where) {
    try {
        return parse_try_files(string_list(n, (where + ".try_files").c_str()));
    } catch (const std::invalid_argument& e) {
        fail(where + ".try_files: " + e.what());
    }
}

bool symlinks_deny_of(const toml::node_view<const toml::node>& n, bool fallback, const std::string& where) {
    if (!n) return fallback;
    std::string symlinks = to_lower(n.value_or(std::string("allow")));
    if (symlinks != "allow" && symlinks != "deny") fail(where + ": symlinks must be \"allow\" or \"deny\"");
    return symlinks == "deny";
}

// A user or group name as the pool file and the system will take it: a POSIX portable
// name, so it can never carry a path, a space or an ini delimiter. "" when absent.
std::string account_name(const toml::node_view<const toml::node>& n, const std::string& where) {
    const std::string name = n.value_or(std::string());
    if (name.empty()) return name;
    if (name.size() > 32) fail(where + ": name too long");
    for (std::size_t i = 0; i < name.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(name[i]);
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
                        (i > 0 && ((c >= '0' && c <= '9') || c == '-'));
        if (!ok) fail(where + ": '" + name + "' is not a valid account name");
    }
    return name;
}

// Where the distro's php-fpm keeps its sockets, for generated pools.
std::string default_pools_run() {
#ifdef __APPLE__
    for (const char* prefix : {"/opt/homebrew", "/usr/local"})
        if (fs::is_directory(std::string(prefix) + "/etc/php")) return std::string(prefix) + "/var/run";
#endif
    if (fs::is_directory("/etc/php-fpm.d")) return "/run/php-fpm";  // RHEL, Fedora
    return "/run/php";                                               // Debian, Ubuntu, Alpine
}

std::vector<std::pair<std::string, std::string>> headers_of(const toml::table* t, const std::string& where);

// The proxy's header policy keys of a `proxy = { ... }` table (site defaults or a location).
void parse_proxy_policy(const toml::table& t, const fs::path& base_dir, UpstreamConfig& out, const std::string& where) {
    if (auto h = t["host"].value<std::string>()) {
        out.host = *h == "pass" || *h == "upstream" ? *h : to_lower(*h);
        if (out.host.empty() || out.host.find_first_of(" \t\r\n/") != std::string::npos)
            fail(where + ".host must be \"pass\", \"upstream\" or a host name");
    }
    if (auto f = t["forwarded"].value<std::string>()) {
        out.forwarded = to_lower(*f);
        if (out.forwarded != "x-forwarded" && out.forwarded != "forwarded" && out.forwarded != "both" &&
            out.forwarded != "off")
            fail(where + ".forwarded must be \"x-forwarded\", \"forwarded\", \"both\" or \"off\"");
    }
    if (t.contains("headers")) {
        auto* ht = t["headers"].as_table();
        if (!ht) fail(where + ".headers must be a table");
        for (auto& [name, value] : headers_of(ht, where)) {
            bool replaced = false;
            for (auto& existing : out.set_headers)
                if (Headers::iequals(existing.first, name)) {
                    existing.second = value;
                    replaced = true;
                }
            if (!replaced) out.set_headers.emplace_back(name, value);
        }
    }
    if (t.contains("hide"))
        for (const auto& name : string_list(t["hide"], (where + ".hide").c_str())) {
            for (unsigned char c : name)
                if (c <= 0x20 || c == ':' || c == 0x7f) fail(where + ".hide: bad field name '" + name + "'");
            out.hide.push_back(name);
        }
    if (auto r = t["redirects"].value<std::string>()) {
        const std::string mode = to_lower(*r);
        if (mode != "rewrite" && mode != "pass") fail(where + ".redirects must be \"rewrite\" or \"pass\"");
        out.rewrite_redirects = mode == "rewrite";
    }
    if (auto tt = t["tls"].as_table()) {
        out.tls.verify = (*tt)["verify"].value_or(out.tls.verify);
        out.tls.server_name = (*tt)["server_name"].value_or(out.tls.server_name);
        if (auto ca = (*tt)["ca"].value<std::string>()) {
            out.tls.ca_file = resolve(base_dir, *ca).string();
            if (!fs::is_regular_file(out.tls.ca_file)) fail(where + ".tls.ca: file not found: " + out.tls.ca_file);
        }
    } else if (t.contains("tls")) {
        fail(where + ".tls must be a table { verify, server_name, ca }");
    }
    out.upgrade = t["upgrade"].value_or(out.upgrade);
    if (auto v = t["tunnel_timeout"].value<std::int64_t>()) {
        if (*v < 0 || *v > 86400 * 30) fail(where + ".tunnel_timeout out of range (seconds, 0 = none)");
        out.tunnel_timeout_s = static_cast<std::uint32_t>(*v);
    }
}

// `php = { ... }` (site) or `fastcgi = { ... }` (location): socket plus options, on top of `base`.
void parse_fcgi_table(const toml::table& t, const fs::path& base_dir, FcgiConfig& out, const std::string& where) {
    if (auto sock = t["socket"].value<std::string>()) {
        std::string text = *sock;
        if (!text.starts_with("unix:") && text.find(':') == std::string::npos)
            text = resolve(base_dir, text).string();  // a bare path: relative to the config file
        std::string err;
        if (!parse_fcgi_address(text, out.address, err)) fail(where + ".socket: " + err);
        out.addresses = {out.address};
        out.configured = true;
    }
    if (auto rr = t["remote_root"].value<std::string>()) {
        if (rr->empty() || (*rr)[0] != '/') fail(where + ".remote_root must be an absolute path");
        out.remote_root = *rr;
        while (out.remote_root.size() > 1 && out.remote_root.back() == '/') out.remote_root.pop_back();
    }
    out.options.buffering = t["buffering"].value_or(out.options.buffering);
    out.options.keep_conn = t["keep_conn"].value_or(out.options.keep_conn);
    auto seconds = [&](const char* key, std::chrono::milliseconds& target) {
        if (auto v = t[key].value<double>()) {
            if (*v <= 0) fail(where + "." + key + " must be positive");
            target = std::chrono::milliseconds(static_cast<long long>(*v * 1000));
        }
    };
    seconds("connect_timeout", out.options.connect_timeout);
    seconds("send_timeout", out.options.send_timeout);
    seconds("read_timeout", out.options.read_timeout);
    seconds("queue_wait", out.options.queue_wait);
    out.options.buffer_max = size_node(t["buffer_max"], out.options.buffer_max, (where + ".buffer_max").c_str());
    out.options.head_max = size_node(t["head_max"], out.options.head_max, (where + ".head_max").c_str());
    out.options.buffer_file_max = size_node(t["buffer_file_max"], static_cast<std::size_t>(out.options.buffer_file_max),
                                            (where + ".buffer_file_max").c_str());
    if (out.options.head_max < 1024) fail(where + ".head_max must be at least 1024");
    out.options.request_buffering = t["request_buffering"].value_or(out.options.request_buffering);
    out.options.path_info = t["path_info"].value_or(out.options.path_info);
    out.options.request_buffer_max =
        size_node(t["request_buffer_max"], out.options.request_buffer_max, (where + ".request_buffer_max").c_str());
    auto count = [&](const char* key, std::size_t& target, std::int64_t lo, std::int64_t hi) {
        if (auto v = t[key].value<std::int64_t>()) {
            if (*v < lo || *v > hi) fail(where + "." + key + " out of range");
            target = static_cast<std::size_t>(*v);
        }
    };
    count("max_idle", out.options.max_idle, 0, 1024);
    if (auto v = t["max_fails"].value<std::int64_t>()) {
        if (*v < 1 || *v > 1000) fail(where + ".max_fails out of range");
        out.options.max_fails = static_cast<unsigned>(*v);
    }
    seconds("fail_timeout", out.options.fail_timeout);
    count("max_connections", out.options.max_connections, 1, 65536);
    count("queue_depth", out.options.queue_depth, 0, 1 << 20);
    if (auto v = t["priority_reserve"].value<double>()) {
        if (*v < 0.0 || *v > 1.0) fail(where + ".priority_reserve must be in [0, 1]");
        out.options.priority_reserve = *v;
    }
    const auto wait_s = std::chrono::duration_cast<std::chrono::seconds>(out.options.queue_wait).count();
    out.retry_after = std::to_string(wait_s < 1 ? 1 : wait_s);
}

std::vector<std::pair<std::string, std::string>> headers_of(const toml::table* t, const std::string& where) {
    std::vector<std::pair<std::string, std::string>> out;
    if (!t) return out;
    for (auto& [name, node] : *t) {
        auto value = node.value<std::string>();
        if (!value) fail(where + ".add_headers." + std::string(name.str()) + " must be a string");
        for (unsigned char c : name.str())
            if (c <= 0x20 || c == ':' || c == 0x7f)
                fail(where + ".add_headers: bad field name '" + std::string(name.str()) + "'");
        for (unsigned char c : *value)
            if ((c < 0x20 && c != '\t') || c == 0x7f)
                fail(where + ".add_headers." + std::string(name.str()) + ": control character in value");
        out.emplace_back(std::string(name.str()), *value);
    }
    return out;
}

// `upstream = "http://host:port"` or a list of them (a group: round-robin per worker,
// failed members skipped, see max_fails / fail_timeout), on a location or on a site
// (the `app = "proxy"` preset). A URI part ("http://host:port/" or ".../v1/") replaces
// the location's prefix (nginx proxy_pass semantics) and needs a prefix location.
void parse_upstreams(const toml::node_view<const toml::node>& n, UpstreamConfig& out, bool prefix_location,
                     const std::string& where) {
    std::vector<std::string> upstreams;
    if (auto up = n.value<std::string>()) upstreams.push_back(*up);
    else if (n) upstreams = string_list(n, where.c_str());
    if (n && upstreams.empty()) fail(where + ": empty list");
    for (std::size_t i = 0; i < upstreams.size(); ++i) {
        std::string text = upstreams[i];
        bool tls = false;
        if (text.starts_with("http://")) text = text.substr(7);
        else if (text.starts_with("https://")) {
            text = text.substr(8);
            tls = true;
#ifndef AGENSIO_HAS_TLS
            fail(where + ": https:// needs a build with TLS");
#endif
        }
        std::string rewrite;
        if (!text.starts_with("unix:")) {
            if (const std::size_t slash = text.find('/'); slash != std::string::npos) {
                rewrite = text.substr(slash);
                text.resize(slash);
                if (!prefix_location) fail(where + ": a URI part needs a prefix location");
                if (rewrite.back() != '/') rewrite += '/';
            }
        }
        if (i == 0) out.rewrite = rewrite;
        else if (rewrite != out.rewrite) fail(where + ": every member of the group needs the same URI part");
        UpstreamAddress a;
        std::string err;
        if (!parse_upstream_address(text, a, err)) fail(where + ": " + err);
        if (tls) {
            if (a.unix) fail(where + ": TLS over a unix socket is not supported");
            a.tls = true;
            a.key = "https://" + a.key;
        }
        for (const auto& other : out.addresses)
            if (other.key == a.key) fail(where + ": " + a.key + " listed twice");
        out.addresses.push_back(std::move(a));
    }
    if (!out.addresses.empty()) {
        out.address = out.addresses.front();
        out.configured = true;
    }
}

void parse_location(const toml::table& t, const fs::path& base_dir, SiteConfig& site, const std::string& where) {
    LocationConfig loc;
    auto path = t["path"].value<std::string>();
    if (!path || path->empty() || ((*path)[0] != '/' && (*path)[0] != '.'))
        fail(where + ": 'path' is required and must start with '/' (or '.' for a suffix location)");
    loc.path = *path;
    if (loc.path[0] == '.') loc.path.insert(0, "/");  // ".php" and "/.php" both mean the suffix ".php"
    std::string match = to_lower(t["match"].value_or(std::string("prefix")));
    if (match != "prefix" && match != "exact" && match != "suffix")
        fail(where + ": match must be \"prefix\", \"exact\" or \"suffix\"");
    loc.exact = match == "exact";
    loc.suffix = match == "suffix";
    if (loc.suffix) {
        if (loc.path.size() < 2) fail(where + ": a suffix location needs an ending such as \".php\"");
        loc.path.erase(0, 1);  // the leading '/' only marks it as a path; ".php" is what is matched
    }
    loc.final = t["final"].value_or(false);
    if (loc.final && (loc.exact || loc.suffix)) fail(where + ": 'final' applies to prefix locations only");
    if (t.contains("deny_suffixes")) {
        loc.deny_suffixes = string_list(t["deny_suffixes"], (where + ".deny_suffixes").c_str());
        for (const auto& d : loc.deny_suffixes)
            if (d.size() < 2 || d[0] != '.') fail(where + ".deny_suffixes: entries are endings such as \".php\"");
    }
    for (const auto& other : site.locations)
        if (other.path == loc.path && other.exact == loc.exact && other.suffix == loc.suffix)
            fail(where + ": duplicate location '" + loc.path + "'");
    if (auto root = t["root"].value<std::string>()) loc.root = resolve_root(base_dir, *root, where);
    else loc.root = site.root;
    if (auto alias = t["alias"].value<std::string>()) {
        if (t.contains("root")) fail(where + ": 'root' and 'alias' are mutually exclusive");
        if (loc.exact || loc.suffix || loc.path.back() != '/')
            fail(where + ": 'alias' needs a prefix path ending with '/'");
        loc.alias = resolve_root(base_dir, *alias, where);
    }
    loc.index = t.contains("index") ? index_list(t["index"], where) : site.index;
    loc.try_files = t.contains("try_files") ? try_files_of(t["try_files"], where) : site.try_files;
    loc.hidden_files = t["hidden_files"].value_or(site.hidden_files);
    loc.symlinks_deny = symlinks_deny_of(t["symlinks"], site.symlinks_deny, where);
    if (auto ht = t["add_headers"].as_table()) loc.add_headers = headers_of(ht, where);
    else if (t.contains("add_headers")) fail(where + ": 'add_headers' must be a table");
    // `upstream = "http://host:port"` (or unix:/path) makes a proxy location; `proxy = { ... }`
    // carries the options (the same keys as php/fastcgi) and may name the upstream too.
    // The site's `proxy = { ... }` is the default; the location's table refines it. A
    // location without its own `upstream` inherits the site's (the proxy preset's origin).
    loc.proxy = site.proxy;
    if (t.contains("upstream")) {
        loc.proxy.addresses.clear();
        loc.proxy.configured = false;
        loc.proxy.rewrite.clear();
    }
    if (auto pt = t["proxy"].as_table()) {
        parse_fcgi_table(*pt, base_dir, loc.proxy, where + ".proxy");
        parse_proxy_policy(*pt, base_dir, loc.proxy, where + ".proxy");
    } else if (t.contains("proxy")) {
        fail(where + ": 'proxy' must be a table");
    }
    parse_upstreams(t["upstream"], loc.proxy, !loc.exact && !loc.suffix, where + ".upstream");
    if (t.contains("upstream") && !t.contains("handler")) loc.handler = "proxy";  // the site's origin needs handler = "proxy"
    else if (t.contains("cgi") && !t.contains("handler")) loc.handler = "cgi";
    else loc.handler = to_lower(t["handler"].value_or(std::string("static")));
    if (loc.handler == "static") {
        loc.kind = HandlerKind::static_;
    } else if (loc.handler == "fastcgi") {
        loc.kind = HandlerKind::fastcgi;
        loc.fastcgi = site.php;  // site-level `php = { socket = ... }` is the default
        if (auto ft = t["fastcgi"].as_table()) parse_fcgi_table(*ft, base_dir, loc.fastcgi, where + ".fastcgi");
        else if (t.contains("fastcgi")) fail(where + ": 'fastcgi' must be a table");
        if (!loc.fastcgi.configured)
            fail(where + ": handler \"fastcgi\" needs fastcgi.socket here or php.socket on the site");
        loc.methods = kFcgiMethods;
        loc.allow = allow_header(kFcgiMethods);
        loc.priority = t["priority"].value_or(false);
    } else if (loc.handler == "cgi") {
        // A process per request: the pool caps them per worker (max_connections, default 8)
        // and queues the rest; the script's own output is the response.
        loc.kind = HandlerKind::cgi;
        loc.cgi.options.max_connections = 8;
        loc.cgi.options.queue_depth = 32;
        loc.cgi.options.read_timeout = std::chrono::milliseconds(30000);
        loc.cgi.options.keep_conn = false;
        if (auto ct = t["cgi"].as_table()) {
            parse_fcgi_table(*ct, base_dir, loc.cgi, where + ".cgi");
            if (auto ip = (*ct)["interpreter"].value<std::string>()) {
                loc.cgi.interpreter = resolve(base_dir, *ip).string();
                if (!fs::is_regular_file(loc.cgi.interpreter))
                    fail(where + ".cgi.interpreter: file not found: " + loc.cgi.interpreter);
            }
            if ((*ct).contains("env")) {
                auto* et = (*ct)["env"].as_table();
                if (!et) fail(where + ".cgi.env must be a table");
                for (auto& [name, value] : headers_of(et, where + ".cgi")) {
                    if (name.find('=') != std::string::npos) fail(where + ".cgi.env: bad name '" + name + "'");
                    loc.cgi.env.emplace_back(name, value);
                }
            }
        } else if (t.contains("cgi")) {
            fail(where + ": 'cgi' must be a table");
        }
        loc.cgi.address.key = "cgi:" + site.server_names.front() + loc.path;  // one pool per location
        loc.cgi.addresses = {loc.cgi.address};
        loc.cgi.configured = true;
        loc.cgi.retry_after = "1";
        loc.methods = kFcgiMethods;
        loc.allow = allow_header(kFcgiMethods);
        loc.priority = t["priority"].value_or(false);
    } else if (loc.handler == "proxy") {
        loc.kind = HandlerKind::proxy;
        if (!loc.proxy.configured) fail(where + ": handler \"proxy\" needs upstream = \"http://host:port\"");
        loc.methods = kFcgiMethods;  // every method an application may see
        loc.allow = allow_header(kFcgiMethods);
        loc.priority = t["priority"].value_or(false);
    } else {
        fail(where + ": handler \"" + loc.handler + "\" is not available (\"static\", \"fastcgi\", \"proxy\" or \"cgi\")");
    }
    if (loc.kind == HandlerKind::fastcgi) loc.fastcgi.params_prefix = FcgiHandler::prebuild_params(site, loc);
    if (t.contains("methods")) {
        const MethodSet implemented = loc.kind == HandlerKind::fastcgi ? kFcgiMethods : kStaticMethods;
        MethodSet set = 0;
        for (const auto& name : string_list(t["methods"], (where + ".methods").c_str())) {
            Method m;
            if (!parse_method(name, m) || m == Method::trace || m == Method::connect || m == Method::other)
                fail(where + ".methods: unknown method '" + name + "'");
            if (!(implemented & method_bit(m)))
                fail(where + ".methods: the " + loc.handler + " handler does not implement " + name);
            set |= method_bit(m);
        }
        if (set == 0) fail(where + ".methods must list at least one method");
        loc.methods = set;
        loc.allow = allow_header(set);
    }
    site.locations.push_back(std::move(loc));
}

// A preset is the whole configuration of a common kind of site. It never overrides what
// the site configured by hand: a location the site already defines is left alone, and
// try_files is only set when the site did not set one.
void apply_preset(SiteConfig& site, const std::string& where) {
    if (site.app.empty() || site.app == "static") return;
    auto has = [&](const std::string& path, bool exact, bool suffix) {
        for (const auto& l : site.locations)
            if (l.path == path && l.exact == exact && l.suffix == suffix) return true;
        return false;
    };
    auto fcgi_location = [&](std::string path, bool exact, bool suffix) {
        LocationConfig loc;
        loc.path = std::move(path);
        loc.exact = exact;
        loc.suffix = suffix;
        loc.root = site.root;
        loc.index = site.index;
        loc.try_files = site.try_files;
        loc.hidden_files = site.hidden_files;
        loc.symlinks_deny = site.symlinks_deny;
        loc.handler = "fastcgi";
        loc.kind = HandlerKind::fastcgi;
        loc.fastcgi = site.php;
        loc.methods = kFcgiMethods;
        loc.allow = allow_header(kFcgiMethods);
        loc.origin = "preset:" + site.app;
        loc.fastcgi.params_prefix = FcgiHandler::prebuild_params(site, loc);
        return loc;
    };
    if (site.app == "proxy") {
        // Everything to the origin(s) named on the site; a hand-written "/" location wins,
        // and other locations (static assets from disk, a second service) coexist.
        if (!site.proxy.configured) fail(where + ": app = \"proxy\" needs upstream = \"http://host:port\" on the site");
        if (!has("/", false, false)) {
            LocationConfig loc;
            loc.path = "/";
            loc.root = site.root;
            loc.index = site.index;
            loc.hidden_files = site.hidden_files;
            loc.symlinks_deny = site.symlinks_deny;
            loc.handler = "proxy";
            loc.kind = HandlerKind::proxy;
            loc.proxy = site.proxy;
            loc.methods = kFcgiMethods;
            loc.allow = allow_header(kFcgiMethods);
            loc.origin = "preset:proxy";
            site.locations.push_back(std::move(loc));
        }
        return;
    }
    if (!site.php.configured)
        fail(where + ": app = \"" + site.app + "\" needs php = { socket = \"...\" } on the site");
    if (site.app == "laravel") {
        // Front controller only: no other .php is ever executed, dotfiles stay hidden
        // (site default), Vite's hashed build output is cached for a year.
        if (site.try_files.empty()) site.try_files = parse_try_files({"$uri", "$uri/", "/index.php?$query_string"});
        if (!has("/index.php", true, false)) site.locations.push_back(fcgi_location("/index.php", true, false));
        if (!has("/build/", false, false)) {
            LocationConfig assets;
            assets.path = "/build/";
            assets.root = site.root;
            assets.index = site.index;
            assets.try_files = parse_try_files({"$uri", "=404"});
            assets.hidden_files = site.hidden_files;
            assets.symlinks_deny = site.symlinks_deny;
            assets.add_headers.emplace_back("Cache-Control", "public, max-age=31536000, immutable");
            assets.origin = "preset:laravel";
            site.locations.push_back(std::move(assets));
        }
    } else if (site.app == "php") {
        if (site.try_files.empty()) site.try_files = parse_try_files({"$uri", "$uri/", "=404"});
        if (!has(".php", false, true)) site.locations.push_back(fcgi_location(".php", false, true));
    } else if (site.app == "wordpress") {
        // Any .php runs (wp-login.php, wp-admin/*, wp-cron.php, plugin endpoints); pretty
        // permalinks fall back to index.php; nothing under uploads or wp-includes is ever
        // executed and their files are cacheable. Site-wide asset caching stays modest
        // because WordPress versions assets by query string, not by file name.
        if (site.try_files.empty()) site.try_files = parse_try_files({"$uri", "$uri/", "/index.php?$query_string"});
        if (!has(".php", false, true)) site.locations.push_back(fcgi_location(".php", false, true));
        auto shielded = [&](const char* path, const char* cache) {
            if (has(path, false, false)) return;
            LocationConfig loc;
            loc.path = path;
            loc.final = true;
            loc.root = site.root;
            loc.index = site.index;
            loc.try_files = parse_try_files({"$uri", "=404"});
            loc.hidden_files = site.hidden_files;
            loc.symlinks_deny = site.symlinks_deny;
            loc.deny_suffixes = {".php", ".phtml", ".phar", ".php5", ".php7", ".phps"};
            loc.add_headers.emplace_back("Cache-Control", cache);
            loc.origin = "preset:wordpress";
            site.locations.push_back(std::move(loc));
        };
        shielded("/wp-content/uploads/", "public, max-age=604800");
        shielded("/wp-includes/", "public, max-age=2592000");
    }
    // Locations the preset created inherit the site's try_files decided above.
    for (auto& loc : site.locations)
        if (loc.origin == "preset:" + site.app && loc.kind == HandlerKind::fastcgi && loc.try_files.empty())
            loc.try_files = site.try_files;
}

// The pool keys of `php = { ... }` for a site with `user` (docs/design-per-site-users.md).
// Without `php.socket` the pool is agensio's to generate: the socket, the state directory
// and the FastCGI sizing follow from the user, which is what makes a site's isolation one
// line of configuration.
void parse_pool(const toml::table* php, const fs::path& base_dir, const Config& cfg, SiteConfig& site,
                const std::string& project_root, const std::string& where) {
    PhpPool& pool = site.pool;
    static constexpr const char* kKeys[] = {"children", "version", "max_requests", "memory_limit",
                                            "max_execution_time", "pm", "open_basedir", "extra"};
    bool any = false;
    if (php)
        for (const char* k : kKeys) any = any || php->contains(k);
    if (site.user.empty()) {
        if (any) fail(where + ".php: pool keys (children, pm, ...) need 'user' on the site");
        return;
    }
    if (php) {
        const std::string w = where + ".php";
        auto count = [&](const char* key, unsigned& target, std::int64_t lo, std::int64_t hi) {
            if (auto v = (*php)[key].value<std::int64_t>()) {
                if (*v < lo || *v > hi) fail(w + "." + key + " out of range");
                target = static_cast<unsigned>(*v);
            }
        };
        count("children", pool.children, 1, 10000);
        count("max_requests", pool.max_requests, 0, 1000000);
        count("max_execution_time", pool.max_execution_time, 0, 86400);
        pool.version = (*php)["version"].value_or(std::string());
        pool.memory_limit = (*php)["memory_limit"].value_or(pool.memory_limit);
        pool.pm = to_lower((*php)["pm"].value_or(pool.pm));
        if (pool.pm != "static" && pool.pm != "dynamic" && pool.pm != "ondemand")
            fail(w + ".pm must be \"static\", \"dynamic\" or \"ondemand\"");
        for (const auto& text : string_list((*php)["open_basedir"], (w + ".open_basedir").c_str()))
            pool.open_basedir.push_back(resolve(base_dir, text).string());
        for (const auto& [k, v] : headers_of((*php)["extra"].as_table(), w))  // same shape: name = "value"
            pool.extra.emplace_back(k, v);
        for (const auto& [k, v] : pool.extra)
            if (k.find_first_of("[]=\n") != std::string::npos || v.find('\n') != std::string::npos)
                fail(w + ".extra: bad key or value '" + k + "'");
    }
    pool.name = "agensio-" + site.user;
    pool.state_dir = cfg.state_dir + "/" + site.user;
    if (pool.open_basedir.empty())
        pool.open_basedir = {project_root, pool.state_dir + "/tmp", pool.state_dir + "/sessions"};
    if (site.php.configured) return;  // an existing pool: nothing generated, the socket is theirs
    pool.generated = true;
    pool.socket = cfg.pools_run + "/" + pool.name + ".sock";
    std::string err;
    if (!parse_fcgi_address("unix:" + pool.socket, site.php.address, err)) fail(where + ": " + err);
    site.php.addresses = {site.php.address};
    site.php.configured = true;
    // Keep-alive sized so kept connections cannot pin every child (C3a), unless set by hand.
    if (!php || !php->contains("keep_conn")) site.php.options.keep_conn = true;
    if (!php || !php->contains("max_connections")) {
        const unsigned workers = cfg.workers ? cfg.workers : std::max(1u, std::thread::hardware_concurrency());
        site.php.options.max_connections = std::max(1u, pool.children / workers);
    }
}

void parse_site(const toml::table& t, const fs::path& base_dir, Config& cfg, const std::string& where) {
    SiteConfig site;
    for (auto& n : string_list(t["server_name"], (where + ".server_name").c_str()))
        site.server_names.push_back(to_lower(n));
    if (site.server_names.empty()) site.server_names.push_back("*");

    for (auto& l : string_list(t["listen"], (where + ".listen").c_str()))
        site.listen.push_back(normalise_listen(l));
    if (site.listen.empty()) fail(where + ": 'listen' is required");

    site.app = to_lower(t["app"].value_or(std::string()));
    if (!site.app.empty() && site.app != "laravel" && site.app != "php" && site.app != "static" &&
        site.app != "wordpress" && site.app != "proxy")
        fail(where + ": app must be \"laravel\", \"wordpress\", \"php\", \"proxy\" or \"static\"");
    if (auto r = t["redirect"].value<std::string>()) {
        if (*r != "https" && (!r->starts_with("https://") || r->size() <= 8 || r->find('/', 8) != std::string::npos))
            fail(where + ".redirect must be \"https\" or an \"https://host[:port]\" prefix");
        if (*r == "https" && t.contains("tls"))
            fail(where + ".redirect = \"https\" on a TLS site would loop; give the target host: \"https://www.example.com\"");
        site.redirect = *r;
    } else if (t.contains("redirect")) {
        fail(where + ".redirect must be a string");
    }
    auto root = t["root"].value<std::string>();
    if (!root && site.app != "proxy" && site.redirect.empty()) fail(where + ": 'root' is required");
    // A proxied application needs no document root; hand-written static locations bring their own.
    site.root = root ? resolve_root(base_dir, *root, where) : base_dir.string();
    const std::string root_given = site.root;  // the project directory for app = "laravel"
    if (site.app == "laravel") {
        // The project directory is given; the web root is its public/ (never the project itself).
        site.root = resolve_root(base_dir, site.root + "/public", where + " (app = \"laravel\")");
        site.index = {"index.php"};
    } else if (site.app == "php") {
        site.index = {"index.php", "index.html"};
    } else if (site.app == "wordpress") {
        site.index = {"index.php"};
    }

    if (t.contains("index")) site.index = index_list(t["index"], where);
    if (t.contains("try_files")) site.try_files = try_files_of(t["try_files"], where);
    if (auto pt = t["php"].as_table()) parse_fcgi_table(*pt, base_dir, site.php, where + ".php");
    else if (t.contains("php")) fail(where + ": 'php' must be a table");
    // Proxy defaults for the site's locations: keep-alive to the origin, and pool bounds
    // sized for a front-end (per worker: 256 in flight, 1024 waiting, 64 idle kept), not
    // for php-fpm children.
    site.proxy.options.keep_conn = true;
    site.proxy.options.max_connections = 256;
    site.proxy.options.queue_depth = 1024;
    site.proxy.options.max_idle = 64;
    if (auto pt = t["proxy"].as_table()) {
        parse_fcgi_table(*pt, base_dir, site.proxy, where + ".proxy");
        parse_proxy_policy(*pt, base_dir, site.proxy, where + ".proxy");
    } else if (t.contains("proxy")) {
        fail(where + ": 'proxy' must be a table");
    }
    parse_upstreams(t["upstream"], site.proxy, true, where + ".upstream");  // the preset's origin
    site.user = account_name(t["user"], where + ".user");
    site.group = account_name(t["group"], where + ".group");
    if (!site.group.empty() && site.user.empty()) fail(where + ": 'group' needs 'user'");
    if (cfg.strict_users && site.user.empty()) fail(where + ": 'user' is required (server.strict_users)");
    parse_pool(t["php"].as_table(), base_dir, cfg, site, root_given, where);

    if (auto mode = t["tls"].value<std::string>()) {
        if (*mode != "auto") fail(where + ".tls: \"auto\" or a table { cert, key }");
        if (!cfg.acme.enabled) fail(where + ".tls = \"auto\" needs [server] acme = { email = \"...\" }");
        for (const auto& n : site.server_names)
            if (n == "*" || n.find('*') != std::string::npos)
                fail(where + ".tls = \"auto\": a certificate needs real host names in server_name (wildcards "
                     "need DNS-01, which is not supported yet)");
        TlsConfig tc;
        tc.automatic = true;
        const fs::path dir = fs::path(cfg.acme.storage) / site.server_names.front();
        tc.cert = dir / "fullchain.pem";
        tc.key = dir / "key.pem";
        site.tls = std::move(tc);
    } else if (auto tls = t["tls"].as_table()) {
        auto cert = (*tls)["cert"].value<std::string>();
        auto key = (*tls)["key"].value<std::string>();
        if (!cert || !key) fail(where + ".tls: 'cert' and 'key' are required");
        TlsConfig tc;
        tc.cert = resolve(base_dir, *cert);
        tc.key = resolve(base_dir, *key);
        if (!fs::is_regular_file(tc.cert)) fail(where + ".tls: cert file not found: " + tc.cert.string());
        if (!fs::is_regular_file(tc.key)) fail(where + ".tls: key file not found: " + tc.key.string());
        site.tls = std::move(tc);
    }
    site.is_default = t["default"].value_or(false);
    site.hidden_files = t["hidden_files"].value_or(false);
    site.symlinks_deny = symlinks_deny_of(t["symlinks"], false, where);
    if (auto a = t["access_log"].value<std::string>())
        site.access_log = (*a == "off" || a->empty()) ? std::string() : resolve(base_dir, *a).string();
    else site.access_log = cfg.log.access;

    if (auto arr = t["location"].as_array()) {
        std::size_t idx = 0;
        for (auto& node : *arr) {
            auto* lt = node.as_table();
            if (!lt) fail(where + ": each [[site.location]] must be a table");
            parse_location(*lt, base_dir, site, where + " [[location]] #" + std::to_string(idx + 1));
            ++idx;
        }
    } else if (t.contains("location")) {
        fail(where + ": 'location' must be an array of tables ([[site.location]])");
    }
    apply_preset(site, where);
    finalize_site(site);
    cfg.sites.push_back(std::move(site));
}

void parse_sites_from(const toml::table& tbl, const fs::path& base_dir, Config& cfg, const std::string& file_label) {
    if (auto arr = tbl["site"].as_array()) {
        std::size_t idx = 0;
        for (auto& node : *arr) {
            auto* t = node.as_table();
            if (!t) fail(file_label + ": each [[site]] must be a table");
            parse_site(*t, base_dir, cfg, file_label + " [[site]] #" + std::to_string(idx + 1));
            ++idx;
        }
    } else if (tbl.contains("site")) {
        fail(file_label + ": 'site' must be an array of tables ([[site]])");
    }
}

// Very small glob: only '*' inside the file name part is supported.
std::vector<fs::path> expand_include(const fs::path& base_dir, const std::string& pattern) {
    fs::path p = resolve(base_dir, pattern);
    std::vector<fs::path> out;
    std::string name = p.filename().string();
    if (name.find('*') == std::string::npos) {
        out.push_back(p);
        return out;
    }
    fs::path dir = p.parent_path();
    std::error_code ec;
    if (!fs::is_directory(dir, ec)) return out;  // an empty include directory is not an error
    auto star = name.find('*');
    std::string prefix = name.substr(0, star), suffix = name.substr(star + 1);
    for (auto& entry : fs::directory_iterator(dir, ec)) {
        if (!entry.is_regular_file()) continue;
        std::string fn = entry.path().filename().string();
        if (fn.size() >= prefix.size() + suffix.size() && fn.compare(0, prefix.size(), prefix) == 0 &&
            fn.compare(fn.size() - suffix.size(), suffix.size(), suffix) == 0)
            out.push_back(entry.path());
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace

std::vector<TryStep> parse_try_files(const std::vector<std::string>& items) {
    std::vector<TryStep> out;
    for (std::size_t i = 0; i < items.size(); ++i) {
        const std::string& item = items[i];
        const bool last = i + 1 == items.size();
        TryStep step;
        if (item == "$uri") {
            step.kind = TryStep::Kind::uri;
        } else if (item == "$uri/") {
            step.kind = TryStep::Kind::uri_dir;
        } else if (!item.empty() && item[0] == '=') {
            if (!last) throw std::invalid_argument("'" + item + "' must be the last element");
            if (item != "=403" && item != "=404")
                throw std::invalid_argument("'" + item + "': only =403 and =404 are supported");
            step.kind = TryStep::Kind::status;
            step.status = item == "=403" ? 403 : 404;
        } else if (!item.empty() && item[0] == '/') {
            if (!last) throw std::invalid_argument("fallback '" + item + "' must be the last element");
            // A "?$query_string" suffix (the nginx idiom) is accepted and dropped: static
            // serving ignores the query, and FastCGI (phase C) forwards the original one.
            std::string target = item.substr(0, item.find('?'));
            if (target.find('$') != std::string::npos)
                throw std::invalid_argument("'" + item + "': variables are not supported in a fallback path");
            if (!normalize_target(target, step.target))
                throw std::invalid_argument("'" + item + "' is not a valid fallback path");
            step.kind = TryStep::Kind::fallback;
        } else {
            throw std::invalid_argument("'" + item + "': expected $uri, $uri/, =403, =404 or a /path");
        }
        out.push_back(std::move(step));
    }
    return out;
}

namespace {
void print_list(std::ostream& out, const char* key, const std::vector<std::string>& v) {
    out << key << " = [";
    for (std::size_t i = 0; i < v.size(); ++i) out << (i ? ", " : "") << '"' << v[i] << '"';
    out << "]\n";
}
void print_try_files(std::ostream& out, const std::vector<TryStep>& v) {
    if (v.empty()) return;
    out << "try_files = [";
    for (std::size_t i = 0; i < v.size(); ++i) {
        out << (i ? ", " : "") << '"';
        switch (v[i].kind) {
            case TryStep::Kind::uri: out << "$uri"; break;
            case TryStep::Kind::uri_dir: out << "$uri/"; break;
            case TryStep::Kind::status: out << "=" << v[i].status; break;
            case TryStep::Kind::fallback: out << v[i].target; break;
        }
        out << '"';
    }
    out << "]\n";
}
void print_fcgi(std::ostream& out, const char* key, const FcgiConfig& f) {
    const FcgiOptions& o = f.options;
    out << key << " = { socket = \"" << f.address.key << "\"";
    if (!f.remote_root.empty()) out << ", remote_root = \"" << f.remote_root << "\"";
    out << ", buffering = " << (o.buffering ? "true" : "false")
        << ", request_buffering = " << (o.request_buffering ? "true" : "false")
        << ", keep_conn = " << (o.keep_conn ? "true" : "false") << ", max_connections = " << o.max_connections
        << ", queue_depth = " << o.queue_depth << ", queue_wait = " << o.queue_wait.count() / 1000.0
        << ", priority_reserve = " << o.priority_reserve << ", connect_timeout = " << o.connect_timeout.count() / 1000.0
        << ", send_timeout = " << o.send_timeout.count() / 1000.0
        << ", read_timeout = " << o.read_timeout.count() / 1000.0
        << ", buffer_max = " << o.buffer_max << ", buffer_file_max = " << o.buffer_file_max
        << ", request_buffer_max = " << o.request_buffer_max << ", head_max = " << o.head_max
        << ", path_info = " << (o.path_info ? "true" : "false") << " }\n";
}
}  // namespace

void explain_config(const Config& cfg, std::ostream& out) {
    out << "# effective configuration of " << cfg.config_path.string() << " (presets expanded)\n";
    for (const auto& site : cfg.sites) {
        out << "\n[[site]]";
        if (!site.app.empty()) out << "  # app = \"" << site.app << "\"";
        out << "\n";
        print_list(out, "server_name", site.server_names);
        print_list(out, "listen", site.listen);
        out << "root = \"" << site.root << "\"\n";
        print_list(out, "index", site.index);
        print_try_files(out, site.try_files);
        if (site.tls && site.tls->automatic)
            out << "tls = \"auto\"  # " << site.tls->cert.string() << ", " << site.tls->key.string() << "\n";
        else if (site.tls)
            out << "tls = { cert = \"" << site.tls->cert.string() << "\", key = \"" << site.tls->key.string()
                << "\" }\n";
        if (!site.redirect.empty()) out << "redirect = \"" << site.redirect << "\"\n";
        if (!site.user.empty()) out << "user = \"" << site.user << "\"\n";
        if (!site.group.empty()) out << "group = \"" << site.group << "\"\n";
        if (site.php.configured) print_fcgi(out, "php", site.php);
        if (site.pool.generated) {
            out << "# php-fpm pool " << site.pool.name << " (generated by `agensio pools`):\n";
            std::istringstream ini(render_pool(cfg, site, cfg.group.empty() ? "<agensio group>" : cfg.group));
            for (std::string line; std::getline(ini, line);) out << "#   " << line << "\n";
        }
        out << "hidden_files = " << (site.hidden_files ? "true" : "false") << "\nsymlinks = \""
            << (site.symlinks_deny ? "deny" : "allow") << "\"\n";
        out << "access_log = \"" << (site.access_log.empty() ? "off" : site.access_log) << "\"\n";
        for (const auto& loc : site.locations) {
            out << "\n[[site.location]]";
            if (!loc.origin.empty()) out << "  # from " << loc.origin;
            else if (loc.path == "/" && !loc.exact && !loc.suffix) out << "  # implicit";
            out << "\n";
            const char* match = loc.exact ? "exact" : loc.suffix ? "suffix" : "prefix";
            out << "path = \"" << loc.path << "\"\nmatch = \"" << match << "\"\n";
            if (loc.final) out << "final = true\n";
            if (!loc.deny_suffixes.empty()) print_list(out, "deny_suffixes", loc.deny_suffixes);
            if (!loc.alias.empty()) out << "alias = \"" << loc.alias << "\"\n";
            else out << "root = \"" << loc.root << "\"\n";
            print_list(out, "index", loc.index);
            print_try_files(out, loc.try_files);
            out << "handler = \"" << loc.handler << "\"\n";
            if (loc.kind == HandlerKind::fastcgi) print_fcgi(out, "fastcgi", loc.fastcgi);
            if (loc.kind == HandlerKind::cgi) {
                print_fcgi(out, "cgi", loc.cgi);
                if (!loc.cgi.interpreter.empty()) out << "cgi.interpreter = \"" << loc.cgi.interpreter << "\"\n";
            }
            if (loc.kind == HandlerKind::proxy) {
                out << "upstream = [";
                for (std::size_t i = 0; i < loc.proxy.addresses.size(); ++i)
                    out << (i ? ", " : "") << '"' << loc.proxy.addresses[i].key << loc.proxy.rewrite << '"';
                out << "]\n";
                print_fcgi(out, "proxy", loc.proxy);
                out << "proxy.host = \"" << loc.proxy.host << "\"\nproxy.forwarded = \"" << loc.proxy.forwarded
                    << "\"\nproxy.redirects = \"" << (loc.proxy.rewrite_redirects ? "rewrite" : "pass")
                    << "\"\nproxy.upgrade = " << (loc.proxy.upgrade ? "true" : "false")
                    << "\nproxy.tunnel_timeout = " << loc.proxy.tunnel_timeout_s << "\n";
                for (const auto& a : loc.proxy.addresses)
                    if (a.tls) {
                        out << "proxy.tls = { verify = " << (loc.proxy.tls.verify ? "true" : "false") << ", server_name = \""
                            << loc.proxy.tls.server_name << "\", ca = \"" << loc.proxy.tls.ca_file << "\" }\n";
                        break;
                    }
                if (!loc.proxy.set_headers.empty()) {
                    out << "proxy.headers = {";
                    for (std::size_t i = 0; i < loc.proxy.set_headers.size(); ++i)
                        out << (i ? ", " : " ") << '"' << loc.proxy.set_headers[i].first << "\" = \""
                            << loc.proxy.set_headers[i].second << '"';
                    out << " }\n";
                }
                if (!loc.proxy.hide.empty()) print_list(out, "proxy.hide", loc.proxy.hide);
            }
            if (loc.priority) out << "priority = true\n";
            out << "methods = \"" << loc.allow << "\"\n";
            out << "hidden_files = " << (loc.hidden_files ? "true" : "false") << "\nsymlinks = \""
                << (loc.symlinks_deny ? "deny" : "allow") << "\"\n";
            if (!loc.add_headers.empty()) {
                out << "add_headers = {";
                for (std::size_t i = 0; i < loc.add_headers.size(); ++i)
                    out << (i ? ", " : " ") << '"' << loc.add_headers[i].first << "\" = \""
                        << loc.add_headers[i].second << '"';
                out << " }\n";
            }
        }
    }
}

void finalize_site(SiteConfig& site) {
    bool has_root_prefix = false;
    for (const auto& loc : site.locations)
        if (!loc.exact && loc.path == "/") has_root_prefix = true;
    if (!has_root_prefix) {
        LocationConfig loc;
        loc.path = "/";
        loc.root = site.root;
        loc.index = site.index;
        loc.try_files = site.try_files;
        loc.hidden_files = site.hidden_files;
        loc.symlinks_deny = site.symlinks_deny;
        site.locations.push_back(std::move(loc));
    }
    // Exact matches first, then suffixes, then prefixes; within a kind the longest first.
    auto rank = [](const LocationConfig& l) { return l.exact ? 0 : l.suffix ? 1 : 2; };
    std::stable_sort(site.locations.begin(), site.locations.end(),
                     [&](const LocationConfig& a, const LocationConfig& b) {
                         if (rank(a) != rank(b)) return rank(a) < rank(b);
                         return a.path.size() > b.path.size();
                     });
}

Config load_config(const fs::path& path) {
    Config cfg;
    std::error_code ec;
    cfg.config_path = fs::absolute(path, ec);
    fs::path base_dir = cfg.config_path.parent_path();

    toml::table tbl;
    try {
        tbl = toml::parse_file(path.string());
    } catch (const toml::parse_error& e) {
        std::string msg = path.string() + ":" + std::to_string(e.source().begin.line) + ":" +
                          std::to_string(e.source().begin.column) + ": " + std::string(e.description());
        fail(msg);
    }
    const toml::table& root = tbl;

    auto server = root["server"];
    if (auto w = server["workers"].value<std::int64_t>()) {
        if (*w < 0 || *w > 1024) fail("server.workers out of range");
        cfg.workers = static_cast<unsigned>(*w);
    }
    if (auto t = server["idle_timeout"].value<std::int64_t>()) {
        if (*t < 1) fail("server.idle_timeout must be at least 1 second");
        cfg.idle_timeout_s = static_cast<std::uint32_t>(*t);
    }
    if (auto m = server["max_requests_per_connection"].value<std::int64_t>()) {
        if (*m < 0) fail("server.max_requests_per_connection must not be negative");
        cfg.max_requests_per_connection = static_cast<std::uint32_t>(*m);
    }
    cfg.max_header_size = size_node(server["max_header_size"], cfg.max_header_size, "server.max_header_size");
    if (cfg.max_header_size < 1024) fail("server.max_header_size must be at least 1024");
    cfg.max_body_size = size_node(server["max_body_size"], cfg.max_body_size, "server.max_body_size");
    if (auto t = server["body_timeout"].value<std::int64_t>()) {
        if (*t < 1) fail("server.body_timeout must be at least 1 second");
        cfg.body_timeout_s = static_cast<std::uint32_t>(*t);
    }
    cfg.reuse_port = to_lower(server["reuse_port"].value_or(std::string("auto")));
    if (cfg.reuse_port != "auto" && cfg.reuse_port != "on" && cfg.reuse_port != "off")
        fail("server.reuse_port must be \"auto\", \"on\" or \"off\"");
    cfg.tcp_nodelay = server["tcp_nodelay"].value_or(true);
    cfg.sendfile = server["sendfile"].value_or(true);
    cfg.sendfile_max_chunk =
        size_node(server["sendfile_max_chunk"], cfg.sendfile_max_chunk, "server.sendfile_max_chunk");
    if (cfg.sendfile_max_chunk < 65536) fail("server.sendfile_max_chunk must be at least 64KB");
    cfg.server_header = server["server_header"].value_or(std::string("agensio"));
    for (const auto& text : string_list(server["trusted_proxies"], "server.trusted_proxies")) {
        Cidr c;
        std::string err;
        if (!parse_cidr(text, c, err)) fail("server.trusted_proxies: " + err);
        cfg.trusted_proxies.push_back(c);
    }
    cfg.user = account_name(server["user"], "server.user");
    cfg.group = account_name(server["group"], "server.group");
    if (auto d = server["pools"].value<std::string>()) cfg.pools_dir = resolve(base_dir, *d).string();
    cfg.pools_run = server["pools_run"].value_or(default_pools_run());
    if (cfg.pools_run.empty() || cfg.pools_run[0] != '/') fail("server.pools_run must be an absolute path");
    cfg.state_dir = server["state_dir"].value_or(cfg.state_dir);
    if (cfg.state_dir.empty() || cfg.state_dir[0] != '/') fail("server.state_dir must be an absolute path");
    cfg.strict_users = server["strict_users"].value_or(false);
    if (auto acme = server["acme"].as_table()) {
        cfg.acme.enabled = true;
        cfg.acme.email = (*acme)["email"].value_or(std::string());
        if (cfg.acme.email.empty() || cfg.acme.email.find('@') == std::string::npos)
            fail("server.acme.email is required (the CA's contact address for the account)");
        cfg.acme.directory = (*acme)["directory"].value_or(cfg.acme.directory);
        if (!cfg.acme.directory.starts_with("https://")) fail("server.acme.directory must be an https:// URL");
        if (auto ca = (*acme)["ca"].value<std::string>()) {
            cfg.acme.ca_file = resolve(base_dir, *ca).string();
            if (!fs::is_regular_file(cfg.acme.ca_file)) fail("server.acme.ca: file not found: " + cfg.acme.ca_file);
        }
        if (auto st = (*acme)["storage"].value<std::string>()) cfg.acme.storage = resolve(base_dir, *st).string();
        else cfg.acme.storage = cfg.state_dir + "/acme";
    } else if (server.as_table() && server.as_table()->contains("acme")) {
        fail("server.acme must be a table { email, directory, ca, storage }");
    }
    if (auto pf = server["pid_file"].value<std::string>()) cfg.pid_file = pf->empty() ? std::string() : resolve(base_dir, *pf).string();
    else {
#ifdef __APPLE__
        cfg.pid_file = "/usr/local/var/run/agensio.pid";
#else
        cfg.pid_file = "/run/agensio.pid";
#endif
    }

    auto cache = root["cache"];
    cfg.cache_max_file_size = size_node(cache["max_file_size"], cfg.cache_max_file_size, "cache.max_file_size");
    cfg.cache_max_size = size_node(cache["max_size"], cfg.cache_max_size, "cache.max_size");
    cfg.stream_chunk_size = size_node(cache["stream_chunk_size"], cfg.stream_chunk_size, "cache.stream_chunk_size");
    if (cfg.stream_chunk_size < 4096) fail("cache.stream_chunk_size must be at least 4096");
    cfg.cache_sendfile_min_size =
        size_node(cache["sendfile_min_size"], cfg.cache_sendfile_min_size, "cache.sendfile_min_size");
    if (auto f = cache["evict_fraction"].value<double>()) {
        if (*f <= 0.0 || *f > 1.0) fail("cache.evict_fraction must be in (0, 1]");
        cfg.cache_evict_fraction = *f;
    }
    if (auto r = cache["revalidate_interval"].value<std::int64_t>()) {
        if (*r < 0) fail("cache.revalidate_interval must not be negative");
        cfg.cache_revalidate_s = static_cast<std::uint32_t>(*r);
    }
    if (auto m = cache["max_open_files"].value<std::int64_t>()) {
        if (*m < 0) fail("cache.max_open_files must not be negative");
        cfg.cache_max_open_files = static_cast<std::size_t>(*m);
    }

    auto log = root["log"];
    if (auto a = log["access"].value<std::string>())
        cfg.log.access = (*a == "off" || a->empty()) ? std::string() : resolve(base_dir, *a).string();
    else cfg.log.access = resolve(base_dir, "logs/access.log").string();  // on by default (see CLAUDE.md)
    std::string format = to_lower(log["format"].value_or(std::string("combined")));
    if (format != "combined" && format != "json") fail("log.format must be \"combined\" or \"json\"");
    cfg.log.json = format == "json";
    if (auto e = log["error"].value<std::string>())
        cfg.log.error = (*e == "stderr" || e->empty()) ? std::string("stderr") : resolve(base_dir, *e).string();
    cfg.log.level = to_lower(log["level"].value_or(std::string("warn")));
    if (cfg.log.level != "error" && cfg.log.level != "warn" && cfg.log.level != "info")
        fail("log.level must be \"error\", \"warn\" or \"info\"");

    parse_sites_from(root, base_dir, cfg, path.filename().string());

    for (auto& pattern : string_list(root["include"], "include")) {
        cfg.includes.push_back(pattern);
        for (auto& file : expand_include(base_dir, pattern)) {
            toml::table sub;
            try {
                sub = toml::parse_file(file.string());
            } catch (const toml::parse_error& e) {
                fail(file.string() + ":" + std::to_string(e.source().begin.line) + ": " + std::string(e.description()));
            }
            parse_sites_from(sub, file.parent_path(), cfg, file.filename().string());
        }
    }

    if (cfg.sites.empty()) fail(path.string() + ": no [[site]] defined");

    // One user, one pool: sites of the same user share it and must size it alike; sites of
    // different users never share a socket, whatever they say.
    for (const auto& a : cfg.sites) {
        if (a.user.empty()) continue;
        for (const auto& b : cfg.sites) {
            if (&a == &b || b.user.empty()) continue;
            const std::string pair = a.server_names.front() + " and " + b.server_names.front();
            if (a.user != b.user) {
                if (a.php.configured && b.php.configured && a.php.address.key == b.php.address.key)
                    fail(pair + " have different users but the same php socket " + a.php.address.key);
                continue;
            }
            if (!a.pool.generated || !b.pool.generated) continue;
            const PhpPool& x = a.pool;
            const PhpPool& y = b.pool;
            const char* differs = x.children != y.children         ? "children"
                                  : x.pm != y.pm                    ? "pm"
                                  : x.max_requests != y.max_requests ? "max_requests"
                                  : x.memory_limit != y.memory_limit ? "memory_limit"
                                  : x.max_execution_time != y.max_execution_time ? "max_execution_time"
                                  : x.version != y.version                       ? "version"
                                  : x.extra != y.extra                           ? "extra"
                                                                                 : nullptr;
            if (differs) fail(pair + " share user " + a.user + " but php." + differs + " differs");
        }
    }

    // The FastCGI pool is per upstream address (and worker), so every location on the same
    // socket must agree on the pool bounds; the first definition wins, a conflict is an error.
    struct PoolBounds {
        const FcgiOptions* opts;
        std::string where;
    };
    std::map<std::string, PoolBounds> pools;
    for (const auto& site : cfg.sites)
        for (const auto& loc : site.locations) {
            if (loc.kind == HandlerKind::static_) continue;
            const UpstreamConfig& up = loc.kind == HandlerKind::fastcgi ? loc.fastcgi
                                       : loc.kind == HandlerKind::cgi   ? loc.cgi
                                                                        : loc.proxy;
            const FcgiOptions& o = up.options;
            const std::string where = site.server_names.front() + " location '" + loc.path + "'";
            std::vector<std::string> keys;
            if (loc.kind != HandlerKind::proxy) keys.push_back(up.address.key);
            else for (const auto& a : up.addresses) keys.push_back(a.key);
            for (const auto& key : keys) {
                auto it = pools.find(key);
                if (it == pools.end()) {
                    pools.emplace(key, PoolBounds{&o, where});
                    continue;
                }
                const FcgiOptions& f = *it->second.opts;
                if (o.max_connections != f.max_connections || o.queue_depth != f.queue_depth ||
                    o.queue_wait != f.queue_wait || o.priority_reserve != f.priority_reserve ||
                    o.max_idle != f.max_idle || o.keep_conn != f.keep_conn)
                    fail(where + ": pool limits (max_connections, queue_depth, queue_wait, priority_reserve, "
                                 "max_idle, keep_conn) for upstream " +
                         key + " differ from " + it->second.where +
                         "; the pool is per upstream, set them once (site-level php = {...} or proxy = {...})");
            }
        }

    // Sites sharing a listen address must agree on TLS on/off.
    for (auto& a : cfg.sites)
        for (auto& b : cfg.sites)
            for (auto& la : a.listen)
                for (auto& lb : b.listen)
                    if (la == lb && a.tls.has_value() != b.tls.has_value())
                        fail("listen address " + la + " is used by both a TLS and a plain site");

    if (auto ct = root["control"].as_table()) {
        cfg.control.enabled = true;
        if (auto s = (*ct)["socket"].value<std::string>()) cfg.control.socket = resolve(base_dir, *s).string();
        else {
#ifdef __APPLE__
            cfg.control.socket = "/usr/local/var/run/agensio/control.sock";
#else
            cfg.control.socket = "/run/agensio/control.sock";
#endif
        }
        cfg.control.admins = account_name((*ct)["admins"], "control.admins");
        cfg.control.operators = account_name((*ct)["operators"], "control.operators");
        cfg.control.viewers = account_name((*ct)["viewers"], "control.viewers");
        if (auto sr = (*ct)["sites_root"].value<std::string>()) cfg.control.sites_root = resolve(base_dir, *sr).string();
        if (auto a = (*ct)["audit"].value<std::string>()) cfg.control.audit = resolve(base_dir, *a).string();
        else if (cfg.log.error != "stderr") cfg.control.audit = (fs::path(cfg.log.error).parent_path() / "audit.log").string();
        else cfg.control.audit = resolve(base_dir, "logs/audit.log").string();
    } else if (root.contains("control")) {
        fail("control must be a table: [control] with socket, admins, operators, viewers, audit");
    }
    return cfg;
}

SiteConfig control_site() {
    SiteConfig site;
    site.server_names = {"*"};
    site.is_default = true;
    site.root = "/";
    LocationConfig loc;
    loc.path = "/";
    loc.root = "/";
    loc.handler = "control";
    loc.kind = HandlerKind::control;
    loc.methods = kStaticMethods | method_bit(Method::post);
    loc.allow = "GET, HEAD, POST, OPTIONS";
    site.locations.push_back(std::move(loc));
    finalize_site(site);
    return site;
}

}  // namespace agensio
