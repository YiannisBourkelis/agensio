#include "config.hpp"

#include "handlers/fastcgi.hpp"
#include "path.hpp"

#include <algorithm>
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

// `php = { ... }` (site) or `fastcgi = { ... }` (location): socket plus options, on top of `base`.
void parse_fcgi_table(const toml::table& t, const fs::path& base_dir, FcgiConfig& out, const std::string& where) {
    if (auto sock = t["socket"].value<std::string>()) {
        std::string text = *sock;
        if (!text.starts_with("unix:") && text.find(':') == std::string::npos)
            text = resolve(base_dir, text).string();  // a bare path: relative to the config file
        std::string err;
        if (!parse_fcgi_address(text, out.address, err)) fail(where + ".socket: " + err);
        out.configured = true;
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
    if (out.options.head_max < 1024) fail(where + ".head_max must be at least 1024");
    out.options.request_buffering = t["request_buffering"].value_or(out.options.request_buffering);
    out.options.request_buffer_max =
        size_node(t["request_buffer_max"], out.options.request_buffer_max, (where + ".request_buffer_max").c_str());
    auto count = [&](const char* key, std::size_t& target, std::int64_t lo, std::int64_t hi) {
        if (auto v = t[key].value<std::int64_t>()) {
            if (*v < lo || *v > hi) fail(where + "." + key + " out of range");
            target = static_cast<std::size_t>(*v);
        }
    };
    count("max_idle", out.options.max_idle, 0, 1024);
    count("max_connections", out.options.max_connections, 1, 65536);
    count("queue_depth", out.options.queue_depth, 0, 1 << 20);
    if (auto v = t["priority_reserve"].value<double>()) {
        if (*v < 0.0 || *v > 1.0) fail(where + ".priority_reserve must be in [0, 1]");
        out.options.priority_reserve = *v;
    }
    const auto wait_s = std::chrono::duration_cast<std::chrono::seconds>(out.options.queue_wait).count();
    out.retry_after = std::to_string(wait_s < 1 ? 1 : wait_s);
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
    loc.handler = to_lower(t["handler"].value_or(std::string("static")));
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
    } else {
        fail(where + ": handler \"" + loc.handler + "\" is not available yet (\"static\" or \"fastcgi\")");
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

void parse_site(const toml::table& t, const fs::path& base_dir, Config& cfg, const std::string& where) {
    SiteConfig site;
    for (auto& n : string_list(t["server_name"], (where + ".server_name").c_str()))
        site.server_names.push_back(to_lower(n));
    if (site.server_names.empty()) site.server_names.push_back("*");

    for (auto& l : string_list(t["listen"], (where + ".listen").c_str()))
        site.listen.push_back(normalise_listen(l));
    if (site.listen.empty()) fail(where + ": 'listen' is required");

    auto root = t["root"].value<std::string>();
    if (!root) fail(where + ": 'root' is required");
    site.root = resolve_root(base_dir, *root, where);

    if (t.contains("index")) site.index = index_list(t["index"], where);
    if (t.contains("try_files")) site.try_files = try_files_of(t["try_files"], where);
    if (auto pt = t["php"].as_table()) parse_fcgi_table(*pt, base_dir, site.php, where + ".php");
    else if (t.contains("php")) fail(where + ": 'php' must be a table");

    if (auto tls = t["tls"].as_table()) {
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

    // Sites sharing a listen address must agree on TLS on/off.
    for (auto& a : cfg.sites)
        for (auto& b : cfg.sites)
            for (auto& la : a.listen)
                for (auto& lb : b.listen)
                    if (la == lb && a.tls.has_value() != b.tls.has_value())
                        fail("listen address " + la + " is used by both a TLS and a plain site");

    return cfg;
}

}  // namespace agensio
