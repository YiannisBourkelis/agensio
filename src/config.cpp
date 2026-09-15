#include "config.hpp"

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
    while (i < text.size() && std::isspace(static_cast<unsigned char>(text[i]))) ++i;
    std::size_t start = i;
    while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) ++i;
    if (start == i) throw std::invalid_argument("size must start with a number: '" + std::string(text) + "'");
    std::uint64_t value = 0;
    auto [ptr, ec] = std::from_chars(text.data() + start, text.data() + i, value);
    if (ec != std::errc()) throw std::invalid_argument("bad size: '" + std::string(text) + "'");
    std::string unit;
    for (; i < text.size(); ++i) {
        char c = text[i];
        if (!std::isspace(static_cast<unsigned char>(c))) unit += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
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
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

[[noreturn]] void fail(const std::string& msg) { throw std::runtime_error(msg); }

std::size_t size_node(const toml::node_view<const toml::node>& n, std::size_t fallback, const char* what) {
    if (!n) return fallback;
    if (auto v = n.value<std::int64_t>()) {
        if (*v < 0) fail(std::string(what) + " must not be negative");
        return static_cast<std::size_t>(*v);
    }
    if (auto s = n.value<std::string>()) {
        try {
            return parse_size(*s);
        } catch (const std::exception& e) {
            fail(std::string(what) + ": " + e.what());
        }
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

void parse_site(const toml::table& t, const fs::path& base_dir, Config& cfg, const std::string& where) {
    SiteConfig site;
    for (auto& n : string_list(t["server_name"], (where + ".server_name").c_str())) site.server_names.push_back(to_lower(n));
    if (site.server_names.empty()) site.server_names.push_back("*");

    for (auto& l : string_list(t["listen"], (where + ".listen").c_str())) site.listen.push_back(normalise_listen(l));
    if (site.listen.empty()) fail(where + ": 'listen' is required");

    auto root = t["root"].value<std::string>();
    if (!root) fail(where + ": 'root' is required");
    fs::path root_path = resolve(base_dir, *root);
    std::error_code ec;
    if (!fs::is_directory(root_path, ec)) fail(where + ": root '" + root_path.string() + "' is not a directory");
    site.root = fs::canonical(root_path, ec).string();
    if (ec) fail(where + ": cannot resolve root '" + root_path.string() + "'");
    while (site.root.size() > 1 && site.root.back() == '/') site.root.pop_back();

    if (t.contains("index")) {
        site.index = string_list(t["index"], (where + ".index").c_str());
        for (auto& i : site.index)
            if (i.empty() || i.find('/') != std::string::npos) fail(where + ": index names must be plain file names");
    }

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
    cfg.max_header_size = size_node(server["max_header_size"], cfg.max_header_size, "server.max_header_size");
    if (cfg.max_header_size < 1024) fail("server.max_header_size must be at least 1024");
    cfg.reuse_port = to_lower(server["reuse_port"].value_or(std::string("auto")));
    if (cfg.reuse_port != "auto" && cfg.reuse_port != "on" && cfg.reuse_port != "off")
        fail("server.reuse_port must be \"auto\", \"on\" or \"off\"");
    cfg.tcp_nodelay = server["tcp_nodelay"].value_or(true);
    cfg.sendfile = server["sendfile"].value_or(true);
    cfg.server_header = server["server_header"].value_or(std::string("agensio"));

    auto cache = root["cache"];
    cfg.cache_max_file_size = size_node(cache["max_file_size"], cfg.cache_max_file_size, "cache.max_file_size");
    cfg.cache_max_size = size_node(cache["max_size"], cfg.cache_max_size, "cache.max_size");
    cfg.stream_chunk_size = size_node(cache["stream_chunk_size"], cfg.stream_chunk_size, "cache.stream_chunk_size");
    if (cfg.stream_chunk_size < 4096) fail("cache.stream_chunk_size must be at least 4096");
    if (auto f = cache["evict_fraction"].value<double>()) {
        if (*f <= 0.0 || *f > 1.0) fail("cache.evict_fraction must be in (0, 1]");
        cfg.cache_evict_fraction = *f;
    }
    if (auto r = cache["revalidate_interval"].value<std::int64_t>()) {
        if (*r < 0) fail("cache.revalidate_interval must not be negative");
        cfg.cache_revalidate_s = static_cast<std::uint32_t>(*r);
    }

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
