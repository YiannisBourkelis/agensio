// Configuration model and TOML loader.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/request.hpp"
#include "net/cidr.hpp"
#include "upstream/fcgi_options.hpp"

namespace agensio {

enum class HandlerKind : std::uint8_t { static_, fastcgi };

struct TlsConfig {
    std::filesystem::path cert;
    std::filesystem::path key;
};

// One element of a try_files list.
struct TryStep {
    enum class Kind {
        uri,       // "$uri": the request path as a regular file
        uri_dir,   // "$uri/": the request path as a directory (index, or redirect to the slash form)
        fallback,  // "/path": internal redirect, routed again through the locations
        status,    // "=404": answer with this status
    };
    Kind kind = Kind::uri;
    std::string target;  // fallback: normalised path (a "?query" suffix is dropped)
    int status = 0;      // status: 403 or 404
};

// A [[site.location]] block, fully resolved: every field has the site's value unless the
// block set its own. The site always ends with an implicit "/" prefix location.
struct LocationConfig {
    std::string path;  // prefix ("/", "/static/"), the whole path (exact) or an ending (suffix, ".php")
    bool exact = false;
    bool suffix = false;
    std::string root;   // absolute, canonical, no trailing slash; the file is root + path
    std::string alias;  // nginx alias: the file is alias + (path minus the location prefix); empty = use root
    std::vector<std::string> index;
    std::vector<TryStep> try_files;  // empty: plain lookup (file, directory index, 404)
    bool hidden_files = false;
    bool symlinks_deny = false;
    std::string handler = "static";  // "static" or "fastcgi" ("proxy" arrives in phase D)
    HandlerKind kind = HandlerKind::static_;
    FcgiConfig fastcgi;                        // handler = "fastcgi": upstream and options
    bool priority = false;                     // may use the pool slots reserved by priority_reserve
    MethodSet methods = kStaticMethods;      // what the handler serves here (`methods = [...]` narrows it)
    std::string allow = "GET, HEAD, OPTIONS";  // Allow header for 405 and OPTIONS
};

// Every method an application handler may see; TRACE and CONNECT never reach a handler.
constexpr MethodSet kFcgiMethods = kStaticMethods | method_bit(Method::post) | method_bit(Method::put) |
                                   method_bit(Method::del) | method_bit(Method::patch);

struct SiteConfig {
    std::vector<std::string> server_names;  // lower-case host names, "*" matches anything
    std::vector<std::string> listen;        // "host:port" strings, normalised
    std::string root;                       // absolute document root, no trailing slash
    std::vector<std::string> index{"index.html"};
    std::vector<TryStep> try_files;  // default for locations that do not set their own
    FcgiConfig php;                  // `php = { socket = ... }`: default upstream for fastcgi locations
    std::optional<TlsConfig> tls;
    bool is_default = false;
    bool hidden_files = false;   // serve paths with a segment starting with '.' (.env, .git, .htaccess)
    bool symlinks_deny = false;  // refuse files whose canonical path leaves the root (realpath per cache miss)
    // Sorted for Router::location: exact before prefix, longer before shorter, "/" last.
    std::vector<LocationConfig> locations;
    std::string access_log;    // absolute path, or "" for no access log (site `access_log`, default [log] access)
    int access_log_sink = -1;  // set by the Server: index into its log registry
};

// [log]
struct LogConfig {
    std::string access;     // default access log path for sites, "" = off; the loader defaults it to
                            // "logs/access.log" next to the configuration file (measured: 0.1-0.2 us/request)
    bool json = false;      // format = "json" instead of "combined"
    std::string error = "stderr";  // "stderr" or a path
    std::string level = "warn";    // error | warn | info
};

struct Config {
    // [server]
    unsigned workers = 0;  // 0 = hardware threads
    std::uint32_t idle_timeout_s = 15;
    std::uint32_t max_requests_per_connection = 1000;  // then Connection: close (0 = unlimited)
    std::size_t max_header_size = 16 * 1024;
    std::size_t max_body_size = 1024 * 1024;  // request bodies above this get 413 (nginx client_max_body_size)
    std::uint32_t body_timeout_s = 60;        // between two reads of a request body (nginx client_body_timeout)
    std::string reuse_port = "auto";  // auto | on | off
    bool tcp_nodelay = true;
    bool sendfile = true;  // zero-copy streaming of uncached files on plain sockets
    std::size_t sendfile_max_chunk =
        1024 * 1024;  // bytes per sendfile() call; one huge call holds the socket lock and the loop
    std::string server_header = "agensio";
    // Proxies in front of us whose X-Forwarded-For / X-Forwarded-Proto are believed: the
    // rightmost untrusted address becomes the client (REMOTE_ADDR, access log) and the
    // scheme sets HTTPS / REQUEST_SCHEME for FastCGI. Empty (default): headers are ignored.
    std::vector<Cidr> trusted_proxies;

    LogConfig log;

    // [cache]
    std::size_t cache_max_file_size = 4u * 1024 * 1024;
    std::size_t cache_max_size = 256u * 1024 * 1024;
    double cache_evict_fraction = 0.2;
    std::uint32_t cache_revalidate_s = 1;
    std::size_t stream_chunk_size = 64 * 1024;
    std::size_t cache_sendfile_min_size =
        48 * 1024;  // cached files at least this large are served by sendfile on plain sockets (0 = never)
    std::size_t cache_max_open_files =
        1024;  // streamed files (above max_file_size) whose open descriptor is kept in the cache (0 = none)

    std::vector<SiteConfig> sites;

    std::filesystem::path config_path;  // the file this came from
};

// Parses "4MB", "256k", "1G", "65536". Throws std::invalid_argument.
std::size_t parse_size(std::string_view text);

// Parses a try_files list: "$uri", "$uri/", "=403"/"=404", or "/path" (last element only
// for the latter two). Throws std::invalid_argument.
std::vector<TryStep> parse_try_files(const std::vector<std::string>& items);

// Appends the implicit "/" location from the site's own settings if none is configured
// and sorts the locations for Router::location. The loader calls it; exposed for tests.
void finalize_site(SiteConfig& site);

// Loads and validates a configuration file. Throws std::runtime_error with a
// human readable message on any problem.
Config load_config(const std::filesystem::path& path);

}  // namespace agensio
