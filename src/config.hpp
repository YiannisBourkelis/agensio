// Configuration model and TOML loader.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <ostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/request.hpp"
#include "net/cidr.hpp"
#include "services/json.hpp"
#include "upstream/options.hpp"

namespace agensio {

enum class HandlerKind : std::uint8_t { static_, fastcgi, proxy, cgi, control, httparena };

struct HttparenaDataset;  // handlers/httparena.hpp: the benchmark handler's dataset, loaded at config time

struct TlsConfig {
    std::filesystem::path cert;
    std::filesystem::path key;
    bool automatic = false;  // `tls = "auto"`: issued and renewed by the built-in ACME client (H3)
};

// [server] acme = { email, directory, ca, storage }: the CA the automatic certificates come from.
struct AcmeConfig {
    bool enabled = false;
    std::string email;  // account contact; the CA sends expiry warnings there
    std::string directory = "https://acme-v02.api.letsencrypt.org/directory";
    std::string ca_file;  // trust anchor for the directory's own TLS ("" = system store; tests: Pebble's)
    std::string storage;  // account key and per-site key.pem/fullchain.pem; default <state_dir>/acme
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

// A file a preset never serves, in the form the static handler matches its backup
// spellings against (handlers/static.hpp, backup_of_protected): "/wp-config.php" is
// dir_len 1, dir_stem "/wp-config", ext ".php"; "/wp-content/db.php" is 12, "/wp-content/db",
// ".php". Lower case, built once at load (config.cpp, protected_name).
struct ProtectedName {
    std::string dir_stem;   // the directory with its slash, then the name without its extension
    std::string ext;        // ".php", ".txt", "" for a name without one
    std::size_t dir_len = 0;
};

// A [[site.location]] block, fully resolved: every field has the site's value unless the
// block set its own. The site always ends with an implicit "/" prefix location.
struct LocationConfig {
    std::string path;  // prefix ("/", "/static/"), the whole path (exact) or an ending (suffix, ".php")
    bool exact = false;
    bool suffix = false;
    bool final = false;  // prefix only (nginx ^~): when it is the longest prefix match, suffix locations are skipped
    std::vector<std::string> deny_suffixes;  // request paths ending with one of these get 404 (".php" under uploads)
    std::vector<ProtectedName> protects;     // names the site never serves: any backup spelling of them gets 404 here (preset `never`)
    std::string root;   // absolute, canonical, no trailing slash; the file is root + path
    std::string alias;  // nginx alias: the file is alias + (path minus the location prefix); empty = use root
    std::vector<std::string> index;
    std::vector<TryStep> try_files;  // empty: plain lookup (file, directory index, 404)
    bool hidden_files = false;
    bool symlinks_deny = false;
    std::string handler = "static";  // "static" or "fastcgi" ("proxy" arrives in phase D)
    HandlerKind kind = HandlerKind::static_;
    std::vector<std::pair<std::string, std::string>> add_headers;  // response fields added on 200/304
    std::string origin;  // "" when configured by hand, else the preset that generated it (explain)
    FcgiConfig fastcgi;                        // handler = "fastcgi": upstream and options
    UpstreamConfig proxy;                      // handler = "proxy": the origin (`upstream = "http://..."`) and options
    UpstreamConfig cgi;                        // handler = "cgi": a process per request (`cgi = { ... }`)
    std::shared_ptr<const HttparenaDataset> httparena;  // handler = "httparena" (AGENSIO_HTTPARENA builds only): `httparena = { dataset }`
    bool priority = false;                     // may use the pool slots reserved by priority_reserve
    std::uint64_t id = 0;  // unique for the process's life (cache key scope); set by finalize_site
    MethodSet methods = kStaticMethods;      // what the handler serves here (`methods = [...]` narrows it)
    std::string allow = "GET, HEAD, OPTIONS";  // Allow header for 405 and OPTIONS
};

// Every method an application handler may see; TRACE and CONNECT never reach a handler.
constexpr MethodSet kFcgiMethods = kStaticMethods | method_bit(Method::post) | method_bit(Method::put) |
                                   method_bit(Method::del) | method_bit(Method::patch);

// The php-fpm pool agensio generates for a site with `user` and no `php.socket`
// (C3b, docs/design-per-site-users.md): `agensio pools` writes it, `-t --explain` shows it.
struct PhpPool {
    bool generated = false;
    std::string name;       // "agensio-<user>", also the pool file's stem
    std::string socket;     // <server.pools_run>/agensio-<user>.sock
    std::string state_dir;  // <server.state_dir>/<user>, holding tmp/ and sessions/
    std::string version;    // php version for the pool directory ("" = newest installed)
    std::string pm = "ondemand";  // ondemand (nothing resident while idle) | dynamic | static (benchmarks)
    unsigned children = 8;      // pm.max_children
    unsigned max_requests = 500;
    std::string memory_limit = "256M";
    unsigned max_execution_time = 60;
    unsigned max_input_time = 60;
    std::vector<std::string> open_basedir;                      // default: project root, tmp, sessions
    std::vector<std::pair<std::string, std::string>> extra;    // php_admin_value passthrough
};

struct SiteConfig {
    std::vector<std::string> server_names;  // lower-case host names, "*" matches anything
    std::string user;   // hosting: PHP runs as this user in its own pool, logs are owned by it
    std::string group;  // default: the user's primary group
    PhpPool pool;
    std::vector<std::string> listen;        // "host:port" strings, normalised
    // The protocols of this site's listeners: [server] protocols unless the site says
    // otherwise (a TLS port that must stay HTTP/1.1 next to one that offers h2). Sites on
    // one address must agree. Resolved at load into the flags the listener takes.
    std::vector<std::string> protocols;
    bool h2 = true;
    bool h2c = false;
    bool h3 = false;  // "h3" in protocols: QUIC on the TLS listener's port (phase I, docs/design-http3.md)
    std::string alpn_wire;
    std::string app;                        // preset: "laravel", "php", "static" or "" (none)
    // `redirect = "https"`: every request gets a 301 to https://<Host><target>; a full
    // "https://host[:port]" prefix names the target instead (canonical www host, another
    // port), also allowed on a TLS site. No root needed.
    std::string redirect;
    std::string root;                       // absolute document root, no trailing slash
    std::string project_root;               // the root as given, before a preset appended its public/ or web/ (site-install's target)
    std::size_t max_body_size = 0;          // this site's request-body limit (413 above; drives the pool's upload sizes); 0 = [server] max_body_size
    std::vector<std::string> index{"index.html"};
    std::vector<TryStep> try_files;  // default for locations that do not set their own
    FcgiConfig php;                  // `php = { socket = ... }`: default upstream for fastcgi locations
    UpstreamConfig proxy;            // `proxy = { ... }`: defaults for the proxy locations of this site
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
// [control] (phase F): the unix socket the control API and `agensio ctl` / `agensio mcp`
// talk to. Off unless the table exists. root and server.user are always admin; the
// groups give the roles to other accounts (control/roles.hpp).
struct ControlConfig {
    bool enabled = false;
    std::string socket;     // default: /run/agensio/control.sock (macOS: /usr/local/var/run/agensio/control.sock)
    std::string admins;     // group names, "" = nobody through that role
    std::string operators;
    std::string viewers;
    std::string audit;      // one line per mutating command or refusal; default next to the error log
    std::string sites_root; // where site_create suggests document roots ("" = /var/www)
    bool provision = true;  // fork the root provisioning helper at start (accounts, layout, pools, restart on request)
    bool install = true;    // site-install may download an application from an https URL (false: uploads only)
    bool install_private = false;  // let site-install fetch from loopback, private and link-local addresses (test beds, internal mirrors)
    std::string install_ca;        // PEM bundle site-install trusts instead of the system store (private mirrors, test beds)
    std::size_t upload_max = 512u * 1024 * 1024;  // `agensio ctl upload` body limit (PUT /v1/uploads/NAME)
    // The ceilings a site setting may be raised to through the control plane ([control]
    // site_limits): root owns the range, site-create/site-update move within it.
    struct SiteLimits {
        std::size_t max_body_size = 512u * 1024 * 1024;
        std::size_t memory_limit = 512u * 1024 * 1024;
        unsigned max_execution_time = 300;
        unsigned max_input_time = 300;
        unsigned children = 32;
        unsigned max_requests = 1000000;
    } site_limits;
};

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
    // HTTP/2 (phase G, docs/design-http2.md): what TLS listeners offer through ALPN, in order
    // of preference ("h2", "h1"), and whether plain listeners accept prior-knowledge HTTP/2
    // ("h2c" in the list; off by default: browsers never use it). Caddy's spelling; the
    // ALPN identifier "http/1.1" is accepted for "h1" and normalised to it.
    std::vector<std::string> protocols = {"h2", "h1"};
    bool h2 = true;         // "h2" in protocols: offered on TLS listeners
    bool h2c = false;       // "h2c" in protocols: accepted on plain listeners
    bool h3 = false;        // "h3" in protocols: HTTP/3 over QUIC on the TLS listeners' ports (UDP)
    std::string alpn_wire;  // the ALPN protocol list as OpenSSL wants it (length-prefixed), from protocols
    struct Http2 {
        std::uint32_t max_concurrent_streams = 128;  // SETTINGS_MAX_CONCURRENT_STREAMS (nginx's default)
    } http2;
    // Proxies in front of us whose X-Forwarded-For / X-Forwarded-Proto are believed: the
    // rightmost untrusted address becomes the client (REMOTE_ADDR, access log) and the
    // scheme sets HTTPS / REQUEST_SCHEME for FastCGI. Empty (default): headers are ignored.
    std::vector<Cidr> trusted_proxies;
    // Hosting (C3b): the group agensio runs as (pool sockets grant it access; "" = the
    // process's group), where `agensio pools` writes pool files ("" = detected per distro),
    // where generated pools listen, and the per-user state directories.
    std::string user;   // start as root, bind, open logs, then become this user (H2 pulled forward)
    std::string group;
    std::string pools_dir;
    std::string pools_run;  // defaulted by the loader per platform
    std::string state_dir = "/var/lib/agensio";
    bool strict_users = false;  // every site must name a user
    AcmeConfig acme;
    std::string pid_file;       // written at start (before dropping privileges); `agensio reload` signals it.
                                // Default: /run/agensio.pid (Linux), /usr/local/var/run/agensio.pid (macOS),
                                // set by the loader; "" disables it

    LogConfig log;
    ControlConfig control;

    // [cache]
    std::size_t cache_max_file_size = 4u * 1024 * 1024;
    std::size_t cache_max_size = 256u * 1024 * 1024;
    double cache_evict_fraction = 0.2;
    std::uint32_t cache_revalidate_s = 1;
    bool cache_precompressed = true;  // serve name.br / name.gz beside a cached file to a client that accepts it
    std::size_t stream_chunk_size = 64 * 1024;
    std::size_t cache_sendfile_min_size =
        48 * 1024;  // cached files at least this large are served by sendfile on plain sockets (0 = never)
    std::size_t cache_max_open_files =
        1024;  // streamed files (above max_file_size) whose open descriptor is kept in the cache (0 = none)

    std::vector<SiteConfig> sites;

    std::filesystem::path config_path;  // the file this came from
    std::vector<std::string> includes;  // the `include` patterns as written (site_create checks sites.d is covered)
};

// Parses "4MB", "256k", "1G", "65536". Throws std::invalid_argument.
std::size_t parse_size(std::string_view text);
// The request-body limit of a site: its own max_body_size, else the server's.
inline std::size_t body_limit_of(const SiteConfig& site, const Config& cfg) noexcept {
    return site.max_body_size ? site.max_body_size : cfg.max_body_size;
}

// Parses a try_files list: "$uri", "$uri/", "=403"/"=404", or "/path" (last element only
// for the latter two). Throws std::invalid_argument.
std::vector<TryStep> parse_try_files(const std::vector<std::string>& items);

// Appends the implicit "/" location from the site's own settings if none is configured
// and sorts the locations for Router::location. The loader calls it; exposed for tests.
void finalize_site(SiteConfig& site);
// The synthetic site the control listener routes to: one location of kind `control`.
SiteConfig control_site();
// Every value `app = "..."` accepts: "static", the PHP presets in table order, "proxy".
// The control API and the MCP tool schema list these, so a new preset row is exposed at once.
std::vector<std::string> app_presets();
// What each `app` value does, for `agensio ctl presets` and the MCP tool: served root,
// which .php runs, front controller, refused suffixes, shielded directories, files never served.
json::Value preset_catalog();
// The official download of a preset's application ("" when the preset has none): the
// newest release, or `version` when given. Pure; used by site-install.
std::string preset_source(const std::string& app, const std::string& version);
// The preset's credential files, relative to the served root ("/wp-config.php"): what the
// hosting rules require to be unreadable by the server's group and what every write path
// creates 0600. A subset of the preset's never-served list. Empty for presets without one.
std::vector<std::string> preset_secrets(const std::string& app);
// Where the preset's application keeps what users upload, relative to the served root
// ("/wp-content/uploads"); "" when the preset has no such place.
std::string preset_uploads(const std::string& app);

// Prints the effective configuration after presets, one TOML-like block per site and
// location, so nothing a preset did is hidden (`agensio -t --explain`).
void explain_config(const Config& cfg, std::ostream& out);

// Loads and validates a configuration file. Throws std::runtime_error with a
// human readable message on any problem.
Config load_config(const std::filesystem::path& path);

}  // namespace agensio
