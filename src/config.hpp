// Configuration model and TOML loader.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <map>
#include <memory>
#include <ostream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/auth.hpp"
#include "core/request.hpp"
#include "net/cidr.hpp"
#include "services/json.hpp"
#include "upstream/options.hpp"

namespace agensio {

// `auth` is never configured: the dispatcher returns a location of that kind while a password is
// verified on the pool ([[site.auth]]); the connection waits for it and routes the request again.
enum class HandlerKind : std::uint8_t { static_, fastcgi, proxy, cgi, control, httparena, auth };

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
    // Suffix only: the script (the path up to the ending) must sit directly in this directory,
    // "/" for the root, "/core/" for Drupal's core entry points; "" = anywhere. The Drupal
    // preset sets it, after Drupal's own .htaccess, which refuses PHP below any other directory.
    std::string script_dir;
    std::vector<std::string> deny_suffixes;  // request paths ending with one of these get 404 (".php" under uploads)
    std::vector<std::string> allow_suffixes;  // when set, only paths ending with one of these are served (else 404)
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
    // Used instead of add_headers for a file whose name carries a content hash
    // (name.<8-64 hex>.ext: a name that changes with its content), when not empty: a Django
    // site's /static/ caches those for a year, the rest briefly (2026-09-28 report).
    std::vector<std::pair<std::string, std::string>> hashed_headers;
    // Written by hand with nothing but path and add_headers: it adds its fields to the location
    // a preset (or the implicit "/") makes at the same path instead of replacing it (a managed
    // site file's HSTS "/" location replaced a proxy preset's "/", 2026-09-28).
    bool headers_only = false;
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

// [[site.access]] (2026-10-07, docs/configuration.md 19, docs/design-site-operations.md 22):
// who may fetch a path of the site, by client address. Checked on the normalised path after
// the site is found and before a location is chosen, so whichever location would serve the
// request (a .php suffix, a proxy, a static file) the rule has already applied; this is
// where nginx's per-location allow/deny is bypassed by a regex location. The longest rule
// covering a path decides; every rule is an allow list, so nothing is open by omission.
struct AccessRule {
    std::string path;     // a prefix covers whole segments ("/admin": /admin, /admin/x, never /administrator); "/" covers the site
    bool exact = false;   // match = "exact": this path, and the script it names run with path info (access::script_of)
    bool any = false;     // allow = ["any"]: everyone (reopens a subtree of a restricted path)
    bool report = false;  // mode = "report": log who would be refused, refuse nobody
    std::vector<Cidr> allow;              // the entries with named sets expanded
    std::vector<std::string> allow_text;  // as written ("@office", "10.0.0.0/8"): --explain, site_show, the log
    std::string origin;   // "" written in the site file, "preset:wordpress" added by a preset
};

// [[site.auth]] (2026-10-08, docs/configuration.md 19b, design section 25): a password in front
// of a path. The user file is read and checked once per load, shared by the rules that name it.
struct AuthUserFile {
    std::string path;
    std::vector<auth::User> users;
    std::uint64_t id = 0;  // unique per load: a connection's memo of a login names the load it was checked against
};

struct AuthRule {
    std::string path;     // matched like an access rule: whole segments, any case, the longest decides
    bool exact = false;
    bool open = false;    // open = true: no password here, below a protected path
    std::string users_path;
    std::shared_ptr<const AuthUserFile> users;
    std::string realm;    // the challenge's realm (default: the site's first name)
    std::vector<Cidr> skip;              // skip_for, sets expanded: these clients need no password
    std::vector<std::string> skip_text;  // as written
    bool plain_http = false;             // plain_http = "allow": asked over plain HTTP too
    enum class Credentials : std::uint8_t { preset, pass, strip };
    Credentials credentials = Credentials::preset;  // resolved at load: pass for PHP sites, strip otherwise
    std::string forward_user;  // a proxy location sends the verified name in this field
    std::string origin;        // "" written in the site file, "preset:wordpress" added by a preset
};

// A path pattern the site refuses with 404 (`refuse`, 2026-10-08, core/refuse.hpp): gitignore-
// style, compiled once at load. One segment of it, lower case: the literals around its '*'s.
struct RefuseSegment {
    std::string first;             // before the first '*' (the whole segment when it has none)
    std::string last;              // after the last '*'
    std::vector<std::string> mid;  // between the stars, in order
    bool star = false;
};

struct RefusePattern {
    std::string text;                 // as written: --explain, site_show, path_check
    std::vector<RefuseSegment> head;  // matched from the site's root; empty for a name in any directory
    bool deep = false;                // a "**" (or a name without '/'): any number of directories, then `tail`
    std::vector<RefuseSegment> tail;
};

// A site's patterns, and what refuse::index builds over them so a path is compared with a few
// patterns only: a name pattern is found by the last byte its segment must end with (256: it
// ends with '*'), an anchored one by its first segment when that is a literal (`groups`, one
// per distinct name), else it is in `anchored_any`; "**/a/b" in `anywhere`.
struct RefuseSet {
    struct Group {
        std::string first;                  // the literal first segment, lower case
        std::vector<std::uint8_t> members;  // indexes into patterns
    };
    std::vector<RefusePattern> patterns;
    std::vector<std::uint8_t> names, anchored_any, anywhere;
    std::array<std::uint8_t, 258> name_at{};
    std::vector<Group> groups;
    std::size_t longest_first = 0;  // the longest literal first segment of a group
    bool empty() const noexcept { return patterns.empty(); }
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
    bool hq_interop = false;  // "hq-interop" in protocols: the interop runner's transport tests (AGENSIO_INTEROP builds only)
    std::string alpn_wire;
    std::string app;                        // preset: "laravel", "php", "static" or "" (none)
    // `redirect = "https"`: every request gets a 301 to https://<Host><target>; a full
    // "https://host[:port]" prefix names the target instead (canonical www host, another
    // port), also allowed on a TLS site. No root needed.
    std::string redirect;
    std::string root;                       // absolute document root, no trailing slash
    std::string project_root;               // the root as given, before a preset appended its public/ or web/ (site-install's target)
    // app = "django" | "wagtail": the project's Python package (NAME/settings, NAME/wsgi.py),
    // which the tasks and the rendered unit load (2026-09-28, the owner's decision: a site
    // field given at site_create, not a parameter of every task).
    std::string project;
    // app = "node": the file node runs (relative to the project directory, server/server.js),
    // which the rendered unit starts; optional in the file, needed for the unit (2026-09-28).
    std::string entry;
    std::size_t max_body_size = 0;          // this site's request-body limit (413 above; drives the pool's upload sizes); 0 = [server] max_body_size
    std::vector<std::string> index{"index.html"};
    std::vector<TryStep> try_files;  // default for locations that do not set their own
    FcgiConfig php;                  // `php = { socket = ... }`: default upstream for fastcgi locations
    UpstreamConfig proxy;            // `proxy = { ... }`: defaults for the proxy locations of this site
    std::optional<TlsConfig> tls;
    bool is_default = false;
    bool hidden_files = false;   // serve paths with a segment starting with '.' (.env, .git, .htaccess)
    bool symlinks_deny = false;  // refuse files whose canonical path leaves the root (realpath per cache miss)
    // `encoded_slashes = "allow"`: a path spelling a separator as a percent escape (%2F, %5C)
    // is decoded and looked up as before 2026-10-02, Apache's AllowEncodedSlashes NoDecode
    // in effect for a front controller that reads REQUEST_URI; the default ("deny") answers
    // 404 on every filesystem-backed location, Apache's Off. Proxy locations pass the raw
    // target either way.
    bool encoded_slashes_allow = false;
    // Sorted for Router::location: exact before prefix, longer before shorter, "/" last.
    std::vector<LocationConfig> locations;
    // Root additions (docs/design-site-operations.md 20): the files beside the managed site
    // file (sites.d/<domain>.root.toml) whose [[location]] tables were merged into this site,
    // each location marked origin "root:<file>"; root's alone, never written or read by the
    // control plane, so a site the tools manage keeps root's freedom.
    std::vector<std::string> root_additions;
    // The file this site was read from (absolute), and whether it is the last good version a
    // reload carried over because that file was set aside (docs/design-site-operations.md 26).
    std::string source;
    bool carried = false;
    // The paths a login form or an authenticating API is posted to (`login_paths`,
    // 2026-10-02, docs/configuration.md 18), on top of the preset's own
    // (preset_login_paths): what the rendered fail2ban jail counts attempts on. Never read
    // when serving; a site without a preset of its own names them here.
    std::vector<std::string> login_paths;
    std::string access_log;    // absolute path, or "" for no access log (site `access_log`, default [log] access)
    int access_log_sink = -1;  // set by the Server: index into its log registry
    // [[site.access]], longest path first (an exact rule before a prefix of the same path);
    // empty, a request pays one test. `access_first` has a bit per byte that follows the
    // leading '/' of a rule's path (bit 0 for "/" itself, every bit for a rule on "/"), so a
    // request whose path starts with no such byte skips the scan.
    std::vector<AccessRule> access;
    std::array<std::uint64_t, 4> access_first{};
    // `refuse`: paths answered 404 whichever location would serve them (core/refuse.hpp);
    // empty, a request pays one test.
    RefuseSet refuse;
    // [[site.auth]], longest path first, with the same first-byte bitmap as `access`.
    std::vector<AuthRule> auth;
    std::array<std::uint64_t, 4> auth_first{};
    // An exact access or password rule (2026-10-09, the alpha.58 report, finding 1): a path that
    // runs a script is judged as that script too (access::script_of); and a CGI location, where
    // any path may run one. Without the first, a request pays nothing for it.
    bool exact_rules = false;
    bool cgi_locations = false;
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
    // Site tasks (F13, services/tasks.*): where the interpreters live ([control] runtimes,
    // one directory per runtime, root's alone), the bounds of every run ([control]
    // task_limits) and whether tasks that download may run ([control] task_network).
    struct Runtimes {
        std::string ruby = "/usr/bin";
        std::string node = "/usr/bin";
        std::string php = "/usr/bin";
        std::string python3 = "/usr/bin";
    } runtimes;
    unsigned task_timeout = 1200;   // seconds before SIGTERM; a task row's own limit is capped by it
    unsigned task_processes = 512;  // RLIMIT_NPROC of the site's account while a task runs
    bool task_network = true;
    // How long a site deleted with its files stays in the trash (<sites_root>/.trash, root's
    // alone) before the hourly expiry removes it; 0 keeps entries until trash_delete (F12b,
    // 2026-09-30, the owner's 60 days).
    unsigned trash_keep = 60;  // days
    // Host protection (2026-10-02, docs/configuration.md 18): whether health looks for the
    // per-address limits in the kernel's firewall and a fail2ban jail over the access logs.
    // "check" warns when they are missing on a host with a public listener; "external" says
    // a panel or the administrator manages them, so the findings are informational;
    // "off" skips the probe.
    std::string host_protection = "check";
};

// The directory [control] runtimes names for a runtime ("ruby"), "" for an unknown one.
std::string runtime_dir(const ControlConfig& control, std::string_view runtime);

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
    // Connections one worker holds at most, TCP and QUIC together; 0 = from the open-file
    // limit at start (connection_ceiling below). Above it a plain listener answers 503 and
    // closes, a TLS one closes before any handshake work (2026-10-02, hardening item 5).
    std::uint32_t max_connections = 0;
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
    bool hq_interop = false;  // "hq-interop" in protocols (AGENSIO_INTEROP builds): the QUIC interop runner's GET-line protocol
    std::string alpn_wire;  // the ALPN protocol list as OpenSSL wants it (length-prefixed), from protocols
    struct Http2 {
        std::uint32_t max_concurrent_streams = 128;  // SETTINGS_MAX_CONCURRENT_STREAMS (nginx's default)
    } http2;
    struct Http3 {
        std::string retry = "auto";  // Retry before a QUIC handshake: "auto" (under load), "always", "never"
        bool alt_svc = true;         // the alt-svc field on h1 and h2 answers of a TLS listener that also speaks h3
    } http3;
    // Proxies in front of us whose X-Forwarded-For / X-Forwarded-Proto are believed: the
    // rightmost untrusted address becomes the client (REMOTE_ADDR, access log) and the
    // scheme sets HTTPS / REQUEST_SCHEME for FastCGI. Empty (default): headers are ignored.
    std::vector<Cidr> trusted_proxies;
    // [addresses] (2026-10-07): named address sets the sites' access rules name as "@name", so
    // one edit reaches every site that uses them; checked and expanded at load.
    std::map<std::string, std::vector<std::string>> address_sets;
    // The user files of the sites' [[site.auth]] rules, each read and checked once per load.
    std::map<std::string, std::shared_ptr<const AuthUserFile>> auth_files;
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
    // Root additions files whose site is not in the configuration (disabled or deleted): the
    // load succeeds, their locations are ignored, -t, the error log and health say so.
    struct OrphanAdditions {
        std::string file, site;
    };
    std::vector<OrphanAdditions> orphan_additions;
    // Included site files set aside (docs/design-site-operations.md 26): the file, the loader's
    // error, and whether the last good version of its sites, carried from the running
    // configuration, keeps serving (a reload) or its sites are not served (a start, or a
    // carried version that lost a conflict). The main file is all or nothing: an error there
    // still fails the load.
    struct HeldBack {
        std::string file, error;
        bool carried = false;
    };
    std::vector<HeldBack> held_back;
    // A digest of each loaded file's text: a reload tells a file it already runs unchanged from
    // a newcomer when two of them conflict (the running one keeps its place).
    std::map<std::string, std::size_t> file_digests;
    const HeldBack* held(std::string_view file) const noexcept {
        for (const auto& h : held_back)
            if (h.file == file) return &h;
        return nullptr;
    }
};

// The per-worker connection ceiling in force: the configured value, else from the open-file
// limit the server raised at start, (limit - 2048 kept for the cache's descriptors, logs and
// upstream connections) / workers, never below 128 (128 too when the limit is unknown).
// Per-address limits are the firewall's (docs/configuration.md 18).
inline std::uint64_t connection_ceiling(const Config& cfg, std::uint64_t fd_limit, unsigned workers) noexcept {
    if (cfg.max_connections) return cfg.max_connections;
    const std::uint64_t spare = fd_limit > 2048 + 128 ? fd_limit - 2048 : 128;
    const std::uint64_t per = spare / (workers ? workers : 1);
    return per < 128 ? 128 : per;
}

// The file beside a managed site's where root extends it: sites.d/<domain>.root.toml.
inline constexpr std::string_view kRootAdditionsSuffix = ".root.toml";

// Parses "4MB", "256k", "1G", "65536". Throws std::invalid_argument.
std::size_t parse_size(std::string_view text);
// The request-body limit of a site: its own max_body_size, else the server's.
inline std::size_t body_limit_of(const SiteConfig& site, const Config& cfg) noexcept {
    return site.max_body_size ? site.max_body_size : cfg.max_body_size;
}
// The error-log line for a request refused with 413 because its declared length is above
// the limit, naming the site, the sizes and the fix (nginx logs the same case as "client
// intended to send too large body"): the first upload above a site's limit is otherwise
// visible in the access log alone (2026-09-27 report). Error path only.
// `at_least`: a body without a declared length (chunked, or HTTP/2 and HTTP/3 without
// content-length), counted as it arrived and refused once past the limit.
std::string body_refused_text(const SiteConfig* site, std::string_view remote, std::uint64_t declared, std::size_t limit, bool at_least = false);

// Parses a try_files list: "$uri", "$uri/", "=403"/"=404", or "/path" (last element only
// for the latter two). Throws std::invalid_argument.
std::vector<TryStep> parse_try_files(const std::vector<std::string>& items);

// Appends the implicit "/" location from the site's own settings if none is configured
// and sorts the locations for Router::location. The loader calls it; exposed for tests.
void finalize_site(SiteConfig& site);

// Access by client address (2026-10-07): the checks the loader, site_update's rules.restricted
// and the access-check command share. "" when fine, else why not.
std::string check_access_path(std::string_view path);
// One allow entry: "any", "@set" (from cfg.address_sets) or an address or range; appended to
// `out` (a set's members) unless it is "any".
std::string access_entry(std::string_view text, const Config& cfg, std::vector<Cidr>& out, bool& any);
// What -t, the error log at start and reload, and health say about the sites' access rules:
// an entry that holds a trusted proxy, a loopback entry with no local proxy trusted, an IPv4-only
// list on a site reachable over IPv6, a single IPv6 address, a whole site restricted.
struct AccessNotice {
    std::string code;      // access_allows_proxy, access_loopback, access_ipv4_only, access_single_ipv6, access_site_restricted,
                           // exact_rule_proxied_script
    std::string severity;  // "warning" or "info"
    std::string site, text;
};
std::vector<AccessNotice> access_notices(const Config& cfg);

// A normalised listen address ("host:port", an IPv6 host unbracketed: "::1:443") that only this
// machine reaches: 127.0.0.0/8, ::1 (an IPv4-mapped 127.x too) or localhost. Judged on the parsed
// address, never its spelling (the alpha.58 report's finding 4: "[::1]" was looked for and "::1"
// stored). Health, -t and the host-protection renderer share it.
bool loopback_listen(std::string_view listen);
// The same address as written in a configuration: "[::1]:443" for IPv6.
std::string display_listen(std::string_view listen);
// The synthetic site the control listener routes to: one location of kind `control`.
SiteConfig control_site();
// Every value `app = "..."` accepts: "static", the PHP presets in table order, "proxy",
// "rails". The control API and the MCP tool schema list these, so a new preset is exposed at once.
std::vector<std::string> app_presets();
// A preset that hands every request to the site's upstream ("proxy", "rails", "redmine"): no
// PHP, no document root served, `upstream` required.
bool proxy_app(std::string_view app) noexcept;
// A Rails application preset ("rails", and "redmine" built on it): the Rails refusals, the
// Rails tasks, the credential files of Rails.
bool rails_app(std::string_view app) noexcept;
// A Django application preset ("django", and "wagtail" built on it): /static/ and /media/
// from disk, the rest to the upstream (Gunicorn); a virtualenv per site; the Python tasks.
bool python_app(std::string_view app) noexcept;
// The Node.js preset ("node"): everything to the upstream, npm's tasks, a unit that runs node.
bool node_app(std::string_view app) noexcept;
// An entry `entry = "..."` takes: a relative path inside the project directory ending in .js,
// .mjs or .cjs, of letters, digits and . _ - /, no "..", no "//". "" or why.
std::string check_entry(std::string_view entry);
// A preset whose application service agensio renders and watches (site_service_unit,
// site_service_status, health): the Rails and the Django presets.
bool service_app(std::string_view app) noexcept;
// A project name `project = "..."` takes: ^[a-z_][a-z0-9_]{0,63}$ and not a module the
// project would shadow (django, wagtail, site, test, ...). "" or why.
std::string check_project_name(std::string_view name);
// What a Django site's settings and unit are told about the site itself: its host names
// (server_name and aliases, "*.example.com" as Django's ".example.com"), the origins with
// the scheme it is reached by (https when a block of the site has TLS), and the first
// origin as the base URL. Comma-separated, no spaces: environment values and unit lines.
struct AppContext {
    std::string hosts, origins, base_url;
    bool https_redirect = false;  // a plain-http block of the site redirects to https
    bool hsts = false;            // a block of the site sends Strict-Transport-Security (add_headers)
};
AppContext app_context(const Config& cfg, const SiteConfig& site);
// A PHP preset (a row of the PHP preset table).
bool php_app(std::string_view app);
// The endings a PHP engine would run (.php, .phtml, .phar, ...) and the ones every PHP preset
// refuses besides them (.inc, editor backups, logs, dumps, SQLite files): what a site's rules
// (control/sites.hpp) refuse below a cached directory.
const std::vector<std::string>& php_suffixes();
const std::vector<std::string>& source_backup_suffixes();
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
// The login paths a preset's application is known to post credentials to (wordpress:
// /wp-login.php, drupal: /user/login, ...), for the rendered fail2ban jail; empty for a preset
// whose applications differ (php, rails, node, proxy, static).
std::vector<std::string> preset_login_paths(const std::string& app);
// The paths of a preset's administration (2026-10-07), what `rules.admin` restricts when the user
// asks; nothing restricts them by default. `login` marks the login page, which visitors use too
// on a shop or a members site, so it joins only on request.
struct AdminPath {
    std::string path;
    bool exact = false;
    bool login = false;
};
std::vector<AdminPath> preset_admin_paths(const std::string& app);
// A `login_paths` entry: "/"-rooted, plain characters, no "..", no "//", at most 255; "" or why not.
std::string check_login_path(const std::string& path);
// Where the preset's application keeps what users upload, relative to the served root
// ("/wp-content/uploads"); "" when the preset has no such place.
std::string preset_uploads(const std::string& app);

// Prints the effective configuration after presets, one TOML-like block per site and
// location, so nothing a preset did is hidden (`agensio -t --explain`).
void explain_config(const Config& cfg, std::ostream& out);

// Loads and validates a configuration file. Throws std::runtime_error with a human readable
// message on a problem of the main file or one every site shares; an included site file with
// an error, or one that conflicts with another, is set aside (Config::held_back) and the rest
// loads. With `running` (a reload), a file set aside keeps the version of its sites the running
// configuration has, and in a conflict a file the running configuration loaded unchanged keeps
// its place (docs/design-site-operations.md 26).
Config load_config(const std::filesystem::path& path, const Config* running = nullptr);
// What the next load would say about a [[site.auth]] users file: "" when it loads, else the
// loader's own refusal (missing, a symlink, another owner than the main configuration's,
// writable by group or others, readable by others, over 1 MB, a line it cannot read). Health
// asks it for every file a rule names, so a file broken under a running server is reported
// before a restart that would not start (2026-10-09). "" in a build without passwords.
std::string auth_users_problem(const std::string& path, const Config& cfg);

}  // namespace agensio
