// Upstream address, per-location options and failure reasons shared by the FastCGI client
// and the HTTP (reverse proxy) client: plain data the configuration loader fills, the
// clients read and the logs report. No Asio here so config.hpp can include it.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace agensio {

struct UpstreamAddress {
    bool unix = false;
    bool tls = false;  // "https://": TLS to the origin (the key carries the scheme so pools stay apart)
    std::string path;  // unix socket path
    std::string host;  // IPv4/IPv6 literal
    std::uint16_t port = 0;
    std::string key;   // "unix:/path" or "host:port", the pool key
};

// "unix:/run/php/php-fpm.sock", "/run/php/php-fpm.sock", "127.0.0.1:9000", "[::1]:9000".
bool parse_upstream_address(std::string_view text, UpstreamAddress& out, std::string& error);

struct UpstreamOptions {
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds send_timeout{30000};
    std::chrono::milliseconds read_timeout{60000};  // between two reads from the upstream
    // Keep the connection after a response. FastCGI (FCGI_KEEP_CONN): off by default on
    // purpose, php-fpm binds one child to each open connection, so every idle keep-alive
    // connection (per worker) pins a child; with more workers than pm.max_children the
    // other workers starve (seen in our own suite: 24 workers, 4 children, every further
    // request a 504). Generated per-site pools (C3b) size for it and turn it on. HTTP
    // proxying: on by default, an origin server expects keep-alive.
    bool keep_conn = false;
    std::size_t max_idle = 8;                       // idle connections kept per upstream and worker
    // Pool bounds (per worker and upstream): an explicit queue instead of the kernel backlog.
    std::size_t max_connections = 16;               // in-flight requests to the upstream
    std::size_t queue_depth = 64;                   // waiting requests before answering 503
    std::chrono::milliseconds queue_wait{5000};     // longest wait in the queue before 503
    double priority_reserve = 0.0;                  // share of max_connections kept for priority locations
    // Response handling.
    bool buffering = true;                          // collect the whole response before answering
    std::size_t buffer_max = 1024 * 1024;           // buffering: spill to a temp file above this
    // Cap on the temp file (nginx fastcgi_max_temp_file_size): beyond it the response is
    // streamed for the rest (head delivered, memory + spill served first), never an
    // unbounded disk write for a readfile() of a huge download.
    std::uint64_t buffer_file_max = 1024ull * 1024 * 1024;
    std::size_t head_max = 64 * 1024;               // response head larger than this is 502 head_too_large
    // FastCGI only. PATH_INFO: split the request path at the first ".php/" (nginx
    // fastcgi_split_path_info ^(.+\.php)(/.+)$): SCRIPT_NAME/SCRIPT_FILENAME get the
    // script, PATH_INFO the rest.
    bool path_info = true;
    // Request body handling.
    bool request_buffering = true;                  // read the whole body before talking to the upstream
    std::size_t request_buffer_max = 256 * 1024;    // request body in memory up to this, then a temp file
    // Passive health (a group of origins): after `max_fails` consecutive failures an
    // address is skipped for `fail_timeout`; a success clears the count. When every
    // address is down the least recently marked one is tried anyway.
    unsigned max_fails = 3;
    std::chrono::milliseconds fail_timeout{10000};
};

// `proxy = { tls = { ... } }`: how TLS to an https:// origin is set up.
struct TlsClientConfig {
    bool verify = true;        // the origin's certificate against the store below
    std::string server_name;   // SNI and the name checked (default: none; needed for verify with an IP literal)
    std::string ca_file;       // a PEM bundle; "" = the system store
    std::string key() const { return (verify ? "v:" : "n:") + ca_file; }  // one ssl::context per distinct setup
};

// A resolved `fastcgi = { ... }` / `php = { ... }` / `proxy = { ... }` table.
struct UpstreamConfig {
    bool configured = false;  // a socket / upstream was given
    UpstreamAddress address;                 // the first (or only) address; FastCGI has one
    std::vector<UpstreamAddress> addresses;  // proxy: the group, round-robin per worker
    UpstreamOptions options;
    // FastCGI: the location's root as the FastCGI server sees it when it runs in another
    // filesystem namespace (a container): SCRIPT_FILENAME, DOCUMENT_ROOT and
    // PATH_TRANSLATED are rewritten from the local root to this one. Empty: same paths.
    std::string remote_root;
    // Proxy: `upstream = "http://host:port/prefix/"` replaces the location's prefix of the
    // target with "/prefix/" (nginx proxy_pass with a URI); "" forwards the target as sent.
    std::string rewrite;
    // Proxy header policy (D2). `host`: "pass" (the client's Host, default), "upstream" (the
    // origin's address) or a literal name. `forwarded`: which client-address convention
    // goes to the origin: "x-forwarded" (X-Forwarded-For/Proto/Host, default),
    // "forwarded" (RFC 7239), "both" or "off". A peer that is not a trusted proxy gets its
    // own X-Forwarded-* replaced, never appended to (nothing a client sends is believed).
    // `set_headers`: fields set on the way to the origin ("" removes; values may use $host,
    // $remote_addr, $scheme, $server_name, $server_port). `hide`: fields dropped from the
    // origin's answer. `rewrite_redirects`: a Location pointing at the origin's address is
    // rewritten to this site.
    std::string host = "pass";
    std::string forwarded = "x-forwarded";
    std::vector<std::pair<std::string, std::string>> set_headers;
    std::vector<std::string> hide;
    bool rewrite_redirects = true;
    // Proxy: forward `Upgrade` requests (WebSocket) and, on a 101, tunnel bytes both ways
    // until a side closes; `tunnel_timeout_s` closes an idle tunnel (0 = never, the
    // default: nginx's 60 s read timeout dropping idle WebSockets is a classic complaint).
    bool upgrade = true;
    std::uint32_t tunnel_timeout_s = 0;
    TlsClientConfig tls;
    // CGI: the interpreter to run the script with ("" = the script itself, #! or binary)
    // and extra environment entries.
    std::string interpreter;
    std::vector<std::pair<std::string, std::string>> env;
    std::string params_prefix;  // FastCGI: constant FCGI_PARAMS pairs of this location, encoded once at load
    std::string retry_after;    // "Retry-After" value for 503s (queue_wait in seconds)
};

// Why an exchange failed, for the error log (with a fix hint) and the access log.
enum class UpstreamFailure : std::uint8_t {
    none,
    connect_refused,         // nothing listens on the socket/port
    socket_missing,          // unix socket path does not exist
    socket_permission,       // we may not connect to the unix socket
    connect_error,           // any other connect failure
    connect_timeout,
    pool_saturated,          // queue full: 503
    queue_timeout,           // waited queue_wait in the queue: 503
    send_timeout,
    read_timeout,            // 504
    closed_early,            // EOF/reset before the response was complete
    primary_script_unknown,  // FastCGI: fpm could not open SCRIPT_FILENAME (its own 404 is passed through)
    bad_response_head,
    head_too_large,
    protocol_error,
    spill_error,             // temp file for a body could not be written
    tls_error,               // handshake or certificate verification with an https:// origin failed
};

const char* to_string(UpstreamFailure f) noexcept;
// The HTTP status we answer with: 503 (pool), 504 (timeouts), 502 (the rest).
int status_for(UpstreamFailure f) noexcept;

// The FastCGI code and its tests use these names.
using FcgiAddress = UpstreamAddress;
using FcgiOptions = UpstreamOptions;
using FcgiConfig = UpstreamConfig;
using FcgiFailure = UpstreamFailure;
inline bool parse_fcgi_address(std::string_view text, UpstreamAddress& out, std::string& error) {
    return parse_upstream_address(text, out, error);
}

}  // namespace agensio
