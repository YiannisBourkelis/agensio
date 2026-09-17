// FastCGI upstream address, per-location options and failure reasons: plain data the
// configuration loader fills, the client reads and the logs report. No Asio here so
// config.hpp can include it.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace agensio {

struct FcgiAddress {
    bool unix = false;
    std::string path;  // unix socket path
    std::string host;  // IPv4/IPv6 literal
    std::uint16_t port = 0;
    std::string key;   // "unix:/path" or "host:port", the pool key
};

// "unix:/run/php/php-fpm.sock", "/run/php/php-fpm.sock", "127.0.0.1:9000", "[::1]:9000".
bool parse_fcgi_address(std::string_view text, FcgiAddress& out, std::string& error);

struct FcgiOptions {
    std::chrono::milliseconds connect_timeout{5000};
    std::chrono::milliseconds send_timeout{30000};
    std::chrono::milliseconds read_timeout{60000};  // between two records from the upstream
    // FCGI_KEEP_CONN. Off by default on purpose: php-fpm binds one child to each open
    // connection, so every idle keep-alive connection (per worker) pins a child; with more
    // workers than pm.max_children the other workers starve (seen in our own suite: 24
    // workers, 4 children, every further request a 504). Turn it on where the pool is sized
    // for it (a per-site pool with max_children > workers x max_idle + concurrency; C3b).
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
    std::size_t head_max = 64 * 1024;               // response head larger than this is 502 head_too_large
    // Request body handling.
    bool request_buffering = true;                  // read the whole body before talking to fpm
    std::size_t request_buffer_max = 256 * 1024;    // request body in memory up to this, then a temp file
};

// A resolved `fastcgi = { ... }` / `php = { ... }` table.
struct FcgiConfig {
    bool configured = false;  // a socket was given
    FcgiAddress address;
    FcgiOptions options;
    std::string params_prefix;  // constant FCGI_PARAMS pairs of this location, encoded once at load
    std::string retry_after;    // "Retry-After" value for 503s (queue_wait in seconds)
};

// Why an exchange failed, for the error log (with a fix hint) and the access log.
enum class FcgiFailure : std::uint8_t {
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
    child_closed_early,      // EOF/reset before END_REQUEST
    primary_script_unknown,  // fpm could not open SCRIPT_FILENAME (its own 404 is passed through)
    bad_response_head,
    head_too_large,
    protocol_error,
    spill_error,             // temp file for a body could not be written
};

const char* to_string(FcgiFailure f) noexcept;
// The HTTP status we answer with: 503 (pool), 504 (timeouts), 502 (the rest).
int status_for(FcgiFailure f) noexcept;

}  // namespace agensio
