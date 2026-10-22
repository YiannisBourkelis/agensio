// Per-worker scratch state. One instance per worker thread, never shared.
#pragma once

#include <array>
#include <ctime>
#include <string>

#include "cache.hpp"
#include "core/auth.hpp"
#include "http_date.hpp"
#include "net/cidr.hpp"
#include "services/log.hpp"

namespace agensio {

struct WorkerState {
    // [[site.auth]] (design section 25): this worker's remembered logins, the verifications it
    // has on the pool (bounded), and the one a request just asked for, which the connection hands
    // to the pool with its continuation (Dispatcher::start_auth).
    auth::Cache auth_cache;
    unsigned auth_inflight = 0;
    std::string auth_scratch;
    struct AuthJob {
        bool pending = false;
        std::string password, hash, user, site, realm, client, method, path;
        auth::Key key{};
        bool known = false, locked = false;
        std::int64_t expires = 0;
    } auth_job;
    DateCache date;
    LocalIndex local;
    std::time_t now = 0;      // wall clock read once per request by the connection
    // [server] server_header as this worker sends it (Server's apply_server_header, at a start and on
    // every reload, on this worker's loop): the value for HTTP/2 and HTTP/3, the line for HTTP/1, and
    // the connection ceiling's 503 (Server::refuse_connection) carrying the same field.
    std::string server_value;
    std::string server_line;  // "Server: agensio\r\n" or empty
    std::string limit_answer;
    std::string prefix200;    // "HTTP/1.1 200 OK\r\nServer: ..\r\nDate: ..\r\n", refreshed per second
    std::time_t prefix200_time = 0;
    std::string h2_server_insert;  // HTTP/2: the server field as an inserting literal, built once (the encoder indexes it after)
    std::string h2_date_insert;    // HTTP/2: the date field as an inserting literal, refreshed per second
    std::time_t h2_date_time = 0;
    std::string path;     // normalised request path
    bool encoded_separator = false;  // the target spelled a '/' or '\\' as a percent escape (%2F, %5C): filesystem handlers answer 404
    std::string fs_path;  // filesystem path being served
    const void* site = nullptr;  // the SiteConfig chosen for the current request (for the access log)
    bool method_allowed = true;  // the current location accepts the request method (else only a try_files fallback may)
    WorkerLogs logs;             // per-worker access log buffers
    std::string scratch;         // handler scratch (capacity retained)
    std::string params_tail;     // FastCGI per-request params (capacity retained)
    // Access by client address (core/access.hpp): the other readings of a path a site's rules
    // test, and the error log's limits for its lines (Dispatcher::admit, access_log_tick).
    std::string access_scratch;
    // A redirect's scheme and host when they change with a path rule's target in one hop
    // (docs/redirects.md 1; Dispatcher::redirect_https, redirect_host). Capacity retained.
    std::string redirect_origin;
    // proxy_scheme_missing (docs/redirects.md 2.4, Dispatcher::note_scheme_missing): the sites this
    // worker noted a trusted proxy without X-Forwarded-Proto for, each at most once a minute.
    struct NoticeGate {
        const void* site = nullptr;
        std::time_t at = 0;
    };
    std::array<NoticeGate, 8> scheme_noted{};
    struct AccessLog {
        // Refusals: one line a second; the access log has every 403 with its client, so the
        // ones held back are only counted, and the count is written when the second is over.
        std::time_t refused_at = 0;
        unsigned refused_held = 0;
        // Report mode exists to name who a rule would lock out: each rule and client written at
        // least once a minute (32 remembered), at most 16 lines a second; past that, counted.
        struct Seen {
            const void* rule = nullptr;
            Cidr::Key client;
            std::time_t at = 0;
            unsigned repeats = 0;  // requests from it since its line
        };
        std::array<Seen, 32> seen{};
        std::time_t report_second = 0;
        unsigned report_in_second = 0;
        unsigned report_unnamed = 0;
    } access_log;
};

}  // namespace agensio
