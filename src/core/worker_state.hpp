// Per-worker scratch state. One instance per worker thread, never shared.
#pragma once

#include <array>
#include <ctime>
#include <string>

#include "cache.hpp"
#include "http_date.hpp"
#include "net/cidr.hpp"
#include "services/log.hpp"

namespace agensio {

struct WorkerState {
    DateCache date;
    LocalIndex local;
    std::time_t now = 0;      // wall clock read once per request by the connection
    std::string server_line;  // "Server: agensio\r\n" or empty (set by Server)
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
