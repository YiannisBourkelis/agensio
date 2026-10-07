// Per-worker scratch state. One instance per worker thread, never shared.
#pragma once

#include <ctime>
#include <string>

#include "cache.hpp"
#include "http_date.hpp"
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
    // test, and the error log's limit of one access line a second per worker with the count of
    // those not written since (a scanner hammering a restricted path must not flood the log).
    std::string access_scratch;
    std::time_t access_logged = 0;
    unsigned access_skipped = 0;
};

}  // namespace agensio
