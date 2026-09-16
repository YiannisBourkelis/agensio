// Per-worker scratch state. One instance per worker thread, never shared.
#pragma once

#include <ctime>
#include <string>

#include "cache.hpp"
#include "http_date.hpp"

namespace agensio {

struct WorkerState {
    DateCache date;
    LocalIndex local;
    std::time_t now = 0;      // wall clock read once per request by the connection
    std::string server_line;  // "Server: agensio\r\n" or empty (set by Server)
    std::string prefix200;    // "HTTP/1.1 200 OK\r\nServer: ..\r\nDate: ..\r\n", refreshed per second
    std::time_t prefix200_time = 0;
    std::string path;     // normalised request path
    std::string fs_path;  // filesystem path being served
};

}  // namespace agensio
