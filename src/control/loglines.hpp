// The log lines the control plane reads back (agensio ctl logs, MCP logs_query): one line of the
// error log, the combined or the JSON access log, parsed by hand. Pure functions over text that
// clients chose (a request line, a User-Agent), so they have a fuzz target of their own
// (tests/fuzz/fuzz_log_line.cpp); moved out of control/commands.* for it (alpha.72).
#pragma once

#include <ctime>
#include <string>
#include <string_view>

namespace agensio::control {

struct LogLine {
    std::time_t time = 0;
    std::string source;  // "error", "access" (the server-wide access log) or a site's name (its own log)
    std::string level;   // error | warn | info, or "" for access lines
    int status = 0;      // access lines
    std::string host;    // JSON access lines: the Host asked for; "" for combined lines, which carry none
    std::string text;    // the line without its newline
};

// Parses one line of any of the three formats (error log, combined, JSON access log).
// False when the line is none of them.
bool parse_log_line(std::string_view line, LogLine& out);

// The line as valid text: every byte that is not part of a well-formed UTF-8 sequence becomes
// the text \xHH (what the access log writes since alpha.43; older files and the error log may
// still hold raw bytes, 2026-10-02 report).
std::string utf8_escaped(std::string_view line);

// "3h", "45m", "2d", "90" (seconds) or "2026-09-18T10:00:00" (local time) into seconds
// before `now` / an absolute time. False when unreadable.
bool parse_since(std::string_view text, std::time_t now, std::time_t& out);

}  // namespace agensio::control
