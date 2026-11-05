// A site's access log kept fewer days than logrotate keeps (`access_log_keep_days`, 0.1.0-alpha.128,
// docs/configuration.md 8b): the rotated files of the site's own access log that hold a line older
// than its days are deleted, hourly. logrotate takes one `rotate` per file and refuses a second entry
// for a file its shipped glob already names, so the days cannot be a logrotate setting per site.
//
// Only logrotate's numbered rotations (packaging/agensio.logrotate: nodateext, delaycompress):
// NAME.1, NAME.2.gz and so on, never the current file, which logrotate rotates daily, nor a name it
// gave by date. A file is judged by the oldest of the lines at its start (the workers' buffers
// interleave a little), inflated for .gz; one whose start does not read (a build without zlib, a
// format of its own) by its time of change less a day. The log's directory below <log directory>/sites/
// may be root's (the start makes it, still root, for a log named before the first start), so with the
// provisioning helper the deletes are its (`log_expire`, the sites and days from the configuration on
// disk, nothing from the request); the server's account owns the files themselves and could empty them
// anyway (docs/security-control-plane.md row 58). Without the helper the server deletes what its account can.
#pragma once

#include <ctime>
#include <string>
#include <string_view>
#include <vector>

#include "services/json.hpp"

namespace agensio {
struct Config;
}

namespace agensio::log_retention {

struct Keep {
    std::string site;  // its first name
    std::string log;   // the site's access_log: absolute, below <log directory>/sites/, *.log
    int days = 0;
    std::string root;  // the log directory (the main file's [log] access), where the walk starts
};

// The sites with access_log_keep_days whose log is where the loader requires it (checked again here:
// the helper acts as root on what this returns).
std::vector<Keep> keeps_of(const Config& cfg);

// logrotate's numbered rotation of `base`: "access.log.1", "access.log.12.gz"; never `base` itself.
bool rotated_name(std::string_view base, std::string_view name) noexcept;

// The oldest time of the access lines in `text` (a file's start, so a partial last line is skipped);
// 0 when none parses.
std::time_t oldest_line(std::string_view text);

// For each keep, the rotated files holding a line older than its days before `now`, deleted: the
// log's directory reached from the log directory (resolved as the main file names it) one component
// at a time without following a link, since the log directory is the server account's and a link it
// planted there (sites -> /var/log) must not send root's deletes elsewhere; each entry a regular file
// reached without following one. {"ok": true, "removed": [paths], "failed": [{"site", "log", "error"}]}.
json::Value expire(const std::vector<Keep>& keeps, std::time_t now);

}  // namespace agensio::log_retention
