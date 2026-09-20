// The read-only control commands (F2) as pure functions over a Config and the files on
// disk: what the server, `agensio ctl`, the MCP bridge and the unit tests all call. No
// server internals here; the server passes its configurations in.
#pragma once

#include <ctime>
#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "services/json.hpp"

namespace agensio::control {

// ---- logs ----

struct LogQuery {
    std::string site;              // a server_name, or "" for every site plus the error log
    std::time_t since = 0;         // lines at or after this time (0 = no bound)
    std::string level = "warn";    // error log: "error" | "warn" (error+warn) | "info" (everything)
    int status_min = 500;          // access logs: lines with this status or above (0 = all)
    std::size_t limit = 200;       // lines returned (the newest)
    std::size_t max_bytes = 2 * 1024 * 1024;  // read per file, from the end
};

struct LogLine {
    std::time_t time = 0;
    std::string source;  // "error" or the site name
    std::string level;   // error | warn | info, or "" for access lines
    int status = 0;      // access lines
    std::string text;    // the line without its newline
};

// Parses one line of any of the three formats (error log, combined, JSON access log).
// False when the line is none of them.
bool parse_log_line(std::string_view line, LogLine& out);
// "3h", "45m", "2d", "90" (seconds) or "2026-09-18T10:00:00" (local time) into seconds
// before `now` / an absolute time. False when unreadable.
bool parse_since(std::string_view text, std::time_t now, std::time_t& out);
// The newest matching lines of `file`, chronological. `truncated` when the byte cap hit.
void scan_log(const std::filesystem::path& file, std::string_view source, const LogQuery& q,
              std::vector<LogLine>& out, bool& truncated);
json::Value logs(const Config& cfg, const LogQuery& q);

// ---- sites and certificates ----

struct CertificateState {
    bool present = false;
    bool placeholder = false;
    std::string issuer;
    std::vector<std::string> names;
    std::time_t not_after = 0;
    long days_left = 0;
    std::string error;  // why it could not be read
};
CertificateState certificate_state(const TlsConfig& tls, std::time_t now);

json::Value sites(const Config& cfg, std::time_t now);
// The site whose server_name list contains `name` (case-insensitive), or null.
const SiteConfig* find_site(const Config& cfg, std::string_view name);
// `server_name = ["*"]` or `default = true`: answers every Host on its listener.
bool is_catch_all(const SiteConfig& s);
bool listener_has_catch_all(const Config& cfg, const std::string& address);
json::Value site(const Config& cfg, const SiteConfig& s, std::time_t now);

// ---- validation and health ----

// Loads `path` again and runs the hosting rules; never throws.
json::Value validate(const std::filesystem::path& path, const Config& running);
// The restart-only settings that differ between the file on disk and the running server.
std::vector<std::string> restart_needed(const Config& fresh, const Config& running);
// php-fpm's global file next to the pool directory (Debian: fpm/php-fpm.conf; RHEL:
// /etc/php-fpm.conf), and whether it sets process_control_timeout, without which a
// reload kills children mid-request (`site-create` and `agensio pools` reload). True
// when the file exists and the setting is absent or 0; `file` names it.
bool php_fpm_hard_reload(const Config& cfg, std::string& file);

struct Finding {
    std::string severity;  // error | warn | info
    std::string code;
    std::string site;      // "" when server-wide
    std::string message;
    std::string fix;       // what to do, "" when nothing
};
// What an administrator should look at: certificates, redirects, port 80 for ACME,
// recent errors, pending restart, root, shared accounts, stale pools.
std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now);
json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now);

// "a=1&b=x%20y" lookups on a request target's query; "" when absent.
std::string query_value(std::string_view target, std::string_view key);

}  // namespace agensio::control
