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

// Backup archives and database dumps found under a document root (health, archives_in_root).
struct ArchivesInRoot {
    std::size_t seen = 0;
    std::size_t count = 0;
    std::string example;
    std::uint64_t example_bytes = 0;
};
ArchivesInRoot archives_in_root(const SiteConfig& site, std::size_t budget);

// What one php-fpm pool keeps resident: its child processes and their memory (Linux /proc).
struct PoolResidency {
    unsigned processes = 0;
    unsigned long long rss_kb = 0, anon_kb = 0;
};
PoolResidency pool_residency(const std::string& pool);

struct Finding {
    std::string severity;  // error | warn | info
    std::string code;
    std::string site;      // "" when server-wide
    std::string message;
    std::string fix;       // what to do, "" when nothing
};
// The refusals at the workers' connection ceiling since start (Server::refusal_report),
// merged over the workers, for one health finding whose fix follows from their shape
// (2026-10-02: an agent must tell an attack from a low ceiling from stuck clients).
struct RefusalReport {
    std::uint64_t refused = 0, connections = 0, idle = 0, ceiling = 0;
    unsigned workers = 0;
    double first_s_ago = 0, last_s_ago = 0;
    std::vector<std::pair<std::string, std::uint64_t>> addresses;  // most refused first
    bool more_addresses = false;                                   // a worker's sample was partial
    std::vector<std::pair<std::string, std::uint64_t>> listeners;  // refusals per listener address
};
// "3 s", "12 min", "2 h", "3 d", for a message.
std::string ago_text(double seconds);
// One address behind most refusals: the firewall's job. Workers full of connections idle
// for 2 s or more: slow or stuck clients. Else legitimate load wanting a higher limit.
Finding refusal_finding(const RefusalReport& r);
// What an administrator should look at: certificates, redirects, port 80 for ACME,
// recent errors, pending restart, root, shared accounts, stale pools.
std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now);
// `extra`: findings the caller gathered where this process cannot look (the sites'
// environment files, through the helper), appended as they are.
json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now, const std::vector<Finding>& extra = {});
// appenv::inspect's answer as findings: a file a task would refuse (warn), one the next task
// tightens (info), a deleted site's file (info), or that the check could not run.
std::vector<Finding> env_findings(const json::Value& inspected);
// The helper's app_check as findings, per site: no unit (info, with site_service_unit),
// stopped, failed or restarting (warn, with site_service_logs and the root line); nothing
// when active, and nothing at all for a reply that is not ok (a busy helper).
std::vector<Finding> service_findings(const json::Value& check);

// "a=1&b=x%20y" lookups on a request target's query; "" when absent.
std::string query_value(std::string_view target, std::string_view key);

}  // namespace agensio::control
