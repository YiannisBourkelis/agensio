// The read-only control commands (F2) as pure functions over a Config and the files on
// disk: what the server, `agensio ctl`, the MCP bridge and the unit tests all call. No
// server internals here; the server passes its configurations in.
#pragma once

#include <ctime>
#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "core/site_notices.hpp"
#include "control/loglines.hpp"
#include "services/json.hpp"
#include "services/php_runtimes.hpp"

namespace agensio {
struct HostFacts;
}

namespace agensio::control {

// ---- logs ----

struct LogQuery {
    std::string site;              // a server_name, or "" for every site plus the error log
    std::time_t since = 0;         // lines at or after this time (0 = no bound)
    std::string level = "warn";    // error log: "error" | "warn" (error+warn) | "info" (everything)
    int status_min = 500;          // access logs: lines with this status or above (0 = all)
    std::size_t limit = 200;       // lines returned (the newest)
    std::size_t max_bytes = 2 * 1024 * 1024;  // read per file, from the end
    // The rotated files read on when `since` reaches past the current file's first line (the
    // alpha.101 report): FILE.1 to FILE.N, plain or .gz as logrotate leaves them; `inflate` false
    // reads no .gz (health, on the worker).
    int rotated_files = 14;
    bool inflate = true;
};

// What one log's reading covered: complete when `since` (or the line limit) was reached, else from
// when its lines go back (`oldest`) and why no further (`reason`); the rotated files read.
struct LogCoverage {
    bool complete = true;
    std::time_t oldest = 0;
    std::string reason;
    std::vector<std::string> rotated;
};

// The newest matching lines of `file` and of its rotated files, chronological. `truncated` when
// the byte cap of the current file hit.
LogCoverage scan_log(const std::filesystem::path& file, std::string_view source, const LogQuery& q,
                     std::vector<LogLine>& out, bool& truncated);
json::Value logs(const Config& cfg, const LogQuery& q);
// The access-log status filter of a logs query: "all", a class ("5xx", "4xx": that class and
// above), or a status ("404": that status and above); "" leaves `min` as it is. False for a
// value it does not understand, `min` unchanged.
bool status_filter(std::string_view text, int& min);

// ---- sites and certificates ----

struct CertificateState {
    bool present = false;
    bool placeholder = false;
    std::string issuer;
    std::vector<std::string> names;
    std::time_t not_before = 0;
    std::time_t not_after = 0;
    long days_left = 0;
    std::string fingerprint;  // SHA-256 of the DER: tells the file on disk from what is served
    std::string error;        // why it could not be read
};
CertificateState certificate_state(const TlsConfig& tls, std::time_t now);  // the file on disk

// What health knows of the running server beyond its configuration (the certificate work, step
// T2): the certificate each pair serves, read from memory, and the ACME manager's last failed
// order per certificate.
struct TlsFacts {
    std::map<std::string, CertificateState> served;                              // by "cert\nkey"
    std::map<std::string, std::pair<std::time_t, std::string>> acme_failures;  // by cert path: when, the error
    std::map<std::string, std::string> load_errors;  // by "cert\nkey": why its files did not load the last time (T3)
    // By site name: the HSTS its application sent while the site had no hsts line, and when
    // (core/site_notices.hpp, docs/redirects.md 4.2): hsts_from_application instead of hsts_suggested.
    std::map<std::string, std::pair<std::string, std::time_t>> application_hsts;
    // The watch of the certificate files (step T3, docs/tls.md 3.3): how often it runs, how many
    // times it has, and how long ago it last did (since the start before its first run), on the
    // steady clock; interval 0: no watch (a build without TLS). certificate_watch_stalled.
    struct Watch {
        long interval_s = 0;
        unsigned long runs = 0;
        long since_s = 0;
    } watch;
};

// With `tls` each TLS site's `tls` carries `served`: the certificate in memory (step T2).
json::Value sites(const Config& cfg, std::time_t now, const TlsFacts* tls = nullptr);
// The site whose server_name list contains `name` (case-insensitive), or null.
const SiteConfig* find_site(const Config& cfg, std::string_view name);
// `server_name = ["*"]` or `default = true`: answers every Host on its listener.
bool is_catch_all(const SiteConfig& s);
bool listener_has_catch_all(const Config& cfg, const std::string& address);
json::Value site(const Config& cfg, const SiteConfig& s, std::time_t now, const TlsFacts* tls = nullptr);
// What the load noted about a site's path redirects (docs/redirects.md 8: a chain, a soft 404, a rule
// answering before a protection, one over certificate validation) as {code, text} objects: site_show,
// path_check's preview and the answer of the change that made them give the same list.
json::Value redirect_notes_json(const SiteConfig& s);
// What the load noted about a site's response header rules (a CSP set over an application's own,
// X-XSS-Protection turned on), as {code, text}: site_show, path_check's preview and the change's answer.
json::Value header_notes_json(const SiteConfig& s);
// Access by client address (docs/configuration.md 19): what the site's rules decide for one
// path and one client address, with the deciding rule and a one-line summary. `error` set
// (and nothing answered) when the path or the address does not parse.
json::Value access_check(const Config& cfg, const SiteConfig& site, std::string_view path, std::string_view address, std::string& error);
// What a site does with one GET for `path` and why (refuse, location, refusals by name,
// try_files, index, redirects; the file, script or origin), as the worker would decide it.
json::Value path_check(const Config& cfg, const SiteConfig& site, std::string_view path, std::string& error);

// ---- validation and health ----

// Loads `path` again and runs the hosting rules; never throws.
// `current`: the configuration being served, so a site file set aside keeps its running version
// as a reload would (design section 26).
json::Value validate(const std::filesystem::path& path, const Config& running, const Config* current = nullptr);
// The restart-only settings that differ between the file on disk and the running server.
std::vector<std::string> restart_needed(const Config& fresh, const Config& running);
// Whether a PHP version's php-fpm.conf leaves process_control_timeout unset, without which its
// reload kills children mid-request (`site-create` and `agensio pools` reload). True when the
// file exists and the setting is absent or 0.
bool php_fpm_hard_reload(const php::Runtime& r);

// Backup archives and database dumps found under a document root (health, archives_in_root). A
// static site or one without app is searched for dumps only (dumps_only): it serves everything as it
// stands, so an archive there is a download offered on purpose. What the site's public_archives
// names is counted apart, in listed_public.
struct ArchivesInRoot {
    struct Found {
        std::string path;    // the file
        std::string served;  // its path as served from the root, the form public_archives and refuse take
        std::uint64_t bytes = 0;
    };
    static constexpr std::size_t kKept = 50;  // the files kept, which health judges one by one
    std::size_t seen = 0;
    std::size_t count = 0;  // found and not listed in public_archives
    std::size_t listed_public = 0;
    bool dumps_only = false;
    std::vector<Found> files;            // the first kKept of count
    std::vector<std::string> unslashed;  // entries that name a directory without the "/" that covers what is below it
};
// What a request for a found file gets today, by the decision path_check explains (2026-10-17):
// served to anyone; kept by the owner's own rule (a refuse pattern, a managed site's rules, a location
// of the site file or of root additions); kept only by the preset's defaults; served only to some
// (an access rule, a password).
enum class ArchiveExposure { served, owner, preset, restricted };
ArchiveExposure archive_exposure(const Config& cfg, const SiteConfig& site, const std::string& served);
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
// What requests saw that only health names (core/site_notices.hpp; docs/redirects.md 2.4, 4.1),
// judged against the running configuration: proxy_scheme_missing seen in the last hour on a site
// that still redirects plain HTTP and still trusts that proxy; hsts_narrows_application while the
// application's value is still stronger than the site's hsts.
std::vector<Finding> notice_findings(const Config& cfg, const std::vector<SiteNotice>& notices, std::time_t now);
// What this binary can serve (2026-10-22, the owner's request): built with TLS and with QUIC, on
// Linux, and the OpenSSL loaded at run time (OpenSSL_version_num(), OpenSSL_version()); build_facts()
// is this process's, the unit tests describe others.
struct BuildFacts {
    bool tls = false;
    bool quic = false;
    bool linux_os = false;
    unsigned long openssl_number = 0;  // 0 without TLS
    std::string openssl;               // "OpenSSL 3.5.7 30 Sep 2026", "" without TLS
};
BuildFacts build_facts();
// status's `protocols`: what this build serves at all (h1, h2c, h2, h3), the OpenSSL loaded, and,
// without HTTP/3, why and what would give it (each listener's own protocols are under `listeners`).
json::Value protocols_json(const BuildFacts& b);
// health's http3_package_available (information): a build without HTTP/3 on a system whose OpenSSL
// has the QUIC API (3.5.1 or later), a TLS site configured: the Debian 12 package on Debian 13, say.
// Nothing on a system without the API (Debian 12, Ubuntu 22.04 and 24.04: no HTTP/3 there by decision).
std::optional<Finding> http3_finding(const BuildFacts& b, const Config& cfg);
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
// With `tls` (the running server's) the certificates are judged as served, else as on disk.
std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now, const TlsFacts* tls = nullptr);
// Files root loads or runs that agensio renders (the alpha.94 report: written with a shell's `>` under a
// root umask of 0002 they were 0664): each one its group or anyone may write, a warn or an error, with
// the chmod that fixes it. `facts.stat` decides; a missing file is nothing to say.
std::vector<Finding> root_file_findings(const std::vector<std::string>& files, const HostFacts& facts);
// `extra`: findings the caller gathered where this process cannot look (the sites'
// environment files, through the helper), appended as they are.
json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now, const std::vector<Finding>& extra = {},
                   const TlsFacts* tls = nullptr);
// appenv::inspect's answer as findings: a file a task would refuse (warn), one the next task
// tightens (info), a deleted site's file (info), or that the check could not run.
std::vector<Finding> env_findings(const json::Value& inspected);
// Passwords ([[site.auth]], 2026-10-09, docs/configuration.md 19b): for every users file a rule
// reads, what the next load would say of it (auth_users_unloadable, an error: the site's file is set
// aside, or for a site in the main file a reload is refused and a restart does not start, while the
// running server keeps its users), whether anyone can log
// in (auth_no_valid_user: every user locked or expired), who can no longer (auth_users_expired);
// a rule asked over plain HTTP on a listener the network reaches (auth_plain_http); and the users
// files under <config dir>/auth/ no site owns (auth_users_orphan). health_findings includes them.
std::vector<Finding> auth_findings(const Config& cfg, std::time_t now);
// The helper's app_check as findings, per site: no unit (info, with site_service_unit),
// stopped, failed or restarting (warn, with site_service_logs and the root line); nothing
// when active, and nothing at all for a reply that is not ok (a busy helper).
std::vector<Finding> service_findings(const json::Value& check);

// "a=1&b=x%20y" lookups on a request target's query; "" when absent.
std::string query_value(std::string_view target, std::string_view key);

}  // namespace agensio::control
