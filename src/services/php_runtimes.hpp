// The PHP versions installed on the host (docs/design-php-versions.md 4): each a runtime agensio can
// give pools to, its own php-fpm master with its configuration, pool directory and service unit.
// Discovered from the distributions' layouts, or named by root in [php.runtimes."X.Y"]; their facts
// read by running their own programs with fixed arguments, never on a worker (a few of them take
// tens of milliseconds, and php-fpm's configuration test needs root: the provisioning helper's).
#pragma once

#include <ctime>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {
struct Config;
}

namespace agensio::php {

struct Runtime {
    std::string version;  // major.minor, "8.4"
    std::string fpm;      // the FPM binary, "/usr/sbin/php-fpm8.4"
    std::string conf;     // its php-fpm.conf
    std::string pools;    // its pool directory
    std::string unit;     // its service ("php8.4-fpm"); "" when not one systemd starts
    std::string cli;      // its command-line binary, for site tasks; "" when none
    bool configured = false;  // named by root in [php.runtimes], not discovered
};

// What discovery reads (injectable, so the unit tests describe a machine).
struct Fs {
    std::function<bool(const std::string& path)> is_file;
    std::function<bool(const std::string& path)> is_dir;
    std::function<std::vector<std::string>(const std::string& dir)> list;  // the entries' names
};
Fs system_fs();

// Every runtime, oldest version first: Debian and Ubuntu (/etc/php/X.Y/fpm), RHEL's Remi
// (/etc/opt/remi/phpXY), Alpine (/etc/phpXY), Homebrew (<prefix>/etc/php/X.Y), the base system's
// one php-fpm (/etc/php-fpm.conf, its version read from the binary later), and root's
// [php.runtimes], which replaces a discovered runtime of the same version. A layout counts only
// with its FPM binary and its configuration file both present.
std::vector<Runtime> discover(const Config& cfg, const Fs& fs);
const Runtime* find(const std::vector<Runtime>& runtimes, std::string_view version);

// A runtime's facts, as its own programs report them.
struct Facts {
    std::string exact;                  // "8.4.24", from php-fpm -v
    std::vector<std::string> modules;   // the extensions the FPM side loads, lower case, sorted (php-fpm -m)
    bool tested = false;                // php-fpm -tt ran (it needs root)
    bool config_ok = false;
    std::string config_error;           // its ERROR lines when the test failed
    std::string control_timeout;        // process_control_timeout as php-fpm reads it ("0s", "10s"); "" unknown
    bool opcache = false;               // opcache.enable for the FPM side (php-fpm -i)
    std::string opcache_memory;         // opcache.memory_consumption, in MB
    bool validate_permission = false;   // opcache.validate_permission
    std::string unit_active;            // systemd's ActiveState ("active", "inactive", "failed"); "" unknown
    std::string unit_enabled;           // UnitFileState ("enabled", "disabled"); "" unknown
    std::string error;                  // what could not be run
};
// Runs a program by absolute path with fixed arguments: its exit status, its output (both streams).
using Exec = std::function<int(const std::string& path, const std::vector<std::string>& args, std::string& out)>;
// `as_root` runs php-fpm's configuration test too; `systemctl`, when found, the unit's state.
Facts gather(const Runtime& r, const Exec& exec, bool as_root, const std::string& systemctl);
Exec system_exec();  // fork and execve, safe in a threaded process; output capped at 512 KB (php-fpm -i)

// The pieces of gather, for the unit tests.
std::string parse_version(std::string_view v_output);                      // "PHP 8.4.24 (fpm-fcgi) ..." -> "8.4.24"
std::vector<std::string> parse_modules(std::string_view m_output);         // both sections, lower case, sorted, once each
std::string ini_value(std::string_view i_output, std::string_view name);   // "name => local => master": the local value
void parse_fpm_test(std::string_view tt_output, Facts& f);                 // process_control_timeout, the result, ERROR lines

// PHP's releases (php.net/supported-versions): active support, then security fixes until, both
// the last day (YYYY-MM-DD). Updated with each PHP release.
struct Release {
    const char* version;
    const char* active_until;
    const char* security_until;
};
const std::vector<Release>& releases();
// "active", "security" (fixes for security only), "eol" (none), or "unknown" for a version the
// table does not list yet (a newer one: treated as supported).
std::string support_status(std::string_view version, std::time_t now);
const Release* release(std::string_view version);

// The versions of the table the system's repositories can install that are not installed: on
// Debian and Ubuntu `apt-cache policy phpX.Y-fpm` (read-only), elsewhere none known.
std::vector<std::string> installable(const Exec& exec, const std::vector<Runtime>& installed, const std::string& apt_cache);
// What a candidate line of `apt-cache policy` says: the candidate version, "" when none.
std::string apt_candidate(std::string_view policy_output);

}  // namespace agensio::php
