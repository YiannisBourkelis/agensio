// Generated php-fpm pools (C3b, docs/design-per-site-users.md): one pool per site with a user
// (docs/design-php-versions.md 5), rendered from the site's `user` and `php = { ... }` keys, written
// by `agensio pools` into the pool directory of the site's PHP version for that version's php-fpm
// master to pick up on reload. Writing never signals php-fpm; the caller reloads the versions
// write_pools() reports changed.
#pragma once

#include <filesystem>
#include <functional>
#include <ostream>
#include <string>
#include <vector>

#include "config.hpp"
#include "services/php_requirements.hpp"
#include "services/php_runtimes.hpp"

namespace agensio {

// The pool file text for a site with a generated pool. `agensio_group` is the group the
// socket grants access to (server.group, or the process's group).
std::string render_pool(const Config& cfg, const SiteConfig& site, const std::string& agensio_group);

struct GeneratedPool {
    std::string name;  // "agensio-<user>-<8 hex>", the file is <name>.conf
    std::string site;  // the site's first name
    std::string user;
    std::string group;
    std::string state_dir;  // <state_dir>/<user>/php/<domain>
    std::string version;    // whose pool directory holds it
    std::string socket;     // where it listens
    std::string text;
};

// One entry per site with a generated pool.
std::vector<GeneratedPool> generated_pools(const Config& cfg, const std::string& agensio_group);

// The process's group name, or "" when unknown (Windows).
std::string current_group_name();

// The runtime that runs a site's generated pool, or null: no version, or none installed by that name.
const php::Runtime* pool_runtime(const std::vector<php::Runtime>& runtimes, const PhpPool& pool);

// ---- ownership rules (C3b-2) ----
// What the checks look at, behind functions so the unit tests can describe a machine
// without owning files as other users. All paths absolute.
struct FileFacts {
    bool is_dir = false;
    unsigned uid = 0;
    unsigned gid = 0;
    unsigned mode = 0;  // permission bits only
};
struct HostFacts {
    std::function<bool(const std::string& path, FileFacts& out)> stat;   // false: does not exist
    std::function<bool(const std::string& name, unsigned& uid, unsigned& gid)> user;  // gid: primary group
    std::function<bool(const std::string& name, unsigned& gid)> group;
    std::function<std::string(unsigned gid)> group_name;  // "" when unknown
    std::function<std::string(unsigned uid)> user_name;   // "" when unknown (may be unset in tests)
    // The groups `name` is in, `gid` included, as initgroups gives them (may be unset in tests:
    // then `gid` alone).
    std::function<std::vector<unsigned>(const std::string& name, unsigned gid)> groups;
};
HostFacts system_facts();

// The account and group the server serves as, the one input every rule shares: `server.user`
// / `server.group` when set, else the primary group of `server.user`, else the process's
// own. Computed here and nowhere else, so `-t` run as root, the running server after its
// privilege drop, `agensio pools` and the health check all agree (2026-09-19: they did not,
// and no socket ownership satisfied all of them).
struct ServerAccount {
    std::string user;   // "" when server.user is not set (the process's own account)
    std::string group;
    unsigned uid = 0;
    unsigned gid = 0;
    bool known = false;  // the group resolved
};
ServerAccount server_account(const Config& cfg, const HostFacts& facts);

// The rules of docs/design-per-site-users.md for every site with `user`: accounts exist;
// roots and open_basedir entries owned by the user (or root) and not writable by others;
// secrets (.env, wp-config.php, .git, ...) not readable by others; the pool socket owned
// by the user and agensio's group, mode 0660 at most; no two users sharing a root, socket,
// state directory or log; logs not readable by other users. One message per failure,
// with the path and what was expected; empty when everything is in order.
std::vector<std::string> check_hosting(const Config& cfg, const HostFacts& facts);
// The same rules with the sites each concerns (indexes into cfg.sites): none for the server's
// own account, one for a site's own paths, two for what two users must not share.
struct HostingError {
    std::string message;
    std::vector<std::size_t> sites;
    // A credential file readable by others or by a group not the site's: its path and what stat
    // gave; "" for every other rule. isolate_hosting sets no site aside for it (2026-10-22).
    std::string credential;
    FileFacts facts;
};
std::vector<HostingError> hosting_errors(const Config& cfg, const HostFacts& facts);
// The hosting rules applied the way site files load (docs/design-site-operations.md 26, step
// C2): a site that breaks one is set aside with its file (set_aside_until_clean), the other
// sites load; with `running` (a reload) a served site keeps its running version only when that
// version passes every rule now, so a root opened to others takes the site down at the next
// reload while an edit that breaks a rule keeps the version that passes. A credential file
// readable by others sets nothing aside: it goes into cfg.exposed_credentials (2026-10-22).
// Returns what refuses the whole configuration: the server's own account, and a rule only the
// main file's sites break (the main file is all or nothing).
std::vector<std::string> isolate_hosting(Config& cfg, const HostFacts& facts, const Config* running);

// Whether the account the server runs as after the start can read `path` (the certificate work,
// step T1): with server.user set, the start reads the certificates as root and every reload after
// that as this account (its group and supplementary groups, as initgroups gives them), through
// every directory on the way, the path as named and where its links lead. "" when it can, or
// when nothing is dropped; else why not, and `fix` gets root's commands.
std::string server_read_problem(const Config& cfg, const HostFacts& facts, const std::string& path, std::string& fix);
struct TlsReadProblem {
    std::size_t site;  // in cfg.sites
    std::string message, fix;
};
// Every certificate and key of a TLS site the server's account could not read on a reload.
std::vector<TlsReadProblem> tls_read_problems(const Config& cfg, const HostFacts& facts);

// The files and directories of a site that hold credentials, absolute: the preset's
// secrets (`preset_secrets`) under the served root, `.env` and `.git`, and for Laravel
// the project's .env, config/, storage/ and .git. One list for the hosting rule and for
// the writers (site-install, site-copy), so the two can never disagree about a file.
std::vector<std::string> secret_paths(const SiteConfig& site);
// The rule itself: a secret may be read by its owner and by the site's own group, never
// by others or by another group (the server's). Pure.
inline bool secret_exposed(unsigned mode, unsigned gid, unsigned site_gid) noexcept {
    return (mode & 0004) || ((mode & 0040) && gid != site_gid);
}
// The mode the writers and the task sweep give a credential directory (.git, storage/):
// nothing for others and no read or write for its group, which is what the rule above
// asks; the set-gid bit and the group's execute stay, so the server may pass through
// (Laravel's public/storage link) but never list it. A 2750 directory becomes 2710.
constexpr unsigned secret_dir_mode(unsigned mode) noexcept { return (mode & 02010u) | 0700u; }

// Makes every runtime's pool directory hold exactly the pools the configuration assigns to it
// (docs/design-php-versions.md 5): writes each site's file into its version's directory, creates the
// site's state directories, removes every other file agensio generated there, and prints what it
// did. With `test` (php-fpm's own configuration test, which needs root), each directory that changed
// is tested and, when php-fpm refuses it, put back as it was. `rc` is 0 when nothing changed, 3 when
// files were written or removed, 1 when something could not be done (the rest is still done);
// `changed` names the versions to reload, those tested clean among them. `remove_others` false is
// the switch's up phase (docs/design-php-versions.md 6.1): the pools the configuration gives each
// version are written and nothing is removed, so the old pool of a site moving to another version
// keeps serving until agensio has switched.
struct PoolsOutcome {
    int rc = 0;
    std::vector<std::string> changed;
    std::vector<std::pair<std::string, std::string>> written;  // version and socket of each pool whose file was written
    struct Before {
        std::string version;
        std::filesystem::path file;
        std::string text;  // "" when the file did not exist
    };
    std::vector<Before> before;  // what each file written or removed held, for restore_pools
};
// "" when the runtime's configuration tests clean, else php-fpm's own message.
using PoolTest = std::function<std::string(const php::Runtime&)>;
PoolsOutcome write_pools(const Config& cfg, const std::vector<php::Runtime>& runtimes, bool dry_run, std::ostream& out, const PoolTest& test = {},
                         bool remove_others = true);
// Puts back what `o` changed in one version's directory: the up phase's socket that did not come up.
void restore_pools(const PoolsOutcome& o, const std::string& version, std::ostream& out);

// The switch around a reload (docs/design-php-versions.md 6, 6.1). A site of `fresh` whose generated
// pool listens on a socket no pool of `running` has: a new site (`from` ""), or one moving to another
// version or account (`moving`), whose new pool must come up before agensio sends it there.
struct PoolSwitch {
    std::string site, from, to;
    bool moving = false;
    std::string app;                // the site's preset, for its requirements
    std::vector<std::string> dirs;  // where its files declare their PHP (the project, the served root)
};
std::vector<PoolSwitch> pool_switches(const Config& running, const Config& fresh);
// What the preflight reads, behind functions so the unit tests describe a machine.
struct PreflightFacts {
    std::function<std::string(const php::Runtime&)> unit_state;  // systemd's ActiveState of its unit, "" unknown
    std::function<bool(const php::Runtime&)> hard_reload;         // its php-fpm.conf sets no process_control_timeout
    std::function<bool(const php::Runtime&)> running;             // its master runs (php::master_running), for a version without a unit
    // What the application needs (docs/design-php-versions.md 7): its preset's table (php::app_requirements
    // when unset), what the version's FPM loads, and what the site's installed release declares.
    std::function<const php::AppRequirements*(std::string_view app)> table;
    std::function<php::Loaded(const php::Runtime&)> loaded;
    std::function<php::Declared(const PoolSwitch&)> declared;
};
// Why a switch must not go ahead: the target version not installed; for a site moving between
// versions also its service or master not running (`run_as_root` the line), or a php-fpm.conf
// without process_control_timeout, whose reload cuts the requests in flight (`cut_requests`: the
// caller may go ahead anyway). A new site is asked only for the version: nothing of it serves yet.
// What the application needs of the target version comes as `requirements` (outside its range, a
// required extension missing: the caller may go ahead with ignore_requirements) or as a `warning`
// (a recommended extension, a version newer than it was tested on, an extension the current version
// loads and the target does not, and for a new site everything): said, never refused.
struct PreflightProblem {
    std::string site, message, run_as_root;
    bool cut_requests = false;
    bool requirements = false;
    bool warning = false;
};
std::vector<PreflightProblem> switch_preflight(const std::vector<PoolSwitch>& switches, const std::vector<php::Runtime>& runtimes, const PreflightFacts& facts);
// The versions that run generated pools while their service is neither active nor unknown (health's php_fpm_inactive).
std::vector<std::string> inactive_versions(const Config& cfg, const std::vector<php::Runtime>& runtimes,
                                           const std::function<std::string(const php::Runtime&)>& unit_state);
// php-fpm's test of a runtime's configuration, run as root (`php-fpm -t -y conf`): "" when clean.
std::string test_runtime(const php::Runtime& r, const php::Exec& exec);
// How a runtime's master rereads its pools: "systemctl reload php8.4-fpm", brew's restart, OpenRC's.
std::string reload_command(const php::Runtime& r);

}  // namespace agensio
