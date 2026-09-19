// Generated php-fpm pools (C3b, docs/design-per-site-users.md): one pool per site user,
// rendered from the site's `user` and `php = { ... }` keys, written by `agensio pools`
// into the distro's pool directory for its php-fpm master to pick up on reload. agensio
// never signals php-fpm; the caller reloads it when write_pools() reports a change.
#pragma once

#include <filesystem>
#include <functional>
#include <ostream>
#include <string>
#include <vector>

#include "config.hpp"

namespace agensio {

// The pool file text for a site with a generated pool. `agensio_group` is the group the
// socket grants access to (server.group, or the process's group).
std::string render_pool(const Config& cfg, const SiteConfig& site, const std::string& agensio_group);

struct GeneratedPool {
    std::string name;  // "agensio-<user>", the file is <name>.conf
    std::string user;
    std::string group;
    std::string state_dir;
    std::string text;
};

// One entry per user (the sites of a user were checked to agree at load time).
std::vector<GeneratedPool> generated_pools(const Config& cfg, const std::string& agensio_group);

// The process's group name, or "" when unknown (Windows).
std::string current_group_name();

// Where the distro's php-fpm reads pool files: server.pools if set, else detected for
// the given php version ("" = the newest installed). Empty when nothing was found.
std::filesystem::path pools_dir(const Config& cfg, const std::string& version);

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

// Writes the pool files into `out_dir`, creates each user's state directories, removes
// generated files whose user is gone, and prints what it did. Returns 0 when nothing
// changed, 3 when files were written or removed (reload php-fpm), 1 on error.
int write_pools(const Config& cfg, const std::filesystem::path& out_dir, bool dry_run, std::ostream& out);

}  // namespace agensio
