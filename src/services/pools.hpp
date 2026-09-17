// Generated php-fpm pools (C3b, docs/design-per-site-users.md): one pool per site user,
// rendered from the site's `user` and `php = { ... }` keys, written by `agensio pools`
// into the distro's pool directory for its php-fpm master to pick up on reload. agensio
// never signals php-fpm; the caller reloads it when write_pools() reports a change.
#pragma once

#include <filesystem>
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

// Writes the pool files into `out_dir`, creates each user's state directories, removes
// generated files whose user is gone, and prints what it did. Returns 0 when nothing
// changed, 3 when files were written or removed (reload php-fpm), 1 on error.
int write_pools(const Config& cfg, const std::filesystem::path& out_dir, bool dry_run, std::ostream& out);

}  // namespace agensio
