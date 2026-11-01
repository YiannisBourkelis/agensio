// What a change to a site's files replaced or removed, kept for an undo (F12, docs/design-site-
// operations.md 27.6): <sites_root>/.history/<domain>/<version>/ with `item` (the file or tree as it
// was) and `meta` (the path, its kind, bytes, why, when). A file a write replaces is hard-linked there
// before the write renames the new one over it, so nothing is copied and the site never misses the
// file; what a delete or a move over it removes is renamed there whole, a directory of any size
// included. The directories are the holder's alone (root's 0700 with the helper, else the server
// account's), never served; the site's account cannot reach them. Every path on the site's side is
// reached by the install's walk, each component O_NOFOLLOW and the site account's, so a symlink
// planted in the tree never sends a rename elsewhere. Kept `versions` per path for `days`
// ([control] file_history).
#pragma once

#include <sys/types.h>

#include <ctime>
#include <string>
#include <string_view>

#include "services/json.hpp"

namespace agensio::history {

struct Settings {
    int versions = 5;  // 0: no history (a delete removes)
    int days = 30;
};

struct Place {
    std::string hist_dir;   // <sites_root>/.history
    uid_t hist_owner = 0;   // who must own it: root with the helper, else the server's account
    std::string domain;     // the site's first name: its own directory in the history
    std::string site_root;  // the site's directory
    uid_t site_uid = 0;     // every component of the walk is this account's
    Settings settings;
};

std::string dir_of(const std::string& sites_root);
// YYYYMMDD-HHMMSS-xxxxxx: a version's name.
bool valid_version(std::string_view v) noexcept;

// Keeps what is at `rel` before a change: `move` takes it out of the site (a delete, a destination a
// move replaces), else a regular file is linked and stays. {"ok", "entry" ("" when nothing is there),
// "kind", "bytes"} or {"ok": false, "error"}. Nothing older goes yet: a change that is then refused
// undoes the keep and must find every version as it was.
json::Value keep(const Place& p, const std::string& rel, bool move, const std::string& reason);
// Once the change succeeded: the versions of `rel` beyond `versions`, oldest first, go.
void prune(const Place& p, const std::string& rel);
// Undoes a keep when the change failed: a moved item goes back to `rel`, a linked one is dropped.
void undo(const Place& p, const std::string& rel, const std::string& entry, bool moved);
// The versions of `rel`, newest first: {"ok", "path", "versions": [{"version", "kept_at", "kind",
// "bytes", "reason"}]}.
json::Value list(const Place& p, const std::string& rel);
// Puts `version` of `rel` back: the place must be empty unless `overwrite`, which keeps what is
// there first. A dry run says what would happen.
json::Value restore(const Place& p, const std::string& rel, const std::string& version, bool overwrite, bool dry_run);
// Every site's versions older than `days`: removed. {"ok", "removed"}.
json::Value expire(const std::string& hist_dir, uid_t owner, const Settings& s, std::time_t now);

}  // namespace agensio::history
