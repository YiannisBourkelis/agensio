// The site's files through the control plane (F12, docs/design-site-operations.md 3 and 27.6): one
// operation per call on one site's tree, as the site's own account, below the site's directory and
// nowhere else. Paths are cleaned relative paths (archive::clean_path), reached by the install's
// walk (every component opened O_NOFOLLOW and required to be the account's), the leaf never
// followed: a symlink anywhere on the way is refused, so a link the application planted cannot
// point a write outside the site. A write goes to a temporary name and is linked or renamed into
// place; its mode follows the directory (a credential file 0600); no set-uid or set-gid bit is ever
// made and nothing is ever run. Every change waits for a person's approval first (control/
// approvals.hpp); what a change replaces or removes is kept in the history (services/history.hpp)
// by the caller that holds it, root's helper or the server, before the account's part runs.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "services/history.hpp"
#include "services/json.hpp"

namespace agensio::files {

inline constexpr std::size_t kContentMax = 180 * 1024;  // a call's content, inside the control socket's 256 KB body
inline constexpr std::size_t kListMax = 2000;           // entries a listing returns
inline constexpr std::size_t kTreeMax = 10000;          // entries a recursive delete without history removes
inline constexpr std::uint64_t kDigestMax = 64ull << 20;  // files hashed whole for sha256

struct Op {
    std::string action;     // list | read | write | edit | mkdir | move | delete | history | restore
    std::string site_root;  // the site's directory (project_root, else root), absolute
    std::string path;       // cleaned, relative; "" only for list (the root itself)
    std::string to;         // move: the destination
    std::string content;    // write: the bytes
    std::string old_text, new_text;  // edit: old occurs exactly once
    std::string if_sha256;  // write, edit, delete: the file must still be this ("absent": must not exist)
    std::string version;    // restore: the history's version
    bool overwrite = false, executable = false, parents = false, recursive = false, dry_run = false, as_base64 = false;
    std::uint64_t offset = 0, tail = 0;
    std::vector<std::string> secrets;  // the preset's credential files, relative to site_root
};

// The request's shapes, the same in the server and the helper: {action, site_root, path, to,
// content (base64), old, new, if_sha256, version, overwrite, executable, parents, recursive,
// dry_run, base64, offset, tail, secrets}. "" with `out` filled, else why.
std::string parse(const json::Value& req, Op& out);

// A path whose content is a secret (docs/design-site-operations.md 27.2): one of the preset's
// credential files or below one, anything below .git/, a name starting with .env, a name ending in
// .key or .pem, a database file (.sqlite, .sqlite3, .db). Reading it waits for approval.
bool secret_path(std::string_view rel, const std::vector<std::string>& secrets) noexcept;

// As the executing account: list, read, write, edit, mkdir, move, delete (the delete without a
// history), each a JSON answer {"ok", "error"?, "as", "path", ...}; a dry run checks everything and
// changes nothing, and for write and edit answers the current file (exists, bytes, sha256, and its
// text when it is UTF-8 within kContentMax), so the server can show the person the change.
json::Value execute(const Op& op);

// Who runs the account's part: the helper's child after the drop, or the server itself.
using AsSite = std::function<json::Value(const std::function<json::Value()>&)>;
struct Context {
    history::Place place;  // where the history lives and whose site it keeps
};
// The whole operation: the history's part (keep before a replace, a move over a file and a delete;
// list and restore), in the caller's identity, and the account's part through `as_site`. A failure of
// the account's part undoes the keep.
json::Value run(const Op& op, const Context& ctx, const AsSite& as_site);

std::string sha256_hex(std::string_view bytes);
bool utf8_text(std::string_view bytes) noexcept;  // well-formed UTF-8 without NUL
std::string base64_encode(std::string_view bytes);
std::optional<std::string> base64_decode(std::string_view text);

}  // namespace agensio::files
