// A managed site's password users (2026-10-09, docs/design-site-operations.md section 25, step
// 4b): the users of its rules.auth, one file per site, <directory of the main configuration>/
// auth/<site>.users, in the format the loader reads (core/auth.hpp parse_users). Root's, the
// server's group, 0640, in a 0750 directory of root's: the server reads it after dropping its
// privileges, the site's account can neither read nor replace it, and the loader's checks
// (owner of the main configuration, not writable by group or others, not readable by others)
// hold. Written and read by the provisioning helper; a server without the helper keeps its own
// under its own account, as the suites run it. Read back as names, methods, expiry, notes and
// locks, never a hash. A password is never sent to the server: the helper generates one and
// answers it once, kept nowhere, or `agensio ctl site-auth-user-set --prompt` asks on the user's
// terminal and sends only the hash. Built with authentication only (libxcrypt and OpenSSL).
#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/auth.hpp"
#include "services/json.hpp"

namespace agensio {
struct Config;
}

namespace agensio::authusers {

constexpr std::size_t kMaxUsers = 1000;
constexpr std::size_t kMaxNote = 200;

// ^[A-Za-z0-9][A-Za-z0-9._@+-]{0,63}$: "" or why. Stricter than the file allows, so a name the
// tools write is one any client can send.
std::string check_user(std::string_view name);
// A hash a caller brings (`agensio ctl --prompt`): one the loader accepts, at most 255 bytes, no
// ':' and no blank, and no lock (`locked` does that): "" or why.
std::string check_hash(std::string_view hash);

// One change to one user, as the control API and the helper take it: {"user", "delete": true},
// or {"user", "generate": true | "hash": "...", "expires": "YYYY-MM-DD" | "", "note": "..." | "",
// "locked": bool}. A field left out keeps what the user has; "" clears expires and note.
struct Change {
    std::string user;
    bool remove = false;
    bool generate = false;
    std::string hash;
    std::optional<std::string> expires;
    std::optional<std::string> note;
    std::optional<bool> locked;
};
// "" when acceptable, else the refusal; `password` is refused with the two ways that exist.
std::string parse_change(const json::Value& body, Change& out);

// Four groups of four, xxxx-xxxx-xxxx-xxxx, from the 32 lower-case letters and digits that do not
// look alike (no 0, 1, l, o): 80 bits, easy to read out and to type. "" without random bytes.
std::string generate_password();

// What a stored hash is: yescrypt, gost-yescrypt, scrypt, bcrypt, sha512crypt, sha256crypt; the
// hash behind a lock's '!' counts; "" for a lock with no hash behind it.
std::string method_of(std::string_view hash);

// The file's text: two comment lines naming the site, then name:hash[:expires=][:note=] lines.
std::string render(const std::vector<auth::User>& users, std::string_view site);

// <directory of the main configuration file>/auth, and <dir>/<site>.users in it.
std::string dir_of(const std::filesystem::path& config_path);
std::string file_of(const std::string& dir, std::string_view site);
// Whether a [[site.auth]] rule of `cfg` reads `file`: its last user is then kept, and a change
// reloads the server so that it applies to the next request.
bool used_by(const Config& cfg, const std::string& file);

// The users without their hashes: {"ok", "site", "file", "exists", "users": [{"name", "method",
// "expires" (YYYY-MM-DD or null), "expired", "note" (or null), "locked"}]}, or {"ok": false,
// "error"} for a file that is refused (a symlink, another owner, writable by others, not parsed).
json::Value describe(const std::string& dir, std::string_view site, unsigned owner, std::int64_t now);

// The change, written as `owner`:`group` 0640 through a temporary file and a rename, in a
// directory of `owner`'s and `group`'s, 0750 (made when missing): {"ok", "site", "file", "user",
// "action": "created" | "changed" | "deleted" | "unchanged", "password" (generated: answered this
// once), "users" (how many now), "removed" (the file, when no user is left)}. `keep_one`: a rule
// uses the file, so its last user is not deleted (lock it, or remove the rule first).
json::Value apply(const std::string& dir, std::string_view site, unsigned owner, unsigned group, const Change& change, bool keep_one);

}  // namespace agensio::authusers
