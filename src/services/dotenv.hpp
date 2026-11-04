// A Laravel application's .env (2026-11-04, the grabloop.app answer): what site_env lists and
// site_env_set changes for a site with env_file, so a secret never passes through an agent's
// conversation. The file is the application's own, in phpdotenv's syntax, wherever the site's
// env_file puts it (shared/.env beside the releases); every line this does not change is kept as it
// was, comments and lines it cannot read included. Written by the provisioning helper as root: the
// file root's, group the site's account, 0640, so PHP reads it and neither the account nor a
// compromised application changes it in place (artisan key:generate cannot rewrite it: generate
// writes APP_KEY instead). The parse, the quoting and the change are pure and unit tested; the file
// is reached from the project directory through directories opened without following a symlink.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "services/appenv.hpp"
#include "services/json.hpp"

namespace agensio::dotenv {

// One line of the file as written, or several when a quoted value goes on over the next lines.
struct Line {
    std::string raw;        // the text, without the final newline (lines of a value over several joined by '\n')
    std::string name;       // an assignment's name; "" for a comment, a blank or anything else
    std::string value;      // the value as phpdotenv reads it (quotes removed, \" and \\ in double quotes)
    bool assignment = false;
    bool exported = false;      // the assignment starts with "export "
    bool readable = true;       // false: a value over several lines, kept and never rewritten
    bool unterminated = false;  // a quote opened and never closed before the end of the file
};
std::vector<Line> parse(std::string_view text);

// ^[A-Za-z_][A-Za-z0-9_.]{0,63}$: "" or why.
std::string check_name(std::string_view name);
// A value as the file holds it so phpdotenv reads it back the same: plain when it is letters, digits
// and _ . / : @ + = , -; in single quotes (literal) otherwise; in double quotes when it holds a
// single quote and no double quote, backslash or dollar sign; else refused. "" with `out`, or why.
std::string render_value(std::string_view value, std::string& out);
// Laravel's APP_KEY: "base64:" and 32 random bytes in base64 (php artisan key:generate's form).
std::string laravel_key();

// A change applied to the text, in the environment file's order (appenv): unset removes every line of
// a name; set replaces the first line of a name (its later ones dropped) or appends one; generate
// writes a random secret under a name that is missing or empty (APP_KEY in Laravel's form, any other
// 128 hex digits) and keeps one that has a value, so unset and generate together rotate it, written
// where the old line was. A name whose value goes over several lines is refused, not rewritten, and a
// file with a quote never closed is refused whole (phpdotenv cannot read it, and the lines after the
// quote belong to that value). The text is read back before it is answered: a change that does not
// read back as given is refused.
struct Result {
    std::string text;
    std::vector<std::string> set, unset, generated, kept, absent;
    std::string error;
};
Result apply(std::string_view text, const appenv::Change& change);

// site_env's answer from the text: {"variables": [{"name", "length", "fingerprint", "value"?}],
// "revealed": [...], "not_found"?: [...]}: a value only for a name in `reveal`.
json::Value describe(std::string_view text, std::string_view key, const std::vector<std::string>& reveal);

#ifndef _WIN32
// The file `rel` below `project`, every directory on the way opened without following a symlink and
// belonging to `account` or root and writable by no other; the file, when there, regular with one
// link, root's or the account's, at most 64 KB. {"ok", "file", "exists", "variables", ...} as
// describe answers, or {"ok": false, "error"}.
json::Value read_file(const std::string& project, const std::string& rel, std::string_view key, const std::vector<std::string>& reveal, unsigned account);
// The change written: a temporary file in the same directory, owned `owner`:`group`, 0640, synced and
// renamed over the file. {"ok", "file", "set", "unset", "generated", "kept", "absent"} (names only) or
// {"ok": false, "error"}.
json::Value write_file(const std::string& project, const std::string& rel, unsigned owner, unsigned group, const appenv::Change& change, unsigned account);
#endif

}  // namespace agensio::dotenv
