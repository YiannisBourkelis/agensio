// A site's application environment (2026-09-27 Writebook report, finding 1): the variables
// an application reads at boot that no task row or unit file can carry, above all
// SECRET_KEY_BASE for a Rails application without credentials (every ONCE application,
// every Kamal or twelve-factor deployment reads it from the environment). One file per
// site, <directory of the main configuration>/env/<site>.env, in systemd's
// EnvironmentFile syntax so the application's service loads the same file
// (docs/examples/puma.service now, F14's generated unit later). It is root's, 0600, in a
// 0700 directory of root's, written and read by the provisioning helper only; a server
// that runs without the helper keeps its own, under its own account. It must be root's
// because systemd reads an EnvironmentFile as root: a file the site's account could
// replace would let it link /etc/shadow into its own environment. Tasks get its
// variables after the ones agensio sets; a name agensio sets or one that changes which
// program runs (PATH, LD_*, RUBYOPT, GEM_*, ...) is refused on the way in and on the way
// out. The pure parts (names, values, render, parse, the change request) are unit
// tested; `read` and `apply` run as real accounts in tests/tasks.sh.
#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "services/json.hpp"

namespace agensio::appenv {

struct Var {
    std::string name;
    std::string value;
};

constexpr std::size_t kMaxVars = 128;
constexpr std::size_t kMaxValue = 4096;
constexpr std::size_t kMaxFile = 64 * 1024;

// Names agensio sets for a task, or that change which program runs or how it loads code.
bool reserved(std::string_view name) noexcept;
// ^[A-Z_][A-Z0-9_]{0,63}$ and not reserved: "" or why.
std::string check_name(std::string_view name);
// Valid UTF-8, no control characters (one line), at most kMaxValue bytes: "" or why.
std::string check_value(std::string_view value);
// A site's file name: its host name (lower-case labels of letters, digits and '-').
bool valid_site(std::string_view site) noexcept;

// The file's text: a header naming the site, one NAME="value" line per variable, in
// systemd's EnvironmentFile syntax (double quotes; backslash, quote, dollar and backtick
// escaped), so systemd and `parse` read back exactly the values written.
std::string render(const std::vector<Var>& vars, std::string_view site);
// The variables of a file: what `render` writes, and the one-line forms systemd reads that
// root may write by hand (NAME=value with backslash escapes, NAME='value', NAME="value",
// comments, blank lines, lines without '=' ignored). A later line with the same name wins,
// as in systemd. false with `why` naming the line for a value that goes on over the next
// line or never closes, which systemd would read differently.
bool parse(std::string_view text, std::vector<Var>& out, std::string& why);

// <directory of the main configuration file>/env
std::string dir_of(const std::filesystem::path& config_path);

// A change as the control API and the helper take it: {"set": {NAME: value}, "unset":
// [NAME], "generate": [NAME]}. "" when acceptable, else the refusal naming the entry.
struct Change {
    std::vector<Var> set;               // replaces or adds
    std::vector<std::string> unset;     // removes
    std::vector<std::string> generate;  // a random secret under each name that is missing
};
std::string parse_change(const json::Value& body, Change& out);

// 128 hex digits from the system's random source (the length of Rails' `bin/rails secret`);
// "" when none could be read.
std::string random_secret();

#ifndef _WIN32
// A site's variables. No directory or no file: none, and ok. The directory and the file
// must belong to `owner`, be no symlink and carry no permission for group or others, the
// file regular and at most kMaxFile bytes, every name pass check_name and every value
// check_value: otherwise false with `why` saying what to fix.
bool read(const std::string& dir, std::string_view site, unsigned owner, std::vector<Var>& out, std::string& why);

// Applies a change as the calling process, which is `owner`: the directory is created 0700
// when missing, the file written to a temporary name, synced and renamed into place 0600,
// and removed when no variable is left. {"ok", "file", "set", "unset", "absent",
// "generated", "kept", "names"} or {"ok": false, "error"}: names only, a value never
// appears in the answer.
json::Value apply(const std::string& dir, std::string_view site, unsigned owner, const Change& change);
#endif

}  // namespace agensio::appenv
