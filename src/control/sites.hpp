// Site files the control API writes (F3): a specification, its TOML rendering, the
// decisions an incomplete request still needs, and the file operations under
// <config dir>/sites.d. Pure functions, unit tested; the handler calls them.
#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "services/json.hpp"

namespace agensio::control {

struct SiteSpec {
    std::string domain;
    std::vector<std::string> aliases;
    std::string https;  // "auto" | "none" | "manual"
    std::string cert, key;  // manual
    bool redirect_http = true;
    bool hsts = false;
    std::string encoded_slashes;  // "" (deny, the default) | "allow": a %2F or %5C in the path decoded and looked up (2026-10-02)
    std::string user, group;
    bool user_decided = false;  // "user" was given (possibly as none); a managed file always has it
    bool no_user = false;       // `no_user: true`: decided, and no account (the same as user null)
    std::string app;  // static | php | laravel | wordpress | proxy
    std::string root;
    std::string upstream;    // app = proxy, rails, redmine, django, wagtail
    std::string project;     // app = django | wagtail: the project's Python package
    std::string entry;       // app = node: the file node runs, relative to root
    std::string php_socket;  // php without a user: an existing pool
    int php_children = 0;    // generated pool sizing (with a user); the same as settings.children
    std::string php_version;
    json::Value settings;    // the allowlisted per-site limits (control/settings.hpp), normalised: {key: value}
    // An application's own server rules (2026-10-01, the Kanboard proposal), bounded so a
    // caller can only make the site serve less: {"private": [paths], "entry_points": [the
    // only .php that run], "cache": [{"path", "max_age"}], "front_controller": "/index.php"};
    // normalised by check_rules, rendered as locations of the managed file.
    json::Value rules;
    // Where the application's login form or authenticating API is posted to, on top of the
    // preset's known paths (2026-10-02): the rendered fail2ban jail counts attempts there;
    // nothing is served or refused by it. Plain paths (check_login_path), at most 16.
    std::vector<std::string> login_paths;
    std::string access_log;  // a site with a user gets its own (rule: nothing shared between users)
    std::string listen_plain = "0.0.0.0:80";
    std::string listen_tls = "0.0.0.0:443";

    json::Value to_json() const;
    static bool from_json(const json::Value& v, SiteSpec& out);
};

// A decision the caller has not made: the field, the question to ask, a suggestion.
struct Decision {
    std::string field;
    std::string question;
    std::string suggestion;
    std::vector<std::string> options;
};

// Host names only: lower-case labels of letters, digits and hyphens, dots between.
bool valid_domain(std::string_view name);
// An account name we would put into `useradd` and `chown`: ^[a-z_][a-z0-9_-]{0,31}$, not a
// word an agent may use for "none" (null, none, nil, undefined, false, true, ~), not a
// system account (root, daemon, nobody, www-data, ...). `why` says what was wrong.
bool valid_account(std::string_view name, std::string& why);
// A path we would put into `mkdir` and a recursive `chown`: absolute, normalised, only
// letters, digits and ._/- , no "..", no whitespace, nothing a shell would interpret.
bool safe_path(std::string_view path, std::string& why);
// A short account name derived from the domain ("www.example.com" -> "example").
std::string suggest_user(std::string_view domain);
// A project name suggested from the domain ("blog.example.com" -> "blog"), a valid package name.
std::string suggest_project(std::string_view domain);
// The application the files under `root` suggest: laravel, wordpress, php, wagtail, django, proxy, static.
std::string detect_app(const std::filesystem::path& root);
// What detect_app looked at for that answer, for a message ("bin/grav and system/defines.php").
std::string detect_app_marker(const std::string& app);

// A site's rules against the preset they apply to: every path a URL path below the root
// (plain characters, no "..", no "//", never "/" alone); `private` prefixes (ending in "/")
// and exact paths; `entry_points` exact .php paths, PHP presets only; `cache` prefixes with a
// max_age of 0 to 31536000, PHP and static presets only (a proxy preset's root is the
// application's directory, which must never be served); `front_controller` one of the entry
// points, PHP presets only. An entry point under a private path is a contradiction, refused.
// "" with `normalised` filled, else why. An empty object clears the rules.
// `cfg`, when given, also checks that every "@set" a restricted rule names is in [addresses].
std::string check_rules(const json::Value& given, const SiteSpec& spec, json::Value& normalised, const Config* cfg = nullptr);

// Applies `body` onto `spec` (fields present win; absent ones keep what spec had) and
// lists the decisions still open. `error` names a value that is wrong outright.
std::vector<Decision> apply_request(const json::Value& body, const Config& cfg, SiteSpec& spec, std::string& error);

// The TOML for the spec, with the managed header that carries the spec as JSON.
constexpr std::string_view kManagedMarker = "# agensio:managed ";
std::string render_site(const SiteSpec& spec, std::string_view stamp);
// The locations a site's rules render, as the loader will see them (a suffix location's path
// without its leading slash): the renderer writes them, site_show labels them "rules"
// (2026-10-02 report: they said nothing, like hand-written ones).
struct RuleLocation {
    enum class Kind { private_, entry, no_other_php, cache } kind;
    std::string path;
    bool exact = false, suffix = false;
    long max_age = 0;  // cache only
};
std::vector<RuleLocation> rule_locations(const SiteSpec& spec);
// Reads the spec back from a managed file; false for a hand-written file.
bool read_managed(const std::filesystem::path& file, SiteSpec& out);

// <config dir>/sites.d and the file of a domain there.
std::filesystem::path sites_dir(const Config& cfg);
std::filesystem::path site_file(const Config& cfg, std::string_view domain);
// True when an include pattern of the main file covers sites.d/*.toml.
bool sites_dir_included(const Config& cfg);
// Atomic write with a .bak of anything overwritten; false with `error`.
bool write_site_file(const std::filesystem::path& file, const std::string& text, std::string& error);

// One thing that stands between the specification and a working site, with the command
// that fixes it (empty for a condition nothing but a restart resolves).
struct Problem {
    std::string code;         // missing_account, missing_group, root_missing, root_unreadable, certificate_missing, needs_restart
    std::string detail;
    std::string run_as_root;  // "" when there is no command to run
    bool blocks = true;       // false: the site can be written now and served after the restart
    json::Value fix;          // the provisioning helper's request that resolves it, or null
};
// Every problem at once, so the caller fixes all of them and retries once. `privileged`
// says whether the server still runs as root (before the drop it can bind any port).
std::vector<Problem> preflight(const SiteSpec& spec, const Config& cfg, bool privileged);
// The commands of the blocking problems (what the older callers and the tests use).
std::vector<std::string> prerequisites(const SiteSpec& spec, const Config& cfg);
// What to run after the site is live (generated pool files, php-fpm reload).
std::vector<std::string> next_steps(const SiteSpec& spec, const Config& cfg);

// The systemd unit that runs a Rails site's Puma or a Django site's Gunicorn until agensio
// manages it (roadmap F14):
// rendered from the site (its account, directory, loopback upstream port), [control]
// runtimes (the Ruby the tasks bundled with) and the site's environment file, never from the
// caller (2026-09-27 Redmine report: a unit copied from docs/examples/puma.service started
// Debian's Ruby on a bundle built by /opt's). Text for root to put in place; every value in
// it is checked to be a plain path or name, so nothing can add a line to the unit.
// {"ok", "site", "unit_name", "path", "unit", "run_as_root": [...], "hint"} or {"ok": false, "error"}.
json::Value service_unit(const SiteConfig& site, const Config& cfg);
// "systemctl reload php8.4-fpm" for the pool directory in use (Debian), "php-fpm" (RHEL), brew.
std::string php_fpm_reload_command(const Config& cfg, const std::string& version);

}  // namespace agensio::control
