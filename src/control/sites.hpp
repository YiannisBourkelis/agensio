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
    std::string user, group;
    bool user_decided = false;  // "user" was given (possibly as none); a managed file always has it
    std::string app;  // static | php | laravel | wordpress | proxy
    std::string root;
    std::string upstream;    // app = proxy
    std::string php_socket;  // php without a user: an existing pool
    int php_children = 0;    // generated pool sizing (with a user)
    std::string php_version;
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
// A short account name derived from the domain ("www.example.com" -> "example").
std::string suggest_user(std::string_view domain);
// The application the files under `root` suggest: laravel, wordpress, php, proxy, static.
std::string detect_app(const std::filesystem::path& root);

// Applies `body` onto `spec` (fields present win; absent ones keep what spec had) and
// lists the decisions still open. `error` names a value that is wrong outright.
std::vector<Decision> apply_request(const json::Value& body, const Config& cfg, SiteSpec& spec, std::string& error);

// The TOML for the spec, with the managed header that carries the spec as JSON.
constexpr std::string_view kManagedMarker = "# agensio:managed ";
std::string render_site(const SiteSpec& spec, std::string_view stamp);
// Reads the spec back from a managed file; false for a hand-written file.
bool read_managed(const std::filesystem::path& file, SiteSpec& out);

// <config dir>/sites.d and the file of a domain there.
std::filesystem::path sites_dir(const Config& cfg);
std::filesystem::path site_file(const Config& cfg, std::string_view domain);
// True when an include pattern of the main file covers sites.d/*.toml.
bool sites_dir_included(const Config& cfg);
// Atomic write with a .bak of anything overwritten; false with `error`.
bool write_site_file(const std::filesystem::path& file, const std::string& text, std::string& error);

// The commands an administrator must run as root before this site can work, empty when
// nothing is missing: the account, the root directory and its owner.
std::vector<std::string> prerequisites(const SiteSpec& spec, const Config& cfg);
// What to run after the site is live (generated pool files, php-fpm reload).
std::vector<std::string> next_steps(const SiteSpec& spec, const Config& cfg);
// "systemctl reload php8.4-fpm" for the pool directory in use (Debian), "php-fpm" (RHEL), brew.
std::string php_fpm_reload_command(const Config& cfg, const std::string& version);

}  // namespace agensio::control
