// Paths a site keeps out of its logs (`access_log_exclude_paths`, 0.1.0-alpha.128, docs/configuration.md
// 8): a request under one of them writes no access-log line, and the error log's lines about it name
// no client address. For a promise like an application's privacy notice ("the server keeps no record
// of these requests"); a login path, a password rule's path and an address rule's path cannot be
// excluded (the loader refuses them, check_log_exclusions in config.cpp), so the fail2ban jails count
// what they counted before.
//
// Judged on the request's cleaned path (normalize_target, the path routing judges), never on the raw
// target: /api/notices/../../wp-login.php is /wp-login.php, a login attempt the jail must see. A
// prefix covers its path and whole segments below it ("/healthz": /healthz and /healthz/live, never
// /healthzx; "/api/notices/": everything below it), in the capitalisation written: the narrower
// reading, since the key hides requests. Asked when a line is written, never while routing: a site
// without the key pays one test of an empty list in its access-log call, one whose access log is off
// returns before it.
#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "path.hpp"

namespace agensio::log_exclude {

inline constexpr std::size_t kMaxPaths = 16;

// `prefix` covers the cleaned `path`.
inline bool covers(std::string_view prefix, std::string_view path) noexcept {
    if (path.size() < prefix.size() || path.compare(0, prefix.size(), prefix) != 0) return false;
    return path.size() == prefix.size() || prefix.back() == '/' || path[prefix.size()] == '/';
}

inline bool covered(const std::vector<std::string>& prefixes, std::string_view path) noexcept {
    for (const std::string& p : prefixes)
        if (covers(p, path)) return true;
    return false;
}

// The request `target` (as sent) of `site` is excluded. `scratch` is the worker's own, reused (its
// capacity kept), so a site with exclusions allocates nothing per request once it is warm. A target
// that does not clean up (a 400) is not excluded.
inline bool excluded(const SiteConfig* site, std::string_view target, std::string& scratch) {
    if (!site || site->access_log_exclude.empty()) return false;
    return normalize_target(target, scratch) && covered(site->access_log_exclude, scratch);
}

}  // namespace agensio::log_exclude
