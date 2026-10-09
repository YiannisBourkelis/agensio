// Access by client address (2026-10-07, docs/configuration.md 19, docs/design-site-operations.md
// 22): which of a site's [[site.access]] rules decides a request path, and whether a client
// address passes it. Used by the dispatcher on every request of a site that has rules, by the
// control plane's access-check and by the tests. Nothing here allocates on an ordinary path.
#pragma once

#include <string>
#include <string_view>

#include <asio/ip/address.hpp>

#include "config.hpp"
#include "core/router.hpp"
#include "core/script_split.hpp"
#include "file.hpp"
#include "net/cidr.hpp"
#include "path.hpp"

namespace agensio::access {

// ASCII case-insensitive: some filesystems (macOS's default, Windows) and some applications
// answer /ADMIN/x with /admin/x, so a rule covers every capitalisation of its path.
inline bool iequal_prefix(std::string_view path, std::string_view prefix) noexcept {
    if (path.size() < prefix.size()) return false;
    for (std::size_t i = 0; i < prefix.size(); ++i) {
        unsigned char a = static_cast<unsigned char>(path[i]), b = static_cast<unsigned char>(prefix[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + 32);
        if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + 32);
        if (a != b) return false;
    }
    return true;
}

// A prefix rule covers its path and everything below it on a segment boundary ("/admin":
// /admin, /admin/ and /admin/x, never /administrator); "/" covers the whole site; an exact
// rule its path alone, and through script_of the paths that run it as their script.
// The same matcher serves [[site.auth]] rules (AuthRule: the same path and exact fields).
template <class Rule>
inline bool covers(const Rule& r, std::string_view path) noexcept {
    if (r.exact) return path.size() == r.path.size() && iequal_prefix(path, r.path);
    if (r.path.size() == 1) return true;
    return iequal_prefix(path, r.path) && (path.size() == r.path.size() || path[r.path.size()] == '/');
}

// The byte after the leading '/', folded to lower case (0 for "/" itself): the bit of
// SiteConfig::access_first that says whether any rule can cover the path.
inline unsigned char first_byte(std::string_view path) noexcept {
    if (path.size() < 2) return 0;
    unsigned char c = static_cast<unsigned char>(path[1]);
    if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + 32);
    return c;
}

inline void mark_first(std::array<std::uint64_t, 4>& bits, unsigned char c) noexcept { bits[c >> 6] |= std::uint64_t{1} << (c & 63); }

// The rule deciding `path` (the site's rules are sorted longest first), or null.
inline const AccessRule* rule_for(const SiteConfig& site, std::string_view path) noexcept {
    const unsigned char c = first_byte(path);
    if (((site.access_first[c >> 6] >> (c & 63)) & 1u) == 0) return nullptr;
    for (const AccessRule& r : site.access)
        if (covers(r, path)) return &r;
    return nullptr;
}

// [[site.auth]]: the rule deciding `path` (longest first, the same bitmap test), or null.
inline const AuthRule* auth_rule_for(const SiteConfig& site, std::string_view path) noexcept {
    const unsigned char c = first_byte(path);
    if (((site.auth_first[c >> 6] >> (c & 63)) & 1u) == 0) return nullptr;
    for (const AuthRule& r : site.auth)
        if (covers(r, path)) return &r;
    return nullptr;
}

inline bool admits(const AccessRule& r, const asio::ip::address& a) noexcept { return r.any || in_any(r.allow, a); }

// The other ways an origin may read the same path, tried only when the path holds the
// character that makes them differ, so an ordinary path has none: a ";parameter" in a segment
// (Tomcat and Jetty read "/a/..;/b" as "/b", Orange Tsai 2018), a '%' left after the one
// decoding (an origin that decodes twice reads "/%2561dmin" as "/admin"), and the part after a
// script ("/index.php/cp" reaches the route "/cp" of a front controller that reads PATH_INFO).
template <typename F>
void other_readings(std::string_view path, std::string& scratch, F&& each) {
    if (path.find(';') != std::string_view::npos) {
        std::string stripped;
        stripped.reserve(path.size());
        bool skip = false;
        for (char c : path) {
            if (c == '/') skip = false;
            else if (c == ';') skip = true;
            if (!skip) stripped.push_back(c);
        }
        if (normalize_target(stripped, scratch)) each(std::string_view(scratch));
    }
    if (path.find('%') != std::string_view::npos && normalize_target(path, scratch)) each(std::string_view(scratch));
    if (const std::size_t end = script_split::php_end(path); end != std::string_view::npos) each(path.substr(end));
}

// The script `path` runs when that is not the path itself (2026-10-09, the alpha.58 report,
// finding 1: an exact rule on /wp-login.php let /wp-login.php/x run wp-login.php). Asked of the
// location that will serve the path and split as its handler splits it (core/script_split.hpp):
// a FastCGI location at the first ".php/" when path_info is on and, for a directory, at its
// index; a CGI location at the longest leading part that names a file, a directory with its
// index. Nothing for a static, proxied or other location: agensio runs no script there, and an
// application behind a proxy decides what its paths mean (an exact rule there covers its path
// alone; config.cpp access_notices says so for a .php one). Only on a site with an exact rule
// and only for a path that could run one: other requests pay a flag test. `out` is a buffer
// the caller keeps (a worker's, never one per request); a CGI location stats its candidates
// with the handler's own test (stat_path).
inline bool script_of(const SiteConfig& site, std::string_view path, std::string& out) {
    if (!site.exact_rules || path.empty()) return false;
    const std::size_t php = script_split::php_end(path);
    const bool dir = path.back() == '/';
    if (php == std::string_view::npos && !dir && !site.cgi_locations) return false;
    const LocationConfig& loc = Router::location(site, path);
    if (loc.kind == HandlerKind::fastcgi) {
        if (php != std::string_view::npos && loc.fastcgi.options.path_info) {
            out.assign(path.substr(0, php));
            return true;
        }
        if (!dir) return false;
        out.assign(path).append(loc.index.empty() ? std::string_view("index.php") : std::string_view(loc.index.front()));
        return true;
    }
    if (loc.kind == HandlerKind::cgi) {
        thread_local std::string fs;  // the candidate files; a CGI request forks a process anyway
        out.assign(path);
        if (dir) out.append(loc.index.empty() ? std::string_view("index.cgi") : std::string_view(loc.index.front()));
        const std::size_t cut = script_split::cgi_end(loc, out, fs, [](const std::string& f) {
            FileInfo fi;
            return stat_path(f.c_str(), fi) && fi.is_regular;
        });
        if (cut == 0) return false;
        out.resize(cut);
        return out != path;
    }
    return false;
}

struct Decision {
    const AccessRule* rule = nullptr;  // the rule that refuses (or, in report mode, would), null when none does
    bool refuse() const noexcept { return rule && !rule->report; }
};

// Every reading of `path` judged by its deciding rule; the client's address is asked for only
// when some rule covers a reading. A rule that refuses wins over one that only reports.
// Each reading is judged as the script it runs too (script_of).
template <typename Address>
Decision decide(const SiteConfig& site, std::string_view path, Address&& address, std::string& scratch) {
    Decision d;
    thread_local std::string script;  // script_of's buffer: kept per thread, no allocation per request
    auto judge = [&](std::string_view p) {
        if (d.refuse()) return;
        const AccessRule* r = rule_for(site, p);
        if (!r || r->any || admits(*r, address())) return;
        if (!d.rule || !r->report) d.rule = r;
    };
    auto judge_all = [&](std::string_view p) {
        judge(p);
        if (!d.refuse() && script_of(site, p, script)) judge(script);
    };
    judge_all(path);
    other_readings(path, scratch, judge_all);
    return d;
}

// [[site.auth]]: the password rule protecting `path`, the strictest over its readings and the
// scripts they run (an open rule never opens a path another reading protects), or null.
inline const AuthRule* auth_protecting_rule(const SiteConfig& site, std::string_view path, std::string& scratch) {
    const AuthRule* found = nullptr;
    thread_local std::string script;  // as in decide
    auto judge = [&](std::string_view p) {
        if (found) return;
        const AuthRule* r = auth_rule_for(site, p);
        if (r && !r->open) found = r;
    };
    auto judge_all = [&](std::string_view p) {
        judge(p);
        if (!found && script_of(site, p, script)) judge(script);
    };
    judge_all(path);
    if (!found) other_readings(path, scratch, judge_all);
    return found;
}

}  // namespace agensio::access
