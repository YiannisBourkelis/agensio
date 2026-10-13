// The fields a site sets on its answers (docs/headers.md 1), resolved when the configuration
// loads. The first of them is HSTS (docs/redirects.md 4), on the answers a site gives over TLS;
// the response-header rules and the security baseline will add theirs here.
#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/headers.hpp"

namespace agensio {

// A flag set once and never copied: a copy of its owner (the next load of a site, a preview)
// starts unset, so what it gates happens once per generation.
struct NoteOnce {
    mutable std::atomic<bool> done{false};
    NoteOnce() = default;
    NoteOnce(const NoteOnce&) noexcept {}
    NoteOnce& operator=(const NoteOnce&) noexcept { return *this; }
};

// Pointed at by the request once its site is known (Dispatcher::route), never copied per
// request: the HTTP/1 writer appends `h1` to the head, the HTTP/2 and HTTP/3 writers send each
// value through their connection's table (one index byte after the first answer).
struct SiteFields {
    std::string h1;    // the fields as HTTP/1 lines, "Strict-Transport-Security: max-age=31536000\r\n"
    std::string hsts;  // the Strict-Transport-Security value; "" when the site sends none
    std::string site;  // the site's first name, for what its answers note (core/site_notices.hpp)
    // hsts_narrows_application (docs/redirects.md 4.1): set once this generation of the site has
    // noted an application's stronger HSTS, so a later answer carrying it costs one load.
    NoteOnce hsts_noted;
    // A site with no hsts line (4.2): the HSTS its application sends itself is noted, once per
    // generation, so health tells the user so instead of suggesting the site's own over it.
    bool watch_application = false;
    NoteOnce application_noted;
    bool empty() const noexcept { return h1.empty(); }
};

// A Strict-Transport-Security value as RFC 6797 6.1 reads it: directives separated by ';', names
// in any case, max-age's value quoted or not; a directive given twice, or no max-age, makes the
// whole field one a browser ignores (valid false).
struct HstsValue {
    bool valid = false;
    std::uint64_t max_age = 0;
    bool subdomains = false;
    bool preload = false;
};

inline HstsValue parse_hsts(std::string_view v) noexcept {
    auto trim = [](std::string_view t) {
        while (!t.empty() && (t.front() == ' ' || t.front() == '\t')) t.remove_prefix(1);
        while (!t.empty() && (t.back() == ' ' || t.back() == '\t')) t.remove_suffix(1);
        return t;
    };
    HstsValue out;
    bool age = false, sub = false, pre = false;
    while (!v.empty()) {
        const std::size_t semi = v.find(';');
        const std::string_view d = trim(v.substr(0, semi));
        v = semi == std::string_view::npos ? std::string_view() : v.substr(semi + 1);
        if (d.empty()) continue;
        const std::size_t eq = d.find('=');
        const std::string_view name = trim(d.substr(0, eq));
        std::string_view value = eq == std::string_view::npos ? std::string_view() : trim(d.substr(eq + 1));
        if (value.size() >= 2 && value.front() == '"' && value.back() == '"') value = value.substr(1, value.size() - 2);
        if (Headers::iequals(name, "max-age")) {
            if (age || value.empty() || value.size() > 19) return {};
            std::uint64_t n = 0;
            for (const char c : value) {
                if (c < '0' || c > '9') return {};
                n = n * 10 + static_cast<std::uint64_t>(c - '0');
            }
            out.max_age = n;
            age = true;
        } else if (Headers::iequals(name, "includesubdomains")) {
            if (sub) return {};
            out.subdomains = sub = true;
        } else if (Headers::iequals(name, "preload")) {
            if (pre) return {};
            out.preload = pre = true;
        }
    }
    out.valid = age;
    return out;
}

// Whether `app` commits browsers to more than `site`: a longer max-age, or includeSubDomains or
// preload the site's lacks. A value browsers would ignore is never stronger.
inline bool hsts_stronger(std::string_view app, std::string_view site) noexcept {
    const HstsValue a = parse_hsts(app);
    if (!a.valid) return false;
    const HstsValue s = parse_hsts(site);
    return a.max_age > s.max_age || (a.subdomains && !s.subdomains) || (a.preload && !s.preload);
}

}  // namespace agensio
