// Answers from a password-protected path ([[site.auth]], 2026-10-09): never one a shared cache
// may keep, whatever the application said. RFC 9111 3.5: a shared cache may reuse a response to
// a request with Authorization when the response says public, s-maxage or must-revalidate;
// 5.2.2.7: an unqualified private forbids a shared cache to store a response at all. RFC 9213
// 2.2: a CDN that follows a targeted field (CDN-Cache-Control, its own ExampleCDN-Cache-Control)
// ignores Cache-Control and Expires. And a client let in by skip_for sends no Authorization, so
// its answers are ordinary ones to a cache. So a protected answer carries Cache-Control: private,
// with the directives that only speak to shared caches removed and what the browser needs kept
// (max-age, no-store, no-cache, must-revalidate, immutable...), and the fields only shared caches
// act on dropped: the targeted fields (by convention "-Cache-Control", RFC 9213 2.4),
// Surrogate-Control (Varnish, Fastly) and Edge-Control (Akamai).
#pragma once

#include <string>
#include <string_view>

namespace agensio::private_cache {

inline bool iequal(std::string_view a, std::string_view b) noexcept {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i) {
        unsigned char x = static_cast<unsigned char>(a[i]), y = static_cast<unsigned char>(b[i]);
        if (x >= 'A' && x <= 'Z') x = static_cast<unsigned char>(x + 32);
        if (y >= 'A' && y <= 'Z') y = static_cast<unsigned char>(y + 32);
        if (x != y) return false;
    }
    return true;
}

// A field only shared caches act on: dropped from a protected answer. Cache-Control itself is
// not one (it is rewritten, keep_directives).
inline bool shared_only_field(std::string_view name) noexcept {
    constexpr std::string_view suffix = "-cache-control";
    if (name.size() > suffix.size() && iequal(name.substr(name.size() - suffix.size()), suffix)) return true;
    return iequal(name, "surrogate-control") || iequal(name, "edge-control");
}

// The directives of one Cache-Control value a protected answer keeps, appended to `kept` with
// ", " between them: every one but public, s-maxage and proxy-revalidate (shared caches only) and
// private (the answer carries it unqualified, which is stricter than private="field"). Commas
// inside a quoted argument do not split.
inline void keep_directives(std::string_view value, std::string& kept) {
    std::size_t i = 0;
    while (i < value.size()) {
        std::size_t start = i;
        bool quoted = false;
        while (i < value.size() && (quoted || value[i] != ',')) {
            if (value[i] == '"') quoted = !quoted;
            else if (value[i] == '\\' && quoted && i + 1 < value.size()) ++i;
            ++i;
        }
        std::string_view d = value.substr(start, i - start);
        ++i;  // the comma
        while (!d.empty() && (d.front() == ' ' || d.front() == '\t')) d.remove_prefix(1);
        while (!d.empty() && (d.back() == ' ' || d.back() == '\t')) d.remove_suffix(1);
        if (d.empty()) continue;
        const std::string_view name = d.substr(0, d.find('='));
        if (iequal(name, "public") || iequal(name, "s-maxage") || iequal(name, "proxy-revalidate") || iequal(name, "private")) continue;
        if (!kept.empty()) kept.append(", ");
        kept.append(d);
    }
}

}  // namespace agensio::private_cache
