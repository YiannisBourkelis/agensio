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
//
// The same directives decide what a response-header rule may change in an application's answer
// (docs/headers.md 2.4, 2026-10-17, the review's D4): a rule's Cache-Control (or a field only
// shared caches read) that would drop a restriction the application's own carries gives way to it
// (restrictions, covers), and a rule never gives an answer that is one user's, one with Set-Cookie
// (which does not stop a cache, RFC 9111 7.3) or to a request with Authorization (3.5), a
// lifetime a shared cache may use (shared_lifetime): it is sent private in its place.
#pragma once

#include <cstdint>
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

// Calls f(directive) for each directive of a Cache-Control value, trimmed, empty ones skipped.
// Commas inside a quoted argument do not split (RFC 9110 5.6.4).
template <class F>
void for_each_directive(std::string_view value, F&& f) {
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
        if (!d.empty()) f(d);
    }
}

// The directives of one Cache-Control value a protected answer keeps, appended to `kept` with
// ", " between them: every one but public, s-maxage and proxy-revalidate (shared caches only) and
// private (the answer carries it unqualified, which is stricter than private="field").
inline void keep_directives(std::string_view value, std::string& kept) {
    for_each_directive(value, [&](std::string_view d) {
        const std::string_view name = d.substr(0, d.find('='));
        if (iequal(name, "public") || iequal(name, "s-maxage") || iequal(name, "proxy-revalidate") || iequal(name, "private")) return;
        if (!kept.empty()) kept.append(", ");
        kept.append(d);
    });
}

// The restrictions a value carries (RFC 9111 5.2.2): no-store, no cache keeps the answer (5.2.2.5);
// private, no shared cache does (5.2.2.7); no-cache, no cache reuses it without asking the origin
// (5.2.2.4). `qualified` counts private="field" and no-cache="field" as the directive: the
// application's restriction on a field is kept whole; a rule's value covers only unqualified.
enum : std::uint8_t { kNoStore = 1, kPrivate = 2, kNoCache = 4 };

inline std::uint8_t restrictions(std::string_view value, bool qualified) noexcept {
    std::uint8_t bits = 0;
    for_each_directive(value, [&](std::string_view d) {
        const std::size_t eq = d.find('=');
        const std::string_view name = d.substr(0, eq);
        if (iequal(name, "no-store")) bits |= kNoStore;
        else if (eq != std::string_view::npos && !qualified) return;
        else if (iequal(name, "private")) bits |= kPrivate;
        else if (iequal(name, "no-cache")) bits |= kNoCache;
    });
    return bits;
}

// Whether a rule's value keeps every restriction of the application's: agensio sends one value, so
// the rule's must hold them (RFC 9111 4.2.1 has a cache honour the most restrictive of conflicting
// directives); no-store holds all three.
inline bool covers(std::uint8_t rule, std::uint8_t application) noexcept {
    return (rule & kNoStore) || (application & ~rule) == 0;
}

// Whether a Cache-Control value lets a shared cache reuse the answer without asking the origin: no
// restriction, and public (5.2.2.9), a shared freshness above 0 (s-maxage, else max-age; 5.2.2.10,
// 5.2.2.1) or an allowance to serve it stale (stale-while-revalidate, stale-if-error, RFC 5861 3
// and 4). An argument that is not a number counts as one above 0.
inline bool shared_lifetime(std::string_view value) noexcept {
    if (restrictions(value, false)) return false;
    bool open = false, has_shared = false, shared = false, max_age = false;
    for_each_directive(value, [&](std::string_view d) {
        const std::size_t eq = d.find('=');
        const std::string_view name = d.substr(0, eq);
        std::string_view arg = eq == std::string_view::npos ? std::string_view() : d.substr(eq + 1);
        if (arg.size() >= 2 && arg.front() == '"' && arg.back() == '"') arg = arg.substr(1, arg.size() - 2);
        const bool above_zero = arg.find_first_not_of('0') != std::string_view::npos;
        if (iequal(name, "public")) open = true;
        else if (iequal(name, "s-maxage")) {
            has_shared = true;
            shared = shared || above_zero;
        } else if (iequal(name, "max-age")) max_age = max_age || above_zero;
        else if (iequal(name, "stale-while-revalidate") || iequal(name, "stale-if-error")) open = open || above_zero;
    });
    return open || (has_shared ? shared : max_age);
}

}  // namespace agensio::private_cache
