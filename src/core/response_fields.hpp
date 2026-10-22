// Applying a site's [[site.response_headers]] (core/response_rules.hpp, docs/headers.md 1) to an
// answer, field by field, as it leaves: the handler's fields first, then the site's decisions
// (remove, set, default), then the guards no rule loosens. An application's answer is decided in
// the loop that already reads its fields (handlers/upstream_common.cpp, keep_upstream and
// append_upstream), which marks it Response::fields_decided; agensio's own answers (a file, an
// error page, a redirect, a 401 or 403) are decided where each writer sends the extra fields
// (apply). A request without a node, the case of every site without rules, costs one test.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "core/headers.hpp"
#include "core/private_cache.hpp"
#include "core/response_rules.hpp"
#include "core/stream.hpp"

namespace agensio::response_fields {

inline bool success(int status) noexcept { return (status >= 200 && status < 300) || status == 304; }

inline std::uint64_t bit(std::size_t i) noexcept { return std::uint64_t{1} << i; }

// The decision for `name`, or -1.
inline int find(const HeaderSet& hs, std::string_view name) noexcept {
    for (std::size_t i = 0; i < hs.fields.size(); ++i)
        if (Headers::iequals(hs.fields[i].name, name)) return static_cast<int>(i);
    return -1;
}

// The set a writer applies to agensio's own answer, or null: no rules for the path, or an
// application's answer the upstream loop has decided.
inline const HeaderSet* pending(const Stream& s) noexcept {
    if (!s.header_node || s.response.fields_decided) return nullptr;
    const bool ok = success(s.response.status);
    const HeaderSet& hs = s.header_ending ? (ok ? s.header_ending->success : s.header_ending->other)
                                          : (ok ? s.header_node->success : s.header_node->other);
    return hs.empty() ? nullptr : &hs;
}

// The static handler answers with a file (its name on disk, before a pre-compressed twin): the
// node's sets for its ending, when a rule names it (endings, docs/headers.md 2.1). One test on a
// node without endings.
inline void served_file(Stream& s, std::string_view file) noexcept {
    if (s.header_node && !s.header_node->by_ending.empty()) s.header_ending = response_rules::ending_sets(*s.header_node, file);
}

// Whether the HTTP/1 writer may send hs.h1 as it is: the answer has nothing for the rules to look
// at (no extra field, no field of agensio's own in its block, no password guard).
inline bool plain(const Stream& s) noexcept {
    return s.response.headers.empty() && !s.response.own_fields && !s.auth.protected_path;
}

// For agensio's own answer: emit(name, value) for each extra field the rules leave, then the rules'
// set fields and the defaults no copy answered. A field agensio wrote into its own block
// (Response::own_fields: no-store on a 401, 403 or 421, Retry-After on a 503) stands: no rule
// replaces or removes it, and it answers a default. Behind a password the guard decides
// Cache-Control and the fields only shared caches read.
template <class Emit>
void apply(const Stream& s, const HeaderSet& hs, Emit&& emit) {
    const Response& r = s.response;
    // Behind a password the guard decides the cache fields; for a file still being written, its no-store.
    const bool guarded = s.auth.protected_path || r.unsettled_file;
    std::uint64_t present = 0;
    if (r.own_fields) {
        std::string_view text = r.prebuilt_headers;
        while (!text.empty()) {
            const std::size_t eol = text.find("\r\n");
            const std::string_view line = text.substr(0, eol);
            text = eol == std::string_view::npos ? std::string_view() : text.substr(eol + 2);
            if (const std::size_t colon = line.find(':'); colon != std::string_view::npos)
                if (const int i = find(hs, line.substr(0, colon)); i >= 0) present |= bit(static_cast<std::size_t>(i));
        }
    }
    const std::uint64_t standing = present;
    for (const HeaderField& h : r.headers) {
        if (const int i = find(hs, h.name); i >= 0) {
            const FieldDecision& d = hs.fields[static_cast<std::size_t>(i)];
            if (!(guarded && d.cache_field) && !(standing & bit(static_cast<std::size_t>(i)))) {
                if (d.verb != FieldDecision::Verb::fallback) continue;  // set and remove: this copy goes
                present |= bit(static_cast<std::size_t>(i));
            }
        }
        emit(h.name, h.value);
    }
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (d.verb == FieldDecision::Verb::remove || (guarded && d.cache_field) || (standing & bit(i))) continue;
        if (d.verb == FieldDecision::Verb::fallback && (present & bit(i))) continue;
        emit(std::string_view(d.name), std::string_view(d.value));
    }
}

// What the upstream loop knows of an application's answer while it decides its fields.
struct Upstream {
    std::uint64_t present = 0;  // the defaults a copy of the application's answered
    // Read before the loop on a set with cache decisions (HeaderSet::cache_watch; note_cache, then
    // settle), never behind a password, whose guard decides the cache fields:
    std::uint64_t carried = 0;                 // the cache decisions whose field the answer carries
    std::uint8_t cache_control = 0;            // the restrictions of the answer's Cache-Control
    std::uint8_t cdn = 0;                      // of its fields only shared caches read, all of them together
    bool has_cache_control = false;
    bool personal = false;                     // one user's: it sets a cookie, varies on Cookie or Authorization
                                               // (or is Vary: *), or answers a request with Authorization
    std::uint64_t stands = 0;                  // cache decisions that give way: the application's copies stay, the rule's line goes
    bool cache_control_kept = false;           // the application's Cache-Control goes out
};

// Before the loop, each field the answer will carry (the application's, then a location's
// add_headers). Vary naming Cookie or Authorization says the answer depends on who asks, and
// Vary: * that no cache can reuse it (RFC 9110 12.5.5, RFC 9111 4.1); a CDN that does not key its
// cache on them would hand it to the next visitor, so it is one user's answer like a cookie's.
inline void note_cache(const HeaderSet& hs, std::string_view name, std::string_view value, Upstream& u) noexcept {
    if (Headers::iequals(name, "set-cookie")) {
        u.personal = true;
        return;
    }
    if (Headers::iequals(name, "vary")) {
        private_cache::for_each_directive(value, [&](std::string_view member) {
            if (member == "*" || Headers::iequals(member, "cookie") || Headers::iequals(member, "authorization")) u.personal = true;
        });
        return;
    }
    const bool cc = Headers::iequals(name, "cache-control");
    const bool shared = !cc && private_cache::shared_only_field(name);
    if (cc || shared) {
        const std::uint8_t bits = private_cache::restrictions(value, true);
        if (cc) {
            u.has_cache_control = true;
            u.cache_control |= bits;
        } else {
            u.cdn |= bits;
        }
    } else if (!Headers::iequals(name, "expires")) {
        return;
    }
    if (const int i = find(hs, name); i >= 0) u.carried |= bit(static_cast<std::size_t>(i));
}

// Then which cache decisions give way (docs/headers.md 2.4):
// - a rule's Cache-Control set or remove whose value does not hold the restrictions of the
//   application's (RFC 9111 5.2.2);
// - a rule's field only shared caches read, set or default, over a restriction in any of the
//   application's such fields or, where it has none of the rule's, in its Cache-Control: a CDN
//   reads the first field of its own list and ignores the others and Cache-Control (RFC 9213 2.2;
//   Fastly and Varnish read Surrogate-Control, and Varnish then no longer looks for private), so
//   the application's word to one CDN holds for every CDN field a rule adds;
// - a rule's Expires over any of those restrictions: the application's max-age or s-maxage
//   overrides it anyway (RFC 9111 5.3), and over a bare private it would give a lifetime the
//   application did not give.
inline void settle(const HeaderSet& hs, Upstream& u) noexcept {
    bool cc_decided = false;
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (!(d.cache_field || d.expires) || d.own_only) continue;
        const std::uint64_t b = bit(i);
        const bool carried = u.carried & b;
        if (d.verb == FieldDecision::Verb::fallback && carried) continue;  // the application's copy answers it
        if (d.verb == FieldDecision::Verb::remove && !carried) continue;
        const std::uint8_t app = d.cache_control ? u.cache_control
                                 : d.expires    ? static_cast<std::uint8_t>(u.cache_control | u.cdn)
                                                : static_cast<std::uint8_t>(u.cdn | (carried ? 0 : u.cache_control));
        if (app && !private_cache::covers(d.restricts, app)) u.stands |= b;
        if (d.cache_control) cc_decided = d.verb != FieldDecision::Verb::fallback && !(u.stands & b);
    }
    u.cache_control_kept = u.has_cache_control && !cc_decided;
}

// For an application's answer, in the upstream loop: whether its field (or a location's
// add_headers field) goes out; a set or remove decision drops every copy, and a copy answers a
// default. Behind a password the guard decides the cache fields; a decision for agensio's own
// answers (the baseline's nosniff) leaves the application's field as it is; a cache decision
// that gives way keeps it.
inline bool keep_upstream(const HeaderSet& hs, std::string_view name, bool guarded, Upstream& u) noexcept {
    const int i = find(hs, name);
    if (i < 0) return true;
    const FieldDecision& d = hs.fields[static_cast<std::size_t>(i)];
    if ((guarded && d.cache_field) || d.own_only || (u.stands & bit(static_cast<std::size_t>(i)))) return true;
    if (d.verb != FieldDecision::Verb::fallback) return false;
    u.present |= bit(static_cast<std::size_t>(i));
    return true;
}

// Then the rules' own lines, into the answer's text block. On an answer that is one user's, a
// lifetime decision is left out, a Cache-Control one sent private in its place (RFC 9111 7.3, 3.5),
// and where the rules leave it no Cache-Control at all, by leaving a lifetime out or by a remove of
// the application's, it gets Cache-Control: private: without one a 200 is heuristically cacheable
// (4.2.2), and 7.3 asks a server to say what a cookie's answer may become.
inline void append_upstream(std::string& out, const HeaderSet& hs, bool guarded, const Upstream& u) {
    bool needs_private = false, cc_sent = false;  // a lifetime left out, or the application's Cache-Control removed
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (d.verb == FieldDecision::Verb::remove && d.cache_control && !guarded && !(u.stands & bit(i))) needs_private = true;
        if (d.verb == FieldDecision::Verb::remove || (guarded && d.cache_field) || d.own_only || (u.stands & bit(i))) continue;
        if (d.verb == FieldDecision::Verb::fallback && (u.present & bit(i))) continue;
        if (u.personal && d.lifetime) {
            if (!d.cache_control) {
                needs_private = true;
                continue;
            }
            out.append(d.name).append(": ").append(d.private_value).append("\r\n");
            cc_sent = true;
            continue;
        }
        cc_sent = cc_sent || d.cache_control;
        out.append(d.name).append(": ").append(d.value).append("\r\n");
    }
    if (u.personal && needs_private && !cc_sent && !u.cache_control_kept) out.append("Cache-Control: private\r\n");
}

}  // namespace agensio::response_fields
