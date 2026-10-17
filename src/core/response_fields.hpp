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
    const bool guarded = s.auth.protected_path;
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
    std::uint64_t no_store = 0, priv = 0, no_cache = 0;  // per decision, the restrictions of its copies
    std::uint8_t cache_control = 0;            // the restrictions of the answer's Cache-Control
    bool has_cache_control = false;
    bool personal = false;                     // one user's: it sets a cookie, or answers a request with Authorization
    std::uint64_t stands = 0;                  // cache decisions that give way: the application's copies stay, the rule's line goes
    bool cache_control_kept = false;           // the application's Cache-Control goes out
};

// Before the loop, each field the answer will carry (the application's, then a location's
// add_headers).
inline void note_cache(const HeaderSet& hs, std::string_view name, std::string_view value, Upstream& u) noexcept {
    if (Headers::iequals(name, "set-cookie")) {
        u.personal = true;
        return;
    }
    const bool cc = Headers::iequals(name, "cache-control");
    if (!cc && !private_cache::shared_only_field(name)) return;
    const std::uint8_t bits = private_cache::restrictions(value, true);
    if (cc) {
        u.has_cache_control = true;
        u.cache_control |= bits;
    }
    const int i = find(hs, name);
    if (i < 0) return;
    const std::uint64_t b = bit(static_cast<std::size_t>(i));
    u.carried |= b;
    if (bits & private_cache::kNoStore) u.no_store |= b;
    if (bits & private_cache::kPrivate) u.priv |= b;
    if (bits & private_cache::kNoCache) u.no_cache |= b;
}

// Then which cache decisions give way (docs/headers.md 2.4): a rule's set or remove whose value does
// not hold the restrictions of the application's copies (RFC 9111 5.2.2), and a rule's field
// only shared caches read where the answer has none and its Cache-Control restricts, since a CDN
// follows that field in place of Cache-Control (RFC 9213 2.2).
inline void settle(const HeaderSet& hs, Upstream& u) noexcept {
    bool cc_decided = false;
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (!d.cache_field || d.own_only) continue;
        const std::uint64_t b = bit(i);
        const bool carried = u.carried & b;
        if (d.verb == FieldDecision::Verb::fallback && carried) continue;  // the application's copy answers it
        if (d.verb == FieldDecision::Verb::remove && !carried) continue;
        std::uint8_t app = d.cache_control ? u.cache_control : 0;
        if (!d.cache_control)
            app = carried ? static_cast<std::uint8_t>(((u.no_store & b) ? private_cache::kNoStore : 0) | ((u.priv & b) ? private_cache::kPrivate : 0) |
                                                      ((u.no_cache & b) ? private_cache::kNoCache : 0))
                          : u.cache_control;
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
// and where that leaves the answer no Cache-Control at all (a rule's remove of it included) it gets
// Cache-Control: private.
inline void append_upstream(std::string& out, const HeaderSet& hs, bool guarded, const Upstream& u) {
    bool left_out = false, cc_sent = false;
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (d.verb == FieldDecision::Verb::remove || (guarded && d.cache_field) || d.own_only || (u.stands & bit(i))) continue;
        if (d.verb == FieldDecision::Verb::fallback && (u.present & bit(i))) continue;
        if (u.personal && d.lifetime) {
            if (!d.cache_control) {
                left_out = true;
                continue;
            }
            out.append(d.name).append(": ").append(d.private_value).append("\r\n");
            cc_sent = true;
            continue;
        }
        cc_sent = cc_sent || d.cache_control;
        out.append(d.name).append(": ").append(d.value).append("\r\n");
    }
    if (left_out && !cc_sent && !u.cache_control_kept) out.append("Cache-Control: private\r\n");
}

}  // namespace agensio::response_fields
