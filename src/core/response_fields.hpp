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
    const HeaderSet& hs = success(s.response.status) ? s.header_node->success : s.header_node->other;
    return hs.empty() ? nullptr : &hs;
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

// For an application's answer, in the upstream loop: whether its field (or a location's
// add_headers field) goes out; a set or remove decision drops every copy, and a copy answers a
// default. Behind a password the guard decides the cache fields.
inline bool keep_upstream(const HeaderSet& hs, std::string_view name, bool guarded, std::uint64_t& present) noexcept {
    const int i = find(hs, name);
    if (i < 0) return true;
    const FieldDecision& d = hs.fields[static_cast<std::size_t>(i)];
    if (guarded && d.cache_field) return true;
    if (d.verb != FieldDecision::Verb::fallback) return false;
    present |= bit(static_cast<std::size_t>(i));
    return true;
}

// Then the rules' own lines, into the answer's text block.
inline void append_upstream(std::string& out, const HeaderSet& hs, bool guarded, std::uint64_t present) {
    for (std::size_t i = 0; i < hs.fields.size(); ++i) {
        const FieldDecision& d = hs.fields[i];
        if (d.verb == FieldDecision::Verb::remove || (guarded && d.cache_field)) continue;
        if (d.verb == FieldDecision::Verb::fallback && (present & bit(i))) continue;
        out.append(d.name).append(": ").append(d.value).append("\r\n");
    }
}

}  // namespace agensio::response_fields
