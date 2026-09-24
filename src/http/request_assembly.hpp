// Request assembly from a decoded field section, shared by HTTP/2 (RFC 9113 8.3) and
// HTTP/3 (RFC 9114 4.3): the pseudo-header rules, the field rules of core/fields.hpp run
// once per dynamic-table entry (the entry's mark), the host and cookie bookkeeping, and,
// once the section is complete, the checks that need the whole section, the cookie join,
// the Request's method, target, host and protocol, and the fields of interest by length.
// The connections own the decoding (HPACK or QPACK), the arenas and the error codes;
// this is the one copy of the rules in between (design-http3 section 4).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "core/fields.hpp"
#include "core/headers.hpp"
#include "core/request.hpp"
#include "http/field_codec.hpp"

namespace agensio::http {

struct RequestSeen {
    std::string_view method, scheme, path, authority, host;
    unsigned pseudo = 0;
    bool regular = false, bad = false, overflow = false, host_field = false;
    unsigned cookies = 0;
    std::size_t cookie_bytes = 0;
    const char* reason = "";

    void reset() noexcept { *this = RequestSeen{}; }
    // The section's bytes moved (decoded into a scratch, kept in the stream's arena).
    void rebase(const char* from, std::size_t len, const char* to) noexcept {
        for (std::string_view* v : {&method, &scheme, &path, &authority, &host}) Headers::rebase_view(*v, from, len, to);
    }
};

// The decode sink for a request's fields. Always returns true: a bad field is recorded
// with its reason and the decode goes on, so the codec's table stays in step with the
// peer's whatever the request was.
inline bool sink_field(RequestSeen& seen, Request& req, std::string_view n, std::string_view v, codec::Origin o) noexcept {
    if (!n.empty() && n.front() == ':') {
        if (seen.regular) { seen.bad = true; seen.reason = "pseudo-header after a regular field"; return true; }
        std::string_view* slot = n == ":method" ? &seen.method : n == ":scheme" ? &seen.scheme
                               : n == ":path" ? &seen.path : n == ":authority" ? &seen.authority : nullptr;
        if (!slot) { seen.bad = true; seen.reason = "unknown or response pseudo-header"; return true; }
        if (!slot->empty() || (slot == &seen.authority && seen.pseudo & 8)) { seen.bad = true; seen.reason = "duplicate pseudo-header"; return true; }
        *slot = v;
        seen.pseudo |= slot == &seen.method ? 1 : slot == &seen.scheme ? 2 : slot == &seen.path ? 4 : 8;
        return true;
    }
    seen.regular = true;
    // The field rules run once per dynamic-table entry (its mark) and not for the syntax
    // of a static pair; the connection-specific rule still runs for those
    // (transfer-encoding is in the static tables).
    if (!(o.checked && *o.checked)) {
        if (!o.static_table) {
            if (!fields::valid_name(n)) { seen.bad = true; seen.reason = "field name not a lower-case token"; return true; }
            if (!fields::valid_value(v)) { seen.bad = true; seen.reason = "field value with CR, LF, NUL or edge whitespace"; return true; }
        }
        if (fields::connection_specific(n)) { seen.bad = true; seen.reason = "connection-specific field"; return true; }
        if (n == "te" && v != "trailers") { seen.bad = true; seen.reason = "te other than trailers"; return true; }
        if (o.checked) *o.checked = 1;
    }
    if (n == "host") {
        if (seen.host_field) { seen.bad = true; seen.reason = "duplicate host"; return true; }
        seen.host_field = true;
        seen.host = v;
    }
    if (n == "cookie") {
        ++seen.cookies;
        seen.cookie_bytes += v.size() + 2;
        if (seen.cookies > 1) return true;  // joined by finish_request
    }
    if (!req.headers.add(n, v)) seen.overflow = true;
    return true;
}

enum class Assembled {
    ok,
    malformed,           // seen.reason says what; the stream is malformed (RFC 9113 8.1.1, RFC 9114 4.1.2)
    bad_content_length,  // not a number, or over 19 digits
};

// After the decode (and the rebase, when the bytes moved): the rules that need the whole
// section, then the Request filled for the handlers. `cookie` receives the joined cookie
// crumbs when there were several (RFC 9113 8.2.3, RFC 9114 4.2.1). `length_known` and
// `content_length` report a content-length field. An overflow (too many fields) is the
// caller's to answer with 431 before calling this.
inline Assembled finish_request(RequestSeen& seen, Request& req, std::string& cookie, std::string_view protocol,
                                bool& length_known, std::uint64_t& content_length) {
    if (!seen.bad) {
        if (seen.method.empty() || seen.scheme.empty() || seen.path.empty()) seen.bad = true, seen.reason = "missing :method, :scheme or :path";
        else if (seen.path == "*" ? seen.method != "OPTIONS" : seen.path.front() != '/') seen.bad = true, seen.reason = ":path not absolute";
        else if (seen.authority.empty() && seen.host.empty()) seen.bad = true, seen.reason = "no :authority and no host";
        else if (!seen.authority.empty() && !seen.host.empty() && seen.authority != seen.host) seen.bad = true, seen.reason = ":authority and host differ";
    }
    if (seen.bad) return Assembled::malformed;
    if (seen.cookies > 1) {  // one field, "; " between the crumbs
        cookie.clear();
        cookie.reserve(seen.cookie_bytes);
        Headers joined;
        for (const HeaderField& f : req.headers) {
            if (f.name != "cookie") { joined.add(f.name, f.value); continue; }
            if (!cookie.empty()) cookie.append("; ");
            cookie.append(f.value);
        }
        // The crumbs beyond the first were never added; every cookie value collected here.
        req.headers = joined;
        req.headers.add("cookie", cookie);
    }
    req.method_name = seen.method;
    if (!parse_method(seen.method, req.method)) req.method = Method::other;
    req.target = seen.path;
    req.host = seen.authority.empty() ? seen.host : seen.authority;
    if (!seen.host_field) req.headers.add("host", req.host);  // handlers see HTTP/1's shape (HTTP_HOST)
    req.version_minor = 1;
    req.protocol = protocol;
    req.keep_alive = true;
    req.length = 1;  // "a request exists" for the log on close
    length_known = false;
    content_length = 0;
    for (const HeaderField& f : req.headers) {
        switch (f.name.size()) {  // the fields of interest, by length first
            case 5: if (f.name == "range") req.range = f.value; break;
            case 8: if (f.name == "if-range") req.if_range = f.value; break;
            case 13: if (f.name == "if-none-match") req.if_none_match = f.value; break;
            case 15: if (f.name == "accept-encoding") req.accept_encoding = f.value; break;
            case 17: if (f.name == "if-modified-since") req.if_modified_since = f.value; break;
            case 14:
                if (f.name == "content-length") {
                    std::uint64_t n = 0;
                    if (f.value.empty() || f.value.size() > 19) return Assembled::bad_content_length;
                    for (const char c : f.value) {
                        if (c < '0' || c > '9') return Assembled::bad_content_length;
                        n = n * 10 + static_cast<std::uint64_t>(c - '0');
                    }
                    length_known = true;
                    content_length = n;
                }
                break;
            default: break;
        }
    }
    return Assembled::ok;
}

}  // namespace agensio::http
