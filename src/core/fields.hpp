// Field rules shared by HTTP/2 (RFC 9113 section 8.2) and HTTP/3 (RFC 9114 section 4.2):
// what a name may look like, what a value may contain, and which fields belong to the
// connection and must not appear at all. HTTP/1 has its own rules in its parser (the
// syntax differs: case-insensitive names, obs-fold); these are applied while an HPACK or
// QPACK block is decoded, so nothing invalid ever reaches a handler, php-fpm or an origin
// (the 2021 HTTP/2-to-HTTP/1.1 smuggling class is exactly a line break in a value).
#pragma once

#include <string_view>

namespace agensio::fields {

// RFC 9110 token characters, lower-case letters only (RFC 9113 8.2.1: an upper-case
// letter makes the field malformed). A pseudo-header's ':' is handled by the caller.
inline bool valid_name(std::string_view name) noexcept {
    if (name.empty()) return false;
    for (const unsigned char c : name) {
        if (c >= 'a' && c <= 'z') continue;
        if (c >= '0' && c <= '9') continue;
        switch (c) {
            case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-': case '.':
            case '^': case '_': case '`': case '|': case '~':
                continue;
            default: return false;
        }
    }
    return true;
}

// No NUL, CR or LF anywhere; no leading or trailing space or tab (RFC 9113 8.2.1).
inline bool valid_value(std::string_view value) noexcept {
    for (const unsigned char c : value)
        if (c == 0 || c == '\r' || c == '\n') return false;
    if (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.back() == ' ' || value.back() == '\t'))
        return false;
    return true;
}

// The pseudo-headers and `host`. Their values are field values like any other (RFC 9113 8.2.1,
// RFC 9114 4.2) and more: they are what HTTP/1 carries in its request line and its Host field,
// and what agensio writes there for an origin (RFC 9113 10.3, RFC 9114 10.3, the intermediary
// encapsulation attacks). An HPACK or QPACK string holds any byte; a request line holds no
// space and no control character, so the rule here is the HTTP/1 parser's own
// (`http1/parser.cpp`), byte for byte, held equal by the unit test: nothing reaches a handler
// over HTTP/2 or HTTP/3 that HTTP/1 could not have carried. Until 0.1.0-alpha.146 these four
// were stored as they came and the target was looked at only up to its "?".

// A request target: no space, no control character, no DEL (HTTP/1: the request line's rule).
inline bool valid_target(std::string_view value) noexcept {
    for (const unsigned char c : value)
        if (c <= 0x20 || c == 0x7f) return false;
    return true;
}

// :authority and host: the same, and none of the delimiters HTTP/1's Host is refused for.
inline bool valid_host(std::string_view value) noexcept {
    for (const unsigned char c : value)
        if (c <= 0x20 || c == 0x7f || c == '/' || c == '\\' || c == '"' || c == '<' || c == '>') return false;
    return true;
}

// :method: a token (RFC 9110 9.1), either case.
inline bool valid_method(std::string_view value) noexcept {
    for (const unsigned char c : value) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) continue;
        switch (c) {
            case '!': case '#': case '$': case '%': case '&': case '\'': case '*': case '+': case '-': case '.':
            case '^': case '_': case '`': case '|': case '~':
                continue;
            default: return false;
        }
    }
    return true;
}

// :scheme: a letter, then letters, digits, "+", "-", "." (RFC 3986 3.1).
inline bool valid_scheme(std::string_view value) noexcept {
    for (std::size_t i = 0; i < value.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(value[i]);
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) continue;
        if (i > 0 && ((c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.')) continue;
        return false;
    }
    return true;
}

// Connection-specific fields are malformed in HTTP/2 and HTTP/3 (RFC 9113 8.2.2). `te` is
// allowed only with the value "trailers" (checked by the caller).
inline bool connection_specific(std::string_view name) noexcept {
    switch (name.size()) {
        case 7: return name == "upgrade";
        case 10: return name == "connection" || name == "keep-alive";
        case 16: return name == "proxy-connection";
        case 17: return name == "transfer-encoding";
        default: return false;
    }
}

}  // namespace agensio::fields
