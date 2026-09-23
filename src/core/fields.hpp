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

// Connection-specific fields are malformed in HTTP/2 and HTTP/3 (RFC 9113 8.2.2). `te` is
// allowed only with the value "trailers" (checked by the caller).
inline bool connection_specific(std::string_view name) noexcept {
    return name == "connection" || name == "keep-alive" || name == "proxy-connection" ||
           name == "transfer-encoding" || name == "upgrade";
}

}  // namespace agensio::fields
