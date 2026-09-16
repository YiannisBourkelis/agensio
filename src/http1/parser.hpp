// Incremental HTTP/1.x request-head parser over a contiguous buffer.
// Zero-copy: the Request only holds string_views into the caller's buffer.
#pragma once

#include <cstddef>
#include <string_view>

#include "core/request.hpp"

namespace agensio {

enum class ParseStatus {
    complete,               // Request filled, Request::length bytes consumed
    incomplete,             // need more data
    bad_request,            // malformed; respond 400 and close
    version_not_supported,  // HTTP major version != 1
    too_many_headers,       // more than kMaxHeaderCount fields; respond 431 and close
};

// Hard limits that do not depend on configuration.
inline constexpr std::size_t kMaxHeaderCount = Headers::kCapacity;
inline constexpr std::size_t kMaxContentLengthDigits = 19;  // fits in 64 bits

// Parses one request from buf. Never touches bytes past the end of the head.
// Rejects (bad_request) everything RFC 9112 says a server must not accept silently:
// obs-fold continuation lines, bare CR inside a line, control characters in field
// values, invalid characters in field names, whitespace before the colon, duplicate
// or conflicting Content-Length, Content-Length together with Transfer-Encoding,
// Transfer-Encoding on HTTP/1.0, duplicate Host, and Host with forbidden characters.
ParseStatus parse_request(std::string_view buf, Request& out) noexcept;

// Case-insensitive ASCII compare.
bool iequals(std::string_view a, std::string_view b) noexcept;
// True if the comma-separated header value contains token (case-insensitive).
bool has_token(std::string_view value, std::string_view token) noexcept;

}  // namespace agensio
