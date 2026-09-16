// HTTP/1.1 chunked transfer coding (RFC 9112 section 7.1): the encoder side used by the
// response writer for bodies of unknown length. The request-body decoder arrives with A3.
#pragma once

#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace agensio {

// "0\r\n\r\n": the last-chunk line plus the empty trailer section.
inline constexpr std::string_view kLastChunk = "0\r\n\r\n";

using ChunkSizeBuffer = std::array<char, 20>;  // 16 hex digits + CRLF

// Formats the chunk-size line "<hex>\r\n" for a chunk of n bytes into buf.
inline std::string_view chunk_size_line(std::uint64_t n, ChunkSizeBuffer& buf) noexcept {
    auto r = std::to_chars(buf.data(), buf.data() + 16, n, 16);
    *r.ptr++ = '\r';
    *r.ptr++ = '\n';
    return std::string_view(buf.data(), static_cast<std::size_t>(r.ptr - buf.data()));
}

}  // namespace agensio
