// QUIC variable-length integers (RFC 9000 section 16): the two high bits of the first
// byte give the length (1, 2, 4 or 8 bytes), big-endian, at most 2^62 - 1.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace agensio::quic {

inline constexpr std::uint64_t kVarintMax = (std::uint64_t{1} << 62) - 1;

inline std::size_t varint_size(std::uint64_t v) noexcept {
    return v < 64 ? 1 : v < 16384 ? 2 : v < 1073741824 ? 4 : 8;
}

// Writes v in exactly n bytes (1, 2, 4 or 8; the value must fit): a length field
// reserved before its payload is known.
inline void write_varint_fixed(unsigned char* p, std::uint64_t v, unsigned n) noexcept {
    switch (n) {
        case 1: p[0] = static_cast<unsigned char>(v); break;
        case 2:
            p[0] = static_cast<unsigned char>(0x40 | (v >> 8));
            p[1] = static_cast<unsigned char>(v);
            break;
        case 4:
            p[0] = static_cast<unsigned char>(0x80 | (v >> 24));
            p[1] = static_cast<unsigned char>(v >> 16);
            p[2] = static_cast<unsigned char>(v >> 8);
            p[3] = static_cast<unsigned char>(v);
            break;
        default:
            p[0] = static_cast<unsigned char>(0xc0 | (v >> 56));
            for (unsigned i = 1; i < 8; ++i) p[i] = static_cast<unsigned char>(v >> (8 * (7 - i)));
            break;
    }
}

inline unsigned char* write_varint(unsigned char* p, std::uint64_t v) noexcept {
    const unsigned n = static_cast<unsigned>(varint_size(v));
    write_varint_fixed(p, v, n);
    return p + n;
}

inline void append_varint(std::string& out, std::uint64_t v) {
    unsigned char buf[8];
    const unsigned char* end = write_varint(buf, v);
    out.append(reinterpret_cast<const char*>(buf), static_cast<std::size_t>(end - buf));
}

// Reads one at p, advancing it; false when truncated.
inline bool read_varint(const unsigned char*& p, const unsigned char* end, std::uint64_t& v) noexcept {
    if (p >= end) return false;
    const unsigned n = 1u << (p[0] >> 6);
    if (static_cast<std::size_t>(end - p) < n) return false;
    v = p[0] & 0x3f;
    for (unsigned i = 1; i < n; ++i) v = (v << 8) | p[i];
    p += n;
    return true;
}

}  // namespace agensio::quic
