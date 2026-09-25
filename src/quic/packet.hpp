// QUIC packet headers (RFC 8999, RFC 9000 section 17): the long header of the handshake
// packets with its version, the two connection ids and, for Initial, the token; the short
// header of 1-RTT packets; the packet number's encoding against the largest acknowledged
// (appendix A.2) and its decoding against the largest received (A.3); Version
// Negotiation. Header protection and the AEAD are crypto.hpp's.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace agensio::quic {

inline constexpr std::uint32_t kVersion1 = 0x00000001;
inline constexpr std::size_t kMaxCidLen = 20;
inline constexpr std::size_t kOurCidLen = 8;      // byte 0 the worker, seven random (design-http3 6.4)
inline constexpr std::size_t kMinInitialDatagram = 1200;
inline constexpr std::size_t kAeadTagLen = 16;
inline constexpr std::size_t kHpSampleLen = 16;

enum class LongType : std::uint8_t { initial = 0, zero_rtt = 1, handshake = 2, retry = 3 };

// Packet number spaces (RFC 9000 12.3); 0-RTT shares the application space.
enum class Space : std::uint8_t { initial = 0, handshake = 1, application = 2 };
inline constexpr unsigned kSpaces = 3;

struct Cid {
    std::uint8_t len = 0;
    unsigned char bytes[kMaxCidLen] = {};
    std::string_view view() const noexcept { return std::string_view(reinterpret_cast<const char*>(bytes), len); }
    bool operator==(const Cid& o) const noexcept { return len == o.len && std::memcmp(bytes, o.bytes, len) == 0; }
    bool operator!=(const Cid& o) const noexcept { return !(*this == o); }
    void assign(const unsigned char* p, std::size_t n) noexcept {
        len = static_cast<std::uint8_t>(n > kMaxCidLen ? kMaxCidLen : n);
        std::memcpy(bytes, p, len);
    }
    // Our ids as the table's 64-bit key (the id is its own hash: seven random bytes).
    std::uint64_t key() const noexcept {
        std::uint64_t k = 0;
        std::memcpy(&k, bytes, kOurCidLen);
        return k;
    }
};

struct PacketHeader {
    bool long_form = false;
    LongType type = LongType::initial;
    std::uint32_t version = 0;
    Cid dcid, scid;
    const unsigned char* token = nullptr;  // Initial: the token (Retry or NEW_TOKEN); Retry: the retry token
    std::size_t token_len = 0;
    std::size_t pn_offset = 0;  // where the packet number begins (the protected part starts here)
    std::size_t length = 0;     // long: the Length field (packet number + payload + tag); short: to the datagram's end
    std::size_t total = 0;      // bytes of this packet in the datagram (long: pn_offset + length)
    bool fixed_bit = false;
    // After header protection removal:
    unsigned pn_len = 0;
    std::uint64_t pn = 0;
    bool key_phase = false;
};

// Parses the unprotected part of the header at [p, p + n) (the start of a packet in a
// datagram; a datagram may hold several, RFC 9000 12.2). `short_dcid_len` is the length
// of our ids. False on a header that is malformed or too short: the packet is dropped.
inline bool parse_header(const unsigned char* p, std::size_t n, std::size_t short_dcid_len, PacketHeader& h) noexcept {
    if (n < 1) return false;
    const unsigned char first = p[0];
    h.fixed_bit = (first & 0x40) != 0;
    h.long_form = (first & 0x80) != 0;
    if (!h.long_form) {
        if (n < 1 + short_dcid_len + 1 + kAeadTagLen) return false;
        h.dcid.assign(p + 1, short_dcid_len);
        h.pn_offset = 1 + short_dcid_len;
        h.length = n - h.pn_offset;
        h.total = n;
        return true;
    }
    if (n < 7) return false;
    h.version = (static_cast<std::uint32_t>(p[1]) << 24) | (static_cast<std::uint32_t>(p[2]) << 16) |
                (static_cast<std::uint32_t>(p[3]) << 8) | p[4];
    std::size_t pos = 5;
    const std::size_t dl = p[pos++];
    if (dl > kMaxCidLen || pos + dl > n) return false;
    h.dcid.assign(p + pos, dl);
    pos += dl;
    if (pos >= n) return false;
    const std::size_t sl = p[pos++];
    if (sl > kMaxCidLen || pos + sl > n) return false;
    h.scid.assign(p + pos, sl);
    pos += sl;
    if (h.version != kVersion1) {
        // Version Negotiation (RFC 8999 6: a server never receives one) or a version we do
        // not speak: only the invariant fields are parsed (RFC 8999 5.1), the rest is
        // opaque, and the endpoint answers a datagram of 1,200 bytes or more with Version
        // Negotiation (RFC 9000 5.2.2). Reading the rest by version 1's rules dropped every
        // such packet, which the interop runner's readiness probe found.
        h.pn_offset = pos;
        h.length = n - pos;
        h.total = n;
        return true;
    }
    h.type = static_cast<LongType>((first >> 4) & 0x3);
    if (h.type == LongType::retry) {  // a server never receives one either
        h.pn_offset = pos;
        h.length = n - pos;
        h.total = n;
        return true;
    }
    auto varint = [&](std::uint64_t& v) -> bool {
        if (pos >= n) return false;
        const unsigned len = 1u << (p[pos] >> 6);
        if (pos + len > n) return false;
        v = p[pos] & 0x3f;
        for (unsigned i = 1; i < len; ++i) v = (v << 8) | p[pos + i];
        pos += len;
        return true;
    };
    if (h.type == LongType::initial) {
        std::uint64_t tl = 0;
        if (!varint(tl) || tl > n - pos) return false;
        h.token = p + pos;
        h.token_len = static_cast<std::size_t>(tl);
        pos += static_cast<std::size_t>(tl);
    }
    std::uint64_t len = 0;
    if (!varint(len)) return false;
    if (len < 1 + kAeadTagLen || len > n - pos) return false;
    h.pn_offset = pos;
    h.length = static_cast<std::size_t>(len);
    h.total = pos + h.length;
    return true;
}

// Packet number length for pn given the largest acknowledged (RFC 9002 A.2; none
// acknowledged: 1 + the number's own size).
inline unsigned pn_length(std::uint64_t pn, std::uint64_t largest_acked, bool any_acked) noexcept {
    const std::uint64_t unacked = any_acked ? pn - largest_acked : pn + 1;
    const std::uint64_t range = unacked * 2 + 1;  // "at least twice the number in flight"
    if (range < (1u << 8)) return 1;
    if (range < (1u << 16)) return 2;
    if (range < (1u << 24)) return 3;
    return 4;
}

inline void write_pn(unsigned char* p, std::uint64_t pn, unsigned len) noexcept {
    for (unsigned i = 0; i < len; ++i) p[i] = static_cast<unsigned char>(pn >> (8 * (len - 1 - i)));
}

// RFC 9000 appendix A.3.
inline std::uint64_t decode_pn(std::uint64_t largest_received, bool any_received, std::uint64_t truncated, unsigned pn_bits) noexcept {
    if (!any_received) return truncated;
    const std::uint64_t expected = largest_received + 1;
    const std::uint64_t win = std::uint64_t{1} << pn_bits;
    const std::uint64_t hwin = win / 2;
    const std::uint64_t mask = win - 1;
    const std::uint64_t candidate = (expected & ~mask) | truncated;
    if (candidate + hwin <= expected && candidate < (std::uint64_t{1} << 62) - win) return candidate + win;
    if (candidate > expected + hwin && candidate >= win) return candidate - win;
    return candidate;
}

// A Version Negotiation packet (RFC 9000 17.2.1) answering a client's ids: our supported
// version and one reserved value, so clients tolerate the list (RFC 9000 15).
inline std::size_t build_version_negotiation(unsigned char* out, std::size_t cap, const Cid& to /*the client's scid*/,
                                             const Cid& from /*the client's dcid*/, std::uint32_t reserved,
                                             unsigned char random_first) noexcept {
    const std::size_t need = 1 + 4 + 1 + to.len + 1 + from.len + 8;
    if (cap < need) return 0;
    std::size_t pos = 0;
    out[pos++] = static_cast<unsigned char>(0x80 | (random_first & 0x7f));
    out[pos++] = out[pos++] = out[pos++] = out[pos++] = 0;
    out[pos++] = to.len;
    std::memcpy(out + pos, to.bytes, to.len);
    pos += to.len;
    out[pos++] = from.len;
    std::memcpy(out + pos, from.bytes, from.len);
    pos += from.len;
    for (std::uint32_t v : {kVersion1, reserved}) {
        out[pos++] = static_cast<unsigned char>(v >> 24);
        out[pos++] = static_cast<unsigned char>(v >> 16);
        out[pos++] = static_cast<unsigned char>(v >> 8);
        out[pos++] = static_cast<unsigned char>(v);
    }
    return pos;
}

}  // namespace agensio::quic
