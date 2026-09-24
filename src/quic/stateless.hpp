// What an endpoint answers without a connection (RFC 9000 8.1.2, 10.3, 17.2.5): the
// Retry packet with its sealed token, the stateless reset for an id nobody knows, the
// INVALID_TOKEN close for a token that does not open; and the client's address as the
// bytes a token is bound to.
#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "quic/crypto.hpp"
#include "quic/frames.hpp"
#include "quic/packet.hpp"

namespace agensio::quic {

// The address and port of a peer as bytes (6 for IPv4, 18 for IPv6), what a Retry token
// is sealed with (RFC 9000 8.1.4: the token proves the address did not change).
inline std::size_t address_bytes(const sockaddr_storage& a, unsigned char out[18]) noexcept {
    if (a.ss_family == AF_INET) {
        const auto* s = reinterpret_cast<const sockaddr_in*>(&a);
        std::memcpy(out, &s->sin_addr, 4);
        std::memcpy(out + 4, &s->sin_port, 2);
        return 6;
    }
    if (a.ss_family == AF_INET6) {
        const auto* s = reinterpret_cast<const sockaddr_in6*>(&a);
        std::memcpy(out, &s->sin6_addr, 16);
        std::memcpy(out + 16, &s->sin6_port, 2);
        return 18;
    }
    return 0;
}

// True when only the port differs (a NAT rebinding, RFC 9000 9.4 keeps the congestion state).
inline bool same_address(const sockaddr_storage& a, const sockaddr_storage& b) noexcept {
    if (a.ss_family != b.ss_family) return false;
    if (a.ss_family == AF_INET)
        return std::memcmp(&reinterpret_cast<const sockaddr_in*>(&a)->sin_addr, &reinterpret_cast<const sockaddr_in*>(&b)->sin_addr, 4) == 0;
    if (a.ss_family == AF_INET6)
        return std::memcmp(&reinterpret_cast<const sockaddr_in6*>(&a)->sin6_addr, &reinterpret_cast<const sockaddr_in6*>(&b)->sin6_addr, 16) == 0;
    return false;
}

// A Retry packet (17.2.5): to the client's source id, from the new id we choose, the
// token, the integrity tag over the pseudo-packet with the original destination id.
inline std::size_t build_retry(unsigned char* out, std::size_t cap, const Cid& odcid, const Cid& client_scid, const Cid& new_scid,
                               std::string_view token) noexcept {
    const std::size_t need = 1 + 4 + 1 + client_scid.len + 1 + new_scid.len + token.size() + 16;
    if (cap < need || token.empty()) return 0;
    unsigned char rnd = 0;
    random_bytes(&rnd, 1);
    std::size_t pos = 0;
    out[pos++] = static_cast<unsigned char>(0xf0 | (rnd & 0x0f));  // long header, fixed bit, type 3, the unused bits random
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 1;
    out[pos++] = client_scid.len;
    std::memcpy(out + pos, client_scid.bytes, client_scid.len);
    pos += client_scid.len;
    out[pos++] = new_scid.len;
    std::memcpy(out + pos, new_scid.bytes, new_scid.len);
    pos += new_scid.len;
    std::memcpy(out + pos, token.data(), token.size());
    pos += token.size();
    if (!retry_tag(odcid, out, pos, out + pos)) return 0;
    return pos + 16;
}

// A stateless reset of n bytes (10.3): random with the fixed bits of a short header, the
// token of the id last. The caller sizes it below the packet it answers.
inline void build_stateless_reset(unsigned char* out, std::size_t n, const Cid& dcid) noexcept {
    random_bytes(out, n - 16);
    out[0] = static_cast<unsigned char>(0x40 | (out[0] & 0x3f));
    reset_token(dcid, out + n - 16);
}

// The answer to an Initial whose Retry token does not open (8.1.2): one Initial packet
// under the keys the client derives from its destination id, closing with INVALID_TOKEN,
// so the client fails at once instead of at its timeout. No state is kept.
inline std::size_t build_invalid_token_close(unsigned char* out, std::size_t cap, const PacketHeader& h) noexcept {
    unsigned char client_secret[32], server_secret[32];
    Keys tx;
    if (!initial_secrets(h.dcid, client_secret, server_secret) || !tx.install(Suite::aes128gcm, server_secret, 32, true)) return 0;
    constexpr std::string_view reason = "invalid token";
    const std::size_t need = 1 + 4 + 1 + h.scid.len + 1 + h.dcid.len + 1 + 2 + 1 + 4 + reason.size() + kAeadTagLen + 8;
    if (cap < need) return 0;
    std::size_t pos = 0;
    out[pos++] = 0xc0;  // Initial, a 1-byte packet number
    out[pos++] = 0; out[pos++] = 0; out[pos++] = 0; out[pos++] = 1;
    out[pos++] = h.scid.len;
    std::memcpy(out + pos, h.scid.bytes, h.scid.len);
    pos += h.scid.len;
    out[pos++] = h.dcid.len;
    std::memcpy(out + pos, h.dcid.bytes, h.dcid.len);
    pos += h.dcid.len;
    out[pos++] = 0;  // token length
    const std::size_t len_pos = pos;
    pos += 2;
    const std::size_t pn_offset = pos;
    out[pos++] = 0;  // packet number 0
    const std::size_t w = put_connection_close(out + pos, cap - pos - kAeadTagLen, false, err::invalid_token, 0, reason);
    if (!w) return 0;
    write_varint_fixed(out + len_pos, 1 + w + kAeadTagLen, 2);
    if (!tx.seal(0, out, pos, w)) return 0;
    unsigned char mask[5];
    if (!tx.mask(out + pn_offset + 4, mask)) return 0;
    protect_header(out, pn_offset, 1, true, mask);
    return pos + w + kAeadTagLen;
}

}  // namespace agensio::quic
