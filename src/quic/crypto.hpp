// Packet protection (RFC 9001): the Initial secrets from the client's first destination
// connection id (5.2), the key schedule (5.1), the AEAD that seals and opens packets
// (5.3), header protection (5.4), key updates (6) and the Retry integrity tag (5.8),
// all through OpenSSL's EVP with one context per key initialised once: a packet costs
// the nonce, the associated data, one update and the tag, never a key schedule.
#pragma once

#include <cstddef>
#include <cstdint>

#include <openssl/evp.h>

#include "quic/packet.hpp"

namespace agensio::quic {

enum class Suite : std::uint8_t { aes128gcm = 0, aes256gcm = 1, chacha20 = 2 };

inline std::size_t hash_len(Suite s) noexcept { return s == Suite::aes256gcm ? 48 : 32; }
inline std::size_t key_len(Suite s) noexcept { return s == Suite::aes128gcm ? 16 : 32; }
// TLS 1.3 cipher suite ids (0x1301 AES_128_GCM_SHA256, 0x1302 AES_256_GCM_SHA384, 0x1303 CHACHA20_POLY1305_SHA256).
bool suite_from_tls_id(std::uint32_t id, Suite& out) noexcept;

// The keys of one level in one direction.
class Keys {
public:
    Keys() = default;
    ~Keys() { clear(); }
    Keys(const Keys&) = delete;
    Keys& operator=(const Keys&) = delete;
    Keys(Keys&& o) noexcept { *this = static_cast<Keys&&>(o); }
    Keys& operator=(Keys&& o) noexcept;

    // Derives key, iv and the header-protection key from the traffic secret and prepares
    // the cipher contexts. `for_sending` selects the encrypting direction.
    bool install(Suite s, const unsigned char* secret, std::size_t secret_len, bool for_sending) noexcept;
    bool valid() const noexcept { return aead_ != nullptr; }
    void clear() noexcept;
    Suite suite() const noexcept { return suite_; }
    const unsigned char* secret() const noexcept { return secret_; }
    std::size_t secret_len() const noexcept { return secret_len_; }

    // Seals the packet at pkt: [0, hdr_len) is the header (associated data), then
    // plain_len bytes of plaintext encrypted in place, then the tag written. The nonce is
    // the iv combined with the packet number.
    bool seal(std::uint64_t pn, unsigned char* pkt, std::size_t hdr_len, std::size_t plain_len) noexcept;
    // Opens in place: payload holds len bytes including the tag; plain_len receives the
    // plaintext length. False on a bad tag (the packet is dropped, the failure counted).
    bool open(std::uint64_t pn, const unsigned char* header, std::size_t hdr_len, unsigned char* payload, std::size_t len,
              std::size_t& plain_len) noexcept;
    // The header-protection mask from the 16-byte sample (5.4).
    bool mask(const unsigned char* sample, unsigned char out[5]) noexcept;

    std::uint64_t sealed = 0;    // packets protected with this key (the confidentiality limit, 6.6)
    std::uint64_t failures = 0;  // packets that failed to open (the integrity limit)

private:
    Suite suite_ = Suite::aes128gcm;
    unsigned char secret_[64] = {};
    std::size_t secret_len_ = 0;
    unsigned char iv_[12] = {};
    EVP_CIPHER_CTX* aead_ = nullptr;
    EVP_CIPHER_CTX* hp_ = nullptr;
};

// RFC 9001 5.2: the two Initial traffic secrets (32 bytes each) for version 1.
bool initial_secrets(const Cid& client_dcid, unsigned char client[32], unsigned char server[32]) noexcept;
// The next generation of a traffic secret (RFC 9001 6.1).
bool next_secret(Suite s, const unsigned char* secret, std::size_t len, unsigned char* out) noexcept;
// RFC 9001 5.8: the tag over the Retry pseudo-packet (the original destination id, then
// the Retry packet without its tag).
bool retry_tag(const Cid& odcid, const unsigned char* retry, std::size_t retry_len, unsigned char tag[16]) noexcept;
// Applies (or removes: the operation is its own inverse) header protection with a mask.
inline void protect_header(unsigned char* pkt, std::size_t pn_offset, unsigned pn_len, bool long_form,
                           const unsigned char mask[5]) noexcept {
    pkt[0] ^= static_cast<unsigned char>(mask[0] & (long_form ? 0x0f : 0x1f));
    for (unsigned i = 0; i < pn_len; ++i) pkt[pn_offset + i] ^= mask[1 + i];
}
bool random_bytes(unsigned char* out, std::size_t n) noexcept;

}  // namespace agensio::quic
