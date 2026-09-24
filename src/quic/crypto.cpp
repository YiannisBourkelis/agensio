#include "quic/crypto.hpp"

#include <cstring>
#include <string>
#include <string_view>

#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace agensio::quic {

namespace {

const EVP_MD* md_of(Suite s) noexcept { return s == Suite::aes256gcm ? EVP_sha384() : EVP_sha256(); }

// HKDF-Expand-Label (RFC 8446 7.1) for outputs of at most one hash block, which every
// QUIC key, iv and secret is: out = HMAC(secret, HkdfLabel || 0x01)[0, len).
bool expand_label(const EVP_MD* md, const unsigned char* secret, std::size_t slen, std::string_view label,
                  unsigned char* out, std::size_t outlen) noexcept {
    unsigned char info[80];
    std::size_t n = 0;
    info[n++] = static_cast<unsigned char>(outlen >> 8);
    info[n++] = static_cast<unsigned char>(outlen);
    constexpr std::string_view prefix = "tls13 ";
    info[n++] = static_cast<unsigned char>(prefix.size() + label.size());
    std::memcpy(info + n, prefix.data(), prefix.size());
    n += prefix.size();
    std::memcpy(info + n, label.data(), label.size());
    n += label.size();
    info[n++] = 0;  // no context
    info[n++] = 1;  // T(1)
    unsigned char t[EVP_MAX_MD_SIZE];
    unsigned tlen = 0;
    if (!HMAC(md, secret, static_cast<int>(slen), info, n, t, &tlen) || tlen < outlen) return false;
    std::memcpy(out, t, outlen);
    return true;
}

const EVP_CIPHER* aead_of(Suite s) noexcept {
    switch (s) {
        case Suite::aes128gcm: return EVP_aes_128_gcm();
        case Suite::aes256gcm: return EVP_aes_256_gcm();
        case Suite::chacha20: return EVP_chacha20_poly1305();
    }
    return nullptr;
}

const EVP_CIPHER* hp_of(Suite s) noexcept {
    switch (s) {
        case Suite::aes128gcm: return EVP_aes_128_ecb();
        case Suite::aes256gcm: return EVP_aes_256_ecb();
        case Suite::chacha20: return EVP_chacha20();
    }
    return nullptr;
}

}  // namespace

bool suite_from_tls_id(std::uint32_t id, Suite& out) noexcept {
    switch (id & 0xffff) {
        case 0x1301: out = Suite::aes128gcm; return true;
        case 0x1302: out = Suite::aes256gcm; return true;
        case 0x1303: out = Suite::chacha20; return true;
        default: return false;
    }
}

Keys& Keys::operator=(Keys&& o) noexcept {
    if (this != &o) {
        clear();
        suite_ = o.suite_;
        std::memcpy(secret_, o.secret_, sizeof secret_);
        secret_len_ = o.secret_len_;
        std::memcpy(iv_, o.iv_, sizeof iv_);
        aead_ = o.aead_;
        hp_ = o.hp_;
        sealed = o.sealed;
        failures = o.failures;
        o.aead_ = o.hp_ = nullptr;
        o.secret_len_ = 0;
    }
    return *this;
}

void Keys::clear() noexcept {
    if (aead_) EVP_CIPHER_CTX_free(aead_);
    if (hp_) EVP_CIPHER_CTX_free(hp_);
    aead_ = hp_ = nullptr;
    OPENSSL_cleanse(secret_, sizeof secret_);
    OPENSSL_cleanse(iv_, sizeof iv_);
    secret_len_ = 0;
    sealed = failures = 0;
}

bool Keys::install(Suite s, const unsigned char* secret, std::size_t secret_len, bool for_sending) noexcept {
    clear();
    if (secret_len > sizeof secret_) return false;
    suite_ = s;
    std::memcpy(secret_, secret, secret_len);
    secret_len_ = secret_len;
    const EVP_MD* md = md_of(s);
    unsigned char key[32], hp[32];
    const std::size_t kl = key_len(s);
    if (!expand_label(md, secret, secret_len, "quic key", key, kl) || !expand_label(md, secret, secret_len, "quic iv", iv_, 12) ||
        !expand_label(md, secret, secret_len, "quic hp", hp, kl))
        return false;
    aead_ = EVP_CIPHER_CTX_new();
    hp_ = EVP_CIPHER_CTX_new();
    if (!aead_ || !hp_) { clear(); return false; }
    const int enc = for_sending ? 1 : 0;
    if (EVP_CipherInit_ex(aead_, aead_of(s), nullptr, nullptr, nullptr, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(aead_, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1 ||
        EVP_CipherInit_ex(aead_, nullptr, nullptr, key, nullptr, enc) != 1) {
        clear();
        return false;
    }
    if (EVP_EncryptInit_ex(hp_, hp_of(s), nullptr, hp, nullptr) != 1) { clear(); return false; }
    EVP_CIPHER_CTX_set_padding(hp_, 0);
    OPENSSL_cleanse(key, sizeof key);
    OPENSSL_cleanse(hp, sizeof hp);
    return true;
}

bool Keys::install_next(const Keys& current, bool for_sending) noexcept {
    unsigned char next[64];
    if (!current.valid() || !next_secret(current.suite_, current.secret_, current.secret_len_, next)) return false;
    if (!install(current.suite_, next, current.secret_len_, for_sending)) return false;
    OPENSSL_cleanse(next, sizeof next);
    if (EVP_CIPHER_CTX_copy(hp_, current.hp_) != 1) {  // the header protection key stays
        clear();
        return false;
    }
    return true;
}

static void make_nonce(const unsigned char iv[12], std::uint64_t pn, unsigned char nonce[12]) noexcept {
    std::memcpy(nonce, iv, 12);
    for (unsigned i = 0; i < 8; ++i) nonce[4 + i] ^= static_cast<unsigned char>(pn >> (8 * (7 - i)));
}

bool Keys::seal(std::uint64_t pn, unsigned char* pkt, std::size_t hdr_len, std::size_t plain_len) noexcept {
    unsigned char nonce[12];
    make_nonce(iv_, pn, nonce);
    int l = 0;
    if (EVP_EncryptInit_ex(aead_, nullptr, nullptr, nullptr, nonce) != 1) return false;
    if (EVP_EncryptUpdate(aead_, nullptr, &l, pkt, static_cast<int>(hdr_len)) != 1) return false;
    unsigned char* body = pkt + hdr_len;
    if (plain_len && EVP_EncryptUpdate(aead_, body, &l, body, static_cast<int>(plain_len)) != 1) return false;
    int l2 = 0;
    if (EVP_EncryptFinal_ex(aead_, body + plain_len, &l2) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(aead_, EVP_CTRL_AEAD_GET_TAG, static_cast<int>(kAeadTagLen), body + plain_len) != 1) return false;
    ++sealed;
    return true;
}

bool Keys::open(std::uint64_t pn, const unsigned char* header, std::size_t hdr_len, unsigned char* payload, std::size_t len,
                std::size_t& plain_len) noexcept {
    if (len < kAeadTagLen) return false;
    unsigned char nonce[12];
    make_nonce(iv_, pn, nonce);
    const std::size_t body = len - kAeadTagLen;
    int l = 0;
    if (EVP_DecryptInit_ex(aead_, nullptr, nullptr, nullptr, nonce) != 1) return false;
    if (EVP_CIPHER_CTX_ctrl(aead_, EVP_CTRL_AEAD_SET_TAG, static_cast<int>(kAeadTagLen), payload + body) != 1) return false;
    if (EVP_DecryptUpdate(aead_, nullptr, &l, header, static_cast<int>(hdr_len)) != 1) return false;
    if (body && EVP_DecryptUpdate(aead_, payload, &l, payload, static_cast<int>(body)) != 1) return false;
    int l2 = 0;
    if (EVP_DecryptFinal_ex(aead_, payload + body, &l2) != 1) {
        ++failures;
        return false;
    }
    plain_len = body;
    return true;
}

bool Keys::mask(const unsigned char* sample, unsigned char out[5]) noexcept {
    int l = 0;
    if (suite_ == Suite::chacha20) {
        // RFC 9001 5.4.4: the sample is the counter (4 bytes) and the nonce (12); the mask
        // is the keystream over five zero bytes. OpenSSL's ChaCha20 iv is exactly that layout.
        static const unsigned char zeros[5] = {0, 0, 0, 0, 0};
        if (EVP_EncryptInit_ex(hp_, nullptr, nullptr, nullptr, sample) != 1) return false;
        return EVP_EncryptUpdate(hp_, out, &l, zeros, 5) == 1;
    }
    unsigned char block[16];
    if (EVP_EncryptUpdate(hp_, block, &l, sample, 16) != 1) return false;
    std::memcpy(out, block, 5);
    return true;
}

bool initial_secrets(const Cid& client_dcid, unsigned char client[32], unsigned char server[32]) noexcept {
    static const unsigned char salt[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                          0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};
    unsigned char initial[EVP_MAX_MD_SIZE];
    unsigned ilen = 0;
    if (!HMAC(EVP_sha256(), salt, sizeof salt, client_dcid.bytes, client_dcid.len, initial, &ilen)) return false;
    return expand_label(EVP_sha256(), initial, ilen, "client in", client, 32) &&
           expand_label(EVP_sha256(), initial, ilen, "server in", server, 32);
}

bool next_secret(Suite s, const unsigned char* secret, std::size_t len, unsigned char* out) noexcept {
    return expand_label(md_of(s), secret, len, "quic ku", out, hash_len(s));
}

bool retry_tag(const Cid& odcid, const unsigned char* retry, std::size_t retry_len, unsigned char tag[16]) noexcept {
    static const unsigned char key[16] = {0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e};
    static const unsigned char nonce[12] = {0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb};
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    bool ok = false;
    int l = 0;
    unsigned char pseudo_prefix[1 + kMaxCidLen];
    pseudo_prefix[0] = odcid.len;
    std::memcpy(pseudo_prefix + 1, odcid.bytes, odcid.len);
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, nonce) == 1 &&
        EVP_EncryptUpdate(ctx, nullptr, &l, pseudo_prefix, 1 + odcid.len) == 1 &&
        EVP_EncryptUpdate(ctx, nullptr, &l, retry, static_cast<int>(retry_len)) == 1 && EVP_EncryptFinal_ex(ctx, nullptr, &l) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1)
        ok = true;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool random_bytes(unsigned char* out, std::size_t n) noexcept { return RAND_bytes(out, static_cast<int>(n)) == 1; }

const unsigned char* process_secret() noexcept {
    static const unsigned char* secret = [] {
        static unsigned char bytes[32];
        RAND_bytes(bytes, sizeof bytes);
        return bytes;
    }();
    return secret;
}

void reset_token(const Cid& cid, unsigned char out[16]) noexcept {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned len = 0;
    HMAC(EVP_sha256(), process_secret(), 32, cid.bytes, cid.len, mac, &len);
    std::memcpy(out, mac, 16);
}

namespace {
// The Retry token's key: one HKDF step from the process secret.
const unsigned char* token_key() noexcept {
    static const unsigned char* key = [] {
        static unsigned char bytes[16];
        expand_label(EVP_sha256(), process_secret(), 32, "retry token", bytes, 16);
        return bytes;
    }();
    return key;
}
}  // namespace

std::string seal_token(const unsigned char* address, std::size_t address_len, const Cid& odcid, std::int64_t now) {
    // nonce(12) || AEAD(time(8) || odcid_len(1) || odcid) with the address as associated data || tag(16)
    std::string out;
    unsigned char nonce[12];
    random_bytes(nonce, sizeof nonce);
    unsigned char plain[9 + kMaxCidLen];
    for (unsigned i = 0; i < 8; ++i) plain[i] = static_cast<unsigned char>(static_cast<std::uint64_t>(now) >> (8 * (7 - i)));
    plain[8] = odcid.len;
    std::memcpy(plain + 9, odcid.bytes, odcid.len);
    const int plain_len = 9 + odcid.len;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return out;
    unsigned char cipher[9 + kMaxCidLen], tag[16];
    int l = 0, l2 = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, token_key(), nonce) == 1 &&
        EVP_EncryptUpdate(ctx, nullptr, &l, address, static_cast<int>(address_len)) == 1 &&
        EVP_EncryptUpdate(ctx, cipher, &l, plain, plain_len) == 1 && EVP_EncryptFinal_ex(ctx, cipher + l, &l2) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1) {
        out.append(reinterpret_cast<const char*>(nonce), 12);
        out.append(reinterpret_cast<const char*>(cipher), static_cast<std::size_t>(plain_len));
        out.append(reinterpret_cast<const char*>(tag), 16);
    }
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

bool open_token(std::string_view token, const unsigned char* address, std::size_t address_len, std::int64_t now,
                std::int64_t max_age, Cid& odcid) noexcept {
    if (token.size() < 12 + 9 + 16 || token.size() > 12 + 9 + kMaxCidLen + 16) return false;
    const auto* t = reinterpret_cast<const unsigned char*>(token.data());
    const std::size_t cipher_len = token.size() - 28;
    unsigned char plain[9 + kMaxCidLen], tag[16];
    std::memcpy(tag, t + 12 + cipher_len, 16);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int l = 0, l2 = 0;
    const bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, token_key(), t) == 1 &&
                    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1 &&
                    EVP_DecryptUpdate(ctx, nullptr, &l, address, static_cast<int>(address_len)) == 1 &&
                    EVP_DecryptUpdate(ctx, plain, &l, t + 12, static_cast<int>(cipher_len)) == 1 &&
                    EVP_DecryptFinal_ex(ctx, plain + l, &l2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return false;
    std::uint64_t issued = 0;
    for (unsigned i = 0; i < 8; ++i) issued = (issued << 8) | plain[i];
    const std::int64_t age = now - static_cast<std::int64_t>(issued);
    if (age < 0 || age > max_age) return false;
    const std::size_t len = plain[8];
    if (len < 8 || len > kMaxCidLen || 9 + len != cipher_len) return false;
    odcid.assign(plain + 9, len);
    return true;
}

}  // namespace agensio::quic
