#include "services/totp.hpp"

#include <array>

#ifdef AGENSIO_HAS_TLS
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#endif

namespace agensio::totp {

namespace {
constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
}  // namespace

bool available() noexcept {
#ifdef AGENSIO_HAS_TLS
    return true;
#else
    return false;
#endif
}

std::string base32_encode(std::string_view bytes) {
    std::string out;
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char ch : bytes) {
        buffer = (buffer << 8) | static_cast<unsigned char>(ch);
        bits += 8;
        while (bits >= 5) {
            out.push_back(kAlphabet[(buffer >> (bits - 5)) & 31]);
            bits -= 5;
        }
    }
    if (bits > 0) out.push_back(kAlphabet[(buffer << (5 - bits)) & 31]);
    return out;
}

std::optional<std::string> base32_decode(std::string_view text) {
    std::string out;
    std::uint32_t buffer = 0;
    int bits = 0;
    for (const char ch : text) {
        if (ch == ' ' || ch == '=') continue;
        int v = -1;
        if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') v = ch - 'a';
        else if (ch >= '2' && ch <= '7') v = ch - '2' + 26;
        if (v < 0) return std::nullopt;
        buffer = (buffer << 5) | static_cast<std::uint32_t>(v);
        bits += 5;
        if (bits >= 8) {
            out.push_back(static_cast<char>((buffer >> (bits - 8)) & 0xff));
            bits -= 8;
        }
    }
    return out;
}

std::string hotp(std::string_view secret, std::uint64_t counter) {
#ifdef AGENSIO_HAS_TLS
    unsigned char msg[8];
    for (int i = 7; i >= 0; --i) {
        msg[i] = static_cast<unsigned char>(counter & 0xff);
        counter >>= 8;
    }
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    if (!::HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.size()), msg, sizeof msg, mac, &len) || len < 20) return "";
    // Dynamic truncation (RFC 4226 5.3): four bytes at the offset the last nibble names.
    const unsigned offset = mac[len - 1] & 0x0f;
    const std::uint32_t bin = (static_cast<std::uint32_t>(mac[offset] & 0x7f) << 24) | (static_cast<std::uint32_t>(mac[offset + 1]) << 16) |
                              (static_cast<std::uint32_t>(mac[offset + 2]) << 8) | static_cast<std::uint32_t>(mac[offset + 3]);
    std::string code = std::to_string(bin % 1000000u);
    if (code.size() < kDigits) code.insert(0, kDigits - code.size(), '0');
    return code;
#else
    (void)secret;
    (void)counter;
    return "";
#endif
}

std::optional<std::int64_t> match(std::string_view secret, std::string_view code, std::int64_t now, std::int64_t last_used) {
    if (code.size() != kDigits || secret.empty()) return std::nullopt;
    for (const char c : code)
        if (c < '0' || c > '9') return std::nullopt;
    const std::int64_t step = step_of(now);
    std::optional<std::int64_t> found;
    // Every candidate is computed and compared, whichever matches, so the time does not tell.
    for (const std::int64_t s : {step - 1, step, step + 1}) {
        if (s < 0) continue;
        const std::string expected = hotp(secret, static_cast<std::uint64_t>(s));
        if (expected.size() != kDigits) continue;
#ifdef AGENSIO_HAS_TLS
        const bool same = CRYPTO_memcmp(expected.data(), code.data(), kDigits) == 0;
#else
        const bool same = false;
#endif
        if (same && s > last_used && !found) found = s;
    }
    return found;
}

std::string new_secret() {
#ifdef AGENSIO_HAS_TLS
    std::array<unsigned char, kSecretBytes> bytes{};
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) return "";
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
#else
    return "";
#endif
}

std::string otpauth_uri(std::string_view label, std::string_view secret) {
    std::string l;
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (const char ch : label) {
        const auto c = static_cast<unsigned char>(ch);
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '@') {
            l.push_back(ch);
        } else {
            l.push_back('%');
            l.push_back(kHex[c >> 4]);
            l.push_back(kHex[c & 15]);
        }
    }
    return "otpauth://totp/agensio:" + l + "?secret=" + base32_encode(secret) + "&issuer=agensio&algorithm=SHA1&digits=6&period=30";
}

}  // namespace agensio::totp
