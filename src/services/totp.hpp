// One-time codes for approvals (docs/design-site-operations.md 27.5): HOTP (RFC 4226) over a time
// step, TOTP (RFC 6238), as every authenticator app takes them: HMAC-SHA1, 6 digits, 30 seconds.
// Pure; the secrets live in the approver files (services/approvers.hpp). Without OpenSSL there is
// no HMAC and available() is false: approvals are refused with the reason.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace agensio::totp {

inline constexpr int kDigits = 6;
inline constexpr std::int64_t kPeriod = 30;
inline constexpr std::size_t kSecretBytes = 20;  // RFC 4226 4: at least 128 bits, 160 recommended

// Whether this build can compute codes (OpenSSL's HMAC).
bool available() noexcept;

// RFC 4648 base32, upper case, no padding: what authenticator apps show and take.
std::string base32_encode(std::string_view bytes);
// Upper or lower case, spaces and '=' padding ignored; nullopt for any other character.
std::optional<std::string> base32_decode(std::string_view text);

// The 6-digit code of `secret` at counter `counter` (RFC 4226 5.3), "" without HMAC.
std::string hotp(std::string_view secret, std::uint64_t counter);
// The time step of `now` (seconds since the epoch).
inline std::int64_t step_of(std::int64_t now) noexcept { return now / kPeriod; }

// The step `code` matches, among the step of `now` and the ones just before and after (a clock
// 30 seconds off), only above `last_used` (a code is accepted once, RFC 6238 5.2); nullopt for no
// match. The comparison takes the same time whatever the code.
std::optional<std::int64_t> match(std::string_view secret, std::string_view code, std::int64_t now, std::int64_t last_used);

// A new secret of kSecretBytes random bytes, "" without random bytes.
std::string new_secret();

// otpauth://totp/agensio:LABEL?secret=...&issuer=agensio&algorithm=SHA1&digits=6&period=30, the URI
// an app reads from a QR code; LABEL percent-encoded but for '@' (an account@host label, as apps show it).
std::string otpauth_uri(std::string_view label, std::string_view secret);

}  // namespace agensio::totp
