// Host names as authority (RFC 9110 section 7.4): the name part of a Host header, and the
// names a presented certificate covers (RFC 6125 matching), so that on a TLS connection a
// request is answered only for a name the certificate the client saw actually names.
// Header-only, allocation-free on the request path, unit tested.
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

// The name of a Host header value, in the case it was sent: "Example.COM.:8443" -> "Example.COM",
// "[::1]:8443" -> "::1" (the port cut, an IPv6 literal's brackets removed, a final dot dropped).
inline std::string_view host_name_part(std::string_view host) noexcept {
    if (host.empty()) return host;
    if (host.front() == '[') {
        const auto close = host.find(']');
        if (close != std::string_view::npos) host = host.substr(1, close - 1);
    } else {
        const auto colon = host.rfind(':');
        if (colon != std::string_view::npos) host = host.substr(0, colon);
    }
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    return host;
}

// Eight bytes with the ASCII capitals among them in lower case and every other byte as it was. Each
// byte is tested in its own lane: its low seven bits plus a constant below 0x81 never carry into the
// next byte, and a byte from 0x80 up is left alone.
inline std::uint64_t fold_capitals8(std::uint64_t x) noexcept {
    constexpr std::uint64_t kOnes = 0x0101010101010101ULL;
    const std::uint64_t low7 = x & (0x7f * kOnes);
    const std::uint64_t from_a = low7 + (0x80 - 'A') * kOnes;   // a lane's top bit: at least 'A'
    const std::uint64_t past_z = low7 + (0x7f - 'Z') * kOnes;   // a lane's top bit: past 'Z'
    const std::uint64_t capital = (from_a ^ past_z) & ~x & (0x80 * kOnes);
    return x | (capital >> 2);  // 0x80 >> 2 is the 0x20 between 'A' and 'a'
}
inline std::uint64_t load8(const char* p) noexcept {
    std::uint64_t v;
    std::memcpy(&v, p, sizeof v);
    return v;
}

// Eight bytes of a name in any case against eight of a name in lower case: folded only when they
// differ as they are (a Host is nearly always sent in lower case, and equal as sent means equal
// folded, `lower` holding no capital).
inline bool word_equals_folded(const char* name, const char* lower) noexcept {
    const std::uint64_t n = load8(name), l = load8(lower);
    return n == l || fold_capitals8(n) == l;
}

// `name` in any case equals `lower`, written in lower case (no capital in it: CertNames::add folds
// every name it stores): ASCII letters folded, no other byte. Compared in place, eight bytes at a
// time (the last eight overlapping the word before them), stopping at the first word that differs.
inline bool equals_folded(std::string_view name, std::string_view lower) noexcept {
    const std::size_t n = name.size();
    if (n != lower.size()) return false;
    if (n >= 8) {
        for (std::size_t i = 0; i + 8 < n; i += 8)
            if (!word_equals_folded(name.data() + i, lower.data() + i)) return false;
        return word_equals_folded(name.data() + n - 8, lower.data() + n - 8);
    }
    for (std::size_t i = 0; i < n; ++i) {
        const char c = name[i];
        if (((c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c) != lower[i]) return false;
    }
    return true;
}

// The form of a host name as written in a certificate or asked of a TLS peer (RFC 6066 3: a DNS host
// name, ASCII, no final dot): labels of ASCII letters, digits, '-' and '_' joined by dots, 63 bytes a
// label and 253 in all, no empty label and so no final dot, and a last label that is not a number (how
// an address ends, never a name: "1.2.3", "010.0.0.1"). An international name is in its xn-- form.
// Wider than RFC 1123 2.1 on purpose, which allows no '_' and no '-' at a label's start or end: the
// certificate reader uses it (acme::certificate_names), and OpenSSL's X509_check_host compares a
// certificate's names as written without judging their form, so a stricter rule would refuse names a
// client's check accepts (the alpha.146 entry of CHANGELOG.md cited RFC 1123 2.1 for this rule).
inline bool valid_host_name(std::string_view name) noexcept {
    if (name.empty() || name.size() > 253) return false;
    std::size_t label = 0;    // the length of the label being read
    bool digits_only = true;  // of that label
    for (const unsigned char c : name) {
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
            digits_only = true;
            continue;
        }
        const bool digit = c >= '0' && c <= '9';
        if (!digit && !((c | 0x20) >= 'a' && (c | 0x20) <= 'z') && c != '-' && c != '_') return false;
        if (++label > 63) return false;
        digits_only = digits_only && digit;
    }
    return label != 0 && !digits_only;
}

// The names of one certificate: exact DNS names and IP addresses, and wildcard entries
// kept as the suffix after "*" (".example.com" for "*.example.com").
struct CertNames {
    std::vector<std::string> exact;
    std::vector<std::string> wildcard;

    // `name` is a certificate's name, not a Host field: there is no port to cut and an IPv6 address
    // is written bare. (Read as a Host field until 0.1.0-alpha.146, an IPv6 address lost what
    // followed its last colon and covered no request.)
    void add(std::string_view name) {
        if (!name.empty() && name.back() == '.') name.remove_suffix(1);
        if (name.empty() || name.size() > 253) return;
        char buf[256];
        for (std::size_t i = 0; i < name.size(); ++i) {
            const char c = name[i];
            buf[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        }
        const std::string_view n(buf, name.size());
        if (n.size() > 2 && n[0] == '*' && n[1] == '.' && n.find('*', 1) == std::string_view::npos) wildcard.emplace_back(n.substr(1));
        else if (n.find('*') == std::string_view::npos) exact.emplace_back(n);
    }

    // RFC 6125 section 6.4.3: a wildcard matches exactly one label, the leftmost, and
    // never the bare domain. `host` is a raw Host header value (port, case, dot allowed).
    // Run for every request over TLS, so compared in place against the names, which add() stored
    // in lower case. Until 0.1.0-alpha.148 the Host was first copied, lowered, into a 256-byte
    // buffer the hardened build zeroes, then compared through memcmp: 178 instructions a call for
    // "127.0.0.1:8443" against two names, 133 now (250 and 160 for a 15-byte name).
    bool covers(std::string_view host) const noexcept {
        const std::string_view h = host_name_part(host);
        if (h.empty() || h.size() > 253) return false;  // no such host name exists
        for (const auto& e : exact)
            if (equals_folded(h, e)) return true;
        for (const auto& w : wildcard) {
            if (h.size() <= w.size() || !equals_folded(h.substr(h.size() - w.size()), w)) continue;
            const std::string_view label = h.substr(0, h.size() - w.size());
            if (!label.empty() && label.find('.') == std::string_view::npos) return true;
        }
        return false;
    }
    bool empty() const noexcept { return exact.empty() && wildcard.empty(); }
};

}  // namespace agensio
