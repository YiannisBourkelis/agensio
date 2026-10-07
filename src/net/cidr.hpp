// IPv4/IPv6 address ranges in CIDR notation, for `trusted_proxies`: whose X-Forwarded-*
// headers may be believed. Parsed once at configuration load; matching is a byte compare.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <asio/ip/address.hpp>

namespace agensio {

// An IPv4 client on a dual-stack socket arrives as ::ffff:a.b.c.d (RFC 4291 2.5.5.2). It is
// the IPv4 address it maps, for matching, the access log and REMOTE_ADDR alike (2026-10-07:
// before, logs carried the mapped text and an IPv6 entry with zero leading bits, ::/8,
// matched every IPv4 client).
inline asio::ip::address unmapped(const asio::ip::address& a) noexcept {
    if (a.is_v6() && a.to_v6().is_v4_mapped()) return asio::ip::make_address_v4(asio::ip::v4_mapped, a.to_v6());
    return a;
}

struct Cidr {
    std::array<unsigned char, 16> bytes{};  // v4 addresses are stored in the low 4 bytes
    unsigned prefix = 0;                     // in bits, over `bytes` as stored
    bool v6 = false;
    // The masked network and the mask as two big-endian words (set by finish(), which
    // parse_cidr calls): an entry is two word compares, so an access rule's list of 64 is
    // scanned in a few dozen nanoseconds per request.
    std::uint64_t net_hi = 0, net_lo = 0, mask_hi = 0, mask_lo = 0;

    static std::uint64_t word(const std::array<unsigned char, 16>& b, std::size_t from) noexcept {
        std::uint64_t w = 0;
        for (std::size_t i = 0; i < 8; ++i) w = (w << 8) | b[from + i];
        return w;
    }

    void finish() noexcept {
        mask_hi = prefix == 0 ? 0 : prefix >= 64 ? ~std::uint64_t{0} : ~std::uint64_t{0} << (64 - prefix);
        mask_lo = prefix <= 64 ? 0 : prefix >= 128 ? ~std::uint64_t{0} : ~std::uint64_t{0} << (128 - prefix);
        net_hi = word(bytes, 0) & mask_hi;
        net_lo = word(bytes, 8) & mask_lo;
    }

    // A client in the form entries are compared in: IPv4 in the low 4 bytes, a mapped client as IPv4.
    struct Key {
        std::uint64_t hi = 0, lo = 0;
        bool v6 = false;
    };
    static Key key_of(const asio::ip::address& given) noexcept {
        const asio::ip::address a = unmapped(given);
        std::array<unsigned char, 16> b{};
        Key k;
        k.v6 = a.is_v6();
        if (k.v6) {
            b = a.to_v6().to_bytes();
        } else {
            const auto v4 = a.to_v4().to_bytes();
            for (std::size_t i = 0; i < 4; ++i) b[i] = v4[i];
        }
        k.hi = word(b, 0);
        k.lo = word(b, 8);
        return k;
    }

    // An IPv4 entry matches IPv4 clients, mapped ones included; an IPv6 entry matches IPv6
    // clients only.
    bool matches(const Key& k) const noexcept { return k.v6 == v6 && (k.hi & mask_hi) == net_hi && (k.lo & mask_lo) == net_lo; }

    bool contains(const asio::ip::address& given) const noexcept { return matches(key_of(given)); }

    // "203.0.113.0/24", "2001:db8:5::/64": what config_reference, -t and health show.
    std::string text() const {
        asio::ip::address a;
        if (v6) {
            asio::ip::address_v6::bytes_type b;
            for (std::size_t i = 0; i < b.size(); ++i) b[i] = bytes[i];
            a = asio::ip::address_v6(b);
        } else {
            a = asio::ip::address_v4(asio::ip::address_v4::bytes_type{bytes[0], bytes[1], bytes[2], bytes[3]});
        }
        return a.to_string() + "/" + std::to_string(prefix);
    }
};

// "10.0.0.0/8", "192.168.1.5" (a /32), "fd00::/8", "::1".
inline bool parse_cidr(std::string_view text, Cidr& out, std::string& error) {
    out = Cidr{};
    std::string_view ip = text;
    unsigned prefix = 0;
    bool has_prefix = false;
    if (const std::size_t slash = text.find('/'); slash != std::string_view::npos) {
        ip = text.substr(0, slash);
        const std::string_view p = text.substr(slash + 1);
        if (p.empty() || p.size() > 3) {
            error = "bad prefix length in '" + std::string(text) + "'";
            return false;
        }
        for (char c : p) {
            if (c < '0' || c > '9') {
                error = "bad prefix length in '" + std::string(text) + "'";
                return false;
            }
            prefix = prefix * 10 + static_cast<unsigned>(c - '0');
        }
        has_prefix = true;
    }
    if (ip.find('%') != std::string_view::npos) {  // a zone id names an interface of this host, never a client
        error = "a zone id is not an address: '" + std::string(text) + "'";
        return false;
    }
    asio::error_code ec;
    auto a = asio::ip::make_address(std::string(ip), ec);
    if (ec) {
        error = "not an IP address: '" + std::string(ip) + "'";
        return false;
    }
    const unsigned given_max = a.is_v6() ? 128 : 32;
    if (has_prefix && prefix > given_max) {
        error = "prefix length out of range in '" + std::string(text) + "'";
        return false;
    }
    // A range written in mapped form is the IPv4 range it names (::ffff:192.0.2.0/120 is
    // 192.0.2.0/24), so it matches the unmapped clients.
    if (a.is_v6() && a.to_v6().is_v4_mapped()) {
        if (has_prefix && prefix < 96) {
            error = "a mapped IPv4 range needs a prefix of 96 or more: '" + std::string(text) + "'";
            return false;
        }
        a = unmapped(a);
        if (has_prefix) prefix -= 96;
    }
    out.v6 = a.is_v6();
    const unsigned max = out.v6 ? 128 : 32;
    if (!has_prefix) prefix = max;
    out.prefix = prefix;
    if (out.v6) {
        out.bytes = a.to_v6().to_bytes();
    } else {
        const auto v4 = a.to_v4().to_bytes();
        for (std::size_t i = 0; i < 4; ++i) out.bytes[i] = v4[i];
    }
    out.finish();
    return true;
}

// The client's bytes are taken once, then each entry is a masked compare (an access rule's
// list of 64 is scanned per request on a site restricted as a whole).
inline bool in_any(const std::vector<Cidr>& ranges, const asio::ip::address& a) noexcept {
    if (ranges.empty()) return false;
    const Cidr::Key k = Cidr::key_of(a);
    for (const Cidr& c : ranges)
        if (c.matches(k)) return true;
    return false;
}

}  // namespace agensio
