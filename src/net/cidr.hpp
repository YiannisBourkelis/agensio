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

struct Cidr {
    std::array<unsigned char, 16> bytes{};  // v4 addresses are mapped into the low 4 bytes
    unsigned prefix = 0;                     // in bits, over `bytes` as stored
    bool v6 = false;

    bool contains(const asio::ip::address& a) const noexcept {
        std::array<unsigned char, 16> b{};
        if (a.is_v6() != v6) {
            // v4-mapped v6 clients match a v4 range and vice versa.
            if (a.is_v6() && a.to_v6().is_v4_mapped()) {
                if (v6) return false;
                const auto v4 = asio::ip::make_address_v4(asio::ip::v4_mapped, a.to_v6()).to_bytes();
                for (std::size_t i = 0; i < 4; ++i) b[i] = v4[i];
            } else {
                return false;
            }
        } else if (v6) {
            b = a.to_v6().to_bytes();
        } else {
            const auto v4 = a.to_v4().to_bytes();
            for (std::size_t i = 0; i < 4; ++i) b[i] = v4[i];
        }
        unsigned bits = prefix;
        for (std::size_t i = 0; i < bytes.size() && bits > 0; ++i) {
            const unsigned take = bits >= 8 ? 8 : bits;
            const unsigned char mask = static_cast<unsigned char>(0xffu << (8 - take));
            if ((b[i] & mask) != (bytes[i] & mask)) return false;
            bits -= take;
        }
        return true;
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
    asio::error_code ec;
    const auto a = asio::ip::make_address(std::string(ip), ec);
    if (ec) {
        error = "not an IP address: '" + std::string(ip) + "'";
        return false;
    }
    out.v6 = a.is_v6();
    const unsigned max = out.v6 ? 128 : 32;
    if (!has_prefix) prefix = max;
    if (prefix > max) {
        error = "prefix length out of range in '" + std::string(text) + "'";
        return false;
    }
    out.prefix = prefix;
    if (out.v6) {
        out.bytes = a.to_v6().to_bytes();
    } else {
        const auto v4 = a.to_v4().to_bytes();
        for (std::size_t i = 0; i < 4; ++i) out.bytes[i] = v4[i];
    }
    return true;
}

inline bool in_any(const std::vector<Cidr>& ranges, const asio::ip::address& a) noexcept {
    for (const Cidr& c : ranges)
        if (c.contains(a)) return true;
    return false;
}

}  // namespace agensio
