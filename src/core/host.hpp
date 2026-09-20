// Host names as authority (RFC 9110 section 7.4): the normalised form of a Host header,
// and the names a presented certificate covers (RFC 6125 matching), so that on a TLS
// connection a request is answered only for a name the certificate the client saw
// actually names. Header-only, allocation-free on the request path, unit tested.
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

// "Example.COM.:8443" -> "example.com" into `buf`; "[::1]:8443" -> "::1". Longer than 253
// characters comes back empty (no such host name exists).
inline std::string_view normalize_host(std::string_view host, char (&buf)[256]) noexcept {
    if (host.empty()) return {};
    if (host.front() == '[') {
        const auto close = host.find(']');
        if (close != std::string_view::npos) host = host.substr(1, close - 1);
    } else {
        const auto colon = host.rfind(':');
        if (colon != std::string_view::npos) host = host.substr(0, colon);
    }
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    if (host.size() > 253) return {};
    for (std::size_t i = 0; i < host.size(); ++i) {
        const char c = host[i];
        buf[i] = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
    }
    return std::string_view(buf, host.size());
}

// The names of one certificate: exact DNS names and IP addresses, and wildcard entries
// kept as the suffix after "*" (".example.com" for "*.example.com").
struct CertNames {
    std::vector<std::string> exact;
    std::vector<std::string> wildcard;

    void add(std::string_view name) {
        char buf[256];
        const std::string_view n = normalize_host(name, buf);
        if (n.empty()) return;
        if (n.size() > 2 && n[0] == '*' && n[1] == '.' && n.find('*', 1) == std::string_view::npos) wildcard.emplace_back(n.substr(1));
        else if (n.find('*') == std::string_view::npos) exact.emplace_back(n);
    }

    // RFC 6125 section 6.4.3: a wildcard matches exactly one label, the leftmost, and
    // never the bare domain. `host` is a raw Host header value (port, case, dot allowed).
    bool covers(std::string_view host) const noexcept {
        char buf[256];
        const std::string_view h = normalize_host(host, buf);
        if (h.empty()) return false;
        for (const auto& e : exact)
            if (e == h) return true;
        for (const auto& w : wildcard) {
            if (h.size() <= w.size() || h.compare(h.size() - w.size(), w.size(), w) != 0) continue;
            const std::string_view label = h.substr(0, h.size() - w.size());
            if (!label.empty() && label.find('.') == std::string_view::npos) return true;
        }
        return false;
    }
    bool empty() const noexcept { return exact.empty() && wildcard.empty(); }
};

}  // namespace agensio
