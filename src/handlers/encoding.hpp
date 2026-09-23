// Which representation of a cached file to serve: the pre-compressed twin the client's
// Accept-Encoding takes (RFC 9110 section 12.5.3) or the file itself. Pure and unit tested;
// called only when the entry holds a twin, so a request for a file without one pays nothing.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace agensio {

enum class Encoding : std::uint8_t { identity, gzip, br };

namespace encoding_detail {

inline std::string_view trim_ws(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t')) s.remove_suffix(1);
    return s;
}

inline bool token_is(std::string_view token, std::string_view lower) noexcept {
    if (token.size() != lower.size()) return false;
    for (std::size_t i = 0; i < token.size(); ++i) {
        const char c = token[i];
        if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c) != lower[i]) return false;
    }
    return true;
}

// The q of ";q=0.8" in thousandths: 800. Absent or unreadable is 1000, the RFC's default;
// the RFC allows at most three decimals, more are ignored.
inline int parse_q(std::string_view params) noexcept {
    for (;;) {
        const std::size_t semi = params.find(';');
        const std::string_view p = trim_ws(params.substr(0, semi == std::string_view::npos ? params.size() : semi));
        if (p.size() >= 2 && (p[0] == 'q' || p[0] == 'Q') && p[1] == '=') {
            const std::string_view v = trim_ws(p.substr(2));
            if (v.empty() || (v[0] != '0' && v[0] != '1')) return 1000;
            int q = (v[0] - '0') * 1000;
            if (v.size() > 1) {
                if (v[1] != '.') return 1000;
                int scale = 100;
                for (std::size_t i = 2; i < v.size() && i < 5; ++i) {
                    if (v[i] < '0' || v[i] > '9') return 1000;
                    q += (v[i] - '0') * scale;
                    scale /= 10;
                }
            }
            return q > 1000 ? 1000 : q;
        }
        if (semi == std::string_view::npos) return 1000;
        params.remove_prefix(semi + 1);
    }
}

}  // namespace encoding_detail

// have_br / have_gzip: which twins the entry holds. A coding named with q=0 is refused, "*"
// stands for the codings not named, the highest q wins and br takes a tie (the smaller
// body); nothing acceptable, or no header at all, means the file as stored.
inline Encoding choose_encoding(std::string_view accept, bool have_br, bool have_gzip) noexcept {
    using namespace encoding_detail;
    int q_br = -1, q_gzip = -1, q_star = -1;
    std::size_t i = 0;
    while (i <= accept.size()) {
        std::size_t j = accept.find(',', i);
        if (j == std::string_view::npos) j = accept.size();
        const std::string_view item = trim_ws(accept.substr(i, j - i));
        i = j + 1;
        if (item.empty()) continue;
        const std::size_t semi = item.find(';');
        const std::string_view token = trim_ws(item.substr(0, semi == std::string_view::npos ? item.size() : semi));
        const int q = semi == std::string_view::npos ? 1000 : parse_q(item.substr(semi + 1));
        if (token == "*") q_star = q;
        else if (token_is(token, "br")) q_br = q;
        else if (token_is(token, "gzip") || token_is(token, "x-gzip")) q_gzip = q;
    }
    const int br = have_br ? (q_br >= 0 ? q_br : q_star) : -1;
    const int gz = have_gzip ? (q_gzip >= 0 ? q_gzip : q_star) : -1;
    if (br <= 0 && gz <= 0) return Encoding::identity;
    return br >= gz ? Encoding::br : Encoding::gzip;
}

}  // namespace agensio
