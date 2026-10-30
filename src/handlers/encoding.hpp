// Which representation of a cached file to serve: the pre-compressed twin the client's
// Accept-Encoding takes (RFC 9110 section 12.5.3) or the file itself. Pure and unit tested;
// called only when the entry holds a twin, so a request for a file without one pays nothing.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace agensio {

enum class Encoding : std::uint8_t { identity, gzip, br, zstd };

// The coding's name as Content-Encoding spells it.
inline std::string_view encoding_name(Encoding e) noexcept {
    switch (e) {
        case Encoding::gzip: return "gzip";
        case Encoding::br: return "br";
        case Encoding::zstd: return "zstd";
        case Encoding::identity: break;
    }
    return "identity";
}

// The codings a server may offer, each a bit, and the order that decides a tie between the ones
// a client takes equally (root's [response_compression] codings, zstd first by default: the
// cheapest encoder for the 83 % of browsers that take it, docs/design-compression.md 4).
struct Codings {
    std::uint8_t mask = 0;                                                            // bit (Encoding - 1)
    std::array<Encoding, 3> order = {Encoding::zstd, Encoding::br, Encoding::gzip};  // first wins a tie
    constexpr bool has(Encoding e) const noexcept { return e != Encoding::identity && (mask & (1u << (static_cast<unsigned>(e) - 1))) != 0; }
    constexpr void add(Encoding e) noexcept {
        if (e != Encoding::identity) mask = static_cast<std::uint8_t>(mask | (1u << (static_cast<unsigned>(e) - 1)));
    }
};

// The coding a file is stored with, from the type table's encoding column (mime_info: "gzip" for
// .svgz), identity for every other file.
inline Encoding stored_coding(std::string_view encoding) noexcept {
    return encoding == "gzip" ? Encoding::gzip : encoding == "br" ? Encoding::br : Encoding::identity;
}

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

// The coding to send among those offered (RFC 9110 12.5.3): a coding named with q=0 is refused,
// "*" stands for the codings not named, the highest q wins, and `offered.order` decides a tie;
// nothing acceptable, or no header at all, means identity (the file as stored, the answer as the
// application sent it). "identity;q=0" with nothing else acceptable is answered identity too, as
// every server does (the RFC allows 406; no client sends it in earnest). One pass over the header,
// no allocation.
inline Encoding choose_encoding(std::string_view accept, Codings offered) noexcept {
    using namespace encoding_detail;
    int q[4] = {-1, -1, -1, -1};  // by Encoding; q[identity] unused
    int q_star = -1;
    std::size_t i = 0;
    while (i <= accept.size()) {
        std::size_t j = accept.find(',', i);
        if (j == std::string_view::npos) j = accept.size();
        const std::string_view item = trim_ws(accept.substr(i, j - i));
        i = j + 1;
        if (item.empty()) continue;
        const std::size_t semi = item.find(';');
        const std::string_view token = trim_ws(item.substr(0, semi == std::string_view::npos ? item.size() : semi));
        const int w = semi == std::string_view::npos ? 1000 : parse_q(item.substr(semi + 1));
        if (token == "*") q_star = w;
        else if (token_is(token, "br")) q[static_cast<unsigned>(Encoding::br)] = w;
        else if (token_is(token, "gzip") || token_is(token, "x-gzip")) q[static_cast<unsigned>(Encoding::gzip)] = w;
        else if (token_is(token, "zstd")) q[static_cast<unsigned>(Encoding::zstd)] = w;
    }
    Encoding best = Encoding::identity;
    int best_q = 0;
    for (const Encoding e : offered.order) {  // in order: the first of equals wins
        if (!offered.has(e)) continue;
        const int qe = q[static_cast<unsigned>(e)] >= 0 ? q[static_cast<unsigned>(e)] : q_star;
        if (qe > best_q) {
            best = e;
            best_q = qe;
        }
    }
    return best;
}

// The twins a cached file holds (name.br, name.gz beside it): br takes a tie, the smaller body.
inline Encoding choose_encoding(std::string_view accept, bool have_br, bool have_gzip) noexcept {
    Codings c;
    c.order = {Encoding::br, Encoding::gzip, Encoding::zstd};
    if (have_br) c.add(Encoding::br);
    if (have_gzip) c.add(Encoding::gzip);
    return choose_encoding(accept, c);
}

}  // namespace agensio
