// Small string_view helpers that never throw, for use in noexcept hot-path code.
#pragma once

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace agensio {

// Like string_view::substr but clamps instead of throwing when pos is past the end.
constexpr std::string_view slice(std::string_view s, std::size_t pos,
                                 std::size_t len = std::string_view::npos) noexcept {
    if (pos >= s.size()) return {};
    return std::string_view(s.data() + pos, std::min(len, s.size() - pos));
}

// Grows `s` to `n` bytes without filling the new ones (what was there stays): for a buffer about
// to be read into. C++23's resize_and_overwrite where the library has it under this standard, the
// library's own spelling of it otherwise, and a plain resize (a fill) as the last resort.
inline void grow_for_overwrite(std::string& s, std::size_t n) {
    if (n <= s.size()) return;
#if defined(__cpp_lib_string_resize_and_overwrite)
    s.resize_and_overwrite(n, [](char*, std::size_t m) noexcept { return m; });
#elif defined(__GLIBCXX__) && defined(_GLIBCXX_RELEASE) && _GLIBCXX_RELEASE >= 12
    s.__resize_and_overwrite(n, [](char*, std::size_t m) noexcept { return m; });
#elif defined(_LIBCPP_VERSION)
    s.__resize_default_init(n);
#else
    s.resize(n);
#endif
}

// The length of the well-formed UTF-8 sequence that starts at s[i] (1 for ASCII), or 0 when
// the byte there begins none (RFC 3629: no overlong form, no surrogate, nothing above
// U+10FFFF, no stray continuation byte). What the access log and logs_query use to keep a
// client's bytes from becoming invalid text (2026-10-02 alpha.43 report: a TLS ClientHello
// sent to port 80 made a 1.7 MB answer fail strict decoding).
constexpr std::size_t utf8_sequence(std::string_view s, std::size_t i) noexcept {
    const auto at = [&](std::size_t k) -> unsigned { return k < s.size() ? static_cast<unsigned char>(s[k]) : 0x100u; };
    const unsigned c = at(i);
    if (c < 0x80) return 1;
    const auto cont = [&](std::size_t k) { return (at(k) & 0xC0u) == 0x80u; };
    if (c >= 0xC2 && c <= 0xDF) return cont(i + 1) ? 2 : 0;
    if (c >= 0xE0 && c <= 0xEF) {
        if (!cont(i + 1) || !cont(i + 2)) return 0;
        const unsigned c1 = at(i + 1);
        if (c == 0xE0 && c1 < 0xA0) return 0;  // overlong
        if (c == 0xED && c1 >= 0xA0) return 0;  // surrogate
        return 3;
    }
    if (c >= 0xF0 && c <= 0xF4) {
        if (!cont(i + 1) || !cont(i + 2) || !cont(i + 3)) return 0;
        const unsigned c1 = at(i + 1);
        if (c == 0xF0 && c1 < 0x90) return 0;  // overlong
        if (c == 0xF4 && c1 >= 0x90) return 0;  // above U+10FFFF
        return 4;
    }
    return 0;
}

// Appends v in decimal (no locale, no allocation beyond the string's growth).
inline void append_number(std::string& s, std::uint64_t v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof(buf), v);
    s.append(buf, r.ptr);
}

}  // namespace agensio
