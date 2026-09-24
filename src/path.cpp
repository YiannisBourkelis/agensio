#include "path.hpp"

#include <cstring>

#include "core/strings.hpp"

namespace agensio {

namespace {
inline int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// The length of the path part of a target that needs no work (no escape, no control
// character, no empty, "." or ".." segment: nearly every request), or npos.
std::size_t plain_path(std::string_view target) noexcept {
    for (std::size_t i = 0; i < target.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(target[i]);
        if (c == '?' || c == '#') return i;
        if (c == '%' || c < 0x20 || c == 0x7f) return std::string_view::npos;
        if (c == '/' && i + 1 < target.size() && (target[i + 1] == '/' || target[i + 1] == '.')) return std::string_view::npos;
    }
    return target.size();
}
}  // namespace

bool normalize_target(std::string_view target, std::string& out) {
    out.clear();
    if (target.empty() || target[0] != '/') return false;
    if (const std::size_t n = plain_path(target); n != std::string_view::npos) {  // as it is
        out.assign(target.data(), n);
        return true;
    }

    // Strip query (and fragment, which clients should never send).
    auto q = target.find('?');
    if (q != std::string_view::npos) target = slice(target, 0, q);
    auto h = target.find('#');
    if (h != std::string_view::npos) target = slice(target, 0, h);

    // 1. Percent-decode into `out`.
    out.reserve(target.size() + 1);
    for (std::size_t i = 0; i < target.size(); ++i) {
        char c = target[i];
        if (c == '%') {
            if (i + 2 >= target.size()) return false;
            int hi = hex_val(target[i + 1]), lo = hex_val(target[i + 2]);
            if (hi < 0 || lo < 0) return false;
            c = static_cast<char>((hi << 4) | lo);
            i += 2;
        }
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc < 0x20 || uc == 0x7f) return false;  // NUL and control characters
        out.push_back(c);
    }

    // 2. Normalise segments in place. Invariant: out[0, w) is "" or "/seg/seg"
    //    (never with a trailing slash); w <= r always, so copies never overlap badly.
    const std::size_t n = out.size();
    std::size_t w = 0, r = 1;
    bool dir = false;
    for (;;) {
        std::size_t e = out.find('/', r);
        if (e == std::string::npos) e = n;
        const std::size_t len = e - r;
        if (len == 0 || (len == 1 && out[r] == '.')) {
            dir = true;  // "//", "/./", trailing "/"
        } else if (len == 2 && out[r] == '.' && out[r + 1] == '.') {
            if (w == 0) return false;  // would climb above the root
            while (w > 0 && out[w - 1] != '/')
                --w;  // drop the last segment
            --w;      // and its leading slash
            dir = true;
        } else {
            out[w++] = '/';
            std::memmove(out.data() + w, out.data() + r, len);
            w += len;
            dir = false;
        }
        if (e >= n) break;
        r = e + 1;
    }
    out.resize(w);
    if (w == 0 || dir) out.push_back('/');
    return true;
}

bool has_hidden_segment(std::string_view path) noexcept {
    for (std::size_t i = 0; i + 1 < path.size(); ++i)
        if (path[i] == '/' && path[i + 1] == '.') return true;
    return false;
}

namespace {
inline char upper(char c) noexcept {
    return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 32) : c;
}

bool reserved_device_name(std::string_view seg) noexcept {
    auto dot = seg.find('.');
    std::string_view base = dot == std::string_view::npos ? seg : seg.substr(0, dot);
    if (base.size() == 3) {
        char a = upper(base[0]), b = upper(base[1]), c = upper(base[2]);
        if ((a == 'C' && b == 'O' && c == 'N') || (a == 'P' && b == 'R' && c == 'N') ||
            (a == 'A' && b == 'U' && c == 'X') || (a == 'N' && b == 'U' && c == 'L'))
            return true;
    }
    if (base.size() == 4 && base[3] >= '1' && base[3] <= '9') {
        char a = upper(base[0]), b = upper(base[1]), c = upper(base[2]);
        if ((a == 'C' && b == 'O' && c == 'M') || (a == 'L' && b == 'P' && c == 'T')) return true;
    }
    return false;
}
}  // namespace

bool windows_path_ok(std::string_view path) noexcept {
    std::size_t start = 0;
    for (std::size_t i = 0; i <= path.size(); ++i) {
        if (i < path.size() && path[i] != '/') {
            if (path[i] == '\\' || path[i] == ':') return false;
            continue;
        }
        std::string_view seg = path.substr(start, i - start);
        if (!seg.empty()) {
            if (seg.back() == '.' || seg.back() == ' ') return false;
            if (reserved_device_name(seg)) return false;
        }
        start = i + 1;
    }
    return true;
}

}  // namespace agensio
