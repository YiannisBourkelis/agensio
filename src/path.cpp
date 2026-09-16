#include "path.hpp"

#include <cstring>

#include "strings.hpp"

namespace agensio {

namespace {
inline int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
}  // namespace

bool normalize_target(std::string_view target, std::string& out) {
    out.clear();
    if (target.empty() || target[0] != '/') return false;

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

}  // namespace agensio
