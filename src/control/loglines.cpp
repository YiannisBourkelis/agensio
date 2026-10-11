#include "control/loglines.hpp"

#include <cctype>
#include <ctime>

#include "core/strings.hpp"
#include "services/json.hpp"

namespace agensio::control {

namespace {

int month_of(std::string_view m) {
    static const char* names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i)
        if (m == names[i]) return i;
    return -1;
}

bool digits(std::string_view s, std::size_t pos, std::size_t n, int& out) {
    if (pos + n > s.size()) return false;
    out = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        out = out * 10 + (c - '0');
    }
    return true;
}

std::time_t local_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

std::time_t utc_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
#ifdef _WIN32
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

// "+0300" or "+03:00" -> seconds east of UTC.
bool zone_offset(std::string_view z, long& out) {
    if (z.size() < 5 || (z[0] != '+' && z[0] != '-')) return false;
    int h = 0, m = 0;
    if (!digits(z, 1, 2, h)) return false;
    const std::size_t mpos = z[3] == ':' ? 4 : 3;
    if (!digits(z, mpos, 2, m)) return false;
    out = (h * 3600 + m * 60) * (z[0] == '-' ? -1 : 1);
    return true;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

}  // namespace

// ---- log lines ----

bool parse_log_line(std::string_view line, LogLine& out) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    if (line.empty()) return false;
    out = LogLine{};
    out.text = std::string(line);
    int y, mo, d, h, mi, s;
    // Error log: "2026/09/18 21:44:39 [warn] message"
    if (line.size() > 22 && line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':' && line[16] == ':' &&
        digits(line, 0, 4, y) && digits(line, 5, 2, mo) && digits(line, 8, 2, d) && digits(line, 11, 2, h) &&
        digits(line, 14, 2, mi) && digits(line, 17, 2, s) && line.substr(20, 1) == "[") {
        const std::size_t close = line.find(']', 21);
        if (close == std::string_view::npos) return false;
        out.time = local_to_time(y, mo - 1, d, h, mi, s);
        out.level = std::string(line.substr(21, close - 21));
        out.source = "error";
        return true;
    }
    // JSON access log: {"time":"2026-09-18T21:44:39+03:00",...,"status":404,...}
    if (line.front() == '{') {
        json::Value v;
        std::string err;
        if (!json::parse(line, v, err)) return false;
        const std::string_view t = v.get("time");
        long off = 0;
        if (t.size() < 19 || !digits(t, 0, 4, y) || !digits(t, 5, 2, mo) || !digits(t, 8, 2, d) ||
            !digits(t, 11, 2, h) || !digits(t, 14, 2, mi) || !digits(t, 17, 2, s) || !zone_offset(t.substr(19), off))
            return false;
        out.time = utc_to_time(y, mo - 1, d, h, mi, s) - off;
        // A status no HTTP answer has is 0 (unknown); a double out of int's range would be undefined.
        const double status = v["status"].num();
        out.status = status >= 0 && status < 1000 ? static_cast<int>(status) : 0;
        out.host = lower(v.get("host"));
        if (const std::size_t colon = out.host.rfind(':'); colon != std::string::npos && out.host.find(']') == std::string::npos) out.host.erase(colon);
        return true;
    }
    // Combined: remote - - [18/Sep/2026:21:44:39 +0300] "GET / HTTP/1.1" 404 153 "-" "-"
    const std::size_t open = line.find(" [");
    if (open == std::string_view::npos) return false;
    const std::string_view stamp = line.substr(open + 2);
    long off = 0;
    if (stamp.size() < 26 || !digits(stamp, 0, 2, d) || stamp[2] != '/' || stamp[6] != '/' || !digits(stamp, 7, 4, y) ||
        !digits(stamp, 12, 2, h) || !digits(stamp, 15, 2, mi) || !digits(stamp, 18, 2, s) ||
        (mo = month_of(stamp.substr(3, 3))) < 0 || !zone_offset(stamp.substr(21, 5), off))
        return false;
    out.time = utc_to_time(y, mo, d, h, mi, s) - off;
    // The status is the first number after the closing quote of the request.
    const std::size_t q1 = line.find('"', open);
    const std::size_t q2 = q1 == std::string_view::npos ? q1 : line.find('"', q1 + 1);
    if (q2 == std::string_view::npos || q2 + 2 >= line.size() || !digits(line, q2 + 2, 3, out.status)) return false;
    return true;
}

bool parse_since(std::string_view text, std::time_t now, std::time_t& out) {
    if (text.empty()) return false;
    if (text.size() >= 19 && text[4] == '-' && text[10] == 'T') {
        int y, mo, d, h, mi, s;
        if (!digits(text, 0, 4, y) || !digits(text, 5, 2, mo) || !digits(text, 8, 2, d) || !digits(text, 11, 2, h) ||
            !digits(text, 14, 2, mi) || !digits(text, 17, 2, s))
            return false;
        out = local_to_time(y, mo - 1, d, h, mi, s);
        return true;
    }
    // Further back than a century is the beginning (0): the digits stop counting there, so
    // neither the number nor its product with the unit can overflow.
    constexpr long kCentury = 100L * 366 * 86400;
    long n = 0;
    std::size_t i = 0;
    for (; i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i)
        if (n <= kCentury) n = n * 10 + (text[i] - '0');
    if (i == 0) return false;
    long unit = 1;
    if (i < text.size()) {
        if (i + 1 != text.size()) return false;
        switch (text[i]) {
            case 's': unit = 1; break;
            case 'm': unit = 60; break;
            case 'h': unit = 3600; break;
            case 'd': unit = 86400; break;
            case 'w': unit = 7 * 86400; break;
            default: return false;
        }
    }
    const long back = n > kCentury / unit ? kCentury : n * unit;
    out = back >= now ? 0 : now - back;
    return true;
}

std::string utf8_escaped(std::string_view line) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(line.size());
    for (std::size_t i = 0; i < line.size();) {
        const unsigned char c = static_cast<unsigned char>(line[i]);
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        const std::size_t n = utf8_sequence(line, i);
        if (n) {
            out.append(line.data() + i, n);
            i += n;
        } else {
            out.append("\\x");
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
            ++i;
        }
    }
    return out;
}

}  // namespace agensio::control
