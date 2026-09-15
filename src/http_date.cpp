#include "http_date.hpp"

namespace agensio {

namespace {
constexpr const char* kDays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
constexpr const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

inline void put2(char* p, int v) {
    p[0] = static_cast<char>('0' + v / 10);
    p[1] = static_cast<char>('0' + v % 10);
}
}  // namespace

void format_http_date(std::time_t t, char* out) {
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    const char* day = kDays[tm.tm_wday];
    const char* mon = kMonths[tm.tm_mon];
    int year = tm.tm_year + 1900;
    // "Sun, 06 Nov 1994 08:49:37 GMT"
    out[0] = day[0]; out[1] = day[1]; out[2] = day[2]; out[3] = ','; out[4] = ' ';
    put2(out + 5, tm.tm_mday); out[7] = ' ';
    out[8] = mon[0]; out[9] = mon[1]; out[10] = mon[2]; out[11] = ' ';
    out[12] = static_cast<char>('0' + (year / 1000) % 10);
    out[13] = static_cast<char>('0' + (year / 100) % 10);
    out[14] = static_cast<char>('0' + (year / 10) % 10);
    out[15] = static_cast<char>('0' + year % 10);
    out[16] = ' ';
    put2(out + 17, tm.tm_hour); out[19] = ':';
    put2(out + 20, tm.tm_min); out[22] = ':';
    put2(out + 23, tm.tm_sec);
    out[25] = ' '; out[26] = 'G'; out[27] = 'M'; out[28] = 'T';
}

}  // namespace agensio
