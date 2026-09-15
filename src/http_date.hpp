// RFC 7231 IMF-fixdate formatting ("Sun, 06 Nov 1994 08:49:37 GMT") and a
// per-worker cache of the current Date header value.
#pragma once

#include <ctime>
#include <string_view>

namespace agensio {

inline constexpr std::size_t kHttpDateLength = 29;

// Writes exactly 29 characters (no terminator) into out.
void format_http_date(std::time_t t, char* out);

// Caches the formatted current time; refreshes at most once per second.
// One instance per worker thread, never shared.
class DateCache {
public:
    std::string_view now() { return at(std::time(nullptr)); }

    // Same, for a caller that already read the clock.
    std::string_view at(std::time_t t) {
        if (t != last_) {
            format_http_date(t, buf_);
            last_ = t;
        }
        return {buf_, kHttpDateLength};
    }

private:
    std::time_t last_ = 0;
    char buf_[kHttpDateLength] = {};
};

}  // namespace agensio
