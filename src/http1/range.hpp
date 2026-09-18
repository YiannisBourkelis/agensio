// Range requests (RFC 9110 section 14) for the static handler: one byte range of a body
// of known size. "bytes=first-last", "bytes=first-" and "bytes=-suffix"; a list of ranges
// is not served in parts (the whole body goes out with 200, which the RFC allows) and
// anything malformed is treated the same way. Header-only, no I/O.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "core/headers.hpp"

namespace agensio {

enum class RangeStatus {
    none,           // no usable single range: answer 200 with the whole body
    single,         // [first, last] inclusive, within the body
    unsatisfiable,  // a well-formed range entirely past the end: 416
};

inline RangeStatus parse_range(std::string_view value, std::uint64_t size, std::uint64_t& first,
                               std::uint64_t& last) noexcept {
    auto trim = [](std::string_view& v) {
        while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
        while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.remove_suffix(1);
    };
    trim(value);
    if (value.size() < 7 || !Headers::iequals(value.substr(0, 6), "bytes=")) return RangeStatus::none;
    std::string_view spec = value.substr(6);
    trim(spec);
    if (spec.empty() || spec.find(',') != std::string_view::npos) return RangeStatus::none;
    const std::size_t dash = spec.find('-');
    if (dash == std::string_view::npos) return RangeStatus::none;
    auto number = [](std::string_view s, std::uint64_t& out) {
        if (s.empty() || s.size() > 19) return false;
        out = 0;
        for (char c : s) {
            if (c < '0' || c > '9') return false;
            out = out * 10 + static_cast<std::uint64_t>(c - '0');
        }
        return true;
    };
    std::string_view a = spec.substr(0, dash), b = spec.substr(dash + 1);
    trim(a);
    trim(b);
    if (a.empty()) {  // "-suffix": the last N bytes
        std::uint64_t n = 0;
        if (!number(b, n) || n == 0) return RangeStatus::none;
        if (size == 0) return RangeStatus::unsatisfiable;
        first = n >= size ? 0 : size - n;
        last = size - 1;
        return RangeStatus::single;
    }
    if (!number(a, first)) return RangeStatus::none;
    if (b.empty()) {  // "first-": to the end
        if (first >= size) return RangeStatus::unsatisfiable;
        last = size - 1;
        return RangeStatus::single;
    }
    if (!number(b, last) || last < first) return RangeStatus::none;
    if (first >= size) return RangeStatus::unsatisfiable;
    if (last >= size) last = size - 1;
    return RangeStatus::single;
}

// If-Range (RFC 9110 section 13.1.5): the range applies only when the validator still
// matches, by strong ETag or by the exact Last-Modified date; otherwise the whole body.
inline bool if_range_matches(std::string_view if_range, std::string_view etag, std::string_view last_modified) noexcept {
    if (if_range.empty()) return true;
    while (!if_range.empty() && (if_range.front() == ' ' || if_range.front() == '\t')) if_range.remove_prefix(1);
    while (!if_range.empty() && (if_range.back() == ' ' || if_range.back() == '\t')) if_range.remove_suffix(1);
    if (if_range.starts_with("W/")) return false;  // a weak validator never permits a range
    if (if_range.starts_with("\"")) return if_range == etag;
    return if_range == last_modified;
}

}  // namespace agensio
