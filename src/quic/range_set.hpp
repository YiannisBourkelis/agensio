// A set of half-open ranges [begin, end) over 64-bit offsets or packet numbers, kept
// sorted, disjoint and merged: the packet numbers received (ACK frames, RFC 9000 19.3),
// the bytes of a stream that arrived out of order, the bytes acknowledged, the bytes to
// resend. Small vectors: a connection in good health holds one range in each.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

namespace agensio::quic {

class RangeSet {
public:
    using Range = std::pair<std::uint64_t, std::uint64_t>;  // [begin, end)

    bool empty() const noexcept { return r_.empty(); }
    std::size_t count() const noexcept { return r_.size(); }
    const std::vector<Range>& ranges() const noexcept { return r_; }
    void clear() noexcept { r_.clear(); }
    std::uint64_t max() const noexcept { return r_.empty() ? 0 : r_.back().second - 1; }  // the largest value held
    std::uint64_t min() const noexcept { return r_.empty() ? 0 : r_.front().first; }
    // The end of the range that starts at `from` (0 when none does): the contiguous prefix.
    std::uint64_t contiguous_from(std::uint64_t from) const noexcept {
        for (const Range& x : r_)
            if (x.first <= from && from < x.second) return x.second;
        return from;
    }

    void add(std::uint64_t begin, std::uint64_t end) {
        if (begin >= end) return;
        // The first range that could touch [begin, end): its end >= begin.
        auto it = std::lower_bound(r_.begin(), r_.end(), begin, [](const Range& x, std::uint64_t b) { return x.second < b; });
        if (it == r_.end() || it->first > end) {
            r_.insert(it, Range{begin, end});
            return;
        }
        // Merge every range overlapping or adjacent.
        it->first = std::min(it->first, begin);
        it->second = std::max(it->second, end);
        auto next = it + 1;
        while (next != r_.end() && next->first <= it->second) {
            it->second = std::max(it->second, next->second);
            next = r_.erase(next);
        }
    }
    void add_point(std::uint64_t v) { add(v, v + 1); }

    bool contains(std::uint64_t begin, std::uint64_t end) const noexcept {
        for (const Range& x : r_)
            if (x.first <= begin && end <= x.second) return true;
        return false;
    }
    bool contains_point(std::uint64_t v) const noexcept { return contains(v, v + 1); }

    // Removes everything below `upto`.
    void remove_below(std::uint64_t upto) {
        while (!r_.empty() && r_.front().second <= upto) r_.erase(r_.begin());
        if (!r_.empty() && r_.front().first < upto) r_.front().first = upto;
    }
    // Removes [begin, end), splitting a range that spans it.
    void remove(std::uint64_t begin, std::uint64_t end) {
        if (begin >= end) return;
        for (std::size_t i = 0; i < r_.size();) {
            Range& x = r_[i];
            if (x.second <= begin || x.first >= end) { ++i; continue; }
            if (x.first < begin && x.second > end) {  // split
                const std::uint64_t tail_end = x.second;
                x.second = begin;
                r_.insert(r_.begin() + static_cast<std::ptrdiff_t>(i) + 1, Range{end, tail_end});
                return;
            }
            if (x.first < begin) { x.second = begin; ++i; continue; }
            if (x.second > end) { x.first = end; ++i; continue; }
            r_.erase(r_.begin() + static_cast<std::ptrdiff_t>(i));
        }
    }
    // Keeps the `n` highest ranges (an ACK frame's budget; the oldest gaps are forgotten).
    void keep_highest(std::size_t n) {
        if (r_.size() > n) r_.erase(r_.begin(), r_.begin() + static_cast<std::ptrdiff_t>(r_.size() - n));
    }
    // The first range at or above `from` that is not in the set, within [from, limit): a gap.
    bool first_gap(std::uint64_t from, std::uint64_t limit, std::uint64_t& gb, std::uint64_t& ge) const noexcept {
        std::uint64_t pos = from;
        for (const Range& x : r_) {
            if (x.second <= pos) continue;
            if (x.first > pos) {
                gb = pos;
                ge = std::min(x.first, limit);
                return gb < ge;
            }
            pos = x.second;
            if (pos >= limit) return false;
        }
        if (pos < limit) {
            gb = pos;
            ge = limit;
            return true;
        }
        return false;
    }

private:
    std::vector<Range> r_;
};

}  // namespace agensio::quic
