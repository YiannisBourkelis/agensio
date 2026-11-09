// The send bytes of a stream that are appended as they come (a streamed answer, design-http3 7.3),
// kept from their append until the peer acknowledges them: QUIC sends a lost range again from the
// sender's copy (RFC 9000 13.3), so the bytes outlive the packet that carried them. Fixed blocks are
// taken as the bytes arrive and freed as the acknowledgements pass them, so a stream holds what is in
// flight and what waits for its window, never the whole answer. A piece is written into one block (its
// source reads into one contiguous room), so a block may end short and the next starts where it ends:
// the stream's offsets run on unbroken. The connection's budget counts every block of its streams.
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

namespace agensio::quic {

class SendBlocks {
public:
    static constexpr std::size_t kSize = 16384;

    SendBlocks() = default;
    SendBlocks(const SendBlocks&) = delete;
    SendBlocks& operator=(const SendBlocks&) = delete;

    // The connection's count of the blocks its streams hold (set once; it outlives the streams).
    void budget(std::size_t* count) noexcept { budget_ = count; }

    bool empty() const noexcept { return blocks_.empty(); }
    std::size_t count() const noexcept { return blocks_.size(); }

    // Whether the next piece takes a new block: the last one has fewer than `min` bytes left.
    bool needs_block(std::size_t min) const noexcept { return blocks_.empty() || kSize - blocks_.back().len < min; }

    // The room for the next piece, which starts at stream offset `end` (where the appended bytes stop):
    // the rest of the last block when `min` bytes are left there, else a new block.
    char* room(std::uint64_t end, std::size_t min, std::size_t& len) {
        if (needs_block(min)) {
            blocks_.push_back(Block{std::unique_ptr<char[]>(new char[kSize]), end, 0});
            if (budget_) ++*budget_;
        }
        Block& b = blocks_.back();
        len = kSize - b.len;
        return b.data.get() + b.len;
    }
    // `n` bytes were written at room()'s pointer.
    void appended(std::size_t n) noexcept { blocks_.back().len += n; }

    // The bytes [off, off + len) into dst; false when any of them is not held.
    bool copy(std::uint64_t off, std::size_t len, unsigned char* dst) const noexcept {
        if (blocks_.empty() || off < blocks_.front().off) return false;
        auto it = std::upper_bound(blocks_.begin(), blocks_.end(), off, [](std::uint64_t o, const Block& b) { return o < b.off; });
        for (--it; len > 0; ++it) {
            if (it == blocks_.end()) return false;
            const std::uint64_t rel = off - it->off;
            if (rel >= it->len) return false;
            const std::size_t n = std::min<std::size_t>(len, it->len - static_cast<std::size_t>(rel));
            std::memcpy(dst, it->data.get() + rel, n);
            dst += n;
            off += n;
            len -= n;
        }
        return true;
    }

    // Every byte below `upto` is acknowledged: the blocks wholly below it are freed, never the last,
    // which a read may be writing into.
    void release_below(std::uint64_t upto) noexcept {
        std::size_t n = 0;
        while (n + 1 < blocks_.size() && blocks_[n].off + blocks_[n].len <= upto) ++n;
        if (n == 0) return;
        blocks_.erase(blocks_.begin(), blocks_.begin() + static_cast<std::ptrdiff_t>(n));
        if (budget_) *budget_ -= n;
    }

    void clear() noexcept {
        if (budget_) *budget_ -= blocks_.size();
        std::vector<Block>().swap(blocks_);  // a pooled stream keeps no list either
    }

private:
    struct Block {
        std::unique_ptr<char[]> data;
        std::uint64_t off = 0;  // the stream offset of its first byte
        std::size_t len = 0;    // the bytes appended
    };
    std::vector<Block> blocks_;  // a vector, not a deque: an empty deque allocates, and every pooled stream has one
    std::size_t* budget_ = nullptr;
};

}  // namespace agensio::quic
