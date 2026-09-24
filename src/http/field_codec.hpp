// What HPACK (RFC 7541) and QPACK (RFC 9204) share: the Huffman code and its decoding
// automaton (RFC 9204 4.1.2 adopts RFC 7541's), the prefixed integer representation
// (RFC 7541 5.1, RFC 9204 4.1.1), and the dynamic table, a ring of entries evicted
// oldest first, with the mark the request assembler sets once an entry's field rules have
// passed (design-http2 6.4: the rules run once per entry, not once per reference). Lifted
// out of http2/hpack in phase I so both codecs are one copy (design-http3 section 4).
// Tables come from tools/gen-hpack-tables.py (codec_tables.hpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace agensio::codec {

// ---- Huffman coding ----

// Bytes the Huffman coding of `s` takes.
std::size_t huffman_size(std::string_view s) noexcept;
// Appends the Huffman coding of `s`, padded with the leading bits of EOS.
void huffman_encode(std::string& out, std::string_view s);

enum class HuffStatus { ok, malformed, too_large };
// Appends the decoded symbols to `out`; stops with too_large when more than `max_out`
// symbols would be produced (the caller's list-size budget), malformed on a code that
// does not exist, EOS in the data, or padding other than up to seven 1-bits.
HuffStatus huffman_decode(std::string_view in, std::string& out, std::size_t max_out);

// ---- prefixed integers ----

// Appends `value` with an N-bit prefix; `prefix_flags` are the high bits of the first byte.
void append_integer(std::string& out, std::uint64_t value, unsigned prefix_bits, std::uint8_t prefix_flags);
// Reads an N-bit-prefix integer at in[pos], advancing pos. False when truncated or above 2^32-1.
bool read_integer(std::string_view in, std::size_t& pos, unsigned prefix_bits, std::uint32_t& value) noexcept;

// Where a decoded field came from: name and value both from the static table (a token
// and a clean value by construction), a dynamic-table entry whose `checked` mark the sink
// may set once its rules have passed, so they run once per entry and not once per
// reference, or a literal (nothing known, `checked` null).
struct Origin {
    bool static_table = false;
    std::uint8_t* checked = nullptr;
};

// ---- the dynamic table ----

// A ring of entries, the newest at head, evicted oldest first as the limit demands. A
// decoder mirrors the peer's encoder with one; our encoders keep their own, so both sides
// of a connection evict by the same code. Allocated on the first insertion. HPACK
// addresses an entry by its distance from the newest; QPACK by an absolute index, which
// the QPACK codec turns into that distance with its insert count.
class DynamicTable {
public:
    static constexpr std::size_t npos = static_cast<std::size_t>(-1);
    explicit DynamicTable(std::size_t capacity) : capacity_(capacity), limit_(capacity) {}
    // Adds the entry, evicting to make room. False, with the table emptied, when the entry
    // alone is larger than the limit (RFC 7541 4.4).
    bool add(std::string_view name, std::string_view value);
    // Changes the maximum size (a size update, a SETTINGS change), evicting to fit.
    void set_limit(std::size_t limit) noexcept;
    void evict_to(std::size_t limit) noexcept;
    // The entry k places from the newest (0 = newest).
    bool at(std::size_t k, std::string_view& name, std::string_view& value) const noexcept;
    // The place (0 = newest) of the newest entry with this name and value, or npos.
    std::size_t find(std::string_view name, std::string_view value) const noexcept;
    // The entry k places from the newest, with its mark.
    bool at(std::size_t k, std::string_view& name, std::string_view& value, std::uint8_t*& mark) const noexcept;
    std::uint8_t* newest_mark() const noexcept { return count_ ? &ring_[head_].checked : nullptr; }
    std::size_t size() const noexcept { return size_; }
    std::size_t count() const noexcept { return count_; }
    std::size_t limit() const noexcept { return limit_; }

private:
    struct Entry {
        std::string name;
        std::string value;
        mutable std::uint8_t checked = 0;  // the decoder's sink marks an entry whose rules have passed
    };
    std::vector<Entry> ring_;  // circular; the newest entry at head_
    std::size_t head_ = 0;
    std::size_t count_ = 0;
    std::size_t size_ = 0;     // RFC 7541 4.1 size of the entries held
    std::size_t capacity_;     // the ring is sized for it on the first insertion
    std::size_t limit_;        // the current maximum
};

}  // namespace agensio::codec
