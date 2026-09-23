// HPACK (RFC 7541): the decoder with its dynamic table and Huffman automaton, and the
// encoding helpers the writer uses. The encoder side never touches a dynamic table
// (static indexes and literals only, Huffman when shorter), so every encoding is
// state-independent and can be built once and copied per response (nginx's discipline;
// what makes a cache entry's prebuilt HPACK block possible). Decoded names and values are
// appended to an arena the stream owns and reported as views into it: one copy, no
// allocation per field. Tables come from tools/gen-hpack-tables.py (hpack_tables.hpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace agensio::hpack {

// ---- Huffman coding (section 5.2) ----

// Bytes the Huffman coding of `s` takes.
std::size_t huffman_size(std::string_view s) noexcept;
// Appends the Huffman coding of `s`, padded with the leading bits of EOS.
void huffman_encode(std::string& out, std::string_view s);

enum class HuffStatus { ok, malformed, too_large };
// Appends the decoded symbols to `out`; stops with too_large when more than `max_out`
// symbols would be produced (the caller's list-size budget), malformed on a code that
// does not exist, EOS in the data, or padding other than up to seven 1-bits.
HuffStatus huffman_decode(std::string_view in, std::string& out, std::size_t max_out);

// ---- integers (section 5.1) ----

// Appends `value` with an N-bit prefix; `prefix_flags` are the high bits of the first byte.
void append_integer(std::string& out, std::uint64_t value, unsigned prefix_bits, std::uint8_t prefix_flags);
// Reads an N-bit-prefix integer at in[pos], advancing pos. False when truncated or above 2^32-1.
bool read_integer(std::string_view in, std::size_t& pos, unsigned prefix_bits, std::uint32_t& value) noexcept;

// ---- encoding: static table and literals only ----

// The index of the first static entry named `name` (lower-case), 0 when there is none.
unsigned static_name_index(std::string_view name) noexcept;
// The index of the static entry with exactly this name and value, 0 when there is none.
unsigned static_index(std::string_view name, std::string_view value) noexcept;
// A string literal: Huffman when that is shorter, the H bit and a 7-bit-prefix length.
void append_string(std::string& out, std::string_view s);
// Indexed header field (6.1).
void append_indexed(std::string& out, unsigned index);
// Literal header field without indexing (6.2.2), the name by static index or as a literal.
void append_literal(std::string& out, unsigned name_index, std::string_view value);
void append_literal(std::string& out, std::string_view name, std::string_view value);
// A field by name (lower-case): indexed when the static table has the exact pair, else a
// literal with the static name index when the name is there, else a literal name.
void append_field(std::string& out, std::string_view name, std::string_view value);
// The :status pseudo-header: one byte for the seven static values, a literal otherwise.
void append_status(std::string& out, int status);

// ---- decoding ----

class Decoder {
public:
    enum class Result {
        ok,
        malformed,  // COMPRESSION_ERROR: index 0 or out of range, a size update above the
                    // ceiling or after a field, a truncated integer or string, bad Huffman data
        too_large,  // the decoded list would exceed max_list_size (stopped at that field)
        too_many,   // the sink refused a field (too many fields)
    };
    // `ceiling` is the SETTINGS_HEADER_TABLE_SIZE we advertised: the most the peer may set.
    explicit Decoder(std::size_t ceiling = 4096);

    // Decodes one complete block. Every field is appended to `arena` and reported as
    // views into it through `sink(name, value)`; a false from the sink stops the decode.
    // The arena is reserved for max_list_size bytes first and never reallocates during
    // the call, so the views stay valid for as long as the caller keeps the arena.
    // The list size (name + value + 32 per field, RFC 7541 4.1) is added up as fields are
    // produced and the decode stops at the first field over max_list_size: a compression
    // bomb costs at most that many bytes.
    using SinkFn = bool (*)(void*, std::string_view, std::string_view);
    Result decode(std::string_view block, std::string& arena, std::size_t max_list_size, SinkFn sink, void* ctx);
    template <class F>
    Result decode(std::string_view block, std::string& arena, std::size_t max_list_size, F&& f) {
        return decode(
            block, arena, max_list_size,
            [](void* c, std::string_view n, std::string_view v) { return (*static_cast<F*>(c))(n, v); }, &f);
    }

    std::size_t table_size() const noexcept { return size_; }
    std::size_t table_entries() const noexcept { return count_; }
    std::size_t table_limit() const noexcept { return limit_; }

private:
    struct Entry {
        std::string name;
        std::string value;
    };
    enum class StrStatus { ok, malformed, too_large };

    void add(std::string_view name, std::string_view value);
    void evict_to(std::size_t limit) noexcept;
    bool lookup(std::uint32_t index, std::string_view& name, std::string_view& value) const noexcept;
    // Reads a string literal at in[pos] into the arena (at most `max_out` decoded bytes).
    StrStatus read_string(std::string_view in, std::size_t& pos, std::string& arena, std::size_t max_out,
                          std::string_view& out);

    std::vector<Entry> ring_;  // circular; the newest entry at head_
    std::size_t head_ = 0;
    std::size_t count_ = 0;
    std::size_t size_ = 0;     // RFC 4.1 size of the entries held
    std::size_t ceiling_;      // what we advertised
    std::size_t limit_;        // the current maximum (size updates move it, up to the ceiling)
};

}  // namespace agensio::hpack
