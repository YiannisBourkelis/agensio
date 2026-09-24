// HPACK (RFC 7541): the decoder with its dynamic table and Huffman automaton, the
// state-free encoding helpers (static indexes and literals, Huffman when shorter) that
// prebuilt blocks are made of, and the connection's Encoder (design 6.2.1): a small
// dynamic table for the fields that repeat across a connection's answers (server, date,
// content-type and whatever a handler's or an upstream's block repeats), while a cache
// entry's validators stay a prebuilt literal tail. Both tables are one DynamicTable, so
// our encoder evicts by the same code as our decoder. Decoded names and values are
// appended to an arena the stream owns and reported as views into it: one copy, no
// allocation per field. Tables come from tools/gen-hpack-tables.py (hpack_tables.hpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
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
// Literal header field with incremental indexing (6.2.1): the representation that inserts
// the field into the decoder's table; the name by static index when it is there.
void append_insert(std::string& out, std::string_view name, std::string_view value);
// Literal header field never indexed (6.2.3): for fields that must not be compressed.
void append_never_indexed(std::string& out, std::string_view name, std::string_view value);

// ---- the dynamic table (section 4) ----

// A ring of entries, the newest at head, evicted oldest first as the limit demands. The
// decoder mirrors the peer's encoder with one; our Encoder keeps its own, so both sides
// of a connection evict by the same code. Allocated on the first insertion.
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
    std::size_t size() const noexcept { return size_; }
    std::size_t count() const noexcept { return count_; }
    std::size_t limit() const noexcept { return limit_; }

private:
    struct Entry {
        std::string name;
        std::string value;
    };
    std::vector<Entry> ring_;  // circular; the newest entry at head_
    std::size_t head_ = 0;
    std::size_t count_ = 0;
    std::size_t size_ = 0;     // RFC 4.1 size of the entries held
    std::size_t capacity_;     // the ring is sized for it on the first insertion
    std::size_t limit_;        // the current maximum
};

// ---- the response encoder (design 6.2.1) ----

// One per connection. A field goes out as a static index when the static table has the
// pair, as an index into this table when it holds the pair, else it is inserted (a
// literal with incremental indexing), except content-length and the validators, which
// change per answer and stay literal, and the sensitive names, never indexed. `server`
// and `date` are remembered by sequence number so they cost no scan: one index byte per
// answer, one insertion per connection for server and one per second for date, whose
// insertion bytes the worker prebuilds. The table is min(the peer's
// SETTINGS_HEADER_TABLE_SIZE, kMaxSize); a block begins with a size update when the
// decoder assumes another size (RFC 7541 4.2, 6.3).
class Encoder {
public:
    static constexpr std::size_t kMaxSize = 1024;  // at most 32 entries of at least 32 bytes each
    Encoder() : table_(kMaxSize) {}
    // The peer's SETTINGS_HEADER_TABLE_SIZE (4096 until it says otherwise).
    void set_peer_max(std::uint32_t value);
    // At the start of every header block: the pending size update, if any.
    void begin(std::string& out);
    // A field by lower-case name.
    void field(std::string& out, std::string_view name, std::string_view value);
    // server and date: `insert_bytes` is append_insert(name, value), prebuilt by the caller.
    void server(std::string& out, std::string_view value, std::string_view insert_bytes);
    void date(std::string& out, std::time_t second, std::string_view value, std::string_view insert_bytes);
    std::size_t table_size() const noexcept { return table_.size(); }
    std::size_t table_entries() const noexcept { return table_.count(); }
    std::size_t table_limit() const noexcept { return max_; }

private:
    enum class Policy { index, literal, never };
    static Policy policy(std::string_view name) noexcept;
    bool alive(std::uint64_t seq) const noexcept { return seq != 0 && seq + table_.count() >= next_seq_; }
    unsigned index_of(std::uint64_t seq) const noexcept { return static_cast<unsigned>(61 + (next_seq_ - seq)); }
    bool insert(std::string_view name, std::string_view value);

    DynamicTable table_;
    std::uint64_t next_seq_ = 1;  // the sequence the next insertion gets
    std::uint64_t server_seq_ = 0;
    std::uint64_t date_seq_ = 0;
    std::time_t date_second_ = 0;
    std::size_t max_ = kMaxSize;  // our maximum: min(peer, kMaxSize)
    std::size_t floor_ = kMaxSize;  // the lowest maximum since the last update sent: a decoder that
                                    // only learns sizes from updates must evict to it first (RFC 7541 4.2)
    std::size_t assumed_ = 4096;  // what the decoder takes as its maximum until told
    bool pending_update_ = true;  // the first block tells it ours
};

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

    std::size_t table_size() const noexcept { return table_.size(); }
    std::size_t table_entries() const noexcept { return table_.count(); }
    std::size_t table_limit() const noexcept { return table_.limit(); }

private:
    enum class StrStatus { ok, malformed, too_large };

    bool lookup(std::uint32_t index, std::string_view& name, std::string_view& value) const noexcept;
    // Reads a string literal at in[pos] into the arena (at most `max_out` decoded bytes).
    StrStatus read_string(std::string_view in, std::size_t& pos, std::string& arena, std::size_t max_out,
                          std::string_view& out);

    DynamicTable table_;
    std::size_t ceiling_;  // what we advertised: the most a size update may set
};

}  // namespace agensio::hpack
