// QPACK (RFC 9204): field sections over the static table and literals. This slice
// advertises a dynamic table capacity of 0 (SETTINGS_QPACK_MAX_TABLE_CAPACITY), so a
// client's encoder may not use its dynamic table (3.2.3) and the decoder needs no
// instruction streams; the decoder with the dynamic table, the rules-once marks and the
// encoder stream come in phase I3 (design-http3 7.2). The Huffman code and the prefixed
// integers are the codec shared with HPACK (http/field_codec.hpp); the static table is
// generated (qpack_tables.hpp).
#pragma once

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "http/field_codec.hpp"

namespace agensio::qpack {

using codec::Origin;
inline constexpr unsigned kStaticCount = 99;

// The first static entry named `name` (lower-case) and the static pair, false when none.
bool static_name(std::string_view name, unsigned& index) noexcept;
bool static_pair(std::string_view name, std::string_view value, unsigned& index) noexcept;

// ---- encoding (4.5): the static table and literals only ----

// The section prefix for a section without dynamic references: Required Insert Count 0, Base 0.
inline void append_section_prefix(std::string& out) { out.append("\0\0", 2); }
// A string literal: Huffman when shorter, the H bit and a 7-bit-prefix length (4.1.2).
void append_string(std::string& out, std::string_view s);
// Indexed field line with a static index (4.5.2).
void append_indexed(std::string& out, unsigned index);
// Literal field line with a static name reference (4.5.4).
void append_literal_name_ref(std::string& out, unsigned index, std::string_view value);
// Literal field line with a literal name (4.5.6).
void append_literal(std::string& out, std::string_view name, std::string_view value);
// A field by lower-case name: the static pair when there is one, else the static name,
// else both literal.
void append_field(std::string& out, std::string_view name, std::string_view value);
// :status: one byte for the fourteen static values, a literal otherwise.
void append_status(std::string& out, int status);

// ---- decoding (sections 3, 4.3, 4.4, 4.5) ----

// The decoder with its dynamic table: the encoder stream's instructions (set capacity,
// insert with a name reference, insert with a literal name, duplicate) fill it, a field
// section's prefix names the insert count it needs (Required Insert Count) and its base,
// and a section that needs more than the table has waits (Result::blocked) until the
// encoder stream delivers it. Dynamic entries carry the rules-once mark of
// design-http2 6.4, as HPACK's do. The decoder stream (section acknowledgements, stream
// cancellations, insert count increments) is written to a string the connection sends.
class Decoder {
public:
    static constexpr std::size_t kMaxCapacity = 4096;  // what we advertise (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    static constexpr std::size_t kMaxBlocked = 16;     // SETTINGS_QPACK_BLOCKED_STREAMS

    enum class Result {
        ok,
        malformed,  // QPACK_DECOMPRESSION_FAILED: an index out of range or evicted, a bad prefix,
                    // a truncated integer or string, bad Huffman data
        too_large,  // the decoded list would exceed max_list_size (stopped at that field)
        blocked,    // the section needs inserts the encoder stream has not delivered yet
    };
    explicit Decoder(std::size_t max_capacity = kMaxCapacity) : table_(max_capacity), max_capacity_(max_capacity) { table_.set_limit(0); }

    using SinkFn = bool (*)(void*, std::string_view, std::string_view, Origin);
    // Decodes one complete field section: every field reported as views into `arena`
    // (literal bytes and dynamic entries, copied) or the static table. `required` receives
    // the section's Required Insert Count (0: no dynamic references). The list size (name
    // + value + 32 per field) stops the decode at the first field over max_list_size.
    Result decode(std::string_view section, std::string& arena, std::size_t max_list_size, SinkFn sink, void* ctx,
                  std::uint64_t& required);
    template <class F>
    Result decode(std::string_view section, std::string& arena, std::size_t max_list_size, F&& f, std::uint64_t& required) {
        using Fn = std::remove_reference_t<F>;
        return decode(section, arena, max_list_size,
                      [](void* c, std::string_view n, std::string_view v, Origin o) { return (*static_cast<Fn*>(c))(n, v, o); }, &f, required);
    }
    // Without the count, for sections that cannot reference the dynamic table (tests, prebuilt blocks).
    template <class F>
    Result decode(std::string_view section, std::string& arena, std::size_t max_list_size, F&& f) {
        std::uint64_t required = 0;
        return decode(section, arena, max_list_size, static_cast<F&&>(f), required);
    }

    // Bytes of the encoder stream (4.3): the complete instructions are applied and
    // `consumed` says how many bytes they took; an incomplete last one waits for more.
    // False is QPACK_ENCODER_STREAM_ERROR (a capacity above ours, an entry larger than
    // the capacity, a reference to an evicted or unknown entry, bad Huffman data).
    bool encoder_stream(std::string_view in, std::size_t& consumed);

    // The decoder stream (4.4), appended to `out`.
    void section_acknowledged(std::uint64_t stream_id, std::uint64_t required, std::string& out);
    void stream_cancelled(std::uint64_t stream_id, std::string& out);
    // Tells the encoder about inserts no acknowledged section covered; nothing when none.
    void insert_count_increment(std::string& out);

    std::uint64_t insert_count() const noexcept { return insert_count_; }
    std::uint64_t known_received() const noexcept { return known_; }
    std::size_t capacity() const noexcept { return table_.limit(); }
    std::size_t table_size() const noexcept { return table_.size(); }
    std::size_t table_entries() const noexcept { return table_.count(); }

    enum class StrStatus { ok, malformed, too_large, incomplete };
    static StrStatus read_string(std::string_view in, std::size_t& pos, bool huffman, std::size_t len, std::string& arena,
                                 std::size_t max_out, std::string_view& out);

private:
    // The entry with an absolute index, if the table still holds it.
    bool entry(std::uint64_t abs, std::string_view& name, std::string_view& value, std::uint8_t*& mark) const noexcept;

    codec::DynamicTable table_;
    std::size_t max_capacity_;
    std::uint64_t insert_count_ = 0;
    std::uint64_t known_ = 0;  // what the encoder knows we received (acknowledgements, increments)
    std::string name_scratch_, value_scratch_;
};

// The encoder side of our answers with the peer's dynamic table (sections 3, 4.3, 4.5;
// design-http3 7.2's second step): server, date, content-type and alt-svc go through the
// table, inserted with a static name reference and then one index byte each, at most
// kMaxCapacity of it and at most the peer's setting. A section that references an entry
// the peer has not acknowledged may block there (RFC 9204 2.1.2), at most the peer's
// SETTINGS_QPACK_BLOCKED_STREAMS of them at once; beyond that, and for a peer that
// allows none, the field is a literal until the acknowledgement arrives. An entry a
// pending section references is never evicted (2.1.1). Everything else stays static or
// literal. The encoder mirrors the peer's table: what it holds, the peer holds once the
// encoder stream is delivered, and the section that needs an insert follows it. Nothing
// here scans per answer: each field remembers its entry, and a section's references live
// in the stream that sent it (Section), so an acknowledgement or a close is a few stores.

// A section's references while the peer has not acknowledged it; owned by the stream.
struct Section {
    std::uint64_t ric = 0;   // Required Insert Count: the highest referenced entry plus one
    std::uint64_t refs[4] = {};
    unsigned n = 0;
    bool pending = false;    // sent with dynamic references: the entries stay until acknowledged
    bool blocking = false;   // referenced an entry the peer had not acknowledged: counts against its limit
};

class Encoder {
public:
    static constexpr std::size_t kMaxCapacity = 1024;
    // The peer's SETTINGS (once per connection): the capacity to use is the smaller of its and ours.
    void set_peer(std::uint64_t capacity, std::uint64_t blocked_streams);
    bool enabled() const noexcept { return capacity_ > 0; }
    // The encoder stream's instructions since the connection last took them (the capacity
    // once, then inserts); they go out before the section that uses them.
    std::string& instructions() noexcept { return instructions_; }

    // A section: begin with the stream's record, the fields, prefix() ahead of the fields'
    // bytes, end() once the section is on its way.
    void begin(Section& section) noexcept;
    void server(std::string& out, std::string_view value) { memo_field(out, 92, "server", value, server_); }
    // The date by second: a run of answers in one second costs a comparison and an index byte.
    void date(std::string& out, std::time_t second, std::string_view value);
    void content_type(std::string& out, std::string_view value);
    void alt_svc(std::string& out, std::string_view value) { memo_field(out, 83, "alt-svc", value, alt_svc_); }
    // Any field by static name index, remembered in `memo` (a scan of the table otherwise).
    struct Memo {
        std::uint64_t abs = 0;
        bool valid = false;
        std::string value;
    };
    void memo_field(std::string& out, unsigned static_name, std::string_view name, std::string_view value, Memo& memo);
    void prefix(std::string& out);
    void end();

    // The peer's decoder stream (4.4): acknowledgements and cancellations are reported by
    // stream id through `on_section(id, cancelled)`, increments applied here. False is
    // QPACK_DECODER_STREAM_ERROR; `consumed` says how many bytes the complete
    // instructions took.
    template <class F>
    bool decoder_stream(std::string_view in, std::size_t& consumed, F&& on_section) {
        std::size_t pos = 0;
        consumed = 0;
        while (pos < in.size()) {
            const unsigned char b = static_cast<unsigned char>(in[pos]);
            std::uint32_t v = 0;
            std::size_t p = pos;
            if (b & 0x80) {  // Section Acknowledgement (4.4.1)
                if (!codec::read_integer(in, p, 7, v)) return in.size() - pos < 12;
                on_section(static_cast<std::uint64_t>(v), false);
            } else if (b & 0x40) {  // Stream Cancellation (4.4.2)
                if (!codec::read_integer(in, p, 6, v)) return in.size() - pos < 12;
                on_section(static_cast<std::uint64_t>(v), true);
            } else {  // Insert Count Increment (4.4.3)
                if (!codec::read_integer(in, p, 6, v)) return in.size() - pos < 12;
                if (!increment(v)) return false;
            }
            pos = p;
            consumed = pos;
        }
        return true;
    }
    // A Section Acknowledgement for the stream holding `section`: the peer decoded it.
    void acknowledged(Section& section) noexcept;
    // A Stream Cancellation, or the stream closed: its references are released.
    void cancelled(Section& section) noexcept;
    bool increment(std::uint64_t n) noexcept;

    std::uint64_t insert_count() const noexcept { return insert_count_; }
    std::uint64_t known_received() const noexcept { return known_; }
    std::size_t table_entries() const noexcept { return entries_.size(); }
    std::size_t table_size() const noexcept { return size_; }
    std::size_t blocking_sections() const noexcept { return blocking_; }
    std::size_t capacity() const noexcept { return capacity_; }

private:
    struct Entry {
        std::uint64_t abs = 0;
        std::size_t size = 0;
        unsigned refs = 0;  // sections sent and not yet acknowledged that reference it
        std::string name, value;
    };
    bool held(std::uint64_t abs) const noexcept {
        return !entries_.empty() && abs >= entries_.front().abs && abs < insert_count_;
    }
    Entry* entry(std::uint64_t abs) noexcept {
        return held(abs) ? &entries_[static_cast<std::size_t>(abs - entries_.front().abs)] : nullptr;
    }
    bool usable(std::uint64_t abs) const noexcept;
    bool insert(unsigned static_name, std::string_view name, std::string_view value, std::uint64_t& abs);
    void reference(std::string& out, std::uint64_t abs);
    void release(Section& section) noexcept;

    std::string instructions_;
    std::vector<Entry> entries_;  // oldest first
    std::size_t size_ = 0, capacity_ = 0;
    std::uint64_t peer_capacity_ = 0, peer_blocked_ = 0;
    bool capacity_sent_ = false;
    std::uint64_t insert_count_ = 0;
    std::uint64_t known_ = 0;
    std::size_t blocking_ = 0;  // pending sections that may block the peer
    Section* current_ = nullptr;
    std::uint64_t base_ = 0;
    Memo server_, alt_svc_, ct_;
    // The last content-type value's static lookup (eleven values are rows of appendix A): a
    // value repeats across a connection's answers, so the table is searched once per change.
    std::string ct_seen_;
    unsigned ct_seen_index_ = 0;
    bool ct_seen_valid_ = false, ct_seen_static_ = false;
    std::uint64_t date_abs_ = 0;
    std::time_t date_second_ = 0;
    bool date_valid_ = false;
};

}  // namespace agensio::qpack
