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
#include <string>
#include <string_view>
#include <type_traits>

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

// ---- decoding ----

class Decoder {
public:
    enum class Result {
        ok,
        malformed,  // QPACK_DECOMPRESSION_FAILED: a dynamic reference (no table), an index out of range,
                    // a truncated integer or string, bad Huffman data
        too_large,  // the decoded list would exceed max_list_size (stopped at that field)
    };
    using SinkFn = bool (*)(void*, std::string_view, std::string_view, Origin);
    // Decodes one complete field section: every field reported as views into `arena`
    // (literal bytes) or the static table. The list size (name + value + 32 per field)
    // stops the decode at the first field over max_list_size.
    Result decode(std::string_view section, std::string& arena, std::size_t max_list_size, SinkFn sink, void* ctx);
    template <class F>
    Result decode(std::string_view section, std::string& arena, std::size_t max_list_size, F&& f) {
        return decode(section, arena, max_list_size,
                      [](void* c, std::string_view n, std::string_view v, Origin o) { return (*static_cast<F*>(c))(n, v, o); }, &f);
    }

private:
    enum class StrStatus { ok, malformed, too_large };
    static StrStatus read_string(std::string_view in, std::size_t& pos, bool huffman, std::size_t len, std::string& arena,
                                 std::size_t max_out, std::string_view& out);
};

}  // namespace agensio::qpack
