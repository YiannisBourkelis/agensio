#include "http3/qpack.hpp"

#include <algorithm>
#include <vector>

#include "http3/qpack_tables.hpp"

namespace agensio::qpack {

namespace {

struct NameIndex {
    std::string_view name;
    unsigned index;
};

const std::vector<NameIndex>& names() {
    static const std::vector<NameIndex> v = [] {
        std::vector<NameIndex> out;
        for (unsigned i = 0; i < kStaticTable.size(); ++i) {
            const std::string_view n = kStaticTable[i].name;
            if (std::none_of(out.begin(), out.end(), [&](const NameIndex& e) { return e.name == n; })) out.push_back({n, i});
        }
        std::sort(out.begin(), out.end(), [](const NameIndex& a, const NameIndex& b) { return a.name < b.name; });
        return out;
    }();
    return v;
}

}  // namespace

bool static_name(std::string_view name, unsigned& index) noexcept {
    const auto& v = names();
    const auto it = std::lower_bound(v.begin(), v.end(), name, [](const NameIndex& e, std::string_view n) { return e.name < n; });
    if (it == v.end() || it->name != name) return false;
    index = it->index;
    return true;
}

bool static_pair(std::string_view name, std::string_view value, unsigned& index) noexcept {
    unsigned first = 0;
    if (!static_name(name, first)) return false;
    // Entries of one name are not always contiguous (the table is ordered by frequency),
    // so the whole table is scanned from the first: 99 entries, done once per prebuilt block.
    for (unsigned i = first; i < kStaticTable.size(); ++i)
        if (kStaticTable[i].name == name && kStaticTable[i].value == value) {
            index = i;
            return true;
        }
    return false;
}

void append_string(std::string& out, std::string_view s) {
    const std::size_t huff = codec::huffman_size(s);
    if (huff < s.size()) {
        codec::append_integer(out, huff, 7, 0x80);
        codec::huffman_encode(out, s);
    } else {
        codec::append_integer(out, s.size(), 7, 0);
        out.append(s);
    }
}

void append_indexed(std::string& out, unsigned index) { codec::append_integer(out, index, 6, 0xc0); }

void append_literal_name_ref(std::string& out, unsigned index, std::string_view value) {
    codec::append_integer(out, index, 4, 0x50);  // 01 N=0 T=1
    append_string(out, value);
}

void append_literal(std::string& out, std::string_view name, std::string_view value) {
    const std::size_t huff = codec::huffman_size(name);
    if (huff < name.size()) {
        codec::append_integer(out, huff, 3, 0x28);  // 001 N=0 H=1
        codec::huffman_encode(out, name);
    } else {
        codec::append_integer(out, name.size(), 3, 0x20);
        out.append(name);
    }
    append_string(out, value);
}

void append_field(std::string& out, std::string_view name, std::string_view value) {
    unsigned i = 0;
    if (static_pair(name, value, i)) return append_indexed(out, i);
    if (static_name(name, i)) return append_literal_name_ref(out, i, value);
    append_literal(out, name, value);
}

void append_status(std::string& out, int status) {
    switch (status) {
        case 103: return append_indexed(out, 24);
        case 200: return append_indexed(out, 25);
        case 304: return append_indexed(out, 26);
        case 404: return append_indexed(out, 27);
        case 503: return append_indexed(out, 28);
        case 100: return append_indexed(out, 63);
        case 204: return append_indexed(out, 64);
        case 206: return append_indexed(out, 65);
        case 302: return append_indexed(out, 66);
        case 400: return append_indexed(out, 67);
        case 403: return append_indexed(out, 68);
        case 421: return append_indexed(out, 69);
        case 425: return append_indexed(out, 70);
        case 500: return append_indexed(out, 71);
        default: break;
    }
    char digits[3];
    if (status < 100 || status > 999) status = 500;
    digits[0] = static_cast<char>('0' + status / 100);
    digits[1] = static_cast<char>('0' + (status / 10) % 10);
    digits[2] = static_cast<char>('0' + status % 10);
    codec::append_integer(out, 24, 4, 0x50);  // :status by name
    out.push_back(3);
    out.append(digits, 3);
}

Decoder::StrStatus Decoder::read_string(std::string_view in, std::size_t& pos, bool huffman, std::size_t len, std::string& arena,
                                        std::size_t max_out, std::string_view& out) {
    if (len > in.size() - pos) return StrStatus::incomplete;
    const std::size_t start = arena.size();
    if (huffman) {
        switch (codec::huffman_decode(in.substr(pos, len), arena, max_out)) {
            case codec::HuffStatus::ok: break;
            case codec::HuffStatus::malformed: arena.resize(start); return StrStatus::malformed;
            case codec::HuffStatus::too_large: arena.resize(start); return StrStatus::too_large;
        }
    } else {
        if (len > max_out) return StrStatus::too_large;
        arena.append(in.data() + pos, len);
    }
    pos += len;
    out = std::string_view(arena).substr(start);
    return StrStatus::ok;
}

bool Decoder::entry(std::uint64_t abs, std::string_view& name, std::string_view& value, std::uint8_t*& mark) const noexcept {
    if (abs >= insert_count_) return false;
    const std::uint64_t k = insert_count_ - 1 - abs;  // places from the newest
    if (k >= table_.count()) return false;            // evicted
    return table_.at(static_cast<std::size_t>(k), name, value, mark);
}

// A string with the H bit and an N-bit length prefix, as the instructions and the field
// lines carry them; `out` points into `arena`.
static Decoder::StrStatus prefixed_string(std::string_view in, std::size_t& pos, unsigned prefix_bits, std::uint8_t h_bit,
                                          std::string& arena, std::size_t max_out, std::string_view& out,
                                          Decoder::StrStatus (*read)(std::string_view, std::size_t&, bool, std::size_t, std::string&,
                                                                     std::size_t, std::string_view&)) {
    if (pos >= in.size()) return Decoder::StrStatus::incomplete;
    const bool huffman = (static_cast<unsigned char>(in[pos]) & h_bit) != 0;
    std::uint32_t len = 0;
    const std::size_t at = pos;
    if (!codec::read_integer(in, pos, prefix_bits, len)) {
        pos = at;
        return Decoder::StrStatus::incomplete;
    }
    return read(in, pos, huffman, len, arena, max_out, out);
}

Decoder::Result Decoder::decode(std::string_view section, std::string& arena, std::size_t max_list_size, SinkFn sink, void* ctx,
                                std::uint64_t& required) {
    if (arena.capacity() < max_list_size + 64) arena.reserve(max_list_size + 64);
    std::size_t pos = 0;
    // The prefix (4.5.1): the Required Insert Count in its wrapped form, then the Base.
    std::uint32_t encoded = 0, delta = 0;
    if (!codec::read_integer(section, pos, 8, encoded)) return Result::malformed;
    if (pos >= section.size()) return Result::malformed;
    const bool sign = (static_cast<unsigned char>(section[pos]) & 0x80) != 0;
    if (!codec::read_integer(section, pos, 7, delta)) return Result::malformed;
    required = 0;
    if (encoded != 0) {
        const std::uint64_t max_entries = max_capacity_ / 32;
        const std::uint64_t full_range = 2 * max_entries;
        if (encoded > full_range) return Result::malformed;
        const std::uint64_t max_value = insert_count_ + max_entries;
        const std::uint64_t max_wrapped = (max_value / full_range) * full_range;
        required = max_wrapped + encoded - 1;
        if (required > max_value) {
            if (required <= full_range) return Result::malformed;
            required -= full_range;
        }
        if (required == 0) return Result::malformed;
    }
    std::uint64_t base = 0;
    if (sign) {
        if (delta >= required) return Result::malformed;
        base = required - delta - 1;
    } else {
        base = required + delta;
    }
    if (required > insert_count_) return Result::blocked;
    std::size_t total = 0;
    auto budget = [&](std::size_t used) -> std::size_t {
        const std::size_t spent = total + 32 + used;
        return spent >= max_list_size ? 0 : max_list_size - spent;
    };
    auto copy_in = [&](std::string_view v) {
        const std::size_t start = arena.size();
        arena.append(v);
        return std::string_view(arena).substr(start);
    };
    auto value_string = [&](std::string_view& v, std::size_t max_out) -> StrStatus {
        return prefixed_string(section, pos, 7, 0x80, arena, max_out, v, &Decoder::read_string);
    };
    // A dynamic entry by absolute index, its bytes copied so the request's views outlive the table.
    auto dynamic = [&](std::uint64_t abs, std::string_view& name, std::string_view& value, Origin& origin, bool value_too) -> bool {
        std::string_view n, v;
        std::uint8_t* mark = nullptr;
        if (!entry(abs, n, v, mark)) return false;
        if (n.size() + (value_too ? v.size() : 0) > budget(0)) return false;
        name = copy_in(n);
        if (value_too) value = copy_in(v);
        origin.checked = mark;
        return true;
    };
    while (pos < section.size()) {
        const unsigned char b = static_cast<unsigned char>(section[pos]);
        std::string_view name, value;
        Origin origin;
        StrStatus st = StrStatus::ok;
        if (b & 0x80) {  // 4.5.2 indexed field line
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 6, index)) return Result::malformed;
            if (b & 0x40) {
                if (index >= kStaticTable.size()) return Result::malformed;
                name = kStaticTable[index].name;
                value = kStaticTable[index].value;
                origin.static_table = true;
            } else {
                if (index >= base) return Result::malformed;
                if (!dynamic(base - 1 - index, name, value, origin, true)) return Result::malformed;
            }
        } else if (b & 0x40) {  // 4.5.4 literal field line with name reference
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 4, index)) return Result::malformed;
            if (b & 0x10) {
                if (index >= kStaticTable.size()) return Result::malformed;
                name = kStaticTable[index].name;
                if (name.size() > budget(0)) return Result::too_large;
            } else {
                if (index >= base) return Result::malformed;
                if (!dynamic(base - 1 - index, name, value, origin, false)) return Result::malformed;
                origin.checked = nullptr;  // the value is a literal: the rules run
            }
            st = value_string(value, budget(name.size()));
        } else if (b & 0x20) {  // 4.5.6 literal field line with literal name
            st = prefixed_string(section, pos, 3, 0x08, arena, budget(0), name, &Decoder::read_string);
            if (st == StrStatus::ok) st = value_string(value, budget(name.size()));
        } else if (b & 0x10) {  // 4.5.3 indexed field line with post-base index
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 4, index)) return Result::malformed;
            if (base + index >= required) return Result::malformed;
            if (!dynamic(base + index, name, value, origin, true)) return Result::malformed;
        } else {  // 4.5.5 literal field line with post-base name reference
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 3, index)) return Result::malformed;
            if (base + index >= required) return Result::malformed;
            if (!dynamic(base + index, name, value, origin, false)) return Result::malformed;
            origin.checked = nullptr;
            st = value_string(value, budget(name.size()));
        }
        switch (st) {
            case StrStatus::ok: break;
            case StrStatus::malformed:
            case StrStatus::incomplete: return Result::malformed;
            case StrStatus::too_large: return Result::too_large;
        }
        total += name.size() + value.size() + 32;
        if (total > max_list_size) return Result::too_large;
        if (!sink(ctx, name, value, origin)) return Result::ok;
    }
    return Result::ok;
}

bool Decoder::encoder_stream(std::string_view in, std::size_t& consumed) {
    std::size_t pos = 0;
    consumed = 0;
    while (pos < in.size()) {
        const unsigned char b = static_cast<unsigned char>(in[pos]);
        std::size_t p = pos;
        name_scratch_.clear();
        value_scratch_.clear();
        std::string_view name, value;
        if (b & 0x80) {  // 4.3.2 insert with name reference: 1 T index(6), value
            std::uint32_t index = 0;
            if (!codec::read_integer(in, p, 6, index)) break;
            if (b & 0x40) {
                if (index >= kStaticTable.size()) return false;
                name = kStaticTable[index].name;
            } else {
                std::string_view n, v;
                std::uint8_t* mark = nullptr;
                if (index >= insert_count_ || !entry(insert_count_ - 1 - index, n, v, mark)) return false;
                name_scratch_.assign(n);  // the insertion may evict the entry referenced
                name = name_scratch_;
            }
            const StrStatus st = prefixed_string(in, p, 7, 0x80, value_scratch_, max_capacity_, value, &Decoder::read_string);
            if (st == StrStatus::incomplete) break;
            if (st != StrStatus::ok) return false;
        } else if (b & 0x40) {  // 4.3.3 insert with literal name: 01 H length(5), name, value
            StrStatus st = prefixed_string(in, p, 5, 0x20, name_scratch_, max_capacity_, name, &Decoder::read_string);
            if (st == StrStatus::incomplete) break;
            if (st != StrStatus::ok) return false;
            st = prefixed_string(in, p, 7, 0x80, value_scratch_, max_capacity_, value, &Decoder::read_string);
            if (st == StrStatus::incomplete) break;
            if (st != StrStatus::ok) return false;
        } else if (b & 0x20) {  // 4.3.1 set dynamic table capacity: 001 capacity(5)
            std::uint32_t cap = 0;
            if (!codec::read_integer(in, p, 5, cap)) break;
            if (cap > max_capacity_) return false;
            table_.set_limit(cap);
            pos = p;
            consumed = pos;
            continue;
        } else {  // 4.3.4 duplicate: 000 index(5)
            std::uint32_t index = 0;
            if (!codec::read_integer(in, p, 5, index)) break;
            std::string_view n, v;
            std::uint8_t* mark = nullptr;
            if (index >= insert_count_ || !entry(insert_count_ - 1 - index, n, v, mark)) return false;
            name_scratch_.assign(n);
            value_scratch_.assign(v);
            name = name_scratch_;
            value = value_scratch_;
        }
        if (name.size() + value.size() + 32 > table_.limit()) return false;  // larger than the table (3.2.2)
        if (!table_.add(name, value)) return false;
        ++insert_count_;
        pos = p;
        consumed = pos;
    }
    return true;
}

void Decoder::section_acknowledged(std::uint64_t stream_id, std::uint64_t required, std::string& out) {
    if (required > known_) known_ = required;
    codec::append_integer(out, stream_id, 7, 0x80);
}

void Decoder::stream_cancelled(std::uint64_t stream_id, std::string& out) { codec::append_integer(out, stream_id, 6, 0x40); }

void Decoder::insert_count_increment(std::string& out) {
    if (insert_count_ <= known_) return;
    codec::append_integer(out, insert_count_ - known_, 6, 0x00);
    known_ = insert_count_;
}

}  // namespace agensio::qpack
