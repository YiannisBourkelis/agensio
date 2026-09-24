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
    if (len > in.size() - pos) return StrStatus::malformed;
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

Decoder::Result Decoder::decode(std::string_view section, std::string& arena, std::size_t max_list_size, SinkFn sink, void* ctx) {
    if (arena.capacity() < max_list_size + 64) arena.reserve(max_list_size + 64);
    std::size_t pos = 0;
    // The prefix (4.5.1): Required Insert Count (8-bit prefix) must be 0 without a dynamic
    // table; the Delta Base is read and ignored (it cannot be referenced).
    std::uint32_t ric = 0, delta = 0;
    if (!codec::read_integer(section, pos, 8, ric) || ric != 0) return Result::malformed;
    if (!codec::read_integer(section, pos, 7, delta)) return Result::malformed;
    std::size_t total = 0;
    auto budget = [&](std::size_t used) -> std::size_t {
        const std::size_t spent = total + 32 + used;
        return spent >= max_list_size ? 0 : max_list_size - spent;
    };
    // A value string after a name: the H bit and the 7-bit length.
    auto value_string = [&](std::string_view& v, std::size_t max_out) -> StrStatus {
        if (pos >= section.size()) return StrStatus::malformed;
        const bool huffman = (static_cast<unsigned char>(section[pos]) & 0x80) != 0;
        std::uint32_t len = 0;
        if (!codec::read_integer(section, pos, 7, len)) return StrStatus::malformed;
        return read_string(section, pos, huffman, len, arena, max_out, v);
    };
    while (pos < section.size()) {
        const unsigned char b = static_cast<unsigned char>(section[pos]);
        std::string_view name, value;
        Origin origin;
        if (b & 0x80) {  // 4.5.2 indexed field line
            if (!(b & 0x40)) return Result::malformed;  // a dynamic reference
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 6, index) || index >= kStaticTable.size()) return Result::malformed;
            name = kStaticTable[index].name;
            value = kStaticTable[index].value;
            origin.static_table = true;
        } else if (b & 0x40) {  // 4.5.4 literal field line with name reference
            if (!(b & 0x10)) return Result::malformed;  // a dynamic name
            std::uint32_t index = 0;
            if (!codec::read_integer(section, pos, 4, index) || index >= kStaticTable.size()) return Result::malformed;
            name = kStaticTable[index].name;
            if (name.size() > budget(0)) return Result::too_large;
            switch (value_string(value, budget(name.size()))) {
                case StrStatus::ok: break;
                case StrStatus::malformed: return Result::malformed;
                case StrStatus::too_large: return Result::too_large;
            }
        } else if (b & 0x20) {  // 4.5.6 literal field line with literal name
            const bool huffman = (b & 0x08) != 0;
            std::uint32_t len = 0;
            if (!codec::read_integer(section, pos, 3, len)) return Result::malformed;
            switch (read_string(section, pos, huffman, len, arena, budget(0), name)) {
                case StrStatus::ok: break;
                case StrStatus::malformed: return Result::malformed;
                case StrStatus::too_large: return Result::too_large;
            }
            switch (value_string(value, budget(name.size()))) {
                case StrStatus::ok: break;
                case StrStatus::malformed: return Result::malformed;
                case StrStatus::too_large: return Result::too_large;
            }
        } else {
            return Result::malformed;  // post-base forms (4.5.3, 4.5.5): dynamic references
        }
        total += name.size() + value.size() + 32;
        if (total > max_list_size) return Result::too_large;
        if (!sink(ctx, name, value, origin)) return Result::ok;
    }
    return Result::ok;
}

}  // namespace agensio::qpack
