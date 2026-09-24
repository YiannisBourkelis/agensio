#include "http2/hpack.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "http2/hpack_tables.hpp"

namespace agensio::hpack {

// ---- static table lookups ----

namespace {

struct NameIndex {
    std::string_view name;
    unsigned index;  // the first entry with this name
};

const std::vector<NameIndex>& names_by_name() {
    static const std::vector<NameIndex> v = [] {
        std::vector<NameIndex> out;
        for (unsigned i = 0; i < kStaticTable.size(); ++i) {
            const std::string_view n = kStaticTable[i].name;
            if (out.empty() || std::none_of(out.begin(), out.end(), [&](const NameIndex& e) { return e.name == n; }))
                out.push_back({n, i + 1});
        }
        std::sort(out.begin(), out.end(), [](const NameIndex& a, const NameIndex& b) { return a.name < b.name; });
        return out;
    }();
    return v;
}

}  // namespace

unsigned static_name_index(std::string_view name) noexcept {
    const auto& v = names_by_name();
    const auto it = std::lower_bound(v.begin(), v.end(), name,
                                     [](const NameIndex& e, std::string_view n) { return e.name < n; });
    return (it != v.end() && it->name == name) ? it->index : 0;
}

unsigned static_index(std::string_view name, std::string_view value) noexcept {
    for (unsigned i = static_name_index(name); i != 0 && i <= kStaticTable.size() && kStaticTable[i - 1].name == name; ++i)
        if (kStaticTable[i - 1].value == value) return i;
    return 0;
}

// ---- encoding ----

void append_string(std::string& out, std::string_view s) {
    const std::size_t huff = huffman_size(s);
    if (huff < s.size()) {
        append_integer(out, huff, 7, 0x80);
        huffman_encode(out, s);
    } else {
        append_integer(out, s.size(), 7, 0);
        out.append(s);
    }
}

void append_indexed(std::string& out, unsigned index) { append_integer(out, index, 7, 0x80); }

void append_literal(std::string& out, unsigned name_index, std::string_view value) {
    append_integer(out, name_index, 4, 0);
    append_string(out, value);
}

void append_literal(std::string& out, std::string_view name, std::string_view value) {
    out.push_back('\0');  // literal without indexing, literal name
    append_string(out, name);
    append_string(out, value);
}

void append_field(std::string& out, std::string_view name, std::string_view value) {
    if (const unsigned i = static_index(name, value)) {
        append_indexed(out, i);
        return;
    }
    if (const unsigned n = static_name_index(name)) append_literal(out, n, value);
    else append_literal(out, name, value);
}

void append_insert(std::string& out, std::string_view name, std::string_view value) {
    if (const unsigned n = static_name_index(name)) {
        append_integer(out, n, 6, 0x40);
    } else {
        append_integer(out, 0, 6, 0x40);
        append_string(out, name);
    }
    append_string(out, value);
}

void append_never_indexed(std::string& out, std::string_view name, std::string_view value) {
    if (const unsigned n = static_name_index(name)) {
        append_integer(out, n, 4, 0x10);
    } else {
        append_integer(out, 0, 4, 0x10);
        append_string(out, name);
    }
    append_string(out, value);
}

void append_status(std::string& out, int status) {
    switch (status) {
        case 200: append_indexed(out, 8); return;
        case 204: append_indexed(out, 9); return;
        case 206: append_indexed(out, 10); return;
        case 304: append_indexed(out, 11); return;
        case 400: append_indexed(out, 12); return;
        case 404: append_indexed(out, 13); return;
        case 500: append_indexed(out, 14); return;
        default: break;
    }
    char digits[4];
    if (status < 100 || status > 999) status = 500;
    digits[0] = static_cast<char>('0' + status / 100);
    digits[1] = static_cast<char>('0' + (status / 10) % 10);
    digits[2] = static_cast<char>('0' + status % 10);
    append_integer(out, 8, 4, 0);  // literal without indexing, name = :status (index 8)
    out.push_back(3);
    out.append(digits, 3);
}

// ---- the encoder ----

Encoder::Policy Encoder::policy(std::string_view name) noexcept {
    switch (name.size()) {
        case 3: if (name == "age") return Policy::literal; break;
        case 4: if (name == "etag" || name == "date") return Policy::literal; break;
        case 6: if (name == "cookie") return Policy::never; break;
        case 7: if (name == "expires") return Policy::literal; break;
        case 8: if (name == "location") return Policy::literal; break;
        case 10: if (name == "set-cookie") return Policy::never; break;
        case 11: if (name == "retry-after") return Policy::literal; break;
        case 13:
            if (name == "authorization" || name == "content-range" || name == "last-modified") return name == "authorization" ? Policy::never : Policy::literal;
            break;
        case 14: if (name == "content-length") return Policy::literal; break;
        case 16: if (name == "www-authenticate") return Policy::never; break;
        case 18: if (name == "proxy-authenticate") return Policy::never; break;
        case 19:
            if (name == "proxy-authorization") return Policy::never;
            if (name == "content-disposition") return Policy::literal;
            break;
        default: break;
    }
    return Policy::index;
}

bool Encoder::insert(std::string_view name, std::string_view value) {
    if (name.size() + value.size() + 32 > max_) return false;  // the decoder would empty its table: not worth an entry
    if (!table_.add(name, value)) return false;
    ++next_seq_;
    return true;
}

void Encoder::set_peer_max(std::uint32_t value) {
    const std::size_t new_max = std::min<std::size_t>(value, kMaxSize);
    if (new_max != max_) {
        table_.set_limit(new_max);  // down: evicts oldest first, as the decoder will on the update
        pending_update_ = true;
    }
    if (value < assumed_) pending_update_ = true;  // the decoder may have shrunk with its own setting: tell it our size
    max_ = new_max;
    floor_ = std::min(floor_, new_max);
}

// A decoder that evicts only on our updates must be walked down to the lowest size we
// used since the last update (the entries evicted there are gone on our side), then up
// to the current one; a decoder that shrank on its own setting sees the same table
// either way.
void Encoder::begin(std::string& out) {
    if (!pending_update_) return;
    if (floor_ < max_ && floor_ < assumed_) append_integer(out, floor_, 5, 0x20);
    if (max_ != assumed_ || floor_ < max_) append_integer(out, max_, 5, 0x20);
    assumed_ = max_;
    floor_ = max_;
    pending_update_ = false;
}

void Encoder::field(std::string& out, std::string_view name, std::string_view value) {
    const unsigned n = static_name_index(name);  // once: the pair, the insertion and the literal all start from it
    for (unsigned i = n; i != 0 && i <= kStaticTable.size() && kStaticTable[i - 1].name == name; ++i) {
        if (kStaticTable[i - 1].value == value) {
            append_indexed(out, i);
            return;
        }
    }
    switch (policy(name)) {
        case Policy::never:
            append_never_indexed(out, name, value);
            return;
        case Policy::index:
            if (max_ > 0) {
                const std::size_t k = table_.find(name, value);
                if (k != DynamicTable::npos) {
                    append_indexed(out, static_cast<unsigned>(62 + k));
                    return;
                }
                if (insert(name, value)) {
                    if (n) {
                        append_integer(out, n, 6, 0x40);
                    } else {
                        append_integer(out, 0, 6, 0x40);
                        append_string(out, name);
                    }
                    append_string(out, value);
                    return;
                }
            }
            break;
        case Policy::literal:
            break;
    }
    if (n) append_literal(out, n, value);
    else append_literal(out, name, value);
}

void Encoder::content_type(std::string& out, std::string_view value) {
    constexpr unsigned kName = 31;  // content-type in the static table
    if (alive(ct_seq_) && value == ct_value_) {  // the run of answers of one type: a comparison and an index byte
        append_indexed(out, index_of(ct_seq_));
        return;
    }
    ct_seq_ = 0;
    if (max_ > 0) {
        const std::size_t k = table_.find("content-type", value);
        if (k != DynamicTable::npos) {
            ct_seq_ = next_seq_ - 1 - k;
            ct_value_.assign(value);
            append_indexed(out, static_cast<unsigned>(62 + k));
            return;
        }
        if (insert("content-type", value)) {
            ct_seq_ = next_seq_ - 1;
            ct_value_.assign(value);
            append_integer(out, kName, 6, 0x40);
            append_string(out, value);
            return;
        }
    }
    append_literal(out, kName, value);
}

void Encoder::server(std::string& out, std::string_view value, std::string_view insert_bytes) {
    if (alive(server_seq_)) {
        append_indexed(out, index_of(server_seq_));
        return;
    }
    if (max_ > 0 && insert("server", value)) {
        server_seq_ = next_seq_ - 1;
        out.append(insert_bytes);
        return;
    }
    append_literal(out, 54, value);
}

void Encoder::date(std::string& out, std::time_t second, std::string_view value, std::string_view insert_bytes) {
    if (second == date_second_ && alive(date_seq_)) {
        append_indexed(out, index_of(date_seq_));
        return;
    }
    if (max_ > 0 && insert("date", value)) {
        date_seq_ = next_seq_ - 1;
        date_second_ = second;
        out.append(insert_bytes);
        return;
    }
    append_literal(out, 33, value);
}

// ---- decoding ----

Decoder::Decoder(std::size_t ceiling) : table_(ceiling), ceiling_(ceiling) {}  // the ring is made on the first insertion

bool Decoder::lookup(std::uint32_t index, std::string_view& name, std::string_view& value) const noexcept {
    if (index == 0) return false;
    if (index <= kStaticTable.size()) {
        name = kStaticTable[index - 1].name;
        value = kStaticTable[index - 1].value;
        return true;
    }
    return table_.at(index - static_cast<std::uint32_t>(kStaticTable.size()) - 1, name, value);  // 0 = newest
}

bool Decoder::lookup(std::uint32_t index, std::string_view& name, std::string_view& value, Origin& origin) const noexcept {
    if (index == 0) return false;
    if (index <= kStaticTable.size()) {
        name = kStaticTable[index - 1].name;
        value = kStaticTable[index - 1].value;
        origin.static_table = true;
        return true;
    }
    return table_.at(index - static_cast<std::uint32_t>(kStaticTable.size()) - 1, name, value, origin.checked);
}

Decoder::StrStatus Decoder::read_string(std::string_view in, std::size_t& pos, std::string& arena,
                                        std::size_t max_out, std::string_view& out) {
    if (pos >= in.size()) return StrStatus::malformed;
    const bool huffman = (static_cast<unsigned char>(in[pos]) & 0x80) != 0;
    std::uint32_t len = 0;
    if (!read_integer(in, pos, 7, len)) return StrStatus::malformed;
    if (len > in.size() - pos) return StrStatus::malformed;
    const std::size_t start = arena.size();
    if (huffman) {
        switch (huffman_decode(in.substr(pos, len), arena, max_out)) {
            case HuffStatus::ok: break;
            case HuffStatus::malformed: arena.resize(start); return StrStatus::malformed;
            case HuffStatus::too_large: arena.resize(start); return StrStatus::too_large;
        }
    } else {
        if (len > max_out) return StrStatus::too_large;
        arena.append(in.data() + pos, len);
    }
    pos += len;
    out = std::string_view(arena).substr(start);
    return StrStatus::ok;
}

Decoder::Result Decoder::decode(std::string_view block, std::string& arena, std::size_t max_list_size, SinkFn sink,
                                void* ctx) {
    if (arena.capacity() < max_list_size + 64) arena.reserve(max_list_size + 64);
    std::size_t pos = 0;
    std::size_t total = 0;      // RFC 4.1 list size produced so far
    bool fields_started = false;
    auto budget = [&](std::size_t used) -> std::size_t {  // decoded bytes this field may still take
        const std::size_t spent = total + 32 + used;
        return spent >= max_list_size ? 0 : max_list_size - spent;
    };
    // Copies a table entry's name/value into the arena so every view has one lifetime.
    auto copy_in = [&](std::string_view s) {
        const std::size_t start = arena.size();
        arena.append(s);
        return std::string_view(arena).substr(start);
    };
    while (pos < block.size()) {
        const unsigned char b = static_cast<unsigned char>(block[pos]);
        std::string_view name, value;
        Origin origin;
        if (b & 0x80) {  // 6.1 indexed
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 7, index) || !lookup(index, name, value, origin)) return Result::malformed;
            if (name.size() + value.size() + 32 > max_list_size - std::min(total, max_list_size)) return Result::too_large;
            if (index > kStaticTable.size()) {  // a dynamic entry can be evicted later in this block: copied
                name = copy_in(name);
                value = copy_in(value);
            }
        } else if (b & 0x40) {  // 6.2.1 literal with incremental indexing
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 6, index)) return Result::malformed;
            if (index) {
                std::string_view v;
                if (!lookup(index, name, v)) return Result::malformed;
                if (name.size() > budget(0)) return Result::too_large;
                if (index > kStaticTable.size()) name = copy_in(name);
            } else {
                switch (read_string(block, pos, arena, budget(0), name)) {
                    case StrStatus::ok: break;
                    case StrStatus::malformed: return Result::malformed;
                    case StrStatus::too_large: return Result::too_large;
                }
            }
            switch (read_string(block, pos, arena, budget(name.size()), value)) {
                case StrStatus::ok: break;
                case StrStatus::malformed: return Result::malformed;
                case StrStatus::too_large: return Result::too_large;
            }
            if (table_.add(name, value)) origin.checked = table_.newest_mark();  // the sink's rules, once for the entry
        } else if (b & 0x20) {  // 6.3 dynamic table size update: only before the first field
            if (fields_started) return Result::malformed;
            std::uint32_t size = 0;
            if (!read_integer(block, pos, 5, size) || size > ceiling_) return Result::malformed;
            table_.set_limit(size);
            continue;
        } else {  // 6.2.2 without indexing (0000) and 6.2.3 never indexed (0001)
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 4, index)) return Result::malformed;
            if (index) {
                std::string_view v;
                if (!lookup(index, name, v)) return Result::malformed;
                if (name.size() > budget(0)) return Result::too_large;
                if (index > kStaticTable.size()) name = copy_in(name);
            } else {
                switch (read_string(block, pos, arena, budget(0), name)) {
                    case StrStatus::ok: break;
                    case StrStatus::malformed: return Result::malformed;
                    case StrStatus::too_large: return Result::too_large;
                }
            }
            switch (read_string(block, pos, arena, budget(name.size()), value)) {
                case StrStatus::ok: break;
                case StrStatus::malformed: return Result::malformed;
                case StrStatus::too_large: return Result::too_large;
            }
        }
        fields_started = true;
        total += name.size() + value.size() + 32;
        if (total > max_list_size) return Result::too_large;
        if (!sink(ctx, name, value, origin)) return Result::too_many;
    }
    return Result::ok;
}

}  // namespace agensio::hpack
