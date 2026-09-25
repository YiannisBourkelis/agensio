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

namespace agensio::qpack {

// ---- the encoder side (design-http3 7.2's second step) ----

void Encoder::set_peer(std::uint64_t capacity, std::uint64_t blocked_streams) {
    peer_capacity_ = capacity;
    peer_blocked_ = blocked_streams;
    capacity_ = static_cast<std::size_t>(std::min<std::uint64_t>(capacity, kMaxCapacity));
}

bool Encoder::usable(std::uint64_t abs) const noexcept {
    if (!held(abs)) return false;
    if (abs < known_) return true;                       // acknowledged: never blocks
    if (current_ && current_->blocking) return true;     // this section already counts
    return blocking_ < peer_blocked_;                    // one more blocked stream is allowed
}

// An insert (4.3.2, with a static name reference): only when the entry fits without
// evicting one a pending section references.
bool Encoder::insert(unsigned static_name, std::string_view name, std::string_view value, std::uint64_t& abs) {
    const std::size_t need = name.size() + value.size() + 32;
    if (capacity_ == 0 || need > capacity_) return false;
    std::size_t evict = 0, freed = 0;
    while (size_ - freed + need > capacity_) {
        if (evict >= entries_.size() || entries_[evict].refs) return false;
        freed += entries_[evict].size;
        ++evict;
    }
    if (evict) {
        entries_.erase(entries_.begin(), entries_.begin() + static_cast<std::ptrdiff_t>(evict));
        size_ -= freed;
    }
    if (!capacity_sent_) {
        codec::append_integer(instructions_, capacity_, 5, 0x20);  // 001: Set Dynamic Table Capacity (4.3.1)
        capacity_sent_ = true;
    }
    codec::append_integer(instructions_, static_name, 6, 0xc0);  // 1 T=1: Insert With Name Reference (4.3.2)
    append_string(instructions_, value);
    Entry e;
    e.abs = insert_count_++;
    e.size = need;
    e.name.assign(name);
    e.value.assign(value);
    entries_.push_back(std::move(e));
    size_ += need;
    abs = insert_count_ - 1;
    return true;
}

void Encoder::begin(Section& section) noexcept {
    section = Section{};
    current_ = &section;
    base_ = insert_count_;  // entries inserted for this section are referenced post-base (4.5.3)
}

// An indexed field line (4.5.2, 4.5.3) and the section's bookkeeping.
void Encoder::reference(std::string& out, std::uint64_t abs) {
    if (abs < base_) codec::append_integer(out, base_ - 1 - abs, 6, 0x80);  // 1 T=0, relative to the base
    else codec::append_integer(out, abs - base_, 4, 0x10);                  // 0001: post-base
    Section& c = *current_;
    if (abs + 1 > c.ric) c.ric = abs + 1;
    if (abs >= known_) c.blocking = true;
    for (unsigned i = 0; i < c.n; ++i)
        if (c.refs[i] == abs) return;
    if (c.n < 4) {
        if (Entry* e = entry(abs)) {
            c.refs[c.n++] = abs;
            ++e->refs;
        }
    }
}

// A field remembered by its entry: the run of one value is a comparison and an index
// byte; a new value goes through the table once (a literal while the peer has not
// acknowledged it and blocking is not allowed, or when the table is full of held entries).
void Encoder::memo_field(std::string& out, unsigned static_name, std::string_view name, std::string_view value,
                         Memo& memo) {
    if (capacity_) {
        if (memo.valid && held(memo.abs) && memo.value == value) {
            if (usable(memo.abs)) return reference(out, memo.abs);
        } else {
            memo.valid = false;
            std::uint64_t abs = 0;
            if (insert(static_name, name, value, abs)) {
                memo.abs = abs;
                memo.value.assign(value);
                memo.valid = true;
                if (usable(abs)) return reference(out, abs);
            }
        }
    }
    append_literal_name_ref(out, static_name, value);
}

void Encoder::date(std::string& out, std::time_t second, std::string_view value) {
    if (capacity_) {
        if (date_valid_ && second == date_second_ && held(date_abs_)) {
            if (usable(date_abs_)) return reference(out, date_abs_);
        } else {
            date_valid_ = false;
            std::uint64_t abs = 0;
            if (insert(6, "date", value, abs)) {
                date_abs_ = abs;
                date_second_ = second;
                date_valid_ = true;
                if (usable(abs)) return reference(out, abs);
            }
        }
    }
    append_literal_name_ref(out, 6, value);
}

// The first content-type row of the static table (appendix A), the name reference of an
// insert or a literal; the profile of 2026-09-25 had the search for it and for the value's
// row at 3 % of the cycles per answer, so both are remembered per value.
constexpr unsigned kContentTypeName = 44;
static_assert(kStaticTable[kContentTypeName].name == "content-type");

void Encoder::content_type(std::string& out, std::string_view value) {
    if (!ct_seen_valid_ || value != ct_seen_) {  // a new value: the static table searched once
        ct_seen_.assign(value);
        ct_seen_valid_ = true;
        ct_seen_static_ = static_pair("content-type", value, ct_seen_index_);
    }
    if (ct_seen_static_) return append_indexed(out, ct_seen_index_);
    memo_field(out, kContentTypeName, "content-type", value, ct_);
}

// The prefix (4.5.1): Required Insert Count encoded modulo twice the peer's maximum entries,
// then the base as a signed delta; "00 00" for a section without dynamic references.
void Encoder::prefix(std::string& out) {
    const std::uint64_t ric = current_ ? current_->ric : 0;
    if (ric == 0) {
        out.append("\0\0", 2);
        return;
    }
    const std::uint64_t max_entries = peer_capacity_ / 32;
    codec::append_integer(out, (ric % (2 * max_entries)) + 1, 8, 0);
    if (base_ >= ric) codec::append_integer(out, base_ - ric, 7, 0);       // sign 0: Base = RIC + delta
    else codec::append_integer(out, ric - base_ - 1, 7, 0x80);             // sign 1: Base = RIC - delta - 1
}

void Encoder::end() {
    if (!current_) return;
    Section& c = *current_;
    if (c.ric != 0) {
        c.pending = true;
        if (c.blocking) ++blocking_;
    }
    current_ = nullptr;
}

void Encoder::release(Section& section) noexcept {
    if (!section.pending) return;
    for (unsigned i = 0; i < section.n; ++i)
        if (Entry* e = entry(section.refs[i]); e && e->refs) --e->refs;
    if (section.blocking && blocking_) --blocking_;
    section.pending = false;
    section.blocking = false;
    section.n = 0;
}

void Encoder::acknowledged(Section& section) noexcept {
    if (!section.pending) return;
    if (section.ric > known_) known_ = section.ric;
    release(section);
}

void Encoder::cancelled(Section& section) noexcept { release(section); }

bool Encoder::increment(std::uint64_t n) noexcept {
    if (n == 0 || known_ + n > insert_count_) return false;
    known_ += n;
    return true;
}

}  // namespace agensio::qpack
