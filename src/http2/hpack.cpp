#include "http2/hpack.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "http2/hpack_tables.hpp"

namespace agensio::hpack {

// ---- Huffman ----

std::size_t huffman_size(std::string_view s) noexcept {
    std::size_t bits = 0;
    for (const unsigned char c : s) bits += kHuffmanCodes[c].bits;
    return (bits + 7) / 8;
}

void huffman_encode(std::string& out, std::string_view s) {
    std::uint64_t acc = 0;
    unsigned nbits = 0;
    for (const unsigned char c : s) {
        const HuffmanCode& code = kHuffmanCodes[c];
        acc = (acc << code.bits) | code.code;
        nbits += code.bits;
        while (nbits >= 8) {
            nbits -= 8;
            out.push_back(static_cast<char>((acc >> nbits) & 0xff));
        }
    }
    if (nbits > 0) {  // pad with the leading bits of EOS (all ones)
        const unsigned pad = 8 - nbits;
        acc = (acc << pad) | ((1u << pad) - 1);
        out.push_back(static_cast<char>(acc & 0xff));
    }
}

HuffStatus huffman_decode(std::string_view in, std::string& out, std::size_t max_out) {
    std::uint8_t state = 0;
    std::uint8_t flags = kHuffmanAccepted;  // the empty string is valid
    std::size_t produced = 0;
    for (const unsigned char c : in) {
        const HuffmanStep& hi = kHuffmanSteps[state][c >> 4];
        if (hi.flags & kHuffmanFail) return HuffStatus::malformed;
        if (hi.flags & kHuffmanSymbol) {
            if (produced == max_out) return HuffStatus::too_large;
            out.push_back(static_cast<char>(hi.symbol));
            ++produced;
        }
        const HuffmanStep& lo = kHuffmanSteps[hi.next][c & 0xf];
        if (lo.flags & kHuffmanFail) return HuffStatus::malformed;
        if (lo.flags & kHuffmanSymbol) {
            if (produced == max_out) return HuffStatus::too_large;
            out.push_back(static_cast<char>(lo.symbol));
            ++produced;
        }
        state = lo.next;
        flags = lo.flags;
    }
    return (flags & kHuffmanAccepted) ? HuffStatus::ok : HuffStatus::malformed;
}

// ---- integers ----

void append_integer(std::string& out, std::uint64_t value, unsigned prefix_bits, std::uint8_t prefix_flags) {
    const std::uint64_t max = (1u << prefix_bits) - 1;
    if (value < max) {
        out.push_back(static_cast<char>(prefix_flags | static_cast<std::uint8_t>(value)));
        return;
    }
    out.push_back(static_cast<char>(prefix_flags | static_cast<std::uint8_t>(max)));
    value -= max;
    while (value >= 128) {
        out.push_back(static_cast<char>((value & 0x7f) | 0x80));
        value >>= 7;
    }
    out.push_back(static_cast<char>(value));
}

bool read_integer(std::string_view in, std::size_t& pos, unsigned prefix_bits, std::uint32_t& value) noexcept {
    if (pos >= in.size()) return false;
    const std::uint32_t max = (1u << prefix_bits) - 1;
    std::uint32_t v = static_cast<unsigned char>(in[pos++]) & max;
    if (v < max) {
        value = v;
        return true;
    }
    std::uint64_t acc = max;
    unsigned shift = 0;
    for (;;) {
        if (pos >= in.size() || shift > 28) return false;  // truncated, or more than 32 bits
        const unsigned char b = static_cast<unsigned char>(in[pos++]);
        acc += static_cast<std::uint64_t>(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) break;
    }
    if (acc > 0xffffffffu) return false;
    value = static_cast<std::uint32_t>(acc);
    return true;
}

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

// ---- decoding ----

Decoder::Decoder(std::size_t ceiling) : ceiling_(ceiling), limit_(ceiling) {}  // the ring is made on the first insertion

void Decoder::evict_to(std::size_t limit) noexcept {
    while (count_ > 0 && size_ > limit) {
        const std::size_t oldest = (head_ + ring_.size() - (count_ - 1)) % ring_.size();
        Entry& e = ring_[oldest];
        size_ -= e.name.size() + e.value.size() + 32;
        e.name.clear();
        e.value.clear();
        --count_;
    }
}

void Decoder::add(std::string_view name, std::string_view value) {
    const std::size_t need = name.size() + value.size() + 32;
    if (need > limit_) {  // RFC 7541 4.4: an entry larger than the table empties it and is not added
        evict_to(0);
        return;
    }
    evict_to(limit_ - need);
    if (ring_.empty()) ring_.resize(ceiling_ / 32 + 1);  // an entry costs at least 32 bytes, so this many fit; 8 KB, only for a peer that indexes
    head_ = (head_ + 1) % ring_.size();
    Entry& e = ring_[head_];
    e.name.assign(name);
    e.value.assign(value);
    ++count_;
    size_ += need;
}

bool Decoder::lookup(std::uint32_t index, std::string_view& name, std::string_view& value) const noexcept {
    if (index == 0) return false;
    if (index <= kStaticTable.size()) {
        name = kStaticTable[index - 1].name;
        value = kStaticTable[index - 1].value;
        return true;
    }
    const std::uint32_t k = index - static_cast<std::uint32_t>(kStaticTable.size()) - 1;  // 0 = newest
    if (k >= count_ || ring_.empty()) return false;
    const Entry& e = ring_[(head_ + ring_.size() - k) % ring_.size()];
    name = e.name;
    value = e.value;
    return true;
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
        if (b & 0x80) {  // 6.1 indexed
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 7, index) || !lookup(index, name, value)) return Result::malformed;
            if (name.size() + value.size() + 32 > max_list_size - std::min(total, max_list_size)) return Result::too_large;
            name = copy_in(name);
            value = copy_in(value);
        } else if (b & 0x40) {  // 6.2.1 literal with incremental indexing
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 6, index)) return Result::malformed;
            if (index) {
                std::string_view v;
                if (!lookup(index, name, v)) return Result::malformed;
                if (name.size() > budget(0)) return Result::too_large;
                name = copy_in(name);
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
            add(name, value);
        } else if (b & 0x20) {  // 6.3 dynamic table size update: only before the first field
            if (fields_started) return Result::malformed;
            std::uint32_t size = 0;
            if (!read_integer(block, pos, 5, size) || size > ceiling_) return Result::malformed;
            evict_to(size);
            limit_ = size;
            continue;
        } else {  // 6.2.2 without indexing (0000) and 6.2.3 never indexed (0001)
            std::uint32_t index = 0;
            if (!read_integer(block, pos, 4, index)) return Result::malformed;
            if (index) {
                std::string_view v;
                if (!lookup(index, name, v)) return Result::malformed;
                if (name.size() > budget(0)) return Result::too_large;
                name = copy_in(name);
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
        if (!sink(ctx, name, value)) return Result::too_many;
    }
    return Result::ok;
}

}  // namespace agensio::hpack
