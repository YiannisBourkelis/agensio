// The codec both HPACK and QPACK use: Huffman, prefixed integers, the dynamic table.
// The code was http2/hpack.cpp's; only its home changed (design-http3 section 4).
#include "http/field_codec.hpp"

#include <algorithm>
#include <cstring>

#include "http/codec_tables.hpp"

namespace agensio::codec {

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
    // No code is shorter than 5 bits, so the output is bounded: the string grows once and
    // the symbols are stored through a pointer (a push_back per symbol was a third of the
    // decode). On failure the output is as it was.
    const std::size_t start = out.size();
    const std::size_t cap = std::min(max_out, in.size() * 8 / 5 + 1);
    out.resize(start + cap);
    char* w = out.data() + start;
    char* const end = w + cap;
    std::uint8_t state = 0;
    std::uint8_t flags = kHuffmanAccepted;  // the empty string is valid
    for (const unsigned char c : in) {
        const HuffmanStep& hi = kHuffmanSteps[state][c >> 4];
        if (hi.flags & kHuffmanFail) {
            out.resize(start);
            return HuffStatus::malformed;
        }
        if (hi.flags & kHuffmanSymbol) {
            if (w == end) {
                out.resize(start);
                return HuffStatus::too_large;
            }
            *w++ = static_cast<char>(hi.symbol);
        }
        const HuffmanStep& lo = kHuffmanSteps[hi.next][c & 0xf];
        if (lo.flags & kHuffmanFail) {
            out.resize(start);
            return HuffStatus::malformed;
        }
        if (lo.flags & kHuffmanSymbol) {
            if (w == end) {
                out.resize(start);
                return HuffStatus::too_large;
            }
            *w++ = static_cast<char>(lo.symbol);
        }
        state = lo.next;
        flags = lo.flags;
    }
    out.resize(static_cast<std::size_t>(w - out.data()));
    if (flags & kHuffmanAccepted) return HuffStatus::ok;
    out.resize(start);
    return HuffStatus::malformed;
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

// ---- the dynamic table ----

void DynamicTable::evict_to(std::size_t limit) noexcept {
    while (count_ > 0 && size_ > limit) {
        const std::size_t oldest = (head_ + ring_.size() - (count_ - 1)) % ring_.size();
        Entry& e = ring_[oldest];
        size_ -= e.name.size() + e.value.size() + 32;
        e.name.clear();
        e.value.clear();
        --count_;
    }
}

void DynamicTable::set_limit(std::size_t limit) noexcept {
    limit_ = limit;
    evict_to(limit_);
}

bool DynamicTable::add(std::string_view name, std::string_view value) {
    const std::size_t need = name.size() + value.size() + 32;
    if (need > limit_) {  // RFC 7541 4.4: an entry larger than the table empties it and is not added
        evict_to(0);
        return false;
    }
    evict_to(limit_ - need);
    if (ring_.empty()) ring_.resize(capacity_ / 32 + 1);  // an entry costs at least 32 bytes, so this many fit
    head_ = (head_ + 1) % ring_.size();
    Entry& e = ring_[head_];
    e.name.assign(name);
    e.value.assign(value);
    e.checked = 0;
    ++count_;
    size_ += need;
    return true;
}

bool DynamicTable::at(std::size_t k, std::string_view& name, std::string_view& value) const noexcept {
    if (k >= count_ || ring_.empty()) return false;
    const Entry& e = ring_[head_ >= k ? head_ - k : head_ + ring_.size() - k];
    name = e.name;
    value = e.value;
    return true;
}

bool DynamicTable::at(std::size_t k, std::string_view& name, std::string_view& value, std::uint8_t*& mark) const noexcept {
    if (k >= count_ || ring_.empty()) return false;
    const Entry& e = ring_[head_ >= k ? head_ - k : head_ + ring_.size() - k];
    name = e.name;
    value = e.value;
    mark = &e.checked;
    return true;
}

std::size_t DynamicTable::find(std::string_view name, std::string_view value) const noexcept {
    std::size_t i = head_;  // newest first, the ring walked backwards without a division per step
    for (std::size_t k = 0; k < count_; ++k) {
        const Entry& e = ring_[i];
        if (e.name.size() == name.size() && e.value.size() == value.size() && e.name == name && e.value == value) return k;
        i = i == 0 ? ring_.size() - 1 : i - 1;
    }
    return npos;
}

}  // namespace agensio::codec
