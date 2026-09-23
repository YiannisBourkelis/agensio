// libFuzzer target for the HPACK decoder and the encoder's round trip.
//   build-fuzz/fuzz_hpack corpus-hpack -max_len=4096 -max_total_time=120   (corpus dir: scratch;
//   a crash file goes to tests/fuzz/regressions/hpack once one exists)
// Every input is decoded twice: by a fresh decoder (each run independent) and by one
// decoder that survives across inputs (the dynamic table evolves as on a connection). The
// input is also read as name/value pairs, encoded with the writer's helpers and decoded
// back, which must reproduce the pairs exactly. Nothing may crash, hang, or make the
// arena grow past the list-size budget.
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>
#include <vector>

#include "http2/hpack.hpp"

using namespace agensio::hpack;

namespace {

Decoder& persistent() {
    static Decoder d(4096);
    return d;
}

void check_arena(const std::string& arena, std::size_t budget) {
    if (arena.size() > budget + 64) std::abort();  // the decode stopped late
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const std::string_view in(reinterpret_cast<const char*>(data), size);  // NOLINT
    const std::size_t budget = 1024 + (size % 4096);
    {
        Decoder fresh(4096);
        std::string arena;
        std::size_t total = 0;
        fresh.decode(in, arena, budget, [&](std::string_view n, std::string_view v) {
            total += n.size() + v.size() + 32;
            return total < budget;
        });
        check_arena(arena, budget);
    }
    {
        std::string arena;
        persistent().decode(in, arena, budget, [](std::string_view, std::string_view) { return true; });
        check_arena(arena, budget);
        if (persistent().table_size() > 4096) std::abort();
    }
    // Round trip: pairs of (name, value) split at the input's bytes.
    {
        std::vector<std::pair<std::string, std::string>> pairs;
        std::string block;
        std::size_t pos = 0;
        while (pos < size && pairs.size() < 32) {
            const std::size_t nlen = data[pos] % 40 + 1;
            const std::size_t vlen = pos + 1 < size ? data[pos + 1] : 0;
            pos += 2;
            if (pos + nlen + vlen > size) break;
            std::string name(in.substr(pos, nlen));
            for (char& c : name) c = static_cast<char>((static_cast<unsigned char>(c) % 26) + 'a');  // a token, lower-case
            const std::string value(in.substr(pos + nlen, vlen));
            pos += nlen + vlen;
            append_field(block, name, value);
            pairs.emplace_back(std::move(name), value);
        }
        Decoder d(4096);
        std::string arena;
        std::vector<std::pair<std::string, std::string>> got;
        const Decoder::Result r = d.decode(block, arena, 1u << 20, [&](std::string_view n, std::string_view v) {
            got.emplace_back(n, v);
            return true;
        });
        if (r != Decoder::Result::ok || got != pairs) std::abort();
        if (d.table_size() != 0) std::abort();  // the encoder never fills a table
    }
    // Huffman round trip of the raw input.
    {
        std::string enc, dec;
        huffman_encode(enc, in);
        if (enc.size() != huffman_size(in)) std::abort();
        if (huffman_decode(enc, dec, size) != HuffStatus::ok || dec != in) std::abort();
    }
    return 0;
}
