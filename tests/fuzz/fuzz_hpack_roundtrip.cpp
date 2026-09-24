// The response encoder against our decoder: random sequences of fields, SETTINGS changes
// and clocks must decode to exactly what was encoded, with both tables in step.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "http2/hpack.hpp"

using namespace agensio::hpack;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    static const char* const kNames[] = {"content-type", "cache-control", "x-powered-by", "etag", "content-length",
                                         "set-cookie", "vary", "last-modified", "x-custom", "authorization"};
    static const char* const kValues[] = {"text/html; charset=utf-8", "no-cache", "PHP/8.4", "\"5f-3d\"", "1234",
                                          "a=b; Path=/", "Accept-Encoding", "Wed, 24 Sep 2026 10:00:00 GMT", "", "x"};
    Encoder e;
    Decoder d(4096);
    std::string server_insert;
    append_insert(server_insert, "server", "agensio");
    std::string date_value = "Wed, 24 Sep 2026 10:00:00 GMT";
    std::string date_insert;
    append_insert(date_insert, "date", date_value);
    std::time_t second = 1;
    std::size_t pos = 0;
    while (pos < size) {
        const std::uint8_t op = data[pos++];
        std::string block;
        std::vector<std::pair<std::string, std::string>> want;
        if (op & 0x80) {  // a settings change: no block goes out for it
            const std::uint32_t v = (op & 0x40) ? 0 : static_cast<std::uint32_t>((op & 0x3f) * 100);
            e.set_peer_max(v);
            continue;
        }
        e.begin(block);  // only for a block that is sent: the update it emits must reach the decoder
        if (op & 0x40) {
            e.server(block, "agensio", server_insert);
            want.emplace_back("server", "agensio");
        }
        if (op & 0x20) {
            if (op & 0x10) {
                ++second;
                date_value[25] = static_cast<char>('0' + (second % 10));
                date_insert.clear();
                append_insert(date_insert, "date", date_value);
            }
            e.date(block, second, date_value, date_insert);
            want.emplace_back("date", date_value);
        }
        const unsigned n = op & 0x07;
        for (unsigned i = 0; i < n && pos < size; ++i) {
            const std::uint8_t sel = data[pos++];
            std::string value = kValues[sel & 0x0f ? (sel & 0x0f) % 10 : 0];
            if (sel & 0x10) value.append(static_cast<std::size_t>((sel >> 5) * 300), 'z');  // some larger than the table
            const char* name = kNames[(sel >> 4) % 10];
            e.field(block, name, value);
            want.emplace_back(name, value);
        }
        std::vector<std::pair<std::string, std::string>> got;
        std::string arena;
        const auto r = d.decode(block, arena, 65536, [&](std::string_view nm, std::string_view v) {
            got.emplace_back(std::string(nm), std::string(v));
            return true;
        });
        if (r != Decoder::Result::ok) {
            std::fprintf(stderr, "decode result %d, block %zu bytes, op %02x\n", static_cast<int>(r), block.size(), op);
            __builtin_trap();
        }
        if (got != want) {
            std::fprintf(stderr, "fields differ: got %zu want %zu (op %02x)\n", got.size(), want.size(), op);
            for (std::size_t i = 0; i < got.size() || i < want.size(); ++i)
                std::fprintf(stderr, "  %zu: got %s=%s want %s=%s\n", i, i < got.size() ? got[i].first.c_str() : "-", i < got.size() ? got[i].second.c_str() : "-",
                             i < want.size() ? want[i].first.c_str() : "-", i < want.size() ? want[i].second.c_str() : "-");
            __builtin_trap();
        }
        if (e.table_size() != d.table_size() || e.table_entries() != d.table_entries()) {
            std::fprintf(stderr, "tables differ: encoder %zu bytes/%zu entries, decoder %zu/%zu (op %02x)\n", e.table_size(), e.table_entries(), d.table_size(), d.table_entries(), op);
            __builtin_trap();
        }
    }
    return 0;
}
