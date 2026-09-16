// libFuzzer target for the HTTP/1.1 request-head parser.
// Build: cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ (with libFuzzer)
// Run:   build-fuzz/fuzz_parser corpus/ -max_len=4096 -max_total_time=60
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "http_parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view buf(reinterpret_cast<const char*>(data), size);
    agensio::Request r;
    const auto st = agensio::parse_request(buf, r);
    if (st == agensio::ParseStatus::complete) {
        // Every view must point into the input and the consumed length must be sane.
        auto inside = [&](std::string_view v) {
            return v.empty() || (v.data() >= buf.data() && v.data() + v.size() <= buf.data() + buf.size());
        };
        assert(r.length > 0 && r.length <= size);
        assert(inside(r.method_name) && inside(r.target) && inside(r.host) && inside(r.connection));
        assert(inside(r.if_none_match) && inside(r.if_modified_since));
        assert(!r.target.empty() && r.target.find(' ') == std::string_view::npos);
        assert(r.version_minor == 0 || r.version_minor == 1);
    }
    return 0;
}
