// libFuzzer target for the HTTP response-head parser of the reverse proxy.
// Build: cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ (with libFuzzer)
// Run:   build-fuzz/fuzz_http_head tests/fuzz/regressions/http_head -max_len=4096 -max_total_time=60
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "upstream/http_head.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view in(reinterpret_cast<const char*>(data), size);
    agensio::http::ResponseHead head;
    const auto st = agensio::http::parse_response_head(in, head);
    if (st == agensio::http::HeadStatus::complete) {
        assert(head.length <= in.size() && head.status >= 100 && head.status <= 599);
        for (const auto& h : head.headers)
            assert(h.name.data() >= in.data() && h.value.data() + h.value.size() <= in.data() + in.size());
        (void)agensio::http::connection_lists(head.headers.get("connection"), "close");
    }
    return 0;
}
