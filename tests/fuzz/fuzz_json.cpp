// libFuzzer target for the JSON parser the control API, the MCP bridge and the log
// reader use on untrusted bytes. Build: cmake -B build-fuzz -DAGENSIO_FUZZ=ON
// -DCMAKE_CXX_COMPILER=clang++.  Run: build-fuzz/fuzz_json tests/fuzz/regressions/json
// -max_len=4096 -max_total_time=60
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "services/json.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view in(reinterpret_cast<const char*>(data), size);
    agensio::json::Value v;
    std::string error;
    if (!agensio::json::parse(in, v, error)) {
        assert(!error.empty());
        return 0;
    }
    // What parsed must serialise and parse again to the same text (canonical form).
    const std::string once = v.dump();
    agensio::json::Value again;
    assert(agensio::json::parse(once, again, error));
    assert(again.dump() == once);
    (void)v["x"]["y"].get("z");  // lookups on any shape are total
    for (const auto& m : v.members()) (void)m.first.size();
    for (const auto& i : v.items()) (void)i.type();
    return 0;
}
