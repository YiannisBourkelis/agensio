// libFuzzer target for the chunked transfer-coding decoder: the wire bytes are fed in
// pieces whose sizes come from the input itself, with a small output buffer, so every
// split and every output-full return path is exercised.
// Build: cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ (with libFuzzer)
// Run:   build-fuzz/fuzz_chunked tests/fuzz/regressions/chunked -max_len=2048 -max_total_time=60
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "http1/chunked.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    if (size == 0) return 0;
    const std::size_t step = 1 + data[0] % 16;
    std::string_view wire(reinterpret_cast<const char*>(data + 1), size - 1);
    agensio::ChunkedDecoder d;
    char out[7];
    std::size_t pos = 0, total = 0;
    while (pos < wire.size()) {
        std::string_view piece = wire.substr(pos, step);
        std::size_t used = 0, produced = 0;
        const auto st = d.decode(piece, used, out, sizeof(out), produced);
        assert(used <= piece.size() && produced <= sizeof(out));
        total += produced;
        pos += used;
        if (st == agensio::ChunkedDecoder::Status::error) break;
        if (st == agensio::ChunkedDecoder::Status::done) {
            assert(d.done());
            break;
        }
        assert(used > 0 || produced > 0);  // must always make progress
    }
    assert(total <= wire.size());
    return 0;
}
