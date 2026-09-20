// libFuzzer target for the archive extractor behind site-install: tar, tar.gz and zip
// bytes from anywhere. Invariants: no crash, no hang, every refusal names a reason, and
// the counting sink sees only what the summary counts. Build: cmake -B build-fuzz
// -DAGENSIO_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++.  Run: build-fuzz/fuzz_archive
// tests/fuzz/regressions/archive -max_len=65536 -max_total_time=120
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "services/archive.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    using namespace agensio::archive;
    MemorySource src(std::string_view(reinterpret_cast<const char*>(data), size));
    CountingSink sink;
    Limits limits;
    limits.max_bytes = 8u << 20;   // a gzip bomb would otherwise take the time budget
    limits.max_entries = 10000;
    Summary summary;
    std::string error;
    const bool ok = extract(src, sink, limits, summary, error);
    if (!ok) assert(!error.empty());
    assert(sink.files == summary.files && sink.directories == summary.directories);
    assert(sink.bytes == summary.bytes && summary.bytes <= limits.max_bytes);
    assert(summary.files + summary.directories <= limits.max_entries);
    std::string cleaned, why;
    (void)clean_path(std::string_view(reinterpret_cast<const char*>(data), size), cleaned, why);
    return 0;
}
