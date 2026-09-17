// libFuzzer target for the FastCGI record reader and the CGI response-head parser.
// Build: cmake -B build-fuzz -DAGENSIO_FUZZ=ON -DCMAKE_CXX_COMPILER=clang++ (with libFuzzer)
// Run:   build-fuzz/fuzz_fcgi tests/fuzz/regressions/fcgi -max_len=4096 -max_total_time=60
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "upstream/fcgi.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    std::string_view in(reinterpret_cast<const char*>(data), size);
    std::string_view rest = in;
    for (;;) {
        std::size_t used = 0;
        agensio::fcgi::RecordHeader h;
        std::string_view content;
        const auto st = agensio::fcgi::next_record(rest, used, h, content);
        if (st != agensio::fcgi::ReadStatus::record) break;
        assert(used >= agensio::fcgi::kHeaderSize && used <= rest.size());
        assert(content.size() == h.content_length);
        assert(content.data() >= rest.data() && content.data() + content.size() <= rest.data() + rest.size());
        agensio::fcgi::EndRequest er;
        (void)agensio::fcgi::parse_end_request(content, er);
        rest.remove_prefix(used);
    }
    agensio::fcgi::CgiHead head;
    const auto hs = agensio::fcgi::parse_cgi_head(in, head);
    if (hs == agensio::fcgi::HeadStatus::complete) {
        assert(head.length <= in.size() && head.status >= 100 && head.status <= 599);
        for (const auto& f : head.headers)
            assert(f.name.data() >= in.data() && f.name.data() + f.name.size() <= in.data() + in.size());
    }
    return 0;
}
