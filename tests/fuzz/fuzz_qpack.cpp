// QPACK (RFC 9204): the encoder stream's instructions into the decoder's dynamic table,
// then a field section against that table, then the decoder stream's answers. The first
// byte splits the input between the two streams. Every outcome is legal except reading
// past the input, unbounded work, or a table beyond its capacity.
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "http3/qpack.hpp"

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    if (size < 2) return 0;
    const std::string_view in(reinterpret_cast<const char*>(data + 1), size - 1);
    const std::size_t split = data[0] % in.size();
    agensio::qpack::Decoder d;
    std::size_t consumed = 0;
    const bool ok = d.encoder_stream(in.substr(0, split), consumed);
    std::string arena;
    std::uint64_t required = 0;
    std::size_t fields = 0;
    const auto r = d.decode(in.substr(split), arena, 16384,
                            [&](std::string_view, std::string_view, agensio::codec::Origin) { return ++fields < 200; }, required);
    std::string out;
    if (ok && r == agensio::qpack::Decoder::Result::ok) d.section_acknowledged(0, required, out);
    d.stream_cancelled(4, out);
    d.insert_count_increment(out);
    return 0;
}
