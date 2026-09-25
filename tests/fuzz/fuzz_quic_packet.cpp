// QUIC packet headers (RFC 9000 17), coalesced datagrams, the version-negotiation builder,
// and the frames of a plaintext payload in every packet number space (RFC 9000 12.4, 19):
// nothing here may read past the input or take more than a bounded step per byte.
#include <cstddef>
#include <cstdint>

#include "quic/frames.hpp"
#include "quic/packet.hpp"

using namespace agensio::quic;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    PacketHeader h;
    std::size_t pos = 0;
    while (pos < size && parse_header(data + pos, size - pos, kOurCidLen, h)) {
        if (!h.long_form || h.total == 0) break;
        pos += h.total;
    }
    if (parse_header(data, size, kOurCidLen, h)) {
        unsigned char out[64 + 2 * kMaxCidLen];
        build_version_negotiation(out, sizeof out, h.scid, h.dcid, 0x0a0a0a0a, 0x5a);
    }
    for (unsigned sp = 0; sp < kSpaces; ++sp) {
        const unsigned char* p = data;
        const unsigned char* end = data + size;
        Frame f;
        while (p < end && read_frame(p, end, f)) {
            (void)frame_allowed(f.type, static_cast<Space>(sp));
            (void)ack_eliciting(f.type);
            (void)probing_frame(f.type);
        }
    }
    return 0;
}
