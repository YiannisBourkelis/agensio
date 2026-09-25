// Transport parameters (RFC 9000 18): decoding arbitrary bytes, then the round trip of
// what decoded through the encoder.
#include <cstddef>
#include <cstdint>
#include <string>

#include "quic/transport_params.hpp"

using namespace agensio::quic;

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    TransportParams t;
    if (!decode_transport_params(data, size, t)) return 0;
    const std::string enc = encode_transport_params(t);
    TransportParams u;
    decode_transport_params(reinterpret_cast<const unsigned char*>(enc.data()), enc.size(), u);
    return 0;
}
