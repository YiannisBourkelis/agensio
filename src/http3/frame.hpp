// HTTP/3 framing (RFC 9114 section 7), stream types (6.2), settings (7.2.4) and error
// codes (8.1). A frame is a varint type, a varint length and a payload, and may span
// STREAM frames and packets: the connection parses incrementally per stream.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "quic/varint.hpp"

namespace agensio::h3 {

namespace frame {
inline constexpr std::uint64_t data = 0x00, headers = 0x01, cancel_push = 0x03, settings = 0x04, push_promise = 0x05,
                               goaway = 0x07, max_push_id = 0x0d;
}
namespace stream_type {
inline constexpr std::uint64_t control = 0x00, push = 0x01, qpack_encoder = 0x02, qpack_decoder = 0x03;
}
namespace setting {
inline constexpr std::uint64_t qpack_max_table_capacity = 0x01, max_field_section_size = 0x06, qpack_blocked_streams = 0x07;
}
namespace err {
inline constexpr std::uint64_t no_error = 0x100, general_protocol = 0x101, internal = 0x102, stream_creation = 0x103,
                               closed_critical_stream = 0x104, frame_unexpected = 0x105, frame_error = 0x106,
                               excessive_load = 0x107, id_error = 0x108, settings_error = 0x109, missing_settings = 0x10a,
                               request_rejected = 0x10b, request_cancelled = 0x10c, request_incomplete = 0x10d,
                               message_error = 0x10e, connect_error = 0x10f, version_fallback = 0x110,
                               qpack_decompression_failed = 0x200, qpack_encoder_stream = 0x201, qpack_decoder_stream = 0x202;
}

// Reserved frame types, stream types and settings (0x1f * N + 0x21) are ignored (7.2.8, 6.2.3, 7.2.4.1).
inline bool reserved(std::uint64_t t) noexcept { return t >= 0x21 && (t - 0x21) % 0x1f == 0; }

inline void append_frame_header(std::string& out, std::uint64_t type, std::uint64_t len) {
    quic::append_varint(out, type);
    quic::append_varint(out, len);
}

}  // namespace agensio::h3
