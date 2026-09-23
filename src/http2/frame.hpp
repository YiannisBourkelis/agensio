// HTTP/2 framing (RFC 9113 section 4): the 9-byte frame header, frame types, flags and
// error codes, and the builders of the control frames the server sends. Header-only,
// allocation-free, every read bounds-checked by the caller (a header is read only from
// kFrameHeaderSize bytes that are known to be present). Fuzzed through the connection.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace agensio::h2 {

inline constexpr std::size_t kFrameHeaderSize = 9;
inline constexpr std::string_view kPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";  // 24 bytes, RFC 9113 3.4
inline constexpr std::uint32_t kMaxStreamId = 0x7fffffffu;

enum class FrameType : std::uint8_t {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

namespace flag {
inline constexpr std::uint8_t end_stream = 0x1;   // DATA, HEADERS
inline constexpr std::uint8_t ack = 0x1;          // SETTINGS, PING
inline constexpr std::uint8_t end_headers = 0x4;  // HEADERS, PUSH_PROMISE, CONTINUATION
inline constexpr std::uint8_t padded = 0x8;       // DATA, HEADERS, PUSH_PROMISE
inline constexpr std::uint8_t priority = 0x20;    // HEADERS
}  // namespace flag

enum class ErrorCode : std::uint32_t {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
};

// The error code's name for the error log.
inline std::string_view error_name(ErrorCode c) noexcept {
    switch (c) {
        case ErrorCode::no_error: return "NO_ERROR";
        case ErrorCode::protocol_error: return "PROTOCOL_ERROR";
        case ErrorCode::internal_error: return "INTERNAL_ERROR";
        case ErrorCode::flow_control_error: return "FLOW_CONTROL_ERROR";
        case ErrorCode::settings_timeout: return "SETTINGS_TIMEOUT";
        case ErrorCode::stream_closed: return "STREAM_CLOSED";
        case ErrorCode::frame_size_error: return "FRAME_SIZE_ERROR";
        case ErrorCode::refused_stream: return "REFUSED_STREAM";
        case ErrorCode::cancel: return "CANCEL";
        case ErrorCode::compression_error: return "COMPRESSION_ERROR";
        case ErrorCode::connect_error: return "CONNECT_ERROR";
        case ErrorCode::enhance_your_calm: return "ENHANCE_YOUR_CALM";
        case ErrorCode::inadequate_security: return "INADEQUATE_SECURITY";
        case ErrorCode::http_1_1_required: return "HTTP_1_1_REQUIRED";
    }
    return "UNKNOWN";
}

struct FrameHeader {
    std::uint32_t length = 0;  // payload bytes (24 bits on the wire)
    std::uint8_t type = 0;
    std::uint8_t flags = 0;
    std::uint32_t stream_id = 0;  // the reserved high bit cleared
};

inline std::uint32_t read_u32(const unsigned char* p) noexcept {
    return (static_cast<std::uint32_t>(p[0]) << 24) | (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) | static_cast<std::uint32_t>(p[3]);
}
inline void write_u32(unsigned char* p, std::uint32_t v) noexcept {
    p[0] = static_cast<unsigned char>(v >> 24);
    p[1] = static_cast<unsigned char>(v >> 16);
    p[2] = static_cast<unsigned char>(v >> 8);
    p[3] = static_cast<unsigned char>(v);
}

// `p` points at kFrameHeaderSize readable bytes.
inline FrameHeader read_frame_header(const unsigned char* p) noexcept {
    FrameHeader h;
    h.length = (static_cast<std::uint32_t>(p[0]) << 16) | (static_cast<std::uint32_t>(p[1]) << 8) |
               static_cast<std::uint32_t>(p[2]);
    h.type = p[3];
    h.flags = p[4];
    h.stream_id = read_u32(p + 5) & kMaxStreamId;
    return h;
}

inline void write_frame_header(unsigned char* p, std::uint32_t length, FrameType type, std::uint8_t flags,
                               std::uint32_t stream_id) noexcept {
    p[0] = static_cast<unsigned char>(length >> 16);
    p[1] = static_cast<unsigned char>(length >> 8);
    p[2] = static_cast<unsigned char>(length);
    p[3] = static_cast<unsigned char>(type);
    p[4] = flags;
    write_u32(p + 5, stream_id & kMaxStreamId);
}

// ---- builders of the frames the server sends, appended to an output buffer ----

inline void append_frame_header(std::string& out, std::uint32_t length, FrameType type, std::uint8_t flags,
                                std::uint32_t stream_id) {
    unsigned char h[kFrameHeaderSize];
    write_frame_header(h, length, type, flags, stream_id);
    out.append(reinterpret_cast<const char*>(h), kFrameHeaderSize);  // NOLINT: bytes to chars
}
inline void append_u32(std::string& out, std::uint32_t v) {
    unsigned char b[4];
    write_u32(b, v);
    out.append(reinterpret_cast<const char*>(b), 4);  // NOLINT: bytes to chars
}
inline void append_u16(std::string& out, std::uint16_t v) {
    out.push_back(static_cast<char>(v >> 8));
    out.push_back(static_cast<char>(v));
}

struct SettingPair {
    std::uint16_t id;
    std::uint32_t value;
};
template <std::size_t N>
void append_settings(std::string& out, const SettingPair (&pairs)[N]) {
    append_frame_header(out, static_cast<std::uint32_t>(N * 6), FrameType::settings, 0, 0);
    for (const SettingPair& p : pairs) {
        append_u16(out, p.id);
        append_u32(out, p.value);
    }
}
inline void append_settings_ack(std::string& out) { append_frame_header(out, 0, FrameType::settings, flag::ack, 0); }
// `payload` points at the 8 opaque bytes of the peer's PING.
inline void append_ping_ack(std::string& out, const unsigned char* payload) {
    append_frame_header(out, 8, FrameType::ping, flag::ack, 0);
    out.append(reinterpret_cast<const char*>(payload), 8);  // NOLINT: bytes to chars
}
inline void append_rst_stream(std::string& out, std::uint32_t stream_id, ErrorCode code) {
    append_frame_header(out, 4, FrameType::rst_stream, 0, stream_id);
    append_u32(out, static_cast<std::uint32_t>(code));
}
inline void append_window_update(std::string& out, std::uint32_t stream_id, std::uint32_t increment) {
    append_frame_header(out, 4, FrameType::window_update, 0, stream_id);
    append_u32(out, increment & kMaxStreamId);
}
// `debug` is optional opaque data (we send a short ASCII reason, which h2spec and nghttp print).
inline void append_goaway(std::string& out, std::uint32_t last_stream_id, ErrorCode code, std::string_view debug) {
    append_frame_header(out, static_cast<std::uint32_t>(8 + debug.size()), FrameType::goaway, 0, 0);
    append_u32(out, last_stream_id & kMaxStreamId);
    append_u32(out, static_cast<std::uint32_t>(code));
    out.append(debug);
}

}  // namespace agensio::h2
