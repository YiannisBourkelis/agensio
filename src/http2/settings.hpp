// HTTP/2 SETTINGS (RFC 9113 section 6.5): the identifiers, the values the server
// advertises, and the peer's values with the validation the RFC requires.
#pragma once

#include <cstdint>

#include "http2/frame.hpp"

namespace agensio::h2 {

enum SettingId : std::uint16_t {
    setting_header_table_size = 0x1,
    setting_enable_push = 0x2,
    setting_max_concurrent_streams = 0x3,
    setting_initial_window_size = 0x4,
    setting_max_frame_size = 0x5,
    setting_max_header_list_size = 0x6,
    setting_enable_connect_protocol = 0x8,  // RFC 8441
    setting_no_rfc7540_priorities = 0x9,    // RFC 9218
};

inline constexpr std::uint32_t kDefaultWindow = 65535;
inline constexpr std::uint32_t kMaxWindow = 0x7fffffffu;
inline constexpr std::uint32_t kMinFrameSize = 16384;
inline constexpr std::uint32_t kMaxFrameSize = (1u << 24) - 1;

// What the peer told us, starting from the protocol defaults.
struct PeerSettings {
    std::uint32_t header_table_size = 4096;  // the encoder's table: we never fill it (hpack.hpp), so it stays unused
    std::uint32_t enable_push = 1;
    std::uint32_t max_concurrent_streams = 0xffffffffu;  // unlimited until told
    std::uint32_t initial_window_size = kDefaultWindow;
    std::uint32_t max_frame_size = kMinFrameSize;
    std::uint32_t max_header_list_size = 0xffffffffu;
    bool no_rfc7540_priorities = false;

    // Applies one pair; unknown identifiers are ignored (RFC 9113 6.5.2). Returns the error
    // that closes the connection when the value is invalid.
    ErrorCode apply(std::uint16_t id, std::uint32_t value) noexcept {
        switch (id) {
            case setting_header_table_size: header_table_size = value; return ErrorCode::no_error;
            case setting_enable_push:
                if (value > 1) return ErrorCode::protocol_error;
                enable_push = value;
                return ErrorCode::no_error;
            case setting_max_concurrent_streams: max_concurrent_streams = value; return ErrorCode::no_error;
            case setting_initial_window_size:
                if (value > kMaxWindow) return ErrorCode::flow_control_error;
                initial_window_size = value;
                return ErrorCode::no_error;
            case setting_max_frame_size:
                if (value < kMinFrameSize || value > kMaxFrameSize) return ErrorCode::protocol_error;
                max_frame_size = value;
                return ErrorCode::no_error;
            case setting_max_header_list_size: max_header_list_size = value; return ErrorCode::no_error;
            case setting_no_rfc7540_priorities:
                if (value > 1) return ErrorCode::protocol_error;
                no_rfc7540_priorities = value == 1;
                return ErrorCode::no_error;
            default: return ErrorCode::no_error;
        }
    }
};

}  // namespace agensio::h2
