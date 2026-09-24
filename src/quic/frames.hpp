// QUIC frames (RFC 9000 section 19): the types, which packet number space may carry
// which (12.4), the encoders that write into a packet under construction (each returns
// the bytes written, 0 when the frame does not fit), and the reader that walks a
// decrypted payload frame by frame. ACK frames are read into a bounded range list; more
// ranges than that are read and ignored (design-http3 9.1).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "quic/packet.hpp"
#include "quic/range_set.hpp"
#include "quic/varint.hpp"

namespace agensio::quic {

namespace frame {
inline constexpr std::uint64_t padding = 0x00, ping = 0x01, ack = 0x02, ack_ecn = 0x03, reset_stream = 0x04,
                               stop_sending = 0x05, crypto = 0x06, new_token = 0x07, stream = 0x08, stream_max = 0x0f,
                               max_data = 0x10, max_stream_data = 0x11, max_streams_bidi = 0x12, max_streams_uni = 0x13,
                               data_blocked = 0x14, stream_data_blocked = 0x15, streams_blocked_bidi = 0x16,
                               streams_blocked_uni = 0x17, new_connection_id = 0x18, retire_connection_id = 0x19,
                               path_challenge = 0x1a, path_response = 0x1b, connection_close = 0x1c,
                               connection_close_app = 0x1d, handshake_done = 0x1e;
}  // namespace frame

// Transport error codes (RFC 9000 20.1).
namespace err {
inline constexpr std::uint64_t no_error = 0x00, internal = 0x01, connection_refused = 0x02, flow_control = 0x03,
                               stream_limit = 0x04, stream_state = 0x05, final_size = 0x06, frame_encoding = 0x07,
                               transport_parameter = 0x08, connection_id_limit = 0x09, protocol_violation = 0x0a,
                               invalid_token = 0x0b, application_error = 0x0c, crypto_buffer_exceeded = 0x0d,
                               key_update = 0x0e, aead_limit_reached = 0x0f, no_viable_path = 0x10, crypto_base = 0x100;
}  // namespace err

inline constexpr unsigned kMaxAckRanges = 32;

// Which frames a space may carry (RFC 9000 12.4, table 3): Initial and Handshake take
// only PADDING, PING, ACK, CRYPTO and the transport CONNECTION_CLOSE.
inline bool frame_allowed(std::uint64_t type, Space space) noexcept {
    if (space == Space::application) return type <= frame::handshake_done;
    switch (type) {
        case frame::padding: case frame::ping: case frame::ack: case frame::ack_ecn: case frame::crypto:
        case frame::connection_close:
            return true;
        default: return false;
    }
}

// A probing frame (RFC 9000 9.1): a packet of only these from a new address is not a
// migration.
inline bool probing_frame(std::uint64_t type) noexcept {
    return type == frame::padding || type == frame::path_challenge || type == frame::path_response || type == frame::new_connection_id;
}

inline bool ack_eliciting(std::uint64_t type) noexcept {
    return type != frame::padding && type != frame::ack && type != frame::ack_ecn && type != frame::connection_close &&
           type != frame::connection_close_app;
}

// ---- encoders: into [p, p + cap), returning the bytes written or 0 ----

inline std::size_t put_ping(unsigned char* p, std::size_t cap) noexcept {
    if (cap < 1) return 0;
    p[0] = frame::ping;
    return 1;
}

inline std::size_t put_handshake_done(unsigned char* p, std::size_t cap) noexcept {
    if (cap < 1) return 0;
    p[0] = frame::handshake_done;
    return 1;
}

// ACK (19.3): the received set's highest ranges, newest first; `delay` already in units
// of 2^ack_delay_exponent microseconds.
inline std::size_t put_ack(unsigned char* p, std::size_t cap, const RangeSet& received, std::uint64_t delay) noexcept {
    const auto& r = received.ranges();
    if (r.empty()) return 0;
    unsigned char* q = p;
    const unsigned char* end = p + cap;
    auto put = [&](std::uint64_t v) -> bool {
        const std::size_t n = varint_size(v);
        if (static_cast<std::size_t>(end - q) < n) return false;
        q = write_varint(q, v);
        return true;
    };
    if (q >= end) return 0;
    *q++ = frame::ack;
    const std::size_t last = r.size() - 1;
    const std::uint64_t largest = r[last].second - 1;
    const std::size_t count = std::min<std::size_t>(r.size() - 1, kMaxAckRanges);
    if (!put(largest) || !put(delay) || !put(count) || !put(r[last].second - r[last].first - 1)) return 0;
    std::uint64_t prev_begin = r[last].first;
    for (std::size_t i = 0; i < count; ++i) {
        const auto& x = r[last - 1 - i];
        const std::uint64_t gap = prev_begin - x.second - 1;  // packets between the ranges, minus one
        if (!put(gap) || !put(x.second - x.first - 1)) return 0;
        prev_begin = x.first;
    }
    return static_cast<std::size_t>(q - p);
}

// CRYPTO (19.6) and STREAM (19.8) frame headers; the payload follows. `with_length`
// false writes the STREAM form without a Length field, the last frame of a packet.
inline std::size_t put_crypto_header(unsigned char* p, std::size_t cap, std::uint64_t offset, std::size_t len) noexcept {
    const std::size_t need = 1 + varint_size(offset) + varint_size(len);
    if (cap < need) return 0;
    p[0] = frame::crypto;
    unsigned char* q = write_varint(p + 1, offset);
    q = write_varint(q, len);
    return static_cast<std::size_t>(q - p);
}

inline std::size_t stream_header_size(std::uint64_t id, std::uint64_t offset, std::size_t len, bool with_length) noexcept {
    return 1 + varint_size(id) + (offset ? varint_size(offset) : 0) + (with_length ? varint_size(len) : 0);
}

inline std::size_t put_stream_header(unsigned char* p, std::size_t cap, std::uint64_t id, std::uint64_t offset,
                                     std::size_t len, bool fin, bool with_length) noexcept {
    const std::size_t need = stream_header_size(id, offset, len, with_length);
    if (cap < need) return 0;
    p[0] = static_cast<unsigned char>(frame::stream | (offset ? 0x04 : 0) | (with_length ? 0x02 : 0) | (fin ? 0x01 : 0));
    unsigned char* q = write_varint(p + 1, id);
    if (offset) q = write_varint(q, offset);
    if (with_length) q = write_varint(q, len);
    return static_cast<std::size_t>(q - p);
}

inline std::size_t put_varints(unsigned char* p, std::size_t cap, std::uint64_t type, std::uint64_t a) noexcept {
    const std::size_t need = varint_size(type) + varint_size(a);
    if (cap < need) return 0;
    unsigned char* q = write_varint(p, type);
    q = write_varint(q, a);
    return static_cast<std::size_t>(q - p);
}
inline std::size_t put_varints(unsigned char* p, std::size_t cap, std::uint64_t type, std::uint64_t a, std::uint64_t b) noexcept {
    const std::size_t need = varint_size(type) + varint_size(a) + varint_size(b);
    if (cap < need) return 0;
    unsigned char* q = write_varint(p, type);
    q = write_varint(q, a);
    q = write_varint(q, b);
    return static_cast<std::size_t>(q - p);
}
inline std::size_t put_varints(unsigned char* p, std::size_t cap, std::uint64_t type, std::uint64_t a, std::uint64_t b, std::uint64_t c) noexcept {
    const std::size_t need = varint_size(type) + varint_size(a) + varint_size(b) + varint_size(c);
    if (cap < need) return 0;
    unsigned char* q = write_varint(p, type);
    q = write_varint(q, a);
    q = write_varint(q, b);
    q = write_varint(q, c);
    return static_cast<std::size_t>(q - p);
}

inline std::size_t put_max_data(unsigned char* p, std::size_t cap, std::uint64_t v) noexcept { return put_varints(p, cap, frame::max_data, v); }
inline std::size_t put_max_stream_data(unsigned char* p, std::size_t cap, std::uint64_t id, std::uint64_t v) noexcept { return put_varints(p, cap, frame::max_stream_data, id, v); }
inline std::size_t put_max_streams(unsigned char* p, std::size_t cap, bool bidi, std::uint64_t v) noexcept { return put_varints(p, cap, bidi ? frame::max_streams_bidi : frame::max_streams_uni, v); }
inline std::size_t put_reset_stream(unsigned char* p, std::size_t cap, std::uint64_t id, std::uint64_t code, std::uint64_t final_size) noexcept { return put_varints(p, cap, frame::reset_stream, id, code, final_size); }
inline std::size_t put_stop_sending(unsigned char* p, std::size_t cap, std::uint64_t id, std::uint64_t code) noexcept { return put_varints(p, cap, frame::stop_sending, id, code); }
inline std::size_t put_retire_connection_id(unsigned char* p, std::size_t cap, std::uint64_t seq) noexcept { return put_varints(p, cap, frame::retire_connection_id, seq); }
inline std::size_t put_data_blocked(unsigned char* p, std::size_t cap, std::uint64_t v) noexcept { return put_varints(p, cap, frame::data_blocked, v); }
inline std::size_t put_stream_data_blocked(unsigned char* p, std::size_t cap, std::uint64_t id, std::uint64_t v) noexcept { return put_varints(p, cap, frame::stream_data_blocked, id, v); }

inline std::size_t put_path_response(unsigned char* p, std::size_t cap, const unsigned char data[8]) noexcept {
    if (cap < 9) return 0;
    p[0] = frame::path_response;
    std::memcpy(p + 1, data, 8);
    return 9;
}
inline std::size_t put_path_challenge(unsigned char* p, std::size_t cap, const unsigned char data[8]) noexcept {
    if (cap < 9) return 0;
    p[0] = frame::path_challenge;
    std::memcpy(p + 1, data, 8);
    return 9;
}

// NEW_CONNECTION_ID (19.15).
inline std::size_t put_new_connection_id(unsigned char* p, std::size_t cap, std::uint64_t seq, std::uint64_t retire_prior_to,
                                         const Cid& cid, const unsigned char token[16]) noexcept {
    const std::size_t need = 1 + varint_size(seq) + varint_size(retire_prior_to) + 1 + cid.len + 16;
    if (cap < need) return 0;
    p[0] = frame::new_connection_id;
    unsigned char* q = write_varint(p + 1, seq);
    q = write_varint(q, retire_prior_to);
    *q++ = cid.len;
    std::memcpy(q, cid.bytes, cid.len);
    q += cid.len;
    std::memcpy(q, token, 16);
    q += 16;
    return static_cast<std::size_t>(q - p);
}

// CONNECTION_CLOSE (19.19): transport (with the frame type that failed) or application.
inline std::size_t put_connection_close(unsigned char* p, std::size_t cap, bool app, std::uint64_t code,
                                        std::uint64_t frame_type, std::string_view reason) noexcept {
    const std::size_t need = 1 + varint_size(code) + (app ? 0 : varint_size(frame_type)) + varint_size(reason.size()) + reason.size();
    if (cap < need) return 0;
    p[0] = static_cast<unsigned char>(app ? frame::connection_close_app : frame::connection_close);
    unsigned char* q = write_varint(p + 1, code);
    if (!app) q = write_varint(q, frame_type);
    q = write_varint(q, reason.size());
    std::memcpy(q, reason.data(), reason.size());
    q += reason.size();
    return static_cast<std::size_t>(q - p);
}

// ---- the reader ----

struct Frame {
    std::uint64_t type = 0;
    // STREAM, CRYPTO, NEW_TOKEN (data), DATAGRAM
    std::uint64_t stream_id = 0;
    std::uint64_t offset = 0;
    std::uint64_t length = 0;
    bool fin = false;
    const unsigned char* data = nullptr;
    // ACK
    std::uint64_t largest_ack = 0;
    std::uint64_t ack_delay = 0;  // in units of the peer's exponent
    unsigned range_count = 0;     // ranges kept, highest first
    RangeSet::Range ranges[kMaxAckRanges + 1];
    // Limits, errors, sequence numbers
    std::uint64_t value = 0;   // MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS, *_BLOCKED, error code, RETIRE seq, NEW_CID seq
    std::uint64_t value2 = 0;  // RESET_STREAM final size, CONNECTION_CLOSE frame type, NEW_CID retire prior to
    Cid cid;                   // NEW_CONNECTION_ID
    const unsigned char* token = nullptr;  // NEW_CONNECTION_ID's reset token (16), PATH_*'s data (8)
    std::string_view reason;   // CONNECTION_CLOSE
};

// Reads the frame at p (advanced past it). False on a malformed frame: FRAME_ENCODING_ERROR.
inline bool read_frame(const unsigned char*& p, const unsigned char* end, Frame& f) noexcept {
    if (!read_varint(p, end, f.type)) return false;
    auto v = [&](std::uint64_t& out) { return read_varint(p, end, out); };
    auto bytes = [&](std::uint64_t n, const unsigned char*& out) -> bool {
        if (n > static_cast<std::uint64_t>(end - p)) return false;
        out = p;
        p += n;
        return true;
    };
    switch (f.type) {
        case frame::padding:
            while (p < end && *p == 0) ++p;  // a run of PADDING is one frame to us
            return true;
        case frame::ping:
        case frame::handshake_done:
            return true;
        case frame::ack:
        case frame::ack_ecn: {
            std::uint64_t count = 0, first = 0;
            if (!v(f.largest_ack) || !v(f.ack_delay) || !v(count) || !v(first)) return false;
            if (first > f.largest_ack) return false;
            f.range_count = 0;
            std::uint64_t largest = f.largest_ack;
            f.ranges[f.range_count++] = {largest - first, largest + 1};
            std::uint64_t smallest = largest - first;
            for (std::uint64_t i = 0; i < count; ++i) {
                std::uint64_t gap = 0, len = 0;
                if (!v(gap) || !v(len)) return false;
                if (gap + 2 > smallest) return false;
                largest = smallest - gap - 2;
                if (len > largest) return false;
                smallest = largest - len;
                if (f.range_count <= kMaxAckRanges) f.ranges[f.range_count++] = {smallest, largest + 1};
            }
            if (f.range_count > kMaxAckRanges) f.range_count = kMaxAckRanges;
            if (f.type == frame::ack_ecn) {
                std::uint64_t ect0 = 0, ect1 = 0, ce = 0;
                if (!v(ect0) || !v(ect1) || !v(ce)) return false;
            }
            return true;
        }
        case frame::reset_stream:
            return v(f.stream_id) && v(f.value) && v(f.value2);
        case frame::stop_sending:
            return v(f.stream_id) && v(f.value);
        case frame::crypto:
            return v(f.offset) && v(f.length) && bytes(f.length, f.data);
        case frame::new_token:
            return v(f.length) && f.length > 0 && bytes(f.length, f.data);
        case frame::max_data:
        case frame::max_streams_bidi:
        case frame::max_streams_uni:
        case frame::data_blocked:
        case frame::streams_blocked_bidi:
        case frame::streams_blocked_uni:
        case frame::retire_connection_id:
            return v(f.value);
        case frame::max_stream_data:
        case frame::stream_data_blocked:
            return v(f.stream_id) && v(f.value);
        case frame::new_connection_id: {
            if (!v(f.value) || !v(f.value2)) return false;
            if (f.value2 > f.value) return false;
            if (p >= end) return false;
            const std::size_t len = *p++;
            if (len < 1 || len > kMaxCidLen) return false;
            const unsigned char* c = nullptr;
            if (!bytes(len, c)) return false;
            f.cid.assign(c, len);
            return bytes(16, f.token);
        }
        case frame::path_challenge:
        case frame::path_response:
            return bytes(8, f.token);
        case frame::connection_close:
        case frame::connection_close_app: {
            if (!v(f.value)) return false;
            if (f.type == frame::connection_close && !v(f.value2)) return false;
            std::uint64_t len = 0;
            const unsigned char* r = nullptr;
            if (!v(len) || !bytes(len, r)) return false;
            f.reason = std::string_view(reinterpret_cast<const char*>(r), static_cast<std::size_t>(len));
            return true;
        }
        default:
            if (f.type >= frame::stream && f.type <= frame::stream_max) {
                f.fin = (f.type & 0x01) != 0;
                if (!v(f.stream_id)) return false;
                f.offset = 0;
                if ((f.type & 0x04) && !v(f.offset)) return false;
                if (f.type & 0x02) {
                    if (!v(f.length)) return false;
                } else {
                    f.length = static_cast<std::uint64_t>(end - p);
                }
                if (f.offset + f.length > kVarintMax) return false;
                return bytes(f.length, f.data);
            }
            return false;  // an unknown type is FRAME_ENCODING_ERROR (RFC 9000 12.4)
    }
}

}  // namespace agensio::quic
