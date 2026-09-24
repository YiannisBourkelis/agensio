// Transport parameters (RFC 9000 section 18): what each side declares in the TLS
// handshake. The encoder writes ours; the decoder reads the peer's with the validation
// of 18.2 (a client must not send the server-only ones, duplicates are an error, the
// bounds each value has). Unknown identifiers are skipped (18.1).
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "quic/packet.hpp"
#include "quic/varint.hpp"

namespace agensio::quic {

struct TransportParams {
    Cid original_dcid;
    bool has_original_dcid = false;
    std::uint64_t max_idle_timeout = 0;  // ms; 0 = none
    unsigned char stateless_reset_token[16] = {};
    bool has_reset_token = false;
    std::uint64_t max_udp_payload_size = 65527;
    std::uint64_t initial_max_data = 0;
    std::uint64_t initial_max_stream_data_bidi_local = 0;
    std::uint64_t initial_max_stream_data_bidi_remote = 0;
    std::uint64_t initial_max_stream_data_uni = 0;
    std::uint64_t initial_max_streams_bidi = 0;
    std::uint64_t initial_max_streams_uni = 0;
    std::uint64_t ack_delay_exponent = 3;
    std::uint64_t max_ack_delay = 25;  // ms
    bool disable_active_migration = false;
    std::uint64_t active_connection_id_limit = 2;
    Cid initial_scid;
    bool has_initial_scid = false;
    Cid retry_scid;
    bool has_retry_scid = false;
};

namespace tp {
inline constexpr std::uint64_t original_dcid = 0x00, max_idle_timeout = 0x01, stateless_reset_token = 0x02,
                               max_udp_payload_size = 0x03, initial_max_data = 0x04, initial_max_stream_data_bidi_local = 0x05,
                               initial_max_stream_data_bidi_remote = 0x06, initial_max_stream_data_uni = 0x07,
                               initial_max_streams_bidi = 0x08, initial_max_streams_uni = 0x09, ack_delay_exponent = 0x0a,
                               max_ack_delay = 0x0b, disable_active_migration = 0x0c, preferred_address = 0x0d,
                               active_connection_id_limit = 0x0e, initial_scid = 0x0f, retry_scid = 0x10;
}  // namespace tp

inline void append_param(std::string& out, std::uint64_t id, std::uint64_t value) {
    append_varint(out, id);
    append_varint(out, varint_size(value));
    append_varint(out, value);
}
inline void append_param_bytes(std::string& out, std::uint64_t id, const unsigned char* p, std::size_t n) {
    append_varint(out, id);
    append_varint(out, n);
    out.append(reinterpret_cast<const char*>(p), n);
}

// Ours, as a server.
inline std::string encode_transport_params(const TransportParams& t) {
    std::string out;
    out.reserve(128);
    if (t.has_original_dcid) append_param_bytes(out, tp::original_dcid, t.original_dcid.bytes, t.original_dcid.len);
    if (t.max_idle_timeout) append_param(out, tp::max_idle_timeout, t.max_idle_timeout);
    if (t.has_reset_token) append_param_bytes(out, tp::stateless_reset_token, t.stateless_reset_token, 16);
    append_param(out, tp::max_udp_payload_size, t.max_udp_payload_size);
    append_param(out, tp::initial_max_data, t.initial_max_data);
    append_param(out, tp::initial_max_stream_data_bidi_local, t.initial_max_stream_data_bidi_local);
    append_param(out, tp::initial_max_stream_data_bidi_remote, t.initial_max_stream_data_bidi_remote);
    append_param(out, tp::initial_max_stream_data_uni, t.initial_max_stream_data_uni);
    append_param(out, tp::initial_max_streams_bidi, t.initial_max_streams_bidi);
    append_param(out, tp::initial_max_streams_uni, t.initial_max_streams_uni);
    if (t.ack_delay_exponent != 3) append_param(out, tp::ack_delay_exponent, t.ack_delay_exponent);
    if (t.max_ack_delay != 25) append_param(out, tp::max_ack_delay, t.max_ack_delay);
    if (t.disable_active_migration) {
        append_varint(out, tp::disable_active_migration);
        append_varint(out, 0);
    }
    append_param(out, tp::active_connection_id_limit, t.active_connection_id_limit);
    if (t.has_initial_scid) append_param_bytes(out, tp::initial_scid, t.initial_scid.bytes, t.initial_scid.len);
    if (t.has_retry_scid) append_param_bytes(out, tp::retry_scid, t.retry_scid.bytes, t.retry_scid.len);
    return out;
}

// The peer's (a client's): false is TRANSPORT_PARAMETER_ERROR.
inline bool decode_transport_params(const unsigned char* p, std::size_t n, TransportParams& t) noexcept {
    const unsigned char* end = p + n;
    std::uint64_t seen = 0;  // a bit per id below 64: duplicates are an error (18.2)
    while (p < end) {
        std::uint64_t id = 0, len = 0;
        if (!read_varint(p, end, id) || !read_varint(p, end, len)) return false;
        if (len > static_cast<std::uint64_t>(end - p)) return false;
        const unsigned char* v = p;
        const unsigned char* vend = p + len;
        p = vend;
        if (id < 64) {
            if (seen & (std::uint64_t{1} << id)) return false;
            seen |= std::uint64_t{1} << id;
        }
        auto integer = [&](std::uint64_t& out) -> bool {
            const unsigned char* q = v;
            return read_varint(q, vend, out) && q == vend;
        };
        switch (id) {
            case tp::original_dcid:
            case tp::stateless_reset_token:
            case tp::preferred_address:
            case tp::retry_scid:
                return false;  // server-only (18.2)
            case tp::max_idle_timeout: if (!integer(t.max_idle_timeout)) return false; break;
            case tp::max_udp_payload_size:
                if (!integer(t.max_udp_payload_size) || t.max_udp_payload_size < 1200) return false;
                break;
            case tp::initial_max_data: if (!integer(t.initial_max_data)) return false; break;
            case tp::initial_max_stream_data_bidi_local: if (!integer(t.initial_max_stream_data_bidi_local)) return false; break;
            case tp::initial_max_stream_data_bidi_remote: if (!integer(t.initial_max_stream_data_bidi_remote)) return false; break;
            case tp::initial_max_stream_data_uni: if (!integer(t.initial_max_stream_data_uni)) return false; break;
            case tp::initial_max_streams_bidi:
                if (!integer(t.initial_max_streams_bidi) || t.initial_max_streams_bidi > (std::uint64_t{1} << 60)) return false;
                break;
            case tp::initial_max_streams_uni:
                if (!integer(t.initial_max_streams_uni) || t.initial_max_streams_uni > (std::uint64_t{1} << 60)) return false;
                break;
            case tp::ack_delay_exponent:
                if (!integer(t.ack_delay_exponent) || t.ack_delay_exponent > 20) return false;
                break;
            case tp::max_ack_delay:
                if (!integer(t.max_ack_delay) || t.max_ack_delay >= (1u << 14)) return false;
                break;
            case tp::disable_active_migration:
                if (len != 0) return false;
                t.disable_active_migration = true;
                break;
            case tp::active_connection_id_limit:
                if (!integer(t.active_connection_id_limit) || t.active_connection_id_limit < 2) return false;
                break;
            case tp::initial_scid:
                if (len > kMaxCidLen) return false;
                t.initial_scid.assign(v, static_cast<std::size_t>(len));
                t.has_initial_scid = true;
                break;
            default: break;  // unknown or greased: ignored
        }
    }
    return true;
}

}  // namespace agensio::quic
