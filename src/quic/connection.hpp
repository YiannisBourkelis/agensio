// One QUIC connection (RFC 9000, 9001, 9002), server side: packets in (header protection,
// the AEAD, the frames of each space), the handshake through the TLS glue, address
// validation, acknowledgements and loss recovery, streams with their credit, the
// packetiser that fills the worker's send batch (design-http3 6.7), the idle and close
// lifecycle. Templated over the application (HTTP/3), which owns the stream objects and
// hears about new streams, readable data, resets, sent data, the handshake and the close;
// no virtual call on the packet path.
//
// Address validation with Retry tokens, stateless resets and the half-open budget live in
// the endpoint (udp.hpp); connection ids are issued and retired here (6.4), keys update
// (RFC 9001 6), a peer whose address changed is validated on its new path (RFC 9000 9),
// the path is probed for a larger datagram once (6.7). Not here: 0-RTT, ECN, active
// migration, NEW_TOKEN (I4).
#pragma once

#include <netinet/in.h>
#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>

#include "quic/crypto.hpp"
#include "quic/frames.hpp"
#include "quic/packet.hpp"
#include "quic/recovery.hpp"
#include "quic/stream.hpp"
#include "quic/timer_heap.hpp"
#include "quic/tls.hpp"
#include "quic/transport_params.hpp"
#include "quic/udp.hpp"

#ifdef AGENSIO_QUIC_TRACE
#include <cstdio>
#define QUIC_TRACE(...) (std::fprintf(stderr, "%lld ", static_cast<long long>(std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count() % 100000000)), std::fprintf(stderr, __VA_ARGS__))
#else
#define QUIC_TRACE(...) ((void)0)
#endif

namespace agensio::quic {

// What the configuration gives the transport (design-http3 section 10: everything
// derives from the existing keys).
struct Limits {
    std::uint64_t idle_timeout_ms = 15000;
    std::uint64_t max_data = 1 << 20;          // initial_max_data
    std::uint64_t stream_window = 16384;       // a request stream's first window (max_header_size)
    std::uint64_t uni_stream_window = 65536;   // the peer's control and QPACK streams
    std::uint64_t max_streams_bidi = 128;
    std::uint64_t max_streams_uni = 8;
    std::size_t max_datagram = 1200;   // until the path is probed
    std::size_t mtu_target_v4 = 1472;  // the probe sizes: a 1,500-byte link less the IPv4 or IPv6 and UDP headers
    std::size_t mtu_target_v6 = 1452;
    std::uint64_t max_ack_delay_ms = 25;
    std::uint64_t crypto_buffer = 16384;       // out-of-order CRYPTO data held per level
};

template <class App>
class QuicConnection : public Timed {
public:
    enum class State : std::uint8_t { handshaking, established, closing, draining, closed };

    QuicConnection(App& app, EndpointBase& ep, SSL_CTX* ctx, const PacketHeader& initial, const AcceptInfo& info,
                   const sockaddr_storage& peer, socklen_t peer_len, const Limits& limits, TimePoint now)
        : app_(app), ep_(ep), limits_(limits), peer_(peer), peer_len_(peer_len), created_(now), last_receive_(now) {
        odcid_ = info.odcid;
        address_validated_ = info.validated;
        peer_cid_ = initial.scid;
        peer_cids_.push_back({0, initial.scid, false, {}});
        Cid ours;
        ours.len = kOurCidLen;
        ours.bytes[0] = ep.worker;
        random_bytes(ours.bytes + 1, kOurCidLen - 1);
        initial_scid_ = ours;
        our_cids_.push_back({0, ours});
        registered_.push_back(ours);
        registered_.push_back(initial.dcid);  // the id the client addresses until the handshake completes (after a Retry: the one our Retry chose)
        unsigned char client_secret[32], server_secret[32];
        ok_ = initial_secrets(initial.dcid, client_secret, server_secret) && rx_[0].install(Suite::aes128gcm, client_secret, 32, false) &&
              tx_[0].install(Suite::aes128gcm, server_secret, 32, true);
        ++ep_.half_open;
        half_open_counted_ = true;
        rec_.max_datagram = limits.max_datagram;
        rec_.reset_cwnd();
        idle_ = std::chrono::milliseconds(limits.idle_timeout_ms);
        our_max_data_ = limits.max_data;
        our_max_streams_bidi_ = limits.max_streams_bidi;
        our_max_streams_uni_ = limits.max_streams_uni;
        TransportParams ours_tp;
        ours_tp.original_dcid = odcid_;
        ours_tp.has_original_dcid = true;
        ours_tp.max_idle_timeout = limits.idle_timeout_ms;
        reset_token(ours, ours_tp.stateless_reset_token);  // any worker can compute it after we are gone (10.3)
        ours_tp.has_reset_token = true;
        ours_tp.max_udp_payload_size = 65527;
        ours_tp.initial_max_data = limits.max_data;
        ours_tp.initial_max_stream_data_bidi_local = limits.stream_window;
        ours_tp.initial_max_stream_data_bidi_remote = limits.stream_window;
        ours_tp.initial_max_stream_data_uni = limits.uni_stream_window;
        ours_tp.initial_max_streams_bidi = limits.max_streams_bidi;
        ours_tp.initial_max_streams_uni = limits.max_streams_uni;
        ours_tp.max_ack_delay = limits.max_ack_delay_ms;
        ours_tp.disable_active_migration = true;
        ours_tp.active_connection_id_limit = 4;
        ours_tp.initial_scid = ours;
        ours_tp.has_initial_scid = true;
        initial_dcid_ = initial.dcid;
        if (info.retried) {
            ours_tp.retry_scid = initial.dcid;
            ours_tp.has_retry_scid = true;
        }
        if (ok_) ok_ = tls_.init(ctx, encode_transport_params(ours_tp));
        advertised_bidi_ = limits.max_streams_bidi;
        advertised_uni_ = limits.max_streams_uni;
        our_max_ack_delay_ = std::chrono::milliseconds(limits.max_ack_delay_ms);
        for (std::uint64_t& c : recent_closed_) c = ~std::uint64_t{0};
    }
    QuicConnection(const QuicConnection&) = delete;
    QuicConnection& operator=(const QuicConnection&) = delete;
    ~QuicConnection() { leave_handshake(); }

    App* owner() noexcept { return &app_; }
    bool ok() const noexcept { return ok_; }
    bool closed() const noexcept { return state_ == State::closed; }
    bool established() const noexcept { return state_ == State::established; }
    State state() const noexcept { return state_; }
    bool touched = false;  // in the endpoint's list for this wake-up

    // The ids the endpoint's table maps to this connection (ours, and the client's
    // original destination id until the handshake completes).
    const std::vector<Cid>& our_cids() const noexcept { return registered_; }
    bool owns(const Cid& cid) const noexcept {
        for (const Cid& c : registered_)
            if (c == cid) return true;
        return false;
    }
    const sockaddr_storage& peer() const noexcept { return peer_; }
    socklen_t peer_len() const noexcept { return peer_len_; }
    TlsSession& tls() noexcept { return tls_; }
    std::string_view alpn() const noexcept { return tls_.alpn(); }
    void unschedule() { ep_.unschedule(this); }

    // ---- application interface ----

    // A server-initiated unidirectional stream (the control and QPACK streams).
    bool open_uni_stream(QuicStream& s) noexcept {
        const std::uint64_t index = next_uni_index_;
        if (index >= peer_max_streams_uni_) return false;
        ++next_uni_index_;
        s.id = index * 4 + 3;
        s.open = true;
        s.max_send = peer_tp_.initial_max_stream_data_uni;
        return true;
    }
    // Data to send (head, body, fin filled in).
    void stream_ready(QuicStream& s) noexcept { enqueue(s); }
    // The application consumed n received bytes: credit goes back.
    void stream_consumed(QuicStream& s, std::size_t n) noexcept {
        s.consume(n);
        data_consumed_ += n;
        if (data_consumed_ + limits_.max_data - our_max_data_ >= limits_.max_data / 4) {
            our_max_data_ = data_consumed_ + limits_.max_data;
            max_data_due_ = true;
        }
        if (!s.fin_seen && s.consumed() + s.window - s.max_recv >= s.window / 4) grant(s, s.consumed() + s.window);
    }
    // A bigger window for a stream (a request body): granted at once.
    void stream_window(QuicStream& s, std::uint64_t window) noexcept {
        s.window = window;
        if (s.consumed() + window > s.max_recv) grant(s, s.consumed() + window);
    }
    void stream_reset(QuicStream& s, std::uint64_t code) noexcept {
        if (s.reset_sent || s.reset_due) return;
        s.reset_due = true;
        s.reset_send_code = code;
        s.ready = false;
        control_.push_back(&s);
    }
    void stream_stop_sending(QuicStream& s, std::uint64_t code) noexcept {
        if (s.stop_due) return;
        s.stop_due = true;
        s.stop_send_code = code;
        control_.push_back(&s);
    }
    // The application is done with the stream (both directions finished or reset): the
    // peer may open another in its place.
    void stream_closed(QuicStream& s) noexcept {
        dequeue(s);
        for (std::size_t i = 0; i < control_.size();)
            if (control_[i] == &s) control_.erase(control_.begin() + static_cast<std::ptrdiff_t>(i)); else ++i;
        for (std::size_t i = 0; i < credit_.size();)
            if (credit_[i] == &s) credit_.erase(credit_.begin() + static_cast<std::ptrdiff_t>(i)); else ++i;
        if (stream_is_client(s.id)) {
            recent_closed_[recent_pos_++ % kRecentClosed] = s.id;
            // The credit goes back with the next packet sent anyway (a client with one
            // request at a time otherwise gets a MAX_STREAMS datagram per request, and
            // acknowledges it); it is sent on its own only when the peer's room is under a
            // quarter of the limit.
            if (stream_is_bidi(s.id)) {
                ++closed_bidi_;
                our_max_streams_bidi_ = closed_bidi_ + limits_.max_streams_bidi;
                if (advertised_bidi_ - std::min(advertised_bidi_, opened_bidi_) < limits_.max_streams_bidi / 4) max_streams_due_ = true;
            } else {
                ++closed_uni_;
                our_max_streams_uni_ = closed_uni_ + limits_.max_streams_uni;
                if (advertised_uni_ - std::min(advertised_uni_, opened_uni_) < limits_.max_streams_uni / 4) max_streams_due_ = true;
            }
            max_streams_pending_ = true;
        }
        s.open = false;
    }
    // An application close: CONNECTION_CLOSE with the application's code.
    void close(bool app_error, std::uint64_t code, std::string_view reason, TimePoint now) noexcept {
        if (state_ == State::closing || state_ == State::draining || state_ == State::closed) return;
        QUIC_TRACE("quic: close app=%d code=%llu %.*s\n", app_error ? 1 : 0, static_cast<unsigned long long>(code),
                   static_cast<int>(reason.size()), reason.data());
        state_ = State::closing;
        leave_handshake();
        close_app_ = app_error;
        close_code_ = code;
        close_frame_type_ = 0;
        close_reason_.assign(reason.data(), std::min<std::size_t>(reason.size(), 64));
        close_due_ = true;
        closing_end_ = now + rec_.pto_duration(Space::application) * 3;
        app_.on_closed(false, code);
    }

    // ---- the endpoint's interface ----

    void receive(unsigned char* data, std::size_t len, const sockaddr_storage& from, socklen_t fromlen, TimePoint now) {
        if (state_ == State::closed || state_ == State::draining || !ok_) return;
        bool on_peer_path = fromlen == peer_len_ && std::memcmp(&from, &peer_, fromlen) == 0;
        if (!on_peer_path && state_ != State::established) return;  // the handshake stays on the path it began on
        if (on_peer_path) {
            bytes_received_ += len;
            last_receive_ = now;
        }
        if (state_ == State::closing) {
            if (++close_packets_ % 3 == 1) close_due_ = true;  // the close again, at a limited rate (RFC 9000 10.2.1)
            return;
        }
        std::size_t pos = 0;
        while (pos < len && state_ != State::closing) {
            PacketHeader h;
            if (!parse_header(data + pos, len - pos, kOurCidLen, h)) break;
            if (h.long_form) {
                if (h.version != kVersion1 || h.type == LongType::retry) break;
                if (h.type == LongType::zero_rtt) {  // not accepted: skipped (RFC 9001 4.6.1)
                    pos += h.total;
                    continue;
                }
                if (!h.fixed_bit) break;
            } else if (!h.fixed_bit) {
                break;
            }
            const Space space = h.long_form ? (h.type == LongType::initial ? Space::initial : Space::handshake) : Space::application;
            const unsigned si = static_cast<unsigned>(space);
            if (!rx_[si].valid()) {  // keys not yet there (or gone): the packet is dropped
                if (!h.long_form) break;
                pos += h.total;
                continue;
            }
            unsigned char* pkt = data + pos;
            const std::size_t total = h.long_form ? h.total : len - pos;
            if (h.pn_offset + 4 + kHpSampleLen > total) break;
            unsigned char mask[5];
            if (!rx_[si].mask(pkt + h.pn_offset + 4, mask)) break;  // header protection keys never change (RFC 9001 6.1)
            pkt[0] ^= static_cast<unsigned char>(mask[0] & (h.long_form ? 0x0f : 0x1f));
            const unsigned pn_len = (pkt[0] & 0x03) + 1;
            std::uint64_t truncated = 0;
            for (unsigned i = 0; i < pn_len; ++i) {
                pkt[h.pn_offset + i] ^= mask[1 + i];
                truncated = (truncated << 8) | pkt[h.pn_offset + i];
            }
            const AckState& acks = rec_.space(space).acks;
            const std::uint64_t pn = decode_pn(acks.largest, acks.any, truncated, pn_len * 8);
            const std::size_t hdr_len = h.pn_offset + pn_len;
            std::size_t plain = 0;
            // The keys of the packet's phase (RFC 9001 6.5): the current ones; the previous
            // for a packet reordered from before an update; the next for a peer's update.
            Keys* keys = &rx_[si];
            bool updating = false;
            if (!h.long_form && ((pkt[0] & 0x04) != 0) != rx_phase_) {
                if (rx_prev_.valid() && pn < phase_first_pn_) {
                    keys = &rx_prev_;
                } else {
                    if (!rx_next_.valid() && !derive_next_rx()) break;
                    keys = &rx_next_;
                    updating = true;
                }
            }
            if (!keys->open(pn, pkt, hdr_len, pkt + hdr_len, total - hdr_len, plain)) {
                QUIC_TRACE("quic: open failed space=%u pn=%llu\n", si, static_cast<unsigned long long>(pn));
                if (keys->failures > integrity_limit(keys->suite())) return fail(err::aead_limit_reached, 0, "AEAD integrity limit reached", now);
                if (h.long_form) { pos += h.total; continue; }
                break;
            }
            if (updating) {
                // The peer's update (or the peer following ours): a second one before we
                // acknowledged the first under the new keys is the error of RFC 9001 6.2.
                if (update_ack_pending_) return fail(err::key_update, 0, "key update before the previous one was acknowledged", now);
                rx_prev_ = std::move(rx_[2]);
                rx_[2] = std::move(rx_next_);
                rx_phase_ = !rx_phase_;
                phase_first_pn_ = pn;
                prev_keys_end_ = now + rec_.pto_duration(Space::application) * 3;
                if (key_phase_ != rx_phase_) {  // our send keys follow before any acknowledgement (6.2)
                    if (!next_tx(now)) return fail(err::internal, 0, "key derivation failed", now);
                    update_ack_pending_ = true;
                }
                QUIC_TRACE("quic: key update: phase %d\n", rx_phase_ ? 1 : 0);
            }
            if (pkt[0] & (h.long_form ? 0x0c : 0x18)) return fail(err::protocol_violation, 0, "reserved header bits", now);
            if (acks.received.contains_point(pn)) {  // a duplicate
                if (h.long_form) { pos += h.total; continue; }
                break;
            }
            QUIC_TRACE("quic: <- space=%u pn=%llu len=%zu\n", si, static_cast<unsigned long long>(pn), plain);
            current_dcid_ = h.dcid;
            from_peer_path_ = on_peer_path;
            non_probing_ = false;
            const std::uint64_t prev_largest = acks.largest;
            const bool prev_any = acks.any;
            const bool eliciting = process_frames(space, pkt + hdr_len, plain, now);
            if (state_ == State::closing || state_ == State::draining) return;
            rec_.on_packet_received(space, pn, eliciting, now, our_max_ack_delay_);
            if (!on_peer_path) {
                last_receive_ = now;  // the peer, wherever it is now
                // A non-probing packet, the highest so far, from a new address: the peer
                // moved (a NAT rebinding, RFC 9000 9.3); its new path is validated.
                if (!h.long_form && non_probing_ && (!prev_any || pn > prev_largest)) {
                    migrate(from, fromlen, len);
                    on_peer_path = true;
                }
            }
            if (space == Space::handshake) {
                address_validated_ = true;
                if (rx_[0].valid()) discard_initial();
            }
            if (h.long_form) pos += h.total;
            else break;
        }
    }

    // The datagrams this connection has to send now, into the batch.
    void produce(SendBatch& batch, TimePoint now) {
        if (!ok_ || state_ == State::closed || state_ == State::draining) return;
        if (state_ == State::established) app_.before_produce();  // the application's own bookkeeping (QPACK's decoder stream)
        if (state_ == State::closing) {
            if (close_due_) {
                close_due_ = false;
                send_close(batch, now);
            }
            return;
        }
        if (mtu_probe_due_ && !mtu_probe_sent_ && tx_[2].valid() && address_validated_) {
            if (unsigned char* buf = batch.reserve(mtu_target_)) {
                want_ping_ = true;
                mtu_probe_sent_ = true;  // one packet of the target size, carrying a PING and the padding
                const std::size_t n = build_packet(Space::application, buf, mtu_target_, now, mtu_target_);
                want_ping_ = false;
                if (n) {
                    batch.commit(n, peer_, peer_len_);
                    bytes_sent_ += n;
                } else {
                    mtu_probe_sent_ = false;
                }
            }
        }
        for (unsigned d = 0; d < 128; ++d) {
            // An unvalidated path (the handshake, a client whose address changed) may be
            // sent three times what arrived on it (RFC 9000 8.1): the datagram shrinks to
            // what is left, so a PATH_CHALLENGE still goes out after a small packet.
            std::size_t cap = max_datagram_;
            if (!address_validated_) {
                const std::uint64_t left = 3 * bytes_received_ > bytes_sent_ ? 3 * bytes_received_ - bytes_sent_ : 0;
                if (left < 64) break;
                cap = static_cast<std::size_t>(std::min<std::uint64_t>(cap, left));
            }
            unsigned char* buf = batch.reserve(cap);
            if (!buf) {  // the wake-up's batch is full: it goes out now and this connection continues
                ep_.flush();
                buf = batch.reserve(cap);
                if (!buf) break;
            }
            bool wants[kSpaces];
            unsigned last = kSpaces;
            for (unsigned i = 0; i < kSpaces; ++i) {
                wants[i] = tx_[i].valid() && !rec_.spaces[i].discarded && wants_to_send(static_cast<Space>(i), now);
                if (wants[i]) last = i;
            }
            if (last == kSpaces) break;
            if (wants[0] && cap < kMinInitialDatagram) break;  // an Initial's datagram is 1,200 bytes or nothing (RFC 9000 14.1)
            std::size_t used = 0;
            bool initial = false;
            // A datagram with a PATH_CHALLENGE or PATH_RESPONSE is expanded to 1,200 bytes
            // (RFC 9000 8.2.1), unless the amplification limit of an unvalidated path forbids.
            const bool path_frames = (path_challenge_due_ || path_responses_ > 0) &&
                                     (address_validated_ || bytes_sent_ + kMinInitialDatagram <= 3 * bytes_received_);
            for (unsigned i = 0; i < kSpaces; ++i) {
                if (!wants[i]) continue;
                std::size_t pad_to = (initial || i == 0) && i == last ? kMinInitialDatagram : 0;
                if (i == 2 && path_frames && pad_to < kMinInitialDatagram) pad_to = std::min(kMinInitialDatagram, cap);
                const std::size_t n = build_packet(static_cast<Space>(i), buf + used, cap - used, now, pad_to > used ? pad_to - used : 0);
                if (n == 0) continue;
                if (i == 0) initial = true;
                used += n;
            }
            if (used == 0) break;
            batch.commit(used, peer_, peer_len_);
            bytes_sent_ += used;
        }
    }

    // The deadline heap fired.
    void on_timer(TimePoint now) {
        if (state_ == State::closing || state_ == State::draining) {
            if (now + std::chrono::microseconds(500) >= closing_end_) finish();
            return;
        }
        if (state_ == State::closed) return;
        if (now + std::chrono::microseconds(500) >= last_receive_ + idle_) {
            QUIC_TRACE("quic: idle timeout\n");
            state_ = State::closed;
            leave_handshake();
            app_.on_closed(false, 0);
            return;
        }
        if (rx_prev_.valid() && now + std::chrono::microseconds(500) >= prev_keys_end_) rx_prev_.clear();  // RFC 9001 6.5
        const TimePoint lt = rec_.loss_timer(at_amplification_limit());
        if (lt != TimePoint::max() && now + std::chrono::microseconds(500) >= lt) {
            rec_.on_timeout(now);
            QUIC_TRACE("quic: loss timer: probes=%u,%u,%u pto_count=%u in_flight=%llu cwnd=%llu\n", rec_.probes[0], rec_.probes[1], rec_.probes[2],
                       rec_.pto_count, static_cast<unsigned long long>(rec_.bytes_in_flight), static_cast<unsigned long long>(rec_.cwnd));
            apply_lost();
        }
    }

    // The next deadline, to the endpoint's heap.
    void reschedule(TimePoint now) {
        TimePoint d = TimePoint::max();
        if (state_ == State::closed) {
            ep_.unschedule(this);
            return;
        }
        if (state_ == State::closing || state_ == State::draining) {
            d = closing_end_;
        } else {
            d = last_receive_ + idle_;
            const TimePoint lt = rec_.loss_timer(at_amplification_limit());
            if (lt < d) d = lt;
            if (rx_prev_.valid() && prev_keys_end_ < d) d = prev_keys_end_;
            const AckState& a = rec_.space(Space::application).acks;
            if (a.eliciting_unacked > 0 && !a.ack_now && a.delay_deadline != TimePoint{} && a.delay_deadline < d) d = a.delay_deadline;
            if (d < now) d = now;
        }
        ep_.schedule(this, d);
    }

    // Counters for the status page.
    std::uint64_t packets_in = 0, packets_out = 0;

private:
    using Level = TlsSession::Level;

    // ---- frames in ----

    bool process_frames(Space space, const unsigned char* p, std::size_t n, TimePoint now) {
        const unsigned char* end = p + n;
        bool eliciting = false;
        Frame f;
        while (p < end) {
            if (!read_frame(p, end, f)) {
                fail(err::frame_encoding, f.type, "malformed frame", now);
                return eliciting;
            }
            if (!frame_allowed(f.type, space)) {
                fail(err::protocol_violation, f.type, "frame not allowed in this space", now);
                return eliciting;
            }
            eliciting = eliciting || ack_eliciting(f.type);
            if (!probing_frame(f.type)) non_probing_ = true;
            handle_frame(space, f, now);
            if (state_ == State::closing || state_ == State::draining) return eliciting;
        }
        return eliciting;
    }

    void handle_frame(Space space, const Frame& f, TimePoint now) {
        switch (f.type) {
            case frame::padding:
            case frame::ping:
                return;
            case frame::ack:
            case frame::ack_ecn:
                if (!rec_.on_ack_received(space, f, now)) return fail(err::protocol_violation, f.type, "ACK of a packet never sent", now);
                apply_acked();
                apply_lost();
                return;
            case frame::crypto:
                on_crypto(space, f.offset, f.data, static_cast<std::size_t>(f.length), now);
                return;
            case frame::new_token:
            case frame::handshake_done:
                return fail(err::protocol_violation, f.type, "client sent a server-only frame", now);
            case frame::reset_stream: {
                if (!count_reset(now)) return;
                QuicStream* s = incoming_stream(f.stream_id, now);
                if (!s) return;
                if (s->fin_seen && s->final_size != f.value2) return fail(err::final_size, f.type, "final size changed", now);
                if (f.value2 < s->highest) return fail(err::final_size, f.type, "final size below data received", now);
                if (!s->fin_seen) {
                    if (f.value2 > s->max_recv) return fail(err::flow_control, f.type, "final size beyond the window", now);
                    data_received_ += f.value2 - s->highest;
                    s->highest = f.value2;
                    s->fin_seen = true;
                    s->final_size = f.value2;
                }
                if (s->reset_received) return;
                s->reset_received = true;
                s->reset_code = f.value;
                app_.on_stream_reset(*s, f.value);
                return;
            }
            case frame::stop_sending: {
                if (stream_is_client(f.stream_id) && !stream_is_bidi(f.stream_id))
                    return fail(err::stream_state, f.type, "STOP_SENDING on a receive-only stream", now);
                if (!count_reset(now)) return;
                QuicStream* s = stream_is_client(f.stream_id) ? incoming_stream(f.stream_id, now) : app_.find_stream(f.stream_id);
                if (!s) return;
                if (s->stop_sending_received) return;
                s->stop_sending_received = true;
                s->stop_code = f.value;
                app_.on_stop_sending(*s, f.value);
                return;
            }
            case frame::max_data:
                if (f.value > peer_max_data_) {
                    peer_max_data_ = f.value;
                    wake_blocked();
                } else {
                    glitch(now);
                }
                return;
            case frame::max_stream_data: {
                if (stream_is_client(f.stream_id) && !stream_is_bidi(f.stream_id))
                    return fail(err::stream_state, f.type, "MAX_STREAM_DATA on a receive-only stream", now);
                QuicStream* s = stream_is_client(f.stream_id) ? incoming_stream(f.stream_id, now) : app_.find_stream(f.stream_id);
                if (!s) return;
                if (f.value > s->max_send) {
                    s->max_send = f.value;
                    s->blocked_reported = false;
                    if (s->has_unsent()) enqueue(*s);
                } else {
                    glitch(now);
                }
                return;
            }
            case frame::max_streams_bidi:
                if (f.value > (std::uint64_t{1} << 60)) return fail(err::frame_encoding, f.type, "MAX_STREAMS too large", now);
                if (f.value > peer_max_streams_bidi_) peer_max_streams_bidi_ = f.value; else glitch(now);
                return;
            case frame::max_streams_uni:
                if (f.value > (std::uint64_t{1} << 60)) return fail(err::frame_encoding, f.type, "MAX_STREAMS too large", now);
                if (f.value > peer_max_streams_uni_) peer_max_streams_uni_ = f.value; else glitch(now);
                return;
            case frame::data_blocked:
            case frame::stream_data_blocked:
            case frame::streams_blocked_bidi:
            case frame::streams_blocked_uni:
                return;
            case frame::path_response:
                if (path_validating_ && from_peer_path_ && std::memcmp(f.token, path_challenge_, 8) == 0) {
                    QUIC_TRACE("quic: path validated\n");
                    path_validating_ = false;
                    address_validated_ = true;
                }
                return;
            case frame::new_connection_id: {
                // The peer's ids (RFC 9000 5.1.1, 19.15): at most four active, the
                // handshake's counted; the retirements a Retire Prior To demands are queued
                // as frames of ours; a sequence that changes content is an error.
                if (peer_cid_.len == 0) return fail(err::protocol_violation, f.type, "NEW_CONNECTION_ID from a zero-length id", now);
                for (const PeerCid& c : peer_cids_) {
                    if (c.seq == f.value) {
                        if (c.cid == f.cid && (!c.has_token || std::memcmp(c.token, f.token, 16) == 0)) return;  // a retransmission
                        return fail(err::protocol_violation, f.type, "NEW_CONNECTION_ID changes a sequence number", now);
                    }
                    if (c.cid == f.cid) return fail(err::protocol_violation, f.type, "NEW_CONNECTION_ID repeats an id", now);
                }
                if (f.value < peer_retired_below_) {  // demanded retired already: retired at once, never active
                    queue_retire(f.value);
                    return;
                }
                if (f.value2 > peer_retired_below_) {
                    peer_retired_below_ = f.value2;
                    for (std::size_t i = 0; i < peer_cids_.size();) {
                        if (peer_cids_[i].seq < peer_retired_below_) {
                            queue_retire(peer_cids_[i].seq);
                            peer_cids_.erase(peer_cids_.begin() + static_cast<std::ptrdiff_t>(i));
                        } else {
                            ++i;
                        }
                    }
                }
                if (peer_cids_.size() >= kMaxActiveCids) return fail(err::connection_id_limit, f.type, "too many connection ids", now);
                PeerCid c;
                c.seq = f.value;
                c.cid = f.cid;
                c.has_token = true;
                std::memcpy(c.token, f.token, 16);
                peer_cids_.push_back(c);
                if (peer_cid_seq_ < peer_retired_below_) {  // the one we address was retired: the lowest remaining
                    const PeerCid* best = nullptr;
                    for (const PeerCid& pc : peer_cids_)
                        if (!best || pc.seq < best->seq) best = &pc;
                    peer_cid_ = best->cid;
                    peer_cid_seq_ = best->seq;
                }
                return;
            }
            case frame::retire_connection_id: {
                // Our ids (19.16): a sequence never issued or the id this packet came to is
                // an error; a retired id leaves the table and a replacement is issued.
                if (f.value >= our_cid_seq_next_) return fail(err::protocol_violation, f.type, "retiring an id never issued", now);
                for (std::size_t i = 0; i < our_cids_.size(); ++i) {
                    if (our_cids_[i].seq != f.value) continue;
                    if (our_cids_[i].cid == current_dcid_) return fail(err::protocol_violation, f.type, "retiring the id the packet was sent to", now);
                    const Cid gone = our_cids_[i].cid;
                    our_cids_.erase(our_cids_.begin() + static_cast<std::ptrdiff_t>(i));
                    unregister(gone);
                    QUIC_TRACE("quic: id retired seq=%llu, %zu active\n", static_cast<unsigned long long>(f.value), our_cids_.size());
                    issue_cids();
                    return;
                }
                return;  // retired already: a retransmission
            }
            case frame::path_challenge:
                if (path_responses_ < 4) {
                    std::memcpy(path_response_[path_responses_++], f.token, 8);
                }
                return;
            case frame::connection_close:
            case frame::connection_close_app:
                QUIC_TRACE("quic: peer close code=%llu %.*s\n", static_cast<unsigned long long>(f.value), static_cast<int>(f.reason.size()), f.reason.data());
                state_ = State::draining;
                closing_end_ = now + rec_.pto_duration(Space::application) * 3;
                app_.on_closed(true, f.value);
                return;
            default:
                if (f.type >= frame::stream && f.type <= frame::stream_max) return on_stream_frame(f, now);
                return fail(err::frame_encoding, f.type, "unknown frame", now);
        }
    }

    // A client-initiated stream by id: existing, new (opened through the application, its
    // limits set), or nullptr when it is closed already or the frame is an error.
    QuicStream* incoming_stream(std::uint64_t id, TimePoint now) {
        if (!stream_is_client(id)) {
            fail(err::stream_state, 0, "frame for a server-initiated stream", now);
            return nullptr;
        }
        const bool bidi = stream_is_bidi(id);
        const std::uint64_t index = id >> 2;
        if (index >= (bidi ? advertised_bidi_ : advertised_uni_)) {
            fail(err::stream_limit, 0, "stream beyond MAX_STREAMS", now);
            return nullptr;
        }
        if (QuicStream* s = app_.find_stream(id)) return s;
        if (recently_closed(id)) return nullptr;  // a late frame for a stream that is done
        // Streams open in id order on the client's side but not in arrival order here:
        // a lower id after a higher one is a new stream, never a closed one (the record of
        // closed ids says which those are).
        std::uint64_t& opened = bidi ? opened_bidi_ : opened_uni_;
        QuicStream* s = app_.on_new_stream(id);
        if (!s) {
            fail(err::internal, 0, "no stream", now);
            return nullptr;
        }
        if (index + 1 > opened) opened = index + 1;
        s->id = id;
        s->open = true;
        s->window = bidi ? limits_.stream_window : limits_.uni_stream_window;
        s->max_recv = s->window;
        s->max_send = bidi ? peer_tp_.initial_max_stream_data_bidi_local : 0;
        return s;
    }

    void on_stream_frame(const Frame& f, TimePoint now) {
        QuicStream* s = incoming_stream(f.stream_id, now);
        if (!s) return;
        const std::uint64_t end = f.offset + f.length;
        if (end > s->max_recv) return fail(err::flow_control, f.type, "stream data beyond the window", now);
        if (s->fin_seen) {
            if (end > s->final_size || (f.fin && end != s->final_size)) return fail(err::final_size, f.type, "data beyond the final size", now);
        } else if (f.fin) {
            if (end < s->highest) return fail(err::final_size, f.type, "final size below data received", now);
            s->fin_seen = true;
            s->final_size = end;
        }
        if (end > s->highest) {
            data_received_ += end - s->highest;
            if (data_received_ > our_max_data_) return fail(err::flow_control, f.type, "connection data beyond the window", now);
            s->highest = end;
        }
        if (s->reset_received) return;
        if (f.length) {
            std::uint64_t from = f.offset;
            const unsigned char* src = f.data;
            std::size_t len = static_cast<std::size_t>(f.length);
            const std::uint64_t consumed = s->consumed();
            if (end > consumed) {
                if (from < consumed) {  // partly consumed already: the rest
                    src += consumed - from;
                    len -= static_cast<std::size_t>(consumed - from);
                    from = consumed;
                }
                const std::size_t rel = static_cast<std::size_t>(from - s->roff);
                if (s->rbuf.size() < rel + len) s->rbuf.resize(rel + len);
                std::memcpy(s->rbuf.data() + rel, src, len);
                s->rranges.add(from, from + len);
            }
        }
        if (s->available() > 0 || (s->at_end() && !s->fin_delivered)) app_.on_stream_readable(*s);
    }

    void on_crypto(Space space, std::uint64_t offset, const unsigned char* data, std::size_t len, TimePoint now) {
        CryptoIn& ci = crypto_in_[static_cast<unsigned>(space)];
        const std::uint64_t end = offset + len;
        if (end <= ci.delivered) return;  // a retransmission of what we have
        if (end > ci.delivered + limits_.crypto_buffer) return fail(err::crypto_buffer_exceeded, frame::crypto, "CRYPTO data too far ahead", now);
        if (offset < ci.delivered) {
            data += ci.delivered - offset;
            len -= static_cast<std::size_t>(ci.delivered - offset);
            offset = ci.delivered;
        }
        const Level level = space == Space::initial ? TlsSession::initial : space == Space::handshake ? TlsSession::handshake : TlsSession::application;
        if (offset == ci.delivered && ci.ranges.empty()) {
            tls_.received(level, data, len);
            ci.delivered = end;
        } else {
            const std::size_t rel = static_cast<std::size_t>(offset - ci.delivered);
            if (ci.buf.size() < rel + len) ci.buf.resize(rel + len);
            std::memcpy(ci.buf.data() + rel, data, len);
            ci.ranges.add(offset, end);
            const std::uint64_t avail = ci.ranges.contiguous_from(ci.delivered);
            if (avail > ci.delivered) {
                const std::size_t n = static_cast<std::size_t>(avail - ci.delivered);
                tls_.received(level, reinterpret_cast<const unsigned char*>(ci.buf.data()), n);
                ci.buf.erase(0, n);
                ci.ranges.remove_below(avail);
                ci.delivered = avail;
            }
        }
        advance_tls(now);
    }

    void advance_tls(TimePoint now) {
        const int r = tls_.advance();
        for (const TlsSession::Secret& s : tls_.secrets()) {
            const unsigned si = s.level == TlsSession::handshake ? 1 : s.level == TlsSession::application ? 2 : kSpaces;
            if (si == kSpaces) continue;  // early data: not accepted
            Keys& k = s.write ? tx_[si] : rx_[si];
            if (!k.install(s.suite, s.bytes, s.len, s.write)) return fail(err::internal, 0, "key derivation failed", now);
            QUIC_TRACE("quic: keys level=%u write=%d\n", si, s.write ? 1 : 0);
        }
        tls_.secrets().clear();
        if (tls_.have_peer_params() && !peer_params_ok_) {
            if (!decode_transport_params(reinterpret_cast<const unsigned char*>(tls_.peer_params().data()), tls_.peer_params().size(), peer_tp_))
                return fail(err::transport_parameter, 0, "invalid transport parameters", now);
            if (!peer_tp_.has_initial_scid || peer_tp_.initial_scid != peer_cid_)
                return fail(err::transport_parameter, 0, "initial_source_connection_id does not match", now);
            peer_params_ok_ = true;
            peer_max_data_ = peer_tp_.initial_max_data;
            peer_max_streams_bidi_ = peer_tp_.initial_max_streams_bidi;
            peer_max_streams_uni_ = peer_tp_.initial_max_streams_uni;
            rec_.max_ack_delay = std::chrono::milliseconds(peer_tp_.max_ack_delay);
            rec_.ack_delay_exponent = static_cast<unsigned>(peer_tp_.ack_delay_exponent);
            if (peer_tp_.max_idle_timeout) idle_ = std::min(idle_, Duration(std::chrono::milliseconds(peer_tp_.max_idle_timeout)));
            max_datagram_ = static_cast<std::size_t>(std::min<std::uint64_t>(limits_.max_datagram, peer_tp_.max_udp_payload_size));
            rec_.max_datagram = max_datagram_;
        }
        if (r < 0 || tls_.has_alert()) return fail(err::crypto_base + tls_.alert(), 0, "TLS alert", now);
        if (r == 1 && state_ == State::handshaking) on_handshake_complete(now);
    }

    void on_handshake_complete(TimePoint now) {
        (void)now;
        QUIC_TRACE("quic: handshake complete alpn=%.*s\n", static_cast<int>(tls_.alpn().size()), tls_.alpn().data());
        state_ = State::established;
        leave_handshake();
        rec_.handshake_confirmed = true;
        handshake_done_due_ = true;
        {
            const std::size_t target = peer_.ss_family == AF_INET6 ? limits_.mtu_target_v6 : limits_.mtu_target_v4;
            const std::size_t cap = static_cast<std::size_t>(std::min<std::uint64_t>(peer_tp_.max_udp_payload_size, 65527));
            mtu_target_ = std::min(target, cap);
            mtu_probe_due_ = mtu_target_ > max_datagram_;
        }
        if (rx_[1].valid()) {  // RFC 9001 4.9.2: Handshake keys go once the handshake is confirmed
            rec_.discard_space(Space::handshake);
            rx_[1].clear();
            tx_[1].clear();
        }
        // The id the client addressed during the handshake is done with: only our ids
        // route here now, and the peer gets as many as it holds (6.4).
        unregister(initial_dcid_);
        issue_cids();
        app_.on_handshake_done();
    }

    // ---- connection ids (design 6.4) ----

    static constexpr std::size_t kMaxActiveCids = 4;   // ours to the peer and the peer's to us
    static constexpr std::uint64_t kMaxCidsIssued = 64;  // per connection, replacements included

    void issue_cids() {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(peer_tp_.active_connection_id_limit, kMaxActiveCids));
        while (our_cids_.size() < want && our_cid_seq_next_ < kMaxCidsIssued) {
            OurCid c;
            c.seq = our_cid_seq_next_;
            c.cid.len = kOurCidLen;
            c.cid.bytes[0] = ep_.worker;
            random_bytes(c.cid.bytes + 1, kOurCidLen - 1);
            if (registered_.empty() || !ep_.map(registered_.front(), c.cid)) return;
            ++our_cid_seq_next_;
            our_cids_.push_back(c);
            registered_.push_back(c.cid);
            new_cid_due_.push_back(c.seq);
            QUIC_TRACE("quic: id issued seq=%llu\n", static_cast<unsigned long long>(c.seq));
        }
    }
    void unregister(const Cid& cid) {
        for (std::size_t i = 0; i < registered_.size(); ++i) {
            if (!(registered_[i] == cid)) continue;
            registered_.erase(registered_.begin() + static_cast<std::ptrdiff_t>(i));
            ep_.unmap(cid, &app_);
            return;
        }
    }
    void queue_retire(std::uint64_t seq) {
        for (std::uint64_t q : retire_due_)
            if (q == seq) return;
        retire_due_.push_back(seq);
    }

    // ---- key update (RFC 9001 6) ----

    bool derive_next_rx() { return rx_next_.install_next(rx_[2], false); }
    bool next_tx(TimePoint now) {
        Keys fresh;
        if (!fresh.install_next(tx_[2], true)) return false;
        tx_[2] = std::move(fresh);
        key_phase_ = !key_phase_;
        tx_phase_first_pn_ = rec_.spaces[2].next_pn;
        last_key_update_ = now;
        return true;
    }
    // Our own update, at the key's confidentiality limit: once the peer acknowledged a
    // packet of the current phase and three PTOs passed since the last one (6.5).
    void maybe_update_keys(TimePoint now) {
        const PnSpace& ps = rec_.spaces[2];
        if (tx_[2].sealed + 4096 < confidentiality_limit(tx_[2].suite()) || update_ack_pending_) return;
        if (!ps.any_acked || ps.largest_acked < tx_phase_first_pn_) {
            if (tx_[2].sealed >= confidentiality_limit(tx_[2].suite())) fail(err::aead_limit_reached, 0, "AEAD confidentiality limit reached", now);
            return;
        }
        if (now < last_key_update_ + rec_.pto_duration(Space::application) * 3) return;
        if (!next_tx(now)) return;
        derive_next_rx();
        QUIC_TRACE("quic: key update initiated: phase %d\n", key_phase_ ? 1 : 0);
    }

    // ---- the peer's address (RFC 9000 9) ----

    void migrate(const sockaddr_storage& from, socklen_t fromlen, std::size_t received) {
        QUIC_TRACE("quic: peer address changed: validating the new path\n");
        const bool port_only = same_address(peer_, from);
        prev_peer_ = peer_;
        prev_peer_len_ = peer_len_;
        prev_validated_ = address_validated_;
        peer_ = from;
        peer_len_ = fromlen;
        address_validated_ = false;  // three times the bytes received on the new path until it answers
        bytes_received_ = received;
        bytes_sent_ = 0;
        max_datagram_ = kMinInitialDatagram;  // the new path's size is unknown: probed again
        rec_.max_datagram = max_datagram_;
        mtu_probe_due_ = mtu_target_ > max_datagram_;
        mtu_probe_sent_ = false;
        ++path_gen_;
        if (!port_only) {  // a port change alone is a NAT rebinding: the estimates stay (9.4)
            rec_.reset_rtt();
            rec_.reset_cwnd();
        }
        random_bytes(path_challenge_, 8);
        path_challenge_due_ = true;
        path_validating_ = true;
        path_tries_ = 0;
    }
    void revert_path() {
        QUIC_TRACE("quic: path validation failed: back to the previous address\n");
        peer_ = prev_peer_;
        peer_len_ = prev_peer_len_;
        address_validated_ = prev_validated_;
        path_validating_ = false;
        path_challenge_due_ = false;
    }

    // ---- budgets (design 9.1) ----

    static constexpr unsigned kGlitchBudget = 100;
    void glitch(TimePoint now) {
        if (++glitches_ >= kGlitchBudget) fail(err::protocol_violation, 0, "too many protocol glitches", now);
    }
    // RESET_STREAM and STOP_SENDING per second, the stream limit's worth: beyond is the
    // application's excessive-load close (Rapid Reset over QUIC).
    bool count_reset(TimePoint now) {
        const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        if (sec != reset_second_) {
            reset_second_ = sec;
            resets_in_second_ = 0;
        }
        if (++resets_in_second_ > limits_.max_streams_bidi) {
            close(true, App::kExcessiveLoad, "too many stream resets", now);
            return false;
        }
        return true;
    }
    void leave_handshake() {
        if (!half_open_counted_) return;
        half_open_counted_ = false;
        if (ep_.half_open) --ep_.half_open;
    }

    void discard_initial() {
        rec_.discard_space(Space::initial);
        rx_[0].clear();
        tx_[0].clear();
    }

    // ---- acknowledgements and losses ----

    void apply_acked() {
        for (const SentItem& it : rec_.acked) {
            switch (it.kind) {
                case ItemKind::stream: {
                    QuicStream* s = app_.find_stream(it.id);
                    if (!s || !s->open) break;
                    if (it.len) s->acked.add(it.offset, it.offset + it.len);
                    if (it.fin) s->fin_acked = true;
                    if (s->trim_head) {  // a control stream: what is acknowledged in order is dropped
                        const std::uint64_t upto = s->acked.contiguous_from(s->head_base);
                        if (upto > s->head_base + 16384 && upto <= s->head_end()) {
                            s->head.erase(0, static_cast<std::size_t>(upto - s->head_base));
                            s->head_base = upto;
                            s->acked.remove_below(upto);
                        }
                        break;
                    }
                    if (!s->send_done && s->fin_acked && (s->total == 0 || s->acked.contains(0, s->total))) {
                        s->send_done = true;
                        app_.on_stream_sent(*s);
                    }
                    break;
                }
                case ItemKind::crypto: {
                    CryptoOut& co = crypto_out_[it.id];
                    co.acked.add(it.offset, it.offset + it.len);
                    break;
                }
                case ItemKind::handshake_done:
                    handshake_done_acked_ = true;
                    break;
                case ItemKind::mtu_probe:
                    if (it.id != path_gen_) break;  // a probe of the path before the address changed
                    if (mtu_target_ > max_datagram_) {
                        QUIC_TRACE("quic: path MTU probe acknowledged: datagrams of %zu bytes\n", mtu_target_);
                        max_datagram_ = mtu_target_;
                        rec_.max_datagram = mtu_target_;
                    }
                    mtu_probe_due_ = false;
                    break;
                default: break;
            }
        }
        rec_.acked.clear();
        maybe_free_tls();
    }

    void apply_lost() {
        for (const SentItem& it : rec_.lost) {
            switch (it.kind) {
                case ItemKind::stream: {
                    QuicStream* s = app_.find_stream(it.id);
                    QUIC_TRACE("quic: lost stream=%llu off=%llu len=%u fin=%d found=%d\n", static_cast<unsigned long long>(it.id),
                               static_cast<unsigned long long>(it.offset), it.len, it.fin ? 1 : 0, s && s->open ? 1 : 0);
                    if (!s || !s->open || s->send_done || s->reset_sent) break;
                    if (it.len) s->lost.add(it.offset, it.offset + it.len);
                    if (it.fin) s->fin_sent = false;
                    if (s->has_unsent()) enqueue(*s);
                    break;
                }
                case ItemKind::crypto:
                    if (tx_[it.id].valid()) crypto_out_[it.id].lost.add(it.offset, it.offset + it.len);
                    break;
                case ItemKind::handshake_done: handshake_done_due_ = true; break;
                case ItemKind::mtu_probe:
                    if (it.id == path_gen_) mtu_probe_due_ = false;  // the path does not carry the target: 1,200 stays
                    break;
                case ItemKind::max_data: max_data_due_ = true; break;
                case ItemKind::max_streams_bidi:
                case ItemKind::max_streams_uni: max_streams_due_ = max_streams_pending_ = true; break;
                case ItemKind::max_stream_data: {
                    QuicStream* s = app_.find_stream(it.id);
                    if (s && s->open && !s->fin_seen) grant(*s, s->max_recv);
                    break;
                }
                case ItemKind::reset_stream: {
                    QuicStream* s = app_.find_stream(it.id);
                    if (s && s->open && !s->reset_due) { s->reset_due = true; control_.push_back(s); }
                    break;
                }
                case ItemKind::stop_sending: {
                    QuicStream* s = app_.find_stream(it.id);
                    if (s && s->open && !s->stop_due) { s->stop_due = true; control_.push_back(s); }
                    break;
                }
                case ItemKind::retire_cid: queue_retire(it.id); break;
                case ItemKind::new_cid: new_cid_due_.push_back(it.id); break;
                case ItemKind::path_challenge:
                    if (path_validating_) {
                        if (++path_tries_ < 3) path_challenge_due_ = true;
                        else revert_path();
                    }
                    break;
                default: break;
            }
        }
        rec_.lost.clear();
    }

    void maybe_free_tls() {
        if (!tls_.ssl() || !handshake_done_acked_) return;
        const CryptoOut& co = crypto_out_[2];
        const std::size_t out = tls_.out(TlsSession::application).size();
        if (out && !co.acked.contains(0, out)) return;
        tls_.free_ssl();
    }

    // ---- what to send ----

    bool at_amplification_limit() const noexcept { return !address_validated_ && bytes_sent_ >= 3 * bytes_received_; }

    bool ack_due(Space space, TimePoint now) const noexcept {
        const AckState& a = rec_.spaces[static_cast<unsigned>(space)].acks;
        if (a.eliciting_unacked == 0) return false;
        if (a.ack_now) return true;
        return a.delay_deadline != TimePoint{} && a.delay_deadline <= now;
    }

    // The TLS session's level for a space (its own numbering has EARLY in between).
    static Level tls_level(unsigned space) noexcept { return space == 0 ? TlsSession::initial : space == 1 ? TlsSession::handshake : TlsSession::application; }

    bool wants_to_send(Space space, TimePoint now) const noexcept {
        const unsigned si = static_cast<unsigned>(space);
        if (ack_due(space, now) || rec_.probes[si] > 0) return true;
        if (!crypto_out_[si].lost.empty() || crypto_out_[si].sent < tls_.out(tls_level(si)).size()) return true;
        if (space != Space::application) return false;
        if (handshake_done_due_ || max_data_due_ || max_streams_due_ || path_responses_ > 0 || path_challenge_due_ || !control_.empty() ||
            !credit_.empty() || !retire_due_.empty() || !new_cid_due_.empty())
            return true;
        return ready_head_ != nullptr && rec_.cwnd_room() >= max_datagram_;
    }

    // ---- the packetiser ----

    // One packet of the space into buf: the header, the frames due, sealed and protected.
    // `pad_to` asks for PADDING so that the packet ends at that many bytes (an Initial
    // datagram's 1,200). Returns the bytes written, 0 when nothing was due.
    std::size_t build_packet(Space space, unsigned char* buf, std::size_t cap, TimePoint now, std::size_t pad_to) {
        const unsigned si = static_cast<unsigned>(space);
        PnSpace& ps = rec_.spaces[si];
        const std::uint64_t pn = ps.next_pn;
        const unsigned pn_len = pn_length(pn, ps.largest_acked, ps.any_acked);
        std::size_t pos = 0;
        std::size_t len_pos = 0;
        if (space == Space::application) {
            if (cap < 1 + peer_cid_.len + pn_len + kAeadTagLen + 1) return 0;
            buf[pos++] = static_cast<unsigned char>(0x40 | (key_phase_ ? 0x04 : 0) | (pn_len - 1));
            std::memcpy(buf + pos, peer_cid_.bytes, peer_cid_.len);
            pos += peer_cid_.len;
        } else {
            const Cid& scid = initial_scid_;
            const std::size_t need = 1 + 4 + 1 + peer_cid_.len + 1 + scid.len + (space == Space::initial ? 1 : 0) + 2 + pn_len + kAeadTagLen + 1;
            if (cap < need) return 0;
            buf[pos++] = static_cast<unsigned char>(0xc0 | ((space == Space::initial ? 0 : 2) << 4) | (pn_len - 1));
            buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 1;
            buf[pos++] = peer_cid_.len;
            std::memcpy(buf + pos, peer_cid_.bytes, peer_cid_.len);
            pos += peer_cid_.len;
            buf[pos++] = scid.len;
            std::memcpy(buf + pos, scid.bytes, scid.len);
            pos += scid.len;
            if (space == Space::initial) buf[pos++] = 0;  // token length
            len_pos = pos;
            pos += 2;  // the Length, written last
        }
        const std::size_t pn_offset = pos;
        write_pn(buf + pos, pn, pn_len);
        pos += pn_len;
        unsigned char* payload = buf + pos;
        if (cap < pos + kAeadTagLen) return 0;
        const std::size_t room = cap - pos - kAeadTagLen;
        SentPacket& rec = ps.record(pn);
        std::size_t w = 0;
        bool eliciting = false, in_flight = false, ack_written = false;

        // ACK: due, or pending and riding on a packet sent for other reasons (RFC 9000
        // 13.2.1 lets a receiver acknowledge sooner than the delay; the response to a
        // single request then carries the acknowledgement of the request, so the client
        // closes its stream at once and no ACK-only packet follows 25 ms later).
        if (ps.acks.eliciting_unacked > 0) {
            const AckState& a = ps.acks;
            const auto delay = std::chrono::duration_cast<std::chrono::microseconds>(now - a.largest_time).count();
            const std::size_t n = put_ack(payload + w, room - w, a.received, delay > 0 ? static_cast<std::uint64_t>(delay) >> 3 : 0);
            if (n) { w += n; ack_written = true; }
        }
        // CRYPTO
        {
            CryptoOut& co = crypto_out_[si];
            const std::string& data = tls_.out(tls_level(si));
            for (int guard = 0; guard < 8; ++guard) {
                std::uint64_t b = 0, e = 0;
                if (!co.lost.empty()) {
                    b = co.lost.ranges().front().first;
                    e = co.lost.ranges().front().second;
                } else if (co.sent < data.size()) {
                    b = co.sent;
                    e = data.size();
                } else {
                    break;
                }
                const std::size_t hdr = 1 + varint_size(b) + varint_size(e - b);
                if (room - w <= hdr + 1) break;
                const std::size_t take = std::min<std::size_t>(static_cast<std::size_t>(e - b), room - w - hdr);
                const std::size_t h = put_crypto_header(payload + w, room - w, b, take);
                std::memcpy(payload + w + h, data.data() + b, take);
                w += h + take;
                rec.items.push_back({ItemKind::crypto, false, si, b, static_cast<std::uint32_t>(take)});
                eliciting = in_flight = true;
                if (!co.lost.empty()) co.lost.remove(b, b + take);
                else co.sent = b + take;
            }
        }
        if (space == Space::application) {
            if (handshake_done_due_) {
                const std::size_t n = put_handshake_done(payload + w, room - w);
                if (n) { w += n; handshake_done_due_ = false; eliciting = in_flight = true; rec.items.push_back({ItemKind::handshake_done, false, 0, 0, 0}); }
            }
            if (max_data_due_) {
                const std::size_t n = put_max_data(payload + w, room - w, our_max_data_);
                if (n) { w += n; max_data_due_ = false; eliciting = in_flight = true; rec.items.push_back({ItemKind::max_data, false, 0, 0, 0}); }
            }
            while (path_responses_ > 0) {
                const std::size_t n = put_path_response(payload + w, room - w, path_response_[path_responses_ - 1]);
                if (!n) break;
                w += n;
                --path_responses_;
                eliciting = in_flight = true;
                rec.items.push_back({ItemKind::path_response, false, 0, 0, 0});
            }
            while (!retire_due_.empty()) {
                const std::size_t n = put_retire_connection_id(payload + w, room - w, retire_due_.back());
                if (!n) break;
                w += n;
                rec.items.push_back({ItemKind::retire_cid, false, retire_due_.back(), 0, 0});
                retire_due_.pop_back();
                eliciting = in_flight = true;
            }
            while (!new_cid_due_.empty()) {
                const std::uint64_t seq = new_cid_due_.back();
                const OurCid* c = nullptr;
                for (const OurCid& oc : our_cids_)
                    if (oc.seq == seq) c = &oc;
                if (!c) {  // retired before it was ever sent
                    new_cid_due_.pop_back();
                    continue;
                }
                unsigned char token[16];
                reset_token(c->cid, token);
                const std::size_t n = put_new_connection_id(payload + w, room - w, seq, 0, c->cid, token);
                if (!n) break;
                w += n;
                new_cid_due_.pop_back();
                eliciting = in_flight = true;
                rec.items.push_back({ItemKind::new_cid, false, seq, 0, 0});
            }
            if (path_challenge_due_) {
                const std::size_t n = put_path_challenge(payload + w, room - w, path_challenge_);
                if (n) {
                    w += n;
                    path_challenge_due_ = false;
                    eliciting = in_flight = true;
                    rec.items.push_back({ItemKind::path_challenge, false, 0, 0, 0});
                }
            }
            while (!credit_.empty()) {
                QuicStream* s = credit_.back();
                if (!s->credit_due) { credit_.pop_back(); continue; }
                const std::size_t n = put_max_stream_data(payload + w, room - w, s->id, s->max_recv);
                if (!n) break;
                w += n;
                s->credit_due = false;
                credit_.pop_back();
                eliciting = in_flight = true;
                rec.items.push_back({ItemKind::max_stream_data, false, s->id, 0, 0});
            }
            while (!control_.empty()) {
                QuicStream* s = control_.back();
                bool fits = true;
                bool reset_now = false;
                if (s->reset_due) {
                    const std::size_t n = put_reset_stream(payload + w, room - w, s->id, s->reset_send_code, s->total);
                    if (!n) { fits = false; } else {
                        w += n;
                        s->reset_due = false;
                        s->reset_sent = true;
                        reset_now = true;
                        eliciting = in_flight = true;
                        rec.items.push_back({ItemKind::reset_stream, false, s->id, 0, 0});
                    }
                }
                if (fits && s->stop_due) {
                    const std::size_t n = put_stop_sending(payload + w, room - w, s->id, s->stop_send_code);
                    if (!n) { fits = false; } else {
                        w += n;
                        s->stop_due = false;
                        eliciting = in_flight = true;
                        rec.items.push_back({ItemKind::stop_sending, false, s->id, 0, 0});
                    }
                }
                if (!fits) break;
                control_.pop_back();
                if (reset_now && !s->send_done) {  // the send side is terminal: the application may close the stream
                    s->send_done = true;
                    dequeue(*s);
                    app_.on_stream_sent(*s);
                }
            }
            // STREAM data: lost ranges first, then new bytes, one frame per stream in turn.
            if (rec_.cwnd_room() >= max_datagram_ || rec_.probes[si] > 0) {
                unsigned turns = 0;
                while (ready_head_ && turns++ < 64) {
                    QuicStream& s = *ready_head_;
                    std::uint64_t b = 0;
                    std::size_t take = 0;
                    bool fin = false, resend = false;
                    const std::size_t hdr_max = stream_header_size(s.id, s.total, 65535, true);
                    if (room - w <= hdr_max + 1) break;
                    const std::size_t avail = room - w - hdr_max;
                    if (!s.lost.empty()) {
                        b = s.lost.ranges().front().first;
                        take = static_cast<std::size_t>(std::min<std::uint64_t>(s.lost.ranges().front().second - b, avail));
                        resend = true;
                    } else if (s.next < s.total) {
                        const std::uint64_t conn_room = peer_max_data_ > data_sent_ ? peer_max_data_ - data_sent_ : 0;
                        const std::uint64_t stream_room = s.max_send > s.next ? s.max_send - s.next : 0;
                        const std::uint64_t allowed = std::min(std::min(conn_room, stream_room), s.total - s.next);
                        if (allowed == 0) {  // blocked by credit: out of the ready list until MAX_* arrives
                            if (!s.blocked_reported) {
                                s.blocked_reported = true;
                                if (stream_room == 0) w += put_stream_data_blocked(payload + w, room - w, s.id, s.max_send);
                                else w += put_data_blocked(payload + w, room - w, peer_max_data_);
                                eliciting = in_flight = true;
                            }
                            dequeue(s);
                            continue;
                        }
                        b = s.next;
                        take = static_cast<std::size_t>(std::min<std::uint64_t>(allowed, avail));
                    } else if (s.fin && !s.fin_sent) {
                        b = s.total;
                        take = 0;
                    } else {
                        dequeue(s);
                        continue;
                    }
                    fin = s.fin && b + take == s.total;
                    const std::size_t h = put_stream_header(payload + w, room - w, s.id, b, take, fin, true);
                    if (!h) break;
                    if (take && !copy_stream_bytes(s, b, take, payload + w + h)) {
                        // The source failed (a file read): the stream is reset.
                        stream_reset(s, 0x102);  // H3_INTERNAL_ERROR; the application learns through on_stream_sent never firing
                        dequeue(s);
                        continue;
                    }
                    w += h + take;
                    rec.items.push_back({ItemKind::stream, fin, s.id, b, static_cast<std::uint32_t>(take)});
                    eliciting = in_flight = true;
                    if (resend) s.lost.remove(b, b + take);
                    else if (take) { s.next = b + take; data_sent_ += take; }
                    if (fin) s.fin_sent = true;
                    if (s.has_unsent()) rotate();
                    else dequeue(s);
                }
            }
        }
        if (space == Space::application && max_streams_pending_ && (max_streams_due_ || eliciting)) {
            const std::size_t n1 = put_max_streams(payload + w, room - w, true, our_max_streams_bidi_);
            const std::size_t n2 = n1 ? put_max_streams(payload + w + n1, room - w - n1, false, our_max_streams_uni_) : 0;
            if (n1 && n2) {
                w += n1 + n2;
                max_streams_pending_ = max_streams_due_ = false;
                advertised_bidi_ = our_max_streams_bidi_;
                advertised_uni_ = our_max_streams_uni_;
                eliciting = in_flight = true;
                rec.items.push_back({ItemKind::max_streams_bidi, false, 0, 0, 0});
            }
        }
        if (want_ping_ && space == Space::application) {  // the MTU probe: its acknowledgement raises the datagram size
            const std::size_t n = put_ping(payload + w, room - w);
            if (n) { w += n; eliciting = in_flight = true; rec.items.push_back({ItemKind::mtu_probe, false, path_gen_, 0, 0}); }
        }
        // A probe needs an ack-eliciting packet: PING when nothing else is.
        if (rec_.probes[si] > 0) {
            if (!eliciting) {
                const std::size_t n = put_ping(payload + w, room - w);
                if (n) { w += n; eliciting = in_flight = true; rec.items.push_back({ItemKind::ping, false, 0, 0, 0}); }
            }
            if (eliciting) --rec_.probes[si];
        }
        if (w == 0) {
            ps.forget(rec);
            return 0;
        }
        // Header protection samples 16 bytes starting 4 bytes into the packet number, so
        // the packet number and the protected payload together must be at least 4 bytes
        // longer than the sample (RFC 9001 5.4.2): a lone PING behind a 1-byte number is
        // padded, or the peer cannot unprotect it and never acknowledges the probe.
        if (pn_len + w + kAeadTagLen < 4 + kHpSampleLen) {
            const std::size_t need = 4 + kHpSampleLen - kAeadTagLen - pn_len - w;
            if (pos + w + need + kAeadTagLen <= cap) {
                std::memset(payload + w, 0, need);
                w += need;
                in_flight = true;
            }
        }
        // Padding to the datagram's minimum (RFC 9000 14.1): PADDING is all zeros.
        if (pad_to && pos + w + kAeadTagLen < pad_to && pad_to <= cap) {
            const std::size_t fill = pad_to - (pos + w + kAeadTagLen);
            std::memset(payload + w, 0, fill);
            w += fill;
            in_flight = true;
        }
        if (len_pos) write_varint_fixed(buf + len_pos, pn_len + w + kAeadTagLen, 2);
        if (!tx_[si].seal(pn, buf, pn_offset + pn_len, w)) {
            ps.forget(rec);
            return 0;
        }
        unsigned char mask[5];
        if (!tx_[si].mask(buf + pn_offset + 4, mask)) {
            ps.forget(rec);
            return 0;
        }
        protect_header(buf, pn_offset, pn_len, space != Space::application, mask);
        const std::size_t total = pn_offset + pn_len + w + kAeadTagLen;
        rec.bytes = static_cast<std::uint32_t>(total);
        rec.ack_eliciting = eliciting;
        rec.in_flight = in_flight;
        ++ps.next_pn;
        rec_.on_packet_sent(space, rec, now);
        if (ack_written) {
            rec_.on_ack_sent(space);
            if (space == Space::application) update_ack_pending_ = false;  // acknowledged under the new keys: the update is complete
        }
        if (space == Space::application) maybe_update_keys(now);
        ++packets_out;
        QUIC_TRACE("quic: -> space=%u pn=%llu len=%zu eliciting=%d\n", si, static_cast<unsigned long long>(pn), total, eliciting ? 1 : 0);
        return total;
    }

    // The bytes [offset, offset + len) of a stream's send data into dst: the head, then the
    // memory body or the file (through a chunk read ahead).
    bool copy_stream_bytes(QuicStream& s, std::uint64_t offset, std::size_t len, unsigned char* dst) noexcept {
        std::size_t done = 0;
        while (done < len) {
            const std::uint64_t at = offset + done;
            const std::size_t want = len - done;
            if (at < s.head_end()) {
                if (at < s.head_base) return false;  // trimmed away: acknowledged long ago
                const std::size_t rel = static_cast<std::size_t>(at - s.head_base);
                const std::size_t n = std::min<std::size_t>(want, s.head.size() - rel);
                std::memcpy(dst + done, s.head.data() + rel, n);
                done += n;
                continue;
            }
            const std::uint64_t body_at = at - s.head_end();
            if (!s.mem.empty()) {
                if (body_at >= s.mem.size()) return false;
                const std::size_t n = std::min<std::size_t>(want, s.mem.size() - static_cast<std::size_t>(body_at));
                std::memcpy(dst + done, s.mem.data() + body_at, n);
                done += n;
                continue;
            }
            if (!s.file) return false;
            if (body_at >= s.file_len) return false;
            if (!(body_at >= s.chunk_off && body_at < s.chunk_off + s.chunk_len)) {  // read the next window
                if (s.chunk.size() < 65536) s.chunk.resize(65536);
                const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(s.chunk.size(), s.file_len - body_at));
                const auto r = s.file->read_at(s.chunk.data(), n, s.file_offset + body_at);
                if (r <= 0) return false;
                s.chunk_off = body_at;
                s.chunk_len = static_cast<std::size_t>(r);
            }
            const std::size_t rel = static_cast<std::size_t>(body_at - s.chunk_off);
            const std::size_t n = std::min<std::size_t>(want, s.chunk_len - rel);
            std::memcpy(dst + done, s.chunk.data() + rel, n);
            done += n;
        }
        return true;
    }

    // ---- close ----

    void fail(std::uint64_t code, std::uint64_t frame_type, std::string_view reason, TimePoint now) {
        if (state_ == State::closing || state_ == State::draining || state_ == State::closed) return;
        QUIC_TRACE("quic: fail code=%llu %.*s\n", static_cast<unsigned long long>(code), static_cast<int>(reason.size()), reason.data());
        state_ = State::closing;
        leave_handshake();
        close_app_ = false;
        close_code_ = code;
        close_frame_type_ = frame_type;
        close_reason_.assign(reason.data(), reason.size());
        close_due_ = true;
        closing_end_ = now + rec_.pto_duration(Space::application) * 3;
        app_.on_closed(false, code);
    }

    // One datagram with the CONNECTION_CLOSE frame in the highest space we have keys for
    // (an application close before the handshake is complete travels as the transport
    // form with APPLICATION_ERROR, RFC 9000 10.2.3).
    void send_close(SendBatch& batch, TimePoint now) {
        (void)now;
        unsigned si = tx_[2].valid() && state_ != State::handshaking ? 2 : tx_[1].valid() ? 1 : tx_[0].valid() ? 0 : kSpaces;
        if (si == kSpaces) return;
        unsigned char* buf = batch.reserve(max_datagram_);
        if (!buf) return;
        const bool app = close_app_ && si == 2;
        const std::uint64_t code = close_app_ && si != 2 ? err::application_error : close_code_;
        PnSpace& ps = rec_.spaces[si];
        const std::uint64_t pn = ps.next_pn++;
        const unsigned pn_len = 4;
        std::size_t pos = 0, len_pos = 0;
        if (si == 2) {
            buf[pos++] = static_cast<unsigned char>(0x40 | (key_phase_ ? 0x04 : 0) | (pn_len - 1));
            std::memcpy(buf + pos, peer_cid_.bytes, peer_cid_.len);
            pos += peer_cid_.len;
        } else {
            const Cid& scid = initial_scid_;
            buf[pos++] = static_cast<unsigned char>(0xc0 | ((si == 0 ? 0 : 2) << 4) | (pn_len - 1));
            buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 0; buf[pos++] = 1;
            buf[pos++] = peer_cid_.len;
            std::memcpy(buf + pos, peer_cid_.bytes, peer_cid_.len);
            pos += peer_cid_.len;
            buf[pos++] = scid.len;
            std::memcpy(buf + pos, scid.bytes, scid.len);
            pos += scid.len;
            if (si == 0) buf[pos++] = 0;
            len_pos = pos;
            pos += 2;
        }
        const std::size_t pn_offset = pos;
        write_pn(buf + pos, pn, pn_len);
        pos += pn_len;
        const std::size_t room = max_datagram_ - pos - kAeadTagLen;
        std::size_t w = put_connection_close(buf + pos, room, app, code, close_frame_type_, close_reason_);
        if (!w) return;
        if (si == 0 && pos + w + kAeadTagLen < kMinInitialDatagram) {
            const std::size_t fill = kMinInitialDatagram - (pos + w + kAeadTagLen);
            std::memset(buf + pos + w, 0, fill);
            w += fill;
        }
        if (len_pos) write_varint_fixed(buf + len_pos, pn_len + w + kAeadTagLen, 2);
        if (!tx_[si].seal(pn, buf, pn_offset + pn_len, w)) return;
        unsigned char mask[5];
        if (!tx_[si].mask(buf + pn_offset + 4, mask)) return;
        protect_header(buf, pn_offset, pn_len, si != 2, mask);
        batch.commit(pn_offset + pn_len + w + kAeadTagLen, peer_, peer_len_);
    }

    void finish() {
        state_ = State::closed;
    }

    // ---- the ready list (round robin) ----

    void enqueue(QuicStream& s) noexcept {
        if (s.ready || !s.open) return;
        s.ready = true;
        s.next_ready = nullptr;
        if (ready_tail_) ready_tail_->next_ready = &s;
        else ready_head_ = &s;
        ready_tail_ = &s;
    }
    void dequeue(QuicStream& s) noexcept {
        if (!s.ready) return;
        QuicStream* prev = nullptr;
        for (QuicStream* p = ready_head_; p; prev = p, p = p->next_ready) {
            if (p != &s) continue;
            if (prev) prev->next_ready = p->next_ready;
            else ready_head_ = p->next_ready;
            if (ready_tail_ == p) ready_tail_ = prev;
            break;
        }
        s.ready = false;
        s.next_ready = nullptr;
    }
    void rotate() noexcept {  // the head to the tail
        QuicStream* h = ready_head_;
        if (!h || h == ready_tail_) return;
        ready_head_ = h->next_ready;
        h->next_ready = nullptr;
        ready_tail_->next_ready = h;
        ready_tail_ = h;
    }
    void wake_blocked() noexcept {
        // Streams left the list when credit ran out: the application's streams are asked
        // again through their blocked flag at the next MAX_STREAM_DATA; connection credit
        // wakes every stream with unsent data.
        app_.for_each_stream([this](QuicStream& s) {
            if (s.open && s.has_unsent() && !s.ready && !s.reset_sent) {
                s.blocked_reported = false;
                enqueue(s);
            }
        });
    }
    void grant(QuicStream& s, std::uint64_t max_recv) noexcept {
        s.max_recv = max_recv;
        if (!s.credit_due) {
            s.credit_due = true;
            credit_.push_back(&s);
        }
    }
    bool recently_closed(std::uint64_t id) const noexcept {
        for (std::uint64_t c : recent_closed_)
            if (c == id) return true;
        return false;
    }

    struct CryptoIn {
        std::string buf;
        RangeSet ranges;
        std::uint64_t delivered = 0;
    };
    struct CryptoOut {
        std::uint64_t sent = 0;
        RangeSet lost;
        RangeSet acked;
    };
    struct PeerCid {
        std::uint64_t seq = 0;
        Cid cid;
        bool has_token = false;  // the handshake's id has none
        unsigned char token[16] = {};
    };
    struct OurCid {
        std::uint64_t seq = 0;
        Cid cid;
    };

    App& app_;
    EndpointBase& ep_;
    Limits limits_;
    sockaddr_storage peer_;
    socklen_t peer_len_;
    bool ok_ = false;
    State state_ = State::handshaking;
    TimePoint created_, last_receive_;
    Duration idle_{};
    Duration our_max_ack_delay_{};
    Cid odcid_, peer_cid_;
    Cid initial_scid_;  // ours during the handshake (sequence 0), the source id of our long headers
    Cid initial_dcid_;  // the id the client addressed in its Initials (after a Retry: our Retry's)
    Cid current_dcid_;  // the id the packet being processed came to
    bool half_open_counted_ = false;
    std::uint64_t peer_cid_seq_ = 0;
    std::vector<OurCid> our_cids_;  // active, sequence 0 first
    std::vector<Cid> registered_;   // what the endpoint's table maps here
    std::uint64_t our_cid_seq_next_ = 1;
    std::vector<std::uint64_t> new_cid_due_;  // NEW_CONNECTION_ID frames to send, by sequence
    std::vector<PeerCid> peer_cids_;          // the peer's active ids, the handshake's included
    std::uint64_t peer_retired_below_ = 0;    // the peer's Retire Prior To
    std::vector<std::uint64_t> retire_due_;
    TlsSession tls_;
    Keys rx_[kSpaces], tx_[kSpaces];
    bool key_phase_ = false;  // of the packets we send
    // Key update (RFC 9001 6): the phase of the packets we read, the keys of the previous
    // phase for reordered packets until prev_keys_end_, the next phase derived on demand.
    Keys rx_prev_, rx_next_;
    bool rx_phase_ = false;
    bool update_ack_pending_ = false;  // the peer's update is not acknowledged under the new keys yet
    std::uint64_t phase_first_pn_ = 0, tx_phase_first_pn_ = 0;
    TimePoint prev_keys_end_{}, last_key_update_{};
    // The peer's address: the previous one for a validation that fails, the challenge in flight.
    sockaddr_storage prev_peer_{};
    socklen_t prev_peer_len_ = 0;
    bool prev_validated_ = false;
    unsigned char path_challenge_[8] = {};
    bool path_challenge_due_ = false, path_validating_ = false;
    unsigned path_tries_ = 0;
    bool from_peer_path_ = true;  // the packet being processed came from the peer's address
    bool non_probing_ = false;    // it carried a frame other than the probing ones
    // Budgets.
    unsigned glitches_ = 0;
    long long reset_second_ = -1;
    std::uint64_t resets_in_second_ = 0;
    Recovery rec_;
    CryptoIn crypto_in_[kSpaces];
    CryptoOut crypto_out_[kSpaces];
    TransportParams peer_tp_;
    bool peer_params_ok_ = false;
    bool address_validated_ = false;
    std::uint64_t bytes_received_ = 0, bytes_sent_ = 0;
    std::size_t max_datagram_ = 1200;
    // Path MTU discovery (RFC 8899 in its simplest form, design 6.7): one probe after the
    // handshake, a PING padded to the target; acknowledged, the target is the datagram size.
    std::size_t mtu_target_ = 0;
    bool mtu_probe_due_ = false, mtu_probe_sent_ = false, want_ping_ = false;
    std::uint64_t path_gen_ = 0;  // counts the peer's address changes: a probe belongs to one path
    // Flow control (RFC 9000 4).
    std::uint64_t our_max_data_ = 0, data_received_ = 0, data_consumed_ = 0;
    std::uint64_t peer_max_data_ = 0, data_sent_ = 0;
    std::uint64_t our_max_streams_bidi_ = 0, our_max_streams_uni_ = 0;
    std::uint64_t opened_bidi_ = 0, opened_uni_ = 0, closed_bidi_ = 0, closed_uni_ = 0;
    static constexpr unsigned kRecentClosed = 64;
    std::uint64_t recent_closed_[kRecentClosed];  // ids of the streams closed last; filled with an impossible id at construction
    unsigned recent_pos_ = 0;
    std::uint64_t peer_max_streams_bidi_ = 0, peer_max_streams_uni_ = 0;
    std::uint64_t next_uni_index_ = 0;
    // Frames due.
    bool handshake_done_due_ = false, handshake_done_acked_ = false;
    bool max_data_due_ = false, max_streams_due_ = false, max_streams_pending_ = false;
    std::uint64_t advertised_bidi_ = 0, advertised_uni_ = 0;  // the MAX_STREAMS the peer knows
    unsigned char path_response_[4][8] = {};
    unsigned path_responses_ = 0;
    std::vector<QuicStream*> control_;  // RESET_STREAM / STOP_SENDING due
    std::vector<QuicStream*> credit_;   // MAX_STREAM_DATA due
    QuicStream* ready_head_ = nullptr;
    QuicStream* ready_tail_ = nullptr;
    // Close.
    bool close_app_ = false, close_due_ = false;
    std::uint64_t close_code_ = 0, close_frame_type_ = 0;
    std::string close_reason_;
    TimePoint closing_end_{};
    unsigned close_packets_ = 0;
};

}  // namespace agensio::quic
