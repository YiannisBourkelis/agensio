// Loss detection and congestion control (RFC 9002), per packet number space: the
// records of packets sent (with what they carried, in a compact form, so a loss can
// re-queue it), the RTT estimate (5), acknowledgement processing and loss detection (6),
// the PTO (6.2), NewReno (7, appendix B), and the receiver's side: the packet numbers
// received and when an ACK is due (RFC 9000 13.2). The connection asks what to send
// (probes, retransmissions) and what may be sent (the congestion window, bytes in flight).
#pragma once

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "quic/frames.hpp"
#include "quic/packet.hpp"
#include "quic/range_set.hpp"

namespace agensio::quic {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

inline constexpr Duration kGranularity = std::chrono::milliseconds(1);
inline constexpr Duration kInitialRtt = std::chrono::milliseconds(333);
inline constexpr unsigned kPacketThreshold = 3;
inline constexpr unsigned kPersistentCongestionThreshold = 3;

// What a sent packet carried, for retransmission on loss. Control frames are regenerated
// from current state (a MAX_DATA carries the value that is current when it is resent).
enum class ItemKind : std::uint8_t {
    stream, crypto, handshake_done, new_cid, retire_cid, max_data, max_stream_data, max_streams_bidi, max_streams_uni,
    reset_stream, stop_sending, ping, path_response, padding
};

struct SentItem {
    ItemKind kind;
    bool fin = false;
    std::uint64_t id = 0;      // stream id; the level for crypto; the sequence for new_cid / retire_cid
    std::uint64_t offset = 0;
    std::uint32_t len = 0;
};

struct SentPacket {
    std::uint64_t pn = 0;
    TimePoint time{};
    std::uint32_t bytes = 0;
    bool ack_eliciting = false;
    bool in_flight = false;
    bool used = false;
    std::vector<SentItem> items;  // capacity kept when the slot is reused
};

// The receiver's state of one space.
struct AckState {
    RangeSet received;      // packet numbers received (the highest ranges kept)
    bool any = false;
    std::uint64_t largest = 0;
    TimePoint largest_time{};
    unsigned eliciting_unacked = 0;  // ack-eliciting packets since our last ACK
    bool ack_now = false;            // an ACK is due at once (a gap, the second packet, Initial/Handshake)
    TimePoint delay_deadline{};      // else by then (max_ack_delay)
    bool wants_ack() const noexcept { return eliciting_unacked > 0 && ack_now; }
};

class PnSpace {
public:
    std::uint64_t next_pn = 0;
    bool any_acked = false;
    std::uint64_t largest_acked = 0;
    TimePoint loss_time{};           // {} = none
    TimePoint last_eliciting_sent{};
    unsigned eliciting_in_flight = 0;
    AckState acks;
    bool discarded = false;

    PnSpace() { ring_.resize(64); }

    // A slot for the packet about to be sent (pn = next_pn).
    SentPacket& record(std::uint64_t pn) {
        SentPacket* s = &ring_[pn & mask()];
        if (s->used) {  // the ring wrapped onto a packet still in flight: double it
            grow();
            s = &ring_[pn & mask()];
        }
        s->used = true;
        s->pn = pn;
        s->items.clear();
        if (pn < oldest_) oldest_ = pn;
        if (!count_) oldest_ = pn;
        ++count_;
        return *s;
    }
    SentPacket* find(std::uint64_t pn) noexcept {
        SentPacket& s = ring_[pn & mask()];
        return s.used && s.pn == pn ? &s : nullptr;
    }
    void forget(SentPacket& s) noexcept {
        s.used = false;
        --count_;
        while (count_ && oldest_ < next_pn && !find(oldest_)) ++oldest_;
    }
    std::uint64_t oldest() const noexcept { return oldest_; }
    std::size_t in_flight_count() const noexcept { return count_; }
    void clear() {
        for (SentPacket& s : ring_) s.used = false;
        count_ = 0;
        oldest_ = next_pn;
    }

private:
    std::size_t mask() const noexcept { return ring_.size() - 1; }
    void grow() {
        std::vector<SentPacket> bigger(ring_.size() * 2);
        for (SentPacket& s : ring_)
            if (s.used) bigger[s.pn & (bigger.size() - 1)] = std::move(s);
        ring_ = std::move(bigger);
    }
    std::vector<SentPacket> ring_;
    std::size_t count_ = 0;
    std::uint64_t oldest_ = 0;  // the lowest pn that may still be in flight
};

// The connection's recovery state. The connection owns the meaning of items: after
// on_ack_received() it walks `acked` and `lost`, which the next call clears.
class Recovery {
public:
    PnSpace spaces[kSpaces];
    std::vector<SentItem> acked;   // items of the packets just acknowledged
    std::vector<SentItem> lost;    // items of the packets just declared lost
    std::size_t max_datagram = 1200;
    Duration max_ack_delay = std::chrono::milliseconds(25);  // the peer's
    unsigned ack_delay_exponent = 3;                         // the peer's
    unsigned probes[kSpaces] = {};  // ack-eliciting packets a PTO asks for, per space
    bool handshake_confirmed = false;

    Recovery() { reset_cwnd(); }

    PnSpace& space(Space s) noexcept { return spaces[static_cast<unsigned>(s)]; }

    // ---- sending ----

    // Called after a packet went out: the record is the one `record()` gave.
    void on_packet_sent(Space sp, SentPacket& p, TimePoint now) noexcept {
        PnSpace& s = space(sp);
        p.time = now;
        if (p.in_flight) {
            if (p.ack_eliciting) {
                s.last_eliciting_sent = now;
                ++s.eliciting_in_flight;
            }
            bytes_in_flight += p.bytes;
        }
    }

    std::uint64_t cwnd_room() const noexcept { return bytes_in_flight >= cwnd ? 0 : cwnd - bytes_in_flight; }

    // ---- receiving ----

    // A packet arrived in the space: the ACK bookkeeping (RFC 9000 13.2.1: Initial and
    // Handshake packets are acknowledged at once, application packets after the second
    // ack-eliciting one, on a gap, or after max_ack_delay).
    void on_packet_received(Space sp, std::uint64_t pn, bool ack_eliciting, TimePoint now, Duration our_max_ack_delay) noexcept {
        AckState& a = space(sp).acks;
        const bool out_of_order = a.any && pn < a.largest;
        const bool gap = a.any && pn > a.largest + 1;
        a.received.add_point(pn);
        a.received.keep_highest(kMaxAckRanges + 1);
        if (!a.any || pn > a.largest) {
            a.any = true;
            a.largest = pn;
            a.largest_time = now;
        }
        if (!ack_eliciting) return;
        ++a.eliciting_unacked;
        if (sp != Space::application || out_of_order || gap || a.eliciting_unacked >= 2) {
            a.ack_now = true;
        } else if (a.eliciting_unacked == 1) {
            a.delay_deadline = now + our_max_ack_delay;
        }
    }

    // An ACK frame we sent went out: the acknowledged state is clean until the next packet.
    void on_ack_sent(Space sp) noexcept {
        AckState& a = space(sp).acks;
        a.eliciting_unacked = 0;
        a.ack_now = false;
        a.delay_deadline = {};
    }

    // ---- acknowledgements (RFC 9002 A.7) ----

    // Processes an ACK frame received in the space. False: an acknowledgement of a
    // packet never sent (PROTOCOL_ERROR).
    bool on_ack_received(Space sp, const Frame& f, TimePoint now) {
        PnSpace& s = space(sp);
        acked.clear();
        lost.clear();
        if (f.largest_ack >= s.next_pn) return false;
        bool newly = false;
        std::uint64_t largest_newly = 0;
        TimePoint largest_newly_time{};
        bool largest_newly_eliciting = false;
        std::uint32_t acked_bytes = 0;
        for (unsigned i = 0; i < f.range_count; ++i) {
            const auto [b, e] = f.ranges[i];
            for (std::uint64_t pn = e; pn-- > b;) {
                if (pn < s.oldest()) break;
                SentPacket* p = s.find(pn);
                if (!p) continue;
                if (!newly || pn > largest_newly) {
                    largest_newly = pn;
                    largest_newly_time = p->time;
                    largest_newly_eliciting = p->ack_eliciting;
                }
                newly = true;
                if (p->in_flight) {
                    bytes_in_flight -= std::min<std::uint64_t>(bytes_in_flight, p->bytes);
                    if (p->ack_eliciting && s.eliciting_in_flight) --s.eliciting_in_flight;
                    acked_bytes += p->bytes;
                    if (p->time > recovery_start) cc_on_acked(p->bytes);
                }
                for (const SentItem& it : p->items) acked.push_back(it);
                s.forget(*p);
            }
        }
        if (!newly) return true;
        if (!s.any_acked || f.largest_ack > s.largest_acked) {
            s.any_acked = true;
            s.largest_acked = f.largest_ack;
        }
        if (largest_newly == f.largest_ack && largest_newly_eliciting) {
            // RFC 9002 5.1: the RTT sample from the largest acknowledged, less the ack delay
            // (bounded by max_ack_delay once the handshake is confirmed).
            Duration ack_delay = std::chrono::microseconds(f.ack_delay << ack_delay_exponent);
            if (handshake_confirmed) ack_delay = std::min(ack_delay, max_ack_delay);
            update_rtt(now - largest_newly_time, ack_delay);
        }
        detect_lost(sp, now);
        pto_count = 0;
        return true;
    }

    // ---- loss detection (A.10) ----

    void detect_lost(Space sp, TimePoint now) {
        PnSpace& s = space(sp);
        s.loss_time = {};
        if (!s.any_acked) return;
        const Duration loss_delay = std::max(kGranularity, std::max(latest_rtt, smoothed_rtt) * 9 / 8);
        const TimePoint lost_send_time = now - loss_delay;
        std::uint32_t lost_bytes = 0;
        TimePoint lost_first{}, lost_last{};
        bool any_lost = false;
        for (std::uint64_t pn = s.oldest(); pn < s.largest_acked; ++pn) {
            SentPacket* p = s.find(pn);
            if (!p) continue;
            if (p->time <= lost_send_time || s.largest_acked >= pn + kPacketThreshold) {
                if (p->in_flight) {
                    bytes_in_flight -= std::min<std::uint64_t>(bytes_in_flight, p->bytes);
                    if (p->ack_eliciting && s.eliciting_in_flight) --s.eliciting_in_flight;
                    lost_bytes += p->bytes;
                    if (!any_lost || p->time < lost_first) lost_first = p->time;
                    if (!any_lost || p->time > lost_last) lost_last = p->time;
                    any_lost = true;
                }
                for (const SentItem& it : p->items) lost.push_back(it);
                s.forget(*p);
            } else {
                const TimePoint t = p->time + loss_delay;
                if (s.loss_time == TimePoint{} || t < s.loss_time) s.loss_time = t;
            }
        }
        if (any_lost) cc_on_lost(lost_bytes, lost_last, lost_first, now);
    }

    // ---- the timer (A.8, A.9) ----

    // The next deadline of loss detection, or TimePoint::max() when none is armed.
    TimePoint loss_timer(bool at_amplification_limit) const noexcept {
        TimePoint earliest = TimePoint::max();
        for (unsigned i = 0; i < kSpaces; ++i) {
            const PnSpace& s = spaces[i];
            if (s.discarded) continue;
            if (s.loss_time != TimePoint{} && s.loss_time < earliest) earliest = s.loss_time;
        }
        if (earliest != TimePoint::max()) return earliest;
        if (at_amplification_limit) return TimePoint::max();
        // PTO: the earliest of the spaces with ack-eliciting packets in flight.
        for (unsigned i = 0; i < kSpaces; ++i) {
            const PnSpace& s = spaces[i];
            if (s.discarded || s.eliciting_in_flight == 0) continue;
            const TimePoint t = s.last_eliciting_sent + pto_duration(static_cast<Space>(i));
            if (t < earliest) earliest = t;
        }
        return earliest;
    }

    Duration pto_duration(Space sp) const noexcept {
        Duration d = smoothed_rtt + std::max(rttvar * 4, kGranularity);
        if (sp == Space::application && handshake_confirmed) d += max_ack_delay;
        for (unsigned i = 0; i < pto_count && i < 12; ++i) d *= 2;
        return d;
    }

    // The timer fired: lost packets declared, or probes asked for.
    void on_timeout(TimePoint now) {
        for (unsigned i = 0; i < kSpaces; ++i) {
            PnSpace& s = spaces[i];
            if (s.discarded || s.loss_time == TimePoint{}) continue;
            if (s.loss_time <= now) {
                detect_lost(static_cast<Space>(i), now);
                return;
            }
        }
        // PTO (A.9): probes in the space whose PTO expired (the earliest).
        TimePoint earliest = TimePoint::max();
        unsigned which = kSpaces;
        for (unsigned i = 0; i < kSpaces; ++i) {
            const PnSpace& s = spaces[i];
            if (s.discarded || s.eliciting_in_flight == 0) continue;
            const TimePoint t = s.last_eliciting_sent + pto_duration(static_cast<Space>(i));
            if (t < earliest) {
                earliest = t;
                which = i;
            }
        }
        if (which == kSpaces) return;
        probes[which] = 2;
        ++pto_count;
    }

    // The space's keys are dropped (RFC 9002 6.4): its packets leave bytes in flight.
    void discard_space(Space sp) noexcept {
        PnSpace& s = space(sp);
        for (std::uint64_t pn = s.oldest(); pn < s.next_pn; ++pn) {
            if (SentPacket* p = s.find(pn)) {
                if (p->in_flight) bytes_in_flight -= std::min<std::uint64_t>(bytes_in_flight, p->bytes);
                s.forget(*p);
            }
        }
        s.clear();
        s.eliciting_in_flight = 0;
        s.loss_time = {};
        s.discarded = true;
        probes[static_cast<unsigned>(sp)] = 0;
        pto_count = 0;
    }

    // ---- congestion control (NewReno, appendix B) ----

    std::uint64_t cwnd = 0;
    std::uint64_t bytes_in_flight = 0;
    std::uint64_t ssthresh = ~std::uint64_t{0};
    TimePoint recovery_start{};
    Duration latest_rtt{}, smoothed_rtt = kInitialRtt, rttvar = kInitialRtt / 2, min_rtt{};
    bool has_rtt = false;
    unsigned pto_count = 0;

    void reset_cwnd() noexcept { cwnd = std::max<std::uint64_t>(std::min<std::uint64_t>(10 * max_datagram, 14720), 2 * max_datagram); }
    std::uint64_t minimum_window() const noexcept { return 2 * max_datagram; }

private:
    void update_rtt(Duration sample, Duration ack_delay) noexcept {
        latest_rtt = sample;
        if (!has_rtt) {
            has_rtt = true;
            min_rtt = sample;
            smoothed_rtt = sample;
            rttvar = sample / 2;
            return;
        }
        min_rtt = std::min(min_rtt, sample);
        Duration adjusted = sample;
        if (adjusted >= min_rtt + ack_delay) adjusted -= ack_delay;
        const Duration diff = smoothed_rtt > adjusted ? smoothed_rtt - adjusted : adjusted - smoothed_rtt;
        rttvar = rttvar * 3 / 4 + diff / 4;
        smoothed_rtt = smoothed_rtt * 7 / 8 + adjusted / 8;
    }

    void cc_on_acked(std::uint32_t bytes) noexcept {
        if (cwnd < ssthresh) cwnd += bytes;  // slow start
        else cwnd += max_datagram * bytes / cwnd;
    }

    void cc_on_lost(std::uint32_t bytes, TimePoint last_lost, TimePoint first_lost, TimePoint now) noexcept {
        (void)bytes;
        if (last_lost > recovery_start) {  // a new recovery period (B.6)
            recovery_start = now;
            ssthresh = std::max(cwnd / 2, minimum_window());
            cwnd = ssthresh;
        }
        // Persistent congestion (B.8): losses spanning more than the threshold's duration
        // collapse the window.
        if (has_rtt && last_lost > first_lost) {
            const Duration span = last_lost - first_lost;
            const Duration threshold = (smoothed_rtt + std::max(rttvar * 4, kGranularity) + max_ack_delay) * kPersistentCongestionThreshold;
            if (span > threshold) cwnd = minimum_window();
        }
    }
};

}  // namespace agensio::quic
