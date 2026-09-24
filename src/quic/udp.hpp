// The UDP endpoint of a worker (design-http3 6.1, measured in bench/udp): one socket per
// listener, read with recvmmsg after async_wait (GRO on, so a burst arrives as one
// message), the datagrams handed to their connections by destination connection id, the
// answers of the whole wake-up collected in one batch and sent with one sendmmsg,
// consecutive datagrams of one size to one peer folded into a GSO message. The worker's
// deadline heap and its one timer live here too (6.8).
#pragma once

#include <asio.hpp>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>
#ifdef __linux__
#include <linux/filter.h>
#endif

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "quic/crypto.hpp"
#include "quic/packet.hpp"
#include "quic/stateless.hpp"
#include "quic/timer_heap.hpp"

#ifndef SOL_UDP
#define SOL_UDP 17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT 103
#endif
#ifndef UDP_GRO
#define UDP_GRO 104
#endif

namespace agensio::quic {

// The datagrams of one wake-up, sent together. A datagram is reserved, written in place
// and committed; consecutive commits of the same size to the same peer join one message
// that the kernel segments (at most 64 segments, 64 KB).
class SendBatch {
public:
    static constexpr std::size_t kMaxSegments = 64;
    explicit SendBatch(std::size_t bytes = 1024 * 1024) : buf_(bytes) {}  // per worker; a full batch goes out and fills again

    bool empty() const noexcept { return msgs_.empty(); }
    std::size_t datagrams() const noexcept { return datagrams_; }
    // Room for a datagram of up to `max` bytes, or nullptr when the batch is full.
    unsigned char* reserve(std::size_t max) noexcept { return pos_ + max <= buf_.size() ? buf_.data() + pos_ : nullptr; }
    void commit(std::size_t len, const sockaddr_storage& to, socklen_t tolen) {
        if (len == 0) return;
#ifdef AGENSIO_QUIC_TRACE
        // Development only: AGENSIO_QUIC_DROP=N loses every Nth datagram before it is sent,
        // so loss detection and retransmission run on loopback.
        static const unsigned drop_every = [] { const char* e = std::getenv("AGENSIO_QUIC_DROP"); return e ? static_cast<unsigned>(std::atoi(e)) : 0u; }();
        // AGENSIO_QUIC_DROP_TAIL=1 loses, once, the first datagram under 600 bytes after the
        // hundredth: the last packet of a response, whose loss only a probe can reveal.
        static const bool drop_tail = std::getenv("AGENSIO_QUIC_DROP_TAIL") != nullptr;
        ++drop_counter_;
        if ((drop_every && drop_counter_ % drop_every == 0) || (drop_tail && !tail_dropped_ && drop_counter_ > 100 && len < 600)) {
            tail_dropped_ = tail_dropped_ || (drop_tail && len < 600);
            std::fprintf(stderr, "quic: DROP datagram %u of %zu bytes\n", drop_counter_, len);
            return;
        }
#endif
        ++datagrams_;
        if (!msgs_.empty()) {
            Msg& m = msgs_.back();
            if (gso_ && !m.closed && m.tolen == tolen && std::memcmp(&m.to, &to, tolen) == 0 && len <= m.seg &&
                m.segments < kMaxSegments && m.len + len <= 65535 && buf_.data() + m.off + m.len == buf_.data() + pos_) {
                m.len += len;
                ++m.segments;
                if (len < m.seg) m.closed = true;  // a shorter last segment ends the message
                pos_ += len;
                return;
            }
        }
        Msg m;
        m.off = pos_;
        m.len = len;
        m.seg = len;
        m.segments = 1;
        m.to = to;
        m.tolen = tolen;
        msgs_.push_back(m);
        pos_ += len;
    }
    void set_gso(bool on) noexcept { gso_ = on; }
    bool gso() const noexcept { return gso_; }

    // Sends everything; the count of datagrams that could not be sent (EAGAIN: the
    // socket's buffer is full; the peers' recovery resends) is returned and the batch is
    // emptied. A refusal of GSO by the kernel or the interface (EIO, EINVAL) switches it
    // off for good and resends the batch one datagram per message.
    std::size_t flush(int fd) noexcept {
        std::size_t dropped = 0;
        if (msgs_.empty()) return 0;
        for (int attempt = 0; attempt < 2; ++attempt) {
            build();
            std::size_t done = 0;
            bool refused = false;
            while (done < hdrs_.size()) {
                const int r = ::sendmmsg(fd, hdrs_.data() + done, static_cast<unsigned>(hdrs_.size() - done), 0);
                if (r < 0) {
                    if (errno == EINTR) continue;
                    if ((errno == EIO || errno == EINVAL) && gso_) {
                        refused = true;
                        break;
                    }
                    if (errno == EMSGSIZE) {  // a datagram the path cannot carry (an MTU probe with DF): skipped, the rest go
                        dropped += msgs_[done].segments;
                        ++done;
                        continue;
                    }
                    for (std::size_t i = done; i < hdrs_.size(); ++i) dropped += msgs_[i].segments;
                    break;
                }
                done += static_cast<std::size_t>(r);
            }
            if (!refused) break;
            gso_ = false;  // the batch is rebuilt as single datagrams
            split_all();
        }
        clear();
        return dropped;
    }
    void clear() noexcept {
        msgs_.clear();
        pos_ = 0;
        datagrams_ = 0;
    }

private:
    struct Msg {
        std::size_t off = 0, len = 0, seg = 0;
        unsigned segments = 0;
        bool closed = false;
        sockaddr_storage to{};
        socklen_t tolen = 0;
    };
    void build() {
        hdrs_.resize(msgs_.size());
        iov_.resize(msgs_.size());
        ctl_.resize(msgs_.size() * CMSG_SPACE(sizeof(std::uint16_t)));
        for (std::size_t i = 0; i < msgs_.size(); ++i) {
            Msg& m = msgs_[i];
            iov_[i] = {buf_.data() + m.off, m.len};
            msghdr& h = hdrs_[i].msg_hdr;
            h = {};
            h.msg_name = &m.to;
            h.msg_namelen = m.tolen;
            h.msg_iov = &iov_[i];
            h.msg_iovlen = 1;
            if (m.segments > 1) {
                char* c = ctl_.data() + i * CMSG_SPACE(sizeof(std::uint16_t));
                h.msg_control = c;
                h.msg_controllen = CMSG_SPACE(sizeof(std::uint16_t));
                cmsghdr* cm = CMSG_FIRSTHDR(&h);
                cm->cmsg_level = SOL_UDP;
                cm->cmsg_type = UDP_SEGMENT;
                cm->cmsg_len = CMSG_LEN(sizeof(std::uint16_t));
                const std::uint16_t seg = static_cast<std::uint16_t>(m.seg);
                std::memcpy(CMSG_DATA(cm), &seg, sizeof seg);
            }
        }
    }
    void split_all() {
        std::vector<Msg> single;
        for (const Msg& m : msgs_) {
            std::size_t off = m.off, left = m.len;
            while (left) {
                Msg s = m;
                s.off = off;
                s.len = std::min(left, m.seg);
                s.seg = s.len;
                s.segments = 1;
                single.push_back(s);
                off += s.len;
                left -= s.len;
            }
        }
        msgs_ = std::move(single);
    }
    std::vector<unsigned char> buf_;
    std::size_t pos_ = 0;
    std::size_t datagrams_ = 0;
    std::vector<Msg> msgs_;
    std::vector<mmsghdr> hdrs_;
    std::vector<iovec> iov_;
    std::vector<char> ctl_;
    bool gso_ = true;
#ifdef AGENSIO_QUIC_TRACE
    unsigned drop_counter_ = 0;
    bool tail_dropped_ = false;
#endif
};

// What the endpoint learned about a client before its connection exists.
struct AcceptInfo {
    bool validated = false;  // a Retry token proved the address (no amplification limit)
    bool retried = false;    // the Initial's destination id is the one our Retry chose
    Cid odcid;               // the original destination id (from the token when retried, else the Initial's)
};

// When a new client is sent a Retry before it gets a connection (design-http3 6.3).
enum class RetryMode : std::uint8_t { never, auto_, always };

// What a connection needs from its endpoint, untemplated: the send batch, the socket to
// flush it through, the deadline heap, the handshake budget.
class EndpointBase {
public:
    static constexpr std::int64_t kTokenAge = 10;          // seconds a Retry token stays valid
    static constexpr unsigned kResetsPerSecond = 1000;     // stateless resets per worker

    SendBatch batch;
    TimerHeap timers;
    int fd = -1;
    std::uint8_t worker = 0;
    std::uint64_t datagrams_in = 0, datagrams_out = 0, dropped = 0, wakeups = 0;
    // Address validation and the half-open budget (6.3): connections still in their
    // handshake; Retry at half the budget in "auto", Initials dropped at the budget.
    RetryMode retry = RetryMode::auto_;
    std::size_t half_open = 0;
    std::size_t half_open_budget = 1024;
    std::uint64_t retries_sent = 0, tokens_refused = 0, initials_dropped = 0, resets_sent = 0;

    void flush() noexcept {
        datagrams_out += batch.datagrams();
        dropped += batch.flush(fd);
    }
    // The connection's deadline changed.
    void schedule(Timed* t, std::chrono::steady_clock::time_point deadline) {
        if (deadline == std::chrono::steady_clock::time_point::max()) {
            timers.remove(t);
            return;
        }
        t->deadline = deadline;
        timers.update(t);
        arm_if_earlier(deadline);
    }
    void unschedule(Timed* t) { timers.remove(t); }
    // An id no longer routes to the connection (the client's original destination id once
    // the handshake is complete, an id the peer retired).
    virtual void unmap(const Cid& cid, const void* conn) = 0;
    // A new id of the connection that `known` maps to (NEW_CONNECTION_ID).
    virtual bool map(const Cid& known, const Cid& added) = 0;

protected:
    virtual void arm_if_earlier(std::chrono::steady_clock::time_point deadline) = 0;
    virtual ~EndpointBase() = default;
};

// The endpoint over a connection type. Conn provides quic() (the QuicConnection), whose
// receive(), produce(), on_timer() and closed() the endpoint drives, and cids().
template <class Conn>
class Endpoint final : public EndpointBase {
public:
    using Clock = std::chrono::steady_clock;
    // Makes the connection for a client's first Initial (or nothing: the datagram is dropped).
    using Accept = std::function<std::shared_ptr<Conn>(Endpoint&, const PacketHeader&, const AcceptInfo&, const sockaddr_storage&,
                                                        socklen_t, Clock::time_point)>;

    Endpoint(asio::io_context& ctx, std::uint8_t worker_index, Accept accept)
        : ctx_(ctx), socket_(ctx), timer_(ctx), accept_(std::move(accept)) {
        worker = worker_index;
        slots_ = 16;  // 1 MB of receive slots per worker (a GRO message fills one)
        slot_ = 65536;
        rbuf_.resize(slots_ * slot_);
        msgs_.resize(slots_);
        iov_.resize(slots_);
        addrs_.resize(slots_);
        ctl_.resize(slots_ * 64);
    }

    // Binds; `error` says why not. With `reuse_port` the socket joins the listener's
    // SO_REUSEPORT group as the worker's member (the workers bind in order, so the
    // group's index is the worker's) and the steering program of design 6.1 is attached:
    // a packet goes to the socket whose index its destination connection id's first
    // byte names, which is the worker that issued the id; a client-chosen id (an
    // Initial) with a first byte beyond the group falls back to the kernel's 4-tuple hash,
    // stable for that client, and the worker that takes it answers with an id naming
    // itself. No privilege is needed (classic BPF); where the attach is refused, the
    // hash alone routes every connection to one worker until its address changes.
    bool open(const asio::ip::udp::endpoint& ep, std::string& error, bool reuse_port = false) {
        asio::error_code ec;
        socket_.open(ep.protocol(), ec);
        if (ec) { error = ec.message(); return false; }
        fd = socket_.native_handle();
        if (ep.protocol() == asio::ip::udp::v6()) socket_.set_option(asio::ip::v6_only(false), ec);  // [::] takes IPv4 too, as the acceptors do
        int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
        if (reuse_port) ::setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on);
        if (::setsockopt(fd, SOL_UDP, UDP_GRO, &on, sizeof on) != 0) gro_ = false;
        int bytes = 4 * 1024 * 1024;
        ::setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof bytes);
        ::setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bytes, sizeof bytes);
#ifdef IP_MTU_DISCOVER
        if (ep.protocol() == asio::ip::udp::v4()) {
            int probe = IP_PMTUDISC_PROBE;
            ::setsockopt(fd, IPPROTO_IP, IP_MTU_DISCOVER, &probe, sizeof probe);
        }
#endif
        socket_.bind(ep, ec);
        if (ec) { error = ec.message(); return false; }
        socket_.non_blocking(true, ec);
        local_ = ep;
        if (reuse_port) steering_ = attach_steering(fd);
        return true;
    }
    bool steering() const noexcept { return steering_; }

    // The classic BPF program that returns the first byte of the destination connection id
    // (offset 1 in a short header, offset 6 in a long one: after the version and the id's
    // length) as the group's socket index.
    static bool attach_steering(int fd) noexcept {
#ifdef SO_ATTACH_REUSEPORT_CBPF
        sock_filter prog[] = {
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),             // A = the header's first byte
            BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x80, 2, 0),  // a long header: two down
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 1),             // short: the id's first byte
            BPF_STMT(BPF_RET | BPF_A, 0),
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 6),             // long: 1 + version 4 + length 1
            BPF_STMT(BPF_RET | BPF_A, 0),
        };
        sock_fprog fprog{static_cast<unsigned short>(sizeof(prog) / sizeof(prog[0])), prog};
        return ::setsockopt(fd, SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF, &fprog, sizeof fprog) == 0;
#else
        (void)fd;
        return false;
#endif
    }
    void start() { wait_read(); }
    void stop() {
        asio::error_code ec;
        socket_.close(ec);
        timer_.cancel();
    }
    const asio::ip::udp::endpoint& local() const noexcept { return local_; }
    bool gro() const noexcept { return gro_; }
    std::size_t connections() const noexcept { return conns_; }

    // A connection's ids: registered by the connection as it issues them.
    void add_cid(const Cid& cid, const std::shared_ptr<Conn>& c) { table_[cid.key()] = c; }
    void remove_cid(const Cid& cid) { table_.erase(cid.key()); }

    // The connection closed for good: out of the table, the object freed with the last
    // reference.
    void retire(Conn& c) {
        c.quic().unschedule();
        // The table's entries may hold the last reference: the ids are copied out first and
        // nothing of the connection is touched after the erasures (the sanitizer caught the
        // walk over its own id list while it was being freed).
        const std::vector<Cid> cids = c.quic().our_cids();
        const void* self = &c;
        --conns_;
        for (const Cid& cid : cids) unmap(cid, self);
    }
    void unmap(const Cid& cid, const void* conn) override {
        const auto it = table_.find(cid.key());
        if (it != table_.end() && it->second.get() == conn) table_.erase(it);
    }
    bool map(const Cid& known, const Cid& added) override {
        const auto it = table_.find(known.key());
        if (it == table_.end() || table_.count(added.key())) return false;  // never over another connection's id
        std::shared_ptr<Conn> c = it->second;
        table_[added.key()] = std::move(c);
        return true;
    }

    // Produce and send now, outside a wake-up (an upstream completion on the loop).
    void flush_connection(Conn& c) {
        const auto now = Clock::now();
        c.quic().produce(batch, now);
        flush();
        c.quic().reschedule(now);
    }

private:
    template <class H>
    auto immediate(H&& h) { return asio::bind_immediate_executor(ctx_.get_executor(), std::forward<H>(h)); }

    void wait_read() {
        socket_.async_wait(asio::socket_base::wait_read, immediate([this](const asio::error_code& ec) {
            if (ec) return;  // closed
            ++wakeups;
            drain();
            wait_read();
        }));
    }

    void drain() {
        const auto now = Clock::now();
        touched_.clear();
        for (int rounds = 0; rounds < 8; ++rounds) {  // a bound per wake-up: timers and other work get the loop back
            for (std::size_t i = 0; i < slots_; ++i) {
                iov_[i] = {rbuf_.data() + i * slot_, slot_};
                msghdr& h = msgs_[i].msg_hdr;
                h = {};
                h.msg_name = &addrs_[i];
                h.msg_namelen = sizeof(sockaddr_storage);
                h.msg_iov = &iov_[i];
                h.msg_iovlen = 1;
                h.msg_control = ctl_.data() + i * 64;
                h.msg_controllen = 64;
            }
            const int r = ::recvmmsg(fd, msgs_.data(), static_cast<unsigned>(slots_), MSG_DONTWAIT, nullptr);
            if (r <= 0) break;
            for (int i = 0; i < r; ++i) {
                const mmsghdr& m = msgs_[static_cast<std::size_t>(i)];
                int seg = 0;
                for (cmsghdr* c = CMSG_FIRSTHDR(&m.msg_hdr); c; c = CMSG_NXTHDR(const_cast<msghdr*>(&m.msg_hdr), c))
                    if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO) std::memcpy(&seg, CMSG_DATA(c), sizeof seg);
                unsigned char* data = rbuf_.data() + static_cast<std::size_t>(i) * slot_;
                const std::size_t len = m.msg_len;
                const std::size_t step = seg > 0 ? static_cast<std::size_t>(seg) : len;
                for (std::size_t off = 0; off < len; off += step) {
                    const std::size_t n = std::min(step, len - off);
                    ++datagrams_in;
                    dispatch(data + off, n, addrs_[static_cast<std::size_t>(i)], m.msg_hdr.msg_namelen, now);
                }
            }
            if (static_cast<std::size_t>(r) < slots_) break;
        }
        // The wake-up's answers, one send.
        for (Conn* c : touched_)
            if (!c->quic().closed()) c->quic().produce(batch, now);
        flush();
        for (Conn* c : touched_) {
            c->quic().touched = false;
            if (c->quic().closed()) retire_shared(*c);
            else c->quic().reschedule(now);
        }
        touched_.clear();
    }

    void dispatch(unsigned char* data, std::size_t len, const sockaddr_storage& from, socklen_t fromlen, Clock::time_point now) {
        if (len < 1 + kOurCidLen) return;
        std::shared_ptr<Conn> c;
        const bool long_form = (data[0] & 0x80) != 0;
        if (long_form) {
            PacketHeader h;
            if (!parse_header(data, len, kOurCidLen, h)) return;
            if (h.version != kVersion1) {
                if (len >= kMinInitialDatagram) send_version_negotiation(h, from, fromlen);
                return;
            }
            if (h.dcid.len >= kOurCidLen) {
                const auto it = table_.find(h.dcid.key());
                if (it != table_.end() && it->second->quic().owns(h.dcid)) c = it->second;
            }
            if (!c) {
                if (h.type != LongType::initial || len < kMinInitialDatagram || h.dcid.len < 8) return;
                AcceptInfo info;
                info.odcid = h.dcid;
                const auto seconds = static_cast<std::int64_t>(std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count());
                if (h.token_len) {
                    // A token from our Retry: the client's address, the original id and the
                    // time must open it; a client that comes back with a stale or foreign
                    // token is told so at once (RFC 9000 8.1.2) and kept out.
                    unsigned char addr[18];
                    const std::size_t alen = address_bytes(from, addr);
                    if (!alen || !open_token(std::string_view(reinterpret_cast<const char*>(h.token), h.token_len), addr, alen, seconds,
                                             kTokenAge, info.odcid)) {
                        ++tokens_refused;
                        if (unsigned char* out = batch.reserve(256)) batch.commit(build_invalid_token_close(out, 256, h), from, fromlen);
                        return;
                    }
                    info.validated = info.retried = true;
                } else if (retry == RetryMode::always || (retry == RetryMode::auto_ && half_open >= half_open_budget / 2)) {
                    send_retry(h, from, fromlen, seconds);
                    return;
                }
                if (half_open >= half_open_budget) {
                    ++initials_dropped;
                    return;
                }
                c = accept_(*this, h, info, from, fromlen, now);
                if (!c) return;
                ++conns_;
#ifdef AGENSIO_QUIC_TRACE
                std::fprintf(stderr, "quic: accept on worker %u\n", worker);
#endif
            }
        } else {
            Cid dcid;
            dcid.assign(data + 1, kOurCidLen);
            const auto it = table_.find(dcid.key());
            if (it == table_.end() || !it->second->quic().owns(dcid)) {
                send_stateless_reset(dcid, len, from, fromlen, now);
                return;
            }
            c = it->second;
        }
        c->quic().receive(data, len, from, fromlen, now);
        if (!c->quic().touched) {
            c->quic().touched = true;
            touched_.push_back(c.get());
        }
    }

    void send_version_negotiation(const PacketHeader& h, const sockaddr_storage& to, socklen_t tolen) {
        unsigned char* out = batch.reserve(64 + 2 * kMaxCidLen);
        if (!out) return;
        unsigned char rnd[5];
        random_bytes(rnd, sizeof rnd);
        const std::uint32_t reserved = 0x0a0a0a0a | (static_cast<std::uint32_t>(rnd[1]) << 4);
        const std::size_t n = build_version_negotiation(out, 64 + 2 * kMaxCidLen, h.scid, h.dcid, reserved, rnd[0]);
        batch.commit(n, to, tolen);
    }

    // A Retry (RFC 9000 17.2.5) with an id naming this worker and a token bound to the
    // client's address and its original id; no state is kept.
    void send_retry(const PacketHeader& h, const sockaddr_storage& to, socklen_t tolen, std::int64_t seconds) {
        unsigned char addr[18];
        const std::size_t alen = address_bytes(to, addr);
        if (!alen) return;
        Cid ours;
        ours.len = kOurCidLen;
        ours.bytes[0] = worker;
        random_bytes(ours.bytes + 1, kOurCidLen - 1);
        const std::string token = seal_token(addr, alen, h.dcid, seconds);
        constexpr std::size_t cap = 128 + 2 * kMaxCidLen;
        unsigned char* out = batch.reserve(cap);
        if (!out) return;
        batch.commit(build_retry(out, cap, h.dcid, h.scid, ours, token), to, tolen);
        ++retries_sent;
    }

    // A short-header packet for an id nobody here knows (10.3): a reset smaller than the
    // packet, at most kResetsPerSecond per worker, none for a packet too small to answer.
    void send_stateless_reset(const Cid& dcid, std::size_t len, const sockaddr_storage& to, socklen_t tolen, Clock::time_point now) {
        if (len < 22) return;
        const auto sec = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
        if (sec != reset_second_) {
            reset_second_ = sec;
            resets_in_second_ = 0;
        }
        if (++resets_in_second_ > kResetsPerSecond) return;
        const std::size_t n = len <= 43 ? len - 1 : 43;
        unsigned char* out = batch.reserve(n);
        if (!out) return;
        build_stateless_reset(out, n, dcid);
        batch.commit(n, to, tolen);
        ++resets_sent;
    }

    void retire_shared(Conn& c) { retire(c); }

    void arm_if_earlier(Clock::time_point deadline) override {
        if (armed_ != Clock::time_point::max() && armed_ <= deadline) return;
        armed_ = deadline;
        timer_.expires_at(deadline);
        timer_.async_wait([this](const asio::error_code& ec) {
            if (ec) return;
            armed_ = Clock::time_point::max();
            fire();
        });
    }

    void fire() {
        const auto now = Clock::now();
        // Every connection whose deadline passed, then one send for all of them.
        std::vector<Conn*> due;
        while (Timed* t = timers.top()) {
            if (t->deadline > now + std::chrono::microseconds(500)) break;
            timers.remove(t);
            auto* c = static_cast<Conn*>(static_cast<typename Conn::Quic*>(t)->owner());
            c->quic().on_timer(now);
            due.push_back(c);
        }
        for (Conn* c : due)
            if (!c->quic().closed()) c->quic().produce(batch, now);
        flush();
        for (Conn* c : due) {
            if (c->quic().closed()) retire_shared(*c);
            else c->quic().reschedule(now);
        }
        if (!timers.empty()) arm_if_earlier(timers.earliest());
    }

    asio::io_context& ctx_;
    asio::ip::udp::socket socket_;
    asio::steady_timer timer_;
    Clock::time_point armed_ = Clock::time_point::max();
    Accept accept_;
    asio::ip::udp::endpoint local_;
    bool gro_ = true;
    bool steering_ = false;
    std::size_t slots_ = 0, slot_ = 0;
    std::vector<unsigned char> rbuf_;
    std::vector<mmsghdr> msgs_;
    std::vector<iovec> iov_;
    std::vector<sockaddr_storage> addrs_;
    std::vector<char> ctl_;
    std::unordered_map<std::uint64_t, std::shared_ptr<Conn>> table_;
    std::vector<Conn*> touched_;
    std::size_t conns_ = 0;
    long long reset_second_ = -1;
    unsigned resets_in_second_ = 0;
};

}  // namespace agensio::quic
