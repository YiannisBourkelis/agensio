// A QUIC connection (src/quic/connection.hpp) driven with arbitrary 1-RTT packets after
// a handshake that never ran (fuzz_establish): the input is a script of plaintext frame
// payloads the harness seals with the keys the connection reads with, and clock steps
// that fire its timers, so streams, flow control, acknowledgements, losses, probes,
// connection ids, key phases and the close all meet the fuzzer with real packet
// protection. Built with -DAGENSIO_TLS=ON (OpenSSL 3.5), see CMakeLists.txt.
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include <openssl/ssl.h>

#include "quic/connection.hpp"

namespace {

using namespace agensio::quic;

struct FuzzEndpoint final : EndpointBase {
    void unmap(const Cid&, const void*) override {}
    bool map(const Cid&, const Cid&) override { return true; }
    void arm_if_earlier(std::chrono::steady_clock::time_point) override {}
};

// The application: streams as a plain list, every readable byte consumed and answered
// with a short body, resets and stops answered as the HTTP/3 layer would.
struct FuzzApp {
    using Quic = QuicConnection<FuzzApp>;
    static constexpr std::uint64_t kExcessiveLoad = 0x107;
    std::vector<std::unique_ptr<QuicStream>> streams;
    Quic* q = nullptr;
    std::size_t closed = 0, answered = 0;

    QuicStream* on_new_stream(std::uint64_t) {
        if (streams.size() > 256) return nullptr;
        streams.push_back(std::make_unique<QuicStream>());
        streams.back()->owner = this;
        return streams.back().get();
    }
    QuicStream* find_stream(std::uint64_t id) noexcept {
        for (auto& s : streams)
            if (s->open && s->id == id) return s.get();
        return nullptr;
    }
    void on_stream_readable(QuicStream& s) {
        if (const std::size_t n = s.available()) q->stream_consumed(s, n);
        if (s.at_end() && !s.fin_delivered) {
            s.fin_delivered = true;
            if (stream_is_bidi(s.id) && !s.fin && s.total == 0) {
                s.mem = "ok\n";
                s.total = 3;
                s.fin = true;
                ++answered;
                q->stream_ready(s);
            }
        }
    }
    void on_stream_reset(QuicStream& s, std::uint64_t) {
        s.fin_delivered = true;
        if (stream_is_bidi(s.id) && !s.send_done && !s.reset_sent) q->stream_reset(s, 0x10c);
        maybe_close(s);
    }
    void on_stop_sending(QuicStream& s, std::uint64_t) {
        if (!s.send_done && !s.reset_sent) q->stream_reset(s, 0x10c);
        maybe_close(s);
    }
    void on_stream_sent(QuicStream& s) { maybe_close(s); }
    void on_handshake_done() {}
    void on_closed(bool, std::uint64_t) {}
    void before_produce() {}
    template <class F>
    void for_each_stream(F f) {
        for (auto& s : streams) f(*s);
    }
    void maybe_close(QuicStream& s) {
        if (!s.open) return;
        const bool recv_done = s.fin_delivered || s.reset_received;
        const bool send_done = !stream_is_bidi(s.id) || s.send_done || s.reset_sent;
        if (recv_done && send_done) {
            q->stream_closed(s);
            ++closed;
        }
    }
};

SSL_CTX* context() {
    static SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    return ctx;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    if (size < 2) return 0;
    using Clock = std::chrono::steady_clock;
    FuzzEndpoint ep;
    ep.batch.set_gso(false);
    FuzzApp app;
    sockaddr_storage peer{};
    auto* in = reinterpret_cast<sockaddr_in*>(&peer);
    in->sin_family = AF_INET;
    in->sin_port = htons(4433);
    in->sin_addr.s_addr = htonl(0x7f000001);
    PacketHeader initial;
    initial.long_form = true;
    initial.type = LongType::initial;
    initial.version = kVersion1;
    initial.dcid.assign(reinterpret_cast<const unsigned char*>("\x01\x02\x03\x04\x05\x06\x07\x08"), 8);
    initial.scid.assign(reinterpret_cast<const unsigned char*>("\x10\x11\x12\x13"), 4);
    Limits limits;
    TimePoint now = Clock::time_point(std::chrono::seconds(1000));
    AcceptInfo info;
    info.odcid = initial.dcid;
    info.validated = true;
    FuzzApp::Quic conn(app, ep, context(), initial, info, peer, sizeof(sockaddr_in), limits, now);
    app.q = &conn;
    if (!conn.ok()) return 0;
    static const unsigned char secret[32] = {7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
                                             7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    if (!conn.fuzz_establish(secret, sizeof secret, now)) return 0;
    Keys client_tx;
    if (!client_tx.install(Suite::aes128gcm, secret, sizeof secret, true)) return 0;
    const Cid dcid = conn.our_cids().front();
    std::uint64_t pn = 0;
    std::size_t pos = 0;
    unsigned char dgram[1600];
    for (int steps = 0; steps < 64 && pos < size && !conn.closed(); ++steps) {
        const unsigned op = data[pos++];
        if (op >= 200) {  // the clock: 100 ms per unit, the timers fire
            now += std::chrono::milliseconds(100 * (op - 199));
            conn.on_timer(now);
            conn.produce(ep.batch, now);
            ep.batch.clear();
            conn.reschedule(now);
            continue;
        }
        if (pos >= size) break;
        std::size_t len = static_cast<std::size_t>(data[pos++]) * 5;  // the frames' length, up to 1,275 bytes
        if (len > size - pos) len = size - pos;
        // A short-header packet: the key phase from the op, the number 1 to 4 bytes.
        const unsigned pn_len = (op & 3) + 1;
        const bool phase = (op & 4) != 0;
        std::size_t p = 0;
        dgram[p++] = static_cast<unsigned char>(0x40 | (phase ? 0x04 : 0) | (pn_len - 1));
        std::memcpy(dgram + p, dcid.bytes, dcid.len);
        p += dcid.len;
        const std::size_t pn_offset = p;
        write_pn(dgram + p, pn, pn_len);
        p += pn_len;
        if (len + p + kAeadTagLen > sizeof dgram) len = sizeof dgram - p - kAeadTagLen;
        std::memcpy(dgram + p, data + pos, len);
        pos += len;
        if (len < 4) {  // room for the header protection sample
            std::memset(dgram + p + len, 0, 4 - len);
            len = 4;
        }
        if (!client_tx.seal(pn, dgram, p, len)) return 0;
        unsigned char mask[5];
        if (!client_tx.mask(dgram + pn_offset + 4, mask)) return 0;
        protect_header(dgram, pn_offset, pn_len, false, mask);
        ++pn;
        conn.receive(dgram, p + len + kAeadTagLen, peer, sizeof(sockaddr_in), now);
        conn.produce(ep.batch, now);
        ep.batch.clear();
        conn.reschedule(now);
        now += std::chrono::microseconds(500 + (op % 50) * 100);
    }
    if (!conn.closed()) {
        conn.close(true, 0x100, "done", now);
        conn.produce(ep.batch, now);
        ep.batch.clear();
    }
    conn.unschedule();
    return 0;
}
