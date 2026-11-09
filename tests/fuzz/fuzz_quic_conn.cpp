// A QUIC connection (src/quic/connection.hpp) driven with arbitrary 1-RTT packets after
// a handshake that never ran (fuzz_establish): the input is a script of plaintext frame
// payloads the harness seals with the keys the connection reads with, and clock steps
// that fire its timers, so streams, flow control, acknowledgements, losses, probes,
// connection ids, key phases and the close all meet the fuzzer with real packet
// protection. Every other request is answered as a streamed body through the stream's send
// blocks (quic/send_blocks.hpp, 0.1.0-alpha.142), appended at each turn of the packetiser and
// freed as the acknowledgements pass them: a resend that asks for a freed byte traps. Of the
// rest, every other is a file read through the connection's windows (sixteen at most,
// 0.1.0-alpha.143): more held, one on a closed stream, or a byte copied without one traps. Built
// with -DAGENSIO_TLS=ON (OpenSSL 3.5), see CMakeLists.txt.
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
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

// A 160 KB file whose bytes are their offsets, for the file answers: three windows' worth.
const agensio::File& fuzz_file() {
    static const agensio::File f = [] {
        agensio::File t = agensio::File::temporary();
        std::vector<char> bytes(160 * 1024);
        for (std::size_t k = 0; k < bytes.size(); ++k) bytes[k] = static_cast<char>(k & 0xff);
        if (!t.append(bytes.data(), bytes.size())) __builtin_trap();
        return t;
    }();
    return f;
}

// The application: streams as a plain list, every readable byte consumed and answered
// with a short body, a streamed one or a file, resets and stops answered as the HTTP/3 layer would.
struct FuzzApp {
    using Quic = QuicConnection<FuzzApp>;
    static constexpr std::uint64_t kExcessiveLoad = 0x107;
    std::vector<std::unique_ptr<QuicStream>> streams;
    std::vector<QuicStream*> streaming;  // answers appended piece by piece into their blocks
    std::size_t blocks_held = 0;
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
                ++answered;
                if ((s.id >> 2) & 1) {  // a streamed body behind a one-byte head
                    s.head = "h";
                    s.total = 1;
                    s.blocks.budget(&blocks_held);
                    streaming.push_back(&s);
                } else if ((s.id >> 2) & 2) {  // a file region behind a one-byte head: small ones too
                    const std::uint64_t index = s.id >> 2;
                    s.head = "h";
                    s.file = &fuzz_file();
                    s.file_offset = (index * 977) % 4096;
                    s.file_len = 1 + (index * 7919) % (160 * 1024 - 4096);
                    s.total = 1 + s.file_len;
                    s.fin = true;
                } else {
                    s.mem = "ok\n";
                    s.total = 3;
                    s.fin = true;
                }
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
    void on_stream_sent(QuicStream& s) {
        if (s.reset_sent && s.reset_send_code == 0x102) __builtin_trap();  // the transport could not copy a byte it sends
        maybe_close(s);
    }
    void on_handshake_done() {}
    void on_closed(bool, std::uint64_t) {}
    void on_check(TimePoint) {}
    // The streamed answers grow while fewer than 4 KB wait and they hold under eight blocks, pieces of
    // 100 to 3,100 bytes whose bytes are their offsets, to 48 KB and the FIN.
    void before_produce() {
        for (std::size_t i = 0; i < streaming.size();) {
            QuicStream& s = *streaming[i];
            if (!s.open || s.fin || s.reset_due || s.reset_sent) {
                streaming[i] = streaming.back();
                streaming.pop_back();
                continue;
            }
            while (s.total - s.next < 4096 && s.blocks.count() < 8 && !s.fin) {
                std::size_t room = 0;
                char* p = s.blocks.room(s.total, 64, room);
                const std::size_t n = std::min<std::size_t>(room, 100 + (s.total * 7919) % 3000);
                for (std::size_t k = 0; k < n; ++k) p[k] = static_cast<char>((s.total + k) & 0xff);
                s.blocks.appended(n);
                s.total += n;
                if (s.total >= 48 * 1024) s.fin = true;
            }
            q->stream_ready(s);
            ++i;
        }
    }
    template <class F>
    void for_each_stream(F f) {
        for (auto& s : streams) f(*s);
    }
    // The windows: at most sixteen held, none by a closed stream or one that waits, and no body byte
    // copied without one (the transport resets such a stream with 0x102).
    void check_windows() const {
        std::size_t held = 0;
        for (const auto& s : streams) {
            if (s->chunk.empty()) continue;
            ++held;
            if (!s->open || s->window_wait) __builtin_trap();
        }
        if (held > 16) __builtin_trap();
        for (const auto& s : streams)
            if ((s->reset_due || s->reset_sent) && s->reset_send_code == 0x102) __builtin_trap();
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
    std::string ack;
    for (int steps = 0; steps < 64 && pos < size && !conn.closed(); ++steps) {
        const unsigned op = data[pos++];
        if (op >= 200) {  // the clock: 100 ms per unit, the timers fire
            now += std::chrono::milliseconds(100 * (op - 199));
            conn.on_timer(now);
            conn.produce(ep.batch, now);
            ep.batch.clear();
            conn.reschedule(now);
            app.check_windows();
            continue;
        }
        if (pos >= size) break;
        const unsigned char* frames = data + pos;
        std::size_t len = 0;
        if (op >= 180) {
            // An ACK of every packet sent but one, `back` below the largest (none when 0 or past the
            // first): what makes losses, probes, late acknowledgements and freed send blocks meet.
            const std::uint64_t sent = conn.fuzz_next_pn();
            const std::uint64_t back = data[pos++] % 16;
            if (sent == 0) continue;
            const std::uint64_t largest = sent - 1;
            ack.assign(1, '\x02');
            append_varint(ack, largest);
            append_varint(ack, 0);  // the delay
            if (back == 0 || back >= largest) {
                append_varint(ack, 0);  // no more ranges
                append_varint(ack, largest);
            } else {
                append_varint(ack, 1);
                append_varint(ack, back - 1);            // largest - back + 1 .. largest
                append_varint(ack, 0);                   // a gap of one packet
                append_varint(ack, largest - back - 1);  // 0 .. largest - back - 1
            }
            frames = reinterpret_cast<const unsigned char*>(ack.data());
            len = ack.size();
        } else {
            len = static_cast<std::size_t>(data[pos++]) * 5;  // the frames' length, up to 1,275 bytes
            if (len > size - pos) len = size - pos;
        }
        // A short-header packet: the key phase from the op, the number 1 to 4 bytes.
        const unsigned pn_len = (op & 3) + 1;
        const bool phase = op < 180 && (op & 4) != 0;  // an ACK of the harness's own in the first key phase
        std::size_t p = 0;
        dgram[p++] = static_cast<unsigned char>(0x40 | (phase ? 0x04 : 0) | (pn_len - 1));
        std::memcpy(dgram + p, dcid.bytes, dcid.len);
        p += dcid.len;
        const std::size_t pn_offset = p;
        write_pn(dgram + p, pn, pn_len);
        p += pn_len;
        if (len + p + kAeadTagLen > sizeof dgram) len = sizeof dgram - p - kAeadTagLen;
        std::memcpy(dgram + p, frames, len);
        if (op < 180) pos += len;
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
        app.check_windows();
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
