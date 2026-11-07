// The HTTP/2 writer (src/http2/writer.hpp) with answers it pulls from a source: the server's own
// connection, dispatcher and proxy handler as a plain listener with h2c runs them, over a socket
// pair, in front of an origin this process plays on a unix socket. The origin sends each answer's
// head and body in pieces when the script says, framed by Content-Length, chunked or by its close,
// of text, of bytes or as an event stream; two locations, /b/ buffered (spilled above 16 KB) and /s/
// streamed (buffering = false), with compression on and every coding asked for, so the writer pulls
// from the upstream's source, a CompressedBody over it or over the spill file, or sends the file.
// The input is a script: requests, the origin's pieces, its ends and early closes, the client's
// WINDOW_UPDATEs and SETTINGS (initial window, frame size), reading stopped and resumed, resets.
//
// The promises held, beyond the sanitizers:
// - frames within the client's frame size and windows (RFC 9113 4.2, 6.9), one response head per
//   stream and then its DATA, nothing after the stream ended; no GOAWAY, and no RST_STREAM but the
//   ones a client like this one can cause (a stream above the limit refused, an answer whose origin
//   failed mid-way);
// - an answer that ends with END_STREAM, status 200, decodes by its Content-Encoding whole, the
//   coding's end reached and nothing after it, to exactly the bytes the origin sent, Content-Length
//   kept; one the origin cut short never ends as complete;
// - once the origin has finished every answer and the client gives room and reads, every stream
//   ends: an answer waiting for a frame from the client is a stall;
// - the client gone, the connection goes, the worker's counters back at zero, and no origin
//   connection is left open.
// The three faults of 0.1.0-alpha.138 it was written after (a read on a source while one was in
// flight, a chunk read into while a write still referred to it, an empty cycle that ran no next
// one) are described in tests/h2-streamed-bodies.py. Built in a fuzz build (agensio_core_fuzz,
// CMakeLists.txt).
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "handlers/encoding.hpp"
#include "http2/connection.hpp"
#include "http2/frame.hpp"
#include "http2/hpack.hpp"
#include "response.hpp"
#include "server.hpp"
#include "services/log.hpp"
#include "../decode_stream.hpp"

namespace {

using namespace agensio;
using Conn = h2::Http2Connection<asio::ip::tcp::socket>;
using h2::FrameHeader;
using h2::FrameType;

[[noreturn]] void violation(const char* what, std::uint32_t stream = 0) {
    std::fprintf(stderr, "fuzz_h2_bodies: %s (stream %u)\n", what, static_cast<unsigned>(stream));
    std::abort();
}
void require(bool ok, const char* what, std::uint32_t stream = 0) {
    if (!ok) violation(what, stream);
}

// FUZZ_H2_TRACE=1: every frame both ways, every response head and the origin's steps on stderr.
const bool kTrace = std::getenv("FUZZ_H2_TRACE") != nullptr;

std::uint32_t u32(std::string_view p, std::size_t at = 0) {
    return h2::read_u32(reinterpret_cast<const unsigned char*>(p.data() + at));
}

// ---- the server, once per process ----

struct Env {
    std::filesystem::path dir;
    std::shared_ptr<Generation> gen;
    LogRegistry logs;
    ErrorLog error_log;
    std::unique_ptr<FileCache> cache;
    std::unique_ptr<StaticHandler> statics;
    std::unique_ptr<FcgiHandler> fcgi;
    std::unique_ptr<ProxyHandler> proxy;
    std::unique_ptr<CgiHandler> cgi;
    std::unique_ptr<ControlHandler> control;
    HttparenaHandler httparena;
    std::unique_ptr<Dispatcher> dispatcher;
    std::unique_ptr<Worker> worker;
    const Listener* listener = nullptr;
    int origin = -1;     // the origin's listening socket
    unsigned input = 0;  // inputs run so far: each one's paths carry its number
};

Env* g_env = nullptr;

std::string config_text(const std::string& d) {
    // FUZZ_H2_ERROR_LOG=path: the server's error log there instead of /dev/null, for triage.
    const char* error_log = std::getenv("FUZZ_H2_ERROR_LOG");
    const std::string origin = "unix:" + d + "/origin.sock";
    // Twelve streams at once, more than the writer's eight reads in flight (kPullBudget): the rest wait.
    // Level 1 everywhere: the levels change the bytes, not the writer's paths.
    return "[server]\nworkers = 1\nprotocols = [\"h2c\", \"h1\"]\nidle_timeout = 15\n"
           "max_requests_per_connection = 1000\nhttp2 = { max_concurrent_streams = 12 }\n"
           "state_dir = \"" + d + "/state\"\n"
           "[log]\naccess = \"/dev/null\"\nerror = \"" + std::string(error_log ? error_log : "/dev/null") + "\"\nlevel = \"info\"\n"
           "[response_compression]\nenabled = true\ncompress_event_streams = true\nlevels = { zstd = 1, br = 1, gzip = 1 }\n"
           "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"" + d + "/www\"\ndefault = true\n"
           "[[site.location]]\npath = \"/b/\"\nupstream = \"" + origin + "\"\nproxy = { buffer_max = \"16KB\", max_connections = 64 }\n"
           "[[site.location]]\npath = \"/s/\"\nupstream = \"" + origin + "\"\nproxy = { buffering = false, max_connections = 64 }\n";
}

// What Server's constructor and build_listeners do for one plain h2c listener, without a socket.
Env& env() {
    if (g_env) return *g_env;
    auto* e = new Env;  // kept for the process: the connections of every input use it
    e->dir = std::filesystem::temp_directory_path() / ("agensio-fuzz-h2b-" + std::to_string(::getpid()));
    const auto& d = e->dir;
    std::filesystem::remove_all(d);
    for (const char* sub : {"www", "state"}) std::filesystem::create_directories(d / sub);
    std::ofstream(d / "agensio.toml") << config_text(d.string());
    // The origin listens before the configuration is loaded, as an application would.
    const std::string sock_path = (d / "origin.sock").string();
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    if (sock_path.size() >= sizeof addr.sun_path) violation("the origin's socket path is too long");
    std::memcpy(addr.sun_path, sock_path.c_str(), sock_path.size() + 1);
    e->origin = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (e->origin < 0 || ::bind(e->origin, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 ||
        ::listen(e->origin, 128) != 0)
        violation("the origin's socket did not open");
    e->gen = std::make_shared<Generation>();
    e->gen->cfg = load_config(d / "agensio.toml");
    Config& c = e->gen->cfg;
    e->error_log.configure(&e->logs, e->logs.add(c.log.error), LogLevel::info);
    for (auto& site : c.sites) site.access_log_sink = e->logs.add(site.access_log);
    c.log.access_sink = e->logs.add(c.log.access);
    std::string err;
    if (!e->logs.open_all(err)) violation("the logs did not open");
    warm_response_tables();
    e->cache = std::make_unique<FileCache>(c.cache_max_file_size, c.cache_max_size, c.cache_evict_fraction, c.cache_max_open_files);
    e->statics = std::make_unique<StaticHandler>(c, *e->cache);
    e->fcgi = std::make_unique<FcgiHandler>(c, e->error_log);
    e->proxy = std::make_unique<ProxyHandler>(c, e->error_log);
    e->cgi = std::make_unique<CgiHandler>(c, e->error_log);
    e->control = std::make_unique<ControlHandler>(e->error_log);
    e->dispatcher = std::make_unique<Dispatcher>(*e->statics, *e->fcgi, *e->proxy, *e->cgi, *e->control, e->httparena);
    e->dispatcher->set_error_log(&e->error_log);
    e->gen->listeners.emplace_back();
    Listener& l = e->gen->listeners.back();
    l.address = "127.0.0.1:18080";
    l.endpoint = asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 18080);
    l.address_text = "127.0.0.1";
    l.port = 18080;
    l.h2c = true;
    l.access_sink = c.log.access_sink;
    for (const auto& site : c.sites) {
        l.router.add_site(site);
        l.site_names.push_back(site.server_names.front());
    }
    e->listener = &l;
    e->worker = std::make_unique<Worker>(0);
    e->worker->gen = e->gen;
    if (!c.server_header.empty()) e->worker->state.server_line = "Server: " + c.server_header + "\r\n";
    e->worker->state.logs.attach(&e->logs, c.log.format);
    g_env = e;
    std::atexit([] { std::filesystem::remove_all(g_env->dir); });
    return *e;
}

// ---- the origin ----

// An answer's bytes, the same for the same seed: words (compressible), noise, or events.
std::string make_body(std::size_t n, std::uint32_t seed, int type) {
    static constexpr std::string_view kWords[] = {"agensio ", "window ", "frame ", "stream ", "<p>",
                                                  "</p>\n", "pull ", "chunk ", "\xce\xb1\xce\xb2 ", "0123456789 "};
    std::uint32_t x = seed * 2654435761u + 0x9e3779b9u;
    auto rnd = [&x] {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        return x;
    };
    std::string b;
    b.reserve(n + 32);
    while (b.size() < n) {
        if (type == 1) {
            const std::uint32_t r = rnd();
            b.append(reinterpret_cast<const char*>(&r), sizeof r);
        } else if (type == 2) {
            b += "data: ";
            b += kWords[rnd() % std::size(kWords)];
            b += std::to_string(rnd() % 1000);
            b += "\n\n";
        } else {
            b += kWords[rnd() % std::size(kWords)];
        }
    }
    b.resize(n);
    return b;
}

constexpr std::string_view kTypes[] = {"text/html; charset=utf-8", "application/octet-stream", "text/event-stream"};

struct Exchange {
    std::uint32_t stream = 0;
    int framing = 0;  // 0 Content-Length, 1 chunked, 2 ended by the origin's close
    int type = 0;     // an index into kTypes
    std::string body;
    std::size_t sent = 0;  // body bytes the origin has queued
    bool head_sent = false;
    bool done = false;  // the origin sent its end (the length reached, the last chunk, its close)
    bool cut = false;   // the origin closed before its end
    int conn = -1;      // the origin connection its request arrived on
    // What the answer decodes to once complete: the whole body, or what came before the close.
    std::string_view expected() const { return framing == 2 ? std::string_view(body).substr(0, sent) : std::string_view(body); }
};

struct OriginConn {
    int fd = -1;
    std::string in, out;
    int exchange = -1;         // the answer it carries, once its request arrived
    bool close_after = false;  // closed once `out` is written: the answer's end or the origin cutting it
};

// ---- the client ----

// Whole frames out of a byte stream, the way the other side reads it.
struct Splitter {
    std::string buf;
    template <class F>
    void feed(std::string_view bytes, F&& on_frame) {
        buf.append(bytes);
        std::size_t pos = 0;
        while (buf.size() - pos >= h2::kFrameHeaderSize) {
            const FrameHeader h = h2::read_frame_header(reinterpret_cast<const unsigned char*>(buf.data() + pos));
            if (buf.size() - pos - h2::kFrameHeaderSize < h.length) break;
            on_frame(h, std::string_view(buf.data() + pos + h2::kFrameHeaderSize, h.length));
            pos += h2::kFrameHeaderSize + h.length;
        }
        buf.erase(0, pos);
    }
};

struct StreamSeen {
    int exchange = -1;
    bool response = false;     // a final response head arrived
    bool ended = false;         // END_STREAM or RST_STREAM from the server, or the client's reset
    bool completed = false;     // END_STREAM from the server
    bool client_reset = false;  // the client reset it
    std::uint32_t reset_code = 0xffffffff;
    int status = 0;
    long long content_length = -1;
    Encoding coding = Encoding::identity;
    std::uint64_t data = 0;    // DATA bytes, padding included (what flow control counts)
    std::uint64_t credit = 0;  // the client's WINDOW_UPDATE increments for the stream
    std::string body;          // the DATA payloads, padding removed
};

// The codings a request asks for; the server answers in one of them or in none.
constexpr std::string_view kAccept[] = {"", "gzip", "br", "zstd", "zstd, br, gzip", "br;q=1, gzip;q=0.5", "identity", "gzip, zstd;q=0.9"};
constexpr std::size_t kSizes[] = {0, 1, 700, 1500, 9000, 16384, 16385, 40000, 65535, 65536, 70000, 140000, 262144, 262145, 300000, 600000};
constexpr std::size_t kPieces[] = {1, 10, 100, 1000, 4096, 16375, 16384, 16385, 65536, 65537, 100000, 262144, 262145, 300000, 1, 2000};
// Never below 1 KB, and at most eight SETTINGS and three streams over the limit per input: the server
// counts dribbles and floods against the connection's glitch budget (connection.hpp), and this client
// stays below it, so a GOAWAY is a finding.
constexpr std::uint32_t kIncrements[] = {1024, 1025, 16384, 65535, 65536, 1u << 20, 1u << 24, 4096};
constexpr std::uint32_t kInitial[] = {0, 1, 1000, 16384, 65535, 100000, 1u << 20, 16383};
constexpr std::uint32_t kFrameSizes[] = {16384, 16385, 32768, 1u << 20};
constexpr std::int64_t kWindowCap = 1LL << 30;  // the client keeps every window below this: no overflow (RFC 9113 6.9.1)
constexpr std::size_t kBodyBudget = 3u << 20;   // the origin's bytes per input

struct Session {
    Env& e;
    const unsigned char* data;
    std::size_t size;
    std::size_t pos = 0;
    int fd = -1;  // the client's end
    bool reading = true;
    bool auto_window = false;
    bool eof = false;
    std::string outbox;
    std::uint32_t next_id = 1;
    std::vector<std::uint32_t> opened;
    unsigned resets = 0, settings_sent = 0, over_limit = 0;

    // The windows as the client gave them.
    std::int64_t initial = 65535, max_initial = 65535;
    std::uint32_t max_frame_ever = 16384;
    std::uint64_t conn_credit = 0, conn_data = 0;

    std::map<std::uint32_t, StreamSeen> streams;
    std::vector<Exchange> exchanges;
    std::size_t body_bytes = 0;
    std::vector<OriginConn> conns;

    // What the server sent.
    Splitter rx;
    bool first_frame = true;
    hpack::Decoder decoder{4096};
    std::string arena, block;
    bool in_block = false;
    std::uint32_t block_stream = 0;
    bool block_end_stream = false;

    Session(Env& env, const unsigned char* d, std::size_t n) : e(env), data(d), size(n) {}

    unsigned next() { return pos < size ? data[pos++] : 0; }

    static std::string u32_bytes(std::uint32_t v) {
        std::string s(4, '\0');
        h2::write_u32(reinterpret_cast<unsigned char*>(s.data()), v);
        return s;
    }

    // ---- sending ----

    void frame(FrameType type, std::uint8_t flags, std::uint32_t id, std::string_view payload) {
        if (outbox.size() > (1u << 20)) return;  // the server stopped reading long ago
        h2::append_frame_header(outbox, static_cast<std::uint32_t>(payload.size()), type, flags, id);
        outbox.append(payload);
    }

    std::size_t flush() {
        std::size_t total = 0;
        while (fd >= 0 && !outbox.empty()) {
            const ssize_t n = ::send(fd, outbox.data(), outbox.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n <= 0) break;
            outbox.erase(0, static_cast<std::size_t>(n));
            total += static_cast<std::size_t>(n);
        }
        return total;
    }

    // The window the server holds for the connection or a stream is at most the client's count of it.
    std::int64_t conn_window() const { return 65535 + static_cast<std::int64_t>(conn_credit) - static_cast<std::int64_t>(conn_data); }
    std::int64_t stream_window(const StreamSeen& s) const {
        return initial + static_cast<std::int64_t>(s.credit) - static_cast<std::int64_t>(s.data);
    }
    void credit_connection(std::int64_t inc) {
        inc = std::min(std::max<std::int64_t>(inc, 1024), kWindowCap - conn_window());
        if (inc < 1024) return;
        frame(FrameType::window_update, 0, 0, u32_bytes(static_cast<std::uint32_t>(inc)));
        conn_credit += static_cast<std::uint64_t>(inc);
    }
    void credit_stream(std::uint32_t id, std::int64_t inc) {
        StreamSeen& s = streams[id];
        if (s.ended) return;
        inc = std::min(std::max<std::int64_t>(inc, 1024), kWindowCap - stream_window(s));
        if (inc < 1024) return;
        frame(FrameType::window_update, 0, id, u32_bytes(static_cast<std::uint32_t>(inc)));
        s.credit += static_cast<std::uint64_t>(inc);
    }
    void setting(std::uint16_t id, std::uint32_t value) {
        std::string p;
        p.push_back(static_cast<char>(id >> 8));
        p.push_back(static_cast<char>(id));
        p += u32_bytes(value);
        frame(FrameType::settings, 0, 0, p);
    }

    static void integer(std::string& out, std::size_t v, int prefix_bits, unsigned char first) {
        const std::size_t max = (1u << prefix_bits) - 1;
        if (v < max) {
            out.push_back(static_cast<char>(first | v));
            return;
        }
        out.push_back(static_cast<char>(first | max));
        v -= max;
        while (v >= 128) {
            out.push_back(static_cast<char>((v & 0x7f) | 0x80));
            v >>= 7;
        }
        out.push_back(static_cast<char>(v));
    }
    static void literal(std::string& out, std::string_view name, std::string_view value) {  // without indexing, new name
        out.push_back(0x00);
        integer(out, name.size(), 7, 0);
        out.append(name);
        integer(out, value.size(), 7, 0);
        out.append(value);
    }

    // ---- receiving ----

    std::size_t read_server() {
        if (fd < 0 || eof) return 0;
        std::size_t total = 0;
        char buf[65536];
        for (;;) {
            const ssize_t n = ::recv(fd, buf, sizeof buf, MSG_DONTWAIT);
            if (n == 0) eof = true;
            if (n <= 0) break;
            total += static_cast<std::size_t>(n);
            rx.feed(std::string_view(buf, static_cast<std::size_t>(n)), [this](const FrameHeader& h, std::string_view p) { on_received(h, p); });
        }
        return total;
    }

    void on_received(const FrameHeader& h, std::string_view p) {
        if (kTrace) std::fprintf(stderr, "< type %u flags %02x stream %u length %zu\n", h.type, h.flags, h.stream_id, p.size());
        const auto type = static_cast<FrameType>(h.type);
        const std::uint32_t id = h.stream_id;
        require(h.length <= max_frame_ever, "a frame larger than the client's SETTINGS_MAX_FRAME_SIZE", id);
        if (first_frame) {
            require(type == FrameType::settings && (h.flags & h2::flag::ack) == 0, "the server's first frame is not SETTINGS");
            first_frame = false;
        }
        if (in_block) require(type == FrameType::continuation && id == block_stream, "a frame inside a header block", id);
        switch (type) {
        case FrameType::headers: {
            require(id % 2 == 1 && streams.contains(id), "HEADERS on a stream the client never opened", id);
            std::size_t pad = 0;
            if (h.flags & h2::flag::padded) {
                require(!p.empty(), "padded HEADERS without its length", id);
                pad = static_cast<unsigned char>(p[0]);
                p.remove_prefix(1);
            }
            if (h.flags & h2::flag::priority) {
                require(p.size() >= 5, "HEADERS priority fields cut short", id);
                p.remove_prefix(5);
            }
            require(pad <= p.size(), "HEADERS padding longer than the frame", id);
            p.remove_suffix(pad);
            block.assign(p);
            block_stream = id;
            block_end_stream = (h.flags & h2::flag::end_stream) != 0;
            in_block = (h.flags & h2::flag::end_headers) == 0;
            if (!in_block) on_block();
            break;
        }
        case FrameType::continuation:
            require(in_block, "CONTINUATION outside a header block", id);
            block.append(p);
            in_block = (h.flags & h2::flag::end_headers) == 0;
            if (!in_block) on_block();
            break;
        case FrameType::data: {
            require(id != 0 && streams.contains(id), "DATA on a stream the client never opened", id);
            StreamSeen& s = streams[id];
            conn_data += p.size();
            require(conn_data <= 65535 + conn_credit, "DATA beyond the connection window", id);
            if (s.client_reset) {  // sent before the server read the client's RST_STREAM (RFC 9113 6.4)
                if (auto_window && !p.empty()) credit_connection(static_cast<std::int64_t>(p.size()));
                break;
            }
            require(s.response, "DATA before the response head", id);
            require(!s.ended, "DATA after the stream ended", id);
            std::size_t pad = 0;
            if (h.flags & h2::flag::padded) {
                require(!p.empty() && static_cast<unsigned char>(p[0]) < p.size(), "DATA padding longer than the frame", id);
                pad = 1 + static_cast<unsigned char>(p[0]);
            }
            s.data += p.size();
            require(s.data <= static_cast<std::uint64_t>(max_initial) + s.credit, "DATA beyond the stream window", id);
            s.body.append(p.substr(pad > 0 ? 1 : 0, p.size() - pad));
            const bool end = (h.flags & h2::flag::end_stream) != 0;
            if (auto_window && !p.empty()) {
                credit_connection(static_cast<std::int64_t>(p.size()));
                if (!end) credit_stream(id, static_cast<std::int64_t>(p.size()));
            }
            if (end) end_stream(s, id);
            break;
        }
        case FrameType::rst_stream: {
            require(p.size() == 4 && id != 0 && streams.contains(id), "RST_STREAM on a stream the client never opened", id);
            StreamSeen& s = streams[id];
            const std::uint32_t code = u32(p);
            // Refused (above the client's twelve), or the answer's source failed mid-way.
            require(code == static_cast<std::uint32_t>(h2::ErrorCode::refused_stream) ||
                        code == static_cast<std::uint32_t>(h2::ErrorCode::internal_error),
                    "an RST_STREAM a well-behaved client never causes", id);
            if (!s.client_reset) require(!s.ended, "RST_STREAM after the stream ended", id);
            s.ended = true;
            s.reset_code = code;
            break;
        }
        case FrameType::settings:
            require(id == 0, "SETTINGS on a stream");
            break;
        case FrameType::ping:
            require(id == 0 && p.size() == 8, "a malformed PING");
            break;
        case FrameType::goaway:
            if (kTrace && p.size() >= 8)
                std::fprintf(stderr, "< GOAWAY last %u code %u: %.*s\n", u32(p) & 0x7fffffff, u32(p, 4), static_cast<int>(p.size() - 8), p.data() + 8);
            violation("a GOAWAY to a client that broke no rule");
        case FrameType::window_update:
            require(p.size() == 4 && (u32(p) & 0x7fffffff) != 0, "a malformed WINDOW_UPDATE", id);
            break;
        default:
            violation("a frame type the server never sends (PUSH_PROMISE, PRIORITY, unknown)", id);
        }
    }

    void on_block() {
        const std::uint32_t id = block_stream;
        StreamSeen& s = streams[id];
        require(!s.ended || s.client_reset, "a header block after the stream ended", id);
        int status = 0;
        long long length = -1;
        bool coding_known = true;
        Encoding coding = Encoding::identity;
        arena.clear();
        const auto result = decoder.decode(block, arena, 1u << 16, [&](std::string_view n, std::string_view v) {
            if (kTrace) std::fprintf(stderr, "<   %.*s: %.*s\n", static_cast<int>(n.size()), n.data(), static_cast<int>(v.size()), v.data());
            if (n == ":status" && v.size() == 3) status = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
            if (n == "content-length") {
                require(length < 0, "two content-length fields", id);
                length = 0;
                for (const char c : v) {
                    require(c >= '0' && c <= '9' && length < (1LL << 50), "a content-length that is not a number", id);
                    length = length * 10 + (c - '0');
                }
            }
            if (n == "content-encoding") {
                if (v == "gzip") coding = Encoding::gzip;
                else if (v == "br") coding = Encoding::br;
                else if (v == "zstd") coding = Encoding::zstd;
                else coding_known = false;
            }
            return true;
        });
        require(result == hpack::Decoder::Result::ok, "a header block the client cannot decode", id);
        if (s.ended) return;  // the client reset it: an answer already on its way
        require(!s.response, "a second header block on a stream (the proxy sends no trailers)", id);
        require(status >= 200 && status <= 599, "a response head without a final :status", id);
        require(coding_known, "a Content-Encoding the client did not ask for", id);
        s.response = true;
        s.status = status;
        s.content_length = length;
        s.coding = coding;
        if (block_end_stream) end_stream(s, id);
    }

    void end_stream(StreamSeen& s, std::uint32_t id) {
        s.ended = true;
        s.completed = true;
        if (s.content_length >= 0) require(s.body.size() == static_cast<std::uint64_t>(s.content_length), "DATA that does not add up to content-length", id);
        if (s.status != 200 || s.exchange < 0) return;
        const Exchange& x = exchanges[static_cast<std::size_t>(s.exchange)];
        require(!x.cut, "an answer the origin cut short ended as complete", id);
        require(x.done, "an answer ended before the origin's end", id);
        const test::Decoded d = test::decode_stream(s.coding, s.body);
        if (!d.available) return;  // no decoder for the coding in this build
        require(d.ok && d.ended, "an answer that does not decode to the coding's end", id);
        const std::string_view want = x.expected();
        if (d.out != want) {
            std::size_t at = 0;
            while (at < d.out.size() && at < want.size() && d.out[at] == want[at]) ++at;
            std::fprintf(stderr, "fuzz_h2_bodies: stream %u, %.*s: %zu bytes decoded, %zu sent by the origin, the first difference at %zu\n",
                         id, static_cast<int>(encoding_name(s.coding).size()), encoding_name(s.coding).data(), d.out.size(), want.size(), at);
            violation("an answer that decodes to other bytes than the origin sent", id);
        }
    }

    // ---- the origin's side ----

    std::size_t origin_io() {
        std::size_t progress = 0;
        for (;;) {
            const int c = ::accept4(e.origin, nullptr, nullptr, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (c < 0) break;
            conns.push_back({c, {}, {}, -1, false});
            ++progress;
        }
        for (std::size_t i = 0; i < conns.size(); ++i) {
            OriginConn& c = conns[i];
            if (c.fd < 0) continue;
            bool peer_closed = false;
            char buf[16384];
            for (;;) {
                const ssize_t n = ::recv(c.fd, buf, sizeof buf, MSG_DONTWAIT);
                if (n == 0) peer_closed = true;
                if (n <= 0) break;
                c.in.append(buf, static_cast<std::size_t>(n));
                progress += static_cast<std::size_t>(n);
            }
            if (c.exchange < 0) {
                if (const std::size_t end = c.in.find("\r\n\r\n"); end != std::string::npos) match_request(i);
            }
            while (!c.out.empty()) {
                const ssize_t n = ::send(c.fd, c.out.data(), c.out.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
                if (n <= 0) break;
                c.out.erase(0, static_cast<std::size_t>(n));
                progress += static_cast<std::size_t>(n);
            }
            if (peer_closed || (c.close_after && c.out.empty())) {
                if (kTrace) std::fprintf(stderr, "origin: connection %zu closed by the %s\n", i, peer_closed ? "server" : "origin");
                ::close(c.fd);
                c.fd = -1;
                ++progress;
            }
        }
        return progress;
    }

    // "GET /b/<input>/<exchange> HTTP/1.1": the answer the request is for.
    void match_request(std::size_t i) {
        OriginConn& c = conns[i];
        const std::size_t sp1 = c.in.find(' '), sp2 = sp1 == std::string::npos ? sp1 : c.in.find(' ', sp1 + 1);
        unsigned input = 0, index = 0;
        int got = 0;
        if (sp2 != std::string::npos) {
            const std::string target = c.in.substr(sp1 + 1, sp2 - sp1 - 1);
            char loc = 0;
            got = std::sscanf(target.c_str(), "/%c/%u/%u", &loc, &input, &index);
        }
        if (got != 3 || input != e.input || index >= exchanges.size() || exchanges[index].conn >= 0) {
            c.close_after = true;  // an earlier input's, or a second request for the same answer
            return;
        }
        c.exchange = static_cast<int>(index);
        exchanges[index].conn = static_cast<int>(i);
        if (kTrace) std::fprintf(stderr, "origin: connection %zu carries exchange %u (stream %u)\n", i, index, exchanges[index].stream);
    }

    // The answers whose request arrived and that the origin has not ended.
    std::vector<std::size_t> answering() const {
        std::vector<std::size_t> out;
        for (std::size_t i = 0; i < exchanges.size(); ++i)
            if (exchanges[i].conn >= 0 && !exchanges[i].done && !exchanges[i].cut && conns[static_cast<std::size_t>(exchanges[i].conn)].fd >= 0)
                out.push_back(i);
        return out;
    }

    void send_head(Exchange& x, OriginConn& c) {
        if (x.head_sent) return;
        x.head_sent = true;
        c.out += "HTTP/1.1 200 OK\r\nContent-Type: ";
        c.out += kTypes[x.type];
        c.out += "\r\n";
        if (x.framing == 0) c.out += "Content-Length: " + std::to_string(x.body.size()) + "\r\n";
        if (x.framing == 1) c.out += "Transfer-Encoding: chunked\r\n";
        c.out += "Connection: close\r\n\r\n";
    }

    void send_piece(Exchange& x, OriginConn& c, std::size_t n) {
        send_head(x, c);
        n = std::min(n, x.body.size() - x.sent);
        if (n > 0) {
            if (x.framing == 1) {
                char size_line[24];
                std::snprintf(size_line, sizeof size_line, "%zx\r\n", n);
                c.out += size_line;
            }
            c.out.append(x.body, x.sent, n);
            if (x.framing == 1) c.out += "\r\n";
            x.sent += n;
        }
        if (x.framing == 0 && x.sent == x.body.size()) {  // the length reached: the end, then the close it announced
            x.done = true;
            c.close_after = true;
        }
    }

    void origin_piece(unsigned sel, std::size_t n) {
        const auto open = answering();
        if (open.empty()) return;
        Exchange& x = exchanges[open[sel % open.size()]];
        send_piece(x, conns[static_cast<std::size_t>(x.conn)], n);
    }

    void origin_finish(std::size_t index) {
        Exchange& x = exchanges[index];
        OriginConn& c = conns[static_cast<std::size_t>(x.conn)];
        send_piece(x, c, x.body.size());
        if (x.framing == 1) c.out += "0\r\n\r\n";
        x.done = true;
        c.close_after = true;
    }

    void origin_cut(unsigned sel) {
        const auto open = answering();
        if (open.empty()) return;
        Exchange& x = exchanges[open[sel % open.size()]];
        // A close-delimited answer ends at the close, so cutting it after its head is its end.
        if (x.framing == 2 && x.head_sent) x.done = true;
        else x.cut = true;
        conns[static_cast<std::size_t>(x.conn)].close_after = true;
    }

    // ---- the event loop ----

    void pump() {
        for (int round = 0; round < 4096; ++round) {
            const std::size_t wrote = flush();
            e.worker->ctx.restart();
            const std::size_t ran = e.worker->ctx.poll();
            const std::size_t got = reading ? read_server() : 0;
            const std::size_t origin = origin_io();
            if (wrote == 0 && ran == 0 && got == 0 && origin == 0) return;
        }
    }

    // ---- the script ----

    void request(unsigned op) {
        if (opened.size() >= 24) return;
        std::size_t open = 0;
        for (const std::uint32_t id : opened) open += streams[id].ended ? 0 : 1;
        if (open >= 12 && over_limit >= 3) return;  // the server's limit (config_text): a few refused, no more
        if (open >= 12) ++over_limit;
        const unsigned loc = next(), accept = next(), size_sel = next(), shape = next();
        std::size_t n = kSizes[size_sel % std::size(kSizes)];
        if (op & 0x80) n += next() * 37;
        if (body_bytes + n > kBodyBudget) n = n % 2000;
        body_bytes += n;
        const std::uint32_t id = next_id;
        next_id += 2;
        Exchange x;
        x.stream = id;
        x.framing = static_cast<int>(shape % 3);
        x.type = static_cast<int>((shape / 3) % 3);
        x.body = make_body(n, static_cast<std::uint32_t>(e.input * 131 + exchanges.size()), x.type);
        exchanges.push_back(std::move(x));
        StreamSeen& s = streams[id];
        s.exchange = static_cast<int>(exchanges.size() - 1);
        opened.push_back(id);
        const std::string path = std::string((loc & 1) ? "/s/" : "/b/") + std::to_string(e.input) + "/" + std::to_string(exchanges.size() - 1);
        std::string b;
        b.push_back(static_cast<char>(0x82));  // :method GET
        b.push_back(static_cast<char>(0x86));  // :scheme http
        literal(b, ":path", path);
        literal(b, ":authority", "a.test");
        if (const std::string_view a = kAccept[accept % std::size(kAccept)]; !a.empty()) literal(b, "accept-encoding", a);
        frame(FrameType::headers, h2::flag::end_headers | h2::flag::end_stream, id, b);
        if (kTrace) std::fprintf(stderr, "> request stream %u %s, %zu bytes, framing %d, %.*s, accept '%.*s'\n", id, path.c_str(), n,
                                 exchanges.back().framing, static_cast<int>(kTypes[exchanges.back().type].size()), kTypes[exchanges.back().type].data(),
                                 static_cast<int>(kAccept[accept % std::size(kAccept)].size()), kAccept[accept % std::size(kAccept)].data());
    }

    std::uint32_t pick_stream(unsigned sel) const { return opened.empty() ? 0 : opened[sel % opened.size()]; }

    void step(unsigned op) {
        switch (op % 16) {
        case 0: case 1: case 2:
            request(op);
            break;
        case 3: case 4: case 5:
            origin_piece(next(), kPieces[next() % std::size(kPieces)]);
            break;
        case 6:
            if (const auto open = answering(); !open.empty()) origin_finish(open[next() % open.size()]);
            break;
        case 7:
            origin_cut(next());
            break;
        case 8:
            credit_connection(kIncrements[next() % std::size(kIncrements)]);
            break;
        case 9:
            if (const std::uint32_t id = pick_stream(next())) credit_stream(id, kIncrements[next() % std::size(kIncrements)]);
            break;
        case 10: {  // SETTINGS_INITIAL_WINDOW_SIZE: every stream's window moves by the difference (RFC 9113 6.9.2)
            const std::uint32_t v = kInitial[next() % std::size(kInitial)];
            if (++settings_sent > 8) break;
            setting(4, v);
            initial = v;
            max_initial = std::max<std::int64_t>(max_initial, v);
            break;
        }
        case 11: {
            const std::uint32_t v = kFrameSizes[next() % std::size(kFrameSizes)];
            if (++settings_sent > 8) break;
            setting(5, v);
            max_frame_ever = std::max(max_frame_ever, v);
            break;
        }
        case 12:
            reading = !reading;
            break;
        case 13:
            auto_window = !auto_window;
            break;
        case 14:
            if (const std::uint32_t id = pick_stream(next()); id && resets < 6 && !streams[id].ended) {
                frame(FrameType::rst_stream, 0, id, u32_bytes(static_cast<std::uint32_t>(h2::ErrorCode::cancel)));
                streams[id].client_reset = true;
                streams[id].ended = true;
                ++resets;
            }
            break;
        default:
            break;  // the loop runs on, the script waits
        }
    }

    // The origin ends every answer, the client gives room and reads: every stream must end.
    void settle() {
        reading = true;
        auto_window = true;
        for (int round = 0; round < 64; ++round) {
            for (const std::size_t i : answering()) origin_finish(i);
            credit_connection(kWindowCap);
            for (const std::uint32_t id : opened) credit_stream(id, kWindowCap);
            pump();
            bool all = true;
            for (const std::uint32_t id : opened) all = all && streams[id].ended;
            if (all && answering().empty()) return settled();
        }
        for (const std::uint32_t id : opened)
            if (!streams[id].ended) violation("a stream that never ended with the origin done and room given: a stall", id);
        settled();
    }

    // Every answer the origin completed, for a stream the client kept, reached it whole: no 502, no reset.
    void settled() {
        for (const std::uint32_t id : opened) {
            const StreamSeen& s = streams[id];
            if (s.client_reset || s.exchange < 0) continue;
            const Exchange& x = exchanges[static_cast<std::size_t>(s.exchange)];
            if (x.done && !x.cut) require(s.completed && s.status == 200, "an answer the origin completed did not reach the client whole", id);
        }
    }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    if (size < 1) return 0;
    Env& e = env();
    ++e.input;
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0) return 0;
    Session s(e, data, size);
    const unsigned setup = s.next();
    // The server's send buffer: a small one fills with one cycle (the writer's backpressure, a write
    // that does not complete inline while a chunk is still referred to).
    static constexpr int kSendBuffers[] = {0, 4096, 16384, 65536};
    if (const int sb = kSendBuffers[setup & 3]) ::setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    s.auto_window = (setup & 4) != 0;
    const bool settle = (setup & 8) == 0;  // else the client leaves mid-way, reads and pulls in flight
    s.fd = sv[1];
    asio::error_code ec;
    asio::ip::tcp::socket sock(e.worker->ctx);
    sock.assign(asio::ip::tcp::v4(), sv[0], ec);
    if (ec) {
        ::close(sv[0]);
        ::close(sv[1]);
        return 0;
    }
    // The client's SETTINGS completes its preface (RFC 9113 3.4), with a first window of its choice.
    if (setup & 0x10) {
        const std::uint32_t v = kInitial[(setup >> 5) % std::size(kInitial)];
        s.setting(4, v);
        s.initial = v;
        s.max_initial = std::max<std::int64_t>(s.max_initial, v);
    } else {
        s.frame(FrameType::settings, 0, 0, {});
    }
    {
        auto conn = std::make_shared<Conn>(std::move(sock), *e.worker, e.gen, e.listener, e.gen->cfg, *e.dispatcher, nullptr, h2::kPreface);
        std::weak_ptr<Conn> weak = conn;
        conn->start();
        conn.reset();
        s.pump();
        for (int steps = 0; steps < 300 && s.pos < s.size; ++steps) {
            s.step(s.next());
            s.pump();
        }
        if (settle) s.settle();
        // The client goes away: the connection must follow, at the latest when its timeouts run.
        ::close(s.fd);
        s.fd = -1;
        s.pump();
        for (int i = 0; i < 6 && !weak.expired(); ++i) {
            if (auto c = weak.lock()) c->fuzz_age(std::chrono::seconds(4 * 15 + 1));
            s.pump();
        }
        require(weak.expired(), "the connection outlived its client and its timeouts");
    }
    require(e.worker->connections.load() == 0 && e.worker->idle.load() == 0, "the worker's counters did not return to zero");
    s.pump();
    for (const OriginConn& c : s.conns)
        if (c.fd >= 0) {
            ::close(c.fd);
            violation("an origin connection left open after its client went away");
        }
    return 0;
}
