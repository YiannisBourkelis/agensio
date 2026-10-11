// The HTTP/2 connection (src/http2/connection.hpp) as a plain listener with h2c runs it, over a
// socket pair, in front of the server's own dispatcher, static handler, file cache and logs, and
// a proxy and a FastCGI location whose origins are not there (a 502 after the request body was
// read). The input is a script of client actions: requests from a table of templates, frames of
// any type with chosen or arbitrary fields, raw bytes, reading stopped and resumed, the windows
// replenished or not, and time moved forward through Http2Connection::fuzz_age. Beyond the
// sanitizers it checks what the server sends: frames within the size and the windows the client
// allowed (RFC 9113 4.2, 6.9), every header block decodable with the table size the client set
// (RFC 7541 4.2, RFC 9113 6.5.3), responses only on streams the client opened and that a GOAWAY
// does not exclude, nothing after a stream ended, a valid :status first and no
// connection-specific field (RFC 9113 8.2.2, 8.3.2), content-length kept, no body for HEAD, 204
// or 304; and that the connection is gone, with the worker's counters back at zero, once its
// client is. Built in a fuzz build (agensio_core_fuzz, CMakeLists.txt).
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "http2/connection.hpp"
#include "http2/frame.hpp"
#include "http2/hpack.hpp"
#include "response.hpp"
#include "server.hpp"
#include "services/log.hpp"

namespace {

using namespace agensio;
using Conn = h2::Http2Connection<asio::ip::tcp::socket>;
using h2::FrameHeader;
using h2::FrameType;

[[noreturn]] void violation(const char* what, std::uint32_t stream = 0) {
    std::fprintf(stderr, "fuzz_h2_conn: %s (stream %u)\n", what, static_cast<unsigned>(stream));
    std::abort();
}
void require(bool ok, const char* what, std::uint32_t stream = 0) {
    if (!ok) violation(what, stream);
}

// FUZZ_H2_TRACE=1: every frame both ways and every response head on stderr, for triage.
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
};

Env* g_env = nullptr;

void write_file(const std::filesystem::path& p, std::size_t size, char fill) {
    std::ofstream(p, std::ios::binary) << std::string(size, fill);
}

std::string config_text(const std::string& d) {
    // FUZZ_H2_ERROR_LOG=path: the server's error log there instead of /dev/null, for triage.
    const char* error_log = std::getenv("FUZZ_H2_ERROR_LOG");
    return "[server]\nworkers = 1\nprotocols = [\"h2c\", \"h1\"]\nidle_timeout = 15\nbody_timeout = 30\n"
           "max_body_size = \"64KB\"\nmax_header_size = \"4KB\"\nmax_requests_per_connection = 40\n"
           "http2 = { max_concurrent_streams = 8 }\nstate_dir = \"" + d + "/state\"\n"
           "[log]\naccess = \"/dev/null\"\nerror = \"" + std::string(error_log ? error_log : "/dev/null") + "\"\nlevel = \"info\"\n"
           "[cache]\nmax_file_size = \"128KB\"\nmax_size = \"4MB\"\n"
           "[[site]]\nserver_name = [\"a.test\"]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"" + d + "/www\"\ndefault = true\n"
           "refuse = [\"/secret/\", \"*.bak\"]\n"
           "[[site.access]]\npath = \"/private\"\nallow = [\"10.0.0.0/8\"]\n"
           "[[site.location]]\npath = \"/spa/\"\ntry_files = [\"$uri\", \"/index.html\"]\n"
           "[[site.location]]\npath = \"/app/\"\nupstream = \"http://127.0.0.1:1\"\n"
           "[[site.location]]\npath = \".php\"\nmatch = \"suffix\"\nhandler = \"fastcgi\"\n"
           "fastcgi = { socket = \"unix:" + d + "/no-php.sock\" }\n"
           "[[site]]\nserver_name = [\"b.test\"]\nlisten = [\"127.0.0.1:18080\"]\nroot = \"" + d + "/www2\"\n"
           "max_body_size = \"1KB\"\n";
}

// What Server's constructor and build_listeners do for one plain h2c listener, without a socket.
Env& env() {
    if (g_env) return *g_env;
    auto* e = new Env;  // kept for the process: the connections of every input use it
    e->dir = std::filesystem::temp_directory_path() / ("agensio-fuzz-h2-" + std::to_string(::getpid()));
    const auto& d = e->dir;
    std::filesystem::remove_all(d);
    for (const char* sub : {"www/dir", "www/secret", "www/private", "www/spa", "www/p", "www2", "state"})
        std::filesystem::create_directories(d / sub);
    write_file(d / "www/index.html", 1024, 'a');
    write_file(d / "www/style.css", 100 * 1024, 'b');
    write_file(d / "www/style.css.br", 20 * 1024, 'c');  // the twin, written after its file
    write_file(d / "www/big.bin", 300 * 1024, 'd');      // above cache.max_file_size: streamed from its descriptor
    write_file(d / "www/dir/index.html", 512, 'e');
    write_file(d / "www/.hidden", 10, 'f');
    write_file(d / "www/secret/x.txt", 10, 'g');
    write_file(d / "www/private/x.txt", 10, 'h');
    write_file(d / "www/old.bak", 10, 'i');
    write_file(d / "www/empty.txt", 0, 'j');
    write_file(d / "www2/index.html", 2048, 'k');
    write_file(d / "www/a.php", 20, 'l');    // scripts on disk, so the FastCGI location connects (and fails: 502)
    write_file(d / "www/p/b.php", 20, 'm');
    std::ofstream(d / "agensio.toml") << config_text(d.string());
    e->gen = std::make_shared<Generation>();
    e->gen->cfg = load_config(d / "agensio.toml");
    Config& c = e->gen->cfg;
    // The logs as Server wires them, into /dev/null: every line is still built.
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
    e->worker->state.logs.attach(&e->logs, c.log.json ? AccessLogFormat::json : AccessLogFormat::combined);
    g_env = e;
    std::atexit([] { std::filesystem::remove_all(g_env->dir); });
    return *e;
}

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
            if (!on_header(h)) break;
            if (buf.size() - pos - h2::kFrameHeaderSize < h.length) break;
            on_frame(h, std::string_view(buf.data() + pos + h2::kFrameHeaderSize, h.length));
            pos += h2::kFrameHeaderSize + h.length;
        }
        buf.erase(0, pos);
    }
    std::function<bool(const FrameHeader&)> on_header = [](const FrameHeader&) { return true; };
};

struct StreamSeen {
    bool opened = false;         // the client sent HEADERS on it
    std::size_t request_at = 0;  // the table size in effect then (an index into Session::table_sizes)
    std::string method;          // set when a template request opened it
    bool response = false;       // a final response head arrived
    bool ended = false;          // END_STREAM or RST_STREAM from the server
    bool reset = false;
    int status = 0;
    long long content_length = -1;
    std::uint64_t data = 0;    // DATA bytes, padding included (what flow control counts)
    std::uint64_t body = 0;    // DATA bytes without padding
    std::uint64_t credit = 0;  // the client's WINDOW_UPDATE increments for the stream
};

constexpr std::string_view kMethods[] = {"GET", "HEAD", "POST", "OPTIONS", "PUT", "DELETE", "CONNECT", "TRACE", "PATCH", "BREW"};
constexpr std::string_view kPaths[] = {
    "/", "/index.html", "/style.css", "/big.bin", "/dir/", "/dir", "/missing", "/.hidden", "/secret/x.txt",
    "/private/x.txt", "/old.bak", "/empty.txt", "/spa/route", "/app/x?y=1", "/a.php", "/p/b.php/extra",
    "/%2e%2e/%2e%2e/etc/passwd", "/a%2Fb", "*", "", "/index.html?q=%00", "//index.html", "/dir/../style.css",
    "/.well-known/x", "/STYLE.CSS", "/index.html#frag", "/\xff\xfe", "/a b"};
constexpr std::string_view kAuthorities[] = {"a.test", "b.test", "", "unknown.test", "a.test:18080", "A.TEST", "a.test.",
                                             "[::1]", "127.0.0.1", "a.test:x"};
constexpr std::string_view kRanges[] = {"bytes=0-99", "bytes=-10", "bytes=1000000-", "bytes=5-1", "bytes=0-0,2-3", "pages=1"};

struct Session {
    Env& e;
    const unsigned char* data;
    std::size_t size;
    std::size_t pos = 0;
    int fd = -1;  // the client's end
    bool reading = true;
    bool auto_window = false;
    bool eof = false;
    std::size_t preface_left = 0;  // preface bytes still to write before the frames the tracker reads
    std::string outbox;
    std::uint32_t next_id = 1;
    std::uint32_t last_id = 0;
    std::uint32_t authority_indexed = 0;  // a request stored :authority in the server's dynamic table

    // What the client sent, read back frame by frame as the server reads it.
    Splitter tx;
    std::vector<std::uint32_t> table_sizes{4096};
    std::uint32_t max_frame = 16384;
    std::uint64_t max_initial = 65535;
    std::uint64_t conn_credit = 0;
    unsigned client_settings = 0, client_pings = 0;
    std::uint32_t highest_opened = 0;
    std::set<std::uint32_t> prioritized;  // PRIORITY may name an idle stream; a self-dependency there is a stream error (RFC 9113 5.3.1)
    std::map<std::uint32_t, StreamSeen> streams;
    // The request blocks decoded as the server decodes them (same bytes, same order), for each
    // stream's method.
    hpack::Decoder request_decoder{4096};
    std::string sent_block, request_arena;
    std::uint32_t request_stream = 0;
    bool in_request_block = false;

    // What the server sent.
    Splitter rx;
    bool first_frame = true;
    hpack::Decoder decoder{4096};  // the server's encoder never asks for more (1 KB at most, design 6.2.1)
    std::string arena, block;
    bool in_block = false;
    std::uint32_t block_stream = 0;
    bool block_end_stream = false;
    std::uint64_t conn_data = 0;
    unsigned settings_acks = 0, ping_acks = 0;
    std::uint32_t goaway_last = 0x7fffffff;
    bool goaway_seen = false;

    Session(Env& env, const unsigned char* d, std::size_t n) : e(env), data(d), size(n) {
        rx.on_header = [this](const FrameHeader& h) {
            require(h.length <= max_frame, "a frame larger than the client's SETTINGS_MAX_FRAME_SIZE", h.stream_id);
            return true;
        };
    }

    unsigned next() { return pos < size ? data[pos++] : 0; }
    std::uint32_t next32() {
        std::uint32_t v = 0;
        for (int i = 0; i < 4; ++i) v = (v << 8) | next();
        return v;
    }
    std::string_view take(std::size_t n) {
        n = std::min(n, size - pos);
        const std::string_view out(reinterpret_cast<const char*>(data + pos), n);
        pos += n;
        return out;
    }

    // ---- sending ----

    void frame(FrameType type, std::uint8_t flags, std::uint32_t id, std::string_view payload) {
        if (outbox.size() > (1u << 20)) return;  // the server stopped reading long ago
        h2::append_frame_header(outbox, static_cast<std::uint32_t>(payload.size()), type, flags, id);
        outbox.append(payload);
    }
    void raw_frame(std::uint8_t type, std::uint8_t flags, std::uint32_t id, std::string_view payload) {
        if (outbox.size() > (1u << 20)) return;
        unsigned char head[h2::kFrameHeaderSize];
        head[0] = static_cast<unsigned char>(payload.size() >> 16);
        head[1] = static_cast<unsigned char>(payload.size() >> 8);
        head[2] = static_cast<unsigned char>(payload.size());
        head[3] = type;
        head[4] = flags;
        h2::write_u32(head + 5, id);
        outbox.append(reinterpret_cast<const char*>(head), sizeof head);
        outbox.append(payload);
    }

    std::size_t flush() {
        std::size_t total = 0;
        while (fd >= 0 && !outbox.empty()) {
            const ssize_t n = ::send(fd, outbox.data(), outbox.size(), MSG_NOSIGNAL | MSG_DONTWAIT);
            if (n <= 0) break;
            std::string_view sent(outbox.data(), static_cast<std::size_t>(n));
            const std::size_t skip = std::min(preface_left, sent.size());
            preface_left -= skip;
            sent.remove_prefix(skip);
            tx.feed(sent, [this](const FrameHeader& h, std::string_view p) { on_sent(h, p); });
            outbox.erase(0, static_cast<std::size_t>(n));
            total += static_cast<std::size_t>(n);
        }
        return total;
    }

    void on_sent(const FrameHeader& h, std::string_view p) {
        if (kTrace) std::fprintf(stderr, "> type %u flags %02x stream %u length %zu\n", h.type, h.flags, h.stream_id, p.size());
        switch (static_cast<FrameType>(h.type)) {
        case FrameType::headers: {
            if (h.stream_id != 0 && !streams[h.stream_id].opened) {
                StreamSeen& s = streams[h.stream_id];
                s.opened = true;
                s.request_at = table_sizes.size() - 1;
                highest_opened = std::max(highest_opened, h.stream_id);
            }
            std::size_t pad = 0;
            if ((h.flags & h2::flag::padded) && !p.empty()) {
                pad = static_cast<unsigned char>(p[0]);
                p.remove_prefix(1);
            }
            if ((h.flags & h2::flag::priority) && p.size() >= 5) p.remove_prefix(5);
            p.remove_suffix(std::min(pad, p.size()));
            sent_block.assign(p);
            request_stream = h.stream_id;
            in_request_block = (h.flags & h2::flag::end_headers) == 0;
            if (!in_request_block) decode_request();
            break;
        }
        case FrameType::continuation:
            if (in_request_block && h.stream_id == request_stream) {
                sent_block.append(p);
                in_request_block = (h.flags & h2::flag::end_headers) == 0;
                if (!in_request_block) decode_request();
            }
            break;
        case FrameType::settings:
            if ((h.flags & h2::flag::ack) == 0 && h.stream_id == 0 && p.size() % 6 == 0) {
                ++client_settings;
                for (std::size_t i = 0; i < p.size(); i += 6) {
                    const unsigned id = (static_cast<unsigned char>(p[i]) << 8) | static_cast<unsigned char>(p[i + 1]);
                    const std::uint32_t v = u32(p, i + 2);
                    if (id == 1) table_sizes.push_back(v);
                    if (id == 4) max_initial = std::max<std::uint64_t>(max_initial, v);
                    if (id == 5 && v >= 16384 && v <= 16777215) max_frame = std::max(max_frame, v);
                }
            }
            break;
        case FrameType::window_update:
            if (p.size() == 4) {
                const std::uint32_t inc = u32(p) & 0x7fffffff;
                if (h.stream_id == 0) conn_credit += inc;
                else streams[h.stream_id].credit += inc;
            }
            break;
        case FrameType::ping:
            if ((h.flags & h2::flag::ack) == 0 && h.stream_id == 0 && p.size() == 8) ++client_pings;
            break;
        case FrameType::priority:
            if (h.stream_id != 0) prioritized.insert(h.stream_id);
            break;
        default:
            break;
        }
    }

    // The request's method, when its block decodes and opened the stream (trailers do not count).
    void decode_request() {
        std::string method;
        request_arena.clear();
        request_decoder.decode(sent_block, request_arena, 1u << 16, [&](std::string_view n, std::string_view v) {
            if (n == ":method" && method.empty()) method = v;
            return true;
        });
        StreamSeen& s = streams[request_stream];
        if (s.method.empty()) s.method = method;
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
        if (first_frame) {
            require(type == FrameType::settings && (h.flags & h2::flag::ack) == 0, "the server's first frame is not SETTINGS");
            first_frame = false;
        }
        if (in_block) require(type == FrameType::continuation && id == block_stream, "a frame inside a header block", id);
        switch (type) {
        case FrameType::headers: {
            require(id % 2 == 1, "HEADERS on a stream id the client cannot open", id);
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
            require(id != 0, "DATA on stream 0");
            StreamSeen& s = streams[id];
            require(s.opened, "DATA on a stream the client never opened", id);
            require(s.response, "DATA before the response head", id);
            require(!s.ended, "DATA after the stream ended", id);
            std::size_t pad = 0;
            if (h.flags & h2::flag::padded) {
                require(!p.empty() && static_cast<unsigned char>(p[0]) < p.size(), "DATA padding longer than the frame", id);
                pad = 1 + static_cast<unsigned char>(p[0]);
            }
            conn_data += p.size();
            require(conn_data <= 65535 + conn_credit, "DATA beyond the connection window", id);
            s.data += p.size();
            require(s.data <= max_initial + s.credit, "DATA beyond the stream window", id);
            s.body += p.size() - pad;
            const bool end = (h.flags & h2::flag::end_stream) != 0;
            if (auto_window && !p.empty()) {
                frame(FrameType::window_update, 0, 0, increment(p.size()));
                if (!end) frame(FrameType::window_update, 0, id, increment(p.size()));
            }
            if (end) end_stream(s, id);
            break;
        }
        case FrameType::rst_stream: {
            require(p.size() == 4 && id != 0, "a malformed RST_STREAM", id);
            require(id <= highest_opened || prioritized.contains(id), "RST_STREAM on a stream the client never opened", id);
            StreamSeen& s = streams[id];
            s.ended = true;
            s.reset = true;
            break;
        }
        case FrameType::settings:
            require(id == 0, "SETTINGS on a stream");
            if (h.flags & h2::flag::ack) {
                require(p.empty(), "a SETTINGS acknowledgement with a payload");
                require(++settings_acks <= client_settings, "more SETTINGS acknowledgements than SETTINGS sent");
            } else {
                require(p.size() % 6 == 0, "SETTINGS of a length not a multiple of 6");
            }
            break;
        case FrameType::ping:
            require(id == 0 && p.size() == 8, "a malformed PING");
            if (h.flags & h2::flag::ack) require(++ping_acks <= client_pings, "more PING acknowledgements than PINGs sent");
            break;
        case FrameType::goaway: {
            require(id == 0 && p.size() >= 8, "a malformed GOAWAY");
            if (kTrace) std::fprintf(stderr, "< GOAWAY last %u code %u: %.*s\n", u32(p) & 0x7fffffff, u32(p, 4), static_cast<int>(p.size() - 8), p.data() + 8);
            const std::uint32_t last = u32(p) & 0x7fffffff;
            require(last <= goaway_last, "GOAWAY's last stream id went up");
            goaway_last = last;
            goaway_seen = true;
            break;
        }
        case FrameType::window_update: {
            require(p.size() == 4, "a malformed WINDOW_UPDATE", id);
            const std::uint32_t inc = u32(p) & 0x7fffffff;
            require(inc != 0, "WINDOW_UPDATE with no increment", id);
            break;
        }
        default:
            violation("a frame type the server never sends (PUSH_PROMISE, PRIORITY, unknown)", id);
        }
    }

    static std::string increment(std::size_t n) {
        std::string s(4, '\0');
        h2::write_u32(reinterpret_cast<unsigned char*>(s.data()), static_cast<std::uint32_t>(n));
        return s;
    }

    void on_block() {
        const std::uint32_t id = block_stream;
        StreamSeen& s = streams[id];
        if (kTrace) {
            std::string scratch;
            hpack::Decoder copy = decoder;
            copy.decode(block, scratch, 1u << 16, [&](std::string_view n, std::string_view v) {
                std::fprintf(stderr, "<   %.*s: %.*s\n", static_cast<int>(n.size()), n.data(), static_cast<int>(v.size()), v.data());
                return true;
            });
        }
        require(s.opened, "a response on a stream the client never opened", id);
        require(!s.ended, "a header block after the stream ended", id);
        require(!goaway_seen || id <= goaway_last, "a response on a stream the GOAWAY said was not processed", id);
        int status = 0;
        long long length = -1;
        bool first = true;
        arena.clear();
        const auto result = decoder.decode(block, arena, 1u << 16, [&](std::string_view n, std::string_view v) {
            if (n == ":status") {
                require(first, ":status not the first field", id);
                require(v.size() == 3 && v[0] >= '1' && v[0] <= '5' && v[1] >= '0' && v[1] <= '9' && v[2] >= '0' && v[2] <= '9',
                        "a :status that is not three digits", id);
                status = (v[0] - '0') * 100 + (v[1] - '0') * 10 + (v[2] - '0');
            } else {
                require(n.empty() || n[0] != ':', "a pseudo-field other than :status in a response", id);
                for (const char c : n) require(!(c >= 'A' && c <= 'Z'), "an upper-case field name", id);
                require(n != "connection" && n != "keep-alive" && n != "proxy-connection" && n != "transfer-encoding" && n != "upgrade",
                        "a connection-specific field", id);
                if (n == "content-length") {
                    require(length < 0, "two content-length fields", id);
                    length = 0;
                    for (const char c : v) {
                        require(c >= '0' && c <= '9' && length < (1LL << 50), "a content-length that is not a number", id);
                        length = length * 10 + (c - '0');
                    }
                }
            }
            first = false;
            return true;
        });
        require(result == hpack::Decoder::Result::ok, "a header block the client cannot decode", id);
        if (kTrace) std::fprintf(stderr, "< stream %u :status %d content-length %lld\n", id, status, length);
        // The table may only grow back to what the client allowed while the request was in flight
        // (the size in effect when it was sent, or any the client set after): a lowered size is
        // signalled at the start of the first block encoded after the server read it.
        std::uint32_t allowed = table_sizes[s.request_at];
        for (std::size_t i = s.request_at + 1; i < table_sizes.size(); ++i) allowed = std::max(allowed, table_sizes[i]);
        require(decoder.table_limit() <= allowed && decoder.table_size() <= decoder.table_limit(),
                "a dynamic table above the size the client allowed", id);
        if (!s.response) {
            require(status != 0 && status != 101, "a response head without a valid :status", id);
            if (status < 200) {
                require(!block_end_stream, "an informational response that ends the stream", id);
            } else {
                s.response = true;
                s.status = status;
                s.content_length = length;
            }
        } else {
            require(status == 0 && block_end_stream, "a second header block that is not trailers", id);
        }
        if (block_end_stream) end_stream(s, id);
    }

    static void end_stream(StreamSeen& s, std::uint32_t id) {
        s.ended = true;
        if (!s.response) return;
        if (s.method == "HEAD" || s.status == 204 || s.status == 304)
            require(s.body == 0, "a body on a response that has none (HEAD, 204, 304)", id);
        else if (s.content_length >= 0)
            require(s.body == static_cast<std::uint64_t>(s.content_length), "DATA that does not add up to content-length", id);
    }

    // ---- the event loop ----

    void pump() {
        for (int round = 0; round < 512; ++round) {
            const std::size_t wrote = flush();
            e.worker->ctx.restart();
            const std::size_t ran = e.worker->ctx.poll();
            const std::size_t got = reading ? read_server() : 0;
            if (wrote == 0 && ran == 0 && got == 0) return;
        }
    }

    // ---- the script ----

    std::uint32_t stream_id(unsigned sel) {
        switch (sel % 8) {
        case 0: return 0;
        case 1: return last_id ? last_id : 1;
        case 2: return next_id;
        case 3: return 2;
        case 4: return 1;
        case 5: return 0x7fffffff;
        case 6: return last_id > 2 ? last_id - 2 : 3;
        default: return (sel / 8) * 2 + 1;
        }
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

    std::string request_block(std::string_view& method) {
        const unsigned m = next(), p = next(), a = next(), x = next(), form = next();
        method = kMethods[m % std::size(kMethods)];
        std::string b;
        if (method == "GET" && (form & 1)) b.push_back(static_cast<char>(0x82));  // static index 2
        else literal(b, ":method", method);
        switch ((form >> 1) & 3) {
        case 0: b.push_back(static_cast<char>(0x86)); break;  // :scheme http
        case 1: literal(b, ":scheme", "https"); break;
        case 2: break;                                        // missing
        default: literal(b, ":scheme", "ftp"); break;
        }
        const std::string_view path = kPaths[p % std::size(kPaths)];
        if (path == "/" && (form & 8)) b.push_back(static_cast<char>(0x84));  // static index 4
        else if (!(form & 0x10) || method != "CONNECT") literal(b, ":path", path);
        const std::string_view authority = kAuthorities[a % std::size(kAuthorities)];
        if ((form & 0x20) && authority_indexed) {
            b.push_back(static_cast<char>(0xbe));  // dynamic index 62: the newest entry the server's table holds
        } else if (form & 0x40) {
            b.push_back(0x41);  // literal with incremental indexing, name :authority (static index 1)
            integer(b, authority.size(), 7, 0);
            b.append(authority);
            authority_indexed = next_id;
        } else if (form & 0x80) {
            literal(b, "host", authority);
        } else {
            literal(b, ":authority", authority);
        }
        if (x & 0x01) literal(b, "range", kRanges[next() % std::size(kRanges)]);
        if (x & 0x02) literal(b, (next() & 1) ? "if-none-match" : "if-modified-since", (next() & 1) ? "*" : "Thu, 01 Jan 2099 00:00:00 GMT");
        if (x & 0x04) literal(b, "accept-encoding", (next() & 1) ? "br, gzip" : "gzip;q=0, br;q=0.5");
        if (x & 0x08) literal(b, "content-length", std::to_string(next() * 512));
        if (x & 0x10) (next() & 1) ? literal(b, "te", "trailers") : literal(b, "expect", "100-continue");
        if (x & 0x20) literal(b, "connection", "keep-alive");
        if (x & 0x40) {
            literal(b, "cookie", "a=1");
            literal(b, "cookie", "b=2");
        }
        if (x & 0x80) literal(b, (next() & 1) ? "X-Upper" : "x-forwarded-for", take(next() % 32));
        return b;
    }

    void request(unsigned op) {
        const std::uint32_t id = next_id;
        std::string_view method;
        const std::string b = request_block(method);
        next_id += 2;
        last_id = id;
        std::uint8_t flags = 0;
        std::string head;
        if (!(op & 0x10)) flags |= h2::flag::end_stream;
        if (op & 0x40) {  // padded
            flags |= h2::flag::padded;
            head.push_back(static_cast<char>(next() % 64));
        }
        if (op & 0x80) {  // a priority block: deprecated, read and ignored
            flags |= h2::flag::priority;
            std::string priority(take(5));
            priority.resize(5, '\0');
            head += priority;
        }
        std::string pad(!head.empty() && (flags & h2::flag::padded) ? static_cast<unsigned char>(head[0]) : 0, '\0');
        if (!(op & 0x20)) {
            frame(FrameType::headers, flags | h2::flag::end_headers, id, head + b + pad);
            return;
        }
        // Split across CONTINUATION frames.
        const std::size_t chunk = next() % 16 + 1;
        std::size_t at = std::min(chunk, b.size());
        frame(FrameType::headers, flags, id, head + b.substr(0, at) + pad);
        while (at < b.size()) {
            const std::size_t n = std::min(chunk, b.size() - at);
            frame(FrameType::continuation, at + n == b.size() ? h2::flag::end_headers : 0, id, b.substr(at, n));
            at += n;
        }
    }

    void step(unsigned op) {
        switch (op % 16) {
        case 0: case 1: case 2: case 3:
            request(op);
            break;
        case 4: {  // DATA
            const std::uint32_t id = stream_id(next());
            const std::size_t len = next() * 64;
            std::uint8_t flags = (op & 0x10) ? h2::flag::end_stream : 0;
            std::string payload(len, 'x');
            if ((op & 0x20) && !payload.empty()) {
                flags |= h2::flag::padded;
                payload[0] = static_cast<char>(std::min<std::size_t>(next(), payload.size() - 1));
            }
            frame(FrameType::data, flags, id, payload);
            break;
        }
        case 5: {  // SETTINGS
            static constexpr std::uint16_t kIds[] = {1, 2, 3, 4, 5, 6, 8, 9, 0xff};
            std::string payload;
            for (unsigned n = next() % 5; n > 0; --n) {
                const std::uint16_t sid = kIds[next() % std::size(kIds)];
                payload.push_back(static_cast<char>(sid >> 8));
                payload.push_back(static_cast<char>(sid));
                std::uint32_t v = next32();
                if (op & 0x20) v %= 70000;  // the useful range: sizes and windows around their defaults
                payload.append(increment(v));
            }
            frame(FrameType::settings, (op & 0x10) ? h2::flag::ack : 0, (op & 0x40) ? 1 : 0, payload);
            break;
        }
        case 6: {  // WINDOW_UPDATE
            const std::uint32_t id = stream_id(next());
            std::uint32_t inc = next32();
            if (op & 0x10) inc %= 1u << 20;
            frame(FrameType::window_update, 0, id, increment(inc));
            break;
        }
        case 7:  // RST_STREAM
            frame(FrameType::rst_stream, 0, stream_id(next()), increment(next() % 16));
            break;
        case 8:  // PING
        {
            std::string payload(take(8));
            payload.resize(8, '\0');
            frame(FrameType::ping, (op & 0x10) ? h2::flag::ack : 0, 0, payload);
            break;
        }
        case 9: {  // PRIORITY
            std::string payload(take(5));
            payload.resize(5, '\0');
            frame(FrameType::priority, 0, stream_id(next()), payload);
            break;
        }
        case 10: {  // GOAWAY from the client
            std::string payload = increment(stream_id(next())) + increment(next() % 16);
            frame(FrameType::goaway, 0, 0, payload);
            break;
        }
        case 11: {  // a frame of any type and flags
            const std::uint8_t type = static_cast<std::uint8_t>(next());
            const std::uint8_t flags = static_cast<std::uint8_t>(next());
            const std::uint32_t id = stream_id(next());
            raw_frame(type, flags, id, take(next() * 4));
            break;
        }
        case 12:  // bytes as they are
            if (outbox.size() < (1u << 20)) outbox.append(take(next()));
            break;
        case 13:
            reading = !reading;
            break;
        case 14:
            auto_window = !auto_window;
            break;
        default: {  // time: the connection made older, then what its timer does
            const auto d = std::chrono::milliseconds(500) * (next() % 64 + 1);
            if (auto c = weak.lock()) c->fuzz_age(d);
            break;
        }
        }
    }

    std::weak_ptr<Conn> weak;
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const unsigned char* data, std::size_t size) {
    if (size < 1) return 0;
    Env& e = env();
    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0) return 0;
    Session s(e, data, size);
    const unsigned setup = s.next();
    // The server's send buffer: a small one fills with a 100 KB answer (the writer's backpressure).
    static constexpr int kSendBuffers[] = {0, 4096, 16384, 65536};
    if (const int sb = kSendBuffers[setup & 3]) ::setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sb, sizeof sb);
    s.auto_window = (setup & 4) != 0;
    s.fd = sv[1];
    asio::error_code ec;
    asio::ip::tcp::socket sock(e.worker->ctx);
    sock.assign(asio::ip::tcp::v4(), sv[0], ec);
    if (ec) {
        ::close(sv[0]);
        ::close(sv[1]);
        return 0;
    }
    // The preface as h2c hands it over (read by the HTTP/1 connection), or from the socket as
    // after ALPN.
    const bool handed_over = (setup & 8) == 0;
    if (!handed_over) {
        s.outbox.assign(h2::kPreface);
        s.preface_left = h2::kPreface.size();
    }
    // The client's SETTINGS completes its preface (RFC 9113 3.4); one setup bit leaves it out.
    if ((setup & 0x10) == 0) s.frame(FrameType::settings, 0, 0, {});
    {
        auto conn = std::make_shared<Conn>(std::move(sock), *e.worker, e.gen, e.listener, e.gen->cfg, *e.dispatcher, nullptr,
                                           handed_over ? h2::kPreface : std::string_view{});
        s.weak = conn;
        conn->start();
    }
    s.pump();
    for (int steps = 0; steps < 200 && s.pos < s.size; ++steps) {
        s.step(s.next());
        s.pump();
    }
    // The client goes away: the connection must follow, at the latest when its timeouts run.
    ::close(s.fd);
    s.fd = -1;
    s.pump();
    for (int i = 0; i < 6 && !s.weak.expired(); ++i) {
        if (auto c = s.weak.lock()) c->fuzz_age(std::chrono::seconds(4 * 15 + 1));
        s.pump();
    }
    require(s.weak.expired(), "the connection outlived its client and its timeouts");
    require(e.worker->connections.load() == 0 && e.worker->idle.load() == 0, "the worker's counters did not return to zero");
    return 0;
}
