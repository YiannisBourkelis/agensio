// One HTTP/2 client connection (RFC 9113): the I/O loop, the frame dispatch, the stream
// table, the request assembly from HPACK, flow control on the receiving side, the
// timeouts, and the two misbehaviour budgets (docs/design-http2.md section 6). Created by
// Http1Connection when the handshake selected "h2" through ALPN, or when a plain listener
// with "h2c" in [server] protocols received the connection preface. Every stream drives
// the same Dispatcher and handlers as HTTP/1; the Http2Writer turns their Responses into
// frames. Nothing here is shared with HTTP/1 at run time: HTTP/1 pays for none of it.
#pragma once

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/body.hpp"
#include "core/fields.hpp"
#include "core/forwarded.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "handlers/dispatch.hpp"
#include "http2/frame.hpp"
#include "http2/hpack.hpp"
#include "http2/settings.hpp"
#include "http2/stream.hpp"
#include "http2/writer.hpp"
#include "server.hpp"
#include "services/log.hpp"

namespace agensio::h2 {

template <class Socket>
class Http2Connection : public std::enable_shared_from_this<Http2Connection<Socket>>, private BodyOwner {
public:
    static constexpr std::uint32_t kMaxFramePayload = 16384;         // what we advertise and accept
    static constexpr std::uint32_t kHeaderTableSize = 4096;          // SETTINGS_HEADER_TABLE_SIZE
    static constexpr std::uint32_t kConnectionWindow = 1u << 20;     // what we let the peer send in total
    static constexpr std::uint32_t kStreamWindowMax = 1u << 20;      // the most one stream is granted for a body
    static constexpr unsigned kMaxContinuations = 8;                 // CONTINUATION frames per header block
    static constexpr unsigned kGlitchBudget = 100;                   // misbehaviour points before the close
    static constexpr unsigned kGlitchSoft = 75;                      // GOAWAY first: a broken client may reconnect
    static constexpr unsigned kControlRate = 10;                     // PING / SETTINGS per second before they count
    static constexpr unsigned kRecentClosed = 8;                     // ids of streams we reset, tolerated for a while
    static constexpr std::uint64_t kDrainAfterResponse = 65536;      // body bytes still taken after a response; more is cut short
    static constexpr unsigned kInlineBudget = 8;                     // reads completed inline before yielding to the loop

    // `initial` holds bytes the HTTP/1 connection had already read (the preface and
    // whatever followed, h2c); on ALPN it is empty.
    Http2Connection(Socket&& socket, Worker& worker, std::shared_ptr<const Generation> gen, const Listener* listener,
                    const Config& cfg, Dispatcher& dispatcher, std::shared_ptr<const CertNames> cert_names,
                    std::string_view initial)
        : socket_(std::move(socket)),
          worker_(worker),
          gen_(std::move(gen)),
          listener_(listener),
          cert_names_(std::move(cert_names)),
          live_(&gen_->cfg),
          cfg_(cfg),
          dispatcher_(dispatcher),
          timer_(worker.ctx),
          idle_timeout_(std::chrono::seconds(cfg.idle_timeout_s)),
          body_timeout_(std::chrono::seconds(cfg.body_timeout_s)),
          in_(kMaxFramePayload + kFrameHeaderSize),
          decoder_(kHeaderTableSize),
          writer_(socket_, *this, worker.ctx, cfg) {
        worker_.connections.fetch_add(1, std::memory_order_relaxed);
        if (initial.size() <= in_.size()) {
            std::memcpy(in_.data(), initial.data(), initial.size());
            in_len_ = initial.size();
        }
    }
    Http2Connection(const Http2Connection&) = delete;
    Http2Connection& operator=(const Http2Connection&) = delete;
    ~Http2Connection() override { worker_.connections.fetch_sub(1, std::memory_order_relaxed); }

    void start() {
        last_activity_ = std::chrono::steady_clock::now();
        arm_timer();
        // Our SETTINGS and the connection window go first (RFC 9113 3.4).
        std::string frames;
        const SettingPair pairs[] = {
            {setting_header_table_size, kHeaderTableSize},
            {setting_max_concurrent_streams, live_->http2.max_concurrent_streams},
            {setting_initial_window_size, kDefaultWindow},
            {setting_max_frame_size, kMaxFramePayload},
            {setting_max_header_list_size, static_cast<std::uint32_t>(live_->max_header_size)},
            {setting_no_rfc7540_priorities, 1},
        };
        append_settings(frames, pairs);
        append_window_update(frames, 0, kConnectionWindow - kDefaultWindow);
        conn_recv_grant_ = kConnectionWindow;
        writer_.control(frames);
        if (in_len_ > 0) process_frames();
        else do_read();
    }

    // ---- what the writer calls ----

    WorkerState& worker_state() noexcept { return worker_.state; }
    void touch() noexcept { last_activity_ = std::chrono::steady_clock::now(); }

    // A stream's END_STREAM reached the kernel: log it, tell a client still sending its
    // body to stop (RFC 9113 8.1.1: RST_STREAM(NO_ERROR) after a complete response), free it.
    void on_stream_written(H2Stream& s) {
        log_request(s);
        if (s.has_body && !s.body_done && s.state == StreamState::open) {
            // The request body is still coming. A small remainder is taken and dropped so the
            // client's view of the stream stays clean; a large or unbounded one is cut short
            // with RST_STREAM(NO_ERROR), which RFC 9113 8.1.1 provides for this case.
            const bool large = s.body_received > s.body_limit ||
                               (s.length_known && s.content_length - s.body_received > kDrainAfterResponse);
            if (!large) {
                s.state = StreamState::half_closed_local;
                s.since = std::chrono::steady_clock::now();
                maybe_finish();
                return;
            }
            send_rst(s.id, ErrorCode::no_error, "response complete before the request body");
        }
        close_stream(s);
        maybe_finish();
    }

    // The writer finished a cycle with nothing more to send.
    void after_write() {
        if (closing_after_write_ && writer_.idle()) begin_linger();
    }

    // A body source failed or ended short: the client sees the stream cut, not a false end.
    void on_stream_failed(H2Stream& s) {
        if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
            log->info("http2 " + remote_text() + " stream " + std::to_string(s.id) + ": response body failed mid-stream");
        send_rst(s.id, ErrorCode::internal_error, "");
        log_request(s);
        close_stream(s);
        maybe_finish();
    }

    // A stream closed while its bytes or its pull were still in flight: back to the pool now.
    void release_deferred(H2Stream& s) {
        if (writer_.in_flight(s) || s.pulling) return;
        s.defer_release = false;
        release(s);
        maybe_finish();
    }

    void close() {
        if (closed_) return;
        closed_ = true;
        asio::error_code ec;
        timer_.cancel();
        writer_.reset();
        for (auto& s : active_) {
            ++s->gen;
            if (s->upstream) {
                s->upstream->cancel();
                s->upstream.reset();
            }
            if (s->responded && !s->logged) log_request(*s);  // the client went away mid-response
            if (s->pending_handler) {
                auto h = std::move(s->pending_handler);
                s->pending_handler = nullptr;
                h(asio::error::operation_aborted, 0);
            }
        }
        if (lowest().is_open()) {
            if constexpr (IsTlsStream<Socket>::value) socket_.shutdown_notify();
            lowest().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            lowest().close(ec);
        }
    }

private:
    // ---- reading ----

    auto& lowest() { return socket_.lowest_layer(); }
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(worker_.ctx.get_executor(), std::forward<F>(f));
    }

    void do_read() {
        if (closed_ || read_pending_) return;
        if (in_len_ >= in_.size()) {  // cannot happen: a frame over the limit is refused before it is buffered
            connection_error(ErrorCode::internal_error, "receive buffer full");
            return;
        }
        read_pending_ = true;
        auto self = this->shared_from_this();
        socket_.async_read_some(asio::buffer(in_.data() + in_len_, in_.size() - in_len_),
                                immediate([self](const asio::error_code& ec, std::size_t n) { self->on_read(ec, n); }));
    }

    void on_read(const asio::error_code& ec, std::size_t n) {
        read_pending_ = false;
        if (closed_) return;
        if (ec) {
            close();  // the client is gone: every exchange in flight is cancelled with it
            return;
        }
        if (linger_) {  // waiting for the peer to take the GOAWAY and hang up
            in_len_ = 0;
            do_read();
            return;
        }
        in_len_ += n;
        last_activity_ = std::chrono::steady_clock::now();
        process_frames();
    }

    // Handles every complete frame in the buffer, keeps the partial one, reads on.
    void process_frames() {
        std::size_t pos = 0;
        if (!preface_seen_) {
            if (in_len_ < kPreface.size()) {
                if (std::memcmp(in_.data(), kPreface.data(), in_len_) != 0) {
                    connection_error(ErrorCode::protocol_error, "not the HTTP/2 connection preface");
                    return;
                }
                do_read();
                return;
            }
            if (std::memcmp(in_.data(), kPreface.data(), kPreface.size()) != 0) {
                connection_error(ErrorCode::protocol_error, "not the HTTP/2 connection preface");
                return;
            }
            preface_seen_ = true;
            pos = kPreface.size();
        }
        // A connection error or a graceful close decided inside a handler ends the loop: the
        // lingering close owns the buffer and the reads from then on (the sanitizer caught the
        // old loop reading a header past the buffer after in_len_ had been reset under it).
        while (!closed_ && !closing_after_write_ && !linger_ && in_len_ - pos >= kFrameHeaderSize) {
            const auto* p = reinterpret_cast<const unsigned char*>(in_.data() + pos);  // NOLINT: bytes
            const FrameHeader h = read_frame_header(p);
            if (h.length > kMaxFramePayload) {
                connection_error(ErrorCode::frame_size_error, "frame larger than SETTINGS_MAX_FRAME_SIZE");
                return;
            }
            if (in_len_ - pos < kFrameHeaderSize + h.length) break;  // wait for the rest
            handle_frame(h, p + kFrameHeaderSize);
            pos += kFrameHeaderSize + h.length;
        }
        if (closed_ || closing_after_write_ || linger_) return;
        if (pos > 0) {
            if (pos < in_len_) std::memmove(in_.data(), in_.data() + pos, in_len_ - pos);
            in_len_ -= pos;
        }
        // A socket that is always readable completes every read inline, and each completion
        // lands here again: every kInlineBudget reads the next one is posted, which bounds
        // the stack and lets the worker's other connections run (HTTP/1 does the same per
        // response; the sanitizer found the unbounded form under h2load as a stack overflow).
        if (++inline_reads_ >= kInlineBudget) {
            inline_reads_ = 0;
            auto self = this->shared_from_this();
            asio::post(worker_.ctx, [self] { self->do_read(); });
            return;
        }
        do_read();
    }

    // ---- frames ----

    void handle_frame(const FrameHeader& h, const unsigned char* payload) {
        // The first frame must be SETTINGS; a header block in progress admits only its CONTINUATION.
        if (!settings_seen_ && h.type != static_cast<std::uint8_t>(FrameType::settings)) {
            connection_error(ErrorCode::protocol_error, "the first frame was not SETTINGS");
            return;
        }
        if (block_stream_ != 0 && (h.type != static_cast<std::uint8_t>(FrameType::continuation) || h.stream_id != block_stream_)) {
            connection_error(ErrorCode::protocol_error, "a frame interrupted a header block");
            return;
        }
        switch (static_cast<FrameType>(h.type)) {
            case FrameType::data: on_data(h, payload); break;
            case FrameType::headers: on_headers(h, payload); break;
            case FrameType::priority:
                if (h.stream_id == 0) return connection_error(ErrorCode::protocol_error, "PRIORITY on stream 0");
                if (h.length != 5) return connection_error(ErrorCode::frame_size_error, "PRIORITY of the wrong length");
                if ((read_u32(payload) & kMaxStreamId) == h.stream_id) {  // RFC 9113 5.3.1
                    if (H2Stream* s = find(h.stream_id)) stream_error(*s, ErrorCode::protocol_error, "stream depends on itself");
                    else send_rst(h.stream_id, ErrorCode::protocol_error, "stream depends on itself"), glitch({});
                    break;
                }
                glitch("PRIORITY frame (deprecated, ignored)");  // RFC 9113 5.3.2: no tree here
                break;
            case FrameType::rst_stream: on_rst_stream(h, payload); break;
            case FrameType::settings: on_settings(h, payload); break;
            case FrameType::push_promise: connection_error(ErrorCode::protocol_error, "PUSH_PROMISE from a client"); break;
            case FrameType::ping: on_ping(h, payload); break;
            case FrameType::goaway: on_goaway(h, payload); break;
            case FrameType::window_update: on_window_update(h, payload); break;
            case FrameType::continuation: on_continuation(h, payload); break;
            default: break;  // unknown types are ignored (RFC 9113 4.1)
        }
    }

    void on_settings(const FrameHeader& h, const unsigned char* p) {
        if (h.stream_id != 0) return connection_error(ErrorCode::protocol_error, "SETTINGS on a stream");
        if (h.flags & flag::ack) {
            if (h.length != 0) return connection_error(ErrorCode::frame_size_error, "SETTINGS ACK with a payload");
            settings_acked_ = true;
            return;
        }
        if (h.length % 6 != 0) return connection_error(ErrorCode::frame_size_error, "SETTINGS of the wrong length");
        settings_seen_ = true;
        if (rate(settings_rate_, "SETTINGS beyond the rate")) return;
        for (std::uint32_t i = 0; i < h.length; i += 6) {
            const std::uint16_t id = static_cast<std::uint16_t>((p[i] << 8) | p[i + 1]);
            const std::uint32_t value = read_u32(p + i + 2);
            const std::uint32_t old_window = peer_.initial_window_size;
            const ErrorCode ec = peer_.apply(id, value);
            if (ec != ErrorCode::no_error) return connection_error(ec, "SETTINGS value out of range");
            if (id == setting_initial_window_size && value != old_window) {
                // Every stream's window moves by the difference (RFC 9113 6.9.2).
                const std::int64_t delta = static_cast<std::int64_t>(value) - static_cast<std::int64_t>(old_window);
                for (auto& s : active_) {
                    const std::int64_t w = static_cast<std::int64_t>(s->send_window) + delta;
                    if (w > kMaxWindow) return connection_error(ErrorCode::flow_control_error, "window overflow");
                    s->send_window = static_cast<std::int32_t>(w);
                    if (w > 0 && s->responded && !s->finished) writer_.enqueue(*s);
                }
            }
            if (id == setting_max_frame_size) writer_.set_max_frame(value);
        }
        std::string ack;
        append_settings_ack(ack);
        writer_.control(ack);
    }

    void on_ping(const FrameHeader& h, const unsigned char* p) {
        if (h.stream_id != 0) return connection_error(ErrorCode::protocol_error, "PING on a stream");
        if (h.length != 8) return connection_error(ErrorCode::frame_size_error, "PING of the wrong length");
        if (h.flags & flag::ack) return;  // we never send PINGs
        if (rate(ping_rate_, "PING beyond the rate")) return;
        std::string ack;
        append_ping_ack(ack, p);
        writer_.control(ack);
    }

    void on_goaway(const FrameHeader& h, const unsigned char*) {
        if (h.stream_id != 0) return connection_error(ErrorCode::protocol_error, "GOAWAY on a stream");
        if (h.length < 8) return connection_error(ErrorCode::frame_size_error, "GOAWAY too short");
        // The client is leaving: no new streams; what is open finishes, then we close.
        going_away_ = true;
        maybe_finish();
    }

    void on_window_update(const FrameHeader& h, const unsigned char* p) {
        if (h.length != 4) return connection_error(ErrorCode::frame_size_error, "WINDOW_UPDATE of the wrong length");
        const std::uint32_t inc = read_u32(p) & kMaxStreamId;
        if (h.stream_id == 0) {
            if (inc == 0) return connection_error(ErrorCode::protocol_error, "WINDOW_UPDATE of zero on the connection");
            const std::int64_t w = static_cast<std::int64_t>(writer_.conn_window()) + inc;
            if (w > kMaxWindow) return connection_error(ErrorCode::flow_control_error, "connection window overflow");
            writer_.set_conn_window(static_cast<std::int32_t>(w));
            if (inc < 1024) glitch("WINDOW_UPDATE below 1 KB");
            for (auto& s : active_)
                if (s->responded && !s->finished && s->send_window > 0) writer_.enqueue(*s);
            return;
        }
        H2Stream* s = find(h.stream_id);
        if (!s) {
            if (h.stream_id > last_stream_id_) return connection_error(ErrorCode::protocol_error, "WINDOW_UPDATE on an idle stream");
            if (inc == 0) {
                send_rst(h.stream_id, ErrorCode::protocol_error, "WINDOW_UPDATE of zero");
                glitch({});
                count_reset();
            } else if (!recently_closed(h.stream_id)) {
                glitch("WINDOW_UPDATE on a closed stream");
            }
            return;
        }
        if (inc == 0) {  // a stream error the client provoked: it counts as a reset (MadeYouReset)
            stream_error(*s, ErrorCode::protocol_error, "WINDOW_UPDATE of zero");
            return;
        }
        const std::int64_t w = static_cast<std::int64_t>(s->send_window) + inc;
        if (w > kMaxWindow) {
            stream_error(*s, ErrorCode::flow_control_error, "stream window overflow");
            return;
        }
        s->send_window = static_cast<std::int32_t>(w);
        if (inc >= 1024) s->since = std::chrono::steady_clock::now();  // progress; a dribble is not
        else glitch("WINDOW_UPDATE below 1 KB");
        if (s->responded && !s->finished) writer_.enqueue(*s);
    }

    void on_rst_stream(const FrameHeader& h, const unsigned char* p) {
        if (h.stream_id == 0) return connection_error(ErrorCode::protocol_error, "RST_STREAM on stream 0");
        if (h.length != 4) return connection_error(ErrorCode::frame_size_error, "RST_STREAM of the wrong length");
        H2Stream* s = find(h.stream_id);
        if (!s) {
            if (h.stream_id > last_stream_id_) return connection_error(ErrorCode::protocol_error, "RST_STREAM on an idle stream");
            if (!recently_closed(h.stream_id)) glitch("RST_STREAM on a closed stream");
            return;
        }
        const ErrorCode code = static_cast<ErrorCode>(read_u32(p));
        if (!s->responded) count_reset();  // cancelled before we answered: the Rapid Reset shape
        if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
            log->info("http2 " + remote_text() + " stream " + std::to_string(s->id) + ": reset by the client (" +
                      std::string(error_name(code)) + ")");
        if (s->responded && !s->logged) log_request(*s);
        close_stream(*s);
        maybe_finish();
    }

    void on_headers(const FrameHeader& h, const unsigned char* p) {
        if (h.stream_id == 0) return connection_error(ErrorCode::protocol_error, "HEADERS on stream 0");
        std::size_t off = 0, len = h.length;
        if (h.flags & flag::padded) {
            if (len < 1) return connection_error(ErrorCode::frame_size_error, "HEADERS padding");
            const std::size_t pad = p[0];
            off = 1;
            if (pad + 1 > len) return connection_error(ErrorCode::protocol_error, "HEADERS padding longer than the frame");
            len -= pad + 1;
        }
        bool self_dependent = false;
        if (h.flags & flag::priority) {  // deprecated: skipped, except that a stream may not depend on itself
            if (len < 5) return connection_error(ErrorCode::frame_size_error, "HEADERS priority fields");
            self_dependent = (read_u32(p + off) & kMaxStreamId) == h.stream_id;
            off += 5;
            len -= 5;
        }
        H2Stream* existing = find(h.stream_id);
        if (existing) {
            // A second HEADERS on an open stream is the trailers: only with END_STREAM, only
            // after a body was announced.
            if ((existing->state != StreamState::open && existing->state != StreamState::half_closed_local) || !(h.flags & flag::end_stream)) {
                stream_error(*existing, ErrorCode::protocol_error, "HEADERS on a stream that is not expecting trailers");
                block_kind_ = BlockKind::discard;  // the block still has to be decoded to keep HPACK in step
            } else {
                block_kind_ = BlockKind::trailers;
            }
        } else {
            if ((h.stream_id & 1) == 0) return connection_error(ErrorCode::protocol_error, "even stream id from a client");
            if (h.stream_id <= last_stream_id_)
                return connection_error(ErrorCode::protocol_error, "stream id lower than one already used");
            last_stream_id_ = h.stream_id;
            block_kind_ = BlockKind::request;
            if (self_dependent) {  // RFC 9113 5.3.1: a stream error; the block is still decoded
                send_rst(h.stream_id, ErrorCode::protocol_error, "stream depends on itself");
                glitch({});
                count_reset();
                block_kind_ = BlockKind::discard;
            }
        }
        block_stream_ = h.stream_id;
        block_end_stream_ = (h.flags & flag::end_stream) != 0;
        block_frames_ = 0;
        block_.clear();
        if (!append_block(p + off, len)) return;
        if (h.flags & flag::end_headers) finish_block();
        else block_since_ = std::chrono::steady_clock::now();
    }

    void on_continuation(const FrameHeader& h, const unsigned char* p) {
        if (block_stream_ == 0 || h.stream_id != block_stream_)
            return connection_error(ErrorCode::protocol_error, "CONTINUATION without a HEADERS");
        if (++block_frames_ > kMaxContinuations)
            return connection_error(ErrorCode::enhance_your_calm, "too many CONTINUATION frames for one header block");
        if (h.length == 0) glitch("empty CONTINUATION");
        if (!append_block(p, h.length)) return;
        if (h.flags & flag::end_headers) finish_block();
    }

    bool append_block(const unsigned char* p, std::size_t len) {
        if (block_.size() + len > live_->max_header_size) {
            connection_error(ErrorCode::enhance_your_calm, "compressed header block over max_header_size");
            return false;
        }
        block_.append(reinterpret_cast<const char*>(p), len);  // NOLINT: bytes to chars
        return true;
    }

    // The block is complete: decode it (always, to keep the HPACK state in step), then act.
    void finish_block() {
        const std::uint32_t id = block_stream_;
        block_stream_ = 0;
        switch (block_kind_) {
            case BlockKind::request: {
                H2Stream* s = open_stream(id);
                if (!s) {  // refused or GOAWAY: decode into scratch so the tables stay in step
                    std::string arena;
                    decoder_.decode(block_, arena, live_->max_header_size, [](std::string_view, std::string_view) { return true; });
                    return;
                }
                begin_request(*s);
                return;
            }
            case BlockKind::trailers:
            case BlockKind::discard: {
                std::string arena;
                const auto r = decoder_.decode(block_, arena, live_->max_header_size, [](std::string_view, std::string_view) { return true; });
                if (r == hpack::Decoder::Result::malformed) return connection_error(ErrorCode::compression_error, "HPACK error in trailers");
                if (r == hpack::Decoder::Result::too_large) return connection_error(ErrorCode::enhance_your_calm, "trailers over max_header_size");
                if (block_kind_ == BlockKind::trailers) {
                    if (H2Stream* s = find(id)) {
                        if (s->state == StreamState::half_closed_local) {
                            close_stream(*s);
                            maybe_finish();
                        } else {
                            s->state = StreamState::half_closed_remote;
                            end_of_body(*s);
                        }
                    }
                }
                return;
            }
        }
    }

    // ---- streams ----

    H2Stream* find(std::uint32_t id) noexcept {
        for (auto& s : active_)
            if (s->id == id) return s.get();
        return nullptr;
    }

    bool recently_closed(std::uint32_t id) const noexcept {
        for (const std::uint32_t r : recent_closed_)
            if (r == id) return true;
        return false;
    }

    // A new stream for a request block, or nullptr (refused: RST_STREAM sent) when the
    // client is over its concurrency, the connection is going away, or its cap is reached.
    H2Stream* open_stream(std::uint32_t id) {
        if (going_away_) {  // the client has not seen our GOAWAY yet: refused, so it retries elsewhere
            send_rst(id, ErrorCode::refused_stream, "");
            return nullptr;
        }
        if (active_.size() >= live_->http2.max_concurrent_streams) {
            for (auto& s : active_) {  // a stream kept only to drain its body gives its slot up
                if (s->state != StreamState::half_closed_local) continue;
                send_rst(s->id, ErrorCode::no_error, "response complete, slot needed");
                close_stream(*s);
                break;
            }
        }
        if (active_.size() >= live_->http2.max_concurrent_streams) {
            send_rst(id, ErrorCode::refused_stream, "over SETTINGS_MAX_CONCURRENT_STREAMS");
            glitch("stream over the concurrency limit");
            count_reset();
            return nullptr;
        }
        refresh_generation();
        std::unique_ptr<H2Stream> s;
        if (!pool_.empty()) {
            s = std::move(pool_.back());
            pool_.pop_back();
        } else {
            s = std::make_unique<H2Stream>();
            s->body_source.owner = this;
            s->body_source.stream = s.get();
        }
        s->id = id;
        s->state = StreamState::open;
        s->send_window = static_cast<std::int32_t>(peer_.initial_window_size);
        s->recv_grant = static_cast<std::int32_t>(kDefaultWindow);
        s->since = std::chrono::steady_clock::now();
        H2Stream* raw = s.get();
        active_.push_back(std::move(s));
        ++streams_opened_;
        // The last stream this connection takes: served, then a GOAWAY naming it and the
        // close (the frame goes out after the answer, so a client never has to read a
        // response behind a GOAWAY).
        if (live_->max_requests_per_connection != 0 && streams_opened_ >= live_->max_requests_per_connection)
            leave_after_streams("max_requests_per_connection reached");
        if (retire_) leave_after_streams("listener left the configuration");
        return raw;
    }

    // Removes the stream from the table; its object goes back to the pool once nothing of
    // it is in flight.
    void close_stream(H2Stream& s) {
        if (s.state == StreamState::closed) return;
        s.state = StreamState::closed;
        if (s.upstream) {
            s.upstream->cancel();
            s.upstream.reset();
        }
        if (s.pending_handler) {
            auto h = std::move(s.pending_handler);
            s.pending_handler = nullptr;
            h(asio::error::operation_aborted, 0);
        }
        if (!s.body_done && s.recv_pending > 0) return_window(s, static_cast<std::uint32_t>(s.recv_pending), false);
        writer_.dequeue(s);
        recent_closed_[recent_pos_++ % kRecentClosed] = s.id;
        if (writer_.in_flight(s) || s.pulling) {
            s.defer_release = true;  // the writer or the pull completion releases it
            return;
        }
        release(s);
    }

    void release(H2Stream& s) {
        for (std::size_t i = 0; i < active_.size(); ++i) {
            if (active_[i].get() != &s) continue;
            std::unique_ptr<H2Stream> p = std::move(active_[i]);
            active_[i] = std::move(active_.back());
            active_.pop_back();
            p->reset();
            pool_.push_back(std::move(p));
            return;
        }
    }

    // ---- the request ----

    void begin_request(H2Stream& s) {
        Request& req = s.stream.request;
        struct Seen {
            std::string_view method, scheme, path, authority;
            unsigned pseudo = 0;
            bool regular = false, bad = false, overflow = false, te_bad = false, host_field = false;
            std::string_view host;
            unsigned cookies = 0;
            std::size_t cookie_bytes = 0;
            const char* reason = "";
        } seen;
        const auto r = decoder_.decode(block_, s.arena, live_->max_header_size, [&](std::string_view n, std::string_view v) {
            if (!n.empty() && n.front() == ':') {
                if (seen.regular) { seen.bad = true; seen.reason = "pseudo-header after a regular field"; return true; }
                std::string_view* slot = n == ":method" ? &seen.method : n == ":scheme" ? &seen.scheme
                                       : n == ":path" ? &seen.path : n == ":authority" ? &seen.authority : nullptr;
                if (!slot) { seen.bad = true; seen.reason = "unknown or response pseudo-header"; return true; }
                if (!slot->empty() || (slot == &seen.authority && seen.pseudo & 8)) { seen.bad = true; seen.reason = "duplicate pseudo-header"; return true; }
                *slot = v;
                seen.pseudo |= slot == &seen.method ? 1 : slot == &seen.scheme ? 2 : slot == &seen.path ? 4 : 8;
                return true;
            }
            seen.regular = true;
            if (!fields::valid_name(n)) { seen.bad = true; seen.reason = "field name not a lower-case token"; return true; }
            if (!fields::valid_value(v)) { seen.bad = true; seen.reason = "field value with CR, LF, NUL or edge whitespace"; return true; }
            if (fields::connection_specific(n)) { seen.bad = true; seen.reason = "connection-specific field"; return true; }
            if (n == "te" && v != "trailers") { seen.bad = true; seen.reason = "te other than trailers"; return true; }
            if (n == "host") {
                if (seen.host_field) { seen.bad = true; seen.reason = "duplicate host"; return true; }
                seen.host_field = true;
                seen.host = v;
            }
            if (n == "cookie") {
                ++seen.cookies;
                seen.cookie_bytes += v.size() + 2;
                if (seen.cookies > 1) return true;  // joined below
            }
            if (!req.headers.add(n, v)) seen.overflow = true;
            return true;
        });
        switch (r) {
            case hpack::Decoder::Result::ok: break;
            case hpack::Decoder::Result::malformed: return connection_error(ErrorCode::compression_error, "HPACK error in the request");
            case hpack::Decoder::Result::too_large: return connection_error(ErrorCode::enhance_your_calm, "decoded header list over max_header_size");
            case hpack::Decoder::Result::too_many: break;  // never returned: the sink keeps decoding
        }
        if (seen.overflow) return fail_stream(s, 431);
        if (!seen.bad) {
            if (seen.method.empty() || seen.scheme.empty() || seen.path.empty()) seen.bad = true, seen.reason = "missing :method, :scheme or :path";
            else if (seen.path == "*" ? seen.method != "OPTIONS" : seen.path.front() != '/') seen.bad = true, seen.reason = ":path not absolute";
            else if (seen.authority.empty() && seen.host.empty()) seen.bad = true, seen.reason = "no :authority and no host";
            else if (!seen.authority.empty() && !seen.host.empty() && seen.authority != seen.host) seen.bad = true, seen.reason = ":authority and host differ";
        }
        if (seen.bad) {
            stream_error(s, ErrorCode::protocol_error, seen.reason);
            return;
        }
        if (seen.cookies > 1) {  // RFC 9113 8.2.3: one field, "; " between the crumbs
            s.cookie.clear();
            s.cookie.reserve(seen.cookie_bytes);
            Headers joined;
            for (const HeaderField& f : req.headers) {
                if (f.name != "cookie") { joined.add(f.name, f.value); continue; }
                if (!s.cookie.empty()) s.cookie.append("; ");
                s.cookie.append(f.value);
            }
            // The crumbs beyond the first were never added; every cookie value collected here.
            req.headers = joined;
            req.headers.add("cookie", s.cookie);
        }
        req.method_name = seen.method;
        if (!parse_method(seen.method, req.method)) req.method = Method::other;
        req.target = seen.path;
        req.host = seen.authority.empty() ? seen.host : seen.authority;
        if (!seen.host_field) req.headers.add("host", req.host);  // handlers see HTTP/1's shape (HTTP_HOST)
        req.version_minor = 1;
        req.protocol = "HTTP/2.0";
        req.keep_alive = true;
        req.length = 1;  // "a request exists" for the log on close
        for (const HeaderField& f : req.headers) {
            if (f.name == "if-none-match") req.if_none_match = f.value;
            else if (f.name == "if-modified-since") req.if_modified_since = f.value;
            else if (f.name == "range") req.range = f.value;
            else if (f.name == "if-range") req.if_range = f.value;
            else if (f.name == "content-length") {
                std::uint64_t n = 0;
                if (f.value.empty() || f.value.size() > 19) return stream_error(s, ErrorCode::protocol_error, "content-length not a number");
                for (const char c : f.value) {
                    if (c < '0' || c > '9') return stream_error(s, ErrorCode::protocol_error, "content-length not a number");
                    n = n * 10 + static_cast<std::uint64_t>(c - '0');
                }
                s.length_known = true;
                s.content_length = n;
            }
        }
        if (block_end_stream_) {
            s.state = StreamState::half_closed_remote;
            s.body_done = true;
            if (s.length_known && s.content_length != 0) return stream_error(s, ErrorCode::protocol_error, "content-length without a body");
        } else {
            s.has_body = true;
            req.has_body = true;
            req.content_length = s.content_length;
            req.chunked = !s.length_known;  // "length unknown" for the handlers
            req.body = &s.body_source;
            s.body_limit = body_limit(req.host);
            if (s.length_known && s.content_length > s.body_limit) return fail_stream(s, 413);
            // The receive window follows the body limit, so an upload runs at the consumer's pace.
            const std::uint64_t want = std::min<std::uint64_t>(std::max<std::uint64_t>(s.body_limit, 1), kStreamWindowMax);
            if (want > kDefaultWindow) {
                std::string wu;
                append_window_update(wu, s.id, static_cast<std::uint32_t>(want - kDefaultWindow));
                s.recv_grant = static_cast<std::int32_t>(want);
                writer_.control(wu);
            }
        }
        dispatch(s);
    }

    std::size_t body_limit(std::string_view host) const noexcept {
        const SiteConfig* site = listener_->router.site(host);
        return site ? body_limit_of(*site, *live_) : live_->max_body_size;
    }

    void dispatch(H2Stream& s) {
        WorkerState& ws = worker_.state;
        ws.now = std::time(nullptr);
        ws.site = nullptr;
        fill_connection_info(s);
        if (!live_->trusted_proxies.empty()) apply_forwarded(s);
        const LocationConfig* loc = dispatcher_.route(s.stream, listener_->router, ws);
        s.site = static_cast<const SiteConfig*>(ws.site);
        int hops = 0;
        while (loc) {
            if (loc->kind == HandlerKind::control) {  // the control API lives on the unix socket, HTTP/1 only
                dispatcher_.static_handler().error(s.stream, 404, true);
                break;
            }
            if (loc->kind != HandlerKind::static_) {  // FastCGI, proxy, CGI: completes later
                const unsigned gen = s.gen;
                H2Stream* sp = &s;
                auto self = this->shared_from_this();
                auto done = [self, sp, gen] {
                    if (sp->gen != gen) return;  // reset or closed meanwhile
                    sp->upstream.reset();
                    self->respond(*sp);
                };
                const auto* site = static_cast<const SiteConfig*>(ws.site);
                std::shared_ptr<UpstreamRequest> req =
                    loc->kind == HandlerKind::fastcgi
                        ? dispatcher_.fcgi().start(s.stream, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                    : loc->kind == HandlerKind::cgi
                        ? dispatcher_.cgi().start(s.stream, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                        : dispatcher_.proxy().start(s.stream, *loc, ws, worker_.upstream_pool, std::move(done));
                if (req && sp->gen == gen && sp->state != StreamState::closed) sp->upstream = std::move(req);
                return;
            }
            loc = dispatcher_.serve_static(s.stream, *loc, ws, hops);
            s.site = static_cast<const SiteConfig*>(ws.site);
        }
        respond(s);
    }

    // The response is filled: over to the writer.
    void respond(H2Stream& s) {
        if (s.state == StreamState::closed) return;
        s.stream.response.upgrade = false;  // a 101 has no meaning here; the body is what came with it
        s.ready = true;
        s.since = std::chrono::steady_clock::now();
        writer_.enqueue(s);
    }

    // A protocol-level answer (413, 431) with the canned page; the body, if any, is left
    // to the client's RST after the response.
    void fail_stream(H2Stream& s, int status) {
        worker_.state.now = std::time(nullptr);
        worker_.state.site = nullptr;
        dispatcher_.static_handler().error(s.stream, status, true);
        respond(s);
    }

    void fill_connection_info(H2Stream& s) {
        ConnectionInfo& c = s.stream.conn;
        if (remote_.empty()) {
            asio::error_code ec;
            const auto ep = lowest().remote_endpoint(ec);
            remote_ = ec ? std::string("-") : ep.address().to_string();
            remote_port_ = ec ? 0 : ep.port();
            if (!ec) remote_addr_ = ep.address();
        }
        c.remote_address = remote_;
        c.remote_port = remote_port_;
        c.local_address = listener_->address_text;
        c.local_port = listener_->port;
        c.tls = IsTlsStream<Socket>::value;
        c.cert = cert_names_.get();
        c.client_address = {};
        c.forwarded_https = false;
        c.trusted_peer = false;
    }

    void apply_forwarded(H2Stream& s) {
        if (!trusted_checked_) {
            trusted_peer_ = in_any(live_->trusted_proxies, remote_addr_);
            trusted_checked_ = true;
        }
        s.stream.conn.trusted_peer = trusted_peer_;
        if (trusted_peer_) resolve_forwarded(s.stream.request, live_->trusted_proxies, s.stream.conn, s.client_addr);
    }

    // A reload switched the worker to a new generation: taken at each new stream.
    void refresh_generation() {
        if (gen_.get() == worker_.gen.get()) return;
        const Listener* l = worker_.gen->find(listener_->address);
        if (!l) {
            retire_ = true;
            return;
        }
        gen_ = worker_.gen;
        listener_ = l;
        live_ = &gen_->cfg;
    }

    // ---- request bodies (DATA frames) ----

    void on_data(const FrameHeader& h, const unsigned char* p) {
        if (h.stream_id == 0) return connection_error(ErrorCode::protocol_error, "DATA on stream 0");
        std::size_t off = 0, len = h.length;
        if (h.flags & flag::padded) {
            if (len < 1) return connection_error(ErrorCode::frame_size_error, "DATA padding");
            const std::size_t pad = p[0];
            off = 1;
            if (pad + 1 > len) return connection_error(ErrorCode::protocol_error, "DATA padding longer than the frame");
            len -= pad + 1;
        }
        // Flow control on the connection counts the whole frame, padding included (RFC 9113 6.9.1).
        if (h.length > conn_recv_grant_) return connection_error(ErrorCode::flow_control_error, "DATA beyond the connection window");
        conn_recv_grant_ -= h.length;
        H2Stream* s = find(h.stream_id);
        if (!s || (s->state != StreamState::open && s->state != StreamState::half_closed_local)) {
            return_conn_window(h.length);
            if (!s) {
                if (h.stream_id > last_stream_id_) return connection_error(ErrorCode::protocol_error, "DATA on an idle stream");
                send_rst(h.stream_id, ErrorCode::stream_closed, "DATA on a closed stream");  // RFC 9113 5.1
                glitch({});
                return;
            }
            stream_error(*s, ErrorCode::stream_closed, "DATA after END_STREAM");
            return;
        }
        if (s->state == StreamState::half_closed_local) {  // the response is out: dropped, still checked
            if (h.length > static_cast<std::uint32_t>(std::max(s->recv_grant, 0)))
                return stream_error(*s, ErrorCode::flow_control_error, "DATA beyond the stream window");
            s->recv_grant -= static_cast<std::int32_t>(h.length);
            return_window(*s, h.length, true);
            s->body_received += len;
            s->discarded += len;
            if (s->length_known && s->body_received > s->content_length)
                return stream_error(*s, ErrorCode::protocol_error, "more DATA than content-length");
            if (h.flags & flag::end_stream) {
                if (s->length_known && s->body_received != s->content_length)
                    return stream_error(*s, ErrorCode::protocol_error, "END_STREAM before content-length bytes");
                close_stream(*s);
                maybe_finish();
                return;
            }
            if (s->discarded > kDrainAfterResponse) {
                send_rst(s->id, ErrorCode::no_error, "response complete, request body cut short");
                close_stream(*s);
                maybe_finish();
            }
            return;
        }
        if (h.length > static_cast<std::uint32_t>(std::max(s->recv_grant, 0)))
            return stream_error(*s, ErrorCode::flow_control_error, "DATA beyond the stream window");
        s->recv_grant -= static_cast<std::int32_t>(h.length);
        if (len == 0 && !(h.flags & flag::end_stream)) glitch("empty DATA frame");
        if (h.length > len) {  // padding bytes never wait for the handler: returned at once
            return_window(*s, h.length - static_cast<std::uint32_t>(len), true);
        }
        s->body_received += len;
        if (s->length_known && s->body_received > s->content_length)
            return stream_error(*s, ErrorCode::protocol_error, "more DATA than content-length");
        if (s->body_received > s->body_limit) {
            if (!s->responded && !s->ready) fail_stream(*s, 413);
            s->body_done = true;  // nothing more is taken from this request
            return_window(*s, static_cast<std::uint32_t>(len), true);
            s->state = StreamState::half_closed_remote;
            deliver_error(*s, make_error_code(BodyError::too_large));
            return;
        }
        if (len > 0) {
            if (s->body_buf.empty()) s->body_buf.resize(std::max<std::size_t>(kDefaultWindow, static_cast<std::size_t>(s->recv_grant + s->recv_pending + static_cast<std::int32_t>(len))));
            if (s->body_pos == s->body_len) s->body_pos = s->body_len = 0;
            if (s->body_len + len > s->body_buf.size()) {
                if (s->body_pos > 0) {
                    std::memmove(s->body_buf.data(), s->body_buf.data() + s->body_pos, s->body_len - s->body_pos);
                    s->body_len -= s->body_pos;
                    s->body_pos = 0;
                }
                if (s->body_len + len > s->body_buf.size()) s->body_buf.resize(s->body_len + len);
            }
            std::memcpy(s->body_buf.data() + s->body_len, p + off, len);
            s->body_len += len;
            s->recv_pending += static_cast<std::int32_t>(len);
            s->since = std::chrono::steady_clock::now();
        }
        if (h.flags & flag::end_stream) {
            s->state = StreamState::half_closed_remote;
            end_of_body(*s);
        } else if (s->pending_handler) {
            deliver(*s);
        }
    }

    void end_of_body(H2Stream& s) {
        s.body_done = true;
        if (s.length_known && s.body_received != s.content_length) {
            stream_error(s, ErrorCode::protocol_error, "END_STREAM before content-length bytes");
            return;
        }
        if (s.pending_handler) deliver(s);
    }

    // The pull source behind Request::body (BodyOwner).
    void read_body(H2Stream& s, char* buf, std::size_t len, StreamBody::ReadHandler handler) override {
        if (!s.has_body || len == 0 || s.state == StreamState::closed) {
            handler(std::error_code{}, 0);
            return;
        }
        if (s.body_pos < s.body_len || s.body_done) {
            s.pending_buf = buf;
            s.pending_len = len;
            s.pending_handler = std::move(handler);
            deliver(s);
            return;
        }
        s.pending_buf = buf;  // nothing buffered: the next DATA frame completes it
        s.pending_len = len;
        s.pending_handler = std::move(handler);
        s.since = std::chrono::steady_clock::now();
    }

    void deliver(H2Stream& s) {
        auto handler = std::move(s.pending_handler);
        s.pending_handler = nullptr;
        if (!handler) return;
        const std::size_t avail = s.body_len - s.body_pos;
        const std::size_t n = std::min(avail, s.pending_len);
        if (n > 0) {
            std::memcpy(s.pending_buf, s.body_buf.data() + s.body_pos, n);
            s.body_pos += n;
            s.recv_pending -= static_cast<std::int32_t>(n);
            return_window(s, static_cast<std::uint32_t>(n), false);
        }
        handler(std::error_code{}, n);  // 0 only at the end of the body
    }

    void deliver_error(H2Stream& s, std::error_code ec) {
        auto handler = std::move(s.pending_handler);
        s.pending_handler = nullptr;
        if (handler) handler(ec, 0);
    }

    // Bytes the handler consumed (or padding, or bytes discarded) are given back to the
    // peer: the stream's window when half of its grant is owed, the connection's likewise.
    void return_window(H2Stream& s, std::uint32_t n, bool discarded) {
        return_conn_window(n);
        if (s.state == StreamState::closed || s.state == StreamState::half_closed_remote || s.body_done) return;
        s.recv_unreturned += n;
        (void)discarded;
        if (s.recv_unreturned >= static_cast<std::uint32_t>(std::max(s.recv_grant + s.recv_pending, 1)) / 2 ||
            s.recv_grant <= static_cast<std::int32_t>(kDefaultWindow / 4)) {
            std::string wu;
            append_window_update(wu, s.id, s.recv_unreturned);
            s.recv_grant += static_cast<std::int32_t>(s.recv_unreturned);
            s.recv_unreturned = 0;
            writer_.control(wu);
        }
    }
    void return_conn_window(std::uint32_t n) {
        conn_unreturned_ += n;
        if (conn_unreturned_ >= kConnectionWindow / 2 || conn_recv_grant_ < kConnectionWindow / 4) {
            std::string wu;
            append_window_update(wu, 0, conn_unreturned_);
            conn_recv_grant_ += conn_unreturned_;
            conn_unreturned_ = 0;
            writer_.control(wu);
        }
    }

    // ---- errors, budgets, GOAWAY ----

    void send_rst(std::uint32_t id, ErrorCode code, std::string_view reason) {
        std::string f;
        append_rst_stream(f, id, code);
        writer_.control(f);
        if (!reason.empty())
            if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
                log->info("http2 " + remote_text() + " stream " + std::to_string(id) + ": RST_STREAM " +
                          std::string(error_name(code)) + ": " + std::string(reason));
    }

    // A stream error: RST_STREAM, the stream closed, a glitch counted; one the client
    // provoked before any response counts as a reset too (MadeYouReset).
    void stream_error(H2Stream& s, ErrorCode code, std::string_view reason) {
        send_rst(s.id, code, reason);
        if (!s.responded) count_reset();
        if (s.responded && !s.logged) log_request(s);
        close_stream(s);
        glitch({});
    }

    void connection_error(ErrorCode code, std::string_view reason) {
        if (closed_ || closing_after_write_) return;
        if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
            log->info("http2 " + remote_text() + ": closing, " + std::string(error_name(code)) + ": " + std::string(reason));
        std::string f;
        append_goaway(f, last_stream_id_, code, reason.substr(0, 64));
        closing_after_write_ = true;
        for (auto& s : active_) {  // nothing more is served; the GOAWAY is the last write
            if (s->upstream) {
                s->upstream->cancel();
                s->upstream.reset();
            }
            writer_.dequeue(*s);
        }
        writer_.control(f);
        if (writer_.idle()) begin_linger();
    }

    // After the last frame: half-close our side and read (discarding) until the peer closes
    // or a second passes, so the GOAWAY reaches it before the connection drops (a close with
    // unread bytes would turn into a reset on the wire).
    void begin_linger() {
        if (closed_ || linger_) return;
        linger_ = true;
        asio::error_code ec;
        lowest().shutdown(asio::ip::tcp::socket::shutdown_send, ec);
        timer_.cancel();
        auto self = this->shared_from_this();
        timer_.expires_after(std::chrono::seconds(1));
        timer_.async_wait([self](const asio::error_code& e) {
            if (!e) self->close();
        });
        in_len_ = 0;
        do_read();
    }

    // Graceful, the frame deferred: no new streams (refused), the open ones finish, then
    // the GOAWAY and the close.
    void leave_after_streams(std::string_view reason) {
        if (going_away_ || closed_) return;
        going_away_ = true;
        goaway_pending_ = true;
        goaway_reason_ = reason;
    }

    // Graceful: no new streams after this id, the open ones finish, then the connection closes.
    void goaway(ErrorCode code, std::string_view reason) {
        if (going_away_ || closed_) return;
        going_away_ = true;
        if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
            log->info("http2 " + remote_text() + ": GOAWAY after stream " + std::to_string(last_stream_id_) + ", " +
                      std::string(error_name(code)) + ": " + std::string(reason));
        std::string f;
        append_goaway(f, last_stream_id_, code, reason.substr(0, 64));
        writer_.control(f);
        maybe_finish();
    }

    void maybe_finish() {
        if (going_away_ && active_.empty() && !closed_) {
            if (goaway_pending_) {
                goaway_pending_ = false;
                if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
                    log->info("http2 " + remote_text() + ": GOAWAY after stream " + std::to_string(last_stream_id_) + ", NO_ERROR: " + goaway_reason_);
                std::string f;
                append_goaway(f, last_stream_id_, ErrorCode::no_error, goaway_reason_);
                writer_.control(f);
            }
            closing_after_write_ = true;
            if (writer_.idle()) begin_linger();
        }
    }

    // Misbehaviour points: at the soft threshold a GOAWAY, at the budget the close.
    void glitch(std::string_view what) {
        ++glitches_;
        if (!what.empty() && glitches_ <= 3)
            if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
                log->info("http2 " + remote_text() + ": " + std::string(what));
        if (glitches_ == kGlitchSoft) goaway(ErrorCode::enhance_your_calm, "misbehaving client (glitch budget)");
        else if (glitches_ >= kGlitchBudget) connection_error(ErrorCode::enhance_your_calm, "glitch budget exhausted");
    }

    // Streams cancelled before a response, by either side, within one second.
    void count_reset() {
        const auto now = std::chrono::steady_clock::now();
        if (now - reset_window_ >= std::chrono::seconds(1)) {
            reset_window_ = now;
            resets_ = 0;
        }
        if (++resets_ > live_->http2.max_concurrent_streams)
            connection_error(ErrorCode::enhance_your_calm, "streams reset before a response beyond the rate");
    }

    // PING and SETTINGS beyond kControlRate per second are glitches. True when the connection closed.
    bool rate(std::pair<std::chrono::steady_clock::time_point, unsigned>& counter, std::string_view what) {
        const auto now = std::chrono::steady_clock::now();
        if (now - counter.first >= std::chrono::seconds(1)) {
            counter.first = now;
            counter.second = 0;
        }
        if (++counter.second > kControlRate) glitch(what);
        return closed_;
    }

    // ---- timers ----

    void arm_timer() {
        auto self = this->shared_from_this();
        timer_.expires_after(idle_timeout_);
        timer_.async_wait([self](const asio::error_code& ec) {
            if (ec || self->closed_) return;
            self->check_timeouts();
        });
    }

    void check_timeouts() {
        const auto now = std::chrono::steady_clock::now();
        if (active_.empty()) {
            if (now - last_activity_ >= idle_timeout_) {
                close();
                return;
            }
        } else {
            if (block_stream_ != 0 && now - block_since_ >= idle_timeout_) {
                connection_error(ErrorCode::enhance_your_calm, "header block not completed in time");
                return;
            }
            for (std::size_t i = 0; i < active_.size();) {
                H2Stream& s = *active_[i];
                const auto age = now - s.since;
                bool cut = false;
                if (s.state == StreamState::half_closed_local && age >= idle_timeout_) {  // the body never finished
                    send_rst(s.id, ErrorCode::no_error, "response complete, request body never finished");
                    close_stream(s);
                    if (closed_) return;
                    continue;
                }
                if (s.pending_handler && age >= body_timeout_) cut = true;             // a body that does not arrive
                else if (s.responded && !s.finished && age >= idle_timeout_) cut = true;  // a response the client does not take
                else if (!s.responded && !s.ready && !s.upstream && !s.has_body && age >= idle_timeout_ * 4) cut = true;  // stuck
                if (cut) {
                    if (ErrorLog* log = dispatcher_.error_log(); log && log->enabled(LogLevel::info))
                        log->info("http2 " + remote_text() + " stream " + std::to_string(s.id) + ": no progress, cancelled");
                    send_rst(s.id, ErrorCode::cancel, "");
                    count_reset();
                    if (s.responded && !s.logged) log_request(s);
                    close_stream(s);
                    if (closed_) return;
                    continue;  // the slot was swapped
                }
                ++i;
            }
            if (now - last_activity_ >= idle_timeout_ * 4 && !writer_.idle()) {  // the socket does not drain
                close();
                return;
            }
        }
        arm_timer();
    }

    // ---- access log ----

    void log_request(H2Stream& s) {
        if (s.logged) return;
        s.logged = true;
        const SiteConfig* site = s.site ? s.site : listener_->router.default_site();
        if (!site || site->access_log_sink < 0) return;
        const Request& req = s.stream.request;
        AccessRecord rec;
        rec.remote = s.stream.conn.client_address.empty() ? std::string_view(remote_) : s.stream.conn.client_address;
        rec.host = req.host;
        rec.method = req.method_name;
        rec.target = req.target;
        rec.version_minor = 1;
        rec.protocol = "HTTP/2.0";
        rec.status = s.stream.response.status;
        rec.bytes = s.body_sent;
        rec.referer = req.headers.get("referer");
        rec.user_agent = req.headers.get("user-agent");
        if (s.stream.response.upstream) rec.upstream = s.stream.response.upstream;
        worker_.state.logs.log(site->access_log_sink, worker_.state.now ? worker_.state.now : std::time(nullptr), rec);
    }

    std::string remote_text() {
        if (remote_.empty()) {
            asio::error_code ec;
            const auto ep = lowest().remote_endpoint(ec);
            remote_ = ec ? std::string("-") : ep.address().to_string();
            remote_port_ = ec ? 0 : ep.port();
            if (!ec) remote_addr_ = ep.address();
        }
        return remote_;
    }

    enum class BlockKind { request, trailers, discard };

    Socket socket_;
    Worker& worker_;
    std::shared_ptr<const Generation> gen_;
    const Listener* listener_;
    std::shared_ptr<const CertNames> cert_names_;
    const Config* live_;
    bool retire_ = false;
    const Config& cfg_;
    Dispatcher& dispatcher_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::duration idle_timeout_;
    std::chrono::steady_clock::duration body_timeout_;
    std::chrono::steady_clock::time_point last_activity_;
    std::vector<char> in_;
    std::size_t in_len_ = 0;
    bool read_pending_ = false;
    unsigned inline_reads_ = 0;
    bool preface_seen_ = false;
    bool settings_seen_ = false;
    bool settings_acked_ = false;
    bool going_away_ = false;
    bool goaway_pending_ = false;   // the GOAWAY is sent once the streams in flight are done
    std::string goaway_reason_;
    bool closing_after_write_ = false;
    bool linger_ = false;
    bool closed_ = false;
    // The header block being assembled.
    std::string block_;
    std::uint32_t block_stream_ = 0;
    bool block_end_stream_ = false;
    unsigned block_frames_ = 0;
    BlockKind block_kind_ = BlockKind::request;
    std::chrono::steady_clock::time_point block_since_{};
    hpack::Decoder decoder_;
    PeerSettings peer_;
    std::uint32_t conn_recv_grant_ = kDefaultWindow;  // what the peer may still send us in total
    std::uint32_t conn_unreturned_ = 0;
    std::uint32_t last_stream_id_ = 0;
    std::uint32_t streams_opened_ = 0;
    std::vector<std::unique_ptr<H2Stream>> active_;
    std::vector<std::unique_ptr<H2Stream>> pool_;
    std::uint32_t recent_closed_[kRecentClosed] = {};
    unsigned recent_pos_ = 0;
    unsigned glitches_ = 0;
    unsigned resets_ = 0;
    std::chrono::steady_clock::time_point reset_window_{};
    std::pair<std::chrono::steady_clock::time_point, unsigned> ping_rate_{}, settings_rate_{};
    std::string remote_;
    std::uint16_t remote_port_ = 0;
    asio::ip::address remote_addr_;
    bool trusted_checked_ = false;
    bool trusted_peer_ = false;
    Http2Writer<Socket, Http2Connection> writer_;  // last: it references socket_ and *this
};

}  // namespace agensio::h2
