// One HTTP/1.x client connection: reads request heads, drives one Stream through the
// handler, and writes the Response as HTTP/1 bytes. Instantiated for a plain TCP socket
// and for a TLS stream. (Phase A2 splits the I/O loop from the HTTP/1 writer.)
#pragma once

#include <array>
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <variant>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/strings.hpp"
#include "core/worker_state.hpp"
#include "handlers/static.hpp"
#include "http1/parser.hpp"
#include "response.hpp"
#include "server.hpp"
#include "tls_stream.hpp"

namespace agensio {

template <class Socket>
struct IsTlsStream : std::false_type {};
#ifdef AGENSIO_HAS_TLS
template <>
struct IsTlsStream<TlsStream> : std::true_type {};
#endif

template <class Socket>
class Connection : public std::enable_shared_from_this<Connection<Socket>> {
public:
    Connection(Socket&& socket, Worker& worker, const Listener& listener, const Config& cfg, StaticHandler& handler)
        : socket_(std::move(socket)),
          worker_(worker),
          listener_(listener),
          cfg_(cfg),
          handler_(handler),
          timer_(worker.ctx),
          idle_timeout_(std::chrono::seconds(cfg.idle_timeout_s)),
          in_(cfg.max_header_size) {
        worker_.connections.fetch_add(1, std::memory_order_relaxed);
        hdr_.reserve(256);
        tail_.reserve(128);
    }

    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    ~Connection() { worker_.connections.fetch_sub(1, std::memory_order_relaxed); }

    void start() {
        last_activity_ = std::chrono::steady_clock::now();
        arm_timer(idle_timeout_);
        if constexpr (IsTlsStream<Socket>::value) {
            auto self = this->shared_from_this();
            socket_.async_handshake([self](const asio::error_code& ec) {
                if (ec) {
                    self->close();
                    return;
                }
                self->last_activity_ = std::chrono::steady_clock::now();
                self->do_read();
            });
        } else {
            do_read();
        }
    }

private:
    auto& lowest() { return socket_.lowest_layer(); }
    Request& request() { return stream_.request; }
    Response& response() { return stream_.response; }

    // Speculative completions (data already readable, write done at once) run inline
    // instead of being posted, which saves a scheduler hop and a kevent poll per request.
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(worker_.ctx.get_executor(), std::forward<F>(f));
    }

    void arm_timer(std::chrono::steady_clock::duration d) {
        auto self = this->shared_from_this();
        timer_.expires_after(d);
        timer_.async_wait([self](const asio::error_code& ec) {
            if (ec) return;  // cancelled
            if (!self->lowest().is_open()) return;
            auto idle = std::chrono::steady_clock::now() - self->last_activity_;
            if (idle >= self->idle_timeout_) self->close();
            else self->arm_timer(self->idle_timeout_ - idle);
        });
    }

    // ---- reading ----

    void do_read() {
        if (in_len_ >= in_.size()) {  // buffer full without a complete request head
            fail_request(431);
            return;
        }
        auto self = this->shared_from_this();
        socket_.async_read_some(asio::buffer(in_.data() + in_len_, in_.size() - in_len_),
                                immediate([self](const asio::error_code& ec, std::size_t n) { self->on_read(ec, n); }));
    }

    void on_read(const asio::error_code& ec, std::size_t n) {
        if (ec) {
            close();
            return;
        }
        in_len_ += n;
        // last_activity_ is refreshed once per response in on_write; a second clock read
        // here was visible in profiles and buys nothing for the idle timer.
        process();
    }

    void process() {
        switch (parse_request(std::string_view(in_.data(), in_len_), request())) {
            case ParseStatus::complete:
                consumed_ = request().length;
                worker_.state.now = std::time(nullptr);
                handler_.handle(stream_, listener_.route, worker_.state);
                if (cfg_.max_requests_per_connection != 0 && ++requests_served_ >= cfg_.max_requests_per_connection)
                    response().keep_alive = false;  // cap reached: this is the last response
                write_response();
                return;
            case ParseStatus::incomplete:
                do_read();
                return;
            case ParseStatus::bad_request:
                fail_request(400);
                return;
            case ParseStatus::version_not_supported:
                fail_request(505);
                return;
            case ParseStatus::too_many_headers:
                fail_request(431);
                return;
        }
    }

    // Protocol-level error: answer, drop whatever is buffered, close.
    void fail_request(int status) {
        worker_.state.now = std::time(nullptr);
        handler_.error(stream_, status, false);
        consumed_ = in_len_;
        write_response();
    }

    // ---- HTTP/1 serialisation ----
    // The head is written as up to three pieces without concatenation: hdr_ (status line,
    // Server, Date), the response's prebuilt block, and tail_ (extra fields + blank line).
    // With no extra fields and a terminated prebuilt block, tail_ is not needed at all.

    void build_head() {
        Response& r = response();
        WorkerState& ws = worker_.state;
        if (r.status == 200) {
            if (ws.prefix200_time != ws.now) {
                ws.prefix200.assign(status_line(200))
                    .append(ws.server_line)
                    .append("Date: ")
                    .append(ws.date.at(ws.now))
                    .append("\r\n");
                ws.prefix200_time = ws.now;
            }
            hdr_.assign(ws.prefix200);
        } else {
            hdr_.assign(status_line(r.status))
                .append(ws.server_line)
                .append("Date: ")
                .append(ws.date.at(ws.now))
                .append("\r\n");
        }
        const bool close_line = !r.keep_alive;
        const bool keepalive_line = r.keep_alive && request().version_minor == 0;
        if (r.headers.empty() && !close_line && !keepalive_line && r.prebuilt_terminated) {
            block_ = r.prebuilt_headers;
            tail_.clear();
            return;
        }
        block_ =
            r.prebuilt_terminated ? slice(r.prebuilt_headers, 0, r.prebuilt_headers.size() - 2) : r.prebuilt_headers;
        tail_.clear();
        for (const HeaderField& h : r.headers)
            tail_.append(h.name).append(": ").append(h.value).append("\r\n");
        if (close_line) tail_.append("Connection: close\r\n");
        else if (keepalive_line) tail_.append("Connection: keep-alive\r\n");
        tail_.append("\r\n");
    }

    std::string_view memory_body() const {
        const Response& r = stream_.response;
        if (r.head) return {};
        if (const auto* m = std::get_if<MemoryBody>(&r.body)) return m->data;
        return {};
    }

    void write_response() {
        build_head();
        auto self = this->shared_from_this();
        auto done = immediate([self](const asio::error_code& ec, std::size_t) { self->on_write(ec); });
        Response& r = response();
        const std::string_view body = memory_body();
        if constexpr (IsTlsStream<Socket>::value) {
            // TlsStream encrypts one buffer per write_some, so coalesce everything up to
            // one full-size record; the rest of the body follows as-is.
            constexpr std::size_t kRecord = 16384;  // max TLS plaintext per record
            out_.assign(hdr_.begin(), hdr_.end());
            out_.insert(out_.end(), block_.begin(), block_.end());
            out_.insert(out_.end(), tail_.begin(), tail_.end());
            const std::size_t room = out_.size() < kRecord ? kRecord - out_.size() : 0;
            const std::size_t take = std::min(room, body.size());
            out_.insert(out_.end(), body.data(),
                        body.data() + take);  // NOLINT(bugprone-suspicious-stringview-data-usage): bounded by take
            if (take == body.size()) asio::async_write(socket_, asio::buffer(out_), done);
            else
                asio::async_write(socket_,
                                  std::array<asio::const_buffer, 2>{
                                      asio::buffer(out_), asio::buffer(body.data() + take, body.size() - take)},
                                  done);
            return;
        } else {
            if (cfg_.sendfile && !sendfile_unsupported_ && !r.head) {
                if (const auto* m = std::get_if<MemoryBody>(&r.body); m && r.entry && r.entry->fd.is_open()) {
                    // Cached entry with an open descriptor: let the kernel send it from the
                    // page cache, headers attached to the same call where supported.
                    begin_sendfile(&r.entry->fd, m->data.size());
                    return;
                }
                if (const auto* f = std::get_if<FileBody>(&r.body)) {
                    begin_sendfile(f->file, f->size);
                    return;
                }
            }
            // Plain socket: one writev over the pieces, nothing concatenated.
            std::array<asio::const_buffer, 4> bufs;
            std::size_t n = 0;
            bufs[n++] = asio::buffer(hdr_);
            if (!block_.empty()) bufs[n++] = asio::buffer(block_);
            if (!tail_.empty()) bufs[n++] = asio::buffer(tail_);
            if (!body.empty()) bufs[n++] = asio::buffer(body);
            switch (n) {
                case 1:
                    asio::async_write(socket_, bufs[0], done);
                    return;
                case 2:
                    asio::async_write(socket_, std::array<asio::const_buffer, 2>{bufs[0], bufs[1]}, done);
                    return;
                case 3:
                    asio::async_write(socket_, std::array<asio::const_buffer, 3>{bufs[0], bufs[1], bufs[2]}, done);
                    return;
                default:
                    asio::async_write(socket_, bufs, done);
                    return;
            }
        }
    }

    void on_write(const asio::error_code& ec) {
        if (ec) {
            close();
            return;
        }
        last_activity_ = std::chrono::steady_clock::now();
        if (sf_file_) {  // headers went out via writev; now the file
            sendfile_step();
            return;
        }
        if (auto* f = std::get_if<FileBody>(&response().body); f && !response().head && f->sent < f->size) {
            stream_chunk(*f);
            return;
        }
        finish_response();
    }

    // Copy path for file bodies (TLS, or platforms without sendfile): pread a chunk, write it.
    void stream_chunk(FileBody& fb) {
        if (chunk_.empty()) chunk_.resize(cfg_.stream_chunk_size);
        const std::uint64_t remaining = fb.size - fb.sent;
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk_.size()));
        const std::int64_t got = fb.file->read_at(chunk_.data(), want, fb.sent);
        if (got <= 0) {  // file shrank or read error: the client sees a short body
            close();
            return;
        }
        fb.sent += static_cast<std::uint64_t>(got);
        auto self = this->shared_from_this();
        asio::async_write(socket_, asio::buffer(chunk_.data(), static_cast<std::size_t>(got)),
                          immediate([self](const asio::error_code& ec, std::size_t) { self->on_write(ec); }));
    }

    // ---- zero-copy path for plain sockets ----
    // Sends the head (hdr_, block_, tail_) and the file with sendfile: the head rides in
    // the same call on macOS/FreeBSD; on Linux it is written first with writev. sendfile
    // runs until the socket buffer is full, then waits for writability.
    void begin_sendfile(const File* file, std::uint64_t size) {
        sf_file_ = file;
        sf_size_ = size;
        sf_sent_ = 0;
        hdr_sent_ = 0;
        hdr_total_ = hdr_.size() + block_.size() + tail_.size();
        if (!lowest().non_blocking()) {
            asio::error_code ec;
            lowest().non_blocking(true, ec);
        }
        // Cork for the duration of the transfer (nginx: tcp_nopush with sendfile). Measured on
        // Linux loopback: without it each spliced page batch leaves as its own small segment.
        set_tcp_cork(static_cast<int>(lowest().native_handle()), true);
        sendfile_step();
    }

    // Fills iov with the not-yet-sent head bytes. Returns the count.
    int pending_head(IoSlice* iov) const {
        const std::string_view pieces[3] = {hdr_, block_, tail_};
        std::size_t skip = hdr_sent_;
        int n = 0;
        for (const auto& piece : pieces) {
            if (skip >= piece.size()) {
                skip -= piece.size();
                continue;
            }
            iov[n++] = IoSlice{piece.data() + skip, piece.size() - skip};
            skip = 0;
        }
        return n;
    }

    void sendfile_step() {
        for (;;) {
            const std::uint64_t remaining = sf_size_ - sf_sent_;
            const std::size_t hdr_remaining = hdr_total_ - hdr_sent_;
            if (remaining == 0 && hdr_remaining == 0) {
                sf_file_ = nullptr;
                set_tcp_cork(static_cast<int>(lowest().native_handle()), false);  // flush the tail
                finish_response();
                return;
            }
            IoSlice iov[3];
            const int n = hdr_remaining ? pending_head(iov) : 0;
            // Cap each call (nginx's sendfile_max_chunk): a single 10 MB sendfile() was measured
            // at 3.85 ms of kernel time, six times nginx's 1 MB calls, because it holds the socket
            // lock against the receiver and the worker's loop for the whole transfer.
            const std::uint64_t count = std::min<std::uint64_t>(remaining, cfg_.sendfile_max_chunk);
            SendFileResult r =
                send_file(static_cast<int>(lowest().native_handle()), *sf_file_, sf_sent_, count, iov, n);
            if (r.headers_unsupported) {
                // Write the head with writev; on_write() comes back here for the file.
                auto self = this->shared_from_this();
                std::array<asio::const_buffer, 3> bufs;
                int k = 0;
                for (int i = 0; i < n; ++i)
                    bufs[k++] = asio::buffer(iov[i].data, iov[i].len);
                hdr_sent_ = hdr_total_;
                auto done = immediate([self](const asio::error_code& ec, std::size_t) { self->on_write(ec); });
                if (k == 1) asio::async_write(socket_, bufs[0], done);
                else if (k == 2) asio::async_write(socket_, std::array<asio::const_buffer, 2>{bufs[0], bufs[1]}, done);
                else asio::async_write(socket_, bufs, done);
                return;
            }
            if (r.unsupported) {  // no sendfile on this platform: use the writev + pread path
                sendfile_unsupported_ = true;
                sf_file_ = nullptr;
                write_response();
                return;
            }
            if (r.sent < 0) {
                close();
                return;
            }
            std::uint64_t sent = static_cast<std::uint64_t>(r.sent);
            if (hdr_remaining) {
                const std::uint64_t h = std::min<std::uint64_t>(sent, hdr_remaining);
                hdr_sent_ += static_cast<std::size_t>(h);
                sent -= h;
            }
            sf_sent_ += sent;
            if (r.would_block) {
                auto self = this->shared_from_this();
                lowest().async_wait(asio::ip::tcp::socket::wait_write, [self](const asio::error_code& ec) {
                    if (ec) {
                        self->close();
                        return;
                    }
                    self->last_activity_ = std::chrono::steady_clock::now();
                    self->sendfile_step();
                });
                return;
            }
            if (r.sent == 0) {  // file shrank underneath us
                close();
                return;
            }
        }
    }

    void finish_response() {
        const bool keep_alive = response().keep_alive;
        sf_file_ = nullptr;
        stream_.reset();
        if (consumed_ < in_len_) std::memmove(in_.data(), in_.data() + consumed_, in_len_ - consumed_);
        in_len_ -= consumed_;
        consumed_ = 0;
        if (!keep_alive) {
            close();
            return;
        }
        // Fairness: inline completions let a connection whose client answers instantly serve
        // request after request without returning to the event loop, starving the other
        // connections on this worker (seen as 2 s timeouts on Linux loopback). Every
        // kInlineBudget responses, hand the continuation back to the loop.
        if (++inline_runs_ >= kInlineBudget) {
            inline_runs_ = 0;
            auto self = this->shared_from_this();
            asio::post(worker_.ctx, [self] { self->next_request(); });
            return;
        }
        next_request();
    }

    void next_request() {
        if (in_len_ > 0) process();  // pipelined request already buffered
        else do_read();
    }

    void close() {
        asio::error_code ec;
        timer_.cancel();
        sf_file_ = nullptr;
        if (lowest().is_open()) {
            if constexpr (IsTlsStream<Socket>::value) socket_.shutdown_notify();
            lowest().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            lowest().close(ec);
        }
        stream_.reset();
    }

    Socket socket_;
    Worker& worker_;
    const Listener& listener_;
    const Config& cfg_;
    StaticHandler& handler_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::duration idle_timeout_;
    std::chrono::steady_clock::time_point last_activity_;
    std::vector<char> in_;
    std::size_t in_len_ = 0;
    std::size_t consumed_ = 0;
    std::uint32_t requests_served_ = 0;
    static constexpr unsigned kInlineBudget = 8;  // responses served inline before yielding to the loop
    unsigned inline_runs_ = 0;
    std::vector<char> chunk_;
    std::vector<char> out_;   // TLS only: coalesced head + body prefix
    std::string hdr_;         // status line + Server + Date
    std::string_view block_;  // the response's prebuilt block (view; kept alive by the response)
    std::string tail_;        // extra fields + blank line, empty on the fast path
    bool sendfile_unsupported_ = false;
    const File* sf_file_ = nullptr;  // sendfile in progress (entry fd or the response's owned file)
    std::uint64_t sf_size_ = 0, sf_sent_ = 0;
    std::size_t hdr_total_ = 0, hdr_sent_ = 0;
    Stream stream_;
};

}  // namespace agensio
