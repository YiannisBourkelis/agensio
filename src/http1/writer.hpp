// HTTP/1 response writer: turns a Response into bytes on the socket. Owns the fast paths
// measured in phase 1 and keeps them exactly as they were before the A2 split:
//   * plain socket, memory body: one writev of up to four pieces, nothing concatenated
//     (per-worker "status + Server + Date" prefix, the response's prebuilt block, the
//     extra fields, the body);
//   * TLS: head and body prefix coalesced into one full-size record;
//   * files on plain sockets: sendfile with the head attached (macOS/FreeBSD) or written
//     first (Linux); files on TLS: pread + write in stream_chunk_size pieces;
// and the pull path for StreamBody sources (FastCGI, proxy, CGI in later phases): one
// chunk is requested only after the previous one has been handed to the kernel, with
// chunked transfer coding when the source does not know its length.
//
// The connection (Owner) provides the socket, its own lifetime (shared_from_this) and
// three callbacks: on_response_written() when every byte of the response has been handed
// to the kernel, close() on a transport error, and touch() on progress for the idle timer.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/strings.hpp"
#include "core/worker_state.hpp"
#include "file.hpp"
#include "http1/chunked.hpp"
#include "response.hpp"
#include "tls_stream.hpp"

namespace agensio {

template <class Socket>
struct IsTlsStream : std::false_type {};
#ifdef AGENSIO_HAS_TLS
template <>
struct IsTlsStream<TlsStream> : std::true_type {};
template <class S>
struct IsTlsStream<BasicTlsStream<S>> : std::true_type {};
#endif

template <class Socket, class Owner>
class Http1Writer {
public:
    Http1Writer(Socket& socket, Owner& owner, asio::io_context& ctx, const Config& cfg)
        : socket_(socket), owner_(owner), ctx_(ctx), cfg_(cfg) {
        hdr_.reserve(256);
        tail_.reserve(128);
    }

    Http1Writer(const Http1Writer&) = delete;
    Http1Writer& operator=(const Http1Writer&) = delete;

    // Writes stream.response. ws.now must be current (the connection sets it per request).
    // Completes through the owner callbacks; `stream` must stay alive until then.
    void write(Stream& stream, WorkerState& ws) {
        stream_ = &stream;
        source_done_ = false;
        body_sent_ = 0;
        build_head(ws);
        start();
    }

    // Body bytes handed to the kernel for the current or last response (access log).
    std::uint64_t body_bytes_sent() const noexcept { return body_sent_; }

    // Idle: the chunk and coalescing buffers go (they come back on first use).
    void shed() noexcept {
        std::vector<char>().swap(chunk_);
        std::vector<char>().swap(out_);
    }

    // Forgets any transfer in progress (the connection is closing).
    void reset() noexcept {
        sf_file_ = nullptr;
        stream_ = nullptr;
    }

private:
    auto& lowest() { return socket_.lowest_layer(); }
    Response& response() { return stream_->response; }

    // Speculative completions (write done at once) run inline instead of being posted,
    // which saves a scheduler hop and a kevent poll per request.
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(ctx_.get_executor(), std::forward<F>(f));
    }
    std::shared_ptr<Owner> self() { return owner_.shared_from_this(); }
    auto write_done() {
        return immediate([self = self(), this](const asio::error_code& ec, std::size_t) { on_write(ec); });
    }

    static StreamBody* source_of(Response& r) noexcept {
        auto* p = std::get_if<std::unique_ptr<StreamBody>>(&r.body);
        return p ? p->get() : nullptr;
    }

    // ---- head ----
    // Written as up to three pieces without concatenation: hdr_ (status line, Server,
    // Date), the response's prebuilt block, and tail_ (extra fields + blank line). With no
    // extra fields and a terminated prebuilt block, tail_ is not needed at all.
    // A StreamBody is framed here: Content-Length when the source knows its length,
    // otherwise chunked (HTTP/1.1) or close-delimited (HTTP/1.0). Handlers that produce a
    // StreamBody must not add those fields themselves.

    void build_head(WorkerState& ws) {
        Response& r = response();
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
        chunked_ = false;
        std::uint64_t source_length = 0;
        bool source_sized = false;
        const StreamBody* source = source_of(r);
        if (source) {
            source_sized = source->length(source_length);
            source_sized_ = source_sized;
            source_remaining_ = source_length;
            if (!source_sized) {
                if (stream_->request.version_minor >= 1) chunked_ = true;
                else r.keep_alive = false;  // HTTP/1.0: the end of the connection delimits the body
            }
        }
        const bool close_line = !r.keep_alive;
        const bool keepalive_line = r.keep_alive && stream_->request.version_minor == 0;
        if (r.headers.empty() && !close_line && !keepalive_line && r.prebuilt_terminated && !source) {
            if (r.alt_svc_line.empty()) {
                block_ = r.prebuilt_headers;
                tail_.clear();
                return;
            }
            // The alt-svc line before the terminator: the block borrowed up to its last line,
            // the prebuilt line and the blank line copied into the tail (a few dozen bytes).
            block_ = slice(r.prebuilt_headers, 0, r.prebuilt_headers.size() - 2);
            tail_.assign(r.alt_svc_line);
            tail_.append("\r\n");
            return;
        }
        block_ =
            r.prebuilt_terminated ? slice(r.prebuilt_headers, 0, r.prebuilt_headers.size() - 2) : r.prebuilt_headers;
        tail_.assign(r.alt_svc_line);
        for (const HeaderField& h : r.headers)
            tail_.append(h.name).append(": ").append(h.value).append("\r\n");
        if (source_sized) {
            tail_.append("Content-Length: ");
            append_number(tail_, source_length);
            tail_.append("\r\n");
        } else if (chunked_) {
            tail_.append("Transfer-Encoding: chunked\r\n");
        }
        if (close_line) tail_.append("Connection: close\r\n");
        else if (keepalive_line) tail_.append("Connection: keep-alive\r\n");
        tail_.append("\r\n");
    }

    std::string_view memory_body() const {
        const Response& r = stream_->response;
        if (r.head) return {};
        if (const auto* m = std::get_if<MemoryBody>(&r.body)) return m->data;
        return {};
    }

    // ---- head + memory body, or head followed by a file / source ----

    void start() {
        Response& r = response();
        const std::string_view body = memory_body();
        body_sent_ = body.size();  // memory bodies go out whole; file paths count as they send
        auto done = write_done();
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
                    // page cache, headers attached to the same call where supported. A
                    // range is a slice of the entry's bytes: its offset is the slice's.
                    begin_sendfile(&r.entry->fd, m->data.size(),
                                   static_cast<std::uint64_t>(m->data.data() - r.entry->data.data()));
                    return;
                }
                if (const auto* f = std::get_if<FileBody>(&r.body)) {
                    begin_sendfile(f->file, f->size, f->offset);
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
            owner_.close();
            return;
        }
        owner_.touch();
        if (sf_file_) {  // headers went out via writev; now the file
            sendfile_step();
            return;
        }
        Response& r = response();
        if (!r.head) {
            if (auto* f = std::get_if<FileBody>(&r.body); f && f->sent < f->size) {
                stream_chunk(*f);
                return;
            }
            if (StreamBody* source = source_of(r); source && !source_done_) {
                pull(*source);
                return;
            }
        }
        finish();
    }

    void finish() {
        sf_file_ = nullptr;
        stream_ = nullptr;
        owner_.on_response_written();
    }

    // ---- copy path for file bodies (TLS, or platforms without sendfile) ----

    void stream_chunk(FileBody& fb) {
        if (chunk_.empty()) chunk_.resize(cfg_.stream_chunk_size);
        const std::uint64_t remaining = fb.size - fb.sent;
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk_.size()));
        const std::int64_t got = fb.file->read_at(chunk_.data(), want, fb.offset + fb.sent);
        if (got <= 0) {  // file shrank or read error: the client sees a short body
            owner_.close();
            return;
        }
        fb.sent += static_cast<std::uint64_t>(got);
        body_sent_ += static_cast<std::uint64_t>(got);
        asio::async_write(socket_, asio::buffer(chunk_.data(), static_cast<std::size_t>(got)), write_done());
    }

    // ---- pull path for StreamBody sources ----
    // Backpressure: the next chunk is requested only from on_write, i.e. after the
    // previous one has been handed to the kernel.

    // A source that declared its length is held to it: never more bytes than declared
    // (the surplus would be read as the next response on a keep-alive connection), and
    // if it ends short the connection is closed so the client sees the truncation
    // instead of a misframed next response.
    void pull(StreamBody& source) {
        if (chunk_.empty()) chunk_.resize(cfg_.stream_chunk_size);
        if (source_sized_ && source_remaining_ == 0) {
            source_done_ = true;
            finish();
            return;
        }
        std::size_t want = chunk_.size();
        if (source_sized_) want = static_cast<std::size_t>(std::min<std::uint64_t>(source_remaining_, want));
        source.async_read(chunk_.data(), want,
                          [self = self(), this](std::error_code ec, std::size_t n) { on_pulled(ec, n); });
    }

    void on_pulled(std::error_code ec, std::size_t n) {
        if (ec) {  // the source failed mid-body: cut the connection so the client sees a short body
            owner_.close();
            return;
        }
        if (n == 0) {
            if (source_sized_ && source_remaining_ > 0) {  // declared more than it delivered
                owner_.close();
                return;
            }
            source_done_ = true;
            if (chunked_) asio::async_write(socket_, asio::buffer(kLastChunk), write_done());
            else finish();
            return;
        }
        if (source_sized_) {
            if (n > source_remaining_) n = static_cast<std::size_t>(source_remaining_);
            source_remaining_ -= n;
        }
        body_sent_ += n;
        if (chunked_) {
            const std::string_view size_line = chunk_size_line(n, chunk_size_);
            asio::async_write(socket_,
                              std::array<asio::const_buffer, 3>{asio::buffer(size_line), asio::buffer(chunk_.data(), n),
                                                                asio::buffer(kCrlf)},
                              write_done());
        } else {
            asio::async_write(socket_, asio::buffer(chunk_.data(), n), write_done());
        }
    }

    // ---- zero-copy path for plain sockets ----
    // Sends the head (hdr_, block_, tail_) and the file with sendfile: the head rides in
    // the same call on macOS/FreeBSD; on Linux it is written first with writev. sendfile
    // runs until the socket buffer is full, then waits for writability.

    void begin_sendfile(const File* file, std::uint64_t size, std::uint64_t offset = 0) {
        sf_file_ = file;
        sf_size_ = size;
        sf_offset_ = offset;
        sf_sent_ = 0;
        body_sent_ = 0;
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
                finish();
                return;
            }
            IoSlice iov[3];
            const int n = hdr_remaining ? pending_head(iov) : 0;
            // Cap each call (nginx's sendfile_max_chunk): a single 10 MB sendfile() was measured
            // at 3.85 ms of kernel time, six times nginx's 1 MB calls, because it holds the socket
            // lock against the receiver and the worker's loop for the whole transfer.
            const std::uint64_t count = std::min<std::uint64_t>(remaining, cfg_.sendfile_max_chunk);
            SendFileResult r =
                send_file(static_cast<int>(lowest().native_handle()), *sf_file_, sf_offset_ + sf_sent_, count, iov, n);
            if (r.headers_unsupported) {
                // Write the head with writev; on_write() comes back here for the file.
                std::array<asio::const_buffer, 3> bufs;
                int k = 0;
                for (int i = 0; i < n; ++i)
                    bufs[k++] = asio::buffer(iov[i].data, iov[i].len);
                hdr_sent_ = hdr_total_;
                auto done = write_done();
                if (k == 1) asio::async_write(socket_, bufs[0], done);
                else if (k == 2) asio::async_write(socket_, std::array<asio::const_buffer, 2>{bufs[0], bufs[1]}, done);
                else asio::async_write(socket_, bufs, done);
                return;
            }
            if (r.unsupported) {  // no sendfile on this platform: use the writev + pread path
                sendfile_unsupported_ = true;
                sf_file_ = nullptr;
                start();
                return;
            }
            if (r.sent < 0) {
                owner_.close();
                return;
            }
            std::uint64_t sent = static_cast<std::uint64_t>(r.sent);
            if (hdr_remaining) {
                const std::uint64_t h = std::min<std::uint64_t>(sent, hdr_remaining);
                hdr_sent_ += static_cast<std::size_t>(h);
                sent -= h;
            }
            sf_sent_ += sent;
            body_sent_ += sent;
            if (r.would_block) {
                lowest().async_wait(asio::ip::tcp::socket::wait_write,
                                    [self = self(), this](const asio::error_code& ec) {
                                        if (ec) {
                                            owner_.close();
                                            return;
                                        }
                                        owner_.touch();
                                        sendfile_step();
                                    });
                return;
            }
            if (r.sent == 0) {  // file shrank underneath us
                owner_.close();
                return;
            }
        }
    }

    static constexpr std::string_view kCrlf = "\r\n";

    Socket& socket_;
    Owner& owner_;
    asio::io_context& ctx_;
    const Config& cfg_;
    Stream* stream_ = nullptr;  // the response being written; owned by the connection
    std::vector<char> chunk_;   // pread / source chunk
    std::vector<char> out_;     // TLS only: coalesced head + body prefix
    std::string hdr_;           // status line + Server + Date
    std::string_view block_;    // the response's prebuilt block (view; kept alive by the response)
    std::string tail_;          // extra fields + blank line, empty on the fast path
    std::uint64_t body_sent_ = 0;  // body bytes handed to the kernel (access log)
    bool chunked_ = false;      // StreamBody of unknown length on HTTP/1.1
    bool source_done_ = false;  // StreamBody reported end of body
    bool source_sized_ = false;         // the StreamBody declared its length
    std::uint64_t source_remaining_ = 0;  // bytes of that length still to send
    ChunkSizeBuffer chunk_size_{};
    bool sendfile_unsupported_ = false;
    const File* sf_file_ = nullptr;  // sendfile in progress (entry fd or the response's owned file)
    std::uint64_t sf_size_ = 0, sf_sent_ = 0, sf_offset_ = 0;
    std::size_t hdr_total_ = 0, hdr_sent_ = 0;
};

}  // namespace agensio
