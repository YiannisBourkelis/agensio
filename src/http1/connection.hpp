// One HTTP/1.x client connection: the I/O loop. Reads request heads into the receive
// buffer, parses them, drives exactly one Stream through the handler, and hands the
// Response to the Http1Writer. Keep-alive, pipelining (unconsumed bytes stay in the
// buffer), the idle and body timeouts, the per-connection request cap and the
// inline-completion fairness budget live here; nothing here knows how a Response
// becomes bytes.
//
// Request bodies (A3): the connection is the body's pull source (Request::body). It
// decodes Content-Length or chunked framing from the receive buffer and the socket,
// enforces server.max_body_size (413 up front when the length is declared, an error
// mid-stream otherwise) and server.body_timeout, sends "100 Continue" on the first read
// when the client asked for it, and drains whatever the handler did not read after the
// response so keep-alive and pipelining survive. Instantiated for a plain TCP socket and
// for a TLS stream.
#pragma once

#include <algorithm>
#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/body.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "handlers/dispatch.hpp"
#include "net/cidr.hpp"
#include "http1/chunked.hpp"
#include "http1/parser.hpp"
#include "http1/writer.hpp"
#include "server.hpp"
#include "services/log.hpp"

namespace agensio {

template <class Socket>
class Http1Connection : public std::enable_shared_from_this<Http1Connection<Socket>> {
public:
    Http1Connection(Socket&& socket, Worker& worker, const Listener& listener, const Config& cfg,
                    Dispatcher& dispatcher)
        : socket_(std::move(socket)),
          worker_(worker),
          listener_(listener),
          cfg_(cfg),
          dispatcher_(dispatcher),
          timer_(worker.ctx),
          idle_timeout_(std::chrono::seconds(cfg.idle_timeout_s)),
          body_timeout_(std::chrono::seconds(cfg.body_timeout_s)),
          in_(cfg.max_header_size),
          body_source_(*this),
          writer_(socket_, *this, worker.ctx, cfg) {
        worker_.connections.fetch_add(1, std::memory_order_relaxed);
    }

    Http1Connection(const Http1Connection&) = delete;
    Http1Connection& operator=(const Http1Connection&) = delete;
    ~Http1Connection() { worker_.connections.fetch_sub(1, std::memory_order_relaxed); }

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

    // ---- callbacks for the writer ----

    // Progress on the socket: feeds the idle timer. Refreshed once per response, not per
    // read; a second clock read was visible in profiles and buys nothing for the timer.
    void touch() noexcept { last_activity_ = std::chrono::steady_clock::now(); }

    // The whole response has been handed to the kernel: drain an unread body, then the
    // next request, or close.
    void on_response_written() {
        responding_ = false;
        const bool keep_alive = stream_.response.keep_alive;
        log_request();
        if (peer_) {
            const std::uint32_t idle_s = stream_.response.tunnel_timeout_s;
            stream_.reset();
            compact();
            start_tunnel(idle_s);
            return;
        }
        stream_.reset();
        compact();
        // Bytes of a pipelined next request that arrived together with the body go back to
        // the head buffer, which now has room (the body was only read after in_ was drained).
        if (bpos_ < blen_) {
            const std::size_t n = std::min(blen_ - bpos_, in_.size() - in_len_);
            std::memcpy(in_.data() + in_len_, body_buf_.data() + bpos_, n);
            in_len_ += n;
            bpos_ += n;
            if (bpos_ == blen_) bpos_ = blen_ = 0;
        }
        if (!keep_alive) {
            close();
            return;
        }
        if (body_pending_) {
            drain();
            return;
        }
        after_response();
    }

    void close() {
        asio::error_code ec;
        timer_.cancel();
        ++request_gen_;  // a late upstream completion must not touch this connection
        if (upstream_) {
            upstream_->cancel();
            upstream_.reset();
        }
        if (!request_logged_ && stream_.request.length > 0) log_request();  // client went away mid-response
        tunnel_ = false;
        responding_ = false;
        if (peer_) {
            if (peer_->sock().is_open()) peer_->sock().close(ec);
            peer_.reset();
        }
        writer_.reset();
        body_pending_ = false;
        bpos_ = blen_ = 0;
        if (lowest().is_open()) {
            if constexpr (IsTlsStream<Socket>::value) socket_.shutdown_notify();
            lowest().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            lowest().close(ec);
        }
        stream_.reset();
    }

    // ---- request body: the pull source behind Request::body ----

    // Delivers up to len decoded body bytes into buf, 0 at the end of the body. Bytes
    // already in the receive buffer complete inline; otherwise one socket read runs under
    // the body timeout. Errors: BodyError::too_large, BodyError::malformed, or a transport
    // error, after which the connection is closed.
    void read_body(char* buf, std::size_t len, StreamBody::ReadHandler handler) {
        if (!body_pending_ || len == 0) {
            handler(std::error_code{}, 0);
            return;
        }
        if (expect_continue_ && !continue_sent_) {
            continue_sent_ = true;
            if (consumed_ >= in_len_) {  // the client is really waiting for our go-ahead
                auto self = this->shared_from_this();
                asio::async_write(socket_, asio::buffer(kContinue),
                                  [self, buf, len, h = std::move(handler)](const asio::error_code& ec,
                                                                           std::size_t) mutable {
                                      if (ec) {
                                          self->close();
                                          h(ec, 0);
                                          return;
                                      }
                                      self->read_body(buf, len, std::move(h));
                                  });
                return;
            }
        }
        // Body bytes come first from what arrived with the head (still in in_, after the
        // head) and then from body_buf_. The head buffer is never compacted while the
        // request is alive: the Request's views (target, Host, every header) point into it
        // and handlers read them after the body, so moving it would corrupt the params.
        const bool from_head_buf = consumed_ < in_len_;
        std::string_view avail;
        if (from_head_buf) avail = std::string_view(in_.data() + consumed_, in_len_ - consumed_);
        else if (bpos_ < blen_) avail = std::string_view(body_buf_.data() + bpos_, blen_ - bpos_);
        if (!avail.empty()) {
            std::size_t used = 0, produced = 0;
            std::error_code ec;
            const bool done = decode_body(avail, buf, len, used, produced, ec);
            if (from_head_buf) consumed_ += used;
            else bpos_ += used;
            if (ec) {
                body_pending_ = false;
                close();
                handler(ec, 0);
                return;
            }
            if (done) body_pending_ = false;
            if (produced > 0 || done) {
                handler(std::error_code{}, produced);
                return;
            }
            // Chunked framing consumed without data yet: fall through and read more.
        }
        if (body_buf_.empty()) body_buf_.resize(in_.size());
        if (bpos_ == blen_) bpos_ = blen_ = 0;
        if (blen_ >= body_buf_.size()) {  // cannot happen: the decoders always consume or produce
            body_pending_ = false;
            close();
            handler(make_error_code(BodyError::malformed), 0);
            return;
        }
        rearm(body_timeout_);
        auto self = this->shared_from_this();
        socket_.async_read_some(
            asio::buffer(body_buf_.data() + blen_, body_buf_.size() - blen_),
            immediate([self, buf, len, h = std::move(handler)](const asio::error_code& ec, std::size_t n) mutable {
                self->rearm(self->idle_timeout_);
                if (ec) {
                    self->close();
                    h(ec, 0);
                    return;
                }
                self->blen_ += n;
                self->read_body(buf, len, std::move(h));
            }));
    }

private:
    class BodySource final : public StreamBody {
    public:
        explicit BodySource(Http1Connection& c) noexcept : c_(c) {}
        bool length(std::uint64_t& out) const noexcept override {
            if (c_.body_chunked_) return false;
            out = c_.body_total_;
            return true;
        }
        void async_read(char* buf, std::size_t len, ReadHandler handler) override {
            c_.read_body(buf, len, std::move(handler));
        }

    private:
        Http1Connection& c_;  // the connection owns this object
    };

    static constexpr std::string_view kContinue = "HTTP/1.1 100 Continue\r\n\r\n";

    // One access log line per request, when the site logs. Costs nothing when it does not:
    // one pointer test. The client address is resolved once per connection, lazily.
    void log_request() {
        request_logged_ = true;
        const auto* site = static_cast<const SiteConfig*>(worker_.state.site);
        if (!site) site = listener_.router.default_site();
        if (!site || site->access_log_sink < 0) return;
        if (remote_.empty()) {
            asio::error_code ec;
            const auto ep = lowest().remote_endpoint(ec);
            remote_ = ec ? std::string("-") : ep.address().to_string();
        }
        const Request& req = stream_.request;
        AccessRecord rec;
        rec.remote = stream_.conn.client_address.empty() ? std::string_view(remote_) : stream_.conn.client_address;
        rec.host = req.host;
        rec.method = req.method_name;
        rec.target = req.target;
        rec.version_minor = req.version_minor;
        rec.status = stream_.response.status;
        rec.bytes = writer_.body_bytes_sent();
        rec.referer = req.headers.get("referer");
        rec.user_agent = req.headers.get("user-agent");
        if (stream_.response.upstream) rec.upstream = stream_.response.upstream;
        worker_.state.logs.log(site->access_log_sink, worker_.state.now, rec);
    }
    static constexpr std::size_t kDrainChunk = 8192;

    auto& lowest() { return socket_.lowest_layer(); }

    // Speculative completions (data already readable) run inline instead of being posted.
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(worker_.ctx.get_executor(), std::forward<F>(f));
    }

    // ---- timers ----

    void arm_timer(std::chrono::steady_clock::duration d) {
        auto self = this->shared_from_this();
        timer_.expires_after(d);
        timer_.async_wait([self](const asio::error_code& ec) {
            if (ec) return;  // cancelled
            if (!self->lowest().is_open()) return;
            auto idle = std::chrono::steady_clock::now() - self->last_activity_;
            if (idle >= self->timeout_) self->close();
            else self->arm_timer(self->timeout_ - idle);
        });
    }

    // Switches between the idle and the body timeout (only around body reads).
    void rearm(std::chrono::steady_clock::duration d) {
        timeout_ = d;
        last_activity_ = std::chrono::steady_clock::now();
        timer_.cancel();
        arm_timer(d);
    }

    // ---- reading ----

    void do_read() {
        if (read_pending_) return;  // an abort watch's read is out: its completion continues here
        if (in_len_ >= in_.size()) {  // buffer full without a complete request head
            fail_request(431);
            return;
        }
        arm_read();
    }

    // The one read this connection may have in flight, whatever state it is in: the next
    // request head, a client-abort watch during an upstream exchange, or the tunnel's
    // client side. on_read() routes the completion by state.
    void arm_read() {
        read_pending_ = true;
        auto self = this->shared_from_this();
        socket_.async_read_some(asio::buffer(in_.data() + in_len_, in_.size() - in_len_),
                                immediate([self](const asio::error_code& ec, std::size_t n) { self->on_read(ec, n); }));
    }

    void on_read(const asio::error_code& ec, std::size_t n) {
        read_pending_ = false;
        if (tunnel_) {
            if (ec) return tunnel_client_eof();
            last_activity_ = std::chrono::steady_clock::now();
            in_len_ += n;
            tunnel_write_peer(in_len_);
            return;
        }
        if (ec) {
            close();  // also cancels an exchange in flight: the client is gone (E9)
            return;
        }
        in_len_ += n;
        // Bytes that arrive during an exchange or while the response goes out belong to a
        // pipelined next request: kept, parsed once this response is done.
        if (upstream_ || responding_) return;
        process();
    }

    // E9: an exchange that has run for a tick is watched for its client leaving, so the
    // pool slot and the application's work are given back instead of held until the
    // answer arrives. Fast exchanges never arm this (no syscall on the common path); a
    // body still being read keeps the body reader as the watch.
    static void on_slow_exchange(void* ctx, unsigned gen) {
        auto* self = static_cast<Http1Connection*>(ctx);
        if (self->request_gen_ != gen || !self->upstream_ || self->body_pending_ || self->read_pending_) return;
        if (self->in_len_ >= self->in_.size()) return;  // no room to notice anything
        self->arm_read();
    }

    void process() {
        Request& req = stream_.request;
        switch (parse_request(std::string_view(in_.data(), in_len_), req)) {
            case ParseStatus::complete:
                break;
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
            case ParseStatus::unsupported_transfer_encoding:
                fail_request(501);
                return;
            case ParseStatus::expectation_failed:
                fail_request(417);
                return;
        }
        consumed_ = req.length;
        request_logged_ = false;
        worker_.state.site = nullptr;
        if (req.has_body) {
            if (!req.chunked && req.content_length > cfg_.max_body_size) {
                fail_request(413);  // refused before the handler runs; the client gets it while it may still be sending
                return;
            }
            body_pending_ = true;
            body_chunked_ = req.chunked;
            body_total_ = req.content_length;
            body_read_ = 0;
            expect_continue_ = req.expect_continue;
            continue_sent_ = false;
            if (body_chunked_) chunked_.reset();
            req.body = &body_source_;
        }
        worker_.state.now = std::time(nullptr);
        if (!cfg_.trusted_proxies.empty()) apply_forwarded();
        dispatch();
    }

    // Behind a trusted proxy: the client is the rightmost X-Forwarded-For entry that is not
    // itself a trusted proxy, and X-Forwarded-Proto says whether it used TLS.
    void apply_forwarded() {
        stream_.conn.client_address = {};
        stream_.conn.forwarded_https = false;
        fill_connection_info();
        if (!trusted_checked_) {
            trusted_peer_ = in_any(cfg_.trusted_proxies, remote_addr_);
            trusted_checked_ = true;
        }
        stream_.conn.trusted_peer = trusted_peer_;
        if (!trusted_peer_) return;
        const Request& req = stream_.request;
        std::string_view xff = req.headers.get("x-forwarded-for");
        while (!xff.empty()) {
            const std::size_t comma = xff.rfind(',');
            std::string_view entry = comma == std::string_view::npos ? xff : xff.substr(comma + 1);
            xff = comma == std::string_view::npos ? std::string_view() : xff.substr(0, comma);
            while (!entry.empty() && (entry.front() == ' ' || entry.front() == '\t')) entry.remove_prefix(1);
            while (!entry.empty() && (entry.back() == ' ' || entry.back() == '\t')) entry.remove_suffix(1);
            if (entry.empty()) continue;
            asio::error_code ec;
            const auto a = asio::ip::make_address(std::string(entry), ec);
            if (ec) break;  // garbage: trust nothing further left
            client_addr_ = entry;
            stream_.conn.client_address = client_addr_;
            if (!in_any(cfg_.trusted_proxies, a)) break;  // first hop that is not one of ours
        }
        const std::string_view proto = req.headers.get("x-forwarded-proto");
        stream_.conn.forwarded_https = Headers::iequals(proto, "https");
    }

    // ---- tunnel (D3): after a 101 the connection is two byte pumps ----
    // Client bytes go to the origin, origin bytes to the client, each direction with its
    // own buffer and read in flight. Whatever either side had already sent past the head
    // goes first. A side's EOF half-closes the other; the second EOF or any error ends
    // both. Idle limit: the connection's own timer with the tunnel's timeout (0 = none).

    void start_tunnel(std::uint32_t idle_s) {
        tunnel_ = true;
        body_pending_ = false;
        if (idle_s == 0) timer_.cancel();
        else rearm(std::chrono::seconds(idle_s));
        peer_->sock().set_option(asio::ip::tcp::no_delay(true), tunnel_ec_);
        if (peer_->in.size() < 16 * 1024) peer_->in.resize(16 * 1024);
        // Client bytes after the request head (in_[0, in_len_)) and origin bytes after
        // the 101 head (peer_->in[0, in_len)) are forwarded before the pumps start reading.
        if (in_len_ > 0) tunnel_write_peer(in_len_);
        else if (!read_pending_) tunnel_read_client();  // a pending abort watch delivers into the tunnel
        if (peer_->in_len > 0) tunnel_write_client(peer_->in_len);
        else tunnel_read_peer();
    }

    void tunnel_read_client() {
        in_len_ = 0;
        arm_read();  // completes in on_read(), which routes to tunnel_write_peer while tunnel_ is set
    }

    void tunnel_write_peer(std::size_t n) {
        auto self = this->shared_from_this();
        peer_->async_write(asio::buffer(in_.data(), n),
                          immediate([self](const asio::error_code& ec, std::size_t) {
                              if (!self->tunnel_) return;
                              if (ec) return self->close();
                              self->in_len_ = 0;
                              self->tunnel_read_client();
                          }));
    }

    void tunnel_read_peer() {
        auto self = this->shared_from_this();
        peer_->async_read_some(asio::buffer(peer_->in.data(), peer_->in.size()),
                                      immediate([self](const asio::error_code& ec, std::size_t n) {
                                          if (!self->tunnel_) return;
                                          if (ec) return self->tunnel_peer_eof();
                                          self->last_activity_ = std::chrono::steady_clock::now();
                                          self->tunnel_write_client(n);
                                      }));
    }

    void tunnel_write_client(std::size_t n) {
        auto self = this->shared_from_this();
        asio::async_write(socket_, asio::buffer(peer_->in.data(), n),
                          immediate([self](const asio::error_code& ec, std::size_t) {
                              if (!self->tunnel_) return;
                              if (ec) return self->close();
                              self->peer_->in_len = 0;
                              self->tunnel_read_peer();
                          }));
    }

    void tunnel_client_eof() {
        client_eof_ = true;
        if (peer_eof_) return close();
        peer_->sock().shutdown(asio::socket_base::shutdown_send, tunnel_ec_);
    }

    void tunnel_peer_eof() {
        peer_eof_ = true;
        if (client_eof_) return close();
        if constexpr (IsTlsStream<Socket>::value) {
            close();  // TLS has no half-close worth the name: close_notify ends the session
        } else {
            lowest().shutdown(asio::ip::tcp::socket::shutdown_send, tunnel_ec_);
        }
    }

    // Routes the request and runs its handler; static completes inline, FastCGI later.
    void dispatch() {
        WorkerState& ws = worker_.state;
        const LocationConfig* loc = dispatcher_.route(stream_, listener_.router, ws);
        int hops = 0;
        while (loc) {
            if (loc->kind != HandlerKind::static_) {  // FastCGI or proxy: completes asynchronously
                fill_connection_info();
                const unsigned gen = ++request_gen_;
                auto self = this->shared_from_this();
                auto done = [self, gen] {
                    if (self->request_gen_ != gen) return;  // connection closed meanwhile
                    // A 101: the origin connection becomes the other end of a tunnel once
                    // the head is out (on_response_written).
                    if (self->stream_.response.upgrade && self->upstream_) self->peer_ = self->upstream_->take_connection();
                    self->upstream_.reset();
                    self->respond();
                };
                const auto* site = static_cast<const SiteConfig*>(ws.site);
                std::shared_ptr<UpstreamRequest> req =
                    loc->kind == HandlerKind::fastcgi
                        ? dispatcher_.fcgi().start(stream_, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                    : loc->kind == HandlerKind::cgi
                        ? dispatcher_.cgi().start(stream_, *site, *loc, ws, worker_.upstream_pool, std::move(done))
                        : dispatcher_.proxy().start(stream_, *loc, ws, worker_.upstream_pool, std::move(done));
                if (req && request_gen_ == gen) {
                    upstream_ = std::move(req);
                    upstream_->on_slow(&Http1Connection::on_slow_exchange, this, gen);
                }
                return;
            }
            loc = dispatcher_.serve_static(stream_, *loc, ws, hops);
        }
        respond();
    }

    // The response is filled in: apply connection policy and hand it to the writer.
    void respond() {
        Response& r = stream_.response;
        if (cfg_.max_requests_per_connection != 0 && ++requests_served_ >= cfg_.max_requests_per_connection)
            r.keep_alive = false;  // cap reached: this is the last response
        // A client waiting for "100 Continue" that gets a final answer instead will not send
        // the body, so there is nothing to drain: close after the response (RFC 9110 10.1.1).
        if (body_pending_ && expect_continue_ && !continue_sent_ && consumed_ >= in_len_) r.keep_alive = false;
        responding_ = true;
        writer_.write(stream_, worker_.state);
    }

    // Client address and listener for handlers that need them (FastCGI params), once.
    void fill_connection_info() {
        if (!stream_.conn.local_port) {
            stream_.conn.local_address = listener_.address_text;
            stream_.conn.local_port = listener_.port;
            stream_.conn.tls = IsTlsStream<Socket>::value;
        }
        if (remote_.empty()) {
            asio::error_code ec;
            const auto ep = lowest().remote_endpoint(ec);
            remote_ = ec ? std::string("-") : ep.address().to_string();
            remote_port_ = ec ? 0 : ep.port();
            if (!ec) remote_addr_ = ep.address();
        }
        stream_.conn.remote_address = remote_;
        stream_.conn.remote_port = remote_port_;
    }

    // Protocol-level error: answer, drop whatever is buffered, close.
    void fail_request(int status) {
        worker_.state.now = std::time(nullptr);
        request_logged_ = false;
        worker_.state.site = nullptr;
        dispatcher_.static_handler().error(stream_, status, false);
        consumed_ = in_len_;
        body_pending_ = false;
        writer_.write(stream_, worker_.state);
    }

    // Decodes body bytes from `avail` into buf. Sets used/produced; returns true at the end
    // of the body. Errors (framing, size limit) are reported in ec.
    bool decode_body(std::string_view avail, char* buf, std::size_t len, std::size_t& used, std::size_t& produced,
                     std::error_code& ec) noexcept {
        if (body_chunked_) {
            const ChunkedDecoder::Status st = chunked_.decode(avail, used, buf, len, produced);
            body_read_ += produced;
            if (st == ChunkedDecoder::Status::error) {
                ec = make_error_code(BodyError::malformed);
                return false;
            }
            if (body_read_ > cfg_.max_body_size) {
                ec = make_error_code(BodyError::too_large);
                return false;
            }
            return st == ChunkedDecoder::Status::done;
        }
        const std::uint64_t remaining = body_total_ - body_read_;
        used = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, std::min(avail.size(), len)));
        std::memcpy(buf, avail.data(), used);
        produced = used;
        body_read_ += used;
        return body_read_ == body_total_;
    }

    // Discards the rest of a body the handler did not read, then continues with the next
    // request. Runs after the response so the client is not kept waiting for its answer.
    void drain() {
        if (drain_.empty()) drain_.resize(kDrainChunk);
        auto self = this->shared_from_this();
        read_body(drain_.data(), drain_.size(), [self](std::error_code ec, std::size_t n) {
            if (ec) return;  // read_body closed the connection
            if (n == 0 && !self->body_pending_) {
                self->compact();
                self->after_response();
                return;
            }
            self->drain();
        });
    }

    // Drops the consumed prefix of the receive buffer (head and body bytes already used).
    void compact() noexcept {
        if (consumed_ == 0) return;
        if (consumed_ < in_len_) std::memmove(in_.data(), in_.data() + consumed_, in_len_ - consumed_);
        in_len_ -= consumed_;
        consumed_ = 0;
    }

    void after_response() {
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

    Socket socket_;
    Worker& worker_;
    const Listener& listener_;
    const Config& cfg_;
    Dispatcher& dispatcher_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::duration idle_timeout_;
    std::chrono::steady_clock::duration body_timeout_;
    std::chrono::steady_clock::duration timeout_ = idle_timeout_;  // the one in effect
    std::chrono::steady_clock::time_point last_activity_;
    std::vector<char> in_;
    std::size_t in_len_ = 0;
    std::size_t consumed_ = 0;  // bytes of the current request (head, then body) already used
    std::uint32_t requests_served_ = 0;
    static constexpr unsigned kInlineBudget = 8;  // responses served inline before yielding to the loop
    unsigned inline_runs_ = 0;
    // Request body state.
    BodySource body_source_;
    bool body_pending_ = false;  // a body exists and has not been fully read
    bool read_pending_ = false;  // one client read in flight (head, abort watch or tunnel)
    bool responding_ = false;    // the writer is sending the response
    bool body_chunked_ = false;
    bool expect_continue_ = false;
    bool continue_sent_ = false;
    std::uint64_t body_total_ = 0;  // declared Content-Length
    std::uint64_t body_read_ = 0;   // decoded bytes delivered so far
    ChunkedDecoder chunked_;
    std::vector<char> drain_;  // scratch for discarding an unread body (allocated on first use)
    std::vector<char> body_buf_;  // body bytes read after the head (allocated on first use)
    std::size_t bpos_ = 0, blen_ = 0;
    std::string remote_;       // client address for the access log / handlers, resolved on first use
    std::uint16_t remote_port_ = 0;
    asio::ip::address remote_addr_;
    std::string client_addr_;      // from X-Forwarded-For when the peer is a trusted proxy
    bool trusted_checked_ = false;
    bool trusted_peer_ = false;
    bool request_logged_ = false;
    unsigned request_gen_ = 0;               // bumps per request and on close; guards late upstream callbacks
    std::shared_ptr<UpstreamRequest> upstream_;  // FastCGI/proxy exchange in flight, cancelled on close
    std::unique_ptr<UpstreamConnection> peer_;   // the origin side of a tunnel after a 101
    bool tunnel_ = false;
    bool client_eof_ = false;
    bool peer_eof_ = false;
    asio::error_code tunnel_ec_;
    Stream stream_;
    Http1Writer<Socket, Http1Connection> writer_;  // last: it references socket_ and *this
};

}  // namespace agensio
