// One HTTP/1.x client connection: the I/O loop. Reads request heads into the receive
// buffer, parses them, drives exactly one Stream through the handler, and hands the
// Response to the Http1Writer. Keep-alive, pipelining (unconsumed bytes stay in the
// buffer), the idle timer, the per-connection request cap and the inline-completion
// fairness budget live here; nothing here knows how a Response becomes bytes.
// Instantiated for a plain TCP socket and for a TLS stream.
#pragma once

#include <chrono>
#include <cstring>
#include <ctime>
#include <memory>
#include <vector>

#include <asio.hpp>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "handlers/static.hpp"
#include "http1/parser.hpp"
#include "http1/writer.hpp"
#include "server.hpp"

namespace agensio {

template <class Socket>
class Http1Connection : public std::enable_shared_from_this<Http1Connection<Socket>> {
public:
    Http1Connection(Socket&& socket, Worker& worker, const Listener& listener, const Config& cfg,
                    StaticHandler& handler)
        : socket_(std::move(socket)),
          worker_(worker),
          listener_(listener),
          cfg_(cfg),
          handler_(handler),
          timer_(worker.ctx),
          idle_timeout_(std::chrono::seconds(cfg.idle_timeout_s)),
          in_(cfg.max_header_size),
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

    // The whole response has been handed to the kernel: next request or close.
    void on_response_written() {
        const bool keep_alive = stream_.response.keep_alive;
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

    void close() {
        asio::error_code ec;
        timer_.cancel();
        writer_.reset();
        if (lowest().is_open()) {
            if constexpr (IsTlsStream<Socket>::value) socket_.shutdown_notify();
            lowest().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            lowest().close(ec);
        }
        stream_.reset();
    }

private:
    auto& lowest() { return socket_.lowest_layer(); }

    // Speculative completions (data already readable) run inline instead of being posted.
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
        process();
    }

    void process() {
        switch (parse_request(std::string_view(in_.data(), in_len_), stream_.request)) {
            case ParseStatus::complete:
                consumed_ = stream_.request.length;
                worker_.state.now = std::time(nullptr);
                handler_.handle(stream_, listener_.route, worker_.state);
                if (cfg_.max_requests_per_connection != 0 && ++requests_served_ >= cfg_.max_requests_per_connection)
                    stream_.response.keep_alive = false;  // cap reached: this is the last response
                writer_.write(stream_, worker_.state);
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
        writer_.write(stream_, worker_.state);
    }

    void next_request() {
        if (in_len_ > 0) process();  // pipelined request already buffered
        else do_read();
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
    Stream stream_;
    Http1Writer<Socket, Http1Connection> writer_;  // last: it references socket_ and *this
};

}  // namespace agensio
