// One client connection: reads requests, runs the handler, writes the plan.
// Instantiated for a plain TCP socket and for a TLS stream.
#pragma once

#include <array>
#include <chrono>
#include <cstring>
#include <memory>
#include <vector>

#include <asio.hpp>
#ifdef AGENSIO_HAS_TLS
#include <asio/ssl.hpp>
#endif

#include "config.hpp"
#include "handler.hpp"
#include "http_parser.hpp"
#include "server.hpp"

namespace agensio {

template <class Stream>
struct is_tls_stream : std::false_type {};
#ifdef AGENSIO_HAS_TLS
template <class S>
struct is_tls_stream<asio::ssl::stream<S>> : std::true_type {};
#endif

template <class Stream>
class Connection : public std::enable_shared_from_this<Connection<Stream>> {
public:
    Connection(Stream&& stream, Worker& worker, const Listener& listener, const Config& cfg, RequestHandler& handler)
        : stream_(std::move(stream)),
          worker_(worker),
          listener_(listener),
          cfg_(cfg),
          handler_(handler),
          timer_(worker.ctx),
          idle_timeout_(std::chrono::seconds(cfg.idle_timeout_s)),
          in_(cfg.max_header_size) {
        worker_.connections.fetch_add(1, std::memory_order_relaxed);
    }

    ~Connection() { worker_.connections.fetch_sub(1, std::memory_order_relaxed); }

    void start() {
        last_activity_ = std::chrono::steady_clock::now();
        arm_timer(idle_timeout_);
        if constexpr (is_tls_stream<Stream>::value) {
            auto self = this->shared_from_this();
            stream_.async_handshake(Stream::server, [self](const asio::error_code& ec) {
                if (ec) { self->close(); return; }
                self->last_activity_ = std::chrono::steady_clock::now();
                self->do_read();
            });
        } else {
            do_read();
        }
    }

private:
    auto& socket() { return stream_.lowest_layer(); }

    void arm_timer(std::chrono::steady_clock::duration d) {
        auto self = this->shared_from_this();
        timer_.expires_after(d);
        timer_.async_wait([self](const asio::error_code& ec) {
            if (ec) return;  // cancelled
            if (!self->socket().is_open()) return;
            auto idle = std::chrono::steady_clock::now() - self->last_activity_;
            if (idle >= self->idle_timeout_) self->close();
            else self->arm_timer(self->idle_timeout_ - idle);
        });
    }

    void do_read() {
        if (in_len_ >= in_.size()) {  // buffer full without a complete request head
            handler_.error(431, false, false, worker_.state, plan_);
            consumed_ = in_len_;
            write_response();
            return;
        }
        auto self = this->shared_from_this();
        stream_.async_read_some(asio::buffer(in_.data() + in_len_, in_.size() - in_len_),
                                [self](const asio::error_code& ec, std::size_t n) { self->on_read(ec, n); });
    }

    void on_read(const asio::error_code& ec, std::size_t n) {
        if (ec) { close(); return; }
        in_len_ += n;
        last_activity_ = std::chrono::steady_clock::now();
        process();
    }

    void process() {
        switch (parse_request(std::string_view(in_.data(), in_len_), req_)) {
            case ParseStatus::complete:
                consumed_ = req_.length;
                handler_.handle(req_, listener_.route, worker_.state, plan_);
                write_response();
                return;
            case ParseStatus::incomplete:
                do_read();
                return;
            case ParseStatus::bad_request:
                handler_.error(400, false, false, worker_.state, plan_);
                consumed_ = in_len_;
                write_response();
                return;
            case ParseStatus::version_not_supported:
                handler_.error(505, false, false, worker_.state, plan_);
                consumed_ = in_len_;
                write_response();
                return;
        }
    }

    void write_response() {
        auto self = this->shared_from_this();
        auto done = [self](const asio::error_code& ec, std::size_t) { self->on_write(ec); };
        const auto& p = plan_;
        if constexpr (is_tls_stream<Stream>::value) {
            // asio::ssl::stream encrypts one buffer of a sequence per write_some, so a
            // header + body pair would become two TLS records and two socket writes.
            // Coalesce the header and the start of the body into one full-size record.
            if (p.body == ResponsePlan::Body::entry || p.body == ResponsePlan::Body::inline_text) {
                const std::string_view body = p.body == ResponsePlan::Body::entry
                                                  ? std::string_view(p.entry->data.data(), p.entry->data.size())
                                                  : p.inline_text;
                constexpr std::size_t kRecord = 16384;  // max TLS plaintext per record
                out_.assign(p.header.begin(), p.header.end());
                const std::size_t room = out_.size() < kRecord ? kRecord - out_.size() : 0;
                const std::size_t take = std::min(room, body.size());
                out_.insert(out_.end(), body.data(), body.data() + take);
                if (take == body.size())
                    asio::async_write(stream_, asio::buffer(out_), done);
                else
                    asio::async_write(stream_, std::array<asio::const_buffer, 2>{asio::buffer(out_), asio::buffer(body.data() + take, body.size() - take)}, done);
                return;
            }
        }
        switch (p.body) {
            case ResponsePlan::Body::entry:
                asio::async_write(stream_, std::array<asio::const_buffer, 2>{asio::buffer(p.header), asio::buffer(p.entry->data)}, done);
                return;
            case ResponsePlan::Body::inline_text:
                asio::async_write(stream_, std::array<asio::const_buffer, 2>{asio::buffer(p.header), asio::buffer(p.inline_text)}, done);
                return;
            case ResponsePlan::Body::file:
            case ResponsePlan::Body::none:
                asio::async_write(stream_, asio::buffer(p.header), done);
                return;
        }
    }

    void on_write(const asio::error_code& ec) {
        if (ec) { close(); return; }
        last_activity_ = std::chrono::steady_clock::now();
        if (plan_.body == ResponsePlan::Body::file && plan_.file_sent < plan_.file_size) {
            stream_chunk();
            return;
        }
        finish_response();
    }

    void stream_chunk() {
        if (chunk_.empty()) chunk_.resize(cfg_.stream_chunk_size);
        const std::uint64_t remaining = plan_.file_size - plan_.file_sent;
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(remaining, chunk_.size()));
        const std::int64_t got = plan_.file.read_at(chunk_.data(), want, plan_.file_sent);
        if (got <= 0) { close(); return; }  // file shrank or read error: the client sees a short body
        plan_.file_sent += static_cast<std::uint64_t>(got);
        auto self = this->shared_from_this();
        asio::async_write(stream_, asio::buffer(chunk_.data(), static_cast<std::size_t>(got)),
                          [self](const asio::error_code& ec, std::size_t) { self->on_write(ec); });
    }

    void finish_response() {
        const bool keep_alive = plan_.keep_alive;
        plan_.reset();
        if (consumed_ < in_len_) std::memmove(in_.data(), in_.data() + consumed_, in_len_ - consumed_);
        in_len_ -= consumed_;
        consumed_ = 0;
        if (!keep_alive) { close(); return; }
        if (in_len_ > 0) process();  // pipelined request already buffered
        else do_read();
    }

    void close() {
        asio::error_code ec;
        timer_.cancel();
        if (socket().is_open()) {
            socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            socket().close(ec);
        }
        plan_.reset();
    }

    Stream stream_;
    Worker& worker_;
    const Listener& listener_;
    const Config& cfg_;
    RequestHandler& handler_;
    asio::steady_timer timer_;
    std::chrono::steady_clock::duration idle_timeout_;
    std::chrono::steady_clock::time_point last_activity_;
    std::vector<char> in_;
    std::size_t in_len_ = 0;
    std::size_t consumed_ = 0;
    std::vector<char> chunk_;
    std::vector<char> out_;   // TLS only: coalesced header + body prefix
    Request req_;
    ResponsePlan plan_;
};

}  // namespace agensio
