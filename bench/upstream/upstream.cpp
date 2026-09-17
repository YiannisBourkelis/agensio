// Benchmark upstream for phase D (roadmap D0): an HTTP/1.1 origin that answers as fast as
// a proxy can ask, so a proxy in front of it is the bottleneck and its CPU per request is
// what a run measures. Deliberately shares no code with agensio. Modes by path:
//   /json           small JSON body
//   /big            a large JSON body (-b bytes, default 100 KB): buffering and body copies
//   /slow?ms=N      the JSON answer after N ms: a working application, connection pools
//   /chunked        the JSON body in three chunks: the proxy's chunked decoder
//   /close          the JSON answer with Connection: close: reconnects
//   /echo           the request body back (Content-Type: application/octet-stream): body forwarding
//   /stats          {"connections":N,"requests":M} accepted so far: proves pool reuse
// Build: target agensio_upstream. Run: agensio_upstream [-p 9100] [-w 1] [-b 102400].
#include <asio.hpp>

#include <atomic>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

std::atomic<std::uint64_t> g_connections{0};
std::atomic<std::uint64_t> g_requests{0};
std::string g_big;

constexpr std::string_view kJson = R"({"ok":true,"service":"upstream"})";

std::string head(std::string_view content_length, bool close, bool chunked = false) {
    std::string h = "HTTP/1.1 200 OK\r\nServer: upstream\r\nContent-Type: application/json\r\n";
    if (chunked) h += "Transfer-Encoding: chunked\r\n";
    else h += "Content-Length: " + std::string(content_length) + "\r\n";
    if (close) h += "Connection: close\r\n";
    return h + "\r\n";
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) return false;
    return true;
}

class Connection : public std::enable_shared_from_this<Connection> {
public:
    explicit Connection(asio::ip::tcp::socket s) : socket_(std::move(s)), timer_(socket_.get_executor()) {
        buf_.resize(16 * 1024);
    }
    void start() {
        asio::error_code ec;
        socket_.set_option(asio::ip::tcp::no_delay(true), ec);
        read();
    }

private:
    void read() {
        if (len_ == buf_.size()) return close();  // head too large
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(buf_.data() + len_, buf_.size() - len_),
                                [self](const asio::error_code& ec, std::size_t n) {
                                    if (ec) return self->close();
                                    self->len_ += n;
                                    self->process();
                                });
    }

    // One request at a time; leftover bytes (pipelining) stay for the next round.
    void process() {
        const std::string_view in(buf_.data(), len_);
        const std::size_t end = in.find("\r\n\r\n");
        if (end == std::string_view::npos) return read();
        const std::string_view request = in.substr(0, end + 4);
        std::string_view target = request.substr(request.find(' ') + 1);
        target = target.substr(0, target.find(' '));
        bool close = false;
        std::size_t body = 0;
        std::size_t pos = request.find("\r\n") + 2;
        while (pos < request.size() - 2) {
            const std::size_t eol = request.find("\r\n", pos);
            const std::string_view line = request.substr(pos, eol - pos);
            const std::size_t colon = line.find(':');
            if (colon != std::string_view::npos) {
                const std::string_view name = line.substr(0, colon);
                std::string_view value = line.substr(colon + 1);
                while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
                if (iequals(name, "connection") && iequals(value, "close")) close = true;
                if (iequals(name, "content-length")) std::from_chars(value.data(), value.data() + value.size(), body);
            }
            pos = eol + 2;
        }
        consumed_ = request.size();
        bool chunked = false;
        {
            std::size_t p2 = request.find("\r\n") + 2;
            while (p2 < request.size() - 2) {
                const std::size_t eol = request.find("\r\n", p2);
                const std::string_view line = request.substr(p2, eol - p2);
                if (line.size() > 18 && iequals(line.substr(0, 18), "transfer-encoding:") &&
                    line.find("chunked") != std::string_view::npos)
                    chunked = true;
                p2 = eol + 2;
            }
        }
        if (target.substr(0, target.find('?')) == "/echo" && chunked) {
            // Chunked request body: decode what is here, read the rest.
            echo_.clear();
            echo_close_ = close;
            echo_chunked_ = true;
            chunk_left_ = 0;
            chunk_done_ = false;
            decode_chunks();
            if (chunk_done_) return send_echo(close);
            return read_echo_chunked();
        }
        if (target.substr(0, target.find('?')) == "/echo") {
            // Keep the body: wait for all of it, then send it back.
            const std::size_t have = len_ - consumed_;
            if (have < body) {
                echo_want_ = body;
                echo_close_ = close;
                echo_.assign(buf_.data() + consumed_, have);
                consumed_ = len_;
                return read_echo();
            }
            echo_.assign(buf_.data() + consumed_, body);
            consumed_ += body;
            return send_echo(close);
        }
        // Any other request body is not part of the benchmark; skip it (it arrived with the
        // head or will be read and dropped before the next request).
        if (body > 0) {
            const std::size_t have = len_ - consumed_;
            if (have < body) {
                skip_ = body - have;
                consumed_ = len_;
            } else {
                consumed_ += body;
            }
        }
        respond(target, close);
    }

    void respond(std::string_view target, bool close) {
        g_requests.fetch_add(1, std::memory_order_relaxed);
        const std::string_view path = target.substr(0, target.find('?'));
        if (path == "/slow") {
            unsigned ms = 0;
            const std::size_t q = target.find("ms=");
            if (q != std::string_view::npos)
                std::from_chars(target.data() + q + 3, target.data() + target.size(), ms);
            auto self = shared_from_this();
            timer_.expires_after(std::chrono::milliseconds(ms));
            timer_.async_wait([self, close](const asio::error_code& ec) {
                if (ec) return;
                self->send(head(std::to_string(kJson.size()), close), kJson, close);
            });
            return;
        }
        if (path == "/json") return send(head(std::to_string(kJson.size()), close), kJson, close);
        if (path == "/big") return send(head(std::to_string(g_big.size()), close), g_big, close);
        if (path == "/close") return send(head(std::to_string(kJson.size()), true), kJson, true);
        if (path == "/chunked") {
            static const std::string chunks = "d\r\n{\"ok\":true,\"s\r\n" "f\r\nervice\":\"upstre\r\n" "4\r\nam\"}\r\n" "0\r\n\r\n";
            return send(head({}, close, true), chunks, close);
        }
        if (path == "/stats") {
            stats_ = "{\"connections\":" + std::to_string(g_connections.load()) + ",\"requests\":" +
                     std::to_string(g_requests.load()) + "}";
            return send(head(std::to_string(stats_.size()), close), stats_, close);
        }
        static const std::string_view nf = "{\"error\":\"not found\"}";
        head_ = "HTTP/1.1 404 Not Found\r\nServer: upstream\r\nContent-Type: application/json\r\nContent-Length: " +
                std::to_string(nf.size()) + (close ? "\r\nConnection: close\r\n\r\n" : "\r\n\r\n");
        write(nf, close);
    }

    void read_echo() {
        auto self = shared_from_this();
        const std::size_t want = std::min(echo_want_ - echo_.size(), buf_.size());
        socket_.async_read_some(asio::buffer(buf_.data(), want), [self](const asio::error_code& ec, std::size_t n) {
            if (ec) return self->close();
            self->echo_.append(self->buf_.data(), n);
            self->len_ = self->consumed_ = 0;
            if (self->echo_.size() < self->echo_want_) return self->read_echo();
            self->send_echo(self->echo_close_);
        });
    }
    // Minimal chunked decoder over buf_[consumed_, len_): hex size line, data, CRLF, 0 ends.
    void decode_chunks() {
        for (;;) {
            std::string_view in(buf_.data() + consumed_, len_ - consumed_);
            if (chunk_left_ == 0) {
                const std::size_t eol = in.find("\r\n");
                if (eol == std::string_view::npos) return;
                std::size_t size = 0;
                std::from_chars(in.data(), in.data() + eol, size, 16);
                consumed_ += eol + 2;
                if (size == 0) {  // last chunk: skip the trailer's CRLF when present
                    in = std::string_view(buf_.data() + consumed_, len_ - consumed_);
                    if (in.starts_with("\r\n")) consumed_ += 2;
                    chunk_done_ = true;
                    return;
                }
                chunk_left_ = size + 2;  // data + CRLF
                continue;
            }
            const std::size_t take = std::min(chunk_left_, in.size());
            if (take == 0) return;
            const std::size_t data = chunk_left_ > 2 ? std::min(take, chunk_left_ - 2) : 0;
            echo_.append(in.data(), data);
            consumed_ += take;
            chunk_left_ -= take;
        }
    }
    void read_echo_chunked() {
        if (consumed_ > 0 && consumed_ < len_) std::memmove(buf_.data(), buf_.data() + consumed_, len_ - consumed_);
        len_ -= consumed_;
        consumed_ = 0;
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(buf_.data() + len_, buf_.size() - len_),
                                [self](const asio::error_code& ec, std::size_t n) {
                                    if (ec) return self->close();
                                    self->len_ += n;
                                    self->decode_chunks();
                                    if (self->chunk_done_) {
                                        self->echo_chunked_ = false;
                                        return self->send_echo(self->echo_close_);
                                    }
                                    self->read_echo_chunked();
                                });
    }

    void send_echo(bool close) {
        g_requests.fetch_add(1, std::memory_order_relaxed);
        head_ = "HTTP/1.1 200 OK\r\nServer: upstream\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                std::to_string(echo_.size()) + (close ? "\r\nConnection: close\r\n\r\n" : "\r\n\r\n");
        write(echo_, close);
    }

    void send(std::string h, std::string_view body, bool close) {
        head_ = std::move(h);
        write(body, close);
    }

    void write(std::string_view body, bool close) {
        auto self = shared_from_this();
        std::array<asio::const_buffer, 2> bufs{asio::buffer(head_), asio::buffer(body)};
        asio::async_write(socket_, bufs, [self, close](const asio::error_code& ec, std::size_t) {
            if (ec || close) return self->close();
            self->next();
        });
    }

    void next() {
        if (consumed_ < len_) std::memmove(buf_.data(), buf_.data() + consumed_, len_ - consumed_);
        len_ -= consumed_;
        consumed_ = 0;
        if (skip_ > 0) return drain();
        if (len_ > 0) return process();
        read();
    }

    void drain() {  // the rest of a request body nobody wanted
        auto self = shared_from_this();
        socket_.async_read_some(asio::buffer(buf_.data(), std::min(skip_, buf_.size())),
                                [self](const asio::error_code& ec, std::size_t n) {
                                    if (ec) return self->close();
                                    self->skip_ -= n;
                                    if (self->skip_ > 0) return self->drain();
                                    self->read();
                                });
    }

    void close() {
        asio::error_code ec;
        socket_.close(ec);
    }

    asio::ip::tcp::socket socket_;
    asio::steady_timer timer_;
    std::vector<char> buf_;
    std::size_t len_ = 0;
    std::size_t consumed_ = 0;
    std::size_t skip_ = 0;
    std::string head_;
    std::string stats_;
    std::string echo_;
    std::size_t echo_want_ = 0;
    bool echo_close_ = false;
    bool echo_chunked_ = false;
    std::size_t chunk_left_ = 0;
    bool chunk_done_ = false;
};

void accept_loop(asio::ip::tcp::acceptor& acc) {
    acc.async_accept([&acc](const asio::error_code& ec, asio::ip::tcp::socket s) {
        if (!ec) {
            g_connections.fetch_add(1, std::memory_order_relaxed);
            std::make_shared<Connection>(std::move(s))->start();
        }
        accept_loop(acc);
    });
}

}  // namespace

int main(int argc, char** argv) {
    unsigned short port = 9100;
    unsigned workers = 1;
    std::size_t big = 100 * 1024;
    for (int i = 1; i + 1 < argc; i += 2) {
        const std::string_view a = argv[i];
        if (a == "-p") port = static_cast<unsigned short>(std::atoi(argv[i + 1]));
        else if (a == "-w") workers = static_cast<unsigned>(std::atoi(argv[i + 1]));
        else if (a == "-b") big = static_cast<std::size_t>(std::atol(argv[i + 1]));
        else {
            std::fprintf(stderr, "usage: agensio_upstream [-p port] [-w workers] [-b big-body-bytes]\n");
            return 2;
        }
    }
    g_big = "{\"data\":\"" + std::string(big > 12 ? big - 12 : 0, 'x') + "\"}";
    if (workers == 0) workers = 1;
#ifndef SO_REUSEPORT
    if (workers > 1) std::fprintf(stderr, "no SO_REUSEPORT here: one worker\n"), workers = 1;
#endif
    std::vector<std::thread> threads;
    for (unsigned w = 0; w < workers; ++w) {
        threads.emplace_back([port] {
            asio::io_context ctx(1);
            asio::ip::tcp::acceptor acc(ctx);
            const asio::ip::tcp::endpoint ep(asio::ip::make_address("127.0.0.1"), port);
            acc.open(ep.protocol());
            acc.set_option(asio::socket_base::reuse_address(true));
#ifdef SO_REUSEPORT
            const int one = 1;
            ::setsockopt(acc.native_handle(), SOL_SOCKET, SO_REUSEPORT, &one, sizeof one);
#endif
            acc.bind(ep);
            acc.listen(4096);
            accept_loop(acc);
            ctx.run();
        });
    }
    std::printf("upstream on 127.0.0.1:%u, %u worker(s), /big is %zu bytes\n", port, workers, g_big.size());
    std::fflush(stdout);
    for (auto& t : threads) t.join();
    return 0;
}
