// TLS stream with a split BIO layout:
//  * writes: OpenSSL talks to the socket directly (socket BIO). One SSL_write pushes
//    every record with back-to-back send() calls until the socket would block.
//  * reads: ciphertext is pulled with the socket's own async_read_some (Asio's
//    speculative read, one edge-triggered kqueue/epoll registration per socket) into a
//    staging buffer that OpenSSL consumes through a minimal custom BIO: no extra copy,
//    no allocation per record.
// A plain socket.async_wait() was measured to cost an extra kevent re-registration per
// call, which is why reads do not use it. Completions run inline (immediate executor):
// posting them made asio poll kevent once per posted handler.
// The OpenSSL error queue is only cleared after an error was seen: ERR_clear_error()
// before every call showed up in profiles.
//
// Satisfies what asio::async_read / asio::async_write need from a stream:
// async_read_some, async_write_some, lowest_layer, get_executor.
#pragma once

#ifdef AGENSIO_HAS_TLS

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <memory>
#include <system_error>
#include <utility>

#include <asio.hpp>
#include <asio/ssl.hpp>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace agensio {

template <class Socket>
class BasicTlsStream {
public:
    using socket_type = Socket;
    using lowest_layer_type = socket_type;
    using executor_type = socket_type::executor_type;

    BasicTlsStream(socket_type&& socket, asio::ssl::context& ctx)
        : socket_(std::move(socket)), rbuf_(std::make_unique_for_overwrite<char[]>(kReadBufferSize)) {
        ssl_.reset(SSL_new(ctx.native_handle()));
        if (!ssl_) throw std::runtime_error("SSL_new failed");
        BioPtr wbio(BIO_new_socket(static_cast<int>(socket_.native_handle()), BIO_NOCLOSE));
        BioPtr rbio(BIO_new(read_bio_method()));
        if (!wbio || !rbio) throw std::runtime_error("BIO allocation failed");
        BIO_set_data(rbio.get(), this);
        rbio_ = rbio.get();
        SSL_set_bio(ssl_.get(), rbio.release(), wbio.release());  // SSL takes ownership of both
        SSL_set_mode(ssl_.get(), SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_AUTO_RETRY);
        SSL_set_read_ahead(ssl_.get(), 1);  // take everything staged in one BIO read
        SSL_set_accept_state(ssl_.get());
    }

    BasicTlsStream(BasicTlsStream&& o) noexcept
        : socket_(std::move(o.socket_)),
          ssl_(std::move(o.ssl_)),
          rbio_(std::exchange(o.rbio_, nullptr)),
          rbuf_(std::move(o.rbuf_)),
          rpos_(o.rpos_),
          rlen_(o.rlen_) {
        if (rbio_) BIO_set_data(rbio_, this);  // the read BIO calls back into this object
    }
    BasicTlsStream& operator=(BasicTlsStream&&) = delete;
    BasicTlsStream(const BasicTlsStream&) = delete;
    BasicTlsStream& operator=(const BasicTlsStream&) = delete;
    ~BasicTlsStream() = default;

    // Client side (TLS to an origin): connect state, SNI and, when `verify`, the peer's
    // certificate checked against the context's store and its name against `server_name`.
    // Call before async_handshake.
    bool set_client(const std::string& server_name, bool verify) noexcept {
        SSL_set_connect_state(ssl_.get());
        if (!server_name.empty() && SSL_set_tlsext_host_name(ssl_.get(), server_name.c_str()) != 1) return false;
        if (verify) {
            SSL_set_verify(ssl_.get(), SSL_VERIFY_PEER, nullptr);
            if (!server_name.empty() && SSL_set1_host(ssl_.get(), server_name.c_str()) != 1) return false;
        }
        return true;
    }

    lowest_layer_type& lowest_layer() noexcept { return socket_; }
    const lowest_layer_type& lowest_layer() const noexcept { return socket_; }
    executor_type get_executor() noexcept { return socket_.get_executor(); }
    SSL* native_handle() noexcept { return ssl_.get(); }

    // Best-effort close_notify; never blocks, errors ignored.
    void shutdown_notify() noexcept {
        if (ssl_) {
            SSL_shutdown(ssl_.get());
            ERR_clear_error();
        }
    }

    // Handshake in the stream's current direction (accept by default). Handler: void(std::error_code).
    template <class Handler>
    void async_handshake(Handler&& handler) {
        do_handshake(std::forward<Handler>(handler));
    }

    // Reads into the first buffer of the sequence. Handler: void(std::error_code, std::size_t).
    template <class MutableBufferSequence, class Handler>
    void async_read_some(const MutableBufferSequence& buffers, Handler&& handler) {
        asio::mutable_buffer b = first_buffer<asio::mutable_buffer>(buffers);
        if (b.size() == 0) {
            complete(std::forward<Handler>(handler), std::error_code(), 0);
            return;
        }
        do_read(b, std::forward<Handler>(handler));
    }

    // Writes the whole first buffer of the sequence (all records) before completing.
    template <class ConstBufferSequence, class Handler>
    void async_write_some(const ConstBufferSequence& buffers, Handler&& handler) {
        asio::const_buffer b = first_buffer<asio::const_buffer>(buffers);
        if (b.size() == 0) {
            complete(std::forward<Handler>(handler), std::error_code(), 0);
            return;
        }
        do_write(b, std::forward<Handler>(handler));
    }

private:
    template <class Buffer, class Sequence>
    static Buffer first_buffer(const Sequence& s) {
        auto it = asio::buffer_sequence_begin(s);
        auto end = asio::buffer_sequence_end(s);
        while (it != end && Buffer(*it).size() == 0)
            ++it;
        return it == end ? Buffer() : Buffer(*it);
    }

    // Completes inline. Recursion is bounded: a read that completes inline leads to a
    // write that completes inline, then to a read that finds no data and returns.
    template <class Handler, class... Args>
    void complete(Handler&& handler, Args... args) {
        handler(args...);
    }

    // Lets asio run speculative completions inline instead of posting them.
    template <class F>
    auto immediate(F&& f) {
        return asio::bind_immediate_executor(socket_.get_executor(), std::forward<F>(f));
    }

    // Maps an SSL_get_error result to an error_code (never called for WANT_*).
    std::error_code map_error(int ssl_err, int ret) noexcept {
        if (ssl_err == SSL_ERROR_ZERO_RETURN) return asio::error::eof;
        if (ssl_err == SSL_ERROR_SYSCALL) {
            unsigned long e = ERR_peek_error();
            if (e == 0) {
                if (ret == 0 || errno == 0) return asio::error::eof;
                return std::error_code(errno, std::generic_category());
            }
            return std::error_code(static_cast<int>(e), asio::error::get_ssl_category());
        }
        unsigned long e = ERR_peek_error();
        if (e != 0) {
            // OpenSSL 3 reports a peer closing without close_notify as an SSL error.
            if (ERR_GET_REASON(e) == SSL_R_UNEXPECTED_EOF_WHILE_READING) return asio::error::eof;
            return std::error_code(static_cast<int>(e), asio::error::get_ssl_category());
        }
        return asio::error::connection_reset;
    }

    template <class Handler>
    void do_handshake(Handler handler) {
        int ret = SSL_do_handshake(ssl_.get());
        if (ret == 1) {
            complete(std::move(handler), std::error_code());
            return;
        }
        int err = SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            retry_after(err, [this, h = std::move(handler)](std::error_code ec) mutable {
                if (ec) h(ec);
                else do_handshake(std::move(h));
            });
            return;
        }
        auto ec = map_error(err, ret);
        ERR_clear_error();
        complete(std::move(handler), ec);
    }

    template <class Handler>
    void do_read(asio::mutable_buffer b, Handler handler) {
        int ret = SSL_read(ssl_.get(), b.data(), static_cast<int>(std::min<std::size_t>(b.size(), 1u << 30)));
        if (ret > 0) {
            complete(std::move(handler), std::error_code(), static_cast<std::size_t>(ret));
            return;
        }
        int err = SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            retry_after(err, [this, b, h = std::move(handler)](std::error_code ec) mutable {
                if (ec) h(ec, 0);
                else do_read(b, std::move(h));
            });
            return;
        }
        auto ec = map_error(err, ret);
        ERR_clear_error();
        complete(std::move(handler), ec, std::size_t(0));
    }

    template <class Handler>
    void do_write(asio::const_buffer b, Handler handler) {
        // Without SSL_MODE_ENABLE_PARTIAL_WRITE this loops over all records internally
        // and only returns early on WANT_WRITE, after which it must be retried with the
        // same arguments (OpenSSL remembers its position).
        int ret = SSL_write(ssl_.get(), b.data(), static_cast<int>(std::min<std::size_t>(b.size(), 1u << 30)));
        if (ret > 0) {
            complete(std::move(handler), std::error_code(), static_cast<std::size_t>(ret));
            return;
        }
        int err = SSL_get_error(ssl_.get(), ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            retry_after(err, [this, b, h = std::move(handler)](std::error_code ec) mutable {
                if (ec) h(ec, 0);
                else do_write(b, std::move(h));
            });
            return;
        }
        auto ec = map_error(err, ret);
        ERR_clear_error();
        complete(std::move(handler), ec, std::size_t(0));
    }

    // WANT_READ: pull ciphertext from the socket into the staging buffer, then retry.
    // WANT_WRITE: wait until the socket is writable, then retry.
    template <class Retry>
    void retry_after(int ssl_err, Retry&& retry) {
        if (ssl_err == SSL_ERROR_WANT_READ) {
            if (rpos_ == rlen_) {
                rpos_ = rlen_ = 0;
            } else if (rpos_ > 0) {  // partial data left (should not happen with read-ahead)
                std::memmove(rbuf_.get(), rbuf_.get() + rpos_, rlen_ - rpos_);
                rlen_ -= rpos_;
                rpos_ = 0;
            }
            if (rlen_ >= kReadBufferSize) {
                // A full staging buffer OpenSSL refuses to consume means a record larger
                // than the protocol allows: a zero-length read here would spin forever.
                complete(std::forward<Retry>(retry), std::error_code(asio::error::message_size));
                return;
            }
            socket_.async_read_some(
                asio::buffer(rbuf_.get() + rlen_, kReadBufferSize - rlen_),
                immediate([this, r = std::forward<Retry>(retry)](std::error_code ec, std::size_t n) mutable {
                    rlen_ += n;
                    r(ec);
                }));
        } else {
            socket_.async_wait(socket_type::wait_write, std::forward<Retry>(retry));
        }
    }

    // ---- custom read BIO over rbuf_ ----
    static int bio_read_ex(BIO* b, char* out, std::size_t len, std::size_t* readbytes) {
        auto* self = static_cast<BasicTlsStream*>(BIO_get_data(b));
        BIO_clear_retry_flags(b);
        const std::size_t avail = self->rlen_ - self->rpos_;
        if (avail == 0) {
            BIO_set_retry_read(b);
            *readbytes = 0;
            return 0;
        }
        const std::size_t n = std::min(avail, len);
        std::memcpy(out, self->rbuf_.get() + self->rpos_, n);
        self->rpos_ += n;
        *readbytes = n;
        return 1;
    }
    static long bio_ctrl(BIO* b, int cmd, long, void*) {
        switch (cmd) {
            case BIO_CTRL_FLUSH:
                return 1;
            case BIO_CTRL_EOF:
                return 0;
            case BIO_CTRL_PENDING: {
                auto* self = static_cast<BasicTlsStream*>(BIO_get_data(b));
                return static_cast<long>(self->rlen_ - self->rpos_);
            }
            default:
                return 0;
        }
    }
    static BIO_METHOD* read_bio_method() {
        static BIO_METHOD* m = [] {
            BIO_METHOD* method = BIO_meth_new(BIO_get_new_index() | BIO_TYPE_SOURCE_SINK, "agensio_read_buffer");
            BIO_meth_set_read_ex(method, &bio_read_ex);
            BIO_meth_set_ctrl(method, &bio_ctrl);
            BIO_meth_set_create(method, [](BIO* b) {
                BIO_set_init(b, 1);
                return 1;
            });
            BIO_meth_set_destroy(method, [](BIO*) { return 1; });
            return method;
        }();
        return m;
    }

    static constexpr std::size_t kReadBufferSize = 17 * 1024;  // one max-size TLS record plus overhead

    struct SslDeleter {
        void operator()(SSL* s) const noexcept { SSL_free(s); }
    };
    struct BioDeleter {
        void operator()(BIO* b) const noexcept { BIO_free(b); }
    };
    using SslPtr = std::unique_ptr<SSL, SslDeleter>;
    using BioPtr = std::unique_ptr<BIO, BioDeleter>;

    socket_type socket_;
    SslPtr ssl_;
    BIO* rbio_ = nullptr;           // non-owning: owned by ssl_, used to update the callback data on move
    std::unique_ptr<char[]> rbuf_;  // ciphertext staging read by the custom BIO
    std::size_t rpos_ = 0;          // consumed
    std::size_t rlen_ = 0;          // filled
};

using TlsStream = BasicTlsStream<asio::ip::tcp::socket>;

}  // namespace agensio

#endif  // AGENSIO_HAS_TLS
