// The TLS 1.3 handshake over QUIC through OpenSSL 3.5's QUIC TLS API (RFC 9001 section 4;
// SSL_set_quic_tls_cbs(3)): OpenSSL runs the handshake, we carry its bytes in CRYPTO
// frames and derive the packet keys from the secrets it yields. The six callbacks only
// move bytes and secrets into this object; the connection reads them out after each
// step, so OpenSSL never calls back into the templated connection.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/ssl.h>

#include "quic/crypto.hpp"

namespace agensio::quic {

class TlsSession {
public:
    // OpenSSL's protection levels, as our indexes: NONE (Initial) 0, EARLY 1, HANDSHAKE 2, APPLICATION 3.
    enum Level : std::uint8_t { initial = 0, early = 1, handshake = 2, application = 3 };
    static constexpr unsigned kLevels = 4;

    struct Secret {
        Level level;
        bool write;
        Suite suite;
        unsigned char bytes[64];
        std::size_t len;
    };

    TlsSession() = default;
    ~TlsSession() { free_ssl(); }
    TlsSession(const TlsSession&) = delete;
    TlsSession& operator=(const TlsSession&) = delete;

    // A server-side session on the listener's context, TLS 1.3 only, with our transport
    // parameters (kept here for the session's life).
    bool init(SSL_CTX* ctx, std::string transport_params);

    // CRYPTO bytes received at a level, in order (the connection reassembles).
    void received(Level l, const unsigned char* p, std::size_t n);
    // Runs the handshake: 1 complete (now or before), 0 more input needed, -1 failed
    // (alert() says how; a TLS alert becomes CONNECTION_CLOSE 0x100 + alert).
    int advance();
    bool done() const noexcept { return done_; }

    // What the last steps produced: secrets in the order yielded (the caller clears the
    // vector), and CRYPTO bytes to send per level (the caller consumes them).
    std::vector<Secret>& secrets() noexcept { return secrets_; }
    std::string& out(Level l) noexcept { return out_[l]; }
    const std::string& out(Level l) const noexcept { return out_[l]; }
    bool have_peer_params() const noexcept { return have_params_; }
    const std::string& peer_params() const noexcept { return peer_params_; }
    bool has_alert() const noexcept { return alert_; }
    std::uint8_t alert() const noexcept { return alert_code_; }
    std::string_view alpn() const noexcept;
    bool suite(Suite& out) const noexcept;
    SSL* ssl() const noexcept { return ssl_; }
    // Nothing after the handshake needs the TLS state (design-http3 6.2): frees it.
    void free_ssl() noexcept;

    // The ex_data index marking a QUIC session's SSL, so the listener's ALPN callback
    // offers h3 there and h2/http1.1 on TCP.
    static int ex_index() noexcept;

private:
    static int cb_crypto_send(SSL*, const unsigned char* buf, std::size_t len, std::size_t* consumed, void* arg);
    static int cb_crypto_recv(SSL*, const unsigned char** buf, std::size_t* bytes_read, void* arg);
    static int cb_crypto_release(SSL*, std::size_t bytes_read, void* arg);
    static int cb_yield_secret(SSL*, std::uint32_t prot_level, int direction, const unsigned char* secret, std::size_t len, void* arg);
    static int cb_got_params(SSL*, const unsigned char* params, std::size_t len, void* arg);
    static int cb_alert(SSL*, unsigned char alert, void* arg);

    SSL* ssl_ = nullptr;
    std::string params_;
    // Received bytes per level, reserved once for the level's whole budget so that the
    // pointer OpenSSL holds between recv and release stays valid whatever is appended.
    std::string in_[kLevels];
    std::size_t in_pos_[kLevels] = {};
    std::string out_[kLevels];
    Level write_level_ = initial;
    Level read_level_ = initial;
    std::vector<Secret> secrets_;
    std::string peer_params_;
    bool have_params_ = false;
    bool alert_ = false;
    std::uint8_t alert_code_ = 0;
    bool done_ = false;
};

}  // namespace agensio::quic
