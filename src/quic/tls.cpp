#include "quic/tls.hpp"

#include <cstring>

#include <openssl/core_dispatch.h>

#ifdef AGENSIO_QUIC_TRACE
#include <cstdio>
#define TLS_TRACE(...) std::fprintf(stderr, __VA_ARGS__)
#else
#define TLS_TRACE(...) ((void)0)
#endif

namespace agensio::quic {

namespace {
constexpr std::size_t kInBuffer = 24 * 1024;  // a level's CRYPTO budget (16 KB) plus room: never reallocated while held
}

namespace {

TlsSession::Level level_of(std::uint32_t prot) noexcept {
    switch (prot) {
        case OSSL_RECORD_PROTECTION_LEVEL_EARLY: return TlsSession::early;
        case OSSL_RECORD_PROTECTION_LEVEL_HANDSHAKE: return TlsSession::handshake;
        case OSSL_RECORD_PROTECTION_LEVEL_APPLICATION: return TlsSession::application;
        default: return TlsSession::initial;
    }
}

}  // namespace

int TlsSession::ex_index() noexcept {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    return index;
}

bool TlsSession::init(SSL_CTX* ctx, std::string transport_params) {
    static const OSSL_DISPATCH dispatch[] = {
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND, reinterpret_cast<void (*)()>(&TlsSession::cb_crypto_send)},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD, reinterpret_cast<void (*)()>(&TlsSession::cb_crypto_recv)},
        {OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD, reinterpret_cast<void (*)()>(&TlsSession::cb_crypto_release)},
        {OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET, reinterpret_cast<void (*)()>(&TlsSession::cb_yield_secret)},
        {OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS, reinterpret_cast<void (*)()>(&TlsSession::cb_got_params)},
        {OSSL_FUNC_SSL_QUIC_TLS_ALERT, reinterpret_cast<void (*)()>(&TlsSession::cb_alert)},
        OSSL_DISPATCH_END};
    free_ssl();
    params_ = std::move(transport_params);
    ssl_ = SSL_new(ctx);
    if (!ssl_) return false;
    SSL_set_accept_state(ssl_);
    if (SSL_set_min_proto_version(ssl_, TLS1_3_VERSION) != 1 || SSL_set_ex_data(ssl_, ex_index(), this) != 1 ||
        SSL_set_quic_tls_cbs(ssl_, dispatch, this) != 1 ||
        SSL_set_quic_tls_transport_params(ssl_, reinterpret_cast<const unsigned char*>(params_.data()), params_.size()) != 1) {
        free_ssl();
        return false;
    }
    return true;
}

void TlsSession::free_ssl() noexcept {
    if (ssl_) SSL_free(ssl_);
    ssl_ = nullptr;
}

void TlsSession::received(Level l, const unsigned char* p, std::size_t n) {
    if (in_[l].capacity() < kInBuffer) in_[l].reserve(kInBuffer);
    in_[l].append(reinterpret_cast<const char*>(p), n);
    TLS_TRACE("tls: received level=%u n=%zu total=%zu\n", l, n, in_[l].size());
}

int TlsSession::advance() {
    if (done_) return 1;
    if (!ssl_) return -1;
    const int r = SSL_do_handshake(ssl_);
    if (r == 1) {
        done_ = true;
        TLS_TRACE("tls: handshake done\n");
        return 1;
    }
    const int e = SSL_get_error(ssl_, r);
    TLS_TRACE("tls: do_handshake r=%d error=%d\n", r, e);
    if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) return 0;
    if (!alert_) {  // a failure without an alert: internal error
        alert_ = true;
        alert_code_ = 80;
    }
    return -1;
}

std::string_view TlsSession::alpn() const noexcept {
    if (!ssl_) return {};
    const unsigned char* p = nullptr;
    unsigned len = 0;
    SSL_get0_alpn_selected(ssl_, &p, &len);
    return std::string_view(reinterpret_cast<const char*>(p), len);
}

bool TlsSession::suite(Suite& out) const noexcept {
    if (!ssl_) return false;
    const SSL_CIPHER* c = SSL_get_current_cipher(ssl_);
    return c && suite_from_tls_id(SSL_CIPHER_get_id(c), out);
}

int TlsSession::cb_crypto_send(SSL*, const unsigned char* buf, std::size_t len, std::size_t* consumed, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    t->out_[t->write_level_].append(reinterpret_cast<const char*>(buf), len);
    *consumed = len;
    TLS_TRACE("tls: send level=%u n=%zu\n", t->write_level_, len);
    return 1;
}

int TlsSession::cb_crypto_recv(SSL*, const unsigned char** buf, std::size_t* bytes_read, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    std::string& in = t->in_[t->read_level_];
    const std::size_t pos = t->in_pos_[t->read_level_];
    *buf = reinterpret_cast<const unsigned char*>(in.data()) + pos;
    *bytes_read = in.size() - pos;
    TLS_TRACE("tls: recv level=%u gives=%zu\n", t->read_level_, *bytes_read);
    return 1;
}

int TlsSession::cb_crypto_release(SSL*, std::size_t bytes_read, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    const Level l = t->read_level_;
    t->in_pos_[l] += bytes_read;
    TLS_TRACE("tls: release level=%u n=%zu\n", l, bytes_read);
    if (t->in_pos_[l] >= t->in_[l].size()) {
        t->in_[l].clear();
        t->in_pos_[l] = 0;
    }
    return 1;
}

int TlsSession::cb_yield_secret(SSL*, std::uint32_t prot_level, int direction, const unsigned char* secret, std::size_t len, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    TLS_TRACE("tls: secret level=%u direction=%d len=%zu\n", prot_level, direction, len);
    if (len > 64) return 0;
    Suite s;
    if (!t->suite(s)) return 0;
    Secret sec;
    sec.level = level_of(prot_level);
    sec.write = direction != 0;
    sec.suite = s;
    std::memcpy(sec.bytes, secret, len);
    sec.len = len;
    if (sec.write) t->write_level_ = sec.level;
    else t->read_level_ = sec.level;
    t->secrets_.push_back(sec);
    return 1;
}

int TlsSession::cb_got_params(SSL*, const unsigned char* params, std::size_t len, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    t->peer_params_.assign(reinterpret_cast<const char*>(params), len);
    t->have_params_ = true;
    return 1;
}

int TlsSession::cb_alert(SSL*, unsigned char alert, void* arg) {
    auto* t = static_cast<TlsSession*>(arg);
    TLS_TRACE("tls: alert %u\n", alert);
    t->alert_ = true;
    t->alert_code_ = alert;
    return 1;
}

}  // namespace agensio::quic
