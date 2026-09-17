#include "upstream/client.hpp"

#include "config.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <utility>

#ifndef _WIN32
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#endif

namespace agensio {

// ---- reasons ----

const char* to_string(UpstreamFailure f) noexcept {
    switch (f) {
        case UpstreamFailure::none: return "ok";
        case UpstreamFailure::connect_refused: return "connect_refused";
        case UpstreamFailure::socket_missing: return "socket_missing";
        case UpstreamFailure::socket_permission: return "socket_permission";
        case UpstreamFailure::connect_error: return "connect_error";
        case UpstreamFailure::connect_timeout: return "connect_timeout";
        case UpstreamFailure::pool_saturated: return "pool_saturated";
        case UpstreamFailure::queue_timeout: return "queue_timeout";
        case UpstreamFailure::send_timeout: return "send_timeout";
        case UpstreamFailure::read_timeout: return "read_timeout";
        case UpstreamFailure::closed_early: return "closed_early";
        case UpstreamFailure::primary_script_unknown: return "primary_script_unknown";
        case UpstreamFailure::bad_response_head: return "bad_response_head";
        case UpstreamFailure::head_too_large: return "head_too_large";
        case UpstreamFailure::protocol_error: return "protocol_error";
        case UpstreamFailure::spill_error: return "spill_error";
        case UpstreamFailure::tls_error: return "tls_error";
    }
    return "unknown";
}

int status_for(UpstreamFailure f) noexcept {
    switch (f) {
        case UpstreamFailure::pool_saturated:
        case UpstreamFailure::queue_timeout: return 503;
        case UpstreamFailure::connect_timeout:
        case UpstreamFailure::send_timeout:
        case UpstreamFailure::read_timeout: return 504;
        default: return 502;
    }
}

// ---- address ----

bool parse_upstream_address(std::string_view text, UpstreamAddress& out, std::string& error) {
    out = UpstreamAddress{};
    if (text.empty()) {
        error = "empty upstream address";
        return false;
    }
    if (text.starts_with("unix:") || text.front() == '/') {
        out.unix = true;
        out.path = std::string(text.starts_with("unix:") ? text.substr(5) : text);
        if (out.path.empty() || out.path.front() != '/') {
            error = "unix socket path must be absolute: '" + std::string(text) + "'";
            return false;
        }
        out.key = "unix:" + out.path;
        return true;
    }
    std::string_view host, port;
    if (text.front() == '[') {
        const std::size_t close = text.find(']');
        if (close == std::string_view::npos || close + 1 >= text.size() || text[close + 1] != ':') {
            error = "expected [ipv6]:port in '" + std::string(text) + "'";
            return false;
        }
        host = text.substr(1, close - 1);
        port = text.substr(close + 2);
    } else {
        const std::size_t colon = text.rfind(':');
        if (colon == std::string_view::npos || colon == 0) {
            error = "expected host:port or unix:/path in '" + std::string(text) + "'";
            return false;
        }
        host = text.substr(0, colon);
        port = text.substr(colon + 1);
    }
    asio::error_code ec;
    const auto addr = asio::ip::make_address(std::string(host), ec);
    if (ec) {
        error = "upstream host must be an IP literal (names are resolved in a later phase): '" + std::string(host) +
                "'";
        return false;
    }
    unsigned p = 0;
    for (char c : port) {
        if (c < '0' || c > '9' || (p = p * 10 + static_cast<unsigned>(c - '0')) > 65535) {
            error = "bad port in '" + std::string(text) + "'";
            return false;
        }
    }
    if (p == 0 || port.empty()) {
        error = "bad port in '" + std::string(text) + "'";
        return false;
    }
    out.host = addr.to_string();
    out.port = static_cast<std::uint16_t>(p);
    out.key = (addr.is_v6() ? "[" + out.host + "]" : out.host) + ":" + std::to_string(p);
    return true;
}

// ---- config-time check ----

std::vector<std::string> check_upstreams(const Config& cfg) {
    std::vector<std::string> warnings;
    std::vector<std::string> seen;
    for (const auto& site : cfg.sites)
        for (const auto& loc : site.locations) {
            if (loc.kind == HandlerKind::static_) continue;
            const bool fcgi = loc.kind == HandlerKind::fastcgi;
            for (const UpstreamAddress& a : fcgi ? loc.fastcgi.addresses : loc.proxy.addresses) {
            if (std::find(seen.begin(), seen.end(), a.key) != seen.end()) continue;
            seen.push_back(a.key);
            asio::io_context ctx;
            asio::generic::stream_protocol::socket s(ctx);
            asio::error_code ec;
            bool done = false;
            auto on_connect = [&](const asio::error_code& e) {
                ec = e;
                done = true;
            };
            if (a.unix) {
#ifdef ASIO_HAS_LOCAL_SOCKETS
                asio::local::stream_protocol::endpoint ep(a.path);
                s.open(asio::generic::stream_protocol(ep.protocol()), ec);
                if (!ec) s.async_connect(ep, on_connect);
#else
                ec = asio::error::operation_not_supported;
#endif
            } else {
                asio::ip::tcp::endpoint ep(asio::ip::make_address(a.host), a.port);
                s.open(asio::generic::stream_protocol(ep.protocol()), ec);
                if (!ec) s.async_connect(ep, on_connect);
            }
            if (!ec && !done) {
                ctx.run_for(std::chrono::seconds(1));
                if (!done) ec = asio::error::timed_out;
            }
            if (!ec) continue;
            std::string hint = ec.message();
            const bool os = ec.category() == asio::system_category() || ec.category() == std::system_category();
            const int v = os ? ec.value() : 0;
            if (v == ENOENT) hint += fcgi ? "; is php-fpm running and is its `listen` this path?" : "; is the upstream running?";
            else if (v == EACCES || v == EPERM) hint += "; check the socket's owner, group and mode";
            else if (v == ECONNREFUSED) hint += "; nothing is listening there";
            warnings.push_back(std::string(fcgi ? "fastcgi" : "proxy") + " upstream " + a.key + " (" +
                               site.server_names.front() + " location '" + loc.path + "'): " + hint);
            }
        }
    return warnings;
}

// ---- pool ----

std::size_t UpstreamPool::limit_for(const UpstreamOptions& opts, bool priority) noexcept {
    if (priority) return opts.max_connections;
    const auto reserved = static_cast<std::size_t>(static_cast<double>(opts.max_connections) * opts.priority_reserve);
    return opts.max_connections > reserved ? opts.max_connections - reserved : 0;
}

std::unique_ptr<UpstreamConnection> UpstreamPool::fresh() { return std::make_unique<UpstreamConnection>(ctx_); }

void UpstreamPool::acquire(const std::string& key, const UpstreamOptions& opts, bool priority,
                           std::shared_ptr<UpstreamRequest> req) {
    Upstream& u = upstreams_[key];
    if (u.active < limit_for(opts, priority)) {
        grant(u, Waiter{std::move(req), priority});
        return;
    }
    if (u.queue.size() >= opts.queue_depth) {
        req->on_queue_refused(UpstreamFailure::pool_saturated);
        return;
    }
    u.queue.push_back(Waiter{std::move(req), priority});
}

void UpstreamPool::grant(Upstream& u, Waiter w) {
    ++u.active;
    std::unique_ptr<UpstreamConnection> c;
    if (!u.idle.empty()) {
        c = std::move(u.idle.back());
        u.idle.pop_back();
        c->reused = true;
    } else {
        c = fresh();
    }
    w.req->on_slot(std::move(c));
}

void UpstreamPool::release(const std::string& key, const UpstreamOptions& opts, std::unique_ptr<UpstreamConnection> conn) {
    Upstream& u = upstreams_[key];
    if (u.active > 0) --u.active;
    if (conn && conn->sock().is_open() && u.idle.size() < opts.max_idle) {
        conn->reused = false;
        conn->in_len = 0;
        u.idle.push_back(std::move(conn));
    }
    // Next in line: a priority waiter first, else the oldest one the limit allows.
    for (auto it = u.queue.begin(); it != u.queue.end(); ++it) {
        if (!it->priority) continue;
        if (u.active >= limit_for(opts, true)) return;
        Waiter w = std::move(*it);
        u.queue.erase(it);
        grant(u, std::move(w));
        return;
    }
    if (!u.queue.empty() && u.active < limit_for(opts, false)) {
        Waiter w = std::move(u.queue.front());
        u.queue.pop_front();
        grant(u, std::move(w));
    }
}

void UpstreamPool::dequeue(const std::string& key, const UpstreamRequest* req) noexcept {
    auto it = upstreams_.find(key);
    if (it == upstreams_.end()) return;
    auto& q = it->second.queue;
    for (auto w = q.begin(); w != q.end(); ++w)
        if (w->req.get() == req) {
            q.erase(w);
            return;
        }
}

void UpstreamPool::watch(UpstreamRequest* req) {
    req->watch_index = watched_.size();
    watched_.push_back(req);
    if (ticking_) return;
    ticking_ = true;
    tick_.expires_after(kTick);
    tick_.async_wait([this](const asio::error_code& ec) {
        if (!ec) tick();
    });
}

void UpstreamPool::unwatch(UpstreamRequest* req) noexcept {
    const std::size_t i = req->watch_index;
    if (i == SIZE_MAX) return;
    UpstreamRequest* last = watched_.back();
    watched_.pop_back();
    if (last != req) {  // the last entry takes the freed slot
        watched_[i] = last;
        last->watch_index = i;
    }
    req->watch_index = SIZE_MAX;
}

void UpstreamPool::tick() {
    const auto now = std::chrono::steady_clock::now();
    // An overdue exchange unwatches itself (swap-remove), so the slot is re-examined.
    for (std::size_t i = 0; i < watched_.size();) {
        UpstreamRequest* r = watched_[i];
        r->on_tick(now);
        if (i < watched_.size() && watched_[i] == r) ++i;
    }
    if (watched_.empty()) {
        ticking_ = false;
        return;
    }
    tick_.expires_after(kTick);
    tick_.async_wait([this](const asio::error_code& ec) {
        if (!ec) tick();
    });
}

std::size_t UpstreamPool::pick(const std::vector<UpstreamAddress>& group, const UpstreamOptions& opts,
                               std::size_t after, unsigned tried_mask) {
    const std::size_t n = group.size();
    if (n == 0) return SIZE_MAX;
    const auto now = std::chrono::steady_clock::now();
    std::size_t start;
    if (after == SIZE_MAX) {
        unsigned& pos = rotation_[&group];
        start = pos % n;
        pos = static_cast<unsigned>((start + 1) % n);
    } else {
        start = (after + 1) % n;
    }
    std::size_t fallback = SIZE_MAX;  // when every member is down: the one marked longest ago
    for (std::size_t k = 0; k < n; ++k) {
        const std::size_t i = (start + k) % n;
        if (i < 32 && (tried_mask & (1u << i))) continue;
        const Health& h = health(group[i]);
        if (h.down_until <= now) return i;
        if (fallback == SIZE_MAX || h.marked < health(group[fallback]).marked) fallback = i;
    }
    (void)opts;
    return fallback;
}

void UpstreamPool::mark_failure(const UpstreamAddress& a, const UpstreamOptions& opts, std::string& note) {
    Health& h = health(a);
    const auto now = std::chrono::steady_clock::now();
    if (++h.failures >= opts.max_fails && h.down_until <= now) {
        h.down_until = now + opts.fail_timeout;
        h.marked = now;
        note = a.key + " marked down for " + std::to_string(opts.fail_timeout.count() / 1000) + " s after " +
               std::to_string(h.failures) + " failure(s)";
    }
}

#ifdef AGENSIO_HAS_TLS
asio::ssl::context* UpstreamPool::tls_context(const TlsClientConfig& tc, std::string& error) {
    auto it = tls_contexts_.find(tc.key());
    if (it != tls_contexts_.end()) return it->second.get();
    auto ctx = std::make_unique<asio::ssl::context>(asio::ssl::context::tls_client);
    asio::error_code ec;
    ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2 |
                     asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1);
    if (tc.verify) {
        if (tc.ca_file.empty()) ctx->set_default_verify_paths(ec);
        else ctx->load_verify_file(tc.ca_file, ec);
        if (ec) {
            error = "cannot load the CA bundle " + (tc.ca_file.empty() ? std::string("(system store)") : tc.ca_file) +
                    ": " + ec.message();
            return nullptr;
        }
        ctx->set_verify_mode(asio::ssl::verify_peer);
    } else {
        ctx->set_verify_mode(asio::ssl::verify_none);
    }
    return (tls_contexts_[tc.key()] = std::move(ctx)).get();
}
#endif

void UpstreamPool::mark_success(const UpstreamAddress& a, std::string& note) {
    auto it = health_.find(a.key);
    if (it == health_.end() || it->second.failures == 0) return;
    if (it->second.down_until != std::chrono::steady_clock::time_point{}) note = a.key + " is back";
    it->second = Health{};
}

// ---- streaming source ----

class UpstreamRequest::Source final : public StreamBody {
public:
    Source(std::shared_ptr<UpstreamRequest> req, bool sized, std::uint64_t length)
        : req_(std::move(req)), sized_(sized), length_(length) {}
    bool length(std::uint64_t& out) const noexcept override {
        out = length_;
        return sized_;
    }
    void async_read(char* buf, std::size_t len, ReadHandler handler) override {
        req_->pull(buf, len, std::move(handler));
    }

private:
    std::shared_ptr<UpstreamRequest> req_;
    bool sized_;
    std::uint64_t length_;
};

// ---- request ----

// Speculative completions (data already readable / writable) run inline instead of being
// posted: the same rule as the connection's own I/O, one event-loop trip fewer per step.
template <class F>
static auto immediate(asio::io_context& ctx, F&& f) {
    return asio::bind_immediate_executor(ctx.get_executor(), std::forward<F>(f));
}

UpstreamRequest::UpstreamRequest(UpstreamPool& pool, const std::vector<UpstreamAddress>& group,
                                 const UpstreamOptions& options, const TlsClientConfig* tls)
    : options_(options), pool_(pool), tls_(tls), group_(&group) {
    member_ = pool_.pick(group, options_, SIZE_MAX, 0);
    if (member_ != SIZE_MAX) {
        address_ = group[member_];
        if (member_ < 32) tried_ |= 1u << member_;
    }
}

UpstreamRequest::~UpstreamRequest() { pool_.unwatch(this); }

void UpstreamRequest::begin(UpstreamBodyInput body, bool priority, bool retry_ok, Completion done) {
    done_ = std::move(done);
    body_ = std::move(body);
    priority_ = priority;
    retry_ok_ = retry_ok && !body_.stream && body_.size == 0;
    out_.clear();
    encode_head(out_);
    // Body entirely in memory: it rides in the same write. Spilled: the in-memory prefix
    // rides along and the temp file follows. Streamed: it follows chunk by chunk.
    if (!body_.stream && !body_.spill.is_open()) {
        encode_body_chunk(out_, body_.memory, true);
        body_.memory.clear();
        body_.memory.shrink_to_fit();
    } else if (!body_.memory.empty()) {
        encode_body_chunk(out_, body_.memory, false);
        body_.memory.clear();
        body_.memory.shrink_to_fit();
    }
    phase_ = Phase::queued;
    pool_.watch(this);
    arm(options_.queue_wait);
    pool_.acquire(address_.key, options_, priority_, shared_from_this());
}

void UpstreamRequest::on_queue_refused(UpstreamFailure why) {
    if (phase_ != Phase::queued) return;
    phase_ = Phase::failed;
    pool_.unwatch(this);
    result_.failure = why;
    deliver_head();
}

void UpstreamRequest::on_slot(std::unique_ptr<UpstreamConnection> conn) {
    if (phase_ != Phase::queued) {  // cancelled or timed out while queued: give the slot back
        pool_.release(address_.key, options_, std::move(conn));
        return;
    }
    ++attempts_;
    conn_ = std::move(conn);
    if (conn_->sock().is_open()) {
        phase_ = Phase::sending;
        send_head();
    } else {
        connect();
    }
}

void UpstreamRequest::cancel() noexcept {
    if (phase_ == Phase::cancelled) return;
    const Phase was = phase_;
    phase_ = Phase::cancelled;
    asio::error_code ec;
    pool_.unwatch(this);
    if (was == Phase::queued) pool_.dequeue(address_.key, this);
    else if (was != Phase::finished && was != Phase::failed) release_connection(false);
    if (conn_ && conn_->sock().is_open()) conn_->sock().close(ec);
    conn_.reset();
    if (waiter_.handler) {  // a pull in flight must not hang
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        h(std::error_code(asio::error::operation_aborted), 0);
    }
    done_ = nullptr;
}

std::unique_ptr<StreamBody> UpstreamRequest::body_source() {
    std::uint64_t length = 0;
    bool sized = false;
    if (const std::string_view cl = result_.headers.get("content-length"); !cl.empty()) {
        std::uint64_t v = 0;
        sized = true;
        for (char c : cl) {
            if (c < '0' || c > '9') {
                sized = false;
                break;
            }
            v = v * 10 + static_cast<std::uint64_t>(c - '0');
        }
        length = v;
    }
    return std::make_unique<Source>(shared_from_this(), sized, length);
}

void UpstreamRequest::arm(std::chrono::milliseconds d) { deadline_ = std::chrono::steady_clock::now() + d; }

void UpstreamRequest::on_tick(std::chrono::steady_clock::time_point now) {
    if (now < deadline_) return;
    auto self = shared_from_this();  // the failure callbacks may drop the last other owner
    switch (phase_) {
        case Phase::queued:
            pool_.unwatch(this);
            pool_.dequeue(address_.key, this);
            phase_ = Phase::failed;
            result_.failure = UpstreamFailure::queue_timeout;
            deliver_head();
            break;
        case Phase::connecting: fail(UpstreamFailure::connect_timeout, asio::error::timed_out); break;
        case Phase::sending:
        case Phase::sending_body: fail(UpstreamFailure::send_timeout, asio::error::timed_out); break;
        case Phase::receiving: fail(UpstreamFailure::read_timeout, asio::error::timed_out); break;
        default: pool_.unwatch(this); break;
    }
}

void UpstreamRequest::connect() {
    phase_ = Phase::connecting;
    arm(options_.connect_timeout);
    auto self = shared_from_this();
    auto on_connect = [self](const asio::error_code& ec) {
        if (self->phase_ != Phase::connecting) return;
        if (ec) {
            // Classify by errno: asio reports OS errors in the system category.
            const bool os_error = ec.category() == asio::system_category() ||
                                  ec.category() == std::system_category() || ec.category() == std::generic_category();
            const int v = os_error ? ec.value() : 0;
            UpstreamFailure why = UpstreamFailure::connect_error;
            if (v == ECONNREFUSED) why = UpstreamFailure::connect_refused;
            else if (v == ENOENT) why = UpstreamFailure::socket_missing;
            else if (v == EACCES || v == EPERM) why = UpstreamFailure::socket_permission;
            self->fail(why, ec);
            return;
        }
        if (self->address_.tls) {
            self->handshake();
            return;
        }
        self->phase_ = Phase::sending;
        self->send_head();
    };
    asio::error_code ec;
    if (address_.unix) {
#ifdef ASIO_HAS_LOCAL_SOCKETS
        asio::local::stream_protocol::endpoint ep(address_.path);
        conn_->sock().open(asio::generic::stream_protocol(ep.protocol()), ec);
        if (!ec) conn_->sock().async_connect(ep, immediate(pool_.context(), on_connect));
#else
        ec = asio::error::operation_not_supported;
#endif
    } else {
        asio::ip::tcp::endpoint ep(asio::ip::make_address(address_.host), address_.port);
        conn_->sock().open(asio::generic::stream_protocol(ep.protocol()), ec);
        if (!ec) {
            // Our writes must not wait for the upstream's ACK (a streamed request body is
            // many small writes); nginx sets this on upstream connections too.
            asio::error_code ignored;
            conn_->sock().set_option(asio::ip::tcp::no_delay(true), ignored);
            conn_->sock().async_connect(ep, immediate(pool_.context(), on_connect));
        }
    }
    if (ec) fail(UpstreamFailure::connect_error, ec);
}

// TLS to the origin: the stream wraps the connected socket, SNI and verification from the
// location's tls table, the handshake runs before the request head goes out.
void UpstreamRequest::handshake() {
#ifdef AGENSIO_HAS_TLS
    std::string error;
    asio::ssl::context* ctx = pool_.tls_context(tls_ ? *tls_ : TlsClientConfig{}, error);
    if (!ctx) {
        fail(UpstreamFailure::tls_error, std::error_code(asio::error::invalid_argument));
        return;
    }
    const TlsClientConfig tc = tls_ ? *tls_ : TlsClientConfig{};
    conn_->tls = std::make_unique<BasicTlsStream<UpstreamConnection::Socket>>(std::move(conn_->socket), *ctx);
    if (!conn_->tls->set_client(tc.server_name, tc.verify)) {
        fail(UpstreamFailure::tls_error, std::error_code(asio::error::invalid_argument));
        return;
    }
    phase_ = Phase::sending;  // the send timeout covers the handshake
    arm(options_.send_timeout);
    auto self = shared_from_this();
    conn_->tls->async_handshake([self](std::error_code ec) {
        if (self->phase_ != Phase::sending) return;
        if (ec) {
            self->fail(UpstreamFailure::tls_error, ec);
            return;
        }
        self->send_head();
    });
#else
    fail(UpstreamFailure::tls_error, std::error_code(asio::error::operation_not_supported));
#endif
}

// On a kept TCP connection the peer's last partial segment of a response sits in Nagle
// until we ACK the segment before it, and our kernel delays that ACK by up to 40 ms
// (php-fpm does not set TCP_NODELAY; a fresh connection never shows this because close()
// flushes). Measured on the Laravel bed: the 78 KB page fell from 3.4k to 1.1k req/s.
// TCP_QUICKACK (Linux) acknowledges immediately; the kernel clears it, so it is set
// before every read of a kept connection. Unix sockets and fresh connections need nothing.
void UpstreamRequest::quick_ack() noexcept {
#ifdef TCP_QUICKACK
    // Only while a response body is still arriving: a small answer that fits one read
    // never stalls, and this saves a setsockopt per exchange on the common case.
    if (address_.unix || !options_.keep_conn || !head_done_) return;
    const int one = 1;
    ::setsockopt(conn_->sock().native_handle(), IPPROTO_TCP, TCP_QUICKACK, &one, sizeof one);
#endif
}

void UpstreamRequest::send_head() {
    arm(options_.send_timeout);
    sent_any_ = true;
    auto self = shared_from_this();
    conn_->async_write(asio::buffer(out_), immediate(pool_.context(), [self](const asio::error_code& ec, std::size_t) {
        if (self->phase_ != Phase::sending) return;
        if (ec) {
            if (self->try_retry(ec)) return;
            self->fail(UpstreamFailure::closed_early, ec);
            return;
        }
        if (self->body_.stream || self->body_.spill.is_open()) {
            self->phase_ = Phase::sending_body;
            self->send_body_next();
        } else {
            self->body_sent();
        }
    }));
}

// The body from the spill file or the client stream, one framed chunk per write.
void UpstreamRequest::send_body_next() {
    auto self = shared_from_this();
    body_chunk_.clear();
    if (body_.spill.is_open()) {
        if (stream_chunk_.size() < kBodyChunk) stream_chunk_.resize(kBodyChunk);
        const std::int64_t got = body_.spill.read_at(stream_chunk_.data(), stream_chunk_.size(), body_pos_);
        if (got < 0) {
            fail(UpstreamFailure::spill_error, std::error_code(errno, std::generic_category()));
            return;
        }
        body_pos_ += static_cast<std::uint64_t>(got);
        const bool last = got == 0;
        encode_body_chunk(body_chunk_, std::string_view(stream_chunk_.data(), static_cast<std::size_t>(got)), last);
        arm(options_.send_timeout);
        conn_->async_write(asio::buffer(body_chunk_),
                          [self, last](const asio::error_code& ec, std::size_t) {
                              if (self->phase_ != Phase::sending_body) return;
                              if (ec) {
                                  self->fail(UpstreamFailure::closed_early, ec);
                                  return;
                              }
                              if (last) self->body_sent();
                              else self->send_body_next();
                          });
        return;
    }
    // Streaming from the client: pull a chunk, forward it, repeat until the end. One pull
    // is outstanding at a time, so one member buffer serves every chunk.
    if (stream_chunk_.size() < kBodyChunk) stream_chunk_.resize(kBodyChunk);
    body_.stream->async_read(stream_chunk_.data(), stream_chunk_.size(), [self](std::error_code ec, std::size_t n) {
        if (self->phase_ != Phase::sending_body) return;
        if (ec) {
            self->fail(UpstreamFailure::closed_early, ec);
            return;
        }
        self->body_chunk_.clear();
        const bool last = n == 0;
        self->encode_body_chunk(self->body_chunk_, std::string_view(self->stream_chunk_.data(), n), last);
        self->arm(self->options_.send_timeout);
        self->conn_->async_write(asio::buffer(self->body_chunk_),
                          [self, last](const asio::error_code& wec, std::size_t) {
                              if (self->phase_ != Phase::sending_body) return;
                              if (wec) {
                                  self->fail(UpstreamFailure::closed_early, wec);
                                  return;
                              }
                              if (last) self->body_sent();
                              else self->send_body_next();
                          });
    });
}

void UpstreamRequest::body_sent() {
    phase_ = Phase::receiving;
    if (!retry_ok_) {  // no resend possible any more: the head buffer is not needed
        out_.clear();
        out_.shrink_to_fit();
    }
    read_more();
}

void UpstreamRequest::read_more() {
    // Not while the decoder runs: delivering the head can run the writer, whose inline
    // completion pulls and lands here; on_data() reads again itself when it is done.
    if (reading_ || in_data_ || phase_ != Phase::receiving) return;
    if (!options_.buffering && head_delivered_ && pending_.size() - pending_pos_ >= kHighWater) return;  // backpressure
    if (conn_->in.size() < 16 * 1024) conn_->in.resize(16 * 1024);
    if (conn_->in_len == conn_->in.size()) conn_->in.resize(conn_->in.size() * 2);  // one huge record
    reading_ = true;
    arm(options_.read_timeout);
    quick_ack();
    auto self = shared_from_this();
    auto on_read = [self](const asio::error_code& ec, std::size_t n) {
        self->reading_ = false;
        if (self->phase_ != Phase::receiving) return;
        if (ec) {
            if (self->try_retry(ec)) return;
            if (ec == asio::error::eof && self->on_eof()) return;
            self->fail(UpstreamFailure::closed_early, ec);
            return;
        }
        self->on_data(n);
    };
    // The first read after sending is a speculative recv that returns EAGAIN while the
    // upstream still works; waiting for readiness instead costs an epoll_ctl (asio re-arms
    // the descriptor for non-speculative ops), the same price. Measured: no difference.
    conn_->async_read_some(asio::buffer(conn_->in.data() + conn_->in_len, conn_->in.size() - conn_->in_len),
                                  immediate(pool_.context(), on_read));
}

// A reused connection that the upstream had closed (php-fpm reload, an origin's idle
// timeout): resend once on a fresh one, only while nothing of the response has been seen
// and for GET/HEAD.
bool UpstreamRequest::try_retry(std::error_code ec) {
    if (!retry_ok_ || attempts_ != 1 || !conn_ || !conn_->reused || result_.head_bytes > 0) return false;
    if (ec != asio::error::eof && ec != asio::error::connection_reset && ec != asio::error::broken_pipe) return false;
    asio::error_code ignored;
    conn_->sock().close(ignored);
    conn_ = pool_.fresh();
    ++attempts_;
    connect();
    return true;
}

void UpstreamRequest::on_data(std::size_t n) {
    conn_->in_len += n;
    in_data_ = true;
    const bool more = decode();
    in_data_ = false;
    if (more && phase_ == Phase::receiving) read_more();
}

void UpstreamRequest::consume(std::size_t n) noexcept {
    if (n == 0) return;
    if (n < conn_->in_len) std::memmove(conn_->in.data(), conn_->in.data() + n, conn_->in_len - n);
    conn_->in_len -= n;
}

UpstreamRequest::HeadStatus UpstreamRequest::feed_head(std::string_view bytes, std::size_t& used) {
    used = bytes.size();
    result_.head_bytes += bytes.size();
    const std::size_t before = head_buf_.size();
    head_buf_.append(bytes);  // grows as needed, bounded by head_max below
    int status = 200;
    Headers headers;
    std::size_t length = 0;
    const HeadStatus hs = parse_head(head_buf_, status, headers, length);
    if (hs == HeadStatus::incomplete) {
        if (head_buf_.size() > options_.head_max) {
            fail(UpstreamFailure::head_too_large, std::error_code());
            return HeadStatus::error;
        }
        return hs;
    }
    if (hs == HeadStatus::error || length > options_.head_max) {
        fail(hs == HeadStatus::error ? UpstreamFailure::bad_response_head : UpstreamFailure::head_too_large,
             std::error_code());
        return HeadStatus::error;
    }
    used = length - before;  // the rest of `bytes` is body
    head_done_ = true;
    result_.status = status;
    result_.head = head_buf_.substr(0, length);
    // Re-parse over the owned copy so the views point into result_.head.
    (void)parse_head(result_.head, status, result_.headers, length);
    head_buf_.clear();
    head_buf_.shrink_to_fit();
    out_.clear();  // no retry once the head arrived
    out_.shrink_to_fit();
    if (!options_.buffering) deliver_head();
    return HeadStatus::complete;
}

void UpstreamRequest::reset_head() {
    head_done_ = false;
    result_.head.clear();
    result_.headers.clear();
    head_buf_.clear();
}

bool UpstreamRequest::store_body(std::string_view bytes) {
    if (bytes.empty()) return true;
    result_.body_size += bytes.size();
    if (!options_.buffering) {
        if (phase_ == Phase::cancelled) return false;
        pending_.append(bytes);
        satisfy_waiter();
        return true;
    }
    if (result_.spill.is_open()) {
        if (spilled_ + bytes.size() > options_.buffer_file_max) {
            // Temp file cap: stream the rest. The head goes out now; pulls serve the spill
            // file first, then what keeps arriving, under the high-water mark.
            options_.buffering = false;
            deliver_head();
            if (phase_ == Phase::cancelled) return false;
            pending_.append(bytes);
            satisfy_waiter();
            return true;
        }
        if (!result_.spill.append(bytes.data(), bytes.size())) {
            fail(UpstreamFailure::spill_error, std::error_code(errno, std::generic_category()));
            return false;
        }
        spilled_ += bytes.size();
        return true;
    }
    if (result_.body.size() + bytes.size() > options_.buffer_max) {
        result_.spill = File::temporary();
        if (!result_.spill.is_open() || !result_.spill.append(result_.body.data(), result_.body.size()) ||
            !result_.spill.append(bytes.data(), bytes.size())) {
            fail(UpstreamFailure::spill_error, std::error_code(errno, std::generic_category()));
            return false;
        }
        spilled_ = result_.body_size;
        result_.body.clear();
        result_.body.shrink_to_fit();
        return true;
    }
    result_.body.append(bytes);
    return true;
}

void UpstreamRequest::finish() {
    phase_ = Phase::finished;
    pool_.unwatch(this);
    pool_.mark_success(address_, note_);
    release_connection(true);
    if (!options_.buffering) {
        if (!head_delivered_) deliver_head();
        satisfy_waiter();  // a waiting pull gets the end of body
        return;
    }
    deliver_head();
}

void UpstreamRequest::finish_upgraded() {
    phase_ = Phase::finished;
    pool_.unwatch(this);
    pool_.release(address_.key, options_, nullptr);
    result_.upgraded = true;
    deliver_head();
}

void UpstreamRequest::release_connection(bool reusable) {
    std::unique_ptr<UpstreamConnection> c = std::move(conn_);
    if (c && (!reusable || !options_.keep_conn || c->in_len != 0 || !keep_alive_ok())) {
        asio::error_code ignored;
        if (c->sock().is_open()) c->sock().close(ignored);
        c.reset();
    }
    pool_.release(address_.key, options_, std::move(c));
}

void UpstreamRequest::deliver_head() {
    if (head_delivered_ || phase_ == Phase::cancelled) return;
    head_delivered_ = true;
    result_.streamed = !options_.buffering;
    if (done_) {
        Completion done = std::move(done_);
        done_ = nullptr;
        done(result_);
    }
}

// A connect failure sent nothing, so any request may move on; after bytes went out only
// an idempotent one (retry_ok_) that has seen no response byte may. Pool refusals are the
// pool's verdict for this worker and are not retried elsewhere.
bool UpstreamRequest::try_next_address(UpstreamFailure why) {
    if (!group_ || group_->size() < 2 || phase_ == Phase::cancelled) return false;
    if (why == UpstreamFailure::pool_saturated || why == UpstreamFailure::queue_timeout) return false;
    if (sent_any_ && (!retry_ok_ || result_.head_bytes > 0)) return false;
    const std::size_t next = pool_.pick(*group_, options_, member_, tried_);
    if (next == SIZE_MAX) return false;
    // Give this address's slot and connection back, start again on the next one.
    std::unique_ptr<UpstreamConnection> c = std::move(conn_);
    if (c) {
        asio::error_code ignored;
        if (c->sock().is_open()) c->sock().close(ignored);
    }
    if (phase_ != Phase::queued) pool_.release(address_.key, options_, nullptr);
    member_ = next;
    address_ = (*group_)[next];
    if (next < 32) tried_ |= 1u << next;
    attempts_ = 0;
    sent_any_ = false;
    body_pos_ = 0;
    phase_ = Phase::queued;
    arm(options_.queue_wait);
    pool_.acquire(address_.key, options_, priority_, shared_from_this());
    return true;
}

void UpstreamRequest::fail(UpstreamFailure why, std::error_code ec) {
    if (phase_ == Phase::cancelled || phase_ == Phase::finished || phase_ == Phase::failed) return;
    if (why != UpstreamFailure::pool_saturated && why != UpstreamFailure::queue_timeout &&
        why != UpstreamFailure::spill_error)
        pool_.mark_failure(address_, options_, note_);
    if (try_next_address(why)) return;
    const Phase was = phase_;
    phase_ = Phase::failed;
    pool_.unwatch(this);
    if (was == Phase::queued) pool_.dequeue(address_.key, this);
    else release_connection(false);
    result_.error = ec;
    if (!head_delivered_) {
        result_.failure = why;
        deliver_head();  // the handler sees result_.failure
    } else {
        result_.failure = why;
        satisfy_waiter();  // streaming: the pull completes with the error
    }
}

void UpstreamRequest::pull(char* buf, std::size_t len, StreamBody::ReadHandler handler) {
    waiter_ = Waiter{buf, len, std::move(handler)};
    satisfy_waiter();
    if (waiter_.handler) read_more();  // nothing pending yet: keep the upstream flowing
}

void UpstreamRequest::satisfy_waiter() {
    if (!waiter_.handler) return;
    // After a mid-response switch to streaming: the bytes already spilled go first.
    if (spill_read_ < spilled_ && result_.spill.is_open()) {
        const std::size_t want = static_cast<std::size_t>(std::min<std::uint64_t>(spilled_ - spill_read_, waiter_.len));
        const std::int64_t got = result_.spill.read_at(waiter_.buf, want, spill_read_);
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        if (got <= 0) {
            h(std::error_code(asio::error::connection_reset), 0);
            return;
        }
        spill_read_ += static_cast<std::uint64_t>(got);
        h(std::error_code{}, static_cast<std::size_t>(got));
        return;
    }
    const std::size_t avail = pending_.size() - pending_pos_;
    if (avail > 0) {
        const std::size_t n = std::min(avail, waiter_.len);
        std::memcpy(waiter_.buf, pending_.data() + pending_pos_, n);
        pending_pos_ += n;
        if (pending_pos_ == pending_.size()) {
            pending_.clear();
            pending_pos_ = 0;
        }
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        h(std::error_code{}, n);
        return;
    }
    if (phase_ == Phase::finished) {
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        h(std::error_code{}, 0);
    } else if (phase_ == Phase::failed) {
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        h(result_.error ? result_.error : std::error_code(asio::error::connection_reset), 0);
    }
    // receiving: the next on_data() satisfies it
}

}  // namespace agensio
