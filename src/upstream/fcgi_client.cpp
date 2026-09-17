#include "upstream/fcgi_client.hpp"

#include "config.hpp"

#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <utility>

namespace agensio {

// ---- reasons ----

const char* to_string(FcgiFailure f) noexcept {
    switch (f) {
        case FcgiFailure::none: return "ok";
        case FcgiFailure::connect_refused: return "connect_refused";
        case FcgiFailure::socket_missing: return "socket_missing";
        case FcgiFailure::socket_permission: return "socket_permission";
        case FcgiFailure::connect_error: return "connect_error";
        case FcgiFailure::connect_timeout: return "connect_timeout";
        case FcgiFailure::pool_saturated: return "pool_saturated";
        case FcgiFailure::queue_timeout: return "queue_timeout";
        case FcgiFailure::send_timeout: return "send_timeout";
        case FcgiFailure::read_timeout: return "read_timeout";
        case FcgiFailure::child_closed_early: return "child_closed_early";
        case FcgiFailure::primary_script_unknown: return "primary_script_unknown";
        case FcgiFailure::bad_response_head: return "bad_response_head";
        case FcgiFailure::head_too_large: return "head_too_large";
        case FcgiFailure::protocol_error: return "protocol_error";
        case FcgiFailure::spill_error: return "spill_error";
    }
    return "unknown";
}

int status_for(FcgiFailure f) noexcept {
    switch (f) {
        case FcgiFailure::pool_saturated:
        case FcgiFailure::queue_timeout: return 503;
        case FcgiFailure::connect_timeout:
        case FcgiFailure::send_timeout:
        case FcgiFailure::read_timeout: return 504;
        default: return 502;
    }
}

// ---- address ----

bool parse_fcgi_address(std::string_view text, FcgiAddress& out, std::string& error) {
    out = FcgiAddress{};
    if (text.empty()) {
        error = "empty FastCGI address";
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
        error = "FastCGI host must be an IP literal (names are resolved in a later phase): '" + std::string(host) + "'";
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
            if (loc.kind != HandlerKind::fastcgi) continue;
            const FcgiAddress& a = loc.fastcgi.address;
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
            if (v == ENOENT) hint += "; is php-fpm running and is its `listen` this path?";
            else if (v == EACCES || v == EPERM) hint += "; check listen.owner/listen.group/listen.mode of the fpm pool";
            else if (v == ECONNREFUSED) hint += "; nothing is listening there";
            warnings.push_back("fastcgi upstream " + a.key + " (" + site.server_names.front() + " location '" +
                               loc.path + "'): " + hint);
        }
    return warnings;
}

// ---- pool ----

std::size_t FcgiPool::limit_for(const FcgiOptions& opts, bool priority) noexcept {
    if (priority) return opts.max_connections;
    const auto reserved = static_cast<std::size_t>(static_cast<double>(opts.max_connections) * opts.priority_reserve);
    return opts.max_connections > reserved ? opts.max_connections - reserved : 0;
}

std::unique_ptr<FcgiConnection> FcgiPool::fresh() { return std::make_unique<FcgiConnection>(ctx_); }

void FcgiPool::acquire(const std::string& key, const FcgiOptions& opts, bool priority,
                       std::shared_ptr<FcgiRequest> req) {
    Upstream& u = upstreams_[key];
    if (u.active < limit_for(opts, priority)) {
        grant(u, Waiter{std::move(req), priority});
        return;
    }
    if (u.queue.size() >= opts.queue_depth) {
        req->on_queue_refused(FcgiFailure::pool_saturated);
        return;
    }
    u.queue.push_back(Waiter{std::move(req), priority});
}

void FcgiPool::grant(Upstream& u, Waiter w) {
    ++u.active;
    std::unique_ptr<FcgiConnection> c;
    if (!u.idle.empty()) {
        c = std::move(u.idle.back());
        u.idle.pop_back();
        c->reused = true;
    } else {
        c = fresh();
    }
    w.req->on_slot(std::move(c));
}

void FcgiPool::release(const std::string& key, const FcgiOptions& opts, std::unique_ptr<FcgiConnection> conn) {
    Upstream& u = upstreams_[key];
    if (u.active > 0) --u.active;
    if (conn && conn->socket.is_open() && u.idle.size() < opts.max_idle) {
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

void FcgiPool::dequeue(const std::string& key, const FcgiRequest* req) noexcept {
    auto it = upstreams_.find(key);
    if (it == upstreams_.end()) return;
    auto& q = it->second.queue;
    for (auto w = q.begin(); w != q.end(); ++w)
        if (w->req.get() == req) {
            q.erase(w);
            return;
        }
}

// ---- streaming source ----

class FcgiRequest::Source final : public StreamBody {
public:
    Source(std::shared_ptr<FcgiRequest> req, bool sized, std::uint64_t length)
        : req_(std::move(req)), sized_(sized), length_(length) {}
    bool length(std::uint64_t& out) const noexcept override {
        out = length_;
        return sized_;
    }
    void async_read(char* buf, std::size_t len, ReadHandler handler) override {
        req_->pull(buf, len, std::move(handler));
    }

private:
    std::shared_ptr<FcgiRequest> req_;
    bool sized_;
    std::uint64_t length_;
};

// ---- request ----

FcgiRequest::FcgiRequest(FcgiPool& pool, const FcgiAddress& address, const FcgiOptions& options)
    : pool_(pool), address_(address), options_(options), timer_(pool.context()) {}

FcgiRequest::~FcgiRequest() = default;

void FcgiRequest::start(std::string_view params_prefix, std::string_view params_tail, FcgiBodyInput body,
                        bool priority, bool retry_ok, Completion done) {
    done_ = std::move(done);
    body_ = std::move(body);
    priority_ = priority;
    retry_ok_ = retry_ok && !body_.stream && body_.size == 0;
    out_.clear();
    out_.reserve(64 + params_prefix.size() + params_tail.size() + body_.memory.size() + 32);
    fcgi::append_begin_request(out_, 1, options_.keep_conn);
    // The PARAMS stream: the prebuilt block and the per-request tail as separate records.
    // Their boundary is a pair boundary, which is what matters: php-fpm cannot parse a
    // name/value pair that spans two records. Neither part can reach kMaxContent (the
    // request head is capped at 16 KB and the block is a few hundred bytes), so the
    // 65535-byte split inside append_stream never lands inside a pair.
    fcgi::append_stream(out_, fcgi::RecordType::params, 1, params_prefix, false);
    fcgi::append_stream(out_, fcgi::RecordType::params, 1, params_tail, true);
    // Body entirely in memory: it rides in the same write; otherwise it follows the head.
    if (!body_.stream && !body_.spill.is_open()) {
        fcgi::append_stream(out_, fcgi::RecordType::stdin_, 1, body_.memory, true);
        body_.memory.clear();
        body_.memory.shrink_to_fit();
    }
    phase_ = Phase::queued;
    arm(options_.queue_wait);
    pool_.acquire(address_.key, options_, priority_, shared_from_this());
}

void FcgiRequest::on_queue_refused(FcgiFailure why) {
    if (phase_ != Phase::queued) return;
    phase_ = Phase::failed;
    timer_.cancel();
    result_.failure = why;
    deliver_head();
}

void FcgiRequest::on_slot(std::unique_ptr<FcgiConnection> conn) {
    if (phase_ != Phase::queued) {  // cancelled or timed out while queued: give the slot back
        pool_.release(address_.key, options_, std::move(conn));
        return;
    }
    ++attempts_;
    conn_ = std::move(conn);
    if (conn_->socket.is_open()) {
        phase_ = Phase::sending;
        send_head();
    } else {
        connect();
    }
}

void FcgiRequest::cancel() noexcept {
    if (phase_ == Phase::cancelled) return;
    const Phase was = phase_;
    phase_ = Phase::cancelled;
    asio::error_code ec;
    timer_.cancel();
    if (was == Phase::queued) pool_.dequeue(address_.key, this);
    else if (was != Phase::finished && was != Phase::failed) release_connection(false);
    if (conn_ && conn_->socket.is_open()) conn_->socket.close(ec);
    conn_.reset();
    if (waiter_.handler) {  // a pull in flight must not hang
        auto h = std::move(waiter_.handler);
        waiter_.handler = nullptr;
        h(std::error_code(asio::error::operation_aborted), 0);
    }
    done_ = nullptr;
}

std::unique_ptr<StreamBody> FcgiRequest::body_source() {
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

void FcgiRequest::arm(std::chrono::milliseconds d) {
    auto self = shared_from_this();
    timer_.expires_after(d);
    timer_.async_wait([self](const asio::error_code& ec) {
        if (ec) return;  // cancelled or re-armed
        switch (self->phase_) {
            case Phase::queued:
                self->pool_.dequeue(self->address_.key, self.get());
                self->phase_ = Phase::failed;
                self->result_.failure = FcgiFailure::queue_timeout;
                self->deliver_head();
                break;
            case Phase::connecting: self->fail(FcgiFailure::connect_timeout, asio::error::timed_out); break;
            case Phase::sending:
            case Phase::sending_body: self->fail(FcgiFailure::send_timeout, asio::error::timed_out); break;
            case Phase::receiving: self->fail(FcgiFailure::read_timeout, asio::error::timed_out); break;
            default: break;
        }
    });
}

void FcgiRequest::connect() {
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
            FcgiFailure why = FcgiFailure::connect_error;
            if (v == ECONNREFUSED) why = FcgiFailure::connect_refused;
            else if (v == ENOENT) why = FcgiFailure::socket_missing;
            else if (v == EACCES || v == EPERM) why = FcgiFailure::socket_permission;
            self->fail(why, ec);
            return;
        }
        self->phase_ = Phase::sending;
        self->send_head();
    };
    asio::error_code ec;
    if (address_.unix) {
#ifdef ASIO_HAS_LOCAL_SOCKETS
        asio::local::stream_protocol::endpoint ep(address_.path);
        conn_->socket.open(asio::generic::stream_protocol(ep.protocol()), ec);
        if (!ec) conn_->socket.async_connect(ep, on_connect);
#else
        ec = asio::error::operation_not_supported;
#endif
    } else {
        asio::ip::tcp::endpoint ep(asio::ip::make_address(address_.host), address_.port);
        conn_->socket.open(asio::generic::stream_protocol(ep.protocol()), ec);
        if (!ec) conn_->socket.async_connect(ep, on_connect);
    }
    if (ec) fail(FcgiFailure::connect_error, ec);
}

void FcgiRequest::send_head() {
    arm(options_.send_timeout);
    auto self = shared_from_this();
    asio::async_write(conn_->socket, asio::buffer(out_), [self](const asio::error_code& ec, std::size_t) {
        if (self->phase_ != Phase::sending) return;
        if (ec) {
            if (self->try_retry(ec)) return;
            self->fail(FcgiFailure::child_closed_early, ec);
            return;
        }
        if (self->body_.stream || self->body_.spill.is_open()) {
            self->phase_ = Phase::sending_body;
            self->send_body_next();
        } else {
            self->body_sent();
        }
    });
}

// STDIN records from the spill file or the client stream, one chunk per write.
void FcgiRequest::send_body_next() {
    auto self = shared_from_this();
    body_chunk_.clear();
    if (body_.spill.is_open()) {
        std::string raw;
        raw.resize(kBodyChunk);
        const std::int64_t got = body_.spill.read_at(raw.data(), raw.size(), body_pos_);
        if (got < 0) {
            fail(FcgiFailure::spill_error, std::error_code(errno, std::generic_category()));
            return;
        }
        body_pos_ += static_cast<std::uint64_t>(got);
        // The in-memory prefix goes first, once.
        if (!body_.memory.empty()) {
            fcgi::append_stream(body_chunk_, fcgi::RecordType::stdin_, 1, body_.memory, false);
            body_.memory.clear();
        }
        if (got > 0)
            fcgi::append_stream(body_chunk_, fcgi::RecordType::stdin_, 1,
                                std::string_view(raw.data(), static_cast<std::size_t>(got)), false);
        const bool last = got == 0;
        if (last) fcgi::append_record(body_chunk_, fcgi::RecordType::stdin_, 1, {});
        arm(options_.send_timeout);
        asio::async_write(conn_->socket, asio::buffer(body_chunk_),
                          [self, last](const asio::error_code& ec, std::size_t) {
                              if (self->phase_ != Phase::sending_body) return;
                              if (ec) {
                                  self->fail(FcgiFailure::child_closed_early, ec);
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
    body_.stream->async_read(stream_chunk_.data(), stream_chunk_.size(),
                             [self](std::error_code ec, std::size_t n) mutable {
                                 if (self->phase_ != Phase::sending_body) return;
                                 if (ec) {
                                     self->fail(FcgiFailure::child_closed_early, ec);
                                     return;
                                 }
                                 self->body_chunk_.clear();
                                 if (n > 0)
                                     fcgi::append_stream(self->body_chunk_, fcgi::RecordType::stdin_, 1,
                                                         std::string_view(self->stream_chunk_.data(), n), false);
                                 const bool last = n == 0;
                                 if (last) fcgi::append_record(self->body_chunk_, fcgi::RecordType::stdin_, 1, {});
                                 self->arm(self->options_.send_timeout);
                                 asio::async_write(self->conn_->socket, asio::buffer(self->body_chunk_),
                                                   [self, last](const asio::error_code& wec, std::size_t) {
                                                       if (self->phase_ != Phase::sending_body) return;
                                                       if (wec) {
                                                           self->fail(FcgiFailure::child_closed_early, wec);
                                                           return;
                                                       }
                                                       if (last) self->body_sent();
                                                       else self->send_body_next();
                                                   });
                             });
}

void FcgiRequest::body_sent() {
    phase_ = Phase::receiving;
    if (!retry_ok_) {
        out_.clear();
        out_.shrink_to_fit();
    }
    read_more();
}

void FcgiRequest::read_more() {
    // Not while the record loop runs: delivering the head can run the writer, whose inline
    // completion pulls and lands here; on_data() reads again itself when it is done.
    if (reading_ || in_data_ || phase_ != Phase::receiving) return;
    if (!options_.buffering && head_delivered_ && pending_.size() - pending_pos_ >= kHighWater) return;  // backpressure
    if (conn_->in.size() < 16 * 1024) conn_->in.resize(16 * 1024);
    if (conn_->in_len == conn_->in.size()) conn_->in.resize(conn_->in.size() * 2);  // one huge record
    reading_ = true;
    arm(options_.read_timeout);
    auto self = shared_from_this();
    conn_->socket.async_read_some(asio::buffer(conn_->in.data() + conn_->in_len, conn_->in.size() - conn_->in_len),
                                  [self](const asio::error_code& ec, std::size_t n) {
                                      self->reading_ = false;
                                      if (self->phase_ != Phase::receiving) return;
                                      if (ec) {
                                          if (self->try_retry(ec)) return;
                                          self->fail(FcgiFailure::child_closed_early, ec);
                                          return;
                                      }
                                      self->on_data(n);
                                  });
}

// A reused connection that the upstream had closed (php-fpm reload): resend once on a
// fresh one, only while nothing of the response has been seen and for GET/HEAD.
bool FcgiRequest::try_retry(std::error_code ec) {
    if (!retry_ok_ || attempts_ != 1 || !conn_ || !conn_->reused || result_.head_bytes > 0) return false;
    if (ec != asio::error::eof && ec != asio::error::connection_reset && ec != asio::error::broken_pipe) return false;
    timer_.cancel();
    asio::error_code ignored;
    conn_->socket.close(ignored);
    conn_ = pool_.fresh();
    ++attempts_;
    connect();
    return true;
}

void FcgiRequest::on_data(std::size_t n) {
    conn_->in_len += n;
    in_data_ = true;
    std::size_t pos = 0;
    while (pos < conn_->in_len) {
        std::size_t used = 0;
        fcgi::RecordHeader h;
        std::string_view content;
        const std::string_view unread(conn_->in.data() + pos, conn_->in_len - pos);
        const auto st = fcgi::next_record(unread, used, h, content);
        if (st == fcgi::ReadStatus::error) {
            in_data_ = false;
            fail(FcgiFailure::protocol_error, std::error_code());
            return;
        }
        if (st == fcgi::ReadStatus::need_more) break;
        pos += used;
        if (h.request_id != 1 && h.type != static_cast<std::uint8_t>(fcgi::RecordType::get_values_result)) continue;
        switch (static_cast<fcgi::RecordType>(h.type)) {
            case fcgi::RecordType::stdout_:
                result_.head_bytes += content.size();
                if (!on_stdout(content)) {  // failed
                    in_data_ = false;
                    return;
                }
                break;
            case fcgi::RecordType::stderr_:
                if (result_.stderr_text.size() < kStderrCap)
                    result_.stderr_text.append(content.substr(0, kStderrCap - result_.stderr_text.size()));
                break;
            case fcgi::RecordType::end_request: {
                // Compact first: finishing hands the connection back to the pool (only when no
                // bytes are left over), and `content` is a view into the buffer being compacted.
                const std::string end(content);
                if (pos < conn_->in_len) std::memmove(conn_->in.data(), conn_->in.data() + pos, conn_->in_len - pos);
                conn_->in_len -= pos;
                in_data_ = false;
                on_end_request(end);
                return;
            }
            default:
                break;  // management records we did not ask for are ignored
        }
    }
    if (pos > 0 && pos < conn_->in_len) std::memmove(conn_->in.data(), conn_->in.data() + pos, conn_->in_len - pos);
    conn_->in_len -= pos;
    in_data_ = false;
    read_more();
}

bool FcgiRequest::on_stdout(std::string_view content) {
    if (!head_done_) {
        head_buf_.append(content);  // grows as needed, bounded by head_max below
        fcgi::CgiHead head;
        const auto hs = fcgi::parse_cgi_head(head_buf_, head);
        if (hs == fcgi::HeadStatus::incomplete) {
            if (head_buf_.size() > options_.head_max) {
                fail(FcgiFailure::head_too_large, std::error_code());
                return false;
            }
            return true;
        }
        if (hs == fcgi::HeadStatus::error || head.length > options_.head_max) {
            fail(hs == fcgi::HeadStatus::error ? FcgiFailure::bad_response_head : FcgiFailure::head_too_large,
                 std::error_code());
            return false;
        }
        head_done_ = true;
        result_.status = head.status;
        result_.head = head_buf_.substr(0, head.length);
        fcgi::CgiHead again;  // re-parse over the owned copy so the views point into result_.head
        (void)fcgi::parse_cgi_head(result_.head, again);
        result_.headers = again.headers;
        const std::string rest = head_buf_.substr(head.length);
        head_buf_.clear();
        head_buf_.shrink_to_fit();
        out_.clear();  // no retry once the head arrived
        out_.shrink_to_fit();
        if (!options_.buffering) deliver_head();
        return store_body(rest);
    }
    return store_body(content);
}

bool FcgiRequest::store_body(std::string_view bytes) {
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
            fail(FcgiFailure::spill_error, std::error_code(errno, std::generic_category()));
            return false;
        }
        spilled_ += bytes.size();
        return true;
    }
    if (result_.body.size() + bytes.size() > options_.buffer_max) {
        result_.spill = File::temporary();
        if (!result_.spill.is_open() || !result_.spill.append(result_.body.data(), result_.body.size()) ||
            !result_.spill.append(bytes.data(), bytes.size())) {
            fail(FcgiFailure::spill_error, std::error_code(errno, std::generic_category()));
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

void FcgiRequest::on_end_request(std::string_view content) {
    fcgi::EndRequest er;
    if (!parse_end_request(content, er) || er.protocol_status != fcgi::ProtocolStatus::request_complete) {
        fail(FcgiFailure::protocol_error, std::error_code());
        return;
    }
    if (!head_done_) {  // the child produced no head at all (a crash; "Primary script unknown" comes with one)
        fail(FcgiFailure::child_closed_early, std::error_code());
        return;
    }
    if (result_.stderr_text.find("Primary script unknown") != std::string::npos)
        result_.failure = FcgiFailure::primary_script_unknown;  // fpm's own 404 is still passed through
    finish();
}

void FcgiRequest::finish() {
    phase_ = Phase::finished;
    timer_.cancel();
    release_connection(true);
    if (!options_.buffering) {
        if (!head_delivered_) deliver_head();
        satisfy_waiter();  // a waiting pull gets the end of body
        return;
    }
    deliver_head();
}

void FcgiRequest::release_connection(bool reusable) {
    std::unique_ptr<FcgiConnection> c = std::move(conn_);
    if (c && (!reusable || !options_.keep_conn || c->in_len != 0)) {
        asio::error_code ignored;
        if (c->socket.is_open()) c->socket.close(ignored);
        c.reset();
    }
    pool_.release(address_.key, options_, std::move(c));
}

void FcgiRequest::deliver_head() {
    if (head_delivered_ || phase_ == Phase::cancelled) return;
    head_delivered_ = true;
    result_.streamed = !options_.buffering;
    if (done_) {
        Completion done = std::move(done_);
        done_ = nullptr;
        done(result_);
    }
}

void FcgiRequest::fail(FcgiFailure why, std::error_code ec) {
    if (phase_ == Phase::cancelled || phase_ == Phase::finished || phase_ == Phase::failed) return;
    const Phase was = phase_;
    phase_ = Phase::failed;
    timer_.cancel();
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

// ---- streaming ----

void FcgiRequest::pull(char* buf, std::size_t len, StreamBody::ReadHandler handler) {
    waiter_ = Waiter{buf, len, std::move(handler)};
    satisfy_waiter();
    if (waiter_.handler) read_more();  // nothing pending yet: keep the upstream flowing
}

void FcgiRequest::satisfy_waiter() {
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
