// What every upstream exchange shares (FastCGI to php-fpm, HTTP to an origin server):
//
//  * UpstreamPool: per worker, never shared. For each upstream address it bounds the number
//    of exchanges in flight (max_connections) with an explicit queue (queue_depth,
//    queue_wait) instead of the kernel backlog, so an overloaded upstream yields an
//    immediate 503 with Retry-After rather than a hang; a share of the slots
//    (priority_reserve) is kept for requests from `priority` locations so admin paths keep
//    working under a front-page flood. Idle connections are kept for reuse.
//  * UpstreamRequest: one exchange. Takes a pool slot, connects (or reuses), sends the head
//    the derived class encoded plus the request body from memory, from a spilled temp file
//    or streamed from the client, then reads the response through the derived class's
//    decoder. The response head is collected up to head_max and parsed by the derived
//    class. With buffering on (default) the body is collected in memory and, above
//    buffer_max, spilled to an unlinked temporary file, so the upstream is released as soon
//    as it finishes and a slow client cannot hold it; with buffering off the body is pulled
//    through a StreamBody with a high-water mark. One retry on a fresh connection when a
//    reused connection dies before any byte of the head arrived, for GET/HEAD only.
//    Every failure carries an UpstreamFailure reason; timeouts map to 504, pool limits to
//    503, the rest to 502. Cancelling (the client went away) drops the connection and
//    suppresses every callback.
//  The wire protocol lives in the derived classes: FcgiRequest (fcgi_client.hpp) and
//  HttpRequest (http_client.hpp).
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <vector>

#include <asio.hpp>

#include "core/body.hpp"
#include "core/headers.hpp"
#include "file.hpp"
#include "upstream/options.hpp"

namespace agensio {

struct UpstreamConnection {
    explicit UpstreamConnection(asio::io_context& ctx) : socket(ctx) {}
    asio::generic::stream_protocol::socket socket;
    std::vector<char> in;  // bytes read from the upstream, not yet consumed
    std::size_t in_len = 0;
    bool reused = false;   // came from the idle list (retry candidate on reset)
};

class UpstreamRequest;
struct Config;

// `agensio -t`: tries to connect to every upstream (1 s each) and returns one warning line
// per unreachable one, naming the reason (missing socket, permission, refused). Warnings,
// not errors: the upstream may legitimately start after us.
std::vector<std::string> check_upstreams(const Config& cfg);

class UpstreamPool {
public:
    explicit UpstreamPool(asio::io_context& ctx) : ctx_(ctx), tick_(ctx) {}
    asio::io_context& context() noexcept { return ctx_; }

    // Deadlines: an exchange records the time its current phase may take; one timer per
    // pool (this worker) ticks every kTick and fails whoever is overdue. No timer per
    // exchange: arming one per phase cost two timerfd_settime syscalls per proxied
    // request (measured: 7 syscalls per request against the static path's 2).
    static constexpr std::chrono::milliseconds kTick{250};
    void watch(UpstreamRequest* req);
    void unwatch(UpstreamRequest* req) noexcept;

    // Asks for a slot to `key`. Granted at once (the request's on_slot runs inline with an
    // idle or fresh connection), queued, or refused (pool_saturated) when the queue is full.
    void acquire(const std::string& key, const UpstreamOptions& opts, bool priority,
                 std::shared_ptr<UpstreamRequest> req);
    // A fresh connection for a retry; the slot stays held.
    std::unique_ptr<UpstreamConnection> fresh();
    // Gives the slot back; `conn` (if any and reusable) joins the idle list. Grants the
    // next queued request, priority ones first.
    void release(const std::string& key, const UpstreamOptions& opts, std::unique_ptr<UpstreamConnection> conn);
    // Removes a queued request (its wait expired or it was cancelled).
    void dequeue(const std::string& key, const UpstreamRequest* req) noexcept;

private:
    struct Waiter {
        std::shared_ptr<UpstreamRequest> req;
        bool priority = false;
    };
    struct Upstream {
        std::vector<std::unique_ptr<UpstreamConnection>> idle;
        std::deque<Waiter> queue;
        std::size_t active = 0;
    };
    static std::size_t limit_for(const UpstreamOptions& opts, bool priority) noexcept;
    void grant(Upstream& u, Waiter w);

    void tick();

    asio::io_context& ctx_;
    std::unordered_map<std::string, Upstream> upstreams_;
    std::vector<UpstreamRequest*> watched_;  // exchanges with a deadline; swap-removed by index
    asio::steady_timer tick_;
    bool ticking_ = false;
};

// The request body as the client sends it.
struct UpstreamBodyInput {
    std::string memory;        // whole body, or the first request_buffer_max bytes before a spill
    File spill;                // the rest of the body when it did not fit in memory
    std::uint64_t size = 0;    // total bytes (memory + spill), or the declared length when streaming
    bool size_known = true;    // streaming: false when the client sent it chunked
    StreamBody* stream = nullptr;  // request_buffering off: pulled chunk by chunk from the client
};

// What the handler gets back.
struct UpstreamResult {
    UpstreamFailure failure = UpstreamFailure::none;  // none: `status`, `headers` and the body are valid
    std::error_code error;                            // the OS/asio error behind the failure, if any
    std::uint64_t head_bytes = 0;                     // response bytes seen before a failure (diagnostics)
    int status = 200;
    std::string head;         // the response head bytes; `headers` are views into it
    Headers headers;          // every field but the status
    std::string body;         // buffered body (buffering on, at most buffer_max bytes)
    File spill;               // the body when it did not fit: an unlinked temp file
    std::uint64_t body_size = 0;
    bool streamed = false;    // the body comes through body_source() (buffering off, or the spill cap was hit)
    bool upgraded = false;    // HTTP 101: no body, the connection is now a tunnel (take_connection())
    std::string stderr_text;  // FastCGI: FCGI_STDERR output (capped), for the error log
};

class UpstreamRequest : public std::enable_shared_from_this<UpstreamRequest> {
public:
    using Completion = std::function<void(UpstreamResult&)>;

    UpstreamRequest(UpstreamPool& pool, const UpstreamAddress& address, const UpstreamOptions& options);
    virtual ~UpstreamRequest();

    // Client gone: drop everything, no callbacks.
    void cancel() noexcept;

    // Streaming mode: the response body as a pull source (valid after `done` ran).
    std::unique_ptr<StreamBody> body_source();
    // After a 101: the origin connection, with any bytes that followed the head still in
    // its `in` buffer. The exchange is over; the pool slot was already given back.
    std::unique_ptr<UpstreamConnection> take_connection() noexcept { return std::move(conn_); }

    // Called by the pool.
    void on_slot(std::unique_ptr<UpstreamConnection> conn);
    void on_queue_refused(UpstreamFailure why);
    void on_tick(std::chrono::steady_clock::time_point now);  // fails the exchange when its phase is overdue
    std::size_t watch_index = SIZE_MAX;                       // position in the pool's watch list

protected:
    // The derived class calls this once its head is ready: encodes the head (and, when the
    // whole body is in memory, the body right behind it) and takes a pool slot. `done` runs
    // once, on the worker thread: with buffering when the whole response is in (or on
    // error), without buffering as soon as the head is parsed (the body then comes through
    // body_source()). `retry_ok`: GET/HEAD, may be resent once.
    void begin(UpstreamBodyInput body, bool priority, bool retry_ok, Completion done);

    // ---- the wire protocol, supplied by the derived class ----
    // The request head into `out` (the body follows through encode_body_chunk).
    virtual void encode_head(std::string& out) = 0;
    // `bytes` of the request body (possibly empty) and, when `last`, whatever ends it.
    virtual void encode_body_chunk(std::string& out, std::string_view bytes, bool last) = 0;
    // Consumes what it can of conn_->in (call consume(n) for used bytes; feed_head() for
    // head bytes, store_body() for body bytes, finish() / fail() to end). Returns false when
    // the exchange ended inside the call.
    virtual bool decode() = 0;
    // The response head from the bytes collected so far.
    enum class HeadStatus { complete, incomplete, error };
    virtual HeadStatus parse_head(std::string_view in, int& status, Headers& headers, std::size_t& length) = 0;
    // EOF from the upstream while receiving: true when that legitimately ended the
    // response (HTTP close-delimited bodies); false means closed_early.
    virtual bool on_eof() { return false; }
    // Whether the connection may serve another exchange after this one.
    virtual bool keep_alive_ok() const noexcept { return true; }

    // ---- helpers for decode() ----
    // Head bytes: collects up to head_max and parses; `used` is how much of `bytes` the
    // head took (the rest is body). complete runs deliver_head() when not buffering.
    HeadStatus feed_head(std::string_view bytes, std::size_t& used);
    // Forget a parsed head (HTTP 1xx interim responses) and collect the next one.
    void reset_head();
    bool store_body(std::string_view bytes);
    void consume(std::size_t n) noexcept;  // drops n bytes from the front of conn_->in
    void finish();
    void finish_upgraded();  // 101: the slot goes back, the connection stays for take_connection()
    void fail(UpstreamFailure why, std::error_code ec);
    bool head_done() const noexcept { return head_done_; }

    UpstreamOptions options_;
    std::unique_ptr<UpstreamConnection> conn_;
    UpstreamResult result_;
    UpstreamBodyInput body_;

private:
    class Source;
    enum class Phase { queued, connecting, sending, sending_body, receiving, finished, failed, cancelled };

    void connect();
    void quick_ack() noexcept;
    void send_head();
    void send_body_next();
    void body_sent();
    void read_more();
    void on_data(std::size_t n);
    bool try_retry(std::error_code ec);
    void arm(std::chrono::milliseconds d);
    void deliver_head();
    void pull(char* buf, std::size_t len, StreamBody::ReadHandler handler);
    void satisfy_waiter();
    void release_connection(bool reusable);

    UpstreamPool& pool_;
    UpstreamAddress address_;
    std::chrono::steady_clock::time_point deadline_{};  // when the current phase becomes a timeout
    std::string out_;           // the encoded head (+ body when in memory); kept for a retry
    std::string body_chunk_;    // one body chunk, framed, from the spill file / client stream
    std::string stream_chunk_;  // one client-body chunk in flight (request_buffering off)
    std::uint64_t body_pos_ = 0;  // bytes of the spill file already sent
    bool priority_ = false;
    bool retry_ok_ = false;
    unsigned attempts_ = 0;
    Completion done_;
    Phase phase_ = Phase::queued;
    bool head_done_ = false;
    bool head_delivered_ = false;
    std::string head_buf_;  // response bytes until the head is complete (grows up to head_max)
    // Streaming mode (from the start, or after the temp-file cap switched to it).
    std::uint64_t spilled_ = 0;      // bytes in result_.spill
    std::uint64_t spill_read_ = 0;   // bytes of result_.spill already handed to a pull
    std::string pending_;    // body bytes not yet pulled
    std::size_t pending_pos_ = 0;
    bool reading_ = false;
    bool in_data_ = false;  // inside on_data(): defers read_more() from re-entrant pulls
    struct Waiter {
        char* buf = nullptr;
        std::size_t len = 0;
        StreamBody::ReadHandler handler;
    } waiter_;
    static constexpr std::size_t kHighWater = 256 * 1024;  // stop reading the upstream when this much is pending
    static constexpr std::size_t kBodyChunk = 64 * 1024;
};

}  // namespace agensio
