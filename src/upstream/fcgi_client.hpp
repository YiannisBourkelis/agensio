// Async FastCGI/1.1 client (responder role) over a unix or TCP socket.
//
//  * FcgiPool: per worker, never shared. For each upstream address it bounds the number
//    of exchanges in flight (max_connections) with an explicit queue (queue_depth,
//    queue_wait) instead of the kernel backlog, so an overloaded fpm yields an immediate
//    503 with Retry-After rather than a hang; a share of the slots (priority_reserve) is
//    kept for requests from `priority` locations so admin paths keep working under a
//    front-page flood. Idle connections are kept for reuse with FCGI_KEEP_CONN.
//  * FcgiRequest: one exchange. Sends BEGIN_REQUEST, the PARAMS stream (a block prebuilt
//    per location plus the per-request tail) and the request body as STDIN records from
//    memory, from a spilled temp file, or streamed from the client, then reads
//    STDOUT/STDERR/END_REQUEST. The CGI head is parsed as soon as it is complete, from a
//    buffer that grows up to head_max. With buffering on (default) the body is collected
//    in memory and, above buffer_max, spilled to an unlinked temporary file, so the fpm
//    child is released as soon as it finishes and a slow client cannot hold it; with
//    buffering off the body is pulled through a StreamBody with a high-water mark.
//  * One retry on a fresh connection when a reused connection dies before any byte of
//    the head arrived, for GET/HEAD only (php-fpm reloads drop keep-alive connections).
//  * Every failure carries an FcgiFailure reason; timeouts map to 504, pool limits to
//    503, the rest to 502. Cancelling (the client went away) drops the upstream
//    connection and suppresses every callback.
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
#include "upstream/fcgi.hpp"
#include "upstream/fcgi_options.hpp"

namespace agensio {

struct FcgiConnection {
    explicit FcgiConnection(asio::io_context& ctx) : socket(ctx) {}
    asio::generic::stream_protocol::socket socket;
    std::vector<char> in;  // bytes read from the upstream, not yet consumed
    std::size_t in_len = 0;
    bool reused = false;   // came from the idle list (retry candidate on reset)
};

class FcgiRequest;
struct Config;

// `agensio -t`: tries to connect to every FastCGI upstream (1 s each) and returns one
// warning line per unreachable one, naming the reason (missing socket, permission,
// refused). Warnings, not errors: php-fpm may legitimately start after us.
std::vector<std::string> check_upstreams(const Config& cfg);

class FcgiPool {
public:
    explicit FcgiPool(asio::io_context& ctx) : ctx_(ctx) {}
    asio::io_context& context() noexcept { return ctx_; }

    // Asks for a slot to `key`. Granted at once (the request's on_slot runs inline with an
    // idle or fresh connection), queued, or refused (pool_saturated) when the queue is full.
    void acquire(const std::string& key, const FcgiOptions& opts, bool priority, std::shared_ptr<FcgiRequest> req);
    // A fresh connection for a retry; the slot stays held.
    std::unique_ptr<FcgiConnection> fresh();
    // Gives the slot back; `conn` (if any and reusable) joins the idle list. Grants the
    // next queued request, priority ones first.
    void release(const std::string& key, const FcgiOptions& opts, std::unique_ptr<FcgiConnection> conn);
    // Removes a queued request (its wait expired or it was cancelled).
    void dequeue(const std::string& key, const FcgiRequest* req) noexcept;

private:
    struct Waiter {
        std::shared_ptr<FcgiRequest> req;
        bool priority = false;
    };
    struct Upstream {
        std::vector<std::unique_ptr<FcgiConnection>> idle;
        std::deque<Waiter> queue;
        std::size_t active = 0;
    };
    static std::size_t limit_for(const FcgiOptions& opts, bool priority) noexcept;
    void grant(Upstream& u, Waiter w);

    asio::io_context& ctx_;
    std::unordered_map<std::string, Upstream> upstreams_;
};

// The request body as the client sends it.
struct FcgiBodyInput {
    std::string memory;        // whole body, or the first request_buffer_max bytes before a spill
    File spill;                // the rest of the body when it did not fit in memory
    std::uint64_t size = 0;    // total bytes (memory + spill), or the declared length when streaming
    StreamBody* stream = nullptr;  // request_buffering off: pulled chunk by chunk from the client
};

// What the handler gets back.
struct FcgiResult {
    FcgiFailure failure = FcgiFailure::none;  // none: `status`, `headers` and the body are valid
    std::error_code error;                    // the OS/asio error behind the failure, if any
    std::uint64_t head_bytes = 0;             // STDOUT bytes seen before a failure (diagnostics)
    int status = 200;
    std::string head;         // the CGI head bytes; `headers` are views into it
    Headers headers;          // every field but Status
    std::string body;         // buffered body (buffering on, at most buffer_max bytes)
    File spill;               // the body when it did not fit: an unlinked temp file
    std::uint64_t body_size = 0;
    bool streamed = false;    // the body comes through body_source() (buffering off, or the spill cap was hit)
    std::string stderr_text;  // FCGI_STDERR output (capped), for the error log
};

class FcgiRequest : public std::enable_shared_from_this<FcgiRequest> {
public:
    using Completion = std::function<void(FcgiResult&)>;

    FcgiRequest(FcgiPool& pool, const FcgiAddress& address, const FcgiOptions& options);
    ~FcgiRequest();

    // Sends the request: `params_prefix` (prebuilt) then `params_tail` (this request),
    // then `body`. `done` runs once, on the worker thread: with buffering when the whole
    // response is in (or on error), without buffering as soon as the head is parsed (the
    // body then comes through body_source()). `retry_ok`: GET/HEAD, may be resent once.
    void start(std::string_view params_prefix, std::string_view params_tail, FcgiBodyInput body, bool priority,
               bool retry_ok, Completion done);

    // Client gone: drop everything, no callbacks.
    void cancel() noexcept;

    // Streaming mode: the response body as a pull source (valid after `done` ran).
    std::unique_ptr<StreamBody> body_source();

    // Called by the pool.
    void on_slot(std::unique_ptr<FcgiConnection> conn);
    void on_queue_refused(FcgiFailure why);

private:
    class Source;
    enum class Phase { queued, connecting, sending, sending_body, receiving, finished, failed, cancelled };

    void connect();
    void send_head();
    void send_body_next();
    void body_sent();
    void read_more();
    void on_data(std::size_t n);
    bool on_stdout(std::string_view content);
    void on_end_request(std::string_view content);
    bool store_body(std::string_view bytes);
    void finish();
    void fail(FcgiFailure why, std::error_code ec);
    bool try_retry(std::error_code ec);
    void arm(std::chrono::milliseconds d);
    void deliver_head();
    void pull(char* buf, std::size_t len, StreamBody::ReadHandler handler);
    void satisfy_waiter();
    void release_connection(bool reusable);

    FcgiPool& pool_;
    FcgiAddress address_;
    FcgiOptions options_;
    asio::steady_timer timer_;
    std::unique_ptr<FcgiConnection> conn_;
    std::string out_;        // BEGIN_REQUEST + PARAMS (+ STDIN when the body is in memory); kept for a retry
    std::string body_chunk_;  // STDIN records built from the spill file / client stream
    std::string stream_chunk_;  // one client-body chunk in flight (request_buffering off)
    FcgiBodyInput body_;
    std::uint64_t body_pos_ = 0;  // bytes of the spill file already sent
    bool priority_ = false;
    bool retry_ok_ = false;
    unsigned attempts_ = 0;
    Completion done_;
    FcgiResult result_;
    Phase phase_ = Phase::queued;
    bool head_done_ = false;
    bool head_delivered_ = false;
    std::string head_buf_;  // STDOUT bytes until the head is complete (grows up to head_max)
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
    static constexpr std::size_t kHighWater = 256 * 1024;  // stop reading fpm when this much is pending
    static constexpr std::size_t kStderrCap = 64 * 1024;
    static constexpr std::size_t kBodyChunk = 64 * 1024;
};

}  // namespace agensio
