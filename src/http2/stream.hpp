// One HTTP/2 stream (RFC 9113 section 5): its state, the embedded Stream the handlers
// see, the arena its decoded fields live in, the flow-control windows, the request body
// as it arrives in DATA frames, and the response as the writer sends it. Streams are
// pooled by the connection, so a request allocates nothing once the connection has
// reached its concurrency; every buffer keeps its capacity between uses.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "core/body.hpp"
#include "core/stream.hpp"
#include "http2/frame.hpp"

namespace agensio {
class UpstreamRequest;
struct SiteConfig;
}  // namespace agensio

namespace agensio::h2 {

enum class StreamState : std::uint8_t {
    idle,
    open,                // HEADERS received, the request may still have a body coming
    half_closed_remote,  // END_STREAM received: the request is complete
    half_closed_local,   // our response is complete, the client's body is still open: DATA is discarded
    closed,
};

struct H2Stream;

// What the body source needs from the connection (one virtual call per body read).
class BodyOwner {
public:
    virtual ~BodyOwner() = default;
    virtual void read_body(H2Stream& s, char* buf, std::size_t len, StreamBody::ReadHandler handler) = 0;
};

struct H2Stream {
    // The request body as the pull source behind Request::body: DATA frames feed body_buf,
    // the handler drains it; a read with nothing buffered waits for the next DATA frame.
    class BodySource final : public StreamBody {
    public:
        bool length(std::uint64_t& out) const noexcept override {
            if (!stream->length_known) return false;
            out = stream->content_length;
            return true;
        }
        void async_read(char* buf, std::size_t len, ReadHandler handler) override {
            owner->read_body(*stream, buf, len, std::move(handler));
        }
        BodyOwner* owner = nullptr;
        H2Stream* stream = nullptr;
    };

    std::uint32_t id = 0;
    StreamState state = StreamState::idle;
    Stream stream;         // Request, Response, ConnectionInfo
    std::string arena;     // decoded field bytes; the Request's views point here
    std::string cookie;    // several cookie fields joined with "; " (RFC 9113 8.2.3)
    std::string scratch;   // lower-cased names while encoding the head
    std::string client_addr;  // X-Forwarded-For result (conn.client_address views it)
    const SiteConfig* site = nullptr;  // decided at routing, for the access log (WorkerState::site is per worker)
    unsigned gen = 0;      // bumps per use and on close; guards late upstream callbacks
    std::shared_ptr<UpstreamRequest> upstream;  // exchange in flight, cancelled on reset or close
    std::chrono::steady_clock::time_point since{};  // when the current phase started (timeouts)

    // Flow control (RFC 9113 6.9). Windows are signed: SETTINGS_INITIAL_WINDOW_SIZE can shrink one below zero.
    std::int32_t send_window = 0;    // what the peer lets us send on this stream
    std::int32_t recv_grant = 0;     // what we told the peer it may send (updates raise it)
    std::int32_t recv_pending = 0;   // bytes buffered but not yet consumed by the handler
    std::uint32_t recv_unreturned = 0;  // consumed bytes not yet returned with WINDOW_UPDATE

    // Request body.
    bool has_body = false;
    bool length_known = false;
    std::uint64_t content_length = 0;
    std::uint64_t body_received = 0;   // DATA bytes accepted so far
    std::uint64_t body_limit = 0;      // the site's or the server's max_body_size
    std::uint64_t discarded = 0;       // body bytes dropped after the response (half_closed_local)
    bool body_done = false;            // END_STREAM seen
    std::vector<char> body_buf;        // DATA bytes not yet read by the handler (allocated on first use)
    std::size_t body_pos = 0, body_len = 0;
    char* pending_buf = nullptr;       // a handler read waiting for DATA
    std::size_t pending_len = 0;
    StreamBody::ReadHandler pending_handler;
    BodySource body_source;

    // Response progress (the writer's).
    bool ready = false;        // the response is filled and waits for the writer
    bool head_sent = false;
    bool finished = false;     // END_STREAM was queued
    bool responded = false;    // the response head went out (a reset after that is not a cancellation)
    bool pulling = false;      // a StreamBody read is in flight
    bool source_done = false;
    bool source_sized = false;
    std::uint64_t source_remaining = 0;
    std::uint64_t body_sent = 0;   // body bytes framed (access log)
    std::uint64_t body_offset = 0; // MemoryBody / FileBody progress
    std::vector<char> chunk;       // file or source bytes waiting to be framed
    std::size_t chunk_len = 0, chunk_pos = 0;
    bool logged = false;
    bool defer_release = false;    // closed while its bytes were in flight: released when the write ends
    bool in_ready = false;         // linked in the writer's ready list
    bool in_cycle = false;         // noted in the writer's cycle in flight (bytes of it are with the kernel)
    H2Stream* next_ready = nullptr;
    std::size_t slot = 0;          // its place in the connection's active table (O(1) release)

    void reset() {
        state = StreamState::idle;
        stream.reset();
        arena.clear();
        cookie.clear();
        scratch.clear();
        client_addr.clear();
        site = nullptr;
        ++gen;
        upstream.reset();
        send_window = recv_grant = recv_pending = 0;
        recv_unreturned = 0;
        has_body = length_known = body_done = false;
        content_length = body_received = body_limit = discarded = 0;
        body_pos = body_len = 0;
        pending_buf = nullptr;
        pending_len = 0;
        pending_handler = nullptr;
        ready = head_sent = finished = responded = pulling = source_done = source_sized = false;
        source_remaining = body_sent = body_offset = 0;
        chunk_len = chunk_pos = 0;
        logged = defer_release = in_ready = in_cycle = false;
        next_ready = nullptr;
        slot = 0;
    }
};

}  // namespace agensio::h2
