// One HTTP/3 stream (RFC 9114 section 6): the QUIC stream's transport state first, so
// the transport's pointer to it is the object; then the embedded Stream the handlers see,
// the arena its decoded fields live in, the frame parser's position, the request body as
// the pull source behind Request::body, and the response's progress. Pooled by the
// connection through http/stream_pool.hpp, as HTTP/2's are.
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "core/body.hpp"
#include "core/stream.hpp"
#include "http3/qpack.hpp"
#include "quic/stream.hpp"

namespace agensio {
class UpstreamRequest;
struct SiteConfig;
}  // namespace agensio

namespace agensio::h3 {

struct H3Stream;

class BodyOwner {
public:
    virtual ~BodyOwner() = default;
    virtual void read_body(H3Stream& s, char* buf, std::size_t len, StreamBody::ReadHandler handler) = 0;
};

struct H3Stream {
    quic::QuicStream q;  // first: the transport addresses the stream through it

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
        H3Stream* stream = nullptr;
    };

    enum class Kind : std::uint8_t { request, peer_uni, our_uni };
    Kind kind = Kind::request;
    std::uint64_t uni_type = 0;  // the stream type of a unidirectional stream
    bool type_known = false;
    bool control_settings_seen = false;

    Stream stream;
    std::string arena;
    std::string cookie;
    std::string scratch;
    std::string client_addr;
    const SiteConfig* site = nullptr;
    unsigned gen = 0;
    std::shared_ptr<UpstreamRequest> upstream;
    std::chrono::steady_clock::time_point since{};

    // The frame parser (7.1): the frame being read and how much of its payload remains.
    bool in_frame = false;
    std::uint64_t frame_type = 0;
    std::uint64_t frame_remaining = 0;
    std::string section;  // the HEADERS payload as it arrives (bounded by max_header_size)
    qpack::Section qpack;  // our answer's dynamic-table references until the peer acknowledges the section
    bool headers_done = false;
    bool blocked = false;         // the section waits for the encoder stream (RFC 9204 2.2.1)
    bool trailers = false;        // the pending section is a trailer section (decoded, discarded)
    std::uint64_t required = 0;   // the blocked section's Required Insert Count

    // Request body: the bytes stay in the QUIC stream's receive buffer until the handler
    // reads them (credit returns as it does).
    bool has_body = false;
    bool length_known = false;
    std::uint64_t content_length = 0;
    std::uint64_t body_received = 0;
    std::uint64_t body_limit = 0;
    std::uint64_t discarded = 0;
    bool body_done = false;
    char* pending_buf = nullptr;
    std::size_t pending_len = 0;
    StreamBody::ReadHandler pending_handler;
    BodySource body_source;

    // A streamed answer (a StreamBody: an unbuffered upstream, CGI, a body compressed in pieces): its
    // pieces are read into the QUIC stream's send blocks, each behind its DATA frame header
    // (design-http3 7.3), while the stream has room.
    bool streaming = false;        // its source is read: the end not reached yet
    bool pulling = false;          // a read of it is out
    bool read_inline = false;      // the read is being started: an answer now is the pull loop's
    bool defer_release = false;    // closed with a read out: released when the read is answered
    bool source_sized = false;     // the source declared its length (content-length), held to it
    std::uint64_t source_remaining = 0;
    std::uint64_t body_bytes = 0;  // the body's bytes appended, for the access log
    std::uint32_t pieces = 0;      // DATA frames appended
    char* piece = nullptr;         // where the read's DATA frame starts, in the last block

    // Response progress.
    bool responded = false;
    bool finished = false;  // every byte acknowledged, or the reset sent
    bool logged = false;
    bool closed = false;
    std::uint16_t unsent_status = 499;  // the access log's status when no byte of the answer went out
    std::size_t slot = 0;

    void reset() {
        q.reset_quic();
        kind = Kind::request;
        uni_type = 0;
        type_known = control_settings_seen = false;
        stream.reset();
        arena.clear();
        cookie.clear();
        scratch.clear();
        client_addr.clear();
        site = nullptr;
        ++gen;
        upstream.reset();
        in_frame = false;
        frame_type = frame_remaining = 0;
        section.clear();
        headers_done = false;
        blocked = trailers = false;
        required = 0;
        has_body = length_known = body_done = false;
        content_length = body_received = body_limit = discarded = 0;
        pending_buf = nullptr;
        pending_len = 0;
        pending_handler = nullptr;
        streaming = pulling = read_inline = defer_release = source_sized = false;
        source_remaining = body_bytes = 0;
        pieces = 0;
        piece = nullptr;
        responded = finished = logged = closed = false;
        unsent_status = 499;
        slot = 0;
    }
};

}  // namespace agensio::h3
