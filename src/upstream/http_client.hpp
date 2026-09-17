// Async HTTP/1.1 client for the reverse proxy: the HTTP wire protocol on top of
// UpstreamRequest (client.hpp), which owns the pool slot, the keep-alive connection,
// timeouts, retry, body sending and response buffering/streaming.
//
// The handler builds the request head (request line and forwarded fields) and this class
// adds the framing of the body it sends: Content-Length when the size is known, chunked
// otherwise. The response body is framed by Content-Length, chunked (decoded here, so the
// writer re-frames it for the client), or the close of the connection; HEAD, 204, 304 and
// 1xx carry none and 1xx interim responses are skipped. The connection is kept when the
// origin allows it (HTTP/1.1 without "Connection: close", HTTP/1.0 with keep-alive) and
// the body was delimited, never after a close-delimited body.
#pragma once

#include <string>
#include <string_view>

#include "http1/chunked.hpp"
#include "upstream/client.hpp"

namespace agensio {

class HttpRequest final : public UpstreamRequest {
public:
    HttpRequest(UpstreamPool& pool, const std::vector<UpstreamAddress>& group, const UpstreamOptions& options)
        : UpstreamRequest(pool, group, options) {}

    // `head` is the request line and the fields to forward, each line CRLF-terminated,
    // without the framing fields and without the final blank line. `is_head`: a HEAD
    // request, whose response has no body. See UpstreamRequest::begin for the rest.
    void start(std::string head, bool is_head, bool upgrade, UpstreamBodyInput body, bool priority, bool retry_ok,
               Completion done) {
        head_ = std::move(head);
        is_head_ = is_head;
        upgrade_ = upgrade;
        begin(std::move(body), priority, retry_ok, std::move(done));
    }

private:
    enum class Framing { none, length, chunked, close };

    void encode_head(std::string& out) override;
    void encode_body_chunk(std::string& out, std::string_view bytes, bool last) override;
    bool decode() override;
    HeadStatus parse_head(std::string_view in, int& status, Headers& headers, std::size_t& length) override;
    bool on_eof() override;
    bool keep_alive_ok() const noexcept override { return keep_alive_; }
    bool on_head_complete();  // decides the framing from the parsed head

    std::string head_;
    bool is_head_ = false;
    bool upgrade_ = false;  // an Upgrade request: "Connection: Upgrade" goes out, a 101 becomes a tunnel
    bool chunked_out_ = false;  // the request body goes out chunked (size unknown)
    Framing framing_ = Framing::none;
    std::uint64_t remaining_ = 0;  // Framing::length: body bytes still expected
    ChunkedDecoder decoder_;
    std::string decoded_;          // one decode step's output
    bool keep_alive_ = false;
};

}  // namespace agensio
