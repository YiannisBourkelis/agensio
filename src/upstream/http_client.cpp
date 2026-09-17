#include "upstream/http_client.hpp"

#include <charconv>

#include "upstream/http_head.hpp"

namespace agensio {

void HttpRequest::encode_head(std::string& out) {
    out.reserve(head_.size() + 64 + body_.memory.size());
    out.append(head_);
    // Framing of what we send: a known size as Content-Length (also 0, so an origin never
    // waits for a body that is not coming on a POST), else chunked.
    const bool have_body = body_.stream || body_.spill.is_open() || !body_.memory.empty() || body_.size > 0;
    if (!body_.stream || body_.size_known) {
        if (have_body || body_.size > 0 || head_.starts_with("POST") || head_.starts_with("PUT") ||
            head_.starts_with("PATCH")) {
            out.append("Content-Length: ");
            out.append(std::to_string(body_.size));
            out.append("\r\n");
        }
    } else {
        chunked_out_ = true;
        out.append("Transfer-Encoding: chunked\r\n");
    }
    out.append(options_.keep_conn ? "Connection: keep-alive\r\n\r\n" : "Connection: close\r\n\r\n");
    head_.clear();
    head_.shrink_to_fit();
}

void HttpRequest::encode_body_chunk(std::string& out, std::string_view bytes, bool last) {
    if (!chunked_out_) {
        out.append(bytes);
        return;
    }
    if (!bytes.empty()) {
        char size[20];
        const auto r = std::to_chars(size, size + sizeof size, bytes.size(), 16);
        out.append(size, static_cast<std::size_t>(r.ptr - size)).append("\r\n").append(bytes).append("\r\n");
    }
    if (last) out.append("0\r\n\r\n");
}

UpstreamRequest::HeadStatus HttpRequest::parse_head(std::string_view in, int& status, Headers& headers,
                                                     std::size_t& length) {
    http::ResponseHead head;
    const auto hs = http::parse_response_head(in, head);
    if (hs == http::HeadStatus::incomplete) return HeadStatus::incomplete;
    if (hs == http::HeadStatus::error) return HeadStatus::error;
    status = head.status;
    headers = head.headers;
    length = head.length;
    keep_alive_ = head.version_minor >= 1;  // refined by on_head_complete from the Connection field
    return HeadStatus::complete;
}

// After the head: how the body is delimited (RFC 9112 section 6.3) and whether the
// connection survives it. Returns false when a 1xx interim response was skipped.
bool HttpRequest::on_head_complete() {
    const int status = result_.status;
    const std::string_view connection = result_.headers.get("connection");
    if (http::connection_lists(connection, "close")) keep_alive_ = false;
    else if (http::connection_lists(connection, "keep-alive")) keep_alive_ = true;
    if (status >= 100 && status < 200 && status != 101) {  // interim: the real head follows
        reset_head();
        return false;
    }
    if (is_head_ || status == 204 || status == 304 || status == 101) {
        framing_ = Framing::none;
        return true;
    }
    const std::string_view te = result_.headers.get("transfer-encoding");
    if (!te.empty()) {
        // Only "chunked" (as the last coding) is delimited; anything else ends with the connection.
        if (te.size() >= 7 && Headers::iequals(te.substr(te.size() - 7), "chunked")) {
            framing_ = Framing::chunked;
            decoder_.reset();
        } else {
            framing_ = Framing::close;
            keep_alive_ = false;
        }
        return true;
    }
    if (const std::string_view cl = result_.headers.get("content-length"); !cl.empty()) {
        std::uint64_t n = 0;
        const auto r = std::from_chars(cl.data(), cl.data() + cl.size(), n);
        if (r.ec != std::errc() || r.ptr != cl.data() + cl.size()) {
            fail(UpstreamFailure::bad_response_head, std::error_code());
            return true;
        }
        framing_ = Framing::length;
        remaining_ = n;
        return true;
    }
    framing_ = Framing::close;
    keep_alive_ = false;
    return true;
}

bool HttpRequest::decode() {
    for (;;) {
        std::string_view in(conn_->in.data(), conn_->in_len);
        if (!head_done()) {
            if (in.empty()) return true;
            std::size_t used = 0;
            const HeadStatus hs = feed_head(in, used);
            if (hs == HeadStatus::error) return false;
            consume(used);
            if (hs == HeadStatus::incomplete) return true;
            if (!on_head_complete()) continue;  // a 1xx was skipped: parse the next head
            if (result_.failure != UpstreamFailure::none) return false;
            if (framing_ == Framing::none || (framing_ == Framing::length && remaining_ == 0)) {
                finish();
                return false;
            }
            continue;  // body bytes may already be in the buffer
        }
        if (in.empty()) return true;
        switch (framing_) {
            case Framing::length: {
                const std::size_t take = static_cast<std::size_t>(std::min<std::uint64_t>(remaining_, in.size()));
                if (!store_body(in.substr(0, take))) return false;
                consume(take);
                remaining_ -= take;
                if (remaining_ == 0) {
                    finish();
                    return false;
                }
                return true;
            }
            case Framing::chunked: {
                std::size_t consumed = 0, produced = 0;
                if (decoded_.size() < 16 * 1024) decoded_.resize(16 * 1024);
                const auto st = decoder_.decode(in, consumed, decoded_.data(), decoded_.size(), produced);
                consume(consumed);
                if (produced > 0 && !store_body(std::string_view(decoded_.data(), produced))) return false;
                if (st == ChunkedDecoder::Status::error) {
                    fail(UpstreamFailure::protocol_error, std::error_code());
                    return false;
                }
                if (st == ChunkedDecoder::Status::done) {
                    finish();
                    return false;
                }
                if (consumed == 0 && produced == 0) return true;  // needs more input
                continue;  // the output buffer was full: decode the rest
            }
            case Framing::close:
                if (!store_body(in)) return false;
                consume(in.size());
                return true;
            case Framing::none:
                return true;
        }
    }
}

bool HttpRequest::on_eof() {
    if (head_done() && framing_ == Framing::close) {
        finish();
        return true;
    }
    return false;
}

}  // namespace agensio
