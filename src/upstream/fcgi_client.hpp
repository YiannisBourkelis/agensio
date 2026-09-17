// Async FastCGI/1.1 client (responder role) over a unix or TCP socket: the FastCGI wire
// protocol on top of UpstreamRequest (client.hpp), which owns the pool slot, the
// connection, timeouts, retry, body sending and response buffering/streaming.
//
// Sends BEGIN_REQUEST, the PARAMS stream (a block prebuilt per location plus the
// per-request tail) and the request body as STDIN records, then reads STDOUT (the CGI
// head, then the body), STDERR (kept for the error log) and END_REQUEST.
#pragma once

#include <string>
#include <string_view>

#include "upstream/client.hpp"
#include "upstream/fcgi.hpp"

namespace agensio {

// The FastCGI code and the tests keep these names.
using FcgiPool = UpstreamPool;
using FcgiConnection = UpstreamConnection;
using FcgiBodyInput = UpstreamBodyInput;
using FcgiResult = UpstreamResult;

class FcgiRequest final : public UpstreamRequest {
public:
    FcgiRequest(UpstreamPool& pool, const std::vector<UpstreamAddress>& group, const UpstreamOptions& options)
        : UpstreamRequest(pool, group, options) {}

    // Sends the request: `params_prefix` (prebuilt) then `params_tail` (this request),
    // then `body`. See UpstreamRequest::begin for `done` and `retry_ok`.
    void start(std::string_view params_prefix, std::string_view params_tail, UpstreamBodyInput body, bool priority,
               bool retry_ok, Completion done) {
        params_prefix_ = params_prefix;
        params_tail_ = params_tail;
        begin(std::move(body), priority, retry_ok, std::move(done));
    }

private:
    void encode_head(std::string& out) override;
    void encode_body_chunk(std::string& out, std::string_view bytes, bool last) override;
    bool decode() override;
    HeadStatus parse_head(std::string_view in, int& status, Headers& headers, std::size_t& length) override;
    bool on_stdout(std::string_view content);
    void on_end_request(std::string_view content);

    std::string_view params_prefix_;  // valid until begin() has encoded the head
    std::string_view params_tail_;
    static constexpr std::size_t kStderrCap = 64 * 1024;
};

}  // namespace agensio
