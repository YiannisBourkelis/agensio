// Reverse proxy handler (phase D): forwards a request to an HTTP/1.1 origin through the
// worker's UpstreamPool and turns the answer into a Response. Asynchronous like the
// FastCGI handler: the request body is collected (memory, then a temp file) or streamed,
// the exchange runs on HttpRequest, and `done` is called once the Response is filled.
// Every failure is logged with its UpstreamFailure reason and reaches the access log's
// upstream field. Nothing here is on the static hot path.
//
// Head handling (D1, the basics; D2 adds the policy knobs): the request line keeps the
// client's target; hop-by-hop fields and those the client's Connection field lists are
// dropped; Host is passed through; X-Forwarded-For gets the client address appended,
// X-Forwarded-Proto and X-Forwarded-Host are set. Response fields come back untouched
// except framing and connection ones.
#pragma once

#include <functional>
#include <memory>
#include <string>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "services/log.hpp"
#include "upstream/http_client.hpp"

namespace agensio {

class ProxyHandler {
public:
    ProxyHandler(const Config& cfg, ErrorLog& log) : cfg_(cfg), log_(log) {}

    // Starts the exchange for `loc` (kind proxy); ws.site and s.conn are set. `done` runs
    // exactly once, when s.response is ready, possibly before start() returns. Returns
    // the in-flight request so the connection can cancel it, or nullptr when the response
    // was produced synchronously.
    std::shared_ptr<UpstreamRequest> start(Stream& s, const LocationConfig& loc, WorkerState& ws, UpstreamPool& pool,
                                           std::function<void()> done);

    // The request head to send: request line and the forwarded fields per `policy`
    // (public for tests).
    static void build_head(std::string& out, const Stream& s, std::string_view target, const UpstreamConfig& policy);

private:
    struct Exchange;
    void finish(Exchange& x, UpstreamResult& r);

    const Config& cfg_;
    ErrorLog& log_;
};

}  // namespace agensio
