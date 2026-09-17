// CGI handler (phase D5): runs a script under the location as a process per request with
// the CGI/1.1 environment (the same variables the FastCGI handler sends, as
// NAME=value strings) and turns its output into a Response. Asynchronous like the other
// upstream handlers: the request body is collected or streamed, the exchange runs on
// CgiRequest through the worker's UpstreamPool (which caps the processes per worker and
// queues the rest), and `done` is called once the Response is filled. For legacy
// applications; nothing here is on the static hot path.
#pragma once

#include <functional>
#include <memory>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "services/log.hpp"
#include "upstream/cgi_client.hpp"

namespace agensio {

class CgiHandler {
public:
    CgiHandler(const Config& cfg, ErrorLog& log) : cfg_(cfg), log_(log) {}

    // Starts the exchange for `loc` (kind cgi); ws.site, ws.path and s.conn are set.
    // `done` runs exactly once, when s.response is ready, possibly before start()
    // returns (404 for a missing script). Returns the in-flight request so the connection
    // can cancel it, or nullptr when the response was produced synchronously.
    std::shared_ptr<UpstreamRequest> start(Stream& s, const SiteConfig& site, const LocationConfig& loc, WorkerState& ws,
                                           UpstreamPool& pool, std::function<void()> done);

private:
    struct Exchange;
    void finish(Exchange& x, UpstreamResult& r);

    const Config& cfg_;
    ErrorLog& log_;
};

}  // namespace agensio
