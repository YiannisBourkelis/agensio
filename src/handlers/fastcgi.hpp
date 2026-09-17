// FastCGI handler: runs a request through php-fpm (or any FastCGI responder) and turns the
// CGI answer into a Response. Asynchronous: the request body is collected (memory, then a
// temp file) or streamed, the exchange runs on the worker's FcgiPool, and `done` is called
// once the Response is filled. Every failure is logged with its FcgiFailure reason and a
// fix hint, and the reason reaches the access log's upstream field.
// The static handler stays synchronous; nothing here is on the static hot path.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "services/log.hpp"
#include "upstream/fcgi_client.hpp"

namespace agensio {

class FcgiHandler {
public:
    FcgiHandler(const Config& cfg, ErrorLog& log) : cfg_(cfg), log_(log) {}

    // Starts the exchange for `loc` (kind fastcgi); ws.site, ws.path and s.conn are set.
    // `done` runs exactly once, when s.response is ready, possibly before start() returns
    // (404 for a missing script). Returns the in-flight request so the connection can
    // cancel it, or nullptr when the response was produced synchronously.
    std::shared_ptr<FcgiRequest> start(Stream& s, const SiteConfig& site, const LocationConfig& loc, WorkerState& ws,
                                       FcgiPool& pool, std::function<void()> done);

    // Fills s.response with a canned error page (502, 503 with Retry-After, 504, 404).
    static void error(Stream& s, int status, std::string_view retry_after = {});

    // The constant FCGI_PARAMS pairs of a location, encoded once at configuration load.
    static std::string prebuild_params(const SiteConfig& site, const LocationConfig& loc);

    // Request headers as HTTP_* pairs, the way nginx does it: names with '_' are dropped
    // (a client could otherwise spoof X-Forwarded-For with X_Forwarded_For), `Proxy` is never
    // forwarded (httpoxy, CVE-2016-5385), repeated fields are joined with ", " (Cookie: "; ").
    static void append_http_params(std::string& out, const Headers& headers, std::string& scratch);

private:
    struct Exchange;
    void append_request_params(std::string& out, Stream& s, const SiteConfig& site, const LocationConfig& loc,
                               WorkerState& ws, std::string_view path_info, std::uint64_t content_length,
                               bool length_known) const;
    void finish(Exchange& x, FcgiResult& r);
    void log_failure(const Exchange& x, const FcgiResult& r);

    const Config& cfg_;
    ErrorLog& log_;
};

}  // namespace agensio
