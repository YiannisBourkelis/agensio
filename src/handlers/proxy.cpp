#include "handlers/proxy.hpp"

#include "handlers/upstream_common.hpp"
#include "upstream/http_head.hpp"

namespace agensio {

struct ProxyHandler::Exchange : std::enable_shared_from_this<Exchange> {
    Stream* stream = nullptr;
    const LocationConfig* loc = nullptr;
    UpstreamPool* pool = nullptr;
    std::function<void()> done;
    UpstreamBodyInput body;
    std::vector<char> chunk;  // body read scratch
    std::shared_ptr<HttpRequest> req;
    bool completed = false;
};

void ProxyHandler::build_head(std::string& out, const Stream& s, std::string_view target) {
    const Request& req = s.request;
    out.append(req.method_name).append(" ").append(target).append(" HTTP/1.1\r\n");
    const std::string_view connection = req.headers.get("connection");
    bool saw_xff = false, saw_host = false;
    for (const HeaderField& h : req.headers) {
        if (http::is_hop_by_hop(h.name) || Headers::iequals(h.name, "expect") ||
            (!connection.empty() && http::connection_lists(connection, h.name)))
            continue;
        if (Headers::iequals(h.name, "x-forwarded-for")) {
            saw_xff = true;
            out.append("X-Forwarded-For: ").append(h.value).append(", ").append(s.conn.remote_address).append("\r\n");
            continue;
        }
        if (Headers::iequals(h.name, "x-forwarded-proto") || Headers::iequals(h.name, "x-forwarded-host")) continue;
        if (Headers::iequals(h.name, "host")) saw_host = true;
        out.append(h.name).append(": ").append(h.value).append("\r\n");
    }
    if (!saw_host) out.append("Host: ").append(req.host).append("\r\n");
    if (!saw_xff) out.append("X-Forwarded-For: ").append(s.conn.remote_address).append("\r\n");
    out.append("X-Forwarded-Proto: ").append(s.conn.tls || s.conn.forwarded_https ? "https" : "http").append("\r\n");
    if (!req.host.empty()) out.append("X-Forwarded-Host: ").append(req.host).append("\r\n");
}

std::shared_ptr<UpstreamRequest> ProxyHandler::start(Stream& s, const LocationConfig& loc, WorkerState& ws,
                                                     UpstreamPool& pool, std::function<void()> done) {
    auto x = std::make_shared<Exchange>();
    x->stream = &s;
    x->loc = &loc;
    x->pool = &pool;
    x->done = std::move(done);
    const UpstreamOptions& opts = loc.proxy.options;
    const Request& req = s.request;
    const bool retry_ok = req.method == Method::get || req.method == Method::head;
    ws.scratch.clear();
    std::string_view target = req.target;
    std::string rewritten;
    if (!loc.proxy.rewrite.empty()) {
        // The location's prefix becomes the upstream's URI; the raw target when it carries
        // the prefix as matched, else the normalised path (with the query re-attached).
        const std::string_view query = target.substr(std::min(target.size(), target.find('?')));
        const std::string_view rest = target.starts_with(loc.path)
                                          ? target.substr(loc.path.size())
                                          : std::string_view(ws.path).substr(std::min(ws.path.size(), loc.path.size()));
        rewritten.reserve(loc.proxy.rewrite.size() + rest.size() + query.size());
        rewritten.append(loc.proxy.rewrite).append(rest);
        if (!target.starts_with(loc.path)) rewritten.append(query);
        target = rewritten;
    }
    build_head(ws.scratch, s, target);
    x->req = std::make_shared<HttpRequest>(pool, loc.proxy.address, opts);
    // The head text is handed to the request as an owned string: collecting the body may
    // run the connection's reads inline, and ws.scratch belongs to whoever runs next.
    std::string head = ws.scratch;
    auto go = [this, x, retry_ok, head = std::move(head)](bool ok) mutable {
        if (!ok) {  // the body could not be spooled: upstream_error already answered 502
            x->completed = true;
            x->done();
            return;
        }
        x->req->start(std::move(head), x->stream->request.method == Method::head, std::move(x->body),
                      x->loc->priority, retry_ok, [this, x](UpstreamResult& r) { finish(*x, r); });
    };
    if (!req.has_body || !req.body) {
        go(true);
        return x->completed ? nullptr : x->req;
    }
    if (!opts.request_buffering) {  // stream the body to the origin as it arrives
        x->body.stream = req.body;
        std::uint64_t declared = 0;
        x->body.size_known = req.body->length(declared);
        x->body.size = declared;
        go(true);
        return x->completed ? nullptr : x->req;
    }
    collect_request_body(s, x->body, opts.request_buffer_max, x->chunk, x, std::move(go));
    return x->completed ? nullptr : x->req;  // the body may have been buffered already: go ran inline
}

void ProxyHandler::finish(Exchange& x, UpstreamResult& res) {
    Stream& s = *x.stream;
    const LocationConfig& loc = *x.loc;
    if (res.failure != UpstreamFailure::none) {
        std::string msg = "proxy " + loc.proxy.address.key + " " + to_string(res.failure) + " for " +
                          std::string(s.request.method_name) + " " + std::string(s.request.target);
        if (res.error) msg += " (" + res.error.message() + ")";
        switch (res.failure) {
            case UpstreamFailure::connect_refused: msg += ": nothing is listening on " + loc.proxy.address.key; break;
            case UpstreamFailure::closed_early:
                msg += res.head_bytes == 0 ? ": the origin closed the connection before answering"
                                           : ": the origin closed the connection mid-response";
                break;
            case UpstreamFailure::read_timeout:
                msg += ": no bytes from the origin for " + std::to_string(loc.proxy.options.read_timeout.count() / 1000) +
                       " s (proxy.read_timeout)";
                break;
            default: break;
        }
        log_.error(msg);
        const int status = status_for(res.failure);
        upstream_error(s, status, status == 503 ? std::string_view(loc.proxy.retry_after) : std::string_view());
        s.response.upstream = to_string(res.failure);
        x.completed = true;
        x.done();
        return;
    }
    apply_upstream_result(s, res, res.streamed ? x.req->body_source() : nullptr, "ok");
    x.completed = true;
    x.done();
}

}  // namespace agensio
