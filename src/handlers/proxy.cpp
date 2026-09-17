#include "handlers/proxy.hpp"

#include <charconv>

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

namespace {

// $host, $remote_addr, $scheme, $server_name, $server_port in a configured header value.
void expand(std::string& out, std::string_view value, const Stream& s) {
    std::size_t pos = 0;
    while (pos < value.size()) {
        const std::size_t dollar = value.find('$', pos);
        if (dollar == std::string_view::npos) {
            out.append(value.substr(pos));
            return;
        }
        out.append(value.substr(pos, dollar - pos));
        const std::string_view rest = value.substr(dollar);
        auto take = [&](std::string_view name, std::string_view replacement) {
            if (!rest.starts_with(name)) return false;
            out.append(replacement);
            pos = dollar + name.size();
            return true;
        };
        const std::string_view client = s.conn.client_address.empty() ? s.conn.remote_address : s.conn.client_address;
        const bool https = s.conn.tls || s.conn.forwarded_https;
        char port[8];
        const auto r = std::to_chars(port, port + sizeof port, s.conn.local_port);
        if (take("$host", s.request.host) || take("$remote_addr", client) || take("$scheme", https ? "https" : "http") ||
            take("$server_name", s.request.host) ||
            take("$server_port", std::string_view(port, static_cast<std::size_t>(r.ptr - port))))
            continue;
        out.push_back('$');
        pos = dollar + 1;
    }
}

// RFC 7239 "for=" needs IPv6 literals bracketed and quoted.
void forwarded_for(std::string& out, std::string_view addr) {
    if (addr.find(':') != std::string_view::npos) out.append("\"[").append(addr).append("]\"");
    else out.append(addr);
}

}  // namespace

bool ProxyHandler::build_head(std::string& out, const Stream& s, std::string_view target, const UpstreamConfig& policy) {
    const Request& req = s.request;
    out.append(req.method_name).append(" ").append(target).append(" HTTP/1.1\r\n");
    const std::string_view connection = req.headers.get("connection");
    // An Upgrade request (WebSocket): the Upgrade field goes through and the origin gets
    // "Connection: Upgrade"; a body cannot ride along.
    const std::string_view upgrade = req.headers.get("upgrade");
    const bool upgrading = policy.upgrade && !upgrade.empty() && !req.has_body &&
                           http::connection_lists(connection, "upgrade");
    if (upgrading) out.append("Upgrade: ").append(upgrade).append("\r\n");
    const bool trusted = s.conn.trusted_peer;
    const bool x_forwarded = policy.forwarded == "x-forwarded" || policy.forwarded == "both";
    const bool rfc_forwarded = policy.forwarded == "forwarded" || policy.forwarded == "both";
    auto configured = [&](std::string_view name) {
        for (const auto& h : policy.set_headers)
            if (Headers::iequals(h.first, name)) return true;
        return false;
    };
    std::string_view xff, xfh, forwarded;
    for (const HeaderField& h : req.headers) {
        if (http::is_hop_by_hop(h.name) || Headers::iequals(h.name, "expect") ||
            (!connection.empty() && http::connection_lists(connection, h.name)))
            continue;
        if (configured(h.name)) continue;  // set below from the configuration
        if (Headers::iequals(h.name, "host")) {
            if (policy.host == "pass") out.append("Host: ").append(h.value).append("\r\n");
            continue;
        }
        // The client's forwarding fields are believed only from a trusted proxy (then
        // appended to), never from the open internet (then replaced).
        if (Headers::iequals(h.name, "x-forwarded-for")) { if (trusted) xff = h.value; continue; }
        if (Headers::iequals(h.name, "x-forwarded-host")) { if (trusted) xfh = h.value; continue; }
        if (Headers::iequals(h.name, "x-forwarded-proto") || Headers::iequals(h.name, "x-forwarded-port")) continue;
        if (Headers::iequals(h.name, "forwarded")) { if (trusted) forwarded = h.value; continue; }
        out.append(h.name).append(": ").append(h.value).append("\r\n");
    }
    if (policy.host == "upstream") out.append("Host: ").append(policy.address.key).append("\r\n");
    else if (policy.host != "pass") out.append("Host: ").append(policy.host).append("\r\n");
    else if (req.headers.get("host").empty() && !req.host.empty()) out.append("Host: ").append(req.host).append("\r\n");
    const bool https = s.conn.tls || s.conn.forwarded_https;
    const std::string_view host = xfh.empty() ? req.host : xfh;
    if (x_forwarded) {
        out.append("X-Forwarded-For: ");
        if (!xff.empty()) out.append(xff).append(", ");
        out.append(s.conn.remote_address).append("\r\n");
        out.append("X-Forwarded-Proto: ").append(https ? "https" : "http").append("\r\n");
        if (!host.empty()) out.append("X-Forwarded-Host: ").append(host).append("\r\n");
    }
    if (rfc_forwarded) {
        out.append("Forwarded: ");
        if (!forwarded.empty()) out.append(forwarded).append(", ");
        out.append("for=");
        forwarded_for(out, s.conn.remote_address);
        out.append(";proto=").append(https ? "https" : "http");
        if (!host.empty()) out.append(";host=").append(host);
        out.append("\r\n");
    }
    for (const auto& h : policy.set_headers) {
        if (h.second.empty()) continue;  // "" removes
        out.append(h.first).append(": ");
        expand(out, h.second, s);
        out.append("\r\n");
    }
    return upgrading;
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
    const bool upgrading = build_head(ws.scratch, s, target, loc.proxy);
    x->req = std::make_shared<HttpRequest>(pool, loc.proxy.address, opts);
    // The head text is handed to the request as an owned string: collecting the body may
    // run the connection's reads inline, and ws.scratch belongs to whoever runs next.
    std::string head = ws.scratch;
    auto go = [this, x, retry_ok, upgrading, head = std::move(head)](bool ok) mutable {
        if (!ok) {  // the body could not be spooled: upstream_error already answered 502
            x->completed = true;
            x->done();
            return;
        }
        x->req->start(std::move(head), x->stream->request.method == Method::head, upgrading, std::move(x->body),
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
    apply_upstream_result(s, res, res.streamed ? x.req->body_source() : nullptr, "ok", loc);
    if (res.upgraded) {
        s.response.upgrade = true;
        s.response.tunnel_timeout_s = loc.proxy.tunnel_timeout_s;
        s.response.upstream = "upgrade";
    }
    x.completed = true;
    x.done();
}

}  // namespace agensio
