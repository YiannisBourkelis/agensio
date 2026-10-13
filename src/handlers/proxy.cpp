#include "handlers/proxy.hpp"

#include <charconv>
#include <cstdint>

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

// The fields in which a client can name its own address to the application (2026-10-13, the
// review of applications' proxy guides). The application sees agensio's loopback address as its
// peer and believes such a field from there: Vaultwarden keys its login limits on X-Real-IP,
// Grafana and Rocket.Chat read it first; Umami reads True-Client-IP, CF-Connecting-IP,
// Fastly-Client-IP, X-NF-Client-Connection-IP, DO-Connecting-IP and X-AppEngine-User-IP before it
// (src/lib/ip.ts), Plausible X-Plausible-IP, CF-Connecting-IP and B-Forwarded-For (remote_ip.ex),
// Rails Client-IP (ActionDispatch::RemoteIp), the request-ip library the rest. X-Real-IP is
// agensio's own and written by build_head; the others are a CDN's, passed from a trusted proxy only.
enum class AddressClaim { none, real_ip, cdn };
struct ClaimField {
    std::string_view name;
    AddressClaim kind;
};
constexpr ClaimField kClaimFields[] = {
    {"x-real-ip", AddressClaim::real_ip},      {"client-ip", AddressClaim::cdn},          {"x-client-ip", AddressClaim::cdn},
    {"x-forwarded", AddressClaim::cdn},        {"forwarded-for", AddressClaim::cdn},      {"true-client-ip", AddressClaim::cdn},
    {"cf-pseudo-ipv4", AddressClaim::cdn},     {"x-plausible-ip", AddressClaim::cdn},     {"b-forwarded-for", AddressClaim::cdn},
    {"cf-connecting-ip", AddressClaim::cdn},   {"fastly-client-ip", AddressClaim::cdn},   {"do-connecting-ip", AddressClaim::cdn},
    {"cf-connecting-ipv6", AddressClaim::cdn}, {"x-cluster-client-ip", AddressClaim::cdn}, {"x-appengine-user-ip", AddressClaim::cdn},
    {"x-nf-client-connection-ip", AddressClaim::cdn},
};
constexpr std::uint32_t claim_lengths() {
    std::uint32_t mask = 0;
    for (const ClaimField& f : kClaimFields) mask |= 1u << f.name.size();
    return mask;
}
// The length first (a field of any other length costs one test), then the bytes against the few
// names of that length; a browser's fields of a matching length (Accept-Encoding, Sec-Fetch-Mode,
// Authorization) differ in their first bytes.
AddressClaim address_claim(std::string_view name) noexcept {
    constexpr std::uint32_t kLengths = claim_lengths();
    if (name.size() >= 32 || ((kLengths >> name.size()) & 1u) == 0) return AddressClaim::none;
    for (const ClaimField& f : kClaimFields)
        if (f.name.size() == name.size() && Headers::iequals(name, f.name)) return f.kind;
    return AddressClaim::none;
}

// RFC 7239 "for=" needs IPv6 literals bracketed and quoted.
void forwarded_for(std::string& out, std::string_view addr) {
    if (addr.find(':') != std::string_view::npos) out.append("\"[").append(addr).append("]\"");
    else out.append(addr);
}

}  // namespace

// Every value of a field the client sent on several lines, in order, each followed by ", "
// (RFC 9110 5.3: the lines are one comma-separated list).
static void append_lines(std::string& out, const Headers& headers, std::string_view name) {
    for (const HeaderField& f : headers)
        if (Headers::iequals(f.name, name) && !f.value.empty()) out.append(f.value).append(", ");
}

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
    std::string_view xfh;
    // A trusted proxy's chains are forwarded whole (below); a field the client listed in
    // Connection or the configuration sets itself never gets this far, so it is not.
    bool xff_lines = false, forwarded_lines = false;
    bool cookie_sent = false;
    for (const HeaderField& h : req.headers) {
        if (http::is_hop_by_hop(h.name) || Headers::iequals(h.name, "expect") ||
            (!connection.empty() && http::connection_lists(connection, h.name)))
            continue;
        // A field with '_' in its name never reaches the origin (alpha.73 report): Rack and Puma read
        // Client_IP as HTTP_CLIENT_IP (Rails' IpSpoofAttackError: a 500 on every page) and
        // X_Remote_User as the field forward_user writes, around the dashed names agensio guards.
        // FastCGI and CGI drop them too (FcgiHandler::append_http_params); nginx does by default
        // (underscores_in_headers off).
        if (h.name.find('_') != std::string_view::npos) continue;
        if (configured(h.name)) continue;  // set below from the configuration
        // One Cookie line for the origin, the crumbs in the order received (RFC 6265 5.4:
        // at most one Cookie field; Rack reads the first line only). HTTP/2 and HTTP/3 join
        // theirs at assembly (RFC 9113 8.2.3); this folds the second Cookie line an HTTP/1.1
        // client should not send but may (2026-09-27 report: Writebook's second cookie lost).
        if (h.name.size() == 6 && Headers::iequals(h.name, "cookie")) {
            if (cookie_sent) continue;
            cookie_sent = true;
            out.append(h.name).append(": ").append(h.value);
            for (const HeaderField* g = &h + 1; g != req.headers.end(); ++g)
                if (g->name.size() == 6 && Headers::iequals(g->name, "cookie")) out.append("; ").append(g->value);
            out.append("\r\n");
            continue;
        }
        if (Headers::iequals(h.name, "host")) {
            if (policy.host == "pass") out.append("Host: ").append(h.value).append("\r\n");
            continue;
        }
        // The client's forwarding fields are believed only from a trusted proxy (then
        // appended to), never from the open internet (then replaced).
        if (Headers::iequals(h.name, "x-forwarded-for")) { xff_lines = trusted; continue; }
        if (Headers::iequals(h.name, "x-forwarded-host")) { if (trusted) xfh = h.value; continue; }
        if (Headers::iequals(h.name, "x-forwarded-proto") || Headers::iequals(h.name, "x-forwarded-port")) continue;
        if (Headers::iequals(h.name, "forwarded")) { forwarded_lines = trusted; continue; }
        // A client naming its own address: X-Real-IP is written below, a CDN's field passes only
        // from a trusted proxy.
        if (const AddressClaim claim = address_claim(h.name);
            claim == AddressClaim::real_ip || (claim == AddressClaim::cdn && !trusted))
            continue;
        out.append(h.name).append(": ").append(h.value).append("\r\n");
    }
    // A field the configuration sets replaces agensio's own line of that name: written once, below
    // (before alpha.71 both went, two Host fields among them, which RFC 9112 7.2 makes a 400).
    if (!configured("host")) {
        if (policy.host == "upstream") out.append("Host: ").append(policy.address.authority()).append("\r\n");  // never the scheme
        else if (policy.host != "pass") out.append("Host: ").append(policy.host).append("\r\n");
        else if (req.headers.get("host").empty() && !req.host.empty()) out.append("Host: ").append(req.host).append("\r\n");
    }
    const bool https = s.conn.tls || s.conn.forwarded_https;
    const std::string_view host = xfh.empty() ? req.host : xfh;
    if (x_forwarded) {
        // A trusted proxy's chain goes on whole: every line in order, then the peer (until
        // 2026-10-07 only the last line, which dropped the hops of a proxy that adds one).
        if (!configured("x-forwarded-for")) {
            out.append("X-Forwarded-For: ");
            if (xff_lines) append_lines(out, req.headers, "x-forwarded-for");
            out.append(s.conn.remote_address).append("\r\n");
        }
        if (!configured("x-forwarded-proto")) out.append("X-Forwarded-Proto: ").append(https ? "https" : "http").append("\r\n");
        // Host passed through already tells the origin what the client asked for; the
        // field is only worth its bytes when Host was rewritten or a proxy in front set it
        // (a Node origin measured 3 % more req/s per field it does not have to parse).
        if (!host.empty() && (policy.host != "pass" || !xfh.empty()) && !configured("x-forwarded-host"))
            out.append("X-Forwarded-Host: ").append(host).append("\r\n");
    }
    if (rfc_forwarded && !configured("forwarded")) {
        out.append("Forwarded: ");
        if (forwarded_lines) append_lines(out, req.headers, "forwarded");
        out.append("for=");
        forwarded_for(out, s.conn.remote_address);
        out.append(";proto=").append(https ? "https" : "http");
        if (!host.empty()) out.append(";host=").append(host);
        out.append("\r\n");
    }
    // X-Real-IP: the client this server believes, the address of its own logs and access rules
    // (nginx's `proxy_set_header X-Real-IP $remote_addr`, which 17 of 25 applications' proxy guides
    // set). A client's copy was dropped above; with forwarded = "off" the origin learns no address.
    if (policy.forwarded != "off" && !configured("x-real-ip"))
        out.append("X-Real-IP: ").append(s.conn.client_address.empty() ? s.conn.remote_address : s.conn.client_address).append("\r\n");
    // [[site.auth]]'s forward_user: the verified name, in a field the client's own copy of was removed.
    if (!s.auth.forward_field.empty() && !s.auth.user.empty() && !configured(s.auth.forward_field))
        out.append(s.auth.forward_field).append(": ").append(s.auth.user).append("\r\n");
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
    x->req = std::make_shared<HttpRequest>(pool, loc.proxy.addresses, opts, &loc.proxy.tls);
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
        const std::string& origin = x.req->address().key;
        std::string msg = "proxy " + origin + " " + to_string(res.failure) + " for " +
                          std::string(s.request.method_name) + " " + std::string(s.request.target);
        if (res.error) msg += " (" + res.error.message() + ")";
        switch (res.failure) {
            case UpstreamFailure::connect_refused: msg += ": nothing is listening on " + origin; break;
            case UpstreamFailure::closed_early:
                msg += res.head_bytes == 0 ? ": the origin closed the connection before answering"
                                           : ": the origin closed the connection mid-response";
                break;
            case UpstreamFailure::read_timeout:
                msg += ": no bytes from the origin for " + std::to_string(loc.proxy.options.read_timeout.count() / 1000) +
                       " s (proxy.read_timeout)";
                break;
            case UpstreamFailure::tls_error:
                msg += ": TLS handshake or certificate verification failed (proxy.tls: verify, server_name, ca)";
                if (loc.proxy.tls.verify && loc.proxy.tls.server_name.empty())
                    msg += "; without server_name the certificate must name " + x.req->address().host +
                           ": set proxy.tls.server_name to the name it carries";
                break;
            default: break;
        }
        if (!x.req->health_note().empty()) msg += "; " + x.req->health_note();
        log_.error(msg);
        const int status = status_for(res.failure);
        upstream_error(s, status, status == 503 ? std::string_view(loc.proxy.retry_after) : std::string_view());
        s.response.upstream = to_string(res.failure);
        x.completed = true;
        x.done();
        return;
    }
    if (!x.req->health_note().empty()) log_.warn("proxy " + x.req->health_note());  // a member down or back
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
