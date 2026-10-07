#include "handlers/dispatch.hpp"

#include <cstdio>

#include "response.hpp"

#include "core/access.hpp"
#include "core/refuse.hpp"
#include "path.hpp"

namespace agensio {

namespace {

// The address an access rule judges: the client a trusted proxy forwarded, else the peer.
const asio::ip::address& client_ip(ConnectionInfo& c) {
    static const asio::ip::address none;  // a connection that cannot say (never in practice): matches no entry
    if (!c.client_address.empty()) return c.client_ip;
    return c.peer ? c.peer->peer_ip() : none;
}

}  // namespace

// [[site.access]] (core/access.hpp, docs/configuration.md 19). The address is asked for only
// when a rule covers some reading of the path, so a public page of a site with rules costs a
// bit test. One error-log line a second per worker, with the count of those not written.
bool Dispatcher::admit(Stream& s, const SiteConfig& site, std::string_view path, WorkerState& ws) {
    const asio::ip::address* addr = nullptr;
    auto address = [&]() -> const asio::ip::address& {
        if (!addr) addr = &client_ip(s.conn);
        return *addr;
    };
    const access::Decision d = access::decide(site, path, address, ws.access_scratch);
    if (!d.rule) return true;
    const std::string text = address().to_string();
    if (log_ && log_->enabled(LogLevel::warn)) {
        auto line = [&](std::string_view head) {
            std::string l(head);
            l.append(site.server_names.front()).append(" rule ").append(d.rule->path);
            if (d.rule->exact) l.append(" (exact)");
            l.append(" allows ");
            for (std::size_t i = 0; i < d.rule->allow_text.size(); ++i) l.append(i ? ", " : "").append(d.rule->allow_text[i]);
            l.append("; client ").append(text);
            if (!s.conn.client_address.empty() && s.conn.peer)
                l.append(" (from X-Forwarded-For; peer ").append(s.conn.peer->peer_ip().to_string()).append(")");
            l.append(" ").append(s.request.method_name).append(" ").append(path.substr(0, 200));
            return l;
        };
        WorkerState::AccessLog& al = ws.access_log;
        if (d.refuse()) {
            if (ws.now != al.refused_at) {
                std::string l = line("access refused: site ");
                if (al.refused_held) l.append(" (").append(std::to_string(al.refused_held)).append(" more refusals since the last such line, not written)");
                log_->warn(l);
                al.refused_at = ws.now;
                al.refused_held = 0;
            } else {
                ++al.refused_held;
            }
        } else {
            // Report mode: named once a minute per rule and client, at most 16 lines a second.
            const Cidr::Key key = Cidr::key_of(address());
            WorkerState::AccessLog::Seen* slot = nullptr;
            WorkerState::AccessLog::Seen* oldest = &al.seen[0];
            for (auto& e : al.seen) {
                if (e.rule == d.rule && e.client.v6 == key.v6 && e.client.hi == key.hi && e.client.lo == key.lo) slot = &e;
                if (e.at < oldest->at) oldest = &e;
            }
            if (slot && ws.now - slot->at < 60) {
                ++slot->repeats;
            } else {
                if (ws.now != al.report_second) {
                    al.report_second = ws.now;
                    al.report_in_second = 0;
                }
                if (al.report_in_second < 16) {
                    ++al.report_in_second;
                    std::string l = line("access would refuse: site ");
                    if (slot && slot->repeats)
                        l.append(" (").append(std::to_string(slot->repeats)).append(" more requests from this client since its last line)");
                    log_->warn(l);
                    if (!slot) slot = oldest;
                    slot->rule = d.rule;
                    slot->client = key;
                    slot->at = ws.now;
                    slot->repeats = 0;
                } else {
                    ++al.report_unnamed;
                }
            }
        }
    }
    if (!d.refuse()) return true;
    refuse_access(s, text);
    return false;
}

void Dispatcher::access_log_tick(WorkerState& ws, std::time_t now) {
    WorkerState::AccessLog& al = ws.access_log;
    if (!log_ || !log_->enabled(LogLevel::warn)) {
        al.refused_held = al.report_unnamed = 0;
        return;
    }
    if (al.refused_held && now != al.refused_at) {
        log_->warn("access refused: " + std::to_string(al.refused_held) +
                   " more refusals since the last such line, not written (the access log has each 403 with its client)");
        al.refused_held = 0;
        al.refused_at = now;
    }
    if (al.report_unnamed && now != al.report_second) {
        log_->warn("access would refuse: " + std::to_string(al.report_unnamed) +
                   " more requests in report mode since the last such line, not named (more than 16 new clients a second)");
        al.report_unnamed = 0;
    }
}

// 403 with the address that was tested, so a user whose address changed can say which one the
// server saw; never stored by a shared cache (it differs per client).
void Dispatcher::refuse_access(Stream& s, std::string_view address) {
    Response& r = s.response;
    r.reset();
    r.status = 403;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.buffer.assign("<!doctype html><html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center>"
                    "<p><center>This page is open to some addresses only. Yours, ");
    r.buffer.append(address).append(", is not one of them.</center></p><hr><center>agensio</center></body></html>\n");
    r.scratch.assign("Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: ");
    r.scratch.append(std::to_string(r.buffer.size())).append("\r\n");
    r.prebuilt_headers = r.scratch;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{std::string_view(r.buffer)};
}

// `redirect = "https"`: 301 to the same host and target over https. The host comes from
// the Host header without its port (the target listens on 443), or from the configured
// prefix; an HTTP/1.0 request without Host gets the site's first name.
void Dispatcher::redirect_https(Stream& s, const SiteConfig& site) {
    const Request& req = s.request;
    Response& r = s.response;
    std::string& location = r.scratch;
    if (site.redirect == "https") {
        std::string_view host = req.host;
        if (host.empty()) host = site.server_names.front();
        const std::size_t bracket = host.rfind(']');
        const std::size_t colon = host.rfind(':');
        if (colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket))
            host = host.substr(0, colon);
        if (host.empty() || host == "*") {
            static_.error(s, 400, false);
            return;
        }
        location.assign("https://").append(host);
    } else {
        location.assign(site.redirect);
    }
    if (!req.target.empty() && req.target.front() == '/') location.append(req.target);
    else location.push_back('/');
    const ErrorPage& page = error_page(301);
    r.status = 301;
    r.head = req.method == Method::head;
    r.headers.add("Location", location);
    r.prebuilt_headers = page.headers;
    r.prebuilt_h2 = page.h2_headers;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{page.body};
}

// 421 Misdirected Request (RFC 9110 15.5.22): this listener, or on TLS this connection's
// certificate, is not authoritative for the
// name in Host. Constant body, never cacheable, so a proxy or an HTTP/2 client that
// coalesced connections retries on a fresh connection instead of remembering a 404.
void Dispatcher::misdirected(Stream& s) {
    static_.error(s, 421, s.request.keep_alive);
    s.response.headers.add("Cache-Control", "no-store");
}

const LocationConfig* Dispatcher::route(Stream& s, const Router& router, WorkerState& ws) {
    const Request& req = s.request;
    Response& r = s.response;
    r.reset();
    r.keep_alive = req.keep_alive;

    // Bodies on requests nobody reads are drained by the connection after the response
    // (nginx behaviour); oversize bodies were already refused with 413 before we ran.
    if (req.version_minor == 1 && req.host.empty()) {
        static_.error(s, 400, false);
        return nullptr;
    }
    // On TLS the connection is authoritative only for the names of the certificate it
    // presented (RFC 9110 7.4, RFC 6125): a Host outside them is 421 whichever sites the
    // listener holds. A request without a Host (HTTP/1.0) claims no name and goes to the
    // catch-all as before. Plain listeners have no certificate and keep the listener rule.
    const bool unauthoritative = s.conn.cert && !req.host.empty() && !s.conn.cert->covers(req.host);
    if (req.method == Method::options && req.target == "*") {  // server-wide OPTIONS
        const SiteConfig* site = router.site(req.host);
        ws.site = site;
        if (!site || unauthoritative) {
            misdirected(s);
            return nullptr;
        }
        static_.no_content(s, Router::location(*site, "/").allow);
        return nullptr;
    }
    if (!normalize_target(req.target, ws.path, &ws.encoded_separator)) {
        static_.error(s, 400, false);
        return nullptr;
    }
#ifdef _WIN32
    if (!windows_path_ok(ws.path)) {
        static_.error(s, 400, false);
        return nullptr;
    }
#endif
    // ACME HTTP-01 (RFC 8555 section 8.3): the CA fetches the token over plain HTTP on any
    // host, so this runs before site routing and only for the challenge prefix.
    constexpr std::string_view kChallenge = "/.well-known/acme-challenge/";
    if (acme_ && ws.path.starts_with(kChallenge) && acme_->lookup(ws.path.substr(kChallenge.size()), r.buffer)) {
        ws.site = router.site(req.host);
        r.scratch = "Content-Type: text/plain\r\nContent-Length: " + std::to_string(r.buffer.size()) + "\r\n\r\n";
        r.prebuilt_headers = r.scratch;
        r.prebuilt_terminated = true;
        r.head = req.method == Method::head;
        r.body = MemoryBody{std::string_view(r.buffer)};
        return nullptr;
    }
    const SiteConfig* site = router.site(req.host);
    ws.site = site;
    if (!site || unauthoritative) {
        misdirected(s);
        return nullptr;
    }
    if (!site->redirect.empty()) {
        redirect_https(s, *site);
        return nullptr;
    }
    // `refuse` and [[site.access]] before any location is chosen: whichever would serve the
    // path (a .php suffix, a proxy) cannot step around them, nginx's regex-location trap. A
    // refused path is 404 for everyone, so it goes first: a restricted client learns nothing.
    if (!site->refuse.empty() && refuse::decide(site->refuse, ws.path, ws.access_scratch)) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    if (!site->access.empty() && !admit(s, *site, ws.path, ws)) return nullptr;
    const LocationConfig* loc = &Router::location(*site, ws.path);
    // A separator spelled as a percent escape (%2F, %5C) never names a file: 404 before any
    // handler that resolves paths on disk runs, Apache's AllowEncodedSlashes Off (2026-10-02
    // alpha.45 report: /x%2F..%2Fwp-login.php reached the script). A proxied application
    // gets the raw target as nginx hands it on, undecoded, and decides itself (GitLab's API
    // encodes group%2Fproject inside a path segment). One predictable test per request; the
    // site's encoded_slashes = "allow" (Apache's NoDecode, for a front controller that reads
    // REQUEST_URI) is read only once the escape was seen.
    if (ws.encoded_separator && loc->kind != HandlerKind::proxy && !site->encoded_slashes_allow) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    if (!check_method(s, *loc, ws)) return nullptr;
    // Endings refused before an application sees the request (a Rails site's databases,
    // logs and keys wherever they live): the static handler checks its own locations.
    if (loc->kind != HandlerKind::static_ && !loc->deny_suffixes.empty() && refused_suffix(ws.path, loc->deny_suffixes)) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    // Static locations answer OPTIONS themselves; an application (FastCGI) gets to see it.
    if (req.method == Method::options && loc->kind == HandlerKind::static_) {
        static_.no_content(s, loc->allow);
        return nullptr;
    }
    return loc;
}

bool Dispatcher::check_method(Stream& s, const LocationConfig& loc, WorkerState& ws) {
    const Request& req = s.request;
    // Methods are a per-location policy: what the handler implements, narrowed by `methods`.
    // TRACE and CONNECT are in no set, so they are always 405.
    ws.method_allowed = (loc.methods & method_bit(req.method)) != 0;
    if (ws.method_allowed) return true;
    const bool application_method = req.method == Method::post || req.method == Method::put ||
                                    req.method == Method::del || req.method == Method::patch;
    bool has_fallback = false;
    for (const TryStep& step : loc.try_files)
        if (step.kind == TryStep::Kind::fallback) has_fallback = true;
    if (loc.kind == HandlerKind::static_ && application_method && has_fallback) return true;
    // A method token nobody knows is syntactically valid, so it is a 405; but it is also
    // what a corrupted request line looks like, so the line is logged, escaped.
    if (req.method == Method::other && log_ && log_->enabled(LogLevel::warn)) {
        std::string line;
        for (unsigned char c : req.method_name) {
            if (c >= 0x20 && c < 0x7f && c != '\\') line.push_back(static_cast<char>(c));
            else { char h[5]; std::snprintf(h, sizeof h, "\\x%02x", c); line += h; }
        }
        log_->warn("unrecognised method '" + line + "' for " + std::string(req.target) + " from " + std::string(s.conn.remote_address) + " (405)");
    }
    static_.error(s, 405, req.keep_alive, loc.allow);
    return false;
}

const LocationConfig* Dispatcher::serve_static(Stream& s, const LocationConfig& loc, WorkerState& ws, int& hops) {
    if (static_.serve_location(s, loc, ws) == StaticHandler::Outcome::done) return nullptr;
    // try_files fallback: ws.path is the new target; route it again, bounded so two
    // locations pointing at each other cannot loop.
    if (++hops > StaticHandler::kMaxInternalRedirects) {
        static_.error(s, 500, s.request.keep_alive);
        return nullptr;
    }
    const auto* site = static_cast<const SiteConfig*>(ws.site);
    if (!site->refuse.empty() && refuse::decide(site->refuse, ws.path, ws.access_scratch)) {  // nor into a refused one
        static_.error(s, 404, s.request.keep_alive);
        return nullptr;
    }
    if (!site->access.empty() && !admit(s, *site, ws.path, ws)) return nullptr;  // a fallback cannot step into a restricted path
    const LocationConfig* next = &Router::location(*site, ws.path);
    if (!check_method(s, *next, ws)) return nullptr;
    return next;
}

}  // namespace agensio
