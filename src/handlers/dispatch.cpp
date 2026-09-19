#include "handlers/dispatch.hpp"

#include "response.hpp"

#include "path.hpp"

namespace agensio {

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
    r.body = MemoryBody{page.body};
}

// 421 Misdirected Request (RFC 9110 15.5.22): this listener is not authoritative for the
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
    if (req.method == Method::options && req.target == "*") {  // server-wide OPTIONS
        const SiteConfig* site = router.site(req.host);
        ws.site = site;
        if (!site) {
            misdirected(s);
            return nullptr;
        }
        static_.no_content(s, Router::location(*site, "/").allow);
        return nullptr;
    }
    if (!normalize_target(req.target, ws.path)) {
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
    if (!site) {
        misdirected(s);
        return nullptr;
    }
    if (!site->redirect.empty()) {
        redirect_https(s, *site);
        return nullptr;
    }
    const LocationConfig* loc = &Router::location(*site, ws.path);
    if (!check_method(s, *loc, ws)) return nullptr;
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
    const LocationConfig* next = &Router::location(*site, ws.path);
    if (!check_method(s, *next, ws)) return nullptr;
    return next;
}

}  // namespace agensio
