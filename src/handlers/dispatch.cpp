#include "handlers/dispatch.hpp"

#include "path.hpp"

namespace agensio {

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
    const SiteConfig* site = router.site(req.host);
    ws.site = site;
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
