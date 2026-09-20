// Request dispatch: the prologue every request goes through (validation, routing to a
// site and a location, the method policy) and the static hop. The connection drives the
// loop because a location's handler may finish asynchronously (FastCGI) while try_files
// fallbacks re-enter the router: static -> fallback -> static or fastcgi.
#pragma once

#include "config.hpp"
#include "core/router.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "handlers/cgi.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/proxy.hpp"
#include "handlers/static.hpp"
#include "services/log.hpp"
#include "control/handler.hpp"
#include "services/acme.hpp"

namespace agensio {

class Dispatcher {
public:
    Dispatcher(StaticHandler& static_handler, FcgiHandler& fcgi, ProxyHandler& proxy, CgiHandler& cgi,
               ControlHandler& control)
        : static_(static_handler), fcgi_(fcgi), proxy_(proxy), cgi_(cgi), control_(control) {}
    CgiHandler& cgi() noexcept { return cgi_; }
    ControlHandler& control() noexcept { return control_; }
    // HTTP-01: /.well-known/acme-challenge/<token> is answered from here before routing.
    void set_acme(AcmeChallenges* challenges) noexcept { acme_ = challenges; }
    void set_error_log(ErrorLog* log) noexcept { log_ = log; }
    ErrorLog* error_log() const noexcept { return log_; }

    StaticHandler& static_handler() noexcept { return static_; }
    FcgiHandler& fcgi() noexcept { return fcgi_; }
    ProxyHandler& proxy() noexcept { return proxy_; }

    // Validates the request, resolves site (ws.site) and location, applies the location's
    // method policy and answers OPTIONS for static locations. Returns nullptr when
    // s.response is already the answer, else the location to serve (ws.path normalised).
    const LocationConfig* route(Stream& s, const Router& router, WorkerState& ws);

    // One static hop. Returns nullptr when s.response is ready, or the location a
    // try_files fallback routed to (ws.path is the new target). `hops` bounds the chain.
    const LocationConfig* serve_static(Stream& s, const LocationConfig& loc, WorkerState& ws, int& hops);

private:
    // Applies loc's method policy. False when a 405 was produced. A method the static
    // handler cannot serve is let through when the location's try_files has a fallback,
    // so a POST to a Laravel route reaches /index.php as nginx would route it; the static
    // handler then answers 405 only if the request resolves to an actual file.
    bool check_method(Stream& s, const LocationConfig& loc, WorkerState& ws);
    void redirect_https(Stream& s, const SiteConfig& site);
    void misdirected(Stream& s);

    StaticHandler& static_;
    FcgiHandler& fcgi_;
    ProxyHandler& proxy_;
    CgiHandler& cgi_;
    ControlHandler& control_;
    AcmeChallenges* acme_ = nullptr;
    ErrorLog* log_ = nullptr;
};

}  // namespace agensio
