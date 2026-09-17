// Request dispatch: the prologue every request goes through (validation, routing to a
// site and a location, the method policy) and the static hop. The connection drives the
// loop because a location's handler may finish asynchronously (FastCGI) while try_files
// fallbacks re-enter the router: static -> fallback -> static or fastcgi.
#pragma once

#include "config.hpp"
#include "core/router.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/proxy.hpp"
#include "handlers/static.hpp"

namespace agensio {

class Dispatcher {
public:
    Dispatcher(StaticHandler& static_handler, FcgiHandler& fcgi, ProxyHandler& proxy)
        : static_(static_handler), fcgi_(fcgi), proxy_(proxy) {}

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

    StaticHandler& static_;
    FcgiHandler& fcgi_;
    ProxyHandler& proxy_;
};

}  // namespace agensio
