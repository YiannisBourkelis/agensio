// One request/response exchange. HTTP/1 embeds exactly one Stream in its connection;
// HTTP/2 and HTTP/3 own one per stream id. Handlers see only this.
#pragma once

#include <cstdint>
#include <string_view>

#include "core/host.hpp"
#include "core/request.hpp"
#include "core/response.hpp"

namespace agensio {

// What the transport knows and application handlers need (FastCGI params, proxy
// headers). Set once per connection; the views point at connection-owned strings.
struct ConnectionInfo {
    std::string_view remote_address;
    std::uint16_t remote_port = 0;
    std::string_view local_address;
    std::uint16_t local_port = 0;
    bool tls = false;
    // Per request, from a trusted proxy's X-Forwarded-For / X-Forwarded-Proto (else empty/false).
    std::string_view client_address;
    bool forwarded_https = false;
    bool trusted_peer = false;  // the peer is one of server.trusted_proxies
    // TLS: the names of the certificate this connection presented at its handshake (null on
    // plain listeners). A request whose Host it does not cover is 421: the connection is
    // not authoritative for that name, whatever sites the listener holds.
    const CertNames* cert = nullptr;
    // Control socket only: the peer's credentials and role (control/roles.hpp), set at accept.
    long peer_uid = -1;
    long peer_gid = -1;
    std::uint8_t role = 0;
};

struct Stream {
    Request request;
    Response response;
    ConnectionInfo conn;  // not reset between requests

    void reset() {
        request.reset();
        response.reset();
    }
};

}  // namespace agensio
