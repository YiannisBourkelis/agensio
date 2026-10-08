// One request/response exchange. HTTP/1 embeds exactly one Stream in its connection;
// HTTP/2 and HTTP/3 own one per stream id. Handlers see only this.
#pragma once

#include <string>

#include <cstdint>
#include <string_view>

#include <asio/ip/address.hpp>

#include "core/host.hpp"
#include "core/request.hpp"
#include "core/response.hpp"

namespace agensio {

// The connection's peer, parsed, asked for on first need: an access rule of the site
// (core/access.hpp, 2026-10-07). HTTP/1 reads it from the socket then, once per connection,
// and never for a connection whose requests need nothing else; HTTP/2 and HTTP/3 hold it.
class PeerSource {
public:
    virtual const asio::ip::address& peer_ip() = 0;

protected:
    ~PeerSource() = default;
};

// What the transport knows and application handlers need (FastCGI params, proxy
// headers). Set once per connection; the views point at connection-owned strings.
// A connection's last verified login ([[site.auth]]): the exact Authorization value, the user
// file load it was checked against (an id, never an address a later load could reuse), the user
// and until when. A browser on a kept-alive connection then costs one comparison per request.
struct AuthMemo {
    std::string value;
    std::uint64_t users_id = 0;
    std::string user;
    std::int64_t until = 0;
};

struct ConnectionInfo {
    std::string_view remote_address;
    std::uint16_t remote_port = 0;
    std::string_view local_address;
    std::uint16_t local_port = 0;
    bool tls = false;
    // Per request, from a trusted proxy's X-Forwarded-For / X-Forwarded-Proto (else empty/false).
    std::string_view client_address;
    asio::ip::address client_ip;  // client_address parsed (set with it)
    bool forwarded_https = false;
    bool trusted_peer = false;  // the peer is one of server.trusted_proxies
    PeerSource* peer = nullptr;  // the connection, for the peer's parsed address (never owning)
    // TLS: the names of the certificate this connection presented at its handshake (null on
    // plain listeners). A request whose Host it does not cover is 421: the connection is
    // not authoritative for that name, whatever sites the listener holds.
    const CertNames* cert = nullptr;
    // Control socket only: the peer's credentials and role (control/roles.hpp), set at accept.
    long peer_uid = -1;
    long peer_gid = -1;
    std::uint8_t role = 0;
    AuthMemo* auth_memo = nullptr;  // the connection's own (never owning); null: none kept
};

// What a password check ([[site.auth]], design section 25) decided for this request: the
// verified user (the access log's user field, REMOTE_USER), whether the answer is one a password
// protects (Cache-Control: private), and the result of a verification the pool ran for it.
struct AuthState {
    enum class Result : std::uint8_t { none, verified, failed, busy };  // busy: the pool was full (503)
    Result result = Result::none;
    bool protected_path = false;  // a rule asked for a password (or skip_for let the client in)
    std::string user;             // the verified name; empty otherwise
    std::string forward_field;    // forward_user of the rule, for a proxy location
    void reset() {
        result = Result::none;
        protected_path = false;
        user.clear();
        forward_field.clear();
    }
};

struct Stream {
    Request request;
    Response response;
    ConnectionInfo conn;  // not reset between requests
    AuthState auth;

    void reset() {
        request.reset();
        response.reset();
        auth.reset();
    }
};

}  // namespace agensio
