// One request/response exchange. HTTP/1 embeds exactly one Stream in its connection;
// HTTP/2 and HTTP/3 own one per stream id. Handlers see only this.
#pragma once

#include <cstdint>
#include <string_view>

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
