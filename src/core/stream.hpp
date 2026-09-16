// One request/response exchange. HTTP/1 embeds exactly one Stream in its connection;
// HTTP/2 and HTTP/3 own one per stream id. Handlers see only this.
#pragma once

#include "core/request.hpp"
#include "core/response.hpp"

namespace agensio {

struct Stream {
    Request request;
    Response response;

    void reset() {
        request.reset();
        response.reset();
    }
};

}  // namespace agensio
