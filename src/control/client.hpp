// A blocking client for the control socket, used by `agensio ctl` and the MCP bridge:
// one request per connection, the reply read to EOF. Not part of the server's loops.
#pragma once

#include <string>

namespace agensio {

struct ControlReply {
    int status = 0;
    std::string body;
};

// False with `error` set when the socket cannot be reached or the reply is not HTTP.
bool control_request(const std::string& socket_path, const std::string& method, const std::string& path,
                     const std::string& body, ControlReply& reply, std::string& error);

// The platform's default socket path (what the server uses when [control] sets none).
std::string default_control_socket();

}  // namespace agensio
