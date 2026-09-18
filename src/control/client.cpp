#include "control/client.hpp"

#include <asio.hpp>

namespace agensio {

std::string default_control_socket() {
#ifdef __APPLE__
    return "/usr/local/var/run/agensio/control.sock";
#else
    return "/run/agensio/control.sock";
#endif
}

bool control_request(const std::string& socket_path, const std::string& method, const std::string& path,
                     const std::string& body, ControlReply& reply, std::string& error) {
#ifdef ASIO_HAS_LOCAL_SOCKETS
    try {
        asio::io_context io;
        asio::local::stream_protocol::socket sock(io);
        sock.connect(asio::local::stream_protocol::endpoint(socket_path));
        std::string req = method + " " + path + " HTTP/1.1\r\nHost: control\r\nConnection: close\r\n";
        if (!body.empty()) req += "Content-Type: application/json\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
        req += "\r\n" + body;
        asio::write(sock, asio::buffer(req));
        std::string raw;
        asio::error_code ec;
        char buf[8192];
        for (;;) {
            const std::size_t n = sock.read_some(asio::buffer(buf), ec);
            if (n) raw.append(buf, n);
            if (ec) break;
        }
        const std::size_t head_end = raw.find("\r\n\r\n");
        if (head_end == std::string::npos || raw.size() < 12) {
            error = "no HTTP reply from " + socket_path;
            return false;
        }
        reply.status = std::atoi(raw.substr(9, 3).c_str());
        reply.body = raw.substr(head_end + 4);
        return true;
    } catch (const std::exception& e) {
        error = std::string("control socket ") + socket_path + ": " + e.what();
        return false;
    }
#else
    (void)socket_path; (void)method; (void)path; (void)body; (void)reply;
    error = "the control socket needs unix domain sockets";
    return false;
#endif
}

}  // namespace agensio
