#include "control/client.hpp"

#include <cctype>
#include <cstdlib>
#include <string>
#include <string_view>
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
        if (!body.empty())
            req += std::string("Content-Type: ") + (method == "PUT" ? "application/octet-stream" : "application/json") +
                   "\r\nContent-Length: " + std::to_string(body.size()) + "\r\n";
        req += "\r\n" + body;
        asio::error_code ec;
        asio::write(sock, asio::buffer(req), ec);  // a refusal (413) may arrive before the body is out: read on
        std::string raw;
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
        reply.version.clear();
        for (std::size_t pos = raw.find("\r\n"); pos != std::string::npos && pos < head_end;) {
            const std::size_t next = raw.find("\r\n", pos + 2);
            const std::string line = raw.substr(pos + 2, (next == std::string::npos ? head_end : next) - pos - 2);
            static constexpr std::string_view kName = "x-agensio-version:";
            if (line.size() > kName.size()) {
                std::string lower = line.substr(0, kName.size());
                for (char& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                if (lower == kName) {
                    std::size_t b = kName.size();
                    while (b < line.size() && line[b] == ' ') ++b;
                    reply.version = line.substr(b);
                }
            }
            pos = next;
        }
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
