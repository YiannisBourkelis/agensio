#include "control/handler.hpp"

#include <ctime>

#include "core/body.hpp"

namespace agensio {

void ControlHandler::reply(Stream& s, int status, const json::Value& body) {
    Response& r = s.response;
    r.status = status;
    r.buffer = body.dump();
    r.buffer.push_back('\n');
    r.scratch = "Content-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: " +
                std::to_string(r.buffer.size()) + "\r\n\r\n";
    r.prebuilt_headers = r.scratch;
    r.prebuilt_terminated = true;
    r.head = s.request.method == Method::head;
    r.body = MemoryBody{std::string_view(r.buffer)};
}

bool ControlHandler::require(Stream& s, Role needed, std::string_view command) {
    const Role role = static_cast<Role>(s.conn.role);
    if (role >= needed) return true;
    audit(s.conn.peer_uid, s.conn.peer_gid, role, command, "forbidden");
    reply(s, 403, json::Value::object().set("error", "forbidden").set("role", std::string(role_name(role)))
                      .set("needs", std::string(role_name(needed))));
    return false;
}

void ControlHandler::audit(long uid, long gid, Role role, std::string_view what, std::string_view result) {
    if (!logs_ || audit_ < 0) return;
    std::tm tm{};
    const std::time_t now = std::time(nullptr);
    ::localtime_r(&now, &tm);
    char stamp[32];
    const std::size_t n = std::strftime(stamp, sizeof stamp, "%Y/%m/%d %H:%M:%S", &tm);
    std::string line(stamp, n);
    line += " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid) + " role=" + std::string(role_name(role)) +
            " " + std::string(what) + ": " + std::string(result) + "\n";
    logs_->sink(audit_).write(line);
}

void ControlHandler::handle(Stream& s, WorkerState& ws) {
    const Request& req = s.request;
    const std::string_view path = ws.path;
    // The read commands (F2): every one is a GET, every one needs the viewer role.
    const bool read_command = path == "/v1/status" || path == "/v1/sites" || path.starts_with("/v1/sites/") ||
                              path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health";
    if (!read_command) {
        reply(s, 404, json::Value::object().set("error", "unknown command").set("path", std::string(path)));
        return;
    }
    if (req.method != Method::get && req.method != Method::head) {
        s.response.headers.add("Allow", "GET, HEAD");
        reply(s, 405, json::Value::object().set("error", "method not allowed"));
        return;
    }
    if (!require(s, Role::viewer, path.substr(4))) return;
    if (!backend_) {
        reply(s, 503, json::Value::object().set("error", "no backend"));
        return;
    }
    if (path == "/v1/status") {
        json::Value body = backend_->status();
        body.set("peer", json::Value::object()
                             .set("uid", static_cast<double>(s.conn.peer_uid))
                             .set("gid", static_cast<double>(s.conn.peer_gid))
                             .set("role", std::string(role_name(static_cast<Role>(s.conn.role)))));
        reply(s, 200, body);
    } else if (path == "/v1/sites") {
        reply(s, 200, backend_->sites());
    } else if (path.starts_with("/v1/sites/")) {
        bool found = false;
        json::Value body = backend_->site(path.substr(10), found);
        if (found) reply(s, 200, body);
        else reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(path.substr(10))));
    } else if (path == "/v1/config/validate") {
        reply(s, 200, backend_->validate());
    } else if (path == "/v1/logs") {
        reply(s, 200, backend_->logs(req.target));
    } else {
        reply(s, 200, backend_->health());
    }
}

}  // namespace agensio
