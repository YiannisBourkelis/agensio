// The control API (phase F): HTTP/1.1 + JSON on the control socket, answered inline on
// worker 0. Every command names the role it needs; the peer's role was decided at accept
// from its credentials (control/roles.hpp) and travels in ConnectionInfo. Mutating
// commands (F3) and refusals are written to the audit log, one line each.
#pragma once

#include <functional>
#include <memory>
#include <string_view>

#include "config.hpp"
#include "control/roles.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "services/json.hpp"
#include "services/log.hpp"

namespace agensio {

// What the server answers with; the handler never touches server internals itself.
struct ControlBackend {
    virtual ~ControlBackend() = default;
    virtual json::Value status() = 0;
    virtual json::Value sites() = 0;
    virtual json::Value site(std::string_view name, bool& found) = 0;
    virtual json::Value validate() = 0;
    virtual json::Value logs(std::string_view target) = 0;  // the request target with its query
    virtual json::Value health() = 0;
    // Mutations (F3). Each returns false with `error` when refused; nothing changed then.
    virtual bool reload_now(std::string& error) = 0;
    virtual bool renew_certificate(std::string_view site, std::string& error) = 0;
    virtual void reopen_logs() = 0;
    virtual const Config& running() = 0;
    virtual bool privileged() = 0;  // still root (before the drop): a reload can bind any port
    // The provisioning helper (F8): available when the server started as root with
    // [control] provision = true. `provision` sends one request and returns its reply.
    virtual bool provision_available() = 0;
    virtual json::Value provision(const json::Value& req) = 0;
    virtual void restart_later() = 0;  // after the current reply went out
};

class ControlHandler {
public:
    explicit ControlHandler(ErrorLog& log) : log_(log) {}
    void attach(ControlBackend* backend, LogRegistry* logs, int audit_sink) noexcept {
        backend_ = backend;
        logs_ = logs;
        audit_ = audit_sink;
    }

    // Reads the request body when there is one, answers, then runs `done` (inline when
    // nothing had to be read). The connection keeps itself alive across it.
    void start(Stream& s, WorkerState& ws, std::function<void()> done);
    // Answers s.request (ws.path is the normalised target) with the body in s.response.buffer.
    void handle(Stream& s, WorkerState& ws);

    // One audit line: who (uid, gid, role), what, and the outcome.
    void audit(long uid, long gid, Role role, std::string_view what, std::string_view result);

private:
    void reply(Stream& s, int status, const json::Value& body);
    bool require(Stream& s, Role needed, std::string_view command);
    void mutate(Stream& s, WorkerState& ws, std::string_view path);
    void site_create(Stream& s, const json::Value& body, std::string_view reason);
    void site_update(Stream& s, std::string_view name, const json::Value& body, std::string_view reason);
    void site_toggle(Stream& s, std::string_view name, std::string_view action, std::string_view reason);
    void audit_peer(const Stream& s, std::string_view what, std::string_view result);

    ErrorLog& log_;
    ControlBackend* backend_ = nullptr;
    LogRegistry* logs_ = nullptr;
    int audit_ = -1;
};

}  // namespace agensio
