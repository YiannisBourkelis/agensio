// The control API (phase F): HTTP/1.1 + JSON on the control socket, answered inline on
// worker 0. Every command names the role it needs; the peer's role was decided at accept
// from its credentials (control/roles.hpp) and travels in ConnectionInfo. Mutating
// commands (F3) and refusals are written to the audit log, one line each.
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "config.hpp"
#include "control/roles.hpp"
#include "control/sites.hpp"
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
    // `must_load`: the site file the change wrote; the reload is refused if that file would be
    // set aside (docs/design-site-operations.md 26), so a change is never reported done for a
    // site that is not served. Other files set aside keep their last good version.
    virtual bool reload_now(std::string& error, std::string_view must_load = {}) = 0;
    // An automatic certificate: an order started (`message` says so). A site with its own files
    // (step T3): they are loaded now, `message` saying what happened; false when they could not be.
    virtual bool renew_certificate(std::string_view site, std::string& error, std::string& message) = 0;
    virtual void reopen_logs() = 0;
    virtual const Config& running() = 0;
    // The restart-only keys the running configuration has other values for than the server
    // started with (control::restart_needed): kept until a restart.
    virtual std::vector<std::string> restart_pending() = 0;
    virtual bool privileged() = 0;  // still root (before the drop): a reload can bind any port
    // The provisioning helper (F8): available when the server started as root with
    // [control] provision = true. `provision` sends one request and returns its reply.
    virtual bool provision_available() = 0;
    virtual json::Value provision(const json::Value& req) = 0;
    virtual void restart_later() = 0;  // after the current reply went out
    // site-install and site-copy (F9): run off the worker (a download can take minutes) and
    // call `done` on worker 0 with the result. Through the helper as the site's account
    // when there is one, else on a thread of this process as its own account. `req.op`
    // "file_copy" selects the copy; anything else is an install.
    virtual void install_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
    virtual std::string uploads_dir() = 0;  // "" when uploads are not possible (no state directory)
    // A site task (F13): off the worker, `done` on worker 0. Through the helper as the site's
    // account (the helper takes the site's name, the task and its parameters, and derives
    // the rest from the configuration on disk), else on a thread as this process's account
    // with the request's root, app and secrets.
    virtual void task_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
    // A site's application environment (services/appenv.*): req.op "env_read" or "env_write"
    // with the site's first host name and the change. Off the worker (the helper may be busy
    // with a task for minutes), `done` on worker 0. Through the helper, whose files are
    // root's, else as this process's own account in its own directory.
    virtual void env_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
    // A managed site's password users (services/authusers.*, 2026-10-09): req.op "auth_users_read"
    // or "auth_users_write" with the site's first host name and, for a write, the change. Off the
    // worker (hashing a generated password takes tens of milliseconds, the helper may be busy with
    // a task), `done` on worker 0. Through the helper, whose files are root's with the server's
    // group, else as this process's own account in its own directory.
    virtual void auth_users_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
    // Whether a site has an environment file: 1 yes, 0 no, -1 unknown (the helper is busy
    // with a task; it is never waited for). Milliseconds, on worker 0.
    // `exposed` receives the names in it that others could read and nobody rotated.
    virtual int env_file_state(std::string_view site, std::vector<std::string>& exposed) = 0;
    // One read-only helper request (app_status, app_logs) off the worker, `done` on worker 0;
    // never waited for while a task holds the helper ({"busy": true} then). Without the
    // helper: {"ok": false, "error"}.
    virtual void helper_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
    // One helper request that waits its turn (the trash operations of F12b: a rename, a
    // removal of a tree, a listing), off the worker, `done` on worker 0. Without the helper:
    // {"ok": false, "error"}.
    virtual void provision_async(const json::Value& req, std::function<void(json::Value)> done) = 0;
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
    // nothing had to be read). The connection keeps itself alive across it. A PUT to
    // /v1/uploads/NAME streams its body to a file instead of memory; a site install
    // finishes later, on the callback the backend runs.
    void start(Stream& s, WorkerState& ws, std::function<void()> done);
    // Answers s.request (ws.path is the normalised target) with the body in s.response.buffer.
    void handle(Stream& s, WorkerState& ws);
    // True when the reply is deferred and `done` will be run later (site install).
    bool handle_deferred(Stream& s, WorkerState& ws, std::function<void()>& done);

    // One audit line: who (uid, gid, role), what, and the outcome.
    void audit(long uid, long gid, Role role, std::string_view what, std::string_view result);

private:
    void reply(Stream& s, int status, const json::Value& body);
    bool require(Stream& s, Role needed, std::string_view command);
    bool mutate(Stream& s, WorkerState& ws, std::string_view path, std::function<void()>& done);
    void site_create(Stream& s, const json::Value& body, std::string_view reason);
    void site_update(Stream& s, std::string_view name, const json::Value& body, std::string_view reason);
    void site_toggle(Stream& s, std::string_view name, std::string_view action, std::string_view reason);
    void site_install(Stream& s, std::string_view name, const json::Value& body, std::string_view reason, std::function<void()> done);
    void site_copy(Stream& s, std::string_view name, const json::Value& body, std::string_view reason, std::function<void()> done);
    void site_task(Stream& s, std::string_view name, const json::Value& body, std::string_view reason, std::function<void()> done);
    void site_env_show(Stream& s, std::string_view name, std::function<void()> done);
    // A Rails site's application service: its unit's state (viewer) or its journal (admin,
    // audited), through the helper's app_status / app_logs.
    void site_service(Stream& s, std::string_view name, bool logs, std::function<void()> done);
    // The trash (F12b): a site deleted with its files, the entries, a restore, a removal.
    void site_trash(Stream& s, std::string_view name, std::string_view what, std::function<void()> done);
    void trash_list(Stream& s, std::function<void()> done);
    // Host protection (docs/configuration.md 18): the ruleset and the jails rendered for this
    // host, and what the kernel's firewall and fail2ban do now, through the helper's
    // host_protection (read-only).
    void protection_show(Stream& s, std::function<void()> done);
    // After a change to the sites: the root lines that bring the installed host protection
    // back in step with them (the fail2ban jail file, the kept ruleset), empty when nothing
    // is installed or nothing changed for them.
    std::vector<std::string> protection_steps();
    void trash_restore(Stream& s, std::string_view entry, std::string_view what, std::function<void()> done);
    void trash_delete(Stream& s, std::string_view entry, std::string_view what, std::function<void()> done);
    void site_env_set(Stream& s, std::string_view name, const json::Value& body, std::string_view reason, std::function<void()> done);
    // A managed site's password users (2026-10-09, design section 25, step 4b): the listing (names,
    // methods, expiry, notes, locks, never a hash) and one user's change or removal, admin only,
    // audited by user name; a change the running configuration reads reloads it.
    void site_auth_users(Stream& s, std::string_view name, std::function<void()> done);
    void site_auth_user_change(Stream& s, std::string_view name, const json::Value& body, bool remove, std::string_view reason, std::function<void()> done);
    void upload_receive(Stream& s, std::string_view name, std::function<void()> done);
    json::Value uploads_list();
    // The php-fpm pool after a site file changed: through the helper when there is one
    // (reported under `done`), else as next steps. Shared by create and update.
    void finish_pool(Stream& s, const control::SiteSpec& spec, const Config& cfg, std::string_view what, json::Value& done, std::vector<std::string>& steps);
    void upload_delete(Stream& s, std::string_view name, std::string_view reason);
    void audit_peer(const Stream& s, std::string_view what, std::string_view result);
    // A site environment's value others could read, reported by the helper under tightened:
    // a warning in the error log too, so it outlives the answer it came in.
    void log_exposures(const json::Value& r);

    ErrorLog& log_;
    ControlBackend* backend_ = nullptr;
    LogRegistry* logs_ = nullptr;
    int audit_ = -1;
    // Sites with a task running (F13): one at a time per site. Touched on worker 0 only,
    // where the control connections and the tasks' completions live.
    std::map<std::string, std::string> running_tasks_;
    // The last task's whole output per site (up to 1 MB, as the task captured it), for
    // site_task_output: answers carry a short part (2026-09-27 report: 68 KB overflowed an
    // MCP host). Worker 0 only; gone at a restart.
    struct TaskOutput {
        std::string task, at, text;
        double total = 0;
        bool cut = false;  // the task kept less than it printed
    };
    std::map<std::string, TaskOutput> last_output_;
};

}  // namespace agensio
