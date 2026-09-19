#include "control/handler.hpp"

#include <ctime>

#include <chrono>
#include <cstdio>

#include "control/commands.hpp"
#include "control/sites.hpp"
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

namespace {
constexpr std::size_t kBodyMax = 256 * 1024;

struct BodyRead {
    std::string data;
    char chunk[8192];
};
}  // namespace

void ControlHandler::start(Stream& s, WorkerState& ws, std::function<void()> done) {
    if (!s.request.has_body || !s.request.body) {
        s.response.buffer.clear();
        handle(s, ws);
        done();
        return;
    }
    auto state = std::make_shared<BodyRead>();
    auto step = std::make_shared<std::function<void()>>();
    *step = [this, &s, &ws, state, step, done]() {
        s.request.body->async_read(state->chunk, sizeof state->chunk, [this, &s, &ws, state, step, done](std::error_code ec, std::size_t n) {
            if (ec) return;  // the connection handles a vanished client
            if (n == 0) {
                s.response.buffer = std::move(state->data);
                handle(s, ws);
                done();
                return;
            }
            state->data.append(state->chunk, n);
            if (state->data.size() > kBodyMax) {
                reply(s, 413, json::Value::object().set("error", "body too large"));
                done();
                return;
            }
            (*step)();
        });
    };
    (*step)();
}

void ControlHandler::audit_peer(const Stream& s, std::string_view what, std::string_view result) {
    audit(s.conn.peer_uid, s.conn.peer_gid, static_cast<Role>(s.conn.role), what, result);
}

void ControlHandler::handle(Stream& s, WorkerState& ws) {
    const Request& req = s.request;
    const std::string_view path = ws.path;
    if (req.method == Method::post) {
        mutate(s, ws, path);
        return;
    }
    // The read commands (F2): every one is a GET, every one needs the viewer role.
    const bool read_command = path == "/v1/status" || path == "/v1/sites" || path.starts_with("/v1/sites/") ||
                              path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health" ||
                              path == "/v1/presets";
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
    } else if (path == "/v1/presets") {
        reply(s, 200, preset_catalog());
    } else {
        reply(s, 200, backend_->health());
    }
}

// ---- mutations (F3) ----

namespace {

std::string now_stamp() {
    std::tm tm{};
    const std::time_t now = std::time(nullptr);
    ::localtime_r(&now, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", &tm);
    return buf;
}

json::Value strings(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& x : v) a.push(x);
    return a;
}

json::Value problems_json(const std::vector<control::Problem>& problems) {
    json::Value a = json::Value::array();
    for (const auto& p : problems) {
        json::Value v = json::Value::object().set("code", p.code).set("detail", p.detail);
        if (!p.run_as_root.empty()) v.set("run_as_root", p.run_as_root);
        v.set("blocks", p.blocks);
        a.push(std::move(v));
    }
    return a;
}

json::Value commands_of(const std::vector<control::Problem>& problems, bool blocking_only) {
    json::Value a = json::Value::array();
    for (const auto& p : problems)
        if (!p.run_as_root.empty() && (!blocking_only || p.blocks)) a.push(p.run_as_root);
    return a;
}

json::Value decisions_json(const std::vector<control::Decision>& needs) {
    json::Value a = json::Value::array();
    for (const auto& d : needs) {
        json::Value v = json::Value::object().set("field", d.field).set("question", d.question).set("suggestion", d.suggestion);
        if (!d.options.empty()) v.set("options", strings(d.options));
        a.push(std::move(v));
    }
    return a;
}

}  // namespace

void ControlHandler::mutate(Stream& s, WorkerState& ws, std::string_view path) {
    (void)ws;
    const bool site_path = path.starts_with("/v1/sites/");
    std::string_view name, action;
    if (site_path) {
        name = path.substr(10);
        const std::size_t slash = name.find('/');
        if (slash != std::string_view::npos) {
            action = name.substr(slash + 1);
            name = name.substr(0, slash);
        }
    }
    if (path == "/v1/status" || path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health" || path == "/v1/presets") {
        s.response.headers.add("Allow", "GET, HEAD");
        reply(s, 405, json::Value::object().set("error", "method not allowed"));
        return;
    }
    const bool known = path == "/v1/reload" || path == "/v1/sites" || path == "/v1/logs/reopen" ||
                       (site_path && !name.empty() && (action.empty() || action == "disable" || action == "enable" ||
                                                       action == "delete" || action == "renew"));
    if (!known) {
        reply(s, 404, json::Value::object().set("error", "unknown command").set("path", std::string(path)));
        return;
    }
    const Role needed = (path == "/v1/reload" || path == "/v1/logs/reopen" || action == "renew") ? Role::operator_ : Role::admin;
    if (!require(s, needed, path.substr(4))) return;
    json::Value body = json::Value::object();
    std::string err;
    if (!s.response.buffer.empty() && (!json::parse(s.response.buffer, body, err) || !body.is_object())) {
        reply(s, 400, json::Value::object().set("error", "body must be a JSON object: " + err));
        return;
    }
    if (!body["confirm"].boolean()) {
        reply(s, 428, json::Value::object().set("error", "confirm required")
                          .set("hint", "this command changes the server; send {\"confirm\": true, \"reason\": \"...\"} once the user agreed"));
        return;
    }
    const std::string reason(body.get("reason"));
    const std::string what = std::string(path.substr(4)) + (reason.empty() ? "" : " (" + reason + ")");
    if (!backend_) {
        reply(s, 503, json::Value::object().set("error", "no backend"));
        return;
    }
    if (path == "/v1/reload") {
        std::string error;
        const bool ok = backend_->reload_now(error);
        audit_peer(s, what, ok ? "ok" : error);
        if (ok) reply(s, 200, json::Value::object().set("ok", true).set("message", "configuration reloaded"));
        else reply(s, 409, json::Value::object().set("ok", false).set("error", error));
        return;
    }
    if (path == "/v1/logs/reopen") {
        backend_->reopen_logs();
        audit_peer(s, what, "ok");
        reply(s, 200, json::Value::object().set("ok", true));
        return;
    }
    if (path == "/v1/sites") {
        site_create(s, body, what);
        return;
    }
    if (action.empty()) {
        site_update(s, name, body, what);
        return;
    }
    if (action == "renew") {
        std::string error;
        const bool ok = backend_->renew_certificate(name, error);
        audit_peer(s, what, ok ? "ordering" : error);
        if (ok) reply(s, 202, json::Value::object().set("ok", true).set("message", "order started; watch `site " + std::string(name) + "` and the error log"));
        else reply(s, 409, json::Value::object().set("ok", false).set("error", error));
        return;
    }
    site_toggle(s, name, action, what);
}

void ControlHandler::site_create(Stream& s, const json::Value& body, std::string_view what) {
    const Config& cfg = backend_->running();
    control::SiteSpec spec;
    std::string error;
    const auto needs = control::apply_request(body, cfg, spec, error);
    if (!error.empty()) {
        reply(s, 400, json::Value::object().set("error", error));
        return;
    }
    if (!needs.empty()) {
        reply(s, 422, json::Value::object().set("error", "decisions needed")
                          .set("hint", "ask the user each question, then send the command again with every field")
                          .set("needs", decisions_json(needs)).set("spec", spec.to_json()));
        return;
    }
    if (!control::sites_dir_included(cfg)) {
        reply(s, 409, json::Value::object().set("error", "the main configuration does not include sites.d")
                          .set("fix", "add include = [\"sites.d/*.toml\"] at the top of " + cfg.config_path.string() + " and reload"));
        return;
    }
    if (control::find_site(cfg, spec.domain)) {
        reply(s, 409, json::Value::object().set("error", "a site already serves " + spec.domain).set("hint", "use site-update"));
        return;
    }
    // Every problem at once, so the caller fixes all of them and retries once.
    const auto problems = control::preflight(spec, cfg, backend_->privileged());
    bool blocking = false, restart = false;
    for (const auto& p : problems) {
        blocking = blocking || p.blocks;
        restart = restart || p.code == "needs_restart";
    }
    const bool dry_run = body["dry_run"].boolean();
    const auto file = control::site_file(cfg, spec.domain);
    const std::string rendered = control::render_site(spec, now_stamp());
    // A listener without a catch-all answers 421 to any other Host: say so once, here.
    json::Value warnings = json::Value::array();
    for (const std::string& address : {spec.listen_plain, spec.listen_tls}) {
        const bool used = address == spec.listen_plain ? (spec.https == "none" || spec.redirect_http) : spec.https != "none";
        if (used && !control::listener_has_catch_all(cfg, address))
            warnings.push("requests to " + address + " with a Host this site does not list answer 421 Misdirected Request "
                          "(also by IP address); add a site with server_name = [\"*\"] on it for a catch-all");
    }
    if (dry_run) {
        reply(s, 200, json::Value::object().set("ok", !blocking).set("dry_run", true).set("file", file.string())
                          .set("would_write", rendered).set("problems", problems_json(problems))
                          .set("run_as_root", commands_of(problems, false)).set("spec", spec.to_json())
                          .set("next_steps", strings(control::next_steps(spec, cfg))).set("warnings", warnings));
        return;
    }
    if (blocking) {
        reply(s, 409, json::Value::object().set("error", "prerequisites missing").set("waiting", true)
                          .set("hint", "show every command to the user to run as root, then send the same command again")
                          .set("problems", problems_json(problems)).set("run_as_root", commands_of(problems, true))
                          .set("spec", spec.to_json()));
        return;
    }
    if (!control::write_site_file(file, rendered, error)) {
        audit_peer(s, what, error);
        reply(s, 500, json::Value::object().set("error", error));
        return;
    }
    if (restart) {
        // The file must still be a valid configuration; the listener is bound at the restart.
        const json::Value check = backend_->validate();
        if (!check["ok"].boolean()) {
            std::error_code ec;
            std::filesystem::remove(file, ec);
            audit_peer(s, what, "refused: " + check["errors"].dump());
            reply(s, 409, json::Value::object().set("error", "the new site did not validate; file removed").set("detail", check["errors"]));
            return;
        }
        audit_peer(s, what, "created " + file.string() + " (restart needed for a privileged port)");
        reply(s, 202, json::Value::object().set("ok", true).set("file", file.string()).set("needs_restart", true).set("waiting", true)
                          .set("problems", problems_json(problems)).set("run_as_root", commands_of(problems, false))
                          .set("hint", "the site file is written and valid; it is served once the service restarts")
                          .set("spec", spec.to_json()).set("next_steps", strings(control::next_steps(spec, cfg))).set("warnings", warnings));
        return;
    }
    if (!backend_->reload_now(error)) {
        std::error_code ec;
        std::filesystem::remove(file, ec);
        audit_peer(s, what, "refused: " + error);
        reply(s, 409, json::Value::object().set("error", "the new site did not validate; file removed").set("detail", error));
        return;
    }
    audit_peer(s, what, "created " + file.string());
    reply(s, 201, json::Value::object().set("ok", true).set("file", file.string()).set("spec", spec.to_json())
                      .set("next_steps", strings(control::next_steps(spec, cfg))).set("warnings", warnings));
}

void ControlHandler::site_update(Stream& s, std::string_view name, const json::Value& body, std::string_view what) {
    const Config& cfg = backend_->running();
    const SiteConfig* existing = control::find_site(cfg, name);
    if (!existing) {
        reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        return;
    }
    control::SiteSpec spec;
    const auto file = control::site_file(cfg, existing->server_names.front());
    if (!control::read_managed(file, spec)) {
        reply(s, 409, json::Value::object().set("error", "this site is not managed by agensio ctl (hand-written or edited)")
                          .set("file", file.string()).set("hint", "edit the file by hand and reload"));
        return;
    }
    std::string error;
    const auto needs = control::apply_request(body, cfg, spec, error);
    if (!error.empty()) {
        reply(s, 400, json::Value::object().set("error", error));
        return;
    }
    if (!needs.empty()) {
        reply(s, 422, json::Value::object().set("error", "decisions needed").set("needs", decisions_json(needs)).set("spec", spec.to_json()));
        return;
    }
    const auto problems = control::preflight(spec, cfg, backend_->privileged());
    bool blocking = false;
    for (const auto& p : problems) blocking = blocking || p.blocks;
    if (body["dry_run"].boolean()) {
        reply(s, 200, json::Value::object().set("ok", !blocking).set("dry_run", true).set("file", file.string())
                          .set("would_write", control::render_site(spec, now_stamp())).set("problems", problems_json(problems))
                          .set("run_as_root", commands_of(problems, false)).set("spec", spec.to_json()));
        return;
    }
    if (blocking) {
        reply(s, 409, json::Value::object().set("error", "prerequisites missing").set("waiting", true)
                          .set("problems", problems_json(problems)).set("run_as_root", commands_of(problems, true)));
        return;
    }
    if (!control::write_site_file(file, control::render_site(spec, now_stamp()), error)) {
        reply(s, 500, json::Value::object().set("error", error));
        return;
    }
    if (!backend_->reload_now(error)) {
        std::error_code ec;
        std::filesystem::rename(file.string() + ".bak", file, ec);
        audit_peer(s, what, "refused: " + error);
        reply(s, 409, json::Value::object().set("error", "the change did not validate; previous file restored").set("detail", error));
        return;
    }
    audit_peer(s, what, "updated " + file.string());
    reply(s, 200, json::Value::object().set("ok", true).set("file", file.string()).set("spec", spec.to_json())
                      .set("next_steps", strings(control::next_steps(spec, cfg))));
}

void ControlHandler::site_toggle(Stream& s, std::string_view name, std::string_view action, std::string_view what) {
    const Config& cfg = backend_->running();
    const std::filesystem::path file = control::site_file(cfg, name);
    const std::filesystem::path disabled = file.string() + ".disabled";
    std::error_code ec;
    std::string error;
    if (action == "disable") {
        if (!std::filesystem::exists(file, ec)) {
            reply(s, 404, json::Value::object().set("error", "no site file " + file.string()));
            return;
        }
        std::filesystem::rename(file, disabled, ec);
    } else if (action == "enable") {
        if (!std::filesystem::exists(disabled, ec)) {
            reply(s, 404, json::Value::object().set("error", "no disabled site file " + disabled.string()));
            return;
        }
        std::filesystem::rename(disabled, file, ec);
    } else {  // delete: the file goes, a .bak stays; the root and the account are never touched
        if (!std::filesystem::exists(file, ec) && !std::filesystem::exists(disabled, ec)) {
            reply(s, 404, json::Value::object().set("error", "no site file for " + std::string(name)));
            return;
        }
        if (std::filesystem::exists(file, ec)) std::filesystem::rename(file, file.string() + ".bak", ec);
        std::filesystem::remove(disabled, ec);
    }
    if (ec) {
        reply(s, 500, json::Value::object().set("error", ec.message()));
        return;
    }
    if (!backend_->reload_now(error)) {
        if (action == "disable") std::filesystem::rename(disabled, file, ec);
        else if (action == "enable") std::filesystem::rename(file, disabled, ec);
        else std::filesystem::rename(file.string() + ".bak", file, ec);
        audit_peer(s, what, "refused: " + error);
        reply(s, 409, json::Value::object().set("error", "reload refused; file restored").set("detail", error));
        return;
    }
    audit_peer(s, what, std::string(action) + " " + file.string());
    reply(s, 200, json::Value::object().set("ok", true).set("file", file.string()).set("action", std::string(action)));
}

}  // namespace agensio
