#include "control/handler.hpp"

#include <ctime>

#include <chrono>
#include <cstdio>

#include <algorithm>
#include <cerrno>
#include <vector>
#include <memory>
#include <optional>
#include <cstring>
#include <filesystem>
#include <fstream>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "control/commands.hpp"
#include "control/protection.hpp"
#include "control/reference.hpp"
#include "control/settings.hpp"
#include "control/sites.hpp"
#include "core/body.hpp"
#include "services/appenv.hpp"
#include "services/archive.hpp"
#include "services/install.hpp"
#include "services/pools.hpp"
#include "services/provision.hpp"
#include "services/tasks.hpp"

namespace agensio {

void ControlHandler::reply(Stream& s, int status, const json::Value& body) {
    Response& r = s.response;
    r.status = status;
    r.buffer = body.dump();
    r.buffer.push_back('\n');
    r.scratch = "Content-Type: application/json\r\nCache-Control: no-store\r\nX-Agensio-Version: " AGENSIO_VERSION "\r\nContent-Length: " +
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
    if (s.request.method == Method::put) {
        const std::string_view path = ws.path;
        if (path.starts_with("/v1/uploads/") && path.size() > 12) {
            upload_receive(s, path.substr(12), std::move(done));
        } else {
            s.response.headers.add("Allow", "GET, HEAD, POST");
            reply(s, path.starts_with("/v1/uploads/") ? 400 : 405,
                  json::Value::object().set("error", path.starts_with("/v1/uploads/") ? "PUT /v1/uploads/NAME needs a file name" : "method not allowed"));
            done();
        }
        return;
    }
    if (!s.request.has_body || !s.request.body) {
        s.response.buffer.clear();
        if (!handle_deferred(s, ws, done)) done();
        return;
    }
    auto state = std::make_shared<BodyRead>();
    auto step = std::make_shared<std::function<void()>>();
    // The step refers to itself weakly: the read in flight (its completion below) is what
    // keeps the chain alive, so the chain ends with the last read. Capturing the step
    // strongly made a cycle that outlived the request, and with it the connection and its
    // buffers, once per request with a body (LeakSanitizer, 2026-09-24).
    *step = [this, &s, &ws, state, weak = std::weak_ptr<std::function<void()>>(step), done]() {
        std::shared_ptr<std::function<void()>> step = weak.lock();
        if (!step) return;
        s.request.body->async_read(state->chunk, sizeof state->chunk, [this, &s, &ws, state, step, done](std::error_code ec, std::size_t n) {
            if (ec) return;  // the connection handles a vanished client
            if (n == 0) {
                s.response.buffer = std::move(state->data);
                std::function<void()> d = done;
                if (!handle_deferred(s, ws, d)) d();
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
    std::function<void()> none;
    handle_deferred(s, ws, none);
}

bool ControlHandler::handle_deferred(Stream& s, WorkerState& ws, std::function<void()>& done) {
    const Request& req = s.request;
    const std::string_view path = ws.path;
    if (req.method == Method::post) return mutate(s, ws, path, done);
    // The read commands (F2): every one is a GET, every one needs the viewer role.
    const bool read_command = path == "/v1/status" || path == "/v1/sites" || path.starts_with("/v1/sites/") ||
                              path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health" ||
                              path == "/v1/presets" || path == "/v1/uploads" || path == "/v1/settings" || path == "/v1/config/reference" ||
                              path == "/v1/trash" || path == "/v1/protection";
    if (!read_command) {
        reply(s, 404, json::Value::object().set("error", "unknown command").set("path", std::string(path)));
        return false;
    }
    if (req.method != Method::get && req.method != Method::head) {
        s.response.headers.add("Allow", "GET, HEAD");
        reply(s, 405, json::Value::object().set("error", "method not allowed"));
        return false;
    }
    if (!require(s, Role::viewer, path.substr(4))) return false;
    if (!backend_) {
        reply(s, 503, json::Value::object().set("error", "no backend"));
        return false;
    }
    if (path.starts_with("/v1/sites/") && path.ends_with("/env") && path.size() > 14) {
        // A site's environment holds its secrets: admin only, every read audited.
        if (!require(s, Role::admin, path.substr(4))) return false;
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "env needs an asynchronous caller"));
            return false;
        }
        site_env_show(s, path.substr(10, path.size() - 10 - 4), done);
        return true;
    }
    if (path.starts_with("/v1/sites/") && (path.ends_with("/service") || path.ends_with("/service/logs"))) {
        // The application's own journal can carry what it printed of its secrets: admin, audited.
        const bool logs = path.ends_with("/service/logs");
        if (logs && !require(s, Role::admin, path.substr(4))) return false;
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "service needs an asynchronous caller"));
            return false;
        }
        const std::size_t suffix = logs ? 13 : 8;
        if (path.size() <= 10 + suffix) {
            reply(s, 404, json::Value::object().set("error", "no such site"));
            return false;
        }
        site_service(s, path.substr(10, path.size() - 10 - suffix), logs, done);
        return true;
    }
    if (path == "/v1/protection") {
        // Host protection: viewer, since it reveals the ports, log paths and login paths that
        // status, site_show and the reference reveal already, and nothing root alone knows.
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "protection needs an asynchronous caller"));
            return false;
        }
        protection_show(s, done);
        return true;
    }
    if (path == "/v1/trash") {
        // What a deleted site left: its pieces' sizes and origins, the account it had. Admin: a
        // site's directory names are a tenant's, and a restore needs the same role.
        if (!require(s, Role::admin, path.substr(4))) return false;
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "trash needs an asynchronous caller"));
            return false;
        }
        trash_list(s, done);
        return true;
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
    } else if (path == "/v1/settings") {
        reply(s, 200, control::settings_catalog(backend_->running(), nullptr));
    } else if (path == "/v1/config/reference") {
        reply(s, 200, control::config_reference(&backend_->running()));
    } else if (path.starts_with("/v1/sites/") && path.ends_with("/tasks")) {
        // The named tasks a site's preset offers (F13): from the table, nothing else can run.
        const std::string_view name = path.substr(10, path.size() - 10 - 6);
        const Config& cfg = backend_->running();
        const SiteConfig* site = control::find_site(cfg, name);
        if (!site) {
            reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
            return false;
        }
        const std::string app = site->app.empty() ? "static" : site->app;
        tasks::CatalogContext cc;
        cc.timeout_cap = cfg.control.task_timeout;
        cc.runtime_dir = [&cfg](std::string_view runtime) { return runtime_dir(cfg.control, runtime); };
        cc.sites_root = cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root;
        json::Value list = tasks::catalog(app, &cc);
        // Every package a task's interpreter is missing, once: root installs them before the
        // first task instead of on the third (2026-09-27 report).
        json::Value missing = json::Value::array();
        for (const auto& t : list.items()) {
            const std::string_view cmd = t["interpreter"].get("run_as_root");
            bool seen = cmd.empty();
            for (const auto& m : missing.items()) seen = seen || m.str() == cmd;
            if (!seen) missing.push(std::string(cmd));
        }
        json::Value body = json::Value::object().set("site", std::string(name)).set("app", app).set("tasks", std::move(list));
        if (!missing.items().empty()) body.set("run_as_root", std::move(missing));
        if (tasks::has_tasks(app)) {
            const auto it = running_tasks_.find(site->server_names.front());
            body.set("running", it == running_tasks_.end() ? json::Value(nullptr) : json::Value(it->second))
                .set("downloads", cfg.control.task_network).set("timeout_cap", static_cast<double>(cfg.control.task_timeout))
                .set("runs_as", site->user.empty() ? json::Value("the owner of the site's directory") : json::Value(site->user))
                .set("directory", site->project_root.empty() ? site->root : site->project_root);
            if (node_app(app)) body.set("entry", site->entry.empty() ? json::Value(nullptr) : json::Value(site->entry));
            if (python_app(app))
                body.set("project", site->project)
                    .set("virtualenv", (cfg.state_dir.empty() ? std::string("<state_dir>") : cfg.state_dir) + "/" +
                                           (site->user.empty() ? std::string("<the server's account>") : site->user) + "/venvs/" + site->server_names.front());
        } else {
            body.set("hint", "tasks belong to a preset: app = \"rails\", \"redmine\", \"django\" and \"wagtail\" have them. This site's app has none, "
                             "and agensio runs no other command.");
        }
        reply(s, 200, body);
    } else if (path.starts_with("/v1/sites/") && path.ends_with("/task-output")) {
        // The last task's output in slices (admin, as the task itself).
        if (!require(s, Role::admin, path.substr(4))) return false;
        const std::string_view name = path.substr(10, path.size() - 10 - 12);
        const SiteConfig* site = control::find_site(backend_->running(), name);
        const auto it = site ? last_output_.find(site->server_names.front()) : last_output_.end();
        if (!site || it == last_output_.end()) {
            reply(s, 404, json::Value::object().set("error", site ? "no task output kept for this site since the server started" : "no such site").set("site", std::string(name)));
            return false;
        }
        const TaskOutput& o = it->second;
        const std::size_t offset = std::min<std::size_t>(o.text.size(), static_cast<std::size_t>(std::strtoull(control::query_value(req.target, "offset").c_str(), nullptr, 10)));
        std::size_t length = static_cast<std::size_t>(std::strtoull(control::query_value(req.target, "length").c_str(), nullptr, 10));
        if (length == 0 || length > 65536) length = 65536;
        std::size_t end = std::min(o.text.size(), offset + length);
        // A slice ends on a character boundary, so each answer is valid UTF-8 and next_offset
        // starts the next one on a boundary too.
        while (end > offset && end < o.text.size() && (static_cast<unsigned char>(o.text[end]) & 0xc0) == 0x80) --end;
        if (end == offset) end = std::min(o.text.size(), offset + length);
        reply(s, 200, json::Value::object().set("site", it->first).set("task", o.task).set("at", o.at).set("output_bytes", o.total)
                          .set("kept", static_cast<double>(o.text.size())).set("kept_all", !o.cut).set("offset", static_cast<double>(offset))
                          .set("next_offset", end < o.text.size() ? json::Value(static_cast<double>(end)) : json::Value(nullptr))
                          .set("output", o.text.substr(offset, end - offset)));
    } else if (path.starts_with("/v1/sites/") && path.ends_with("/unit")) {
        // The Puma unit of a Rails site, for root to put in place (read-only text; F14 will apply it).
        const std::string_view name = path.substr(10, path.size() - 10 - 5);
        const SiteConfig* site = control::find_site(backend_->running(), name);
        if (!site) reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        else {
            json::Value u = control::service_unit(*site, backend_->running());
            reply(s, u["ok"].boolean() ? 200 : 409, u);
        }
    } else if (path.starts_with("/v1/sites/") && path.ends_with("/settings")) {
        const std::string_view name = path.substr(10, path.size() - 10 - 9);
        const SiteConfig* site = control::find_site(backend_->running(), name);
        if (site) reply(s, 200, control::settings_catalog(backend_->running(), site));
        else reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
    } else if (path.starts_with("/v1/sites/")) {
        bool found = false;
        json::Value body = backend_->site(path.substr(10), found);
        if (found) {
            // A managed site's rules (control/sites.hpp), as data: the locations they render
            // are in the listing, this says which ones the rules made.
            control::SiteSpec spec;
            const Config& running = backend_->running();
            if (const SiteConfig* site = control::find_site(running, path.substr(10));
                site && control::read_managed(control::site_file(running, site->server_names.front()), spec)) {
                if (spec.rules.is_object() && !spec.rules.members().empty()) body.set("rules", spec.rules);
                // Root additions (design section 20): the root-owned file beside the managed one
                // where root extends the site with locations no field covers; named before it
                // exists too, so an agent knows where the block it hands root belongs.
                const std::string& domain = site->server_names.front();
                const std::filesystem::path file = control::site_file(running, domain).parent_path() / (domain + std::string(kRootAdditionsSuffix));
                json::Value paths = json::Value::array();
                for (const auto& l : site->locations)
                    if (l.origin.starts_with("root:")) paths.push(l.path + (l.exact ? " (exact)" : l.suffix ? " (suffix)" : ""));
                json::Value ra = json::Value::object()
                                     .set("file", file.string())
                                     .set("present", !site->root_additions.empty())
                                     .set("locations", static_cast<double>(paths.items().size()))
                                     .set("paths", std::move(paths));
                if (!site->root_additions.empty()) {
                    json::Value files = json::Value::array();
                    for (const auto& f : site->root_additions) files.push(f);
                    ra.set("files", std::move(files));
                }
                ra.set("note", "root's file (0644), never written by the control plane: `site = \"" + domain +
                                   "\"` on its first line, then [[location]] tables with any key config_reference lists for [[site.location]]; "
                                   "agensio reload applies it and the site stays managed; a location at a path the site file already has is refused at reload");
                body.set("root_additions", std::move(ra));
            }
            reply(s, 200, body);
        } else {
            reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(path.substr(10))));
        }
    } else if (path == "/v1/config/validate") {
        reply(s, 200, backend_->validate());
    } else if (path == "/v1/logs") {
        // A site that does not exist is a 404, as for the other site commands: a mistyped name
        // answered "count 0" read as "no errors" (2026-10-02 alpha.43 report).
        if (const std::string site = control::query_value(req.target, "site"); !site.empty() && !control::find_site(backend_->running(), site))
            reply(s, 404, json::Value::object().set("error", "no such site").set("site", site));
        else
            reply(s, 200, backend_->logs(req.target));
    } else if (path == "/v1/presets") {
        reply(s, 200, preset_catalog());
    } else if (path == "/v1/uploads") {
        reply(s, 200, uploads_list());
    } else {
        reply(s, 200, backend_->health());
    }
    return false;
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

// The credential files of a site, relative to its directory, for the writers: what the
// hosting rule checks (secret_paths), restricted to what lies below the site's directory.
json::Value site_secrets(const SiteConfig& site, const std::string& site_root) {
    json::Value a = json::Value::array();
    for (const auto& abs : secret_paths(site))
        if (abs.size() > site_root.size() + 1 && abs.compare(0, site_root.size(), site_root) == 0 && abs[site_root.size()] == '/')
            a.push(abs.substr(site_root.size() + 1));
    return a;
}

// A site's request-body limit as a next step: the first upload above it is a 413 the
// application never sees (2026-09-27 report: a 2.75 MB book cover on the 1 MB default).
// Only while the site runs on the server's default: a limit set for the site was a choice
// already (alpha.33 report: a site at 100 MB was told how to raise it to 100 MB).
std::string body_limit_step(const SiteConfig& site, const Config& cfg) {
    if (site.max_body_size) return "";
    return "this site accepts request bodies (uploads included) up to " + control::size_text(body_limit_of(site, cfg)) +
           ", the server's default; larger ones get 413 before the application sees them: site_update with settings {max_body_size: \"100MB\"} raises it, "
           "up to [control] site_limits";
}

struct SiteFacts {
    bool rails_root = false;
    bool python_root = false;  // a Django or Wagtail site's whole project (2026-09-28)
    bool node_root = false;    // a Node site's whole application (2026-09-28)
    std::string key, ruby_dir, node_dir, body_step, app, project, entry, home;
    std::string served_sub;    // the served root's path below the project directory (Laravel's public), "" when they are one
};

// The hosting-rule errors of the configuration on disk, as a set: a writer compares the
// state before and after what it wrote, so its answer never says ok to a state the
// validator refuses, and a problem that was there before is not blamed on the call.
std::vector<std::string> validation_errors(ControlBackend& backend) {
    std::vector<std::string> out;
    const json::Value v = backend.validate();
    for (const auto& e : v["errors"].items())
        if (e.is_string()) out.push_back(e.str());
    return out;
}

// Errors in `after` that were not in `before`.
json::Value new_errors(const std::vector<std::string>& before, const std::vector<std::string>& after) {
    json::Value a = json::Value::array();
    for (const auto& e : after)
        if (std::find(before.begin(), before.end(), e) == before.end()) a.push(e);
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

bool ControlHandler::mutate(Stream& s, WorkerState& ws, std::string_view path, std::function<void()>& done) {
    (void)ws;
    const bool site_path = path.starts_with("/v1/sites/");
    const bool upload_path = path.starts_with("/v1/uploads/");
    const bool trash_path = path.starts_with("/v1/trash/");
    std::string_view name, action;
    if (site_path || upload_path || trash_path) {
        name = path.substr(site_path ? 10 : upload_path ? 12 : 10);
        const std::size_t slash = name.find('/');
        if (slash != std::string_view::npos) {
            action = name.substr(slash + 1);
            name = name.substr(0, slash);
        }
    }
    if (path == "/v1/status" || path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health" || path == "/v1/presets" ||
        path == "/v1/uploads" || path == "/v1/settings" || path == "/v1/config/reference" || (site_path && action == "settings")) {
        s.response.headers.add("Allow", "GET, HEAD");
        reply(s, 405, json::Value::object().set("error", "method not allowed"));
        return false;
    }
    const bool known = path == "/v1/reload" || path == "/v1/sites" || path == "/v1/logs/reopen" ||
                       (site_path && !name.empty() && (action.empty() || action == "disable" || action == "enable" ||
                                                       action == "delete" || action == "renew" || action == "install" || action == "copy" ||
                                                       action == "task" || action == "env")) ||
                       (upload_path && !name.empty() && action == "delete") || (trash_path && !name.empty() && (action == "restore" || action == "delete")) ||
                       path == "/v1/trash/expire";
    if (!known) {
        reply(s, 404, json::Value::object().set("error", "unknown command").set("path", std::string(path)));
        return false;
    }
    const Role needed = (path == "/v1/reload" || path == "/v1/logs/reopen" || action == "renew" || upload_path) ? Role::operator_ : Role::admin;
    if (!require(s, needed, path.substr(4))) return false;
    json::Value body = json::Value::object();
    std::string err;
    if (!s.response.buffer.empty() && (!json::parse(s.response.buffer, body, err) || !body.is_object())) {
        reply(s, 400, json::Value::object().set("error", "body must be a JSON object: " + err));
        return false;
    }
    if (!body["confirm"].boolean()) {
        reply(s, 428, json::Value::object().set("error", "confirm required")
                          .set("hint", "this command changes the server; send {\"confirm\": true, \"reason\": \"...\"} once the user agreed"));
        return false;
    }
    const std::string reason(body.get("reason"));
    const std::string what = std::string(path.substr(4)) + (reason.empty() ? "" : " (" + reason + ")");
    if (!backend_) {
        reply(s, 503, json::Value::object().set("error", "no backend"));
        return false;
    }
    if (path == "/v1/reload") {
        std::string error;
        const bool ok = backend_->reload_now(error);
        audit_peer(s, what, ok ? "ok" : error);
        if (ok) reply(s, 200, json::Value::object().set("ok", true).set("message", "configuration reloaded"));
        else reply(s, 409, json::Value::object().set("ok", false).set("error", error));
        return false;
    }
    if (path == "/v1/logs/reopen") {
        backend_->reopen_logs();
        audit_peer(s, what, "ok");
        reply(s, 200, json::Value::object().set("ok", true));
        return false;
    }
    if (trash_path || path == "/v1/trash/expire") {
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "the trash needs an asynchronous caller"));
            return false;
        }
        if (path == "/v1/trash/expire") {
            backend_->provision_async(json::Value::object().set("op", "trash_expire"), [this, &s, what, done](json::Value r) {
                audit_peer(s, what, r["ok"].boolean() ? "removed " + std::to_string(r["removed"].items().size()) + " expired entr" +
                                                                (r["removed"].items().size() == 1 ? "y" : "ies")
                                                          : "failed: " + std::string(r.get("error")));
                reply(s, r["ok"].boolean() ? 200 : 409, r);
                done();
            });
            return true;
        }
        if (!provision::valid_trash_entry(name)) {
            reply(s, 400, json::Value::object().set("error", "not a trash entry's name (trash lists them: <domain>-<date>-<time>)"));
            return false;
        }
        if (action == "restore") trash_restore(s, name, what, std::move(done));
        else trash_delete(s, name, what, std::move(done));
        return true;
    }
    if (path == "/v1/sites") {
        site_create(s, body, what);
        return false;
    }
    if (upload_path) {
        upload_delete(s, name, what);
        return false;
    }
    if (action.empty()) {
        site_update(s, name, body, what);
        return false;
    }
    if (action == "renew") {
        std::string error;
        const bool ok = backend_->renew_certificate(name, error);
        audit_peer(s, what, ok ? "ordering" : error);
        if (ok) reply(s, 202, json::Value::object().set("ok", true).set("message", "order started; watch `site " + std::string(name) + "` and the error log"));
        else reply(s, 409, json::Value::object().set("ok", false).set("error", error));
        return false;
    }
    if (action == "install" || action == "copy" || action == "task" || action == "env") {
        if (!done) {  // no way to defer: answered synchronously as a refusal
            reply(s, 503, json::Value::object().set("error", "install, copy, task and env need an asynchronous caller"));
            return false;
        }
        if (action == "copy") site_copy(s, name, body, what, std::move(done));
        else if (action == "task") site_task(s, name, body, what, std::move(done));
        else if (action == "env") site_env_set(s, name, body, what, std::move(done));
        else site_install(s, name, body, what, std::move(done));
        return true;
    }
    if (action == "delete" && body["files"].boolean()) {
        // With its files (F12b): everything into the trash, then the site file goes and the
        // configuration reloads; deferred like an install, since the helper does the moves.
        if (!done) {
            reply(s, 503, json::Value::object().set("error", "delete with files needs an asynchronous caller"));
            return false;
        }
        site_trash(s, name, what, std::move(done));
        return true;
    }
    site_toggle(s, name, action, what);
    return false;
}

// ---- the trash (F12b) ----

namespace {

std::string size_words(double bytes) {
    char buf[32];
    if (bytes >= 1024.0 * 1024 * 1024) std::snprintf(buf, sizeof buf, "%.1f GB", bytes / (1024.0 * 1024 * 1024));
    else if (bytes >= 1024.0 * 1024) std::snprintf(buf, sizeof buf, "%.1f MB", bytes / (1024.0 * 1024));
    else if (bytes >= 1024.0) std::snprintf(buf, sizeof buf, "%.0f KB", bytes / 1024.0);
    else std::snprintf(buf, sizeof buf, "%.0f bytes", bytes);
    return buf;
}

}  // namespace

// A site deleted with its files: the helper moves the site's directory, the account's state
// directory (or the site's virtualenv), its logs and its environment file into the trash and
// keeps the site file's text in the manifest; then the site file goes and the configuration
// reloads. A reload that fails brings everything back. The account is kept.
void ControlHandler::site_trash(Stream& s, std::string_view name, std::string_view what, std::function<void()> done) {
    const Config& cfg = backend_->running();
    const SiteConfig* site = control::find_site(cfg, name);
    if (!site) {
        reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        done();
        return;
    }
    if (!backend_->provision_available()) {
        reply(s, 409, json::Value::object()
                          .set("error", "deleting a site with its files needs the provisioning helper (agensio started as root with [control] provision), which moves them into root's trash")
                          .set("hint", "site_delete without files removes the configuration alone; the files are then removed by hand"));
        done();
        return;
    }
    const std::string key = site->server_names.front();
    const std::filesystem::path file = control::site_file(cfg, key);
    const bool php_pool = php_app(site->app) && !site->user.empty() && site->pool.generated;
    audit_peer(s, what, "moving the site's files into the trash");
    backend_->provision_async(json::Value::object().set("op", "site_trash").set("site", key), [this, &s, what = std::string(what), key, file, php_pool, done](json::Value r) {
        if (!r["ok"].boolean()) {
            audit_peer(s, what, "refused: " + std::string(r.get("error")));
            reply(s, 409, r);
            done();
            return;
        }
        // The files are in the trash: the site file goes, the configuration reloads.
        std::error_code ec;
        const std::string site_file(r.get("site_file"));
        std::filesystem::remove(file, ec);
        std::filesystem::remove(file.string() + ".disabled", ec);
        std::string error;
        if (!backend_->reload_now(error)) {
            // Put the file back and the files with it, so nothing is half done.
            if (!site_file.empty()) {
                std::ofstream out(site_file, std::ios::trunc);
                out << std::string(r.get("site_file_text"));
            }
            const std::string entry(r.get("entry"));
            const json::Value back = backend_->provision(json::Value::object().set("op", "site_restore").set("entry", entry));
            audit_peer(s, what, "reload refused (" + error + "); files " + (back["ok"].boolean() ? "restored" : "NOT restored: " + std::string(back.get("error"))));
            reply(s, 409, json::Value::object().set("ok", false).set("error", "reload refused; the site and its files were put back").set("detail", error)
                              .set("files_restored", back["ok"].boolean()));
            done();
            return;
        }
        std::string moved;
        for (const auto& p : r["pieces"].items()) moved += (moved.empty() ? "" : ", ") + std::string(p.get("from"));
        audit_peer(s, what, "deleted with its files: " + moved + " -> " + std::string(r.get("directory")) + "; the account " +
                                (r.get("account").empty() ? std::string("(none)") : std::string(r.get("account")) + " kept"));
        json::Value body = json::Value::object().set("ok", true).set("action", "delete").set("files", true).set("site", key).set("entry", r["entry"])
                               .set("trash", r["directory"]).set("pieces", r["pieces"]).set("deleted_at", r["deleted_at"]).set("expires_at", r["expires_at"]);
        json::Value steps = json::Value::array();
        steps.push("site_restore " + std::string(r.get("entry")) + " brings the site and every file back, into an empty place only; trash_list shows what the trash holds");
        if (r["expires_at"].is_null()) steps.push("the entry stays until trash_delete removes it ([control] trash_keep = 0)");
        else steps.push("the entry is removed on " + std::string(r.get("expires_at")) + " ([control] trash_keep); trash_delete removes it sooner");
        if (!r.get("account").empty())
            steps.push("the account " + std::string(r.get("account")) + " is kept (a restore needs its uid); once the entry is gone" +
                       (r["account_shared"].boolean() ? ", other sites still use it" : ", root may remove it: userdel " + std::string(r.get("account"))));
        json::Value done_now = json::Value::array();
        if (php_pool) {
            const json::Value pool = backend_->provision(json::Value::object().set("op", "pools_apply"));
            if (pool["ok"].boolean()) done_now.push("php-fpm pools: " + std::string(pool.get("output")));
            else steps.push("# the helper could not apply the pools (" + std::string(pool.get("error")) + "); run: agensio pools");
        }
        if (!r["run_as_root"].items().empty()) body.set("run_as_root", r["run_as_root"]);
        for (const auto& p : protection_steps()) steps.push(p);
        body.set("next_steps", steps);
        if (!done_now.items().empty()) body.set("done", done_now);
        reply(s, 200, body);
        done();
    });
}

// A world-readable file the server reads itself (the kept ruleset, the installed jail), up to
// 1 MB; nullopt when absent or unreadable.
static std::optional<std::string> read_whole_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::string text;
    char buf[65536];
    while (in.read(buf, sizeof buf) || in.gcount() > 0) {
        text.append(buf, static_cast<std::size_t>(in.gcount()));
        if (text.size() > (1u << 20)) break;
    }
    return text;
}

void ControlHandler::protection_show(Stream& s, std::function<void()> done) {
    const control::ProtectionInput in = control::protection_input(backend_->running());
    auto finish = [this, &s, done, in](json::Value probe_reply) {
        control::ProtectionFiles files;
        files.firewall_file = read_whole_file(in.firewall_file);
        files.installed_jail = read_whole_file(std::string(control::kJailFile));
        for (const auto& f : control::installed_filter_paths()) files.installed_filters.push_back(read_whole_file(f));
        reply(s, 200, control::protection_report(in, control::read_probe(probe_reply, in), files));
        done();
    };
    if (!in.exposed || in.host_protection == "off")
        finish(json::Value::object().set("ok", false).set("error", in.exposed ? "[control] host_protection = \"off\": the host is not checked" : "every listener is on loopback: nothing to check"));
    else
        backend_->helper_async(json::Value::object().set("op", "host_protection"), finish);
}

// 2026-10-02 alpha.43 addendum: a login path added through site_update was not counted until
// root rendered the jail again, and the answer said nothing. Only files root installed are
// judged: the jail at /etc/fail2ban/jail.d/agensio.conf against the rendering for the sites as
// they are now, the kept ruleset <config dir>/firewall.nft against its rendering (a new
// public port); a host without them hears it from health instead.
std::vector<std::string> ControlHandler::protection_steps() {
    std::vector<std::string> out;
    const control::ProtectionInput in = control::protection_input(backend_->running());
    if (const auto jail = read_whole_file(std::string(control::kJailFile)); jail && *jail != control::render_jail(in)) {
        // A filter of an older build installed beside it goes first (alpha.44 report).
        bool filters_differ = false;
        const auto paths = control::installed_filter_paths();
        for (std::size_t i = 0; i < paths.size(); ++i)
            if (const auto text = read_whole_file(paths[i]); text && *text != control::protection_filters()[i].text) filters_differ = true;
        out.push_back("the fail2ban jail on disk is older than this change (the sites' login paths, logs or ports): until root renders it again the new paths are not counted; as root: " +
                      (filters_differ ? control::filter_install_command() + "; " : std::string()) + "agensio ctl protection --jail > " + std::string(control::kJailFile) + "; fail2ban-client reload");
    }
    if (const auto nft = read_whole_file(in.firewall_file); nft && *nft != control::render_nft(in))
        out.push_back("the firewall ruleset on disk is older than this change (the public ports): as root: agensio ctl protection --nft > " + in.firewall_file + "; nft -f " + in.firewall_file);
    return out;
}

void ControlHandler::trash_list(Stream& s, std::function<void()> done) {
    backend_->helper_async(json::Value::object().set("op", "trash_list"), [this, &s, done](json::Value r) {
        if (r["busy"].boolean()) {
            reply(s, 503, json::Value::object().set("error", "the provisioning helper is busy with a task or an install; ask again when it finishes").set("busy", true));
        } else if (!r["ok"].boolean()) {
            reply(s, 409, r);
        } else {
            double total = 0;
            for (const auto& e : r["entries"].items()) total += e["bytes"].num();
            r.set("total_bytes", total).set("total", size_words(total));
            r.set("hint", r["entries"].items().empty()
                              ? std::string("the trash is empty: site_delete with files: true puts a site's directory, logs, environment and account state here")
                              : "site_restore ENTRY brings one back into an empty place; trash_delete ENTRY removes it now; entries expire after [control] trash_keep days "
                                "(the hourly expiry, or agensio ctl trash-expire); an account_in_use of false means no site uses that account any more, and root may "
                                "remove it once the entry is gone (userdel)");
            reply(s, 200, r);
        }
        done();
    });
}

void ControlHandler::trash_restore(Stream& s, std::string_view entry, std::string_view what, std::function<void()> done) {
    if (!backend_->provision_available()) {
        reply(s, 409, json::Value::object().set("error", "the trash is the provisioning helper's (agensio started as root with [control] provision)"));
        done();
        return;
    }
    audit_peer(s, what, "restoring from the trash");
    backend_->provision_async(json::Value::object().set("op", "site_restore").set("entry", std::string(entry)), [this, &s, what = std::string(what), done](json::Value r) {
        if (!r["ok"].boolean()) {
            audit_peer(s, what, "refused: " + std::string(r.get("error")));
            reply(s, 409, r);
            done();
            return;
        }
        std::string error;
        const bool reloaded = backend_->reload_now(error);
        std::string back;
        for (const auto& p : r["restored"].items()) back += (back.empty() ? "" : ", ") + std::string(p.get("path"));
        audit_peer(s, what, "restored " + std::string(r.get("site")) + ": " + back + (reloaded ? "" : "; reload refused: " + error));
        json::Value steps = json::Value::array();
        if (php_app(r.get("app")) && !r.get("account").empty() && backend_->provision_available()) {
            const json::Value pool = backend_->provision(json::Value::object().set("op", "pools_apply"));
            if (!pool["ok"].boolean()) steps.push("# the helper could not apply the pools (" + std::string(pool.get("error")) + "); run: agensio pools");
        }
        if (service_app(r.get("app")) && !r.get("account").empty())
            steps.push("the application's service was removed with the site: site_service_unit " + std::string(r.get("site")) + " renders it again for root");
        for (const auto& p : protection_steps()) steps.push(p);
        r.set("next_steps", steps);
        if (!reloaded)
            reply(s, 409, r.set("ok", false).set("error", "the files and the site file are back, but the reload was refused; health lists what to fix").set("detail", error));
        else
            reply(s, 200, r);
        done();
    });
}

void ControlHandler::trash_delete(Stream& s, std::string_view entry, std::string_view what, std::function<void()> done) {
    if (!backend_->provision_available()) {
        reply(s, 409, json::Value::object().set("error", "the trash is the provisioning helper's (agensio started as root with [control] provision)"));
        done();
        return;
    }
    backend_->provision_async(json::Value::object().set("op", "trash_delete").set("entry", std::string(entry)), [this, &s, what = std::string(what), done](json::Value r) {
        audit_peer(s, what, r["ok"].boolean() ? "removed for good" : "refused: " + std::string(r.get("error")));
        reply(s, r["ok"].boolean() ? 200 : 409, r);
        done();
    });
}

// ---- uploads and installs (F9) ----

namespace {

struct UploadState {
    int fd = -1;
    std::string path, final_path, name;
    std::uint64_t bytes = 0;
    char chunk[64 * 1024];
    ~UploadState() {
        if (fd >= 0) {
            ::close(fd);
            std::error_code ec;
            std::filesystem::remove(path, ec);  // an upload that did not complete leaves nothing
        }
    }
};

}  // namespace

void ControlHandler::upload_receive(Stream& s, std::string_view name, std::function<void()> done) {
    if (!require(s, Role::operator_, "uploads/" + std::string(name))) {
        done();
        return;
    }
    if (!install::valid_upload_name(name)) {
        reply(s, 400, json::Value::object().set("error", "the upload name must be a plain file name: letters, digits, '.', '_', '-', not starting with a dot"));
        done();
        return;
    }
    const std::string dir = backend_ ? backend_->uploads_dir() : "";
    if (dir.empty()) {
        reply(s, 503, json::Value::object().set("error", "uploads are off: the server has no writable state directory (see the error log at start)"));
        done();
        return;
    }
    if (!s.request.has_body || !s.request.body) {
        reply(s, 400, json::Value::object().set("error", "an upload needs a body"));
        done();
        return;
    }
    auto st = std::make_shared<UploadState>();
    st->name = std::string(name);
    st->final_path = dir + "/" + st->name;
    st->path = st->final_path + ".part";
    st->fd = ::open(st->path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (st->fd < 0) {
        reply(s, 500, json::Value::object().set("error", "cannot create " + st->path + ": " + std::strerror(errno)));
        done();
        return;
    }
    audit_peer(s, "uploads/" + st->name, "receiving");
    auto step = std::make_shared<std::function<void()>>();
    *step = [this, &s, st, weak = std::weak_ptr<std::function<void()>>(step), done]() {  // weak: see start()
        std::shared_ptr<std::function<void()>> step = weak.lock();
        if (!step) return;
        s.request.body->async_read(st->chunk, sizeof st->chunk, [this, &s, st, step, done](std::error_code ec, std::size_t n) {
            if (ec) {
                audit_peer(s, "uploads/" + st->name, "aborted: " + ec.message());
                return;  // the connection handles a vanished client; the .part file goes with the state
            }
            if (n == 0) {
                std::error_code fec;
                bool ok = ::fsync(st->fd) == 0;
                ::close(st->fd);
                st->fd = -1;
                if (ok) {
                    std::filesystem::rename(st->path, st->final_path, fec);
                    ok = !fec;
                }
                if (!ok) {
                    std::filesystem::remove(st->path, fec);
                    audit_peer(s, "uploads/" + st->name, "failed to store");
                    reply(s, 500, json::Value::object().set("error", "cannot store the upload"));
                } else {
                    audit_peer(s, "uploads/" + st->name, "stored " + std::to_string(st->bytes) + " bytes");
                    reply(s, 201, json::Value::object().set("ok", true).set("file", st->name).set("bytes", static_cast<double>(st->bytes))
                                      .set("hint", "install it with site-install NAME --file " + st->name));
                }
                done();
                return;
            }
            const char* p = st->chunk;
            std::size_t left = n;
            while (left > 0) {
                const ssize_t w = ::write(st->fd, p, left);
                if (w < 0) {
                    if (errno == EINTR) continue;
                    reply(s, 507, json::Value::object().set("error", std::string("writing the upload: ") + std::strerror(errno)));
                    audit_peer(s, "uploads/" + st->name, std::string("write failed: ") + std::strerror(errno));
                    done();
                    return;
                }
                p += w;
                left -= static_cast<std::size_t>(w);
            }
            st->bytes += n;
            (*step)();
        });
    };
    (*step)();
}

json::Value ControlHandler::uploads_list() {
    json::Value list = json::Value::array();
    const std::string dir = backend_ ? backend_->uploads_dir() : "";
    if (!dir.empty()) {
        std::error_code ec;
        std::vector<std::filesystem::directory_entry> entries;
        for (const auto& e : std::filesystem::directory_iterator(dir, ec)) entries.push_back(e);
        std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) { return a.path().filename() < b.path().filename(); });
        for (const auto& e : entries) {
            const std::string name = e.path().filename().string();
            if (!install::valid_upload_name(name) || !e.is_regular_file(ec)) continue;  // .part files and strangers are not offered
            struct stat st {};
            ::stat(e.path().c_str(), &st);
            char stamp[32];
            std::tm tm{};
            ::localtime_r(&st.st_mtime, &tm);
            std::strftime(stamp, sizeof stamp, "%Y-%m-%dT%H:%M:%S", &tm);
            list.push(json::Value::object().set("file", name).set("bytes", static_cast<double>(st.st_size)).set("uploaded", stamp));
        }
    }
    return json::Value::object().set("uploads", list).set("directory", dir)
        .set("hint", dir.empty() ? "uploads are off: no writable state directory" : "agensio ctl upload NAME < archive.tar.gz adds one; site-install NAME --file FILE unpacks it into a site");
}

void ControlHandler::upload_delete(Stream& s, std::string_view name, std::string_view what) {
    const std::string dir = backend_->uploads_dir();
    if (!install::valid_upload_name(name) || dir.empty()) {
        reply(s, 404, json::Value::object().set("error", "no such upload").set("file", std::string(name)));
        return;
    }
    const std::string path = dir + "/" + std::string(name);
    std::error_code ec;
    if (!std::filesystem::is_regular_file(path, ec) || !std::filesystem::remove(path, ec)) {
        reply(s, 404, json::Value::object().set("error", "no such upload").set("file", std::string(name)));
        return;
    }
    audit_peer(s, what, "deleted");
    reply(s, 200, json::Value::object().set("ok", true).set("file", std::string(name)));
}

void ControlHandler::site_install(Stream& s, std::string_view name, const json::Value& body, std::string_view what, std::function<void()> done) {
    const Config& cfg = backend_->running();
    const SiteConfig* site = control::find_site(cfg, name);
    if (!site) {
        reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        done();
        return;
    }
    // The source: a URL, an upload, or the preset's official archive (with a version).
    std::string url(body.get("url")), file(body.get("file")), version(body.get("version"));
    const std::string app = site->app.empty() ? "static" : site->app;
    if (url.empty() && file.empty()) {
        url = preset_source(app, version);
        if (url.empty()) {
            reply(s, 422, json::Value::object().set("error", "no source: give url (an https archive) or file (an upload)")
                              .set("hint", app == "laravel" ? "Laravel projects are created with composer, not from an archive; upload the project as a tarball or give the URL of one"
                                           : app == "redmine" ? "Redmine has no address for the newest release: give version (e.g. 7.0.1, digits and dots) and the sha256 redmine.org publishes"
                                                              : "this preset has no official download; give url or file")
                              .set("app", app));
            done();
            return;
        }
    }
    if (!url.empty() && !file.empty()) {
        reply(s, 400, json::Value::object().set("error", "give either url or file, not both"));
        done();
        return;
    }
    if (!url.empty() && !cfg.control.install) {
        reply(s, 403, json::Value::object().set("error", "downloads are off on this server ([control] install = false)")
                          .set("hint", "upload the archive with `agensio ctl upload NAME < file` and install with file: NAME"));
        done();
        return;
    }
    if (!url.empty() && !url.starts_with("https://")) {
        reply(s, 400, json::Value::object().set("error", "url must be https://"));
        done();
        return;
    }
    if (!file.empty() && !install::valid_upload_name(file)) {
        reply(s, 400, json::Value::object().set("error", "file must be the name of an upload (see uploads)"));
        done();
        return;
    }
    const std::string sha(body.get("sha256"));
    if (!sha.empty() && !install::valid_sha256(sha)) {
        reply(s, 400, json::Value::object().set("error", "sha256 must be 64 hex digits"));
        done();
        return;
    }
    // Where: the site's project directory (the configured root, above the served
    // subdirectory of a preset), or `path` below it (a plugin or theme directory;
    // create_path makes the missing levels as the site's account).
    const std::string site_root = site->project_root.empty() ? site->root : site->project_root;
    std::string target = site_root;
    const std::string sub(body.get("path"));
    if (!sub.empty()) {
        std::string clean, why;
        if (!archive::clean_path(sub, clean, why)) {
            reply(s, 400, json::Value::object().set("error", "path must be relative, below the site's directory, without '..': " + why));
            done();
            return;
        }
        target += "/" + clean;
    }
    std::string why;
    if (site_root.empty() || !control::safe_path(site_root, why) || !control::safe_path(target, why)) {
        reply(s, 409, json::Value::object().set("error", "the site's directory is not a path an install can use: " + why).set("target", target));
        done();
        return;
    }
    const bool create_path = body["create_path"].boolean();
    const bool dry_run = body["dry_run"].boolean();
    json::Value req = json::Value::object().set("site_root", site_root).set("target", target).set("create_path", create_path).set("dry_run", dry_run)
                          .set("secrets", site_secrets(*site, site_root));
    if (!site->user.empty()) req.set("user", site->user);
    if (!url.empty()) req.set("url", url);
    if (!file.empty()) req.set("upload", file);
    if (!sha.empty()) req.set("sha256", sha);
    if (!body["strip"].is_null()) req.set("strip", body["strip"]);
    if (rails_app(app) && target == site_root) req.set("ruby_check", true);  // the pinned Ruby against the runtime's (next steps)
    if (node_app(app) && target == site_root) req.set("node_check", true);   // engines.node against the runtime's node
    const std::string source = url.empty() ? "upload " + file : url;
    if (!dry_run) audit_peer(s, what, "installing " + source + " into " + target + (create_path ? " (create_path)" : ""));
    const std::vector<std::string> before = dry_run ? std::vector<std::string>{} : validation_errors(*backend_);
    // What the answer's next steps depend on (2026-09-27 Writebook report: a Rails site was
    // told to open a browser, and nothing named the 1 MB body limit before the first upload).
    SiteFacts sf;
    sf.rails_root = rails_app(app) && target == site_root;
    sf.python_root = python_app(app) && target == site_root;
    sf.project = site->project;
    sf.node_root = node_app(app) && target == site_root;
    if (site->root.size() > site_root.size() && site->root.starts_with(site_root + "/")) sf.served_sub = site->root.substr(site_root.size() + 1);
    sf.entry = site->entry;
    sf.node_dir = runtime_dir(cfg.control, "node");
    if (!site->user.empty() && !cfg.state_dir.empty()) sf.home = cfg.state_dir + "/" + site->user;
    sf.app = app;
    sf.key = site->server_names.front();
    sf.ruby_dir = runtime_dir(cfg.control, "ruby");
    sf.body_step = app == "static" ? std::string() : body_limit_step(*site, cfg);
    // A dry run takes the same walk as the real call (as the same account) and reports
    // the refusal it would meet or the directories it would create; nothing is written.
    backend_->install_async(req, [this, &s, what = std::string(what), target, url, file, source, dry_run, before, sf, done](json::Value r) {
        const bool ok = r["ok"].boolean();
        if (dry_run) {
            if (ok) reply(s, 200, r.set("source", source).set("hint", "nothing was written; the same call without dry_run installs"));
            else reply(s, 409, json::Value::object().set("ok", false).set("dry_run", true).set("error", r.get("error")).set("target", target));
            done();
            return;
        }
        std::string made;
        for (const auto& c : r["created"].items()) made += " created " + std::string(c.get("path")) + " (" + std::string(c.get("owner")) + " " + std::string(c.get("mode")) + ")";
        for (const auto& c : r["secured"].items()) made += " secured " + std::string(c.str()) + " (0600)";
        audit_peer(s, what, ok ? "installed " + std::to_string(static_cast<long>(r["files"].num())) + " files into " + target + " (sha256 " + std::string(r.get("sha256")) + ")" + made
                              : "failed: " + std::string(r.get("error")));
        if (!ok) {
            reply(s, 409, json::Value::object().set("ok", false).set("error", r.get("error")).set("target", target));
        } else if (const json::Value fresh = new_errors(before, validation_errors(*backend_)); !fresh.items().empty()) {
            // The state written passes the writer's own checks but not the whole
            // configuration's: say so instead of ok, with the validator's words.
            audit_peer(s, what, "written, but the configuration no longer validates: " + fresh.dump());
            reply(s, 409, r.set("ok", false).set("written", true).set("error", "the files are installed, but the configuration no longer validates; agensio -t and a restart would refuse it")
                              .set("errors", fresh).set("hint", "fix what the errors name (health lists them with a fix each), then config_validate"));
        } else {
            json::Value warnings = json::Value::array();
            if (!before.empty()) warnings.push("the configuration already failed validation before this call (health lists the findings); the install itself is fine");
            json::Value steps = json::Value::array();
            if (!url.empty()) steps.push("the files came from " + std::string(r.get("url").empty() ? url : std::string(r.get("url"))) + "; sha256 " + std::string(r.get("sha256")));
            const json::Value facts = r["facts"];  // a copy: r.set below may move r's members
            if (sf.rails_root) {
                if (const std::string pin(facts.get("ruby_version")); !pin.empty()) {
                    const std::string have(facts.get("runtime_ruby"));
                    // Bundler reads `ruby file: ".ruby-version"` as exact; a pin of fewer parts
                    // ("3.4") is matched by any release of it.
                    const bool same = !have.empty() && (have == pin || have.starts_with(pin + "."));
                    if (same)
                        steps.push("the application pins Ruby " + pin + " (.ruby-version), and the Ruby of [control] runtimes (" + sf.ruby_dir + ") is " + have + ": they match");
                    else if (!have.empty())
                        steps.push("the application pins Ruby " + pin + " (.ruby-version), but the Ruby of [control] runtimes (" + sf.ruby_dir + ") is " + have +
                                   ": bundle_install refuses until root installs " + pin + " under /opt and points runtimes.ruby at its bin directory "
                                   "(docs/configuration.md 15, a Ruby for one application; agensio reload applies it)");
                    else
                        steps.push("the application pins Ruby " + pin + " (.ruby-version); the Ruby of [control] runtimes (" + sf.ruby_dir + ") could not be asked for its version (" +
                                   std::string(facts.get("runtime_ruby_error").empty() ? "the interpreter rule refused it: site_tasks_list says why" : facts.get("runtime_ruby_error")) +
                                   "); when it is another version bundle_install refuses (docs/configuration.md 15)");
                }
                // Redmine and every archive that ships database.yml.example: the database first
                // (2026-09-27 Redmine report: bundle_install then had no driver, db_prepare failed).
                const bool no_db = !facts["database_yml"].boolean();
                const std::string db = no_db ? "site_env_set with set: {\"DATABASE_URL\": \"sqlite3:db/production.sqlite3\"} (or postgresql://USER:PASSWORD@HOST/NAME), "
                                               "site_task database_config, " : "";
                const std::string unit = "then the application server: site_service_unit gives its systemd unit for root to install";
                if (sf.app == "redmine")
                    steps.push(db + "site_task gemfile_local, bundle_install, db_migrate, load_default_data with params {\"lang\": \"en\"}, assets_precompile; " + unit);
                else
                    steps.push(db + "site_task bundle_install, then db_prepare and assets_precompile; " + unit);
            } else if (sf.python_root && facts["manage_py"].boolean()) {
                // A Django project from an archive: its packages, its settings and its admin through
                // the preset's tasks; the project's package must be what the site names.
                steps.push("site_task venv_create, pip_install_requirements" + std::string(facts["requirements_txt"].boolean() ? "" : " (the archive has no requirements.txt: "
                           "it must bring one, or pip_install gives the packages it needs)") + ", pip_install with packages \"gunicorn\" (the user confirms it), "
                           "django_settings, migrate, collectstatic; "
                           "site_env_set with generate: [\"DJANGO_SUPERUSER_PASSWORD\"] and site_task createsuperuser for the first admin; then the "
                           "application server: site_service_unit gives its systemd unit for root to install");
                bool found = false;
                std::string names;
                for (const auto& p : facts["wsgi_packages"].items()) {
                    found = found || p.str() == sf.project;
                    names += (names.empty() ? "" : ", ") + std::string(p.str());
                }
                if (!found)
                    warnings.push("the site's project is " + sf.project + ", but " +
                                  (names.empty() ? std::string("no top-level directory of the archive holds wsgi.py") : "the archive's package with wsgi.py is " + names) +
                                  ": site_update with project " + (names.empty() ? std::string("NAME") : names.substr(0, names.find(','))) +
                                  " before django_settings, or the tasks and the unit load a package that does not exist");
            } else if (sf.python_root) {
                steps.push("the archive holds no manage.py at its top: a Django project's directory is the site's root (strip or path place it there)");
            } else if (sf.node_root && facts["package_json"].boolean()) {
                // A Node application from an archive (2026-09-28, the Uptime Kuma report: the answer
                // said to open a browser while nothing ran).
                const bool kuma = facts.get("package_name") == "uptime-kuma";
                if (const std::string want(facts.get("engines_node")), have(facts.get("runtime_node")); !want.empty() && !have.empty()) {
                    const json::Value& m = facts["engines_match"];
                    steps.push("the application asks for node " + want + " (package.json engines) and the node of [control] runtimes (" + sf.node_dir + ") is " + have +
                               (m.is_null() ? std::string(": that range is not one agensio reads, so check it by hand")
                                : m.boolean() ? std::string(": they match")
                                              : std::string(": they do not match, and npm_ci or the application may refuse; root installs a Node that fits (under /opt) "
                                                            "and points runtimes.node at its bin directory (docs/configuration.md 4f), then agensio reload")));
                } else if (!want.empty() && !facts.get("runtime_node_error").empty()) {
                    steps.push("the application asks for node " + want + "; the node of [control] runtimes could not be asked for its version (" +
                               std::string(facts.get("runtime_node_error")) + "): site_tasks_list shows whether it is installed");
                }
                std::string scripts;
                for (const auto& n : facts["scripts"].items()) scripts += (scripts.empty() ? "" : ", ") + std::string(n.str());
                steps.push("site_task npm_ci (the dependencies its package-lock.json pins), then " +
                           (kuma ? std::string("npm_run with params {\"script\": \"download-dist\"} (Uptime Kuma's prebuilt frontend, from its GitHub release)")
                                 : "the post-install steps the application documents, through npm_run with the script's name" +
                                       (scripts.empty() ? std::string() : " (its scripts: " + scripts + ")")));
                if (kuma && !sf.home.empty())
                    steps.push("site_env_set with set: {\"DATA_DIR\": \"" + sf.home + "/data/\", \"UPTIME_KUMA_DB_TYPE\": \"sqlite\"}: DATA_DIR keeps kuma.db, "
                               "which holds the credentials of every monitored service, out of the project, in the site account's own home (Kuma "
                               "makes the directory); the database type skips Kuma's database page, which the first visitor would otherwise answer");
                const std::string guess(facts.get("entry_guess"));
                if (!guess.empty() && guess != sf.entry)
                    steps.push("site_update with entry \"" + guess + "\": the file node runs (package.json's start script names it)");
                else if (guess.empty() && sf.entry.empty())
                    steps.push("site_update with entry: the file node runs, relative to the project (package.json names none in its start script or main)");
                steps.push("then the application server: site_service_unit gives its systemd unit for root to install");
                if (kuma)
                    steps.push("Uptime Kuma creates its admin account in the browser on the first visit: whoever opens the site first becomes its "
                               "admin, so the user opens https://" + sf.key + "/ right after the service starts");
                if (!facts["lockfile"].boolean())
                    warnings.push("the archive has no package-lock.json: npm_ci installs only what a lockfile pins, and the application's release should carry one");
            } else if (sf.node_root) {
                steps.push("the archive holds no package.json at its top: a Node application's directory is the site's root (strip or path place it there)");
            } else {
                steps.push("open the site in a browser to finish the application's own setup (database, admin account)");
            }
            // The failure tier of fail2ban (docs/configuration.md 18): what the user does in the
            // application so that failed logins are counted, never done by agensio (the owner's
            // rule: it suggests, its own work ends at its files).
            if (const SiteConfig* fsite = control::find_site(backend_->running(), sf.key))
                for (const auto& step : control::failure_tier_steps(sf.app, fsite->root, fsite->user.empty() ? sf.key : std::string())) steps.push(step);
            // The directories the application's own .htaccess files deny, as the matching rule
            // (2026-10-01): under the served root only, the project directory's subdirectory
            // of a Laravel or Drupal root stripped.
            if ((php_app(sf.app) || sf.app == "static") && !facts["htaccess_denied"].items().empty()) {
                std::string list;
                for (const auto& d : facts["htaccess_denied"].items()) {
                    std::string rel(d.str());
                    if (sf.served_sub.empty() || rel.starts_with(sf.served_sub + "/")) {
                        if (!sf.served_sub.empty()) rel.erase(0, sf.served_sub.size() + 1);
                        list += (list.empty() ? "" : ", ") + std::string("\"/") + rel + "/\"";
                    }
                }
                if (!list.empty()) {
                    // First of the steps (2026-10-02 report): the site is exposed until the rule runs.
                    json::Value first = json::Value::array().push(
                        "first, before the site is opened: the application's own .htaccess files deny " + list +
                        " to the web (Apache's rule; agensio never reads .htaccess when serving): site_update with rules: {\"private\": [" + list +
                        "]} denies them here, and rules.entry_points names the only .php files that run when its documentation lists them");
                    for (const auto& x : steps.items()) first.push(x);
                    steps = std::move(first);
                }
            }
            if (!sf.body_step.empty()) steps.push(sf.body_step);
            if (!file.empty()) steps.push("the upload " + file + " is still stored; delete it with uploads delete " + file + " when no longer needed");
            r.set("next_steps", steps);
            if (sf.app == "proxy" && facts["package_json"].boolean() && !facts["gemfile"].boolean())
                warnings.push("this is a Node application (package.json): site_update with app \"node\" gives the site npm_ci, npm_run and a unit that runs it; "
                              "app = \"proxy\" only forwards to an application that something else runs");
            if (sf.app == "rails" && facts["redmine"].boolean())  // the archive is Redmine: its preset has the tasks it needs
                warnings.push("this is Redmine (lib/redmine/version.rb): site_update with app \"redmine\" gives the site its tasks (gemfile_local for Puma, "
                              "load_default_data, plugins_migrate) and its credential files");
            // An application that came without Rails credentials reads SECRET_KEY_BASE from its
            // environment (every ONCE application, every Kamal deployment): a fresh install
            // gets one, once. Never for an application with credentials, whose own secret an
            // environment value would override, signing its users out.
            // A Django project's secret key likewise: agensio_settings.py reads DJANGO_SECRET_KEY.
            const bool rails_secret = sf.rails_root && facts["gemfile"].boolean() && !facts["credentials"].boolean();
            const bool django_secret = sf.python_root && facts["manage_py"].boolean();
            if (rails_secret || django_secret) {
                const std::string name = rails_secret ? "SECRET_KEY_BASE" : "DJANGO_SECRET_KEY";
                const std::string before_task = rails_secret ? "db_prepare" : "django_settings";
                const std::string why = rails_secret ? "the application came without Rails credentials, so it reads its secret from the environment"
                                                     : "agensio_settings.py (django_settings) reads the project's secret key from there";
                const json::Value change = json::Value::object().set("op", "env_write").set("site", sf.key).set("generate", json::Value::array().push(name));
                backend_->env_async(change, [this, &s, what, r, warnings, name, before_task, why, done](json::Value e) mutable {
                    json::Value made = json::Value::array();
                    if (!e["ok"].boolean()) {
                        warnings.push(name + " could not be written into the site's environment (" + std::string(e.get("error")) +
                                      "); run site_env_set with generate: [\"" + name + "\"] before " + before_task);
                    } else if (!e["generated"].items().empty()) {
                        made.push(name + " generated into " + std::string(e.get("file")) + ": " + why + "; the tasks and its service read that file");
                        audit_peer(s, what, "generated " + name + " into " + std::string(e.get("file")));
                    } else {
                        made.push(name + " was already in the site's environment (" + std::string(e.get("file")) + "); kept");
                    }
                    r.set("done", made);
                    if (!warnings.items().empty()) r.set("warnings", warnings);
                    reply(s, 201, r);
                    done();
                });
                return;
            }
            if (!warnings.items().empty()) r.set("warnings", warnings);
            reply(s, 201, r);
        }
        done();
    });
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
    // With the provisioning helper, the blocking problems that have a fix are done here and
    // now instead of handed back as commands; what the helper refuses comes back as such.
    json::Value done = json::Value::array();
    std::vector<control::Problem> remaining;
    if (!dry_run && blocking && backend_->provision_available()) {
        for (const auto& p : problems) {
            if (!p.blocks || p.fix.is_null()) {
                remaining.push_back(p);
                continue;
            }
            const json::Value r = backend_->provision(p.fix);
            if (r["ok"].boolean()) {
                done.push(p.code + ": " + std::string(p.fix.get("op")) + (p.fix.get("name").empty() ? "" : " " + std::string(p.fix.get("name"))) +
                          (p.fix.get("dir").empty() ? "" : " " + std::string(p.fix.get("dir"))));
                audit_peer(s, what, "provisioned " + p.code + " " + p.fix.dump());
            } else {
                control::Problem left = p;
                left.detail += " (the helper refused: " + std::string(r.get("error")) + ")";
                remaining.push_back(left);
                audit_peer(s, what, "helper refused " + p.fix.dump() + ": " + std::string(r.get("error")));
            }
        }
        blocking = false;
        for (const auto& p : remaining) blocking = blocking || p.blocks;
    } else {
        remaining = problems;
    }
    // A listener without a catch-all answers 421 to any other Host: say so once, here.
    json::Value warnings = json::Value::array();
    if (!spec.root.empty() && spec.app != "static" && !proxy_app(spec.app)) {
        const std::string detected = control::detect_app(spec.root);
        if (!detected.empty() && detected != spec.app && detected != "static" && detected != "proxy" && detected != "php")
            warnings.push("the files under " + spec.root + " look like " + detected + " (" + control::detect_app_marker(detected) +
                          "), not " + spec.app + ": the " + spec.app + " preset's refusals do not fit them (health reports it as preset_mismatch); use app: " + detected);
    }
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
                          .set("problems", problems_json(remaining)).set("run_as_root", commands_of(remaining, true))
                          .set("done", done).set("spec", spec.to_json()));
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
        const bool helper = backend_->provision_available();
        if (helper) backend_->restart_later();
        reply(s, 202, json::Value::object().set("ok", true).set("file", file.string()).set("needs_restart", true).set("waiting", !helper)
                          .set("restarting", helper).set("problems", problems_json(remaining)).set("run_as_root", helper ? json::Value::array() : commands_of(remaining, false))
                          .set("hint", helper ? "the site file is written and valid; the service restarts in a moment and serves it"
                                              : "the site file is written and valid; it is served once the service restarts")
                          .set("done", done).set("spec", spec.to_json()).set("next_steps", strings(control::next_steps(spec, cfg))).set("warnings", warnings));
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
    done.push("site file " + file.string() + " written, agensio reloaded");
    // The rest of the root work, when the helper is there: the site's log to its group, the
    // php-fpm pool written and reloaded. next_steps then holds only what remains.
    std::vector<std::string> steps = control::next_steps(spec, cfg);
    if (backend_->provision_available() && !spec.user.empty() && !spec.access_log.empty()) {
        const std::string group = spec.group.empty() ? spec.user : spec.group;
        const json::Value r = backend_->provision(json::Value::object().set("op", "log_own").set("file", spec.access_log).set("group", group));
        // What is claimed under done was seen on disk, not inferred from the helper's reply.
        const HostFacts facts = system_facts();
        FileFacts f;
        unsigned gid = 0;
        const bool handed = r["ok"].boolean() && facts.stat(spec.access_log, f) && facts.group(group, gid) && f.gid == gid && (f.mode & 0040);
        if (handed) done.push("log " + spec.access_log + " readable by " + spec.user + " (group " + group + ", 0640)");
        else warnings.push("the site's log " + spec.access_log + " is not readable by " + spec.user + (r["ok"].boolean() ? "" : " (the helper refused: " + std::string(r.get("error")) + ")") +
                           "; as root: chown " + std::string(cfg.user.empty() ? "agensio" : cfg.user) + ":" + group + " " + spec.access_log + " && chmod 0640 " + spec.access_log);
    }
    finish_pool(s, spec, cfg, what, done, steps);
    for (const auto& p : protection_steps()) steps.push_back(p);
    reply(s, 201, json::Value::object().set("ok", true).set("file", file.string()).set("spec", spec.to_json())
                      .set("done", done).set("next_steps", strings(steps)).set("warnings", warnings));
}

void ControlHandler::finish_pool(Stream& s, const control::SiteSpec& spec, const Config& cfg, std::string_view what, json::Value& done, std::vector<std::string>& steps) {
    const bool php = php_app(spec.app);
    if (!(php && !spec.user.empty() && spec.php_socket.empty())) return;
    if (!backend_->provision_available()) return;  // next_steps already name agensio pools and the reload
    const json::Value r = backend_->provision(json::Value::object().set("op", "pools_apply"));
    if (r["ok"].boolean()) {
        std::string text(r.get("output"));
        while (!text.empty() && (text.back() == '\n' || text.back() == ' ')) text.pop_back();
        done.push("php-fpm pool agensio-" + spec.user + ": " + text);
        audit_peer(s, what, "pool applied: " + text);
        std::vector<std::string> rest;
        for (const auto& st : steps)
            if (st != "agensio pools" && !st.starts_with("systemctl reload php") && !st.starts_with("brew services")) rest.push_back(st);
        steps = rest;
    } else {
        steps.insert(steps.begin(), "# the helper could not apply the pool (" + std::string(r.get("error")) + "); run: agensio pools");
    }
    (void)cfg;
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
                          .set("file", file.string())
                          .set("hint", "edit the file by hand and reload; a site the tools manage takes root's extra locations in " +
                                           std::string(kRootAdditionsSuffix) + " beside its file instead (site_show: root_additions), so it stays managed"));
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
    json::Value done = json::Value::array();
    std::vector<control::Problem> remaining;
    if (blocking && backend_->provision_available()) {
        for (const auto& p : problems) {
            if (!p.blocks || p.fix.is_null()) {
                remaining.push_back(p);
                continue;
            }
            const json::Value r = backend_->provision(p.fix);
            if (r["ok"].boolean()) {
                done.push(p.code + ": " + std::string(p.fix.get("op")));
                audit_peer(s, what, "provisioned " + p.code + " " + p.fix.dump());
            } else {
                control::Problem left = p;
                left.detail += " (the helper refused: " + std::string(r.get("error")) + ")";
                remaining.push_back(left);
            }
        }
        blocking = false;
        for (const auto& p : remaining) blocking = blocking || p.blocks;
    } else {
        remaining = problems;
    }
    if (blocking) {
        reply(s, 409, json::Value::object().set("error", "prerequisites missing").set("waiting", true)
                          .set("problems", problems_json(remaining)).set("run_as_root", commands_of(remaining, true)).set("done", done));
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
    json::Value done_now = done;
    done_now.push("site file " + file.string() + " written, agensio reloaded");
    std::vector<std::string> steps = control::next_steps(spec, cfg);
    finish_pool(s, spec, cfg, what, done_now, steps);
    for (const auto& p : protection_steps()) steps.push_back(p);
    reply(s, 200, json::Value::object().set("ok", true).set("file", file.string()).set("spec", spec.to_json())
                      .set("done", done_now).set("next_steps", strings(steps)));
}

void ControlHandler::site_toggle(Stream& s, std::string_view name, std::string_view action, std::string_view what) {
    const Config& cfg = backend_->running();
    // An application site's environment file, named in a delete's answer; the path is taken
    // now, as the reload below replaces the configuration `cfg` refers to.
    std::optional<std::string> env_file;
    int env_state = -1;
    std::vector<std::string> env_exposed;
    if (const SiteConfig* site = control::find_site(cfg, name); action == "delete" && site && proxy_app(site->app) && appenv::valid_site(site->server_names.front())) {
        env_file = appenv::dir_of(cfg.config_path) + "/" + site->server_names.front() + ".env";
        env_state = backend_->env_file_state(site->server_names.front(), env_exposed);  // asked while the site is still on disk
    }
    const std::filesystem::path file = control::site_file(cfg, name);
    const std::filesystem::path disabled = file.string() + ".disabled";
    std::error_code ec;
    std::string error;
    // Root's additions to the site (design section 20) go aside with the site file on a plain
    // delete, each as <file>.bak beside the site file's .bak: the loader ignores .bak files, so
    // no orphan warning follows, and a rename keeps the file root's. The running site names
    // the files the loader merged; the canonical name covers a site deleted while disabled.
    std::vector<std::string> set_aside;
    if (action == "delete") {
        if (const SiteConfig* site = control::find_site(cfg, name))
            for (const auto& f : site->root_additions)
                if (std::filesystem::path(f).parent_path() == file.parent_path() && std::filesystem::exists(f, ec)) set_aside.push_back(f);
        const std::string canonical = (file.parent_path() / (std::string(name) + std::string(kRootAdditionsSuffix))).string();
        if (std::find(set_aside.begin(), set_aside.end(), canonical) == set_aside.end() && std::filesystem::exists(canonical, ec)) set_aside.push_back(canonical);
    }
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
        for (const auto& f : set_aside)
            if (!ec) std::filesystem::rename(f, f + ".bak", ec);
    }
    if (ec) {
        reply(s, 500, json::Value::object().set("error", ec.message()));
        return;
    }
    if (!backend_->reload_now(error)) {
        if (action == "disable") std::filesystem::rename(disabled, file, ec);
        else if (action == "enable") std::filesystem::rename(file, disabled, ec);
        else {
            std::filesystem::rename(file.string() + ".bak", file, ec);
            for (const auto& f : set_aside) std::filesystem::rename(f + ".bak", f, ec);
        }
        audit_peer(s, what, "refused: " + error);
        reply(s, 409, json::Value::object().set("error", "reload refused; file restored").set("detail", error));
        return;
    }
    std::string aside_note;
    for (const auto& f : set_aside) aside_note += (aside_note.empty() ? "" : ", ") + f + " -> " + f + ".bak";
    audit_peer(s, what, std::string(action) + " " + file.string() + (aside_note.empty() ? "" : "; root additions set aside: " + aside_note));
    json::Value body = json::Value::object().set("ok", true).set("file", file.string()).set("action", std::string(action));
    if (const auto ps = protection_steps(); !ps.empty()) body.set("next_steps", strings(ps));
    if (!set_aside.empty()) {
        std::vector<std::string> baks;
        for (const auto& f : set_aside) baks.push_back(f + ".bak");
        body.set("root_additions_set_aside", strings(baks))
            .set("root_additions_note", "root's additions to the site were renamed .bak beside the site file's .bak, still root's; rename both back to bring the site back with them, or remove them once the site is gone for good");
    }
    // A deleted application site's environment stays, as its files do (2026-09-27 report: it
    // holds secrets and nothing said so). The server cannot look inside root's directory.
    // Named when it exists (the helper says; 2026-09-27 report), said as "if it has one" only
    // when the helper was busy and could not tell, and not at all when there is none.
    if (env_file && env_state != 0) {
        const std::string& env = *env_file;
        body.set("kept", json::Value::array().push("the site's environment " + env + (env_state == 1 ? "" : ", if it has one (the helper was busy and could not tell)") +
                                                    ": its secrets (SECRET_KEY_BASE and the like), kept as the site's directory and account are"))
            .set("run_as_root", json::Value::array().push("rm -f " + env));
        std::string names;
        for (const auto& n : env_exposed) names += (names.empty() ? "" : ", ") + n;
        const bool one = env_exposed.size() == 1;
        body.set("hint", names.empty() ? "run_as_root removes the environment file once the site is gone for good; keep it to bring the site back with the same secrets"
                                       : names + " in it " + (one ? "was" : "were") + " readable by others and never rotated: bringing the site back with this file brings " +
                                             (one ? "that value" : "those values") + " back, so rotate " + (one ? "it" : "them") +
                                             " then (site_env_set), or remove the file with run_as_root once the site is gone for good");
        if (!names.empty()) body.set("exposed", strings(env_exposed));
    }
    reply(s, 200, body);
}

// One of the site's files copied to another path of the same site (F9b): the drop-in
// files applications ship as templates (wp-content/db.php from a plugin's db.copy,
// Drupal's settings.php from default.settings.php). Never across sites, never content
// from the caller, never a directory: the smallest primitive that covers those cases.
void ControlHandler::site_copy(Stream& s, std::string_view name, const json::Value& body, std::string_view what, std::function<void()> done) {
    const Config& cfg = backend_->running();
    const SiteConfig* site = control::find_site(cfg, name);
    if (!site) {
        reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        done();
        return;
    }
    const std::string site_root = site->project_root.empty() ? site->root : site->project_root;
    std::string from, to, why;
    if (!archive::clean_path(body.get("from"), from, why)) {
        reply(s, 400, json::Value::object().set("error", "from must be a relative path below the site's directory, without '..': " + why));
        done();
        return;
    }
    if (!archive::clean_path(body.get("to"), to, why)) {
        reply(s, 400, json::Value::object().set("error", "to must be a relative path below the site's directory, without '..': " + why));
        done();
        return;
    }
    if (from == to) {
        reply(s, 400, json::Value::object().set("error", "from and to are the same path"));
        done();
        return;
    }
    if (site_root.empty() || !control::safe_path(site_root, why)) {
        reply(s, 409, json::Value::object().set("error", "the site's directory is not a path a copy can use: " + why));
        done();
        return;
    }
    const bool overwrite = body["overwrite"].boolean(), dry_run = body["dry_run"].boolean();
    json::Value req = json::Value::object().set("op", "file_copy").set("site_root", site_root).set("from", from).set("to", to)
                          .set("overwrite", overwrite).set("dry_run", dry_run).set("secrets", site_secrets(*site, site_root));
    if (!site->user.empty()) req.set("user", site->user);
    if (!dry_run) audit_peer(s, what, "copying " + from + " to " + to + " in " + site_root + (overwrite ? " (overwrite)" : ""));
    const std::vector<std::string> before = dry_run ? std::vector<std::string>{} : validation_errors(*backend_);
    backend_->install_async(req, [this, &s, what = std::string(what), dry_run, before, done](json::Value r) {
        const bool ok = r["ok"].boolean();
        if (dry_run) {
            if (ok) reply(s, 200, r.set("hint", "nothing was written; the same call without dry_run copies"));
            else reply(s, 409, json::Value::object().set("ok", false).set("dry_run", true).set("error", r.get("error")));
            done();
            return;
        }
        const bool replaced = !r["replaced"].is_null();
        audit_peer(s, what, ok ? (replaced ? "replaced " : "wrote ") + std::string(r.get("to")) + " from " + std::string(r.get("from")) + " (" + std::string(r.get("as")) + " " + std::string(r.get("mode")) + (r["secured"].boolean() ? ", credentials" : "") + ", " + std::to_string(static_cast<long>(r["bytes"].num())) + " bytes)"
                              : "failed: " + std::string(r.get("error")));
        if (!ok) {
            reply(s, 409, json::Value::object().set("ok", false).set("error", r.get("error")));
        } else if (const json::Value fresh = new_errors(before, validation_errors(*backend_)); !fresh.items().empty()) {
            audit_peer(s, what, "written, but the configuration no longer validates: " + fresh.dump());
            reply(s, 409, r.set("ok", false).set("written", true).set("error", "the file is written, but the configuration no longer validates; agensio -t and a restart would refuse it")
                              .set("errors", fresh).set("hint", "fix what the errors name (health lists them with a fix each), then config_validate"));
        } else {
            if (!before.empty()) r.set("warnings", json::Value::array().push("the configuration already failed validation before this call (health lists the findings); the copy itself is fine"));
            reply(s, replaced ? 200 : 201, r);
        }
        done();
    });
}

namespace {

// One argument as a shell would need it written, for the audit line (nothing is ever run
// through a shell; the line should still read back as the exact argv).
std::string shell_word(const std::string& a) {
    if (!a.empty() && a.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-./=:,+@%") == std::string::npos) return a;
    std::string out = "'";
    for (char c : a) out += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return out + "'";
}

}  // namespace

// site-task (F13): one named task of the site's preset, run as the site's account in the
// site's directory, through the helper (or as this process's account without one). The
// caller names the task and gives parameters; the command is the table's (services/tasks).
void ControlHandler::site_task(Stream& s, std::string_view name, const json::Value& body, std::string_view what, std::function<void()> done) {
    const Config& cfg = backend_->running();
    auto answer = [&](int status, const json::Value& v) {
        reply(s, status, v);
        done();
    };
    const SiteConfig* site = control::find_site(cfg, name);
    if (!site) return answer(404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
    const std::string app = site->app.empty() ? "static" : site->app;
    if (!tasks::has_tasks(app))
        return answer(422, json::Value::object().set("error", "app = \"" + app + "\" has no tasks").set("app", app)
                               .set("hint", "tasks belong to a preset: app = \"rails\", \"redmine\", \"django\" and \"wagtail\" have them (site_tasks_list shows a site's). "
                                       "agensio runs no other command."));
    const std::string task(body.get("task"));
    const tasks::Row* row = tasks::find(app, task);
    if (!row) {
        json::Value names = json::Value::array();
        for (const auto& n : tasks::names(app)) names.push(n);
        return answer(400, json::Value::object().set("error", task.empty() ? "which task? give task: one of the preset's (tasks)" : "no task '" + task + "' for app = \"" + app + "\"")
                               .set("tasks", std::move(names)));
    }
    const json::Value params = body["params"].is_null() ? json::Value::object() : body["params"];
    if (std::string bad = tasks::check_params(*row, params); !bad.empty()) return answer(400, json::Value::object().set("error", bad).set("task", task));
    const std::string site_root = site->project_root.empty() ? site->root : site->project_root;
    std::string why;
    if (site_root.empty() || !control::safe_path(site_root, why))
        return answer(409, json::Value::object().set("error", "the site has no directory a task can run in" + (why.empty() ? std::string() : ": " + why))
                               .set("hint", "the site's root is the project directory tasks run in; site_update sets it"));
    const bool dry_run = body["dry_run"].boolean();
    const std::string key = site->server_names.front();
    // A task whose caller names what gets installed (pip_install) runs only when the user confirmed
    // it in person (2026-09-28, the owner's decision): the MCP bridge after the client's own dialog
    // (user_confirmed "mcp"), agensio ctl in a terminal ("terminal"). An agent's confirm is not
    // enough, and the bridge never passes one of its arguments as this field.
    std::string confirmed_how;
    if (row->user_confirm && !dry_run) {
        const std::string how(body.get("user_confirmed"));
        if (how != "mcp" && how != "terminal") {
            std::string given;
            for (const auto& m : params.members()) given += " --param " + shell_word(m.first + "=" + m.second.str());
            return answer(428, json::Value::object()
                                   .set("error", "task " + task + " runs only when the user confirms it in person: the MCP bridge asks in the client's own dialog, "
                                                 "agensio ctl in the terminal")
                                   .set("warning", tasks::confirmation_warning(key, params.get("packages"), site->user, ""))
                                   .set("run_in_terminal", "agensio ctl site-task " + key + " " + task + given + " --yes --reason \"...\""));
        }
        std::string client(body.get("client"));
        client = tasks::clean_text(client.substr(0, 80));
        for (char& c : client)
            if (c == '\n' || c == '\r') c = ' ';
        confirmed_how = how == "mcp" ? "confirmed by the user in the MCP client's dialog" + (client.empty() ? std::string() : " (" + client + ")")
                                     : std::string("confirmed by the user in a terminal (agensio ctl)");
    }
    if (!dry_run)
        if (const auto it = running_tasks_.find(key); it != running_tasks_.end())
            return answer(409, json::Value::object().set("error", "a task is already running on this site: " + it->second + "; one task per site at a time").set("running", it->second));
    json::Value req = json::Value::object().set("op", "task_run").set("site", key).set("task", task).set("params", params).set("dry_run", dry_run)
                          .set("app", app).set("root", site_root).set("secrets", site_secrets(*site, site_root));
    if (python_app(app)) {  // what a Django site's tasks are told (the helper derives the same from the file on disk)
        const AppContext ac = app_context(cfg, *site);
        req.set("project", site->project).set("hosts", ac.hosts).set("origins", ac.origins).set("base_url", ac.base_url)
            .set("https_redirect", ac.https_redirect).set("hsts", ac.hsts);
    }
    if (!dry_run) {
        running_tasks_[key] = task + " (since " + now_stamp() + ")";
        std::string given;
        for (const auto& m : params.members()) given += " " + m.first + "=" + m.second.str();
        audit_peer(s, what, "running task " + task + given + " in " + site_root + (confirmed_how.empty() ? std::string() : ", " + confirmed_how));
    }
    const std::vector<std::string> before = dry_run ? std::vector<std::string>{} : validation_errors(*backend_);
    // A running Rails application loads its gems, schema and assets at start: after a task
    // that changes them the answer carries root's restart line (alpha.33 report, P3).
    std::string restart;
    if (service_app(app) && !site->user.empty())
        for (const char* t : {"bundle_install", "db_migrate", "db_prepare", "plugins_migrate", "assets_precompile", "pip_install_requirements",
                              "pip_install", "django_settings", "migrate", "collectstatic", "npm_ci", "npm_run"})
            if (task == t) restart = "agensio-app-" + site->user + ".service";
    backend_->task_async(req, [this, &s, what = std::string(what), key, task, dry_run, before, restart, done](json::Value r) {
        if (!dry_run) running_tasks_.erase(key);
        // The whole output stays here; the answer carries its end on success, its start and
        // end on failure, and says how to read the rest.
        if (!dry_run && r["ran"].boolean() && r.get("wrote").empty()) {
            TaskOutput& o = last_output_[key];
            o.task = task;
            o.at = now_stamp();
            o.text = std::string(r.get("output"));
            o.total = r["output_bytes"].num();
            o.cut = r["truncated"].boolean();
            const bool success = r["ok"].boolean();
            const std::size_t head = success ? 0 : 4096, tail = success ? 4096 : 12288;
            if (o.text.size() > head + tail) {
                auto boundary = [&](std::size_t at) {  // never inside a UTF-8 character
                    while (at < o.text.size() && (static_cast<unsigned char>(o.text[at]) & 0xc0) == 0x80) ++at;
                    return at;
                };
                const std::size_t tail_at = boundary(o.text.size() - tail), head_end = boundary(head);
                const std::string marker = "[... " + std::to_string(tail_at - head_end) + " bytes not shown: site_task_output reads the whole output ...]\n";
                r.set("output", o.text.substr(0, head_end) + (head_end ? "\n" : "") + marker + o.text.substr(tail_at));
                r.set("truncated", true);
            }
            r.set("output_kept", static_cast<double>(o.text.size()));
        }
        log_exposures(r);
        const bool ok = r["ok"].boolean();
        if (dry_run) {
            if (ok) reply(s, 200, r.set("hint", "nothing ran; the same call without dry_run runs exactly this"));
            else reply(s, 409, r.set("dry_run", true));
            done();
            return;
        }
        // The audit line says what actually ran (the argv the helper executed), as whom,
        // and how it ended; the output stays in the answer.
        if (!r["ran"].boolean()) {
            audit_peer(s, what, "refused: " + std::string(r.get("error")));
        } else if (!r.get("wrote").empty()) {  // a template row: a fixed file, no program
            audit_peer(s, what, "wrote " + std::string(r.get("wrote")) + " (" + std::string(r.get("mode")) + ") as " + std::string(r.get("as")) +
                                    " from the fixed template of " + std::string(r.get("task")) +
                                    (r.get("replaced").empty() ? std::string() : ", replacing " + std::string(r.get("replaced"))));
        } else {
            std::string argv;
            for (const auto& a : r["argv"].items()) argv += (argv.empty() ? "" : " ") + shell_word(a.str());
            // A row that runs root's interpreter under another name (a site's virtualenv) says both.
            if (const std::string prog(r.get("program")); !prog.empty() && !r["argv"].items().empty() && r["argv"].items().front().str() != prog)
                argv = shell_word(prog) + " as " + argv;
            std::string end = r["timed_out"].boolean() ? "stopped at the time limit"
                              : !r["signal"].is_null() ? "signal " + std::to_string(static_cast<int>(r["signal"].num()))
                              : r["exit"].is_null() ? "did not end" : "exit " + std::to_string(static_cast<int>(r["exit"].num()));
            end += " after " + std::to_string(static_cast<long>(r["duration_ms"].num() / 1000)) + " s";
            if (!r["secured"].items().empty()) end += ", secured " + std::to_string(r["secured"].items().size()) + " credential path(s)";
            audit_peer(s, what, "ran as " + std::string(r.get("as")) + " in " + std::string(r.get("cwd")) + ": " + argv + " -> " + end);
        }
        if (!ok) {
            reply(s, 409, r.set("ok", false));
        } else if (const json::Value fresh = new_errors(before, validation_errors(*backend_)); !fresh.items().empty()) {
            audit_peer(s, what, "ran, but the configuration no longer validates: " + fresh.dump());
            reply(s, 409, r.set("ok", false).set("error", "the task ran, but the configuration no longer validates; agensio -t and a restart would refuse it")
                              .set("errors", fresh).set("hint", "fix what the errors name (health lists them with a fix each), then config_validate"));
        } else {
            if (!before.empty()) r.set("warnings", json::Value::array().push("the configuration already failed validation before this task (health lists the findings); the task itself is fine"));
            json::Value steps = json::Value::array();
            if (!restart.empty())
                steps.push("if " + restart + " already runs (site_service_status " + key + "), as root: systemctl restart " + restart +
                           " (the application loads this change only when it starts)");
            if (task == "createsuperuser")
                steps.push("the admin's password is DJANGO_SUPERUSER_PASSWORD in the site's environment: site_env with reveal: [\"DJANGO_SUPERUSER_PASSWORD\"] "
                           "shows it, only when the user asks to see it; the unit site_service_unit renders keeps it from the application "
                           "(UnsetEnvironment=), and the user may change it in the application's admin");
            if (!steps.items().empty()) r.set("next_steps", std::move(steps));
            reply(s, 200, r);
        }
        done();
    });
}

// A site's application environment (services/appenv.*; 2026-09-27 Writebook report): the
// variables its tasks and its service get, SECRET_KEY_BASE above all. Admin only both
// ways; a read is audited with the names it returned, a write with the names it changed,
// never a value.
namespace {

const SiteConfig* env_site(const Config& cfg, std::string_view name, int& status, json::Value& refusal) {
    const SiteConfig* site = control::find_site(cfg, name);
    if (!site) {
        status = 404;
        refusal = json::Value::object().set("error", "no such site").set("site", std::string(name));
        return nullptr;
    }
    if (!proxy_app(site->app)) {
        status = 422;
        refusal = json::Value::object().set("error", "site " + std::string(name) + " has app = \"" + (site->app.empty() ? std::string("static") : site->app) +
                                                         "\"; a site's environment is for applications agensio runs (app = \"rails\", \"redmine\", \"django\", \"wagtail\", \"node\" or \"proxy\")")
                      .set("app", site->app);
        return nullptr;
    }
    if (!appenv::valid_site(site->server_names.front())) {
        status = 422;
        refusal = json::Value::object().set("error", "the site's first name (" + site->server_names.front() + ") is not a host name an environment file can carry");
        return nullptr;
    }
    return site;
}

std::string joined(const json::Value& names) {
    std::string out;
    for (const auto& n : names.items()) out += (out.empty() ? "" : ", ") + std::string(n.str());
    return out;
}

}  // namespace

void ControlHandler::log_exposures(const json::Value& r) {
    for (const auto& n : r["tightened"].items())
        if (n.is_string() && n.str().find("rotate what it holds") != std::string_view::npos) log_.warn("site environment: " + std::string(n.str()));
}

void ControlHandler::site_service(Stream& s, std::string_view name, bool logs, std::function<void()> done) {
    const SiteConfig* site = control::find_site(backend_->running(), name);
    if (!site) {
        reply(s, 404, json::Value::object().set("error", "no such site").set("site", std::string(name)));
        done();
        return;
    }
    if (!service_app(site->app) || site->user.empty()) {
        reply(s, 409, json::Value::object()
                          .set("error", "site " + site->server_names.front() + " has no application service")
                          .set("hint", "a Rails or Django site (app = \"rails\", \"redmine\", \"django\" or \"wagtail\") with its own user has one, "
                                       "agensio-app-<user>.service, rendered by site_service_unit"));
        done();
        return;
    }
    const std::string key = site->server_names.front();
    json::Value req = json::Value::object().set("op", logs ? "app_logs" : "app_status").set("site", key);
    if (logs) {
        const std::string lines = control::query_value(s.request.target, "lines");
        const std::string since = control::query_value(s.request.target, "since");
        if (!lines.empty()) {
            const long n = lines.size() <= 4 && lines.find_first_not_of("0123456789") == std::string::npos ? std::strtol(lines.c_str(), nullptr, 10) : 0;
            if (n < 1 || n > 1000) {
                reply(s, 400, json::Value::object().set("error", "lines is 1 to 1000 (200 when absent)"));
                done();
                return;
            }
            req.set("lines", static_cast<double>(n));
        }
        if (!since.empty()) {
            if (since.size() < 2 || since.size() > 5 || since.find_first_not_of("0123456789") != since.size() - 1 ||
                std::string("smhd").find(since.back()) == std::string::npos) {
                reply(s, 400, json::Value::object().set("error", "since is a number and s, m, h or d, e.g. 30m or 3h"));
                done();
                return;
            }
            req.set("since", since);
        }
    }
    const bool python = python_app(site->app), node = node_app(site->app);
    backend_->helper_async(req, [this, &s, key, logs, python, node, done](json::Value r) {
        if (r["busy"].boolean()) {
            reply(s, 503, json::Value::object()
                              .set("error", "the provisioning helper is busy with a task or an install; ask again when it finishes")
                              .set("busy", true));
        } else if (!r["ok"].boolean()) {
            if (logs) audit_peer(s, "sites/" + key + "/service/logs", "refused: " + std::string(r.get("error")));
            reply(s, 409, r);
        } else if (logs) {
            const std::string& out = r["output"].str();
            const auto count = std::count(out.begin(), out.end(), '\n');
            audit_peer(s, "sites/" + key + "/service/logs", "read " + std::to_string(count) + " lines of the journal of " + std::string(r.get("unit")));
            r.set("hint", out.empty() ? "the journal holds nothing for this unit in that window: it never ran, or ran before the window"
                                      : std::string("the application's own lines as systemd kept them, newest last; ") +
                                            (python ? "a Python traceback (its last line names the exception: ModuleNotFoundError, "
                                                      "ImproperlyConfigured, OperationalError), 'Address already in use' or a Gunicorn "
                                                      "'Worker failed to boot'"
                                             : node ? "a Node stack trace (Error: Cannot find module, EADDRINUSE, EACCES), or the application's own "
                                                      "last words before it exited"
                                                    : "a Ruby backtrace or 'Address already in use'") +
                                            " usually names the cause. After a fix, root restarts the unit");
            reply(s, 200, r);
        } else {
            const json::Value& st = r["state"];
            const std::string unit(r.get("unit")), load(st.get("LoadState")), active(st.get("ActiveState")), sub(st.get("SubState"));
            json::Value steps = json::Value::array();
            std::string summary;
            if (load == "not-found") {
                summary = "no unit " + unit + " on this host: nothing runs the application";
                steps.push("site_service_unit " + key + " renders it; root installs it with the three commands in that answer");
            } else if (active == "active") {
                summary = "running (" + sub + ") since " + std::string(st.get("ActiveEnterTimestamp")) + ", pid " + std::string(st.get("MainPID"));
                if (st.get("UnitFileState") != "enabled") steps.push("as root: systemctl enable " + unit + " (it does not start at boot now)");
            } else if (active == "failed" || (active == "activating" && sub == "auto-restart")) {
                summary = unit + " failed (" + std::string(st.get("Result")) + ", exit status " + std::string(st.get("ExecMainStatus")) + ")";
                steps.push("site_service_logs " + key + " shows why");
                steps.push("after the fix, as root: systemctl restart " + unit);
            } else if (active == "inactive") {
                summary = unit + " is stopped";
                steps.push("as root: systemctl enable --now " + unit);
                steps.push("site_service_logs " + key + " shows its last run");
            } else {
                summary = unit + " is " + active + " (" + sub + ")";
            }
            r.set("summary", summary);
            if (!steps.items().empty()) r.set("next_steps", std::move(steps));
            reply(s, 200, r);
        }
        done();
    });
}

void ControlHandler::site_env_show(Stream& s, std::string_view name, std::function<void()> done) {
    int status = 0;
    json::Value refusal;
    const SiteConfig* site = env_site(backend_->running(), name, status, refusal);
    if (!site) {
        reply(s, status, refusal);
        done();
        return;
    }
    // Names, lengths and fingerprints; a value only for the names in ?reveal=A,B (the owner's
    // decision after the alpha.27 report: a value returned is in the agent's context and
    // transcript, so it leaves the server only when someone asks for that value).
    json::Value reveal = json::Value::array();
    const std::string asked = control::query_value(s.request.target, "reveal");
    for (std::size_t pos = 0; pos < asked.size();) {
        std::size_t comma = asked.find(',', pos);
        if (comma == std::string::npos) comma = asked.size();
        const std::string n = asked.substr(pos, comma - pos);
        pos = comma + 1;
        if (n.empty()) continue;
        if (n.size() > 64 || n.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos) {
            reply(s, 400, json::Value::object().set("error", "reveal names variables: ?reveal=NAME,NAME"));
            done();
            return;
        }
        reveal.push(n);
    }
    const std::string key = site->server_names.front();
    const bool rails = rails_app(site->app), django = python_app(site->app), node = node_app(site->app);
    backend_->env_async(json::Value::object().set("op", "env_read").set("site", key).set("reveal", reveal), [this, &s, key, rails, django, node, done](json::Value r) {
        const std::string what = "sites/" + key + "/env";
        if (!r["ok"].boolean()) {
            audit_peer(s, what, "read refused: " + std::string(r.get("error")));
            reply(s, 409, r);
        } else {
            json::Value names = json::Value::array();
            for (const auto& v : r["variables"].items()) names.push(std::string(v.get("name")));
            std::string line = names.items().empty() ? std::string("read: no variables") : "read the names of " + joined(names);
            if (!r["revealed"].items().empty()) line += "; REVEALED the value of " + joined(r["revealed"]);
            if (!r["tightened"].items().empty()) line += "; tightened: " + joined(r["tightened"]);
            audit_peer(s, what, line);
            log_exposures(r);
            // The hint follows the preset (Django report against alpha.33: a proxy site was told
            // about SECRET_KEY_BASE and tasks it does not have).
            std::string hint;
            if (r["exists"].boolean())
                hint = std::string("names, lengths and fingerprints only (the same fingerprint means the same value); a value is returned only when its "
                                   "name is in reveal, and only when the user asked to see it. site_env_set changes them; ") +
                       (rails || django || node ? "the tasks read the file on their next run, the application when its service restarts"
                                        : "the application reads them when its service restarts, from a unit that loads this file with EnvironmentFile=");
            else if (node)
                hint = "no environment file yet: site_env_set creates it with what the application reads from its environment (an API key, a "
                       "session secret with generate, Uptime Kuma's DATA_DIR); HOST, PORT and NODE_ENV are agensio's (the unit binds the application to "
                       "the upstream's loopback address) and refused. The unit site_service_unit renders loads the file";
            else if (django)
                hint = "no environment file yet: site_env_set creates it (generate: [\"DJANGO_SECRET_KEY\"] for the project's secret key, which "
                       "django_settings needs; generate: [\"DJANGO_SUPERUSER_PASSWORD\"] before createsuperuser; set: {\"DATABASE_URL\": ...} for "
                       "a database other than the project's SQLite)";
            else if (rails)
                hint = "no environment file yet: site_env_set creates it (generate: [\"SECRET_KEY_BASE\"] for a Rails application without credentials, "
                       "set: {\"DATABASE_URL\": ...} for its database)";
            else
                hint = "no environment file yet: site_env_set creates it with what the application reads from its environment: set: {NAME: value} for a "
                       "setting or an API key, generate: [NAME] for a random secret (a Django SECRET_KEY, a session secret). The unit that runs the "
                       "application loads the file with EnvironmentFile=" + std::string(r.get("file"));
            r.set("hint", hint);
            reply(s, 200, r);
        }
        done();
    });
}

void ControlHandler::site_env_set(Stream& s, std::string_view name, const json::Value& body, std::string_view what, std::function<void()> done) {
    int status = 0;
    json::Value refusal;
    const SiteConfig* site = env_site(backend_->running(), name, status, refusal);
    if (!site) {
        reply(s, status, refusal);
        done();
        return;
    }
    appenv::Change change;
    if (std::string bad = appenv::parse_change(body, change); !bad.empty()) {
        reply(s, 400, json::Value::object().set("error", bad)
                          .set("hint", "set: {NAME: value}, unset: [NAME], generate: [NAME] (a random secret for a missing name, e.g. SECRET_KEY_BASE)"));
        done();
        return;
    }
    if (std::string bad = appenv::check_change_for_app(site->app, change); !bad.empty()) {
        reply(s, 400, json::Value::object().set("error", bad));
        done();
        return;
    }
    const std::string key = site->server_names.front();
    json::Value req = json::Value::object().set("op", "env_write").set("site", key);
    for (const char* k : {"set", "unset", "generate"})
        if (!body[k].is_null()) req.set(k, body[k]);
    std::string plan;
    auto list = [&](const char* verb, const std::vector<std::string>& names) {
        if (names.empty()) return;
        std::string n;
        for (const auto& x : names) n += (n.empty() ? "" : ", ") + x;
        plan += (plan.empty() ? "" : "; ") + std::string(verb) + " " + n;
    };
    std::vector<std::string> set_names;
    for (const auto& v : change.set) set_names.push_back(v.name);
    list("set", set_names);
    list("unset", change.unset);
    list("generate", change.generate);
    audit_peer(s, what, "changing the environment: " + plan);
    // The service's restart line (P4 b of the alpha.33 report: it named the example file):
    // a Rails site with its own account has the unit site_service_unit renders; any other
    // proxy site's application is started by whatever root set up for it.
    const std::string restart = service_app(site->app) && !site->user.empty()
        ? "the application reads it when its service restarts: the unit site_service_unit renders loads the file (EnvironmentFile=); as root, systemctl restart agensio-app-" + site->user + ".service"
        : std::string("the application reads it when its service restarts: the unit that runs it must load the file (EnvironmentFile=, the file named above); root restarts that unit");
    const bool django = python_app(site->app);
    backend_->env_async(req, [this, &s, what = std::string(what), restart, django, done](json::Value r) {
        if (!r["ok"].boolean()) {
            audit_peer(s, what, "refused: " + std::string(r.get("error")));
            reply(s, 409, r);
            done();
            return;
        }
        std::string result;
        for (const char* k : {"set", "unset", "generated", "kept", "absent", "tightened"})
            if (!r[k].items().empty()) result += (result.empty() ? "" : "; ") + std::string(k) + " " + joined(r[k]);
        audit_peer(s, what, "environment " + std::string(r.get("file")) + ": " + (result.empty() ? std::string("unchanged") : result) +
                                (r.get("removed").empty() ? "" : "; removed the file, no variable left"));
        log_exposures(r);
        if (!r.get("removed").empty())
            r.set("done", json::Value::array().push("removed " + std::string(r.get("removed")) + ": no variables left (site_env_set creates it again)"));
        if (!r["still_exposed"].items().empty())
            r.set("warnings", json::Value::array().push(joined(r["still_exposed"]) + (r["still_exposed"].items().size() == 1 ? " still holds the value" : " still hold the values") +
                                                         " others could read: give " + (r["still_exposed"].items().size() == 1 ? "it" : "them") +
                                                         " a new value (generate for a generated secret; change a password where it is used too), and health warns until then"));
        json::Value steps = json::Value::array();
        // The first admin's DJANGO_SUPERUSER_* names are createsuperuser's alone: the unit unsets
        // them, so no restart hands them to the application (alpha.35 report, P4 c).
        std::size_t superuser = 0, changed = 0;
        for (const char* k : {"set", "unset", "generated", "kept"})
            for (const auto& n : r[k].items()) {
                ++changed;
                if (n.str().starts_with("DJANGO_SUPERUSER_")) ++superuser;
            }
        if (django && superuser)
            steps.push("DJANGO_SUPERUSER_PASSWORD (and _USERNAME, _EMAIL) are read by site_task createsuperuser alone; the unit site_service_unit "
                       "renders removes them from the application's environment (UnsetEnvironment=), so they need no restart");
        if (!django || superuser < changed) {
            steps.push("the tasks read it from their next run");
            steps.push(restart);
        }
        r.set("next_steps", steps);
        if (!r["kept"].items().empty())
            r.set("hint", "kept " + joined(r["kept"]) + ": generate never replaces a value; to rotate one, unset and generate it in one call "
                          "(a new SECRET_KEY_BASE signs every user out and invalidates signed links)");
        reply(s, 200, r);
        done();
    });
}

}  // namespace agensio
