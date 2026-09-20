#include "control/handler.hpp"

#include <ctime>

#include <chrono>
#include <cstdio>

#include <algorithm>
#include <cerrno>
#include <vector>
#include <memory>
#include <cstring>
#include <filesystem>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include "control/commands.hpp"
#include "control/sites.hpp"
#include "core/body.hpp"
#include "services/archive.hpp"
#include "services/install.hpp"

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
    *step = [this, &s, &ws, state, step, done]() {
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
                              path == "/v1/presets" || path == "/v1/uploads";
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
    std::string_view name, action;
    if (site_path || upload_path) {
        name = path.substr(site_path ? 10 : 12);
        const std::size_t slash = name.find('/');
        if (slash != std::string_view::npos) {
            action = name.substr(slash + 1);
            name = name.substr(0, slash);
        }
    }
    if (path == "/v1/status" || path == "/v1/config/validate" || path == "/v1/logs" || path == "/v1/health" || path == "/v1/presets" ||
        path == "/v1/uploads") {
        s.response.headers.add("Allow", "GET, HEAD");
        reply(s, 405, json::Value::object().set("error", "method not allowed"));
        return false;
    }
    const bool known = path == "/v1/reload" || path == "/v1/sites" || path == "/v1/logs/reopen" ||
                       (site_path && !name.empty() && (action.empty() || action == "disable" || action == "enable" ||
                                                       action == "delete" || action == "renew" || action == "install" || action == "copy")) ||
                       (upload_path && !name.empty() && action == "delete");
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
    if (action == "install" || action == "copy") {
        if (!done) {  // no way to defer: answered synchronously as a refusal
            reply(s, 503, json::Value::object().set("error", "install and copy need an asynchronous caller"));
            return false;
        }
        if (action == "copy") site_copy(s, name, body, what, std::move(done));
        else site_install(s, name, body, what, std::move(done));
        return true;
    }
    site_toggle(s, name, action, what);
    return false;
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
    *step = [this, &s, st, step, done]() {
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
    json::Value req = json::Value::object().set("site_root", site_root).set("target", target).set("create_path", create_path).set("dry_run", dry_run);
    if (!site->user.empty()) req.set("user", site->user);
    if (!url.empty()) req.set("url", url);
    if (!file.empty()) req.set("upload", file);
    if (!sha.empty()) req.set("sha256", sha);
    if (!body["strip"].is_null()) req.set("strip", body["strip"]);
    const std::string source = url.empty() ? "upload " + file : url;
    if (!dry_run) audit_peer(s, what, "installing " + source + " into " + target + (create_path ? " (create_path)" : ""));
    // A dry run takes the same walk as the real call (as the same account) and reports
    // the refusal it would meet or the directories it would create; nothing is written.
    backend_->install_async(req, [this, &s, what = std::string(what), target, url, file, source, dry_run, done](json::Value r) {
        const bool ok = r["ok"].boolean();
        if (dry_run) {
            if (ok) reply(s, 200, r.set("source", source).set("hint", "nothing was written; the same call without dry_run installs"));
            else reply(s, 409, json::Value::object().set("ok", false).set("dry_run", true).set("error", r.get("error")).set("target", target));
            done();
            return;
        }
        std::string made;
        for (const auto& c : r["created"].items()) made += " created " + std::string(c.get("path")) + " (" + std::string(c.get("owner")) + " " + std::string(c.get("mode")) + ")";
        audit_peer(s, what, ok ? "installed " + std::to_string(static_cast<long>(r["files"].num())) + " files into " + target + " (sha256 " + std::string(r.get("sha256")) + ")" + made
                              : "failed: " + std::string(r.get("error")));
        if (!ok) {
            reply(s, 409, json::Value::object().set("ok", false).set("error", r.get("error")).set("target", target));
        } else {
            json::Value steps = json::Value::array();
            if (!url.empty()) steps.push("the files came from " + std::string(r.get("url").empty() ? url : std::string(r.get("url"))) + "; sha256 " + std::string(r.get("sha256")));
            steps.push("open the site in a browser to finish the application's own setup (database, admin account)");
            if (!file.empty()) steps.push("the upload " + file + " is still stored; delete it with uploads delete " + file + " when no longer needed");
            r.set("next_steps", steps);
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
    // The rest of the root work, when the helper is there: the site's log to its group, the
    // php-fpm pool written and reloaded. next_steps then holds only what remains.
    std::vector<std::string> steps = control::next_steps(spec, cfg);
    if (backend_->provision_available()) {
        const Config& live = backend_->running();
        if (!spec.user.empty() && !spec.access_log.empty()) {
            const json::Value r = backend_->provision(json::Value::object().set("op", "log_own").set("file", spec.access_log)
                                                          .set("group", spec.group.empty() ? spec.user : spec.group));
            if (r["ok"].boolean()) done.push("log " + spec.access_log + " readable by " + spec.user);
        }
        const bool php = spec.app != "static" && spec.app != "proxy";
        if (php && !spec.user.empty() && spec.php_socket.empty()) {
            const json::Value r = backend_->provision(json::Value::object().set("op", "pools_apply"));
            if (r["ok"].boolean()) {
                done.push("php-fpm pool: " + std::string(r.get("output")));
                std::vector<std::string> rest;
                for (const auto& st : steps)
                    if (st != "agensio pools" && !st.starts_with("systemctl reload php") && !st.starts_with("brew services")) rest.push_back(st);
                steps = rest;
            } else {
                steps.insert(steps.begin(), "# the helper could not apply the pool (" + std::string(r.get("error")) + "); run: agensio pools");
            }
        }
        (void)live;
    }
    reply(s, 201, json::Value::object().set("ok", true).set("file", file.string()).set("spec", spec.to_json())
                      .set("done", done).set("next_steps", strings(steps)).set("warnings", warnings));
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
                          .set("overwrite", overwrite).set("dry_run", dry_run);
    if (!site->user.empty()) req.set("user", site->user);
    if (!dry_run) audit_peer(s, what, "copying " + from + " to " + to + " in " + site_root + (overwrite ? " (overwrite)" : ""));
    backend_->install_async(req, [this, &s, what = std::string(what), dry_run, done](json::Value r) {
        const bool ok = r["ok"].boolean();
        if (dry_run) {
            if (ok) reply(s, 200, r.set("hint", "nothing was written; the same call without dry_run copies"));
            else reply(s, 409, json::Value::object().set("ok", false).set("dry_run", true).set("error", r.get("error")));
            done();
            return;
        }
        const bool replaced = !r["replaced"].is_null();
        audit_peer(s, what, ok ? (replaced ? "replaced " : "wrote ") + std::string(r.get("to")) + " from " + std::string(r.get("from")) + " (" + std::string(r.get("as")) + " " + std::string(r.get("mode")) + ", " + std::to_string(static_cast<long>(r["bytes"].num())) + " bytes)"
                              : "failed: " + std::string(r.get("error")));
        if (!ok) reply(s, 409, json::Value::object().set("ok", false).set("error", r.get("error")));
        else reply(s, replaced ? 200 : 201, r);
        done();
    });
}

}  // namespace agensio
