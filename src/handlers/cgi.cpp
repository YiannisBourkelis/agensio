#include "handlers/cgi.hpp"

#include "file.hpp"
#include "handlers/fastcgi.hpp"
#include "handlers/static.hpp"
#include "handlers/upstream_common.hpp"
#include "upstream/fcgi.hpp"

namespace agensio {

struct CgiHandler::Exchange : std::enable_shared_from_this<Exchange> {
    Stream* stream = nullptr;
    const SiteConfig* site = nullptr;
    const LocationConfig* loc = nullptr;
    UpstreamPool* pool = nullptr;
    WorkerState* ws = nullptr;
    std::function<void()> done;
    UpstreamBodyInput body;
    std::vector<char> chunk;
    std::shared_ptr<CgiRequest> req;
    std::string script;
    std::string path_info;
    bool completed = false;
};

namespace {

// The script is the longest leading part of the path that names a regular file under the
// location (Apache's rule); the rest is PATH_INFO. A directory URI takes the index.
bool resolve_script(const LocationConfig& loc, WorkerState& ws, std::string& path_info) {
    if (ws.path.back() == '/') ws.path.append(loc.index.empty() ? std::string("index.cgi") : loc.index.front());
    const std::string full = ws.path;
    for (std::size_t cut = full.size();;) {
        ws.path.assign(full, 0, cut);
        fs_path_of(loc, ws);
        FileInfo fi;
        if (stat_path(ws.fs_path.c_str(), fi) && fi.is_regular) {
            path_info.assign(full, cut, std::string::npos);
            return true;
        }
        const std::size_t slash = full.rfind('/', cut - 1);
        if (slash == std::string::npos || slash == 0) return false;
        cut = slash;
    }
}

}  // namespace

std::shared_ptr<UpstreamRequest> CgiHandler::start(Stream& s, const SiteConfig& site, const LocationConfig& loc,
                                                   WorkerState& ws, UpstreamPool& pool, std::function<void()> done) {
    std::string path_info;
    if (!resolve_script(loc, ws, path_info)) {
        upstream_error(s, 404);
        s.response.upstream = "cgi:no_script";
        done();
        return nullptr;
    }
    auto x = std::make_shared<Exchange>();
    x->stream = &s;
    x->site = &site;
    x->loc = &loc;
    x->pool = &pool;
    x->ws = &ws;
    x->done = std::move(done);
    x->script = ws.fs_path;
    x->path_info = std::move(path_info);
    const UpstreamOptions& opts = loc.cgi.options;
    const Request& req = s.request;

    auto launch = [this, x](bool ok) {
        if (!ok) {  // the body could not be spooled: upstream_error already answered 502
            x->completed = true;
            x->done();
            return;
        }
        // The environment: the FastCGI builders produce the same variables, decoded here
        // into NAME=value strings, plus the location's own `env` entries.
        std::vector<std::string> env;
        std::string params = FcgiHandler::prebuild_params(*x->site, *x->loc);
        std::string tail;
        FcgiHandler::append_request_params(tail, *x->stream, *x->site, *x->loc, *x->ws, x->path_info, x->body.size,
                                           true);
        params.append(tail);
        fcgi::for_each_param(params, [&](std::string_view name, std::string_view value) {
            env.emplace_back(std::string(name).append("=").append(value));
        });
        for (const auto& e : x->loc->cgi.env) env.emplace_back(e.first + "=" + e.second);
        env.emplace_back("PATH=/usr/local/bin:/usr/bin:/bin");
        std::vector<std::string> argv;
        if (!x->loc->cgi.interpreter.empty()) argv.push_back(x->loc->cgi.interpreter);
        argv.push_back(x->script);
        const std::string cwd = x->script.substr(0, x->script.rfind('/'));
        x->req = std::make_shared<CgiRequest>(*x->pool, x->loc->cgi.addresses, x->loc->cgi.options);
        x->req->start(std::move(env), std::move(argv), cwd, std::move(x->body), x->loc->priority,
                      [this, x](UpstreamResult& r) { finish(*x, r); });
    };
    if (!req.has_body || !req.body) {
        launch(true);
        return x->completed ? nullptr : x->req;
    }
    if (!opts.request_buffering) {
        x->body.stream = req.body;
        std::uint64_t declared = 0;
        x->body.size_known = req.body->length(declared);
        x->body.size = declared;
        launch(true);
        return x->completed ? nullptr : x->req;
    }
    collect_request_body(s, x->body, opts.request_buffer_max, x->chunk, x, launch);
    return x->completed ? nullptr : x->req;
}

void CgiHandler::finish(Exchange& x, UpstreamResult& res) {
    Stream& s = *x.stream;
    if (!res.stderr_text.empty()) {
        std::string_view text = res.stderr_text;
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.remove_suffix(1);
        log_.warn("cgi " + x.script + " stderr: " + std::string(text.substr(0, 1024)));
    }
    if (res.failure != UpstreamFailure::none) {
        std::string msg = "cgi " + x.script + " " + to_string(res.failure);
        if (res.error) msg += " (" + res.error.message() + ")";
        switch (res.failure) {
            case UpstreamFailure::closed_early:
                msg += res.head_bytes == 0 ? ": the script exited without printing a header block"
                                           : ": the script exited in the middle of its output";
                break;
            case UpstreamFailure::read_timeout:
                msg += ": no output for " + std::to_string(x.loc->cgi.options.read_timeout.count() / 1000) +
                       " s (cgi.read_timeout); the process was killed";
                break;
            case UpstreamFailure::pool_saturated:
                msg += ": " + std::to_string(x.loc->cgi.options.max_connections) +
                       " processes already running for this location on this worker (cgi.max_connections)";
                break;
            default: break;
        }
        log_.error(msg);
        const int status = status_for(res.failure);
        upstream_error(s, status, status == 503 ? std::string_view(x.loc->cgi.retry_after) : std::string_view());
        s.response.upstream = to_string(res.failure);
        x.completed = true;
        x.done();
        return;
    }
    apply_upstream_result(s, res, res.streamed ? x.req->body_source() : nullptr, "ok", *x.loc);
    x.completed = true;
    x.done();
}

}  // namespace agensio
