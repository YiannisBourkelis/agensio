#include "handlers/fastcgi.hpp"

#include "handlers/upstream_common.hpp"

#include <cstring>
#include <sys/stat.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include "core/strings.hpp"
#include "handlers/static.hpp"
#include "response.hpp"

namespace agensio {

// One in-flight exchange: owns the request body while it is collected, then the upstream request.
struct FcgiHandler::Exchange : std::enable_shared_from_this<Exchange> {
    Stream* stream = nullptr;
    const SiteConfig* site = nullptr;
    const LocationConfig* loc = nullptr;
    WorkerState* ws = nullptr;
    FcgiPool* pool = nullptr;
    std::function<void()> done;
    FcgiBodyInput body;
    std::vector<char> chunk;  // body read scratch
    std::shared_ptr<FcgiRequest> req;
    std::string script;       // SCRIPT_FILENAME
    std::string path_info;    // the part of the path after the script ("/index.php/extra" -> "/extra")
    bool completed = false;
};

void FcgiHandler::error(Stream& s, int status, std::string_view retry_after) {
    upstream_error(s, status, retry_after);
}

namespace {

void append_upper_env(std::string& out, std::string_view name) {
    for (char c : name) {
        if (c == '-') out.push_back('_');
        else if (c >= 'a' && c <= 'z') out.push_back(static_cast<char>(c - 32));
        else out.push_back(c);
    }
}

}  // namespace

std::string FcgiHandler::prebuild_params(const SiteConfig& site, const LocationConfig& loc) {
    std::string out;
    fcgi::append_param(out, "GATEWAY_INTERFACE", "CGI/1.1");
    fcgi::append_param(out, "SERVER_SOFTWARE", "agensio/" AGENSIO_VERSION);
    fcgi::append_param(out, "REDIRECT_STATUS", "200");  // PHP's cgi.force_redirect wants it
    const std::string& local_root = loc.alias.empty() ? loc.root : loc.alias;
    fcgi::append_param(out, "DOCUMENT_ROOT", loc.fastcgi.remote_root.empty() ? local_root : loc.fastcgi.remote_root);
    if (const std::string& first = site.server_names.front(); first != "*")
        fcgi::append_param(out, "SERVER_NAME", first);
    return out;
}

void FcgiHandler::append_http_params(std::string& out, const Headers& headers, std::string& scratch) {
    for (std::size_t i = 0; i < headers.size(); ++i) {
        const HeaderField& h = headers[i];
        if (h.name.find('_') != std::string_view::npos || Headers::iequals(h.name, "proxy")) continue;
        bool seen = false;
        for (std::size_t j = 0; j < i && !seen; ++j)
            seen = Headers::iequals(headers[j].name, h.name);
        if (seen) continue;  // merged into the first occurrence below
        scratch.assign("HTTP_");
        append_upper_env(scratch, h.name);
        std::string_view value = h.value;
        std::string joined;
        for (std::size_t j = i + 1; j < headers.size(); ++j) {
            if (!Headers::iequals(headers[j].name, h.name)) continue;
            if (joined.empty()) joined.assign(value);
            joined.append(Headers::iequals(h.name, "cookie") ? "; " : ", ").append(headers[j].value);
        }
        fcgi::append_param(out, scratch, joined.empty() ? value : std::string_view(joined));
    }
}

void FcgiHandler::append_request_params(std::string& out, Stream& s, const SiteConfig& site, const LocationConfig& loc,
                                        WorkerState& ws, std::string_view path_info, std::uint64_t content_length,
                                        bool length_known) const {
    const Request& req = s.request;
    std::string& tmp = ws.scratch;  // per-worker scratch, capacity retained
    auto add = [&](std::string_view name, std::string_view value) { fcgi::append_param(out, name, value); };
    add("SERVER_PROTOCOL", req.version_minor == 0 ? "HTTP/1.0" : "HTTP/1.1");
    add("REQUEST_METHOD", req.method_name);
    // The script as the FastCGI server sees it: the local root swapped for remote_root.
    const std::string& local_root = loc.alias.empty() ? loc.root : loc.alias;
    const std::string& doc_root = loc.fastcgi.remote_root.empty() ? local_root : loc.fastcgi.remote_root;
    if (loc.fastcgi.remote_root.empty()) {
        add("SCRIPT_FILENAME", ws.fs_path);
    } else {
        tmp.assign(doc_root).append(std::string_view(ws.fs_path).substr(local_root.size()));
        add("SCRIPT_FILENAME", tmp);
    }
    add("SCRIPT_NAME", ws.path);
    add("REQUEST_URI", req.target);
    add("DOCUMENT_URI", ws.path);
    if (!path_info.empty()) {
        add("PATH_INFO", path_info);
        tmp.assign(doc_root).append(path_info);
        add("PATH_TRANSLATED", tmp);
    }
    const std::size_t q = req.target.find('?');
    add("QUERY_STRING", q == std::string_view::npos ? std::string_view() : req.target.substr(q + 1));
    if (const std::string_view ct = req.headers.get("content-type"); !ct.empty()) add("CONTENT_TYPE", ct);
    if (req.has_body && length_known) {
        tmp.clear();
        append_number(tmp, content_length);
        add("CONTENT_LENGTH", tmp);
    }
    add("REMOTE_ADDR", s.conn.client_address.empty() ? s.conn.remote_address : s.conn.client_address);
    tmp.clear();
    append_number(tmp, s.conn.remote_port);
    add("REMOTE_PORT", tmp);
    add("SERVER_ADDR", s.conn.local_address);
    tmp.clear();
    append_number(tmp, s.conn.local_port);
    add("SERVER_PORT", tmp);
    if (site.server_names.front() == "*") add("SERVER_NAME", req.host);
    const bool https = s.conn.tls || s.conn.forwarded_https;
    add("REQUEST_SCHEME", https ? "https" : "http");
    if (https) add("HTTPS", "on");
    append_http_params(out, req.headers, tmp);
}

std::shared_ptr<FcgiRequest> FcgiHandler::start(Stream& s, const SiteConfig& site, const LocationConfig& loc,
                                                WorkerState& ws, FcgiPool& pool, std::function<void()> done) {
    // The script: the request path, plus the index for a directory URI, under root/alias.
    // "/index.php/extra/path" is split into the script and PATH_INFO (nginx
    // fastcgi_split_path_info ^(.+\.php)(/.+)$).
    std::string path_info;
    if (loc.fastcgi.options.path_info) {
        const std::string_view marker = ".php/";
        if (const std::size_t p = ws.path.find(marker); p != std::string::npos) {
            path_info = ws.path.substr(p + marker.size() - 1);
            ws.path.resize(p + marker.size() - 1);
        }
    }
    if (ws.path.back() == '/') ws.path.append(loc.index.empty() ? std::string("index.php") : loc.index.front());
    fs_path_of(loc, ws);
    FileInfo fi;
    if (!stat_path(ws.fs_path.c_str(), fi) || !fi.is_regular) {
        error(s, 404);
        s.response.upstream = "fastcgi:no_script";
        done();
        return nullptr;
    }
    auto x = std::make_shared<Exchange>();
    x->stream = &s;
    x->site = &site;
    x->loc = &loc;
    x->ws = &ws;
    x->pool = &pool;
    x->done = std::move(done);
    x->script = ws.fs_path;
    x->path_info = std::move(path_info);
    const FcgiOptions& opts = loc.fastcgi.options;
    const Request& req = s.request;
    const bool retry_ok = req.method == Method::get || req.method == Method::head;

    // Everything after the body is settled: the per-request params, then the exchange.
    auto launch = [this, x, retry_ok](bool length_known) {
        WorkerState& w = *x->ws;
        w.params_tail.clear();
        append_request_params(w.params_tail, *x->stream, *x->site, *x->loc, w, x->path_info, x->body.size,
                              length_known);
        x->req = std::make_shared<FcgiRequest>(*x->pool, x->loc->fastcgi.address, x->loc->fastcgi.options);
        x->req->start(x->loc->fastcgi.params_prefix, w.params_tail, std::move(x->body), x->loc->priority, retry_ok,
                      [this, x](FcgiResult& r) { finish(*x, r); });
    };

    if (!req.has_body || !req.body) {
        launch(true);
        return x->completed ? nullptr : x->req;
    }
    if (!opts.request_buffering) {  // stream the body to fpm as it arrives
        x->body.stream = req.body;
        std::uint64_t declared = 0;
        const bool known = req.body->length(declared);
        x->body.size = declared;
        launch(known);
        return x->completed ? nullptr : x->req;
    }
    // Collect the body first: memory up to request_buffer_max, then a temp file. Bounded by
    // server.max_body_size in the connection. `launch` may run inline when the body was
    // already buffered; a spill failure was answered (502) by the collector.
    collect_request_body(s, x->body, opts.request_buffer_max, x->chunk, x, [x, launch](bool ok) {
        if (ok) launch(true);
        else {
            x->req.reset();
            x->completed = true;
            x->done();
        }
    });
    return x->completed ? nullptr : x->req;
}

void FcgiHandler::log_failure(const Exchange& x, const FcgiResult& res) {
    const FcgiAddress& a = x.loc->fastcgi.address;
    std::string msg = "fastcgi " + a.key + " " + to_string(res.failure) + " for " + x.script;
    if (res.error) msg += " (" + res.error.message() + ")";
    switch (res.failure) {
        case FcgiFailure::socket_permission: {
#ifndef _WIN32
            struct stat st{};
            if (::stat(a.path.c_str(), &st) == 0) {
                char mode[8];
                std::snprintf(mode, sizeof(mode), "%04o", static_cast<unsigned>(st.st_mode & 07777));
                msg += ": socket " + a.path + " is owner " + std::to_string(st.st_uid) + ":" +
                       std::to_string(st.st_gid) + " mode " + mode + ", agensio runs as " +
                       std::to_string(::getuid()) + ":" + std::to_string(::getgid()) +
                       "; fix listen.owner/listen.group/listen.mode in the fpm pool or add agensio to that group";
            } else {
                msg += ": socket " + a.path + " cannot be stat'ed";
            }
#endif
            break;
        }
        case FcgiFailure::socket_missing:
            msg += ": nothing created " + a.path + "; is php-fpm running and is `listen` in its pool this path?";
            break;
        case FcgiFailure::connect_refused:
            msg += ": nothing is listening on " + a.key + "; is php-fpm running?";
            break;
        case FcgiFailure::primary_script_unknown:
            msg += ": php-fpm could not open SCRIPT_FILENAME " + x.script +
                   "; check the fpm pool's user can read it and that chroot/open_basedir allow it";
            break;
        case FcgiFailure::closed_early:
            if (res.head_bytes == 0)
                msg += ": the connection closed before any byte of the response arrived "
                       "(child crashed or fpm reloaded)";
            else
                msg += ": the connection closed after " + std::to_string(res.head_bytes) +
                       " bytes (child died mid-response)";
            break;
        case FcgiFailure::pool_saturated:
            msg += ": " + std::to_string(x.loc->fastcgi.options.max_connections) + " in flight and " +
                   std::to_string(x.loc->fastcgi.options.queue_depth) +
                   " queued per worker; raise max_connections/queue_depth or pm.max_children";
            break;
        case FcgiFailure::queue_timeout:
            msg += ": waited queue_wait in the pool queue; php-fpm is too slow for the load";
            break;
        case FcgiFailure::read_timeout:
            msg += ": no data for read_timeout; raise fastcgi.read_timeout or fix the slow script";
            break;
        case FcgiFailure::head_too_large:
            msg += ": response head exceeds head_max (" + std::to_string(x.loc->fastcgi.options.head_max) + " bytes)";
            break;
        default:
            break;
    }
    if (res.failure == FcgiFailure::primary_script_unknown) log_.warn(msg);
    else log_.error(msg);
}

void FcgiHandler::finish(Exchange& x, FcgiResult& res) {
    Stream& s = *x.stream;
    Response& r = s.response;
    const LocationConfig& loc = *x.loc;
    if (!res.stderr_text.empty() && res.failure != FcgiFailure::primary_script_unknown) {
        std::string msg = "fastcgi " + loc.fastcgi.address.key + " stderr for " + x.script + ": ";
        std::string_view text = res.stderr_text;
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r')) text.remove_suffix(1);
        msg.append(text.substr(0, 1024));
        log_.warn(msg);
    }
    if (res.failure != FcgiFailure::none && res.failure != FcgiFailure::primary_script_unknown) {
        log_failure(x, res);
        const int status = status_for(res.failure);
        error(s, status, status == 503 ? std::string_view(loc.fastcgi.retry_after) : std::string_view());
        r.upstream = to_string(res.failure);
        x.completed = true;
        x.done();
        return;
    }
    if (res.failure == FcgiFailure::primary_script_unknown) log_failure(x, res);
    apply_upstream_result(s, res, res.streamed ? x.req->body_source() : nullptr,
                          to_string(res.failure));  // "ok" or "primary_script_unknown"
    x.completed = true;
    x.done();
}

}  // namespace agensio
