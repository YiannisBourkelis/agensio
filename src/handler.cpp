#include "handler.hpp"

#include <charconv>
#include <cstring>
#include <ctime>

#include "mime.hpp"
#include "response.hpp"
#include "path.hpp"

namespace agensio {

namespace {

inline void append_number(std::string& s, std::uint64_t v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof(buf), v);
    s.append(buf, r.ptr);
}

inline void append_hex(std::string& s, std::uint64_t v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof(buf), v, 16);
    s.append(buf, r.ptr);
}

inline char lower(char c) noexcept { return (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c; }

}  // namespace

void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out) {
    out.clear();
    out.push_back('"');
    append_hex(out, static_cast<std::uint64_t>(mtime));
    out.push_back('-');
    append_hex(out, size);
    out.push_back('"');
}

const SiteConfig* Route::lookup(std::string_view host) const noexcept {
    if (host.empty() || by_name.empty()) return default_site;
    // Strip the port: "example.com:8080", "[::1]:8080".
    if (host.front() == '[') {
        auto close = host.find(']');
        if (close != std::string_view::npos) host = host.substr(1, close - 1);
    } else {
        auto colon = host.rfind(':');
        if (colon != std::string_view::npos) host = host.substr(0, colon);
    }
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    if (host.size() > 253) return default_site;
    char buf[256];
    for (std::size_t i = 0; i < host.size(); ++i) buf[i] = lower(host[i]);
    auto it = by_name.find(std::string_view(buf, host.size()));
    return it == by_name.end() ? default_site : it->second;
}

RequestHandler::RequestHandler(const Config& cfg, FileCache& cache) : cfg_(cfg), cache_(cache) {
    if (!cfg.server_header.empty()) server_line_ = "Server: " + cfg.server_header + "\r\n";
}

void RequestHandler::begin_header(int status, WorkerState& ws, ResponsePlan& plan) {
    plan.header.append(status_line(status));
    plan.header.append(server_line_);
    plan.header.append("Date: ");
    plan.header.append(ws.date.now());
    plan.header.append("\r\n");
}

void RequestHandler::end_header(bool keep_alive, int version_minor, ResponsePlan& plan) {
    if (!keep_alive) plan.header.append("Connection: close\r\n");
    else if (version_minor == 0) plan.header.append("Connection: keep-alive\r\n");
    plan.header.append("\r\n");
}

void RequestHandler::end_header(const Request& req, ResponsePlan& plan) {
    end_header(plan.keep_alive, req.version_minor, plan);
}

void RequestHandler::error(int status, bool keep_alive, bool head, WorkerState& ws, ResponsePlan& plan,
                           std::string_view extra_headers) {
    plan.reset();
    plan.keep_alive = keep_alive;
    const ErrorPage& page = error_page(status);
    begin_header(status, ws, plan);
    plan.header.append(page.headers);
    plan.header.append(extra_headers);
    end_header(keep_alive, 1, plan);
    if (!head) {
        plan.body = ResponsePlan::Body::inline_text;
        plan.inline_text = page.body;
    }
}

bool RequestHandler::not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept {
    if (!req.if_none_match.empty()) {
        std::string_view v = req.if_none_match;
        if (v == "*") return true;
        std::size_t i = 0;
        while (i < v.size()) {
            std::size_t j = v.find(',', i);
            if (j == std::string_view::npos) j = v.size();
            std::string_view tag = v.substr(i, j - i);
            while (!tag.empty() && (tag.front() == ' ' || tag.front() == '\t')) tag.remove_prefix(1);
            while (!tag.empty() && (tag.back() == ' ' || tag.back() == '\t')) tag.remove_suffix(1);
            if (tag.size() > 2 && tag[0] == 'W' && tag[1] == '/') tag.remove_prefix(2);
            if (tag == etag) return true;
            i = j + 1;
        }
        return false;
    }
    if (!req.if_modified_since.empty()) return req.if_modified_since == last_modified;
    return false;
}

void RequestHandler::serve_entry(const Request& req, EntryPtr e, WorkerState& ws, ResponsePlan& plan) {
    const bool head = req.method == Method::HEAD;
    if (not_modified(req, e->etag, e->last_modified)) {
        begin_header(304, ws, plan);
        plan.header.append("ETag: ").append(e->etag).append("\r\nLast-Modified: ").append(e->last_modified).append("\r\n");
        end_header(req, plan);
        return;
    }
    begin_header(200, ws, plan);
    plan.header.append(e->headers);
    end_header(req, plan);
    if (!head) {
        plan.body = ResponsePlan::Body::entry;
        plan.entry = std::move(e);
    }
}

void RequestHandler::serve_file(const Request& req, File&& f, const FileInfo& fi, WorkerState& ws, ResponsePlan& plan) {
    const bool head = req.method == Method::HEAD;
    std::string& etag = ws.tmp;
    make_etag(fi.mtime, fi.size, etag);
    char lm[kHttpDateLength];
    format_http_date(static_cast<std::time_t>(fi.mtime), lm);
    if (not_modified(req, etag, std::string_view(lm, kHttpDateLength))) {
        begin_header(304, ws, plan);
        plan.header.append("ETag: ").append(etag).append("\r\nLast-Modified: ").append(lm, kHttpDateLength).append("\r\n");
        end_header(req, plan);
        return;
    }
    begin_header(200, ws, plan);
    plan.header.append("Content-Type: ").append(mime_for_path(ws.fs_path)).append("\r\nContent-Length: ");
    append_number(plan.header, fi.size);
    plan.header.append("\r\nLast-Modified: ").append(lm, kHttpDateLength).append("\r\nETag: ").append(etag).append("\r\n");
    end_header(req, plan);
    if (!head) {
        plan.body = ResponsePlan::Body::file;
        plan.file = std::move(f);
        plan.file_size = fi.size;
        plan.file_sent = 0;
    }
}

void RequestHandler::redirect_slash(const Request& req, WorkerState& ws, ResponsePlan& plan) {
    const ErrorPage& page = error_page(301);
    begin_header(301, ws, plan);
    plan.header.append("Location: ").append(ws.path).append("/\r\n");
    plan.header.append(page.headers);
    end_header(req, plan);
    if (req.method != Method::HEAD) {
        plan.body = ResponsePlan::Body::inline_text;
        plan.inline_text = page.body;
    }
}

void RequestHandler::handle(const Request& req, const Route& route, WorkerState& ws, ResponsePlan& plan) {
    plan.reset();
    plan.keep_alive = req.keep_alive;
    const bool head = req.method == Method::HEAD;

    if (req.method == Method::OTHER) {
        error(405, req.keep_alive, head, ws, plan, "Allow: GET, HEAD\r\n");
        return;
    }
    if (req.has_body) {  // we do not read request bodies; refuse and close
        error(413, false, head, ws, plan);
        return;
    }
    if (req.version_minor == 1 && req.host.empty()) {
        error(400, false, head, ws, plan);
        return;
    }
    if (!normalize_target(req.target, ws.path)) {
        error(400, false, head, ws, plan);
        return;
    }

    const SiteConfig* site = route.lookup(req.host);
    const std::time_t now = std::time(nullptr);
    const CacheKeyView key{site, ws.path};

    // 1. Worker-local index (no lock, no refcount traffic), then the shared store.
    //    `raw` is only dereferenced on this thread before any index mutation.
    CacheEntry* raw = nullptr;
    const EntryPtr* local = ws.local.find(key);
    if (local) {
        if ((*local)->stale.load(std::memory_order_acquire)) { ws.local.erase(key); local = nullptr; }
        else raw = local->get();
    }
    EntryPtr fetched;  // only set when we had to go to the shared store
    if (!raw) {
        fetched = cache_.find(key);
        if (fetched) {
            raw = fetched.get();
            ws.local.insert(key, fetched);  // may rehash: `local` is not used after this point
        }
    }
    // 2. Revalidate against the filesystem at most once per interval.
    if (raw && cfg_.cache_revalidate_s > 0 &&
        now - raw->last_validated.load(std::memory_order_relaxed) >= static_cast<std::int64_t>(cfg_.cache_revalidate_s)) {
        FileInfo fi;
        if (!stat_path(raw->file_path.c_str(), fi) || !fi.is_regular || fi.mtime != raw->mtime || fi.size != raw->size) {
            cache_.erase(key, raw);
            ws.local.erase(key);
            raw = nullptr;
        } else {
            raw->last_validated.store(now, std::memory_order_relaxed);
        }
    }
    if (raw) {
        // Write the shared line at most once per second, not once per hit.
        if (raw->last_access.load(std::memory_order_relaxed) != now) raw->last_access.store(now, std::memory_order_relaxed);
        // Exactly one strong reference is taken for the duration of the response.
        EntryPtr ref = fetched ? std::move(fetched) : *local;
        serve_entry(req, std::move(ref), ws, plan);
        return;
    }

    // 3. Miss: resolve on the filesystem.
    ws.fs_path.assign(site->root).append(ws.path);
    File f;
    FileInfo fi;
    if (ws.path.back() == '/') {
        const std::size_t base = ws.fs_path.size();
        for (const auto& index : site->index) {
            ws.fs_path.resize(base);
            ws.fs_path.append(index);
            f = File::open(ws.fs_path.c_str());
            if (f.is_open() && f.info(fi) && fi.is_regular) break;
            f.close();
        }
        if (!f.is_open()) {
            ws.fs_path.resize(base);
            FileInfo dir;
            const bool exists = stat_path(ws.fs_path.c_str(), dir) && dir.is_directory;
            error(exists ? 403 : 404, req.keep_alive, head, ws, plan);
            return;
        }
    } else {
        f = File::open(ws.fs_path.c_str());
        if (!f.is_open() || !f.info(fi)) {
            error(404, req.keep_alive, head, ws, plan);
            return;
        }
        if (fi.is_directory) {
            redirect_slash(req, ws, plan);
            return;
        }
        if (!fi.is_regular) {
            error(404, req.keep_alive, head, ws, plan);
            return;
        }
    }

    // 4. Small enough: load into the cache and serve from there.
    if (fi.size <= cache_.max_file_size()) {
        auto entry = std::make_shared<CacheEntry>();
        entry->data.resize(static_cast<std::size_t>(fi.size));
        if (fi.size > 0 && !entry->data.empty() && !f.read_all(entry->data.data(), entry->data.size())) {
            error(500, req.keep_alive, head, ws, plan);
            return;
        }
        f.close();
        entry->file_path = ws.fs_path;
        entry->mtime = fi.mtime;
        entry->size = fi.size;
        make_etag(fi.mtime, fi.size, entry->etag);
        entry->last_modified.resize(kHttpDateLength);
        format_http_date(static_cast<std::time_t>(fi.mtime), entry->last_modified.data());
        entry->headers.reserve(160);
        entry->headers.append("Content-Type: ").append(mime_for_path(ws.fs_path)).append("\r\nContent-Length: ");
        append_number(entry->headers, fi.size);
        entry->headers.append("\r\nLast-Modified: ").append(entry->last_modified).append("\r\nETag: ").append(entry->etag).append("\r\n");
        entry->last_access.store(now, std::memory_order_relaxed);
        entry->last_validated.store(now, std::memory_order_relaxed);

        EntryPtr canonical = cache_.insert(key, entry);
        if (canonical) ws.local.insert(key, canonical);
        else canonical = std::move(entry);  // cache full for this size class: serve once, uncached
        serve_entry(req, std::move(canonical), ws, plan);
        return;
    }

    // 5. Too large to cache: stream from the open file.
    serve_file(req, std::move(f), fi, ws, plan);
}

}  // namespace agensio
