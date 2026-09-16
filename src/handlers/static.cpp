#include "handlers/static.hpp"

#include <charconv>
#include <cstring>
#include <ctime>

#include "core/strings.hpp"
#include "http_date.hpp"
#include "mime.hpp"
#include "path.hpp"
#include "response.hpp"

namespace agensio {

namespace {

inline void append_hex(std::string& s, std::uint64_t v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof(buf), v, 16);
    s.append(buf, r.ptr);
}

}  // namespace

void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out) {
    out.clear();
    out.push_back('"');
    append_hex(out, static_cast<std::uint64_t>(mtime));
    out.push_back('-');
    append_hex(out, size);
    out.push_back('"');
}

StaticHandler::StaticHandler(const Config& cfg, FileCache& cache) : cfg_(cfg), cache_(cache) {}

void StaticHandler::error(Stream& s, int status, bool keep_alive, std::string_view allow) {
    Response& r = s.response;
    r.reset();
    const ErrorPage& page = error_page(status);
    r.status = status;
    r.keep_alive = keep_alive;
    r.head = s.request.method == Method::HEAD;
    r.prebuilt_headers = page.headers;  // Content-Type + Content-Length, not terminated
    if (!allow.empty()) r.headers.add("Allow", allow);
    r.body = MemoryBody{page.body};
}

bool StaticHandler::not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept {
    if (!req.if_none_match.empty()) {
        std::string_view v = req.if_none_match;
        if (v == "*") return true;
        std::size_t i = 0;
        while (i < v.size()) {
            std::size_t j = v.find(',', i);
            if (j == std::string_view::npos) j = v.size();
            std::string_view tag = slice(v, i, j - i);
            while (!tag.empty() && (tag.front() == ' ' || tag.front() == '\t'))
                tag.remove_prefix(1);
            while (!tag.empty() && (tag.back() == ' ' || tag.back() == '\t'))
                tag.remove_suffix(1);
            if (tag.size() > 2 && tag[0] == 'W' && tag[1] == '/') tag.remove_prefix(2);
            if (tag == etag) return true;
            i = j + 1;
        }
        return false;
    }
    if (!req.if_modified_since.empty()) return req.if_modified_since == last_modified;
    return false;
}

void StaticHandler::serve_entry(Stream& s, EntryPtr e) {
    Response& r = s.response;
    r.head = s.request.method == Method::HEAD;
    if (not_modified(s.request, e->etag, e->last_modified)) {
        r.status = 304;
        r.headers.add("ETag", e->etag);
        r.headers.add("Last-Modified", e->last_modified);
        r.entry = std::move(e);  // keeps the views above alive
        return;
    }
    // Zero-concatenation path: the entry's prebuilt block already ends with the blank line.
    r.status = 200;
    r.prebuilt_headers = e->headers;
    r.prebuilt_terminated = true;
    if (e->descriptor_only) r.body = FileBody{&e->fd, e->size, 0};  // streamed from the cached descriptor
    else r.body = MemoryBody{std::string_view(e->data.data(), e->data.size())};
    r.entry = std::move(e);
}

void StaticHandler::fill_entry(CacheEntry& entry, const FileInfo& fi, const WorkerState& ws, std::time_t now) {
    entry.file_path = ws.fs_path;
    entry.mtime = fi.mtime;
    entry.size = fi.size;
    make_etag(fi.mtime, fi.size, entry.etag);
    entry.last_modified.resize(kHttpDateLength);
    format_http_date(static_cast<std::time_t>(fi.mtime), entry.last_modified.data());
    entry.headers.reserve(160);
    entry.headers.append("Content-Type: ").append(mime_for_path(ws.fs_path)).append("\r\nContent-Length: ");
    append_number(entry.headers, fi.size);
    entry.headers.append("\r\nLast-Modified: ")
        .append(entry.last_modified)
        .append("\r\nETag: ")
        .append(entry.etag)
        .append("\r\n\r\n");
    entry.last_access.store(now, std::memory_order_relaxed);
    entry.last_validated.store(now, std::memory_order_relaxed);
}

void StaticHandler::serve_file(Stream& s, File&& f, const FileInfo& fi, WorkerState& ws) {
    Response& r = s.response;
    r.head = s.request.method == Method::HEAD;
    std::string etag;
    make_etag(fi.mtime, fi.size, etag);
    char lm[kHttpDateLength];
    format_http_date(static_cast<std::time_t>(fi.mtime), lm);
    if (not_modified(s.request, etag, std::string_view(lm, kHttpDateLength))) {
        r.status = 304;
        r.scratch.assign("ETag: ")
            .append(etag)
            .append("\r\nLast-Modified: ")
            .append(lm, kHttpDateLength)
            .append("\r\n");
        r.prebuilt_headers = r.scratch;
        return;
    }
    r.status = 200;
    r.scratch.assign("Content-Type: ").append(mime_for_path(ws.fs_path)).append("\r\nContent-Length: ");
    append_number(r.scratch, fi.size);
    r.scratch.append("\r\nLast-Modified: ")
        .append(lm, kHttpDateLength)
        .append("\r\nETag: ")
        .append(etag)
        .append("\r\n\r\n");
    r.prebuilt_headers = r.scratch;
    r.prebuilt_terminated = true;
    r.owned_file = std::move(f);
    r.body = FileBody{&r.owned_file, fi.size, 0};
}

void StaticHandler::redirect_slash(Stream& s, WorkerState& ws) {
    Response& r = s.response;
    const ErrorPage& page = error_page(301);
    r.status = 301;
    r.head = s.request.method == Method::HEAD;
    r.scratch.assign(ws.path).push_back('/');
    r.headers.add("Location", r.scratch);
    r.prebuilt_headers = page.headers;
    r.body = MemoryBody{page.body};
}

// The filesystem path for ws.path under the location: root + path, or with `alias` the
// alias directory in place of the location prefix (nginx semantics).
static void fs_path_of(const LocationConfig& loc, WorkerState& ws) {
    if (loc.alias.empty()) ws.fs_path.assign(loc.root).append(ws.path);
    else ws.fs_path.assign(loc.alias).append(ws.path, loc.path.size() - 1, std::string::npos);  // keeps the '/'
}

// Opens the first index file of the directory ws.path (which ends with '/') under loc.root.
// Leaves ws.fs_path at the file that was opened, or at the directory if none was.
bool StaticHandler::open_index(const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi) {
    fs_path_of(loc, ws);
    const std::size_t base = ws.fs_path.size();
    for (const auto& index : loc.index) {
        ws.fs_path.resize(base);
        ws.fs_path.append(index);
        f = File::open(ws.fs_path.c_str());
        if (f.is_open() && f.info(fi) && fi.is_regular) return true;
        f.close();
    }
    ws.fs_path.resize(base);
    return false;
}

// The rule without try_files: a directory URI serves its index (403 without one, 404 if
// the directory does not exist); a file URI serves the file, redirects to the slash form
// for a directory, and is 404 otherwise.
StaticHandler::Lookup StaticHandler::plain_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f,
                                                  FileInfo& fi) {
    const bool keep_alive = s.request.keep_alive;
    if (ws.path.back() == '/') {
        if (open_index(loc, ws, f, fi)) return Lookup::found;
        FileInfo dir;
        const bool exists = stat_path(ws.fs_path.c_str(), dir) && dir.is_directory;
        error(s, exists ? 403 : 404, keep_alive);
        return Lookup::responded;
    }
    fs_path_of(loc, ws);
    f = File::open(ws.fs_path.c_str());
    if (!f.is_open() || !f.info(fi)) {
        error(s, 404, keep_alive);
        return Lookup::responded;
    }
    if (fi.is_directory) {
        redirect_slash(s, ws);
        return Lookup::responded;
    }
    if (!fi.is_regular) {
        error(s, 404, keep_alive);
        return Lookup::responded;
    }
    return Lookup::found;
}

// try_files (nginx semantics, minus variables other than $uri): the first element that
// resolves wins; "$uri" is a regular file, "$uri/" a directory (its index when the URI
// ends with '/', otherwise a redirect to the slash form), "=code" answers that status,
// and a path is an internal redirect the caller routes again. Nothing matched is 404.
StaticHandler::Lookup StaticHandler::try_files_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws,
                                                      File& f, FileInfo& fi) {
    const bool keep_alive = s.request.keep_alive;
    const bool dir_uri = ws.path.back() == '/';
    for (const TryStep& step : loc.try_files) {
        switch (step.kind) {
            case TryStep::Kind::uri:
                if (dir_uri) break;
                fs_path_of(loc, ws);
                f = File::open(ws.fs_path.c_str());
                if (f.is_open() && f.info(fi) && fi.is_regular) return Lookup::found;
                f.close();
                break;
            case TryStep::Kind::uri_dir: {
                if (dir_uri) {
                    if (open_index(loc, ws, f, fi)) return Lookup::found;
                    break;
                }
                fs_path_of(loc, ws);
                FileInfo dir;
                if (stat_path(ws.fs_path.c_str(), dir) && dir.is_directory) {
                    redirect_slash(s, ws);
                    return Lookup::responded;
                }
                break;
            }
            case TryStep::Kind::status:
                error(s, step.status, keep_alive);
                return Lookup::responded;
            case TryStep::Kind::fallback:
                ws.path = step.target;
                return Lookup::redirect;
        }
    }
    error(s, 404, keep_alive);
    return Lookup::responded;
}

StaticHandler::Outcome StaticHandler::serve_location(Stream& s, const LocationConfig& loc, WorkerState& ws) {
    const Request& req = s.request;
    // Dotfiles and dot-directories (.env, .git, .htaccess) are never served unless the
    // location opts in. 404 rather than 403 so their existence is not disclosed.
    if (!loc.hidden_files && has_hidden_segment(ws.path)) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }
    const std::time_t now = ws.now;
    const CacheKeyView key{&loc, ws.path};

    // 1. Worker-local index (no lock, no refcount traffic), then the shared store.
    //    `raw` is only dereferenced on this thread before any index mutation.
    CacheEntry* raw = nullptr;
    const EntryPtr* local = ws.local.find(key);
    if (local) {
        if ((*local)->stale.load(std::memory_order_acquire)) {
            ws.local.erase(key);
            local = nullptr;
        } else raw = local->get();
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
        now - raw->last_validated.load(std::memory_order_relaxed) >=
            static_cast<std::int64_t>(cfg_.cache_revalidate_s)) {
        FileInfo fi;
        if (!stat_path(raw->file_path.c_str(), fi) || !fi.is_regular || fi.mtime != raw->mtime ||
            fi.size != raw->size) {
            cache_.erase(key, raw);
            ws.local.erase(key);
            raw = nullptr;
        } else {
            raw->last_validated.store(now, std::memory_order_relaxed);
        }
    }
    if (raw) {
        // Write the shared line at most once per second, not once per hit.
        if (raw->last_access.load(std::memory_order_relaxed) != now)
            raw->last_access.store(now, std::memory_order_relaxed);
        // Exactly one strong reference is taken for the duration of the response.
        EntryPtr ref = fetched ? std::move(fetched) : *local;
        serve_entry(s, std::move(ref));
        return Outcome::done;
    }

    // 3. Miss: resolve on the filesystem, by the plain rule or the location's try_files.
    File f;
    FileInfo fi;
    switch (loc.try_files.empty() ? plain_lookup(s, loc, ws, f, fi) : try_files_lookup(s, loc, ws, f, fi)) {
        case Lookup::found:
            break;
        case Lookup::responded:
            return Outcome::done;
        case Lookup::redirect:
            return Outcome::redirect;
    }

    // Symlink policy: with symlinks = "deny" the resolved file must stay under the root (or alias).
    if (loc.symlinks_deny && !path_within_root(ws.fs_path.c_str(), loc.alias.empty() ? loc.root : loc.alias)) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }

    // 4. Small enough: load into the cache and serve from there.
    if (fi.size <= cache_.max_file_size()) {
        auto entry = std::make_shared<CacheEntry>();
        entry->data.resize(static_cast<std::size_t>(fi.size));
        if (fi.size > 0 && !entry->data.empty() && !f.read_all(entry->data.data(), entry->data.size())) {
            error(s, 500, req.keep_alive);
            return Outcome::done;
        }
        if (cfg_.cache_sendfile_min_size > 0 && fi.size >= cfg_.cache_sendfile_min_size) entry->fd = std::move(f);
        else f.close();
        fill_entry(*entry, fi, ws, now);

        EntryPtr canonical = cache_.insert(key, entry);
        if (canonical) ws.local.insert(key, canonical);
        else canonical = std::move(entry);  // cache full for this size class: serve once, uncached
        serve_entry(s, std::move(canonical));
        return Outcome::done;
    }

    // 5. Too large to hold in memory: keep the open descriptor and the prebuilt headers in
    //    the cache (descriptor entry), so repeat requests stream it without an
    //    open/fstat/realpath or header formatting. Every reader uses pread/sendfile with
    //    explicit offsets, so one descriptor serves concurrent responses.
    if (cache_.max_open_files() > 0) {
        auto entry = std::make_shared<CacheEntry>();
        entry->descriptor_only = true;
        entry->fd = std::move(f);
        fill_entry(*entry, fi, ws, now);
        EntryPtr canonical = cache_.insert(key, entry);
        if (canonical) {
            ws.local.insert(key, canonical);
            serve_entry(s, std::move(canonical));
            return Outcome::done;
        }
        f = std::move(entry->fd);  // store refused it: serve once from the open file
    }
    serve_file(s, std::move(f), fi, ws);
    return Outcome::done;
}

void StaticHandler::handle(Stream& s, const Router& router, WorkerState& ws) {
    const Request& req = s.request;
    Response& r = s.response;
    r.reset();
    r.keep_alive = req.keep_alive;

    if (req.method == Method::OTHER) {
        error(s, 405, req.keep_alive, "GET, HEAD");
        return;
    }
    // A body on GET/HEAD is ignored: the connection drains it after the response (nginx
    // behaviour); oversize bodies were already refused with 413 before we were called.
    if (req.version_minor == 1 && req.host.empty()) {
        error(s, 400, false);
        return;
    }
    if (!normalize_target(req.target, ws.path)) {
        error(s, 400, false);
        return;
    }
#ifdef _WIN32
    if (!windows_path_ok(ws.path)) {
        error(s, 400, false);
        return;
    }
#endif

    const SiteConfig* site = router.site(req.host);
    const LocationConfig* loc = &Router::location(*site, ws.path);
    for (int hops = 0;; ++hops) {
        if (serve_location(s, *loc, ws) == Outcome::done) return;
        // try_files fallback: ws.path is the new target; route it again, bounded so two
        // locations pointing at each other cannot loop.
        if (hops >= kMaxInternalRedirects) {
            error(s, 500, req.keep_alive);
            return;
        }
        loc = &Router::location(*site, ws.path);
    }
}

}  // namespace agensio
