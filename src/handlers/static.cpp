#include "handlers/static.hpp"

#include "http2/hpack.hpp"

#include "http1/range.hpp"

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
    r.head = s.request.method == Method::head;
    r.prebuilt_headers = page.headers;  // Content-Type + Content-Length, not terminated
    r.prebuilt_h2 = page.h2_headers;
    r.content_type = "text/html; charset=utf-8";
    if (!allow.empty()) r.headers.add("Allow", allow);
    r.body = MemoryBody{page.body};
}

void StaticHandler::no_content(Stream& s, std::string_view allow) {
    Response& r = s.response;
    r.reset();
    r.status = 204;
    r.keep_alive = s.request.keep_alive;
    r.headers.add("Allow", allow);
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

// A Range request on a file of known size: 206 with the slice, 416 when it lies past the
// end, or nothing (the caller sends the whole body) when there is no usable single range
// or If-Range says the file changed. Off the plain path: one test of an empty view.
StaticHandler::RangeOutcome StaticHandler::apply_range(Stream& s, std::uint64_t size, std::string_view content_type,
                                                       std::string_view etag, std::string_view last_modified,
                                                       std::uint64_t& first, std::uint64_t& length,
                                                       std::string_view extra) {
    const Request& req = s.request;
    if (req.range.empty() || !if_range_matches(req.if_range, etag, last_modified)) return RangeOutcome::whole;
    std::uint64_t last = 0;
    const RangeStatus st = parse_range(req.range, size, first, last);
    if (st == RangeStatus::none) return RangeOutcome::whole;
    Response& r = s.response;
    if (st == RangeStatus::unsatisfiable) {
        error(s, 416, req.keep_alive);
        r.scratch.assign("bytes */");
        append_number(r.scratch, size);
        r.headers.add("Content-Range", r.scratch);
        return RangeOutcome::done;
    }
    length = last - first + 1;
    r.status = 206;
    r.scratch.assign("Content-Type: ").append(content_type).append("\r\nContent-Range: bytes ");
    append_number(r.scratch, first);
    r.scratch.push_back('-');
    append_number(r.scratch, last);
    r.scratch.push_back('/');
    append_number(r.scratch, size);
    r.scratch.append("\r\nContent-Length: ");
    append_number(r.scratch, length);
    r.scratch.append("\r\nLast-Modified: ")
        .append(last_modified)
        .append("\r\nETag: ")
        .append(etag)
        .append("\r\n")
        .append(extra)
        .append("Accept-Ranges: bytes\r\n\r\n");
    r.prebuilt_headers = r.scratch;
    r.prebuilt_terminated = true;
    return RangeOutcome::partial;
}

void StaticHandler::serve_entry(Stream& s, EntryPtr e) {
    // A pre-compressed twin when the client takes one: the twin is an entry of its own, so
    // the reference moves to it and eviction of the file cannot free bytes in flight. A file
    // without twins pays two pointer tests.
    if (e->has_variants() && !s.request.accept_encoding.empty()) {
        switch (choose_encoding(s.request.accept_encoding, e->br != nullptr, e->gzip != nullptr)) {
            case Encoding::br: {
                EntryPtr twin = e->br;
                e = std::move(twin);
                break;
            }
            case Encoding::gzip: {
                EntryPtr twin = e->gzip;
                e = std::move(twin);
                break;
            }
            case Encoding::identity: break;
        }
    }
    Response& r = s.response;
    r.head = s.request.method == Method::head;
    if (not_modified(s.request, e->etag, e->last_modified)) {
        r.status = 304;
        r.headers.add("ETag", e->etag);
        r.headers.add("Last-Modified", e->last_modified);
        if (!e->coding_headers.empty()) r.headers.add("Vary", "Accept-Encoding");
        r.entry = std::move(e);  // keeps the views above alive
        return;
    }
    std::uint64_t first = 0, length = 0;
    switch (apply_range(s, e->size, e->content_type, e->etag, e->last_modified, first, length, e->coding_headers)) {
        case RangeOutcome::done: return;
        case RangeOutcome::partial:
            if (e->descriptor_only) r.body = FileBody{&e->fd, length, 0, first};
            else r.body = MemoryBody{std::string_view(e->data.data() + first, static_cast<std::size_t>(length))};
            r.entry = std::move(e);
            return;
        case RangeOutcome::whole: break;
    }
    // Zero-concatenation path: the entry's prebuilt block already ends with the blank line.
    r.status = 200;
    r.prebuilt_headers = e->headers;
    r.prebuilt_terminated = true;
    r.prebuilt_h2 = e->h2_block;
    r.content_type = e->content_type;
    r.content_encoding = e->content_encoding;
    r.vary = !e->coding_headers.empty();
    if (e->descriptor_only) r.body = FileBody{&e->fd, e->size, 0};  // streamed from the cached descriptor
    else r.body = MemoryBody{std::string_view(e->data.data(), e->data.size())};
    r.entry = std::move(e);
}

void StaticHandler::fill_entry(CacheEntry& entry, const FileInfo& fi, std::string_view path,
                               std::string_view content_type, Encoding coding, bool vary, std::time_t now) {
    static constexpr std::string_view kVary = "Vary: Accept-Encoding\r\n";
    static constexpr std::string_view kBr = "Content-Encoding: br\r\nVary: Accept-Encoding\r\n";
    static constexpr std::string_view kGzip = "Content-Encoding: gzip\r\nVary: Accept-Encoding\r\n";
    entry.file_path = path;
    entry.content_type = content_type;
    entry.mtime = fi.mtime;
    entry.size = fi.size;
    entry.coding_headers = coding == Encoding::br ? kBr : coding == Encoding::gzip ? kGzip : vary ? kVary : std::string_view{};
    entry.content_encoding = coding == Encoding::br ? std::string_view("br") : coding == Encoding::gzip ? std::string_view("gzip") : std::string_view{};
    make_etag(fi.mtime, fi.size, entry.etag);
    entry.last_modified.resize(kHttpDateLength);
    format_http_date(static_cast<std::time_t>(fi.mtime), entry.last_modified.data());
    entry.headers.reserve(224);
    entry.headers.append("Content-Type: ").append(content_type).append("\r\nContent-Length: ");
    append_number(entry.headers, fi.size);
    entry.headers.append("\r\nLast-Modified: ")
        .append(entry.last_modified)
        .append("\r\nETag: ")
        .append(entry.etag)
        .append("\r\n")
        .append(entry.coding_headers)
        .append("Accept-Ranges: bytes\r\n\r\n");
    // The HTTP/2 tail: the fields that change per file as one HPACK block of literals,
    // built here and copied per response by the h2 writer (nginx encodes every header of
    // every response; the cache pays once per entry). content-type, content-encoding and
    // vary are not in it: the writer sends those through the connection's dynamic table.
    entry.h2_block.reserve(96);
    std::string length;
    append_number(length, fi.size);
    hpack::append_field(entry.h2_block, "content-length", length);
    hpack::append_field(entry.h2_block, "last-modified", entry.last_modified);
    hpack::append_field(entry.h2_block, "etag", entry.etag);
    hpack::append_field(entry.h2_block, "accept-ranges", "bytes");
    entry.last_access.store(now, std::memory_order_relaxed);
    entry.last_validated.store(now, std::memory_order_relaxed);
}

// The pre-compressed twins of the file just loaded, name.br and name.gz beside it (Vite,
// webpack, the brotli and gzip tools write them at build time; nginx's gzip_static and
// brotli_static serve them): a twin at least as new as the file is loaded like the file,
// bytes, a descriptor for sendfile when large enough, the file's Content-Type and an ETag
// of its own. An older twin is a build that was not redone and is left alone rather than
// served stale. Two opens per fill, failing at once when there are none.
void StaticHandler::load_variants(CacheEntry& parent, const FileInfo& fi, const LocationConfig& loc,
                                  WorkerState& ws, std::time_t now) {
    struct Twin {
        const char* suffix;
        Encoding coding;
    };
    static constexpr Twin kTwins[] = {{".br", Encoding::br}, {".gz", Encoding::gzip}};
    const std::size_t base = ws.fs_path.size();
    for (const Twin& t : kTwins) {
        ws.fs_path.resize(base);
        ws.fs_path.append(t.suffix);
        File f = File::open(ws.fs_path.c_str());
        FileInfo tfi;
        if (!f.is_open() || !f.info(tfi) || !tfi.is_regular || tfi.size == 0 || tfi.mtime < fi.mtime ||
            tfi.size > cache_.max_file_size())
            continue;
        if (loc.symlinks_deny && !path_within_root(ws.fs_path.c_str(), loc.alias.empty() ? loc.root : loc.alias)) continue;
        auto twin = std::make_shared<CacheEntry>();
        twin->data.resize(static_cast<std::size_t>(tfi.size));
        if (!f.read_all(twin->data.data(), twin->data.size())) continue;
        if (cfg_.cache_sendfile_min_size > 0 && tfi.size >= cfg_.cache_sendfile_min_size) twin->fd = std::move(f);
        fill_entry(*twin, tfi, ws.fs_path, parent.content_type, t.coding, true, now);
        (t.coding == Encoding::br ? parent.br : parent.gzip) = std::move(twin);
    }
    ws.fs_path.resize(base);
}

// Whether the twins beside a cached file are as the entry loaded them: the same two stats
// as a fill, once per revalidation interval, so a twin added, replaced or removed shows
// within the interval like a change of the file itself.
bool StaticHandler::twins_unchanged(const CacheEntry& e, WorkerState& ws) {
    struct Twin {
        const char* suffix;
        const CacheEntry* cached;
    };
    const Twin twins[] = {{".br", e.br.get()}, {".gz", e.gzip.get()}};
    for (const Twin& t : twins) {
        ws.fs_path.assign(e.file_path).append(t.suffix);
        FileInfo fi;
        const bool usable = stat_path(ws.fs_path.c_str(), fi) && fi.is_regular && fi.size > 0 && fi.mtime >= e.mtime &&
                            fi.size <= cache_.max_file_size();
        if (usable != (t.cached != nullptr)) return false;
        if (t.cached && (t.cached->mtime != fi.mtime || t.cached->size != fi.size)) return false;
    }
    return true;
}

void StaticHandler::serve_file(Stream& s, File&& f, const FileInfo& fi, WorkerState& ws) {
    Response& r = s.response;
    r.head = s.request.method == Method::head;
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
    std::uint64_t first = 0, length = 0;
    switch (apply_range(s, fi.size, mime_for_path(ws.fs_path), etag, std::string_view(lm, kHttpDateLength), first,
                        length)) {
        case RangeOutcome::done: return;
        case RangeOutcome::partial:
            r.owned_file = std::move(f);
            r.body = FileBody{&r.owned_file, length, 0, first};
            return;
        case RangeOutcome::whole: break;
    }
    r.status = 200;
    r.scratch.assign("Content-Type: ").append(mime_for_path(ws.fs_path)).append("\r\nContent-Length: ");
    append_number(r.scratch, fi.size);
    r.scratch.append("\r\nLast-Modified: ")
        .append(lm, kHttpDateLength)
        .append("\r\nETag: ")
        .append(etag)
        .append("\r\nAccept-Ranges: bytes\r\n\r\n");
    r.prebuilt_headers = r.scratch;
    r.prebuilt_terminated = true;
    r.owned_file = std::move(f);
    r.body = FileBody{&r.owned_file, fi.size, 0};
}

void StaticHandler::redirect_slash(Stream& s, WorkerState& ws) {
    Response& r = s.response;
    const ErrorPage& page = error_page(301);
    r.status = 301;
    r.head = s.request.method == Method::head;
    r.scratch.assign(ws.path).push_back('/');
    r.headers.add("Location", r.scratch);
    r.prebuilt_headers = page.headers;
    r.prebuilt_h2 = page.h2_headers;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{page.body};
}

void fs_path_of(const LocationConfig& loc, WorkerState& ws) {
    if (loc.alias.empty()) ws.fs_path.assign(loc.root).append(ws.path);
    else ws.fs_path.assign(loc.alias).append(ws.path, loc.path.size() - 1, std::string::npos);  // keeps the '/'
}

// The index file of the directory ws.path (which ends with '/'): `found` with it open and
// ws.fs_path at it, `responded` when there is none (ws.fs_path at the directory), or
// `redirect` when the index belongs to another location. That last case is nginx's
// `index` semantics, an internal redirect to path + index: a Laravel site's "/" becomes
// "/index.php", which the exact FastCGI location owns, not the static one.
StaticHandler::Lookup StaticHandler::index_lookup(const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi) {
    fs_path_of(loc, ws);
    const std::size_t base = ws.fs_path.size();
    for (const auto& index : loc.index) {
        ws.fs_path.resize(base);
        ws.fs_path.append(index);
        f = File::open(ws.fs_path.c_str());
        if (!f.is_open() || !f.info(fi) || !fi.is_regular) {
            f.close();
            continue;
        }
        const auto* site = static_cast<const SiteConfig*>(ws.site);
        const std::size_t path_len = ws.path.size();
        ws.path.append(index);
        if (&Router::location(*site, ws.path) != &loc) {
            f.close();
            return Lookup::redirect;  // ws.path is now the index path; the caller routes it again
        }
        ws.path.resize(path_len);
        return Lookup::found;
    }
    ws.fs_path.resize(base);
    return Lookup::responded;
}

// The rule without try_files: a directory URI serves its index (403 without one, 404 if
// the directory does not exist); a file URI serves the file, redirects to the slash form
// for a directory, and is 404 otherwise.
StaticHandler::Lookup StaticHandler::plain_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f,
                                                  FileInfo& fi) {
    const bool keep_alive = s.request.keep_alive;
    if (ws.path.back() == '/') {
        const Lookup r = index_lookup(loc, ws, f, fi);
        if (r != Lookup::responded) return r;
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
                    const Lookup r = index_lookup(loc, ws, f, fi);
                    if (r != Lookup::responded) return r;
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
    // A site without a document root (redirect, proxy) has nothing to serve here; never
    // fall back to the filesystem root or the configuration directory.
    if (loc.root.empty() && loc.alias.empty()) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }
    // Dotfiles and dot-directories (.env, .git, .htaccess) are never served unless the
    // location opts in. 404 rather than 403 so their existence is not disclosed.
    if (!loc.hidden_files && has_hidden_segment(ws.path)) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }
    // Endings this location refuses outright (PHP sources under an uploads directory).
    // Refused endings answer 404 like hidden files, so a refusal never confirms that a
    // file exists (one policy for dotfiles, credentials files and PHP where it may not run).
    if (!loc.deny_suffixes.empty() && refused_suffix(ws.path, loc.deny_suffixes)) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }
    // Backup spellings of the names the site never serves (wp-config.php.bak, .wp-config.php.swp):
    // the same 404 as the name, whatever the ending and whatever hidden_files says.
    if (!loc.protects.empty() && backup_of_protected(ws.path, loc.protects)) {
        error(s, 404, req.keep_alive);
        return Outcome::done;
    }
    // A method this handler does not serve (POST to a Laravel route): only try_files can
    // rescue it by redirecting to an application location; a real file means 405.
    if (!ws.method_allowed) {
        File f;
        FileInfo fi;
        switch (try_files_lookup(s, loc, ws, f, fi)) {
            case Lookup::redirect: return Outcome::redirect;
            case Lookup::found: error(s, 405, req.keep_alive, loc.allow); return Outcome::done;
            case Lookup::responded: return Outcome::done;
        }
    }
    const std::time_t now = ws.now;
    const CacheKeyView key{loc.id, ws.path};

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
        bool same = stat_path(raw->file_path.c_str(), fi) && fi.is_regular && fi.mtime == raw->mtime && fi.size == raw->size;
        if (same && cfg_.cache_precompressed && !raw->descriptor_only) same = twins_unchanged(*raw, ws);
        if (!same) {
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
        add_headers(s, loc);
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
        const std::string_view type = mime_for_path(ws.fs_path);
        entry->content_type = type;
        if (cfg_.cache_precompressed) load_variants(*entry, fi, loc, ws, now);
        fill_entry(*entry, fi, ws.fs_path, type, Encoding::identity, entry->has_variants(), now);

        EntryPtr canonical = cache_.insert(key, entry);
        if (canonical) ws.local.insert(key, canonical);
        else canonical = std::move(entry);  // cache full for this size class: serve once, uncached
        serve_entry(s, std::move(canonical));
        add_headers(s, loc);
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
        fill_entry(*entry, fi, ws.fs_path, mime_for_path(ws.fs_path), Encoding::identity, false, now);
        EntryPtr canonical = cache_.insert(key, entry);
        if (canonical) {
            ws.local.insert(key, canonical);
            serve_entry(s, std::move(canonical));
            add_headers(s, loc);
            return Outcome::done;
        }
        f = std::move(entry->fd);  // store refused it: serve once from the open file
    }
    serve_file(s, std::move(f), fi, ws);
    add_headers(s, loc);
    return Outcome::done;
}

// Configured response fields (add_headers) on 200 and 304; the values live in the config.
void StaticHandler::add_headers(Stream& s, const LocationConfig& loc) {
    for (const auto& h : loc.add_headers)
        s.response.headers.add(h.first, h.second);
}

}  // namespace agensio
