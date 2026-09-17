// Static file handler: turns a request into a Response served from the cache or a file.
// No socket I/O here; the protocol connection writes the Response. The dispatcher picks the
// site and the location; this handler applies the location's root, index, try_files and
// policies. An internal redirect from try_files re-enters the router with the new path.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>

#include "cache.hpp"
#include "config.hpp"
#include "core/router.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "file.hpp"

namespace agensio {

class StaticHandler {
public:
    StaticHandler(const Config& cfg, FileCache& cache);

    enum class Outcome { done, redirect };  // redirect: ws.path holds the try_files target

    // Serves ws.path under `loc` (cache, file, try_files). ws.now must be set by the caller.
    Outcome serve_location(Stream& s, const LocationConfig& loc, WorkerState& ws);

    // Fills s.response with a canned error page. `allow` adds an Allow header (405).
    void error(Stream& s, int status, bool keep_alive, std::string_view allow = {});
    // 204 with an Allow header (OPTIONS).
    void no_content(Stream& s, std::string_view allow);

    static constexpr int kMaxInternalRedirects = 8;  // try_files fallbacks per request (nginx: 10)

private:
    enum class Lookup { found, responded, redirect };

    Lookup plain_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    Lookup try_files_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    Lookup index_lookup(const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);

    void serve_entry(Stream& s, EntryPtr e);  // takes ownership of the ref
    static void add_headers(Stream& s, const LocationConfig& loc);
    // Metadata and prebuilt header block shared by memory and descriptor entries.
    void fill_entry(CacheEntry& e, const FileInfo& fi, const WorkerState& ws, std::time_t now);
    void serve_file(Stream& s, File&& f, const FileInfo& fi, WorkerState& ws);
    void redirect_slash(Stream& s, WorkerState& ws);
    static bool not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept;

    const Config& cfg_;
    FileCache& cache_;
};

// Helpers shared with tests and the other handlers.
void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out);
// The filesystem path for ws.path under the location: root + path, or with `alias` the
// alias directory in place of the location prefix (nginx semantics). Result in ws.fs_path.
void fs_path_of(const LocationConfig& loc, WorkerState& ws);

}  // namespace agensio
