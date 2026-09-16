// Static file handler: turns a request into a Response served from the cache or a file.
// No socket I/O here; the protocol connection writes the Response. The router picks the
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

    // Fills s.response for s.request. ws.now must be set by the caller.
    void handle(Stream& s, const Router& router, WorkerState& ws);

    // Fills s.response with a canned error page. `allow` adds an Allow header (405).
    void error(Stream& s, int status, bool keep_alive, std::string_view allow = {});
    // 204 with an Allow header (OPTIONS).
    void no_content(Stream& s, std::string_view allow);

    static constexpr int kMaxInternalRedirects = 8;  // try_files fallbacks per request (nginx: 10)

private:
    enum class Outcome { done, redirect };  // redirect: ws.path holds the try_files target
    enum class Lookup { found, responded, redirect };

    Outcome serve_location(Stream& s, const LocationConfig& loc, WorkerState& ws);
    Lookup plain_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    Lookup try_files_lookup(Stream& s, const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);
    static bool open_index(const LocationConfig& loc, WorkerState& ws, File& f, FileInfo& fi);

    void serve_entry(Stream& s, EntryPtr e);  // takes ownership of the ref
    // Metadata and prebuilt header block shared by memory and descriptor entries.
    void fill_entry(CacheEntry& e, const FileInfo& fi, const WorkerState& ws, std::time_t now);
    void serve_file(Stream& s, File&& f, const FileInfo& fi, WorkerState& ws);
    void redirect_slash(Stream& s, WorkerState& ws);
    static bool not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept;

    const Config& cfg_;
    FileCache& cache_;
};

// Helpers shared with tests.
void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out);

}  // namespace agensio
