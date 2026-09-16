// Static file handler: turns a request into a Response served from the cache or a file.
// No socket I/O here; the protocol connection writes the Response.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include "cache.hpp"
#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"
#include "file.hpp"

namespace agensio {

struct StringViewHash {
    using is_transparent = void;
    std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
};

// Which site serves which Host header on one listening address. (Phase A4 grows this
// into the router with locations.)
struct Route {
    std::unordered_map<std::string, const SiteConfig*, StringViewHash, std::equal_to<>> by_name;
    const SiteConfig* default_site = nullptr;

    // host is the raw Host header value (may include a port).
    const SiteConfig* lookup(std::string_view host) const noexcept;
};

class StaticHandler {
public:
    StaticHandler(const Config& cfg, FileCache& cache);

    // Fills s.response for s.request. ws.now must be set by the caller.
    void handle(Stream& s, const Route& route, WorkerState& ws);

    // Fills s.response with a canned error page. `allow` adds an Allow header (405).
    void error(Stream& s, int status, bool keep_alive, std::string_view allow = {});

private:
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
