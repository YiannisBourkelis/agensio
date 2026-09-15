// Turns a parsed request into a response plan (headers + where the body comes from).
// Contains no I/O on sockets; the Connection executes the plan.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

#include "cache.hpp"
#include "config.hpp"
#include "file.hpp"
#include "http_date.hpp"
#include "http_parser.hpp"

namespace agensio {

struct StringViewHash {
    using is_transparent = void;
    std::size_t operator()(std::string_view s) const noexcept { return std::hash<std::string_view>{}(s); }
};

// Which site serves which Host header on one listening address.
struct Route {
    std::unordered_map<std::string, const SiteConfig*, StringViewHash, std::equal_to<>> by_name;
    const SiteConfig* default_site = nullptr;

    // host is the raw Host header value (may include a port).
    const SiteConfig* lookup(std::string_view host) const noexcept;
};

// Per-worker scratch state. Never shared between threads.
struct WorkerState {
    DateCache date;
    LocalIndex local;
    std::string path;      // normalised request path
    std::string fs_path;   // filesystem path being served
    std::string tmp;
};

struct ResponsePlan {
    enum class Body { none, entry, file, inline_text };

    std::string header;                 // complete header block, ends with "\r\n\r\n"
    Body body = Body::none;
    EntryPtr entry;                     // Body::entry
    File file;                          // Body::file
    std::uint64_t file_size = 0;
    std::uint64_t file_sent = 0;
    std::string_view inline_text;       // Body::inline_text (static storage)
    bool keep_alive = true;

    void reset() {
        header.clear();
        body = Body::none;
        entry.reset();
        file.close();
        file_size = file_sent = 0;
        inline_text = {};
        keep_alive = true;
    }
};

class RequestHandler {
public:
    RequestHandler(const Config& cfg, FileCache& cache);

    void handle(const Request& req, const Route& route, WorkerState& ws, ResponsePlan& plan);

    // Builds an error response. `head` suppresses the body.
    void error(int status, bool keep_alive, bool head, WorkerState& ws, ResponsePlan& plan,
               std::string_view extra_headers = {});

private:
    void begin_header(int status, WorkerState& ws, ResponsePlan& plan);
    void end_header(const Request& req, ResponsePlan& plan);
    void end_header(bool keep_alive, int version_minor, ResponsePlan& plan);
    void serve_entry(const Request& req, EntryPtr e, WorkerState& ws, ResponsePlan& plan);  // takes ownership of the ref
    void serve_file(const Request& req, File&& f, const FileInfo& fi, WorkerState& ws, ResponsePlan& plan);
    void redirect_slash(const Request& req, WorkerState& ws, ResponsePlan& plan);
    static bool not_modified(const Request& req, std::string_view etag, std::string_view last_modified) noexcept;

    const Config& cfg_;
    FileCache& cache_;
    std::string server_line_;   // "Server: agensio\r\n"
};

// Helpers shared with tests.
void make_etag(std::int64_t mtime, std::uint64_t size, std::string& out);

}  // namespace agensio
