// Access and error logging.
//
//  * LogFile: one descriptor per path, shared by every worker, opened O_APPEND so that each
//    write() of whole lines lands atomically at the end of the file. reopen() is the
//    rotation hook (SIGUSR1): the path is opened again and swapped in; the descriptor it
//    replaces is kept until the *next* reopen so a worker that raced the swap still writes
//    into the rotated file instead of a closed (or worse, recycled) descriptor.
//  * WorkerLogs: per worker, never shared. One buffer per sink; a request appends one
//    formatted line (no syscall); the buffer is written when it reaches kFlushSize or when
//    the worker's flush timer fires. The local time string is formatted once per second.
//  * ErrorLog: server-wide, level-filtered, nginx-like lines ("2026/09/17 10:15:32 [error] ...").
//
// Formats: "vhost_combined" (the default since 2026-11-02) is Apache's: the combined line with
// the requested host and the listener's port in front (%v:%p), what a shared file needs to tell a
// stray domain from a scan by bare address, read by GoAccess as VCOMBINED and by the shipped
// fail2ban filters, which take the prefix as optional; "combined" is the classic line, byte-
// compatible with Apache/nginx; "json" is one object per line. All escape the client's fields.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace agensio {

enum class LogLevel { error = 0, warn = 1, info = 2 };
enum class AccessLogFormat { combined, json, vhost_combined };

inline std::string_view access_log_format_name(AccessLogFormat f) noexcept {
    return f == AccessLogFormat::json ? "json" : f == AccessLogFormat::vhost_combined ? "vhost_combined" : "combined";
}

// Where the logs are opened (0.1.0-alpha.129, docs/configuration.md 8c, docs/security-control-plane.md
// row 59). The start opens every log as root and keeps the descriptors across the privilege drop, and
// the site files under sites.d are the server account's: so below the log directory, whose sites/ is
// that account's too, nothing is trusted. A path there is reached one component at a time without
// following a link (a link planted as sites/, or as a site's log, is refused by name), the file must
// be a regular one with one name, and only sites/ is ever made. A path elsewhere was named by the main
// file or by a site file of its owner (config.cpp site_log_problem), root's word as with nginx and
// Apache, and is opened as named; the directory it lies in is root's to own.
struct LogPlacement {
    std::string directory;  // the log directory (config.hpp log_directory): "" walks nothing
    long uid = -1, gid = -1;  // the server's account, which sites/ belongs to when root makes it; -1 unknown
};

// Whether `path` lies below `directory` (lexically; both absolute and normal; never for "").
bool below_log_dir(const std::string& directory, const std::string& path) noexcept;

// The one open of a path below the log directory: the directory resolved as the main file names it (a
// link at or above it is the system's layout; made 0750 root:<server group> when missing, as the package
// makes it), every component below it opened without following a link, the final one with `flags`
// (O_NOFOLLOW, O_CLOEXEC and, against a FIFO, O_NONBLOCK added; a file created with `mode`), then checked:
// a directory when `flags` says so, else a regular file with one name, owned by root or the server's
// account. sites/ directly below the directory is made when missing (with O_CREAT) and, as root, made the
// server account's, 0750 (a sites/ root made before 0.1.0-alpha.129 stayed root's); no other directory
// is made. -1 with `why` and errno (ELOOP for a link, ENOENT for a directory it does not make, EACCES
// when the account cannot create the file, EINVAL for a path it does not walk).
int open_below_log_dir(const LogPlacement& where, const std::string& path, int flags, unsigned mode, std::string& why) noexcept;
// The same walk, read-only, for -t, the reload's notices and health (the alpha.129 report, P2: -t passed
// what the start then refused): nothing made, nothing handed over, the file opened for reading and closed.
// "" when the start would open `path` (a missing log, sites/ or log directory, which it makes) or when this
// account may not look (a -t not run as root); else the start's refusal, with its fix, or without it when
// `fix` is given, which then holds the fix alone.
std::string probe_below_log_dir(const LogPlacement& where, const std::string& path, std::string* fix = nullptr) noexcept;

class LogFile {
public:
    explicit LogFile(std::string path) : path_(std::move(path)) {}
    LogFile(const LogFile&) = delete;
    LogFile& operator=(const LogFile&) = delete;
    ~LogFile();

    // Opens (or reopens) the path: below `where.directory` through open_below_log_dir, elsewhere as
    // named, creating its parent directory if missing. "stderr" means descriptor 2. Returns false
    // with errno set and error() saying why.
    bool open(const LogPlacement& where) noexcept;
    // Rotation: open again, swap, and release the descriptor from the reopen before this one.
    bool reopen(const LogPlacement& where) noexcept { return open(where); }
    // One write() of `data` (looped on partial writes); errors are dropped, logging never fails a request.
    void write(std::string_view data) noexcept;
    // The open descriptor made `uid`:`gid` 0640 (fchown, fchmod: never by path, which follows a link):
    // the server's account at the start, so it writes on after the privilege drop and a site's group
    // reads. True when it already is; false with errno (EPERM for an account not in the group).
    bool own(unsigned uid, unsigned gid) noexcept;
    // The open descriptor's owner and group (fstat); false when not open.
    bool owner(unsigned& uid, unsigned& gid) const noexcept;
    // Why the last open failed, in words ("" when it succeeded); errno_of() its errno.
    const std::string& error() const noexcept { return error_; }
    int errno_of() const noexcept { return errno_; }

    const std::string& path() const noexcept { return path_; }
    // Whether the configuration in force names this file. A sink of a site that is gone keeps
    // its descriptor (a worker may still flush a line to it) but is never opened again:
    // before 2026-09-30 every reload recreated a deleted site's log, empty, which then stood in
    // the way of restoring the site from the trash.
    bool wanted() const noexcept { return wanted_; }
    void set_wanted(bool w) noexcept { wanted_ = w; }
    bool is_open() const noexcept { return fd_.load(std::memory_order_acquire) >= 0; }

private:
    std::string path_;
    std::atomic<int> fd_{-1};
    int previous_ = -1;  // descriptor replaced by the last reopen, closed at the next one
    bool wanted_ = true;
    std::string error_;
    int errno_ = 0;
};

// Sinks by path: sites that log to the same file share one descriptor.
class LogRegistry {
public:
    struct Failure {
        std::string path, why;
        int err = 0;  // errno
    };
    // Where the sinks are opened (LogPlacement); set before the first open, kept for the reopens.
    void set_placement(LogPlacement where) { where_ = std::move(where); }
    const LogPlacement& placement() const noexcept { return where_; }
    // Returns the sink id for `path` (adding it if new); "" and "off" give -1 (no logging).
    int add(const std::string& path);  // marks the sink wanted
    void unmark_all() noexcept;        // before a configuration's sinks are added again
    LogFile& sink(int id) noexcept { return *sinks_[static_cast<std::size_t>(id)]; }
    std::size_t size() const noexcept { return sinks_.size(); }
    // Opens every wanted sink not open yet (a reload opens what it added; a file opened before stays
    // as it is until a SIGUSR1 reopens it), each failure appended to `failed`.
    void open_wanted(std::vector<Failure>& failed) noexcept;
    // open_wanted for one error: false naming the first path that did not open in `error`.
    bool open_all(std::string& error) noexcept;
    // Every wanted sink opened again (SIGUSR1, logs_reopen); a file that does not open keeps its
    // previous descriptor, so its lines go on into the file opened before: each such one in the answer
    // (the alpha.129 report, P3: it was said nowhere).
    std::vector<Failure> reopen_all() noexcept;
    // Whether a sink for `path` is open: a reload keeps it as it is (validate judges as the reload does).
    bool is_open(const std::string& path) const noexcept;

private:
    std::vector<std::unique_ptr<LogFile>> sinks_;
    LogPlacement where_;
};

// What one access log line needs; every view is borrowed for the duration of the call.
struct AccessRecord {
    std::string_view remote;  // client address
    std::string_view host;    // Host header as sent (json, and vhost_combined's prefix: lower case, port dropped)
    std::uint16_t port = 0;   // the listener's port (vhost_combined's prefix)
    std::string_view method;
    std::string_view target;
    int version_minor = 1;
    std::string_view protocol;  // "HTTP/2.0" from the HTTP/2 connection; empty: HTTP/1.<version_minor>
    int status = 200;
    std::uint64_t bytes = 0;  // body bytes sent
    std::string_view referer;
    std::string_view user_agent;
    std::string_view upstream;  // "ok", an FcgiFailure name, or empty for static (json only)
    std::string_view user;      // the user a password check verified ([[site.auth]]); empty: "-"
};

class WorkerLogs {
public:
    static constexpr std::size_t kFlushSize = 32 * 1024;

    // Sizes one buffer per registry sink. Call once per worker before requests arrive.
    void attach(LogRegistry* registry, AccessLogFormat format);
    bool enabled() const noexcept { return registry_ != nullptr && !buffers_.empty(); }

    // Appends one line for `sink`; writes the buffer out when it is full.
    void log(int sink, std::time_t now, const AccessRecord& r);
    // Writes every non-empty buffer (timer, shutdown).
    void flush() noexcept;

    // Formatters, exposed for tests. `time_local` is "17/Sep/2026:10:15:32 +0300",
    // `time_iso` is "2026-09-17T10:15:32+03:00".
    static void format_combined(std::string& out, std::string_view time_local, const AccessRecord& r);
    static void format_vhost_combined(std::string& out, std::string_view time_local, const AccessRecord& r);
    static void format_json(std::string& out, std::string_view time_iso, const AccessRecord& r);
    // [log] format applies on reload: set from the worker's own loop when it takes the generation.
    void set_format(AccessLogFormat format) noexcept { format_ = format; }

private:
    void refresh_time(std::time_t now);

    LogRegistry* registry_ = nullptr;
    AccessLogFormat format_ = AccessLogFormat::combined;
    std::vector<std::string> buffers_;
    std::time_t time_second_ = 0;
    std::string time_local_;
    std::string time_iso_;
};

class ErrorLog {
public:
    void configure(LogRegistry* registry, int sink, LogLevel level) noexcept {
        registry_ = registry;
        sink_ = sink;
        level_ = level;
    }
    bool enabled(LogLevel level) const noexcept { return sink_ >= 0 && level <= level_; }
    void log(LogLevel level, std::string_view message) noexcept;
    void error(std::string_view message) noexcept { log(LogLevel::error, message); }
    void warn(std::string_view message) noexcept { log(LogLevel::warn, message); }
    void info(std::string_view message) noexcept { log(LogLevel::info, message); }

private:
    LogRegistry* registry_ = nullptr;
    int sink_ = -1;
    LogLevel level_ = LogLevel::warn;
};

// Parses "error" | "warn" | "info"; returns false for anything else.
bool parse_log_level(std::string_view text, LogLevel& out) noexcept;

}  // namespace agensio
