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
// Formats: "combined" is byte-compatible with Apache/nginx (fail2ban filters work
// unchanged); "json" is one object per line. Both escape the client-controlled fields.
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
enum class AccessLogFormat { combined, json };

class LogFile {
public:
    explicit LogFile(std::string path) : path_(std::move(path)) {}
    LogFile(const LogFile&) = delete;
    LogFile& operator=(const LogFile&) = delete;
    ~LogFile();

    // Opens (or reopens) the path, creating its parent directory if missing. "stderr" means
    // descriptor 2. Returns false with errno set.
    bool open() noexcept;
    // Rotation: open again, swap, and release the descriptor from the reopen before this one.
    bool reopen() noexcept { return open(); }
    // One write() of `data` (looped on partial writes); errors are dropped, logging never fails a request.
    void write(std::string_view data) noexcept;

    const std::string& path() const noexcept { return path_; }
    bool is_open() const noexcept { return fd_.load(std::memory_order_acquire) >= 0; }

private:
    std::string path_;
    std::atomic<int> fd_{-1};
    int previous_ = -1;  // descriptor replaced by the last reopen, closed at the next one
};

// Sinks by path: sites that log to the same file share one descriptor.
class LogRegistry {
public:
    // Returns the sink id for `path` (adding it if new); "" and "off" give -1 (no logging).
    int add(const std::string& path);
    LogFile& sink(int id) noexcept { return *sinks_[static_cast<std::size_t>(id)]; }
    std::size_t size() const noexcept { return sinks_.size(); }
    // Opens every sink; on failure returns false and names the path in `error`.
    bool open_all(std::string& error) noexcept;
    void reopen_all() noexcept;

private:
    std::vector<std::unique_ptr<LogFile>> sinks_;
};

// What one access log line needs; every view is borrowed for the duration of the call.
struct AccessRecord {
    std::string_view remote;  // client address
    std::string_view host;    // Host header (json only)
    std::string_view method;
    std::string_view target;
    int version_minor = 1;
    int status = 200;
    std::uint64_t bytes = 0;  // body bytes sent
    std::string_view referer;
    std::string_view user_agent;
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
    static void format_json(std::string& out, std::string_view time_iso, const AccessRecord& r);

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
