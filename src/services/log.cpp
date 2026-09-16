#include "services/log.hpp"

#include <cerrno>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <filesystem>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <sys/stat.h>
#define AGENSIO_OPEN_FLAGS (_O_WRONLY | _O_APPEND | _O_CREAT | _O_BINARY)
#else
#include <fcntl.h>
#include <unistd.h>
#define AGENSIO_OPEN_FLAGS (O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC)
#endif

namespace agensio {

namespace {

int sys_open_append(const char* path) noexcept {
#ifdef _WIN32
    int fd = -1;
    _sopen_s(&fd, path, AGENSIO_OPEN_FLAGS, _SH_DENYNO, _S_IREAD | _S_IWRITE);
    return fd;
#else
    return ::open(path, AGENSIO_OPEN_FLAGS, 0644);
#endif
}

void sys_close(int fd) noexcept {
#ifdef _WIN32
    _close(fd);
#else
    ::close(fd);
#endif
}

// One write() per call, retried on partial writes and EINTR; other errors drop the data.
void write_all(int fd, std::string_view data) noexcept {
    while (!data.empty()) {
#ifdef _WIN32
        const int n = _write(fd, data.data(), static_cast<unsigned>(data.size()));
#else
        const ssize_t n = ::write(fd, data.data(), data.size());
#endif
        if (n < 0) {
            if (errno == EINTR) continue;
            return;
        }
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}

inline void append_uint(std::string& s, std::uint64_t v) {
    char buf[24];
    auto r = std::to_chars(buf, buf + sizeof(buf), v);
    s.append(buf, r.ptr);
}

// nginx-style escaping for the combined format: '"', '\\' and control bytes as \xHH.
void append_escaped(std::string& out, std::string_view v) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (unsigned char c : v) {
        if (c == '"' || c == '\\' || c < 0x20 || c == 0x7f) {
            out.append("\\x");
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
}

// JSON string escaping (RFC 8259); bytes >= 0x80 pass through as UTF-8.
void append_json(std::string& out, std::string_view v) {
    static constexpr char kHex[] = "0123456789abcdef";
    out.push_back('"');
    for (unsigned char c : v) {
        switch (c) {
            case '"': out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (c < 0x20 || c == 0x7f) {
                    out.append("\\u00");
                    out.push_back(kHex[c >> 4]);
                    out.push_back(kHex[c & 15]);
                } else {
                    out.push_back(static_cast<char>(c));
                }
        }
    }
    out.push_back('"');
}

void local_time(std::time_t t, std::tm& out) noexcept {
#ifdef _WIN32
    localtime_s(&out, &t);
#else
    localtime_r(&t, &out);
#endif
}

}  // namespace

// ---- LogFile ----

LogFile::~LogFile() {
    const int fd = fd_.exchange(-1, std::memory_order_acq_rel);
    if (fd > 2) sys_close(fd);
    if (previous_ > 2) sys_close(previous_);
}

bool LogFile::open() noexcept {
    int fd = -1;
    if (path_ == "stderr") fd = 2;
    else {
        fd = sys_open_append(path_.c_str());
        if (fd < 0 && errno == ENOENT) {  // default "logs/access.log" next to a fresh config
            std::error_code ec;
            std::filesystem::create_directories(std::filesystem::path(path_).parent_path(), ec);
            if (!ec) fd = sys_open_append(path_.c_str());
        }
        if (fd < 0) return false;
    }
    const int old = fd_.exchange(fd, std::memory_order_acq_rel);
    if (previous_ > 2) sys_close(previous_);
    previous_ = old;
    return true;
}

void LogFile::write(std::string_view data) noexcept {
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd < 0 || data.empty()) return;
    write_all(fd, data);
}

// ---- LogRegistry ----

int LogRegistry::add(const std::string& path) {
    if (path.empty() || path == "off") return -1;
    for (std::size_t i = 0; i < sinks_.size(); ++i)
        if (sinks_[i]->path() == path) return static_cast<int>(i);
    sinks_.push_back(std::make_unique<LogFile>(path));
    return static_cast<int>(sinks_.size() - 1);
}

bool LogRegistry::open_all(std::string& error) noexcept {
    for (auto& s : sinks_) {
        if (!s->open()) {
            error = "cannot open log file " + s->path() + ": " + std::strerror(errno);
            return false;
        }
    }
    return true;
}

void LogRegistry::reopen_all() noexcept {
    for (auto& s : sinks_)
        s->reopen();  // a failed reopen keeps writing to the previous descriptor
}

// ---- WorkerLogs ----

void WorkerLogs::attach(LogRegistry* registry, AccessLogFormat format) {
    registry_ = registry;
    format_ = format;
    buffers_.assign(registry ? registry->size() : 0, std::string());
    for (auto& b : buffers_)
        b.reserve(kFlushSize + 512);
}

void WorkerLogs::refresh_time(std::time_t now) {
    if (now == time_second_ && !time_local_.empty()) return;
    time_second_ = now;
    std::tm tm{};
    local_time(now, tm);
    char buf[64];
    std::size_t n = std::strftime(buf, sizeof(buf), "%d/%b/%Y:%H:%M:%S %z", &tm);
    time_local_.assign(buf, n);
    n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", &tm);
    time_iso_.assign(buf, n);
    if (time_iso_.size() >= 5) time_iso_.insert(time_iso_.size() - 2, ":");  // +0300 -> +03:00
}

void WorkerLogs::log(int sink, std::time_t now, const AccessRecord& r) {
    if (sink < 0 || static_cast<std::size_t>(sink) >= buffers_.size()) return;
    refresh_time(now);
    std::string& buf = buffers_[static_cast<std::size_t>(sink)];
    if (format_ == AccessLogFormat::json) format_json(buf, time_iso_, r);
    else format_combined(buf, time_local_, r);
    if (buf.size() >= kFlushSize) {
        registry_->sink(sink).write(buf);
        buf.clear();
    }
}

void WorkerLogs::flush() noexcept {
    for (std::size_t i = 0; i < buffers_.size(); ++i) {
        if (buffers_[i].empty()) continue;
        registry_->sink(static_cast<int>(i)).write(buffers_[i]);
        buffers_[i].clear();
    }
}

// remote - - [time] "METHOD target HTTP/1.x" status bytes "referer" "user-agent"
void WorkerLogs::format_combined(std::string& out, std::string_view time_local, const AccessRecord& r) {
    out.append(r.remote.empty() ? std::string_view("-") : r.remote).append(" - - [").append(time_local).append("] \"");
    if (r.method.empty()) {
        out.push_back('-');
    } else {
        append_escaped(out, r.method);
        out.push_back(' ');
        append_escaped(out, r.target);
        out.append(r.version_minor == 0 ? " HTTP/1.0" : " HTTP/1.1");
    }
    out.append("\" ");
    append_uint(out, static_cast<std::uint64_t>(r.status));
    out.push_back(' ');
    append_uint(out, r.bytes);
    out.append(" \"");
    if (r.referer.empty()) out.push_back('-');
    else append_escaped(out, r.referer);
    out.append("\" \"");
    if (r.user_agent.empty()) out.push_back('-');
    else append_escaped(out, r.user_agent);
    out.append("\"\n");
}

void WorkerLogs::format_json(std::string& out, std::string_view time_iso, const AccessRecord& r) {
    out.append("{\"time\":");
    append_json(out, time_iso);
    out.append(",\"remote\":");
    append_json(out, r.remote);
    out.append(",\"host\":");
    append_json(out, r.host);
    out.append(",\"method\":");
    append_json(out, r.method);
    out.append(",\"target\":");
    append_json(out, r.target);
    out.append(",\"proto\":\"HTTP/1.").push_back(r.version_minor == 0 ? '0' : '1');
    out.append("\",\"status\":");
    append_uint(out, static_cast<std::uint64_t>(r.status));
    out.append(",\"bytes\":");
    append_uint(out, r.bytes);
    out.append(",\"referer\":");
    append_json(out, r.referer);
    out.append(",\"user_agent\":");
    append_json(out, r.user_agent);
    out.append("}\n");
}

// ---- ErrorLog ----

void ErrorLog::log(LogLevel level, std::string_view message) noexcept {
    if (!enabled(level)) return;
    std::tm tm{};
    local_time(std::time(nullptr), tm);
    char stamp[32];
    const std::size_t n = std::strftime(stamp, sizeof(stamp), "%Y/%m/%d %H:%M:%S", &tm);
    std::string line;
    line.reserve(n + message.size() + 16);
    line.append(stamp, n);
    line.append(level == LogLevel::error ? " [error] " : level == LogLevel::warn ? " [warn] " : " [info] ");
    line.append(message);
    line.push_back('\n');
    registry_->sink(sink_).write(line);
}

bool parse_log_level(std::string_view text, LogLevel& out) noexcept {
    if (text == "error") out = LogLevel::error;
    else if (text == "warn") out = LogLevel::warn;
    else if (text == "info") out = LogLevel::info;
    else return false;
    return true;
}

}  // namespace agensio
