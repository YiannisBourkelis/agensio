#include "services/log.hpp"

#include "core/strings.hpp"

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
#include <sys/stat.h>
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
    return ::open(path, AGENSIO_OPEN_FLAGS, 0640);  // logs are the server's and a site group's to read, nobody else's
#endif
}

#ifndef _WIN32
// The log directory made when it is not there (a first start without the package, the default logs/
// next to the configuration): root's with the server's group, 0750, the package's layout; as anyone
// else, that account's. The components above it as create_directories makes them.
bool make_log_dir(const LogPlacement& where, std::string& why) noexcept {
    std::error_code ec;
    std::filesystem::create_directories(where.directory, ec);
    if (ec) {
        errno = ec.value();
        why = where.directory + ": " + ec.message();
        return false;
    }
    ::chmod(where.directory.c_str(), 0750);
    if (::geteuid() == 0 && where.gid >= 0) (void)::chown(where.directory.c_str(), 0, static_cast<gid_t>(where.gid));
    return true;
}
#endif

}  // namespace

bool below_log_dir(const std::string& directory, const std::string& path) noexcept {
    return !directory.empty() && path.size() > directory.size() + 1 && path.compare(0, directory.size(), directory) == 0 && path[directory.size()] == '/';
}

namespace {

constexpr int kProbeFine = -2;  // the probe's answer: nothing there the start would refuse, or nothing this account may judge

// The fix each refusal carries (the alpha.129 report, S2: one answer for every kind was wrong for most):
// a link standing for a directory, one standing for the log itself, a file of another kind. Each refusal
// is a problem and its fix, joined by ": " for the start's and the reopen's lines and given apart to the
// notices (the alpha.130 report, F3a: log_path_refused's fix was empty), worded alike on every path (F3d).
const char* const kDirFix = "make it a directory again (move the link aside, mkdir it, move the files back); for logs on another disk, "
                            "link or mount the log directory itself, which is followed";
const char* const kRecreate = "the start creates the log as a regular file, and so does the next reopen of a log already open";

const char* kind_of(mode_t m) noexcept {
    return S_ISFIFO(m) ? "a FIFO, " : S_ISDIR(m) ? "a directory, " : S_ISSOCK(m) ? "a socket, " : (S_ISCHR(m) || S_ISBLK(m)) ? "a device, " : "";
}

// open_below_log_dir and, with `probe`, its read-only twin: nothing made, nothing handed over, a missing
// log or sites/ (which the start makes) and a directory this account may not enter answered kProbeFine.
// `fix` (may be null): the refusal's fix apart, `why` then the problem alone.
int walk_below(const LogPlacement& where, const std::string& path, int flags, unsigned mode, std::string& why, bool probe, std::string* fix) noexcept {
    auto say = [&](std::string problem, std::string remedy = {}) {
        if (fix) {
            why = std::move(problem);
            *fix = std::move(remedy);
        } else {
            why = remedy.empty() ? std::move(problem) : problem + ": " + remedy;
        }
    };
#ifdef _WIN32
    (void)where;
    (void)flags;
    (void)mode;
    (void)probe;
    errno = EINVAL;
    say(path + ": not on this platform");
    return -1;
#else
    namespace fs = std::filesystem;
    const std::string& dir = where.directory;
    const std::string no_link = "; below the log directory " + dir + " every path is opened without following a link";
    const std::string no_dir = "below the log directory agensio makes only sites/";
    if (!below_log_dir(dir, path)) {
        errno = EINVAL;
        say(path + " is not below the log directory " + dir);
        return -1;
    }
    std::error_code ec;
    fs::path real = fs::canonical(dir, ec);
    if (ec == std::errc::no_such_file_or_directory && (flags & O_CREAT)) {
        if (!make_log_dir(where, why)) return -1;
        real = fs::canonical(dir, ec);
    }
    if (ec) {
        if (probe && (ec == std::errc::no_such_file_or_directory || ec == std::errc::permission_denied)) return kProbeFine;
        errno = ec.value();
        say(dir + ": " + ec.message());
        return -1;
    }
    int cur = ::open(real.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (cur < 0) {
        if (probe && errno == EACCES) return kProbeFine;
        say(dir + ": " + std::strerror(errno));
        return -1;
    }
    const std::string rel = path.substr(dir.size() + 1);
    std::string walked = dir;  // the directory `cur` is, by the path's own name
    std::size_t pos = 0;
    bool first = true;
    for (;;) {
        const std::size_t slash = rel.find('/', pos);
        const bool last = slash == std::string::npos;
        const std::string part = rel.substr(pos, last ? std::string::npos : slash - pos);
        pos = last ? rel.size() : slash + 1;
        if (part.empty() || part == "." || part == "..") {
            ::close(cur);
            errno = EINVAL;
            say(path + ": not a plain path below the log directory " + dir);
            return -1;
        }
        if (last) {
            const bool directory = (flags & O_DIRECTORY) != 0;
            const int fd = ::openat(cur, part.c_str(), flags | O_NOFOLLOW | O_CLOEXEC | (directory ? 0 : O_NONBLOCK), mode);
            int e = errno;
            // A FIFO without a reader (ENXIO) or a directory opened for writing (EISDIR): named by its kind,
            // as the probe's open, which succeeds, names it (F3d).
            struct stat seen {};
            const bool kind_known = fd < 0 && (e == ENXIO || e == EISDIR) && ::fstatat(cur, part.c_str(), &seen, AT_SYMLINK_NOFOLLOW) == 0;
            ::close(cur);
            if (fd < 0) {
                if (probe && (e == ENOENT || e == EACCES)) return kProbeFine;
                errno = e;
                // A link gives ELOOP, or ENOTDIR when a directory was asked for.
                if (directory && (e == ELOOP || e == ENOTDIR)) say(path + ": a symbolic link or not a directory" + no_link, kDirFix);
                else if (e == ELOOP) say(path + ": a symbolic link" + no_link + ", and a log is a regular file", std::string("remove the link; ") + kRecreate);
                else if (e == ENXIO || e == EISDIR)
                    say(path + ": " + (kind_known ? std::string(kind_of(seen.st_mode)) : e == EISDIR ? std::string("a directory, ") : std::string("a FIFO or a device, ")) +
                            "not a regular file (below the log directory nothing else is opened)",
                        std::string("move it aside; ") + kRecreate);
                else if (e == EACCES) say(path + ": " + std::strerror(e) + " (this account cannot create it in " + walked + ")");
                else say(path + ": " + std::strerror(e));
                return -1;
            }
            struct stat st {};
            if (::fstat(fd, &st) != 0) {
                e = errno;
                ::close(fd);
                errno = e;
                say(path + ": " + std::strerror(e));
                return -1;
            }
            if (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode)) {
                ::close(fd);
                errno = EINVAL;
                if (directory) say(path + ": not a directory (below the log directory nothing else is opened)" + no_link, kDirFix);
                else say(path + ": " + kind_of(st.st_mode) + "not a regular file (below the log directory nothing else is opened)", std::string("move it aside; ") + kRecreate);
                return -1;
            }
            if (!directory && st.st_nlink > 1) {  // a hard link to another file (fs.protected_hardlinks off): not written, not handed over
                ::close(fd);
                errno = EINVAL;
                say(path + ": has " + std::to_string(st.st_nlink) + " names (a hard link); below the log directory a log has one",
                    std::string("remove this name (the file it shares keeps its other); ") + kRecreate);
                return -1;
            }
            if (!directory && st.st_uid != 0 && where.uid >= 0 && st.st_uid != static_cast<uid_t>(where.uid) && ::geteuid() != st.st_uid) {
                ::close(fd);
                errno = EINVAL;
                say(path + ": owned by uid " + std::to_string(st.st_uid) + ", neither root's nor the server account's: not written",
                    std::string("give it to the server's account, or remove it; ") + kRecreate);
                return -1;
            }
            if (!directory) {  // O_NONBLOCK served against a FIFO; a regular file's writes ignore it, but keep the descriptor plain
                const int fl = ::fcntl(fd, F_GETFL);
                if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
            }
            return fd;
        }
        int next = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        const bool sites = first && part == "sites";
        if (next < 0 && errno == ENOENT && sites && (flags & O_CREAT)) {
            if (::mkdirat(cur, "sites", 0750) == 0 || errno == EEXIST) next = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        int e = errno;
        ::close(cur);
        if (next < 0) {
            if (probe && e == EACCES) return kProbeFine;
            const std::string missing_fix = "mkdir it as root, or name " + dir + "/sites/<name>.log";
            if (probe && e == ENOENT && sites) {
                // The start makes sites/; a log directly in it is then made too, anything deeper is not.
                const std::string rest = rel.substr(pos);
                const std::size_t s2 = rest.find('/');
                if (s2 == std::string::npos) return kProbeFine;
                errno = ENOENT;
                say(path + ": the directory " + walked + "/sites/" + rest.substr(0, s2) + " does not exist; " + no_dir, missing_fix);
                return -1;
            }
            errno = e;
            if (e == ELOOP || e == ENOTDIR)  // a link to a directory is ENOTDIR to an O_DIRECTORY open without following
                say(walked + "/" + part + ": a symbolic link or not a directory" + no_link, kDirFix);
            else if (e == ENOENT) say(path + ": the directory " + walked + "/" + part + " does not exist; " + no_dir, missing_fix);
            else say(walked + "/" + part + ": " + std::strerror(e));
            return -1;
        }
        if (!probe && sites && where.uid >= 0 && ::geteuid() == 0) {
            // sites/ is the server account's: it creates a site's log there on a reload, after the
            // privilege drop (the package makes it so; a start before 0.1.0-alpha.129 made it root's).
            struct stat st {};
            if (::fstat(next, &st) == 0 && S_ISDIR(st.st_mode) && (st.st_uid != static_cast<uid_t>(where.uid) || (where.gid >= 0 && st.st_gid != static_cast<gid_t>(where.gid)))) {
                if (::fchown(next, static_cast<uid_t>(where.uid), where.gid >= 0 ? static_cast<gid_t>(where.gid) : st.st_gid) == 0) (void)::fchmod(next, 0750);
            }
        }
        walked += "/" + part;
        cur = next;
        first = false;
    }
#endif
}

}  // namespace

int open_below_log_dir(const LogPlacement& where, const std::string& path, int flags, unsigned mode, std::string& why) noexcept {
    return walk_below(where, path, flags, mode, why, false, nullptr);
}

std::string probe_below_log_dir(const LogPlacement& where, const std::string& path, std::string* fix) noexcept {
    std::string why;
    const int fd = walk_below(where, path, O_RDONLY, 0, why, true, fix);
    if (fd >= 0) {
#ifndef _WIN32
        ::close(fd);
#endif
        return {};
    }
    return fd == kProbeFine ? std::string() : why;
}

namespace {

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

// nginx-style escaping for the combined format (ngx_http_log_escape): '"', '\\', control
// bytes and every byte from 0x7F up as \xHH, so a line is always ASCII whatever a client
// sent (2026-10-02 alpha.43 report: raw bytes 0x80-0xFF made logs_query's answer invalid text).
void append_escaped(std::string& out, std::string_view v) {
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (unsigned char c : v) {
        if (c == '"' || c == '\\' || c < 0x20 || c >= 0x7f) {
            out.append("\\x");
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        } else {
            out.push_back(static_cast<char>(c));
        }
    }
}

// JSON string escaping (RFC 8259); well-formed UTF-8 passes through, a byte that is not part
// of one is written as the text \xHH (the combined format's spelling), so a line is always
// valid text.
void append_json(std::string& out, std::string_view v) {
    static constexpr char kHex[] = "0123456789abcdef";
    out.push_back('"');
    for (std::size_t i = 0; i < v.size();) {
        const unsigned char c = static_cast<unsigned char>(v[i]);
        if (c >= 0x80) {
            const std::size_t n = utf8_sequence(v, i);
            if (n) {
                out.append(v.data() + i, n);
                i += n;
            } else {
                out.append("\\\\x");
                out.push_back(kHex[c >> 4]);
                out.push_back(kHex[c & 15]);
                ++i;
            }
            continue;
        }
        ++i;
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

bool LogFile::open(const LogPlacement& where) noexcept {
    int fd = -1;
    error_.clear();
    errno_ = 0;
    if (path_ == "stderr") fd = 2;
    else if (below_log_dir(where.directory, path_)) {
        fd = open_below_log_dir(where, path_, AGENSIO_OPEN_FLAGS, 0640, error_);
        if (fd < 0) {
            errno_ = errno;
            return false;
        }
    } else {
        fd = sys_open_append(path_.c_str());
        if (fd < 0 && errno == ENOENT) {  // a path root named elsewhere, its directory not there yet
            std::error_code ec;
            std::filesystem::create_directories(std::filesystem::path(path_).parent_path(), ec);
            if (!ec) fd = sys_open_append(path_.c_str());
        }
        if (fd < 0) {
            errno_ = errno;
            error_ = path_ + ": " + std::strerror(errno);
            return false;
        }
    }
    const int old = fd_.exchange(fd, std::memory_order_acq_rel);
    if (previous_ > 2) sys_close(previous_);
    previous_ = old;
    return true;
}

bool LogFile::own(unsigned uid, unsigned gid) noexcept {
#ifdef _WIN32
    (void)uid;
    (void)gid;
    return true;
#else
    const int fd = fd_.load(std::memory_order_acquire);
    if (fd <= 2) return true;  // stderr, or not open
    struct stat st {};
    if (::fstat(fd, &st) != 0) return false;
    if (st.st_uid == uid && st.st_gid == gid && (st.st_mode & 07777) == 0640) return true;
    if (::fchown(fd, uid, gid) != 0) return false;
    (void)::fchmod(fd, 0640);
    return true;
#endif
}

bool LogFile::owner(unsigned& uid, unsigned& gid) const noexcept {
#ifdef _WIN32
    (void)uid;
    (void)gid;
    return false;
#else
    const int fd = fd_.load(std::memory_order_acquire);
    struct stat st {};
    if (fd < 0 || ::fstat(fd, &st) != 0) return false;
    uid = st.st_uid;
    gid = st.st_gid;
    return true;
#endif
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
        if (sinks_[i]->path() == path) {
            sinks_[i]->set_wanted(true);
            return static_cast<int>(i);
        }
    sinks_.push_back(std::make_unique<LogFile>(path));
    return static_cast<int>(sinks_.size() - 1);
}

void LogRegistry::unmark_all() noexcept {
    for (auto& s : sinks_) s->set_wanted(false);
}

void LogRegistry::open_wanted(std::vector<Failure>& failed) noexcept {
    for (auto& s : sinks_) {
        if (!s->wanted() || s->is_open()) continue;
        if (!s->open(where_)) failed.push_back({s->path(), s->error(), s->errno_of()});
    }
}

bool LogRegistry::open_all(std::string& error) noexcept {
    std::vector<Failure> failed;
    open_wanted(failed);
    if (failed.empty()) return true;
    error = "cannot open log file " + failed.front().why;
    return false;
}

std::vector<LogRegistry::Failure> LogRegistry::reopen_all() noexcept {
    std::vector<Failure> failed;
    for (auto& s : sinks_)
        if (s->wanted() && !s->reopen(where_)) failed.push_back({s->path(), s->error(), s->errno_of()});  // the previous descriptor stays
    return failed;
}

bool LogRegistry::is_open(const std::string& path) const noexcept {
    // Wanted or not: a site added again finds its sink open and the reload keeps it (open_wanted).
    for (const auto& s : sinks_)
        if (s->path() == path) return s->is_open();
    return false;
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
    if (sink < 0 || !registry_) return;
    // A reload may add sinks after attach(): grow this worker's buffers to match (own
    // thread, no lock). Before 2026-09-19 lines for a new sink were silently dropped.
    if (static_cast<std::size_t>(sink) >= buffers_.size()) buffers_.resize(static_cast<std::size_t>(sink) + 1);
    refresh_time(now);
    std::string& buf = buffers_[static_cast<std::size_t>(sink)];
    if (format_ == AccessLogFormat::json) format_json(buf, time_iso_, r);
    else if (format_ == AccessLogFormat::vhost_combined) format_vhost_combined(buf, time_local_, r);
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

// remote - user [time] "METHOD target HTTP/1.x" status bytes "referer" "user-agent"; user is the
// name a password check verified ([[site.auth]]), "-" otherwise (never the name a client merely claimed).
void WorkerLogs::format_combined(std::string& out, std::string_view time_local, const AccessRecord& r) {
    out.append(r.remote.empty() ? std::string_view("-") : r.remote).append(" - ");
    if (r.user.empty()) out.push_back('-');
    else append_escaped(out, r.user);
    out.append(" [").append(time_local).append("] \"");
    if (r.method.empty()) {
        out.push_back('-');
    } else {
        append_escaped(out, r.method);
        out.push_back(' ');
        append_escaped(out, r.target);
        if (r.protocol.empty()) out.append(r.version_minor == 0 ? " HTTP/1.0" : " HTTP/1.1");
        else out.push_back(' '), out.append(r.protocol);
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

// Apache's vhost_combined (Debian's other_vhosts_access.log: `LogFormat "%v:%p %h %l %u %t ..."`):
// host:port and a space in front of the combined line. The host is the one the request asked for,
// lower case and without its port ("[2001:db8::1]" keeps its brackets), "-" when it sent none
// (HTTP/1.0); the port is the listener's, the one the client connected to. A parser of the combined
// line that reads the first field as the client (fail2ban's <HOST>, GoAccess's COMBINED) must be told
// of the prefix: the shipped filters take it as optional, GoAccess reads it as VCOMBINED.
void WorkerLogs::format_vhost_combined(std::string& out, std::string_view time_local, const AccessRecord& r) {
    std::string_view host = r.host;
    if (host.empty()) {
        out.push_back('-');
    } else {
        if (host.front() == '[') {  // an IPv6 literal: the port, if any, follows the bracket
            if (const std::size_t close = host.find(']'); close != std::string_view::npos) host = host.substr(0, close + 1);
        } else if (const std::size_t colon = host.rfind(':'); colon != std::string_view::npos) {
            host = host.substr(0, colon);
        }
        // Lower case, escaped by append_escaped's rule (a Host is a token the parser checked, so the
        // escape is rare): one scan, then the whole host appended at once when nothing needs changing.
        bool plain = true;
        for (unsigned char c : host)
            if ((c >= 'A' && c <= 'Z') || c == '"' || c == '\\' || c < 0x20 || c >= 0x7f) {
                plain = false;
                break;
            }
        if (plain) {
            out.append(host);
        } else {
            static constexpr char kHex[] = "0123456789ABCDEF";
            for (unsigned char c : host) {
                if (c == '"' || c == '\\' || c < 0x20 || c >= 0x7f) {
                    out.append("\\x");
                    out.push_back(kHex[c >> 4]);
                    out.push_back(kHex[c & 15]);
                } else {
                    out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c + 32 : c));
                }
            }
        }
    }
    out.push_back(':');
    append_uint(out, r.port);
    out.push_back(' ');
    format_combined(out, time_local, r);
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
    if (r.protocol.empty()) out.append(",\"proto\":\"HTTP/1.").push_back(r.version_minor == 0 ? '0' : '1');
    else out.append(",\"proto\":\"").append(r.protocol);
    out.append("\",\"status\":");
    append_uint(out, static_cast<std::uint64_t>(r.status));
    out.append(",\"bytes\":");
    append_uint(out, r.bytes);
    out.append(",\"referer\":");
    append_json(out, r.referer);
    out.append(",\"user_agent\":");
    append_json(out, r.user_agent);
    if (!r.user.empty()) {
        out.append(",\"user\":");
        append_json(out, r.user);
    }
    if (!r.upstream.empty()) {
        out.append(",\"upstream\":");
        append_json(out, r.upstream);
    }
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
    // One entry, one line (2026-10-21): a message's line breaks (a program's output, php-fpm's or the
    // helper's) become "; ", so a grep for the entry shows all of it, logs_query and fail2ban's
    // agensio-auth filter read entries as lines, and no text inside one can start a line of its own.
    while (!message.empty() && (message.back() == '\n' || message.back() == '\r')) message.remove_suffix(1);
    for (std::size_t i = 0; i < message.size(); ++i) {
        const char c = message[i];
        if (c != '\n' && c != '\r') {
            line.push_back(c);
            continue;
        }
        while (i + 1 < message.size() && (message[i + 1] == '\n' || message[i + 1] == '\r')) ++i;
        line.append("; ");
    }
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
