#include "services/log_retention.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif
#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif

#include "config.hpp"
#include "control/loglines.hpp"

namespace agensio::log_retention {

namespace fs = std::filesystem;

namespace {
constexpr std::size_t kHead = 64 * 1024;  // a file's start read for its oldest line
constexpr std::time_t kDay = 24 * 60 * 60;
}  // namespace

std::vector<Keep> keeps_of(const Config& cfg) {
    std::vector<Keep> out;
    const std::string sites_dir = (fs::path(log_directory(cfg)) / "sites").string();
    for (const auto& s : cfg.sites) {
        if (s.access_log_keep_days < 1 || s.access_log_keep_days > 14 || s.server_names.empty()) continue;
        const std::string& f = s.access_log;
        if (!(f.size() > sites_dir.size() + 1 && f.compare(0, sites_dir.size(), sites_dir) == 0 && f[sites_dir.size()] == '/') || !f.ends_with(".log") ||
            fs::path(f).lexically_normal().string() != f)
            continue;
        if (std::any_of(out.begin(), out.end(), [&](const Keep& k) { return k.log == f; })) continue;
        out.push_back(Keep{s.server_names.front(), f, s.access_log_keep_days, log_directory(cfg)});
    }
    return out;
}

bool rotated_name(std::string_view base, std::string_view name) noexcept {
    if (base.empty() || name.size() < base.size() + 2 || name.compare(0, base.size(), base) != 0 || name[base.size()] != '.') return false;
    std::string_view rest = name.substr(base.size() + 1);
    if (rest.ends_with(".gz")) rest.remove_suffix(3);
    if (rest.empty() || rest.size() > 4) return false;
    return std::all_of(rest.begin(), rest.end(), [](char c) { return c >= '0' && c <= '9'; }) && rest.front() != '0';
}

std::time_t oldest_line(std::string_view text) {
    std::time_t oldest = 0;
    std::size_t at = 0;
    while (at < text.size()) {
        const std::size_t nl = text.find('\n', at);
        if (nl == std::string_view::npos) break;  // the last line read may be cut: never judged
        const std::string_view line = text.substr(at, nl - at);
        at = nl + 1;
        control::LogLine l;
        if (line.empty() || !control::parse_log_line(line, l) || l.source == "error" || l.time <= 0) continue;
        if (oldest == 0 || l.time < oldest) oldest = l.time;
    }
    return oldest;
}

#ifndef _WIN32
namespace {

// The start of an open rotated file, inflated for a .gz one; "" when it does not read.
std::string head_of(int fd, bool gz) {
    std::string out(kHead, '\0');
    if (gz) {
#ifdef AGENSIO_HAS_ZLIB
        const int copy = ::dup(fd);
        if (copy < 0) return {};
        gzFile g = ::gzdopen(copy, "rb");
        if (!g) {
            ::close(copy);
            return {};
        }
        const int n = ::gzread(g, out.data(), static_cast<unsigned>(out.size()));
        ::gzclose(g);
        out.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
        return out;
#else
        return {};
#endif
    }
    std::size_t got = 0;
    while (got < out.size()) {
        const ssize_t n = ::read(fd, out.data() + got, out.size() - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        got += static_cast<std::size_t>(n);
    }
    out.resize(got);
    return out;
}

}  // namespace
#endif

json::Value expire(const std::vector<Keep>& keeps, std::time_t now) {
    json::Value removed = json::Value::array(), failed = json::Value::array();
#ifndef _WIN32
    for (const Keep& k : keeps) {
        const fs::path log(k.log);
        const std::string dir = log.parent_path().string(), base = log.filename().string();
        auto fail = [&](const std::string& what) {
            failed.push(json::Value::object().set("site", k.site).set("log", k.log).set("days", k.days).set("error", what + ": " + std::strerror(errno)));
        };
        // The log's directory reached from the log directory as the server opens its logs (services/log.hpp
        // open_below_log_dir): one component at a time, no link followed, so a link the server's account
        // planted in sites/ never sends root's deletes elsewhere.
        std::string why;
        const int d = open_below_log_dir(LogPlacement{k.root, -1, -1}, dir, O_RDONLY | O_DIRECTORY, 0, why);
        if (d < 0) {
            if (errno != ENOENT) fail(why);
            continue;
        }
        std::vector<std::string> names;
        if (const int listing = ::dup(d); listing >= 0) {
            if (DIR* dp = ::fdopendir(listing)) {
                while (const dirent* e = ::readdir(dp))
                    if (rotated_name(base, e->d_name)) names.emplace_back(e->d_name);
                ::closedir(dp);
            } else {
                ::close(listing);
            }
        }
        const std::time_t before = now - static_cast<std::time_t>(k.days) * kDay;
        for (const std::string& name : names) {
            struct stat st {};
            if (::fstatat(d, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(st.st_mode)) continue;
            std::time_t oldest = 0;
            if (const int f = ::openat(d, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); f >= 0) {
                oldest = oldest_line(head_of(f, name.ends_with(".gz")));
                ::close(f);
            }
            if (oldest == 0) oldest = st.st_mtime - kDay;  // its last line less the day logrotate rotates by
            if (oldest >= before) continue;
            if (::unlinkat(d, name.c_str(), 0) == 0) removed.push(dir + "/" + name);
            else if (errno != ENOENT) fail(dir + "/" + name);
        }
        ::close(d);
    }
#else
    (void)keeps;
    (void)now;
#endif
    return json::Value::object().set("ok", true).set("removed", std::move(removed)).set("failed", std::move(failed));
}

}  // namespace agensio::log_retention
