#include "services/approvers.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>

#include "config.hpp"
#include "services/totp.hpp"

namespace agensio::approvers {

namespace fs = std::filesystem;

namespace {

constexpr std::size_t kFileMax = 4096;

// The file's text through a descriptor opened without following a symlink, checked as it is open:
// a regular file of `owner`'s, nothing for group or others. "" with `why` set when it fails.
std::string read_checked(const fs::path& path, uid_t owner, std::string& why) {
    why.clear();
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        why = errno == ELOOP ? "a symlink" : std::string("cannot be read: ") + std::strerror(errno);
        return "";
    }
    struct stat st{};
    std::string text;
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) why = "not a regular file";
    else if (st.st_uid != owner) why = "owned by uid " + std::to_string(st.st_uid) + ", not " + std::to_string(owner);
    else if ((st.st_mode & 077) != 0) why = "readable or writable by group or others (chmod 600)";
    else if (st.st_size > static_cast<off_t>(kFileMax)) why = "larger than an approver file can be";
    else {
        char buf[kFileMax];
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n < 0) why = std::string("cannot be read: ") + std::strerror(errno);
        else text.assign(buf, static_cast<std::size_t>(n));
    }
    ::close(fd);
    return why.empty() ? text : std::string();
}

std::string dir_check(const fs::path& dir, uid_t owner) {
    struct stat st{};
    if (::lstat(dir.c_str(), &st) != 0) return errno == ENOENT ? "missing" : std::string("cannot be read: ") + std::strerror(errno);
    if (S_ISLNK(st.st_mode)) return "a symlink";
    if (!S_ISDIR(st.st_mode)) return "not a directory";
    if (st.st_uid != owner) return "owned by uid " + std::to_string(st.st_uid) + ", not " + std::to_string(owner);
    if ((st.st_mode & 077) != 0) return "open to group or others (chmod 700)";
    return "";
}

// "key = value" lines; "" for a key that is absent.
std::string field(std::string_view text, std::string_view key) {
    std::size_t at = 0;
    while (at < text.size()) {
        const std::size_t end = std::min(text.find('\n', at), text.size());
        std::string_view line = text.substr(at, end - at);
        at = end + 1;
        if (line.starts_with(key)) {
            line.remove_prefix(key.size());
            while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
            if (!line.starts_with("=")) continue;
            line.remove_prefix(1);
            while (!line.empty() && (line.front() == ' ' || line.front() == '"')) line.remove_prefix(1);
            while (!line.empty() && (line.back() == ' ' || line.back() == '"' || line.back() == '\r')) line.remove_suffix(1);
            return std::string(line);
        }
    }
    return "";
}

// Writes `text` to `path` whole, 0600, through a temporary name and a rename.
bool write_private(const fs::path& path, std::string_view text, bool exclusive, std::string& why) {
    const fs::path tmp = path.string() + ".tmp";
    ::unlink(tmp.c_str());
    if (exclusive && ::access(path.c_str(), F_OK) == 0) {
        why = path.string() + " exists";
        return false;
    }
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        why = "cannot write " + tmp.string() + ": " + std::strerror(errno);
        return false;
    }
    bool ok = ::fchmod(fd, 0600) == 0 && ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (ok) ok = ::rename(tmp.c_str(), path.c_str()) == 0;
    if (!ok) {
        why = "cannot write " + path.string() + ": " + std::strerror(errno);
        ::unlink(tmp.c_str());
    }
    return ok;
}

std::string utc_now() {
    char buf[32];
    std::tm tm{};
    const std::time_t t = std::time(nullptr);
    ::gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

}  // namespace

fs::path dir_of(const Config& cfg) {
    return cfg.config_path.parent_path() / "approvers";
}

std::string check_name(std::string_view name) {
    if (name.empty() || name.size() > 32) return "an approver's name is 1 to 32 characters";
    for (std::size_t i = 0; i < name.size(); ++i) {
        const char c = name[i];
        const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (i > 0 && (c == '-' || c == '_'));
        if (!ok) return "an approver's name is lower-case letters, digits, '-' and '_', starting with a letter or digit";
    }
    return "";
}

std::vector<Approver> list(const fs::path& dir, uid_t owner, std::string& dir_problem) {
    std::vector<Approver> out;
    dir_problem = dir_check(dir, owner);
    if (!dir_problem.empty()) return out;
    std::error_code ec;
    for (const auto& entry : fs::directory_iterator(dir, ec)) {
        const std::string file = entry.path().filename().string();
        if (!file.ends_with(".totp")) continue;
        Approver a;
        a.name = file.substr(0, file.size() - 5);
        if (!check_name(a.name).empty()) continue;  // not one approver-add writes
        std::string why;
        const std::string text = read_checked(entry.path(), owner, why);
        if (!why.empty()) {
            a.problem = a.name + ".totp: " + why;
        } else {
            const auto secret = totp::base32_decode(field(text, "secret"));
            if (!secret || secret->size() < 16) a.problem = a.name + ".totp: no secret of at least 128 bits";
            a.created = field(text, "created");
        }
        std::string step_why;
        const std::string step = read_checked(dir / (a.name + ".step"), owner, step_why);
        if (step_why.empty() && !step.empty()) a.last_step = std::strtoll(step.c_str(), nullptr, 10);
        out.push_back(std::move(a));
    }
    std::sort(out.begin(), out.end(), [](const Approver& x, const Approver& y) { return x.name < y.name; });
    return out;
}

bool add(const fs::path& dir, std::string_view name, std::string_view secret, bool replace, std::string& why) {
    if (std::string bad = check_name(name); !bad.empty()) {
        why = bad;
        return false;
    }
    if (secret.size() < 16) {
        why = "no secret (this build has no random bytes)";
        return false;
    }
    struct stat st{};
    if (::lstat(dir.c_str(), &st) != 0) {
        if (::mkdir(dir.c_str(), 0700) != 0) {
            why = "cannot create " + dir.string() + ": " + std::strerror(errno);
            return false;
        }
    }
    if (const std::string bad = dir_check(dir, ::geteuid()); !bad.empty()) {
        why = dir.string() + ": " + bad;
        return false;
    }
    const std::string text = "# agensio approver " + std::string(name) +
                             ": the secret of an authenticator app's codes (docs/approvals.md); root's, 0600; never copy it elsewhere\n"
                             "secret = " + totp::base32_encode(secret) + "\ncreated = " + utc_now() + "\n";
    if (!write_private(dir / (std::string(name) + ".totp"), text, !replace, why)) return false;
    ::unlink((dir / (std::string(name) + ".step")).c_str());  // a new secret starts with no step used
    return true;
}

bool remove(const fs::path& dir, std::string_view name, std::string& why) {
    if (std::string bad = check_name(name); !bad.empty()) {
        why = bad;
        return false;
    }
    if (::unlink((dir / (std::string(name) + ".totp")).c_str()) != 0) {
        why = "no approver " + std::string(name) + " in " + dir.string();
        return false;
    }
    ::unlink((dir / (std::string(name) + ".step")).c_str());
    return true;
}

Checker::Result Checker::check(const fs::path& dir, uid_t owner, std::string_view code, std::int64_t now) {
    Result r;
    if (!totp::available()) {
        r.error = "this agensio was built without OpenSSL, which approval codes need";
        return r;
    }
    if (now < locked_until_) {
        r.locked_until = locked_until_;
        r.error = "approvals are stopped for " + std::to_string(locked_until_ - now) + " s after " + std::to_string(kMaxFailures) +
                  " wrong codes in ten minutes";
        return r;
    }
    std::string dir_problem;
    const std::vector<Approver> all = list(dir, owner, dir_problem);
    std::size_t usable = 0;
    for (const Approver& a : all) {
        if (!a.problem.empty()) continue;
        ++usable;
        std::string why;
        const std::string text = read_checked(dir / (a.name + ".totp"), owner, why);
        const auto secret = why.empty() ? totp::base32_decode(field(text, "secret")) : std::nullopt;
        if (!secret) continue;
        if (const auto step = totp::match(*secret, code, now, a.last_step)) {
            std::string werr;
            if (!write_private(dir / (a.name + ".step"), std::to_string(*step) + "\n", false, werr)) {
                r.error = "the code matched, but the step it used could not be kept (" + werr + "), so it was not accepted";
                return r;
            }
            failures_.clear();
            r.ok = true;
            r.approver = a.name;
            return r;
        }
    }
    if (usable == 0) {
        r.error = "no approver is set up" + (dir_problem.empty() || dir_problem == "missing" ? std::string() : " (" + dir.string() + ": " + dir_problem + ")") +
                  ": root runs agensio approver-add NAME on the server and adds the secret to an authenticator app (docs/approvals.md)";
        return r;
    }
    failures_.erase(std::remove_if(failures_.begin(), failures_.end(), [&](std::int64_t t) { return t <= now - kWindow; }), failures_.end());
    failures_.push_back(now);
    r.failures = static_cast<int>(failures_.size());
    if (r.failures >= kMaxFailures) {
        locked_until_ = now + kWindow;
        r.locked_until = locked_until_;
        failures_.clear();
    }
    r.error = "the code matches no approver: wrong, already used, or the phone's clock is more than 30 s off" +
              (r.locked_until ? std::string("; approvals are now stopped for ten minutes") : std::string());
    return r;
}

}  // namespace agensio::approvers
