#include "services/history.hpp"

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <vector>

#include "control/sites.hpp"
#include "services/install.hpp"

namespace agensio::history {

std::string dir_of(const std::string& sites_root) { return sites_root + "/.history"; }

bool valid_version(std::string_view v) noexcept {
    // YYYYMMDD-HHMMSS-uuuuuu: the UTC second and the microsecond it was kept at.
    if (v.size() != 22 || v[8] != '-' || v[15] != '-') return false;
    for (std::size_t i = 0; i < v.size(); ++i)
        if (i != 8 && i != 15 && !(v[i] >= '0' && v[i] <= '9')) return false;
    return true;
}

#ifndef _WIN32

namespace {

json::Value fail(const std::string& why) { return json::Value::object().set("ok", false).set("error", why); }

// A directory of the history: created 0700 when asked, never through a symlink, the holder's alone.
int open_owned(int parent, const std::string& name, uid_t owner, bool create, std::string& why) {
    if (create && ::mkdirat(parent, name.c_str(), 0700) != 0 && errno != EEXIST) {
        why = name + ": " + std::strerror(errno);
        return -1;
    }
    const int fd = ::openat(parent, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        why = errno == ENOENT ? "missing" : name + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
        return -1;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_uid != owner) {
        ::close(fd);
        why = name + " belongs to uid " + std::to_string(st.st_uid) + ", not the history's holder; refused";
        return -1;
    }
    if ((st.st_mode & 077) != 0 && ::fchmod(fd, 0700) != 0) {
        ::close(fd);
        why = name + ": " + std::strerror(errno);
        return -1;
    }
    return fd;
}

// The history's own root, <sites_root>/.history, and below it the domain's directory.
int open_domain(const Place& p, bool create, std::string& why) {
    const std::size_t slash = p.hist_dir.rfind('/');
    if (slash == std::string::npos || slash == 0) {
        why = "no history directory";
        return -1;
    }
    const std::string parent = p.hist_dir.substr(0, slash), leaf = p.hist_dir.substr(slash + 1);
    const int pfd = ::open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd < 0) {
        why = parent + ": " + std::strerror(errno);
        return -1;
    }
    const int hfd = open_owned(pfd, leaf, p.hist_owner, create, why);
    ::close(pfd);
    if (hfd < 0) return -1;
    if (!control::valid_domain(p.domain)) {
        ::close(hfd);
        why = "not a site's name";
        return -1;
    }
    const int dfd = open_owned(hfd, p.domain, p.hist_owner, create, why);
    ::close(hfd);
    return dfd;
}

// Removes dir_fd/name whatever it is, never following a symlink.
bool remove_tree(int dir_fd, const std::string& name, std::string& why, int depth = 0) {
    struct stat st {};
    if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT || (why = name + ": " + std::strerror(errno), false);
    if (!S_ISDIR(st.st_mode)) {
        if (::unlinkat(dir_fd, name.c_str(), 0) != 0 && errno != ENOENT) return why = name + ": " + std::strerror(errno), false;
        return true;
    }
    if (depth > 256) return why = name + ": deeper than 256 levels", false;
    const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return why = name + ": " + std::strerror(errno), false;
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        return why = name + ": " + std::strerror(errno), false;
    }
    std::vector<std::string> children;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
    for (const auto& c : children)
        if (!remove_tree(::dirfd(d), c, why, depth + 1)) {
            ::closedir(d);
            return false;
        }
    ::closedir(d);
    if (::unlinkat(dir_fd, name.c_str(), AT_REMOVEDIR) != 0 && errno != ENOENT) return why = name + ": " + std::strerror(errno), false;
    return true;
}

// Bytes of the regular files below dir_fd/name, bounded.
std::uint64_t tree_bytes(int dir_fd, const std::string& name, int depth, std::size_t& seen) {
    struct stat st {};
    if (depth > 64 || seen > 100000 || ::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return 0;
    ++seen;
    if (S_ISREG(st.st_mode)) return static_cast<std::uint64_t>(st.st_size);
    if (!S_ISDIR(st.st_mode)) return 0;
    const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return 0;
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        return 0;
    }
    std::uint64_t total = 0;
    std::vector<std::string> children;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
    for (const auto& c : children) total += tree_bytes(::dirfd(d), c, depth + 1, seen);
    ::closedir(d);
    return total;
}

std::string iso(std::time_t t) {
    char buf[32];
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

bool read_meta(int dfd, const std::string& version, json::Value& meta) {
    const int vfd = ::openat(dfd, version.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (vfd < 0) return false;
    const int mfd = ::openat(vfd, "meta", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    ::close(vfd);
    if (mfd < 0) return false;
    char buf[4096];
    const ssize_t n = ::read(mfd, buf, sizeof buf);
    ::close(mfd);
    std::string err;
    return n > 0 && json::parse(std::string_view(buf, static_cast<std::size_t>(n)), meta, err) && meta.is_object();
}

std::vector<std::string> versions_in(int dfd) {
    std::vector<std::string> out;
    const int fd = ::dup(dfd);
    if (fd < 0) return out;
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        return out;
    }
    while (const struct dirent* e = ::readdir(d))
        if (valid_version(e->d_name)) out.emplace_back(e->d_name);
    ::closedir(d);
    std::sort(out.begin(), out.end());
    return out;
}

// Versions of `rel` beyond `keep_n`, oldest first, removed; `spare` never.
void prune_versions(int dfd, const std::string& rel, int keep_n, const std::string& spare = {}) {
    std::vector<std::string> mine;
    for (const auto& v : versions_in(dfd)) {
        json::Value meta;
        if (read_meta(dfd, v, meta) && meta.get("path") == rel) mine.push_back(v);
    }
    std::string why;
    for (std::size_t i = 0; mine.size() - i > static_cast<std::size_t>(std::max(keep_n, 0)); ++i)
        if (mine[i] != spare) remove_tree(dfd, mine[i], why);
}

// The site's directory and the open parent of `rel`, every component the site account's.
int open_parent(const Place& p, const std::string& rel, std::string& leaf, std::string& why) {
    const int root_fd = ::open(p.site_root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0) {
        why = "site directory " + p.site_root + ": " + std::strerror(errno);
        return -1;
    }
    struct stat rs {};
    if (::fstat(root_fd, &rs) != 0 || rs.st_uid != p.site_uid) {
        ::close(root_fd);
        why = "site directory " + p.site_root + " belongs to uid " + std::to_string(rs.st_uid) + ", not to the site's account; refused";
        return -1;
    }
    std::string dir;
    install::split_leaf(rel, dir, leaf);
    bool missing = false;
    const int dfd = install::walk_dirs_owned(root_fd, p.site_root, dir, p.site_uid, why, missing);
    ::close(root_fd);
    return dfd;
}

json::Value keep_impl(const Place& p, const std::string& rel, bool move, const std::string& reason, bool prune_after) {
    if (rel.empty()) return fail("the site's directory itself is never moved");
    std::string leaf, why;
    const int sdir = open_parent(p, rel, leaf, why);
    if (sdir < 0) return fail(why);
    struct stat st {};
    if (::fstatat(sdir, leaf.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) {
        const int e = errno;
        ::close(sdir);
        return e == ENOENT ? json::Value::object().set("ok", true).set("entry", "") : fail(p.site_root + "/" + rel + ": " + std::strerror(e));
    }
    const std::string kind = S_ISDIR(st.st_mode) ? "directory" : S_ISLNK(st.st_mode) ? "symlink" : S_ISREG(st.st_mode) ? "file" : "";
    if (kind.empty() || st.st_uid != p.site_uid || (!move && kind != "file")) {
        ::close(sdir);
        return fail(p.site_root + "/" + rel + (kind.empty() ? " is not a file, directory or symlink" : st.st_uid != p.site_uid ? " belongs to another account" : " is not a regular file") + "; refused");
    }
    const int dfd = open_domain(p, true, why);
    if (dfd < 0) {
        ::close(sdir);
        return fail("history: " + why);
    }
    std::string version;
    for (int attempt = 0; attempt < 100 && version.empty(); ++attempt) {
        struct timeval tv {};
        ::gettimeofday(&tv, nullptr);
        char stamp[32];
        std::tm tm{};
        const std::time_t sec = tv.tv_sec;
        ::gmtime_r(&sec, &tm);
        std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
        char us[8];
        std::snprintf(us, sizeof us, "%06ld", static_cast<long>((tv.tv_usec + attempt) % 1000000));
        const std::string v = std::string(stamp) + "-" + us;
        if (::mkdirat(dfd, v.c_str(), 0700) == 0) version = v;
        else if (errno != EEXIST) break;
    }
    const int vfd = version.empty() ? -1 : ::openat(dfd, version.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (vfd < 0) {
        ::close(sdir);
        ::close(dfd);
        return fail("history: cannot make a version: " + std::string(std::strerror(errno)));
    }
    const bool placed = move ? ::renameat(sdir, leaf.c_str(), vfd, "item") == 0 : ::linkat(sdir, leaf.c_str(), vfd, "item", 0) == 0;
    const int e = errno;
    ::close(sdir);
    if (!placed) {
        ::close(vfd);
        remove_tree(dfd, version, why);
        ::close(dfd);
        return fail("history: cannot keep " + p.site_root + "/" + rel + ": " + std::strerror(e) + (e == EXDEV ? " (the history is on another filesystem than the site)" : ""));
    }
    std::size_t seen = 0;
    const std::uint64_t bytes = kind == "directory" ? tree_bytes(vfd, "item", 0, seen) : static_cast<std::uint64_t>(st.st_size);
    const std::time_t now = std::time(nullptr);
    const std::string meta = json::Value::object()
                                 .set("path", rel)
                                 .set("kind", kind)
                                 .set("bytes", static_cast<double>(bytes))
                                 .set("reason", reason)
                                 .set("kept_at", iso(now))
                                 .set("kept_at_s", static_cast<double>(now))
                                 .set("moved", move)
                                 .dump();
    const int mfd = ::openat(vfd, "meta", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (mfd >= 0) {
        (void)!::write(mfd, meta.data(), meta.size());
        ::close(mfd);
    }
    ::close(vfd);
    if (prune_after) prune_versions(dfd, rel, p.settings.versions, version);
    ::close(dfd);
    return json::Value::object().set("ok", true).set("entry", version).set("kind", kind).set("bytes", static_cast<double>(bytes));
}

}  // namespace

json::Value keep(const Place& p, const std::string& rel, bool move, const std::string& reason) { return keep_impl(p, rel, move, reason, false); }

void prune(const Place& p, const std::string& rel) {
    std::string why;
    const int dfd = open_domain(p, false, why);
    if (dfd < 0) return;
    prune_versions(dfd, rel, p.settings.versions);
    ::close(dfd);
}

void undo(const Place& p, const std::string& rel, const std::string& entry, bool moved) {
    if (entry.empty() || !valid_version(entry)) return;
    std::string why, leaf;
    const int dfd = open_domain(p, false, why);
    if (dfd < 0) return;
    if (moved) {
        const int sdir = open_parent(p, rel, leaf, why);
        const int vfd = ::openat(dfd, entry.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (sdir >= 0 && vfd >= 0) (void)::renameat(vfd, "item", sdir, leaf.c_str());
        if (sdir >= 0) ::close(sdir);
        if (vfd >= 0) ::close(vfd);
    }
    remove_tree(dfd, entry, why);
    ::close(dfd);
}

json::Value list(const Place& p, const std::string& rel) {
    json::Value versions = json::Value::array();
    std::string why;
    const int dfd = open_domain(p, false, why);
    if (dfd >= 0) {
        std::vector<std::string> all = versions_in(dfd);
        for (auto it = all.rbegin(); it != all.rend(); ++it) {
            json::Value meta;
            if (!read_meta(dfd, *it, meta) || meta.get("path") != rel) continue;
            versions.push(json::Value::object().set("version", *it).set("kept_at", meta.get("kept_at")).set("kind", meta.get("kind"))
                              .set("bytes", meta["bytes"].num()).set("reason", meta.get("reason")));
        }
        ::close(dfd);
    } else if (why != "missing") {
        return fail("history: " + why);
    }
    return json::Value::object().set("ok", true).set("path", p.site_root + "/" + rel).set("versions", std::move(versions))
        .set("kept", json::Value::object().set("versions", p.settings.versions).set("days", p.settings.days));
}

json::Value restore(const Place& p, const std::string& rel, const std::string& version, bool overwrite, bool dry_run) {
    if (!valid_version(version)) return fail("version must be one site_file_history lists (YYYYMMDD-HHMMSS-uuuuuu)");
    std::string why, leaf;
    const int dfd = open_domain(p, false, why);
    if (dfd < 0) return fail(why == "missing" ? "nothing of this site is in the history" : "history: " + why);
    json::Value meta;
    if (!read_meta(dfd, version, meta)) {
        ::close(dfd);
        return fail("no version " + version + " in this site's history (site_file_history lists them; versions go after " + std::to_string(p.settings.days) + " days)");
    }
    if (meta.get("path") != rel) {
        ::close(dfd);
        return fail("version " + version + " keeps " + std::string(meta.get("path")) + ", not " + rel);
    }
    const int sdir = open_parent(p, rel, leaf, why);
    if (sdir < 0) {
        ::close(dfd);
        return fail(why);
    }
    struct stat cur {};
    const bool exists = ::fstatat(sdir, leaf.c_str(), &cur, AT_SYMLINK_NOFOLLOW) == 0;
    if (exists && !overwrite) {
        ::close(sdir);
        ::close(dfd);
        return fail(p.site_root + "/" + rel + " exists; overwrite: true keeps it in the history first and puts version " + version + " back");
    }
    json::Value answer = json::Value::object().set("ok", true).set("path", p.site_root + "/" + rel).set("version", version)
                             .set("kind", meta.get("kind")).set("bytes", meta["bytes"].num());
    if (dry_run) {
        ::close(sdir);
        ::close(dfd);
        return answer.set("dry_run", true).set("would_replace", exists);
    }
    ::close(sdir);
    std::string kept;
    if (exists) {
        const json::Value k = keep_impl(p, rel, true, "replaced by a restore of " + version, false);
        if (!k["ok"].boolean()) {
            ::close(dfd);
            return k;
        }
        kept = std::string(k.get("entry"));
    }
    const int sdir2 = open_parent(p, rel, leaf, why);
    const int vfd = ::openat(dfd, version.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    const bool placed = sdir2 >= 0 && vfd >= 0 && ::renameat(vfd, "item", sdir2, leaf.c_str()) == 0;
    const int e = errno;
    if (sdir2 >= 0) ::close(sdir2);
    if (vfd >= 0) ::close(vfd);
    if (!placed) {
        if (!kept.empty()) undo(p, rel, kept, true);
        ::close(dfd);
        return fail("cannot put " + version + " back: " + (sdir2 < 0 ? why : std::string(std::strerror(e))));
    }
    remove_tree(dfd, version, why);
    prune_versions(dfd, rel, p.settings.versions);
    ::close(dfd);
    if (!kept.empty()) answer.set("replaced", kept);
    return answer;
}

json::Value expire(const std::string& hist_dir, uid_t owner, const Settings& s, std::time_t now) {
    json::Value removed = json::Value::array();
    const std::size_t slash = hist_dir.rfind('/');
    if (slash == std::string::npos || slash == 0) return json::Value::object().set("ok", true).set("removed", std::move(removed));
    const int pfd = ::open(hist_dir.substr(0, slash).c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (pfd < 0) return json::Value::object().set("ok", true).set("removed", std::move(removed));
    std::string why;
    const int hfd = open_owned(pfd, hist_dir.substr(slash + 1), owner, false, why);
    ::close(pfd);
    if (hfd < 0) return json::Value::object().set("ok", why == "missing").set("removed", std::move(removed)).set("error", why == "missing" ? "" : why);
    std::vector<std::string> domains;
    if (const int fd = ::dup(hfd); fd >= 0) {
        if (DIR* d = ::fdopendir(fd)) {
            while (const struct dirent* e = ::readdir(d))
                if (control::valid_domain(e->d_name)) domains.emplace_back(e->d_name);
            ::closedir(d);
        } else {
            ::close(fd);
        }
    }
    for (const auto& domain : domains) {
        const int dfd = open_owned(hfd, domain, owner, false, why);
        if (dfd < 0) continue;
        for (const auto& v : versions_in(dfd)) {
            json::Value meta;
            const bool old = !read_meta(dfd, v, meta) || now - static_cast<std::time_t>(meta["kept_at_s"].num()) > static_cast<std::time_t>(s.days) * 86400;
            if (old && remove_tree(dfd, v, why)) removed.push(domain + "/" + v);
        }
        ::close(dfd);
    }
    ::close(hfd);
    return json::Value::object().set("ok", true).set("removed", std::move(removed));
}

#else

json::Value keep(const Place&, const std::string&, bool, const std::string&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
void prune(const Place&, const std::string&) {}
void undo(const Place&, const std::string&, const std::string&, bool) {}
json::Value list(const Place&, const std::string&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
json::Value restore(const Place&, const std::string&, const std::string&, bool, bool) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
json::Value expire(const std::string&, uid_t, const Settings&, std::time_t) { return json::Value::object().set("ok", true).set("removed", json::Value::array()); }

#endif

}  // namespace agensio::history
