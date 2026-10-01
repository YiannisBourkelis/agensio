#include "services/provision.hpp"

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include <chrono>
#include <functional>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <ctime>
#include <algorithm>
#include <sstream>

#include "control/commands.hpp"
#include "control/sites.hpp"
#include "services/appenv.hpp"
#include "services/archive.hpp"
#include "services/fetch.hpp"
#include "services/install.hpp"
#include "services/pools.hpp"
#include "services/tasks.hpp"

namespace agensio {

namespace fs = std::filesystem;

namespace provision {

std::string sites_root(const Config& cfg) { return cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root; }

std::string logs_root(const Config& cfg) {
    if (cfg.log.access.empty() || cfg.log.access == "off") return "/var/log/agensio";
    return fs::path(cfg.log.access).parent_path().string();
}

std::string uploads_dir(const Config& cfg) { return cfg.state_dir + "/uploads"; }
std::string trash_dir(const Config& cfg) { return sites_root(cfg) + "/.trash"; }

bool valid_trash_entry(std::string_view name) noexcept {
    // <domain>-YYYYMMDD-HHMMSS: the domain lower-case letters, digits, dots and hyphens.
    if (name.size() < 1 + 1 + 8 + 1 + 6 || name.size() > 253 + 16) return false;
    const std::size_t stamp = name.size() - 16;
    if (name[stamp] != '-' || name[stamp + 9] != '-') return false;
    for (std::size_t i = stamp + 1; i < name.size(); ++i)
        if (i != stamp + 9 && !(name[i] >= '0' && name[i] <= '9')) return false;
    return control::valid_domain(name.substr(0, stamp));
}

std::string site_tree(const Config& cfg, const SiteConfig& site, std::string& why) {
    const std::string root = site.project_root.empty() ? site.root : site.project_root;
    const std::string base = sites_root(cfg);
    if (root.empty() || !under_root(root, base) || root == base) {
        why = "the site's directory " + (root.empty() ? std::string("(none)") : root) + " is not below sites_root " + base + "; remove its files by hand";
        return "";
    }
    const std::size_t slash = root.find('/', base.size() + 1);
    const std::string top = slash == std::string::npos ? root : root.substr(0, slash);
    bool shared = false;
    for (const auto& s : cfg.sites) {
        if (&s == &site) continue;
        const std::string other = s.project_root.empty() ? s.root : s.project_root;
        if (!other.empty() && under_root(other, top) && !(s.server_names == site.server_names)) shared = true;
    }
    return shared ? root : top;
}

bool under_root(const std::string& path, const std::string& root) {
    return path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/');
}

namespace {
bool under(const std::string& path, const std::string& root) { return under_root(path, root); }
}  // namespace

std::string validate(const json::Value& req, const Config& cfg) {
    const std::string op(req.get("op"));
    std::string why;
    if (op == "account_add") {
        const std::string name(req.get("name"));
        if (!control::valid_account(name, why)) return "account_add: " + why;
        return "";
    }
    if (op == "site_layout") {
        const std::string dir(req.get("dir")), owner(req.get("owner"));
        if (!control::safe_path(dir, why)) return "site_layout: dir " + why;
        if (!under(dir, sites_root(cfg)) || dir == sites_root(cfg)) return "site_layout: " + dir + " is not below " + sites_root(cfg);
        if (!control::valid_account(owner, why)) return "site_layout: owner " + why;
        return "";
    }
    if (op == "log_own") {
        const std::string file(req.get("file")), group(req.get("group"));
        if (!control::safe_path(file, why)) return "log_own: file " + why;
        if (!under(file, logs_root(cfg)) || !file.ends_with(".log")) return "log_own: " + file + " is not a log under " + logs_root(cfg);
        if (!control::valid_account(group, why)) return "log_own: group " + why;
        return "";
    }
    if (op == "app_install") {
        const std::string target(req.get("target")), user(req.get("user")), url(req.get("url")), upload(req.get("upload"));
        const std::string site_root(req.get("site_root"));
        if (!control::safe_path(target, why)) return "app_install: target " + why;
        if (!control::safe_path(site_root, why)) return "app_install: site_root " + why;
        if (!under(site_root, sites_root(cfg)) || site_root == sites_root(cfg)) return "app_install: " + site_root + " is not below " + sites_root(cfg);
        if (!under(target, site_root)) return "app_install: " + target + " is not below the site's directory " + site_root;
        for (const char* flag : {"create_path", "dry_run", "ruby_check", "node_check"})
            if (!req[flag].is_null() && req[flag].type() != json::Value::Type::boolean) return std::string("app_install: ") + flag + " must be a boolean";
        if (!user.empty() && !control::valid_account(user, why)) return "app_install: user " + why;
        if (url.empty() == upload.empty()) return "app_install: exactly one of url and upload";
        std::string h, p, path;
        if (!url.empty() && !fetch::split_url(url, h, p, path)) return "app_install: url must be https://host/path without credentials";
        if (!url.empty() && !cfg.control.install) return "app_install: downloads are off ([control] install = false); upload the archive instead";
        if (!upload.empty() && !install::valid_upload_name(upload)) return "app_install: upload is not a plain file name";
        if (!req.get("sha256").empty() && !install::valid_sha256(req.get("sha256"))) return "app_install: sha256 must be 64 hex digits";
        const json::Value& strip = req["strip"];
        if (!strip.is_null() && (strip.type() != json::Value::Type::number || (strip.num() != -1 && strip.num() != 0 && strip.num() != 1)))
            return "app_install: strip must be -1, 0 or 1";
        std::string clean;
        for (const auto& sec : req["secrets"].items())
            if (!sec.is_string() || !archive::clean_path(sec.str(), clean, why) || clean != sec.str()) return "app_install: secrets must be clean relative paths";
        return "";
    }
    if (op == "file_copy") {
        const std::string site_root(req.get("site_root")), user(req.get("user")), from(req.get("from")), to(req.get("to"));
        if (!control::safe_path(site_root, why)) return "file_copy: site_root " + why;
        if (!under(site_root, sites_root(cfg)) || site_root == sites_root(cfg)) return "file_copy: " + site_root + " is not below " + sites_root(cfg);
        if (!user.empty() && !control::valid_account(user, why)) return "file_copy: user " + why;
        std::string clean;
        for (const auto* which : {"from", "to"}) {
            const std::string v(req.get(which));
            if (!archive::clean_path(v, clean, why) || clean != v) return std::string("file_copy: ") + which + " must be a clean relative path below the site: " + (why.empty() ? "not normalised" : why);
        }
        if (from == to) return "file_copy: from and to are the same path";
        for (const char* flag : {"overwrite", "dry_run"})
            if (!req[flag].is_null() && req[flag].type() != json::Value::Type::boolean) return std::string("file_copy: ") + flag + " must be a boolean";
        for (const auto& sec : req["secrets"].items())
            if (!sec.is_string() || !archive::clean_path(sec.str(), clean, why) || clean != sec.str()) return "file_copy: secrets must be clean relative paths";
        return "";
    }
    if (op == "task_run") {
        // Names and parameters only: the helper looks the site up in the configuration on
        // disk and takes the command from the task table (task_run below).
        const std::string site(req.get("site")), task(req.get("task"));
        if (!control::valid_domain(site)) return "task_run: site must be a site's host name";
        if (task.empty() || task.size() > 64 || task.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos)
            return "task_run: task must be a task's name (lower-case letters, digits, _)";
        const json::Value& params = req["params"];
        if (!params.is_null() && !params.is_object()) return "task_run: params must be an object";
        for (const auto& m : params.members())
            if (m.first.empty() || m.first.size() > 64 || !m.second.is_string() || m.second.str().size() > 256) return "task_run: parameters are short strings";
        if (!req["dry_run"].is_null() && req["dry_run"].type() != json::Value::Type::boolean) return "task_run: dry_run must be a boolean";
        return "";
    }
    if (op == "env_read" || op == "env_write") {
        // A site's name, and for a write the change; the helper finds the site on disk.
        if (!control::valid_domain(req.get("site"))) return op + ": site must be a site's host name";
        const json::Value& reveal = req["reveal"];
        if (!reveal.is_null() && (!reveal.is_array() || reveal.items().size() > 128)) return op + ": reveal must be a list of names";
        for (const auto& r : reveal.items())
            if (!r.is_string() || r.str().empty() || r.str().size() > 64 || r.str().find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_") != std::string::npos)
                return op + ": reveal names variables";
        if (op == "env_write") {
            appenv::Change change;
            if (std::string bad = appenv::parse_change(req, change); !bad.empty()) return "env_write: " + bad;
        }
        return "";
    }
    if (op == "app_status" || op == "app_logs") {
        // A site's name, and for the journal how much; the helper finds the site on disk and
        // derives the unit from its account, so no unit name comes from the server.
        if (!control::valid_domain(req.get("site"))) return op + ": site must be a site's host name";
        const json::Value& lines = req["lines"];
        if (!lines.is_null() && (lines.type() != json::Value::Type::number || lines.num() < 1 || lines.num() > 1000)) return op + ": lines is 1 to 1000";
        const std::string since(req.get("since"));
        if (!since.empty() && (since.size() < 2 || since.size() > 5 || since.find_first_not_of("0123456789") != since.size() - 1 ||
                               std::string("smhd").find(since.back()) == std::string::npos))
            return op + ": since is a number and s, m, h or d (e.g. 3h)";
        return "";
    }
    if (op == "site_trash") {
        if (!control::valid_domain(req.get("site"))) return "site_trash: site must be a site's host name";
        return "";
    }
    if (op == "site_restore" || op == "trash_delete") {
        if (!valid_trash_entry(req.get("entry"))) return op + ": entry must be a trash entry's name (<domain>-<date>-<time>)";
        return "";
    }
    if (op == "pools_apply" || op == "service_restart" || op == "ping" || op == "env_check" || op == "app_check" || op == "trash_list" ||
        op == "trash_expire")
        return "";
    return "unknown operation '" + op + "'";
}

}  // namespace provision

#ifndef _WIN32

namespace {

// Runs a program by absolute path with a fixed argv and an empty environment; the
// combined output and the exit status come back. Never a shell. At most `cap` bytes of
// output are kept: the first ones, or with `keep_tail` the last (a journal's newest lines).
int run(const char* path, const std::vector<std::string>& args, std::string& output, std::size_t cap = 8192, bool keep_tail = false) {
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        output = std::strerror(errno);
        return -1;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        output = std::strerror(errno);
        return -1;
    }
    if (pid == 0) {
        ::dup2(pipefd[1], 1);
        ::dup2(pipefd[1], 2);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(path));
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        const char* env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", nullptr};
        ::execve(path, argv.data(), const_cast<char**>(env));
        ::_exit(127);
    }
    ::close(pipefd[1]);
    char buf[512];
    for (;;) {
        const ssize_t n = ::read(pipefd[0], buf, sizeof buf);
        if (n <= 0) break;
        output.append(buf, static_cast<std::size_t>(n));
        if (!keep_tail && output.size() > cap) break;
        if (keep_tail && output.size() > 2 * cap) output.erase(0, output.size() - cap);
    }
    if (keep_tail && output.size() > cap) output.erase(0, output.size() - cap);
    ::close(pipefd[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

const char* find_binary(std::initializer_list<const char*> candidates) {
    for (const char* c : candidates)
        if (::access(c, X_OK) == 0) return c;
    return nullptr;
}

// An account the helper may hand directories to: a system account with a nologin shell
// whose home is its state directory, i.e. one created for a site (by us or by hand).
bool site_account(const Config& cfg, const std::string& name, uid_t& uid, gid_t& gid, std::string& why) {
    const struct passwd* pw = ::getpwnam(name.c_str());
    if (!pw) {
        why = "account " + name + " does not exist";
        return false;
    }
    const std::string shell = pw->pw_shell ? pw->pw_shell : "";
    const std::string home = pw->pw_dir ? pw->pw_dir : "";
    if (!(shell.ends_with("/nologin") || shell.ends_with("/false"))) {
        why = "account " + name + " has a login shell; only site accounts (nologin) can own a site";
        return false;
    }
    if (!(home == cfg.state_dir + "/" + name)) {
        why = "account " + name + "'s home is not " + cfg.state_dir + "/" + name + "; only site accounts can own a site";
        return false;
    }
    uid = pw->pw_uid;
    gid = pw->pw_gid;
    return true;
}

// Walks `dir` component by component without following symlinks, creating what is
// missing, and gives every directory from the first one below sites_root down to `dir`
// the layout owner:group 2750. A directory owned by anyone but root, the server or the
// owner is refused: that would hand another site's directory over.
bool lay_out(const Config& cfg, const std::string& dir, uid_t owner, gid_t group, uid_t server_uid, std::string& why) {
    const std::string root = provision::sites_root(cfg);
    int fd = ::open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        why = std::strerror(errno);
        return false;
    }
    std::string so_far;
    std::size_t pos = 1;
    while (pos <= dir.size()) {
        const std::size_t next = dir.find('/', pos);
        const std::string part = dir.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
        pos = next == std::string::npos ? dir.size() + 1 : next + 1;
        if (part.empty()) continue;
        so_far += "/" + part;
        const bool in_layout = so_far.size() > root.size() && so_far.compare(0, root.size(), root) == 0;
        int child = ::openat(fd, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 && errno == ENOENT && in_layout) {
            if (::mkdirat(fd, part.c_str(), 0750) != 0 && errno != EEXIST) {
                why = "mkdir " + so_far + ": " + std::strerror(errno);
                ::close(fd);
                return false;
            }
            child = ::openat(fd, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (child < 0) {
            why = so_far + ": " + (errno == ELOOP || errno == ENOTDIR ? "is a symlink or not a directory; refused" : std::strerror(errno));
            ::close(fd);
            return false;
        }
        ::close(fd);
        fd = child;
        if (!in_layout) continue;
        struct stat st {};
        if (::fstat(fd, &st) != 0) {
            why = so_far + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
        if (st.st_uid != 0 && st.st_uid != server_uid && st.st_uid != owner) {
            why = so_far + " belongs to uid " + std::to_string(st.st_uid) + ", another site; refused";
            ::close(fd);
            return false;
        }
        if (::fchown(fd, owner, group) != 0 || ::fchmod(fd, 02750) != 0) {
            why = so_far + ": " + std::strerror(errno);
            ::close(fd);
            return false;
        }
    }
    ::close(fd);
    return true;
}

// Which account installs: the site's user when the site has one, else the owner of the
// site's directory, and in both cases only a site account or the server's own account.
// Root, a login account or another site's account is refused before anything runs. The
// site's directory is what is looked at, not the target: a plugin's directory may not
// exist yet (create_path), and the child checks every component on its own walk.
bool install_account(const Config& cfg, const std::string& site_root, const std::string& user, uid_t& uid, gid_t& gid, std::string& why) {
    struct stat st {};
    if (::lstat(site_root.c_str(), &st) != 0) {
        why = "site directory " + site_root + ": " + std::strerror(errno);
        return false;
    }
    if (!S_ISDIR(st.st_mode)) {
        why = "site directory " + site_root + " is not a directory (or is a symlink); refused";
        return false;
    }
    if (!user.empty()) {
        if (!site_account(cfg, user, uid, gid, why)) return false;
        if (st.st_uid != uid) {
            why = "site directory " + site_root + " belongs to uid " + std::to_string(st.st_uid) + ", not to " + user + "; refused";
            return false;
        }
        return true;
    }
    if (st.st_uid == 0) {
        why = "site directory " + site_root + " belongs to root; give it to a site account (or the server's account) first";
        return false;
    }
    const struct passwd* pw = ::getpwuid(st.st_uid);
    if (!pw) {
        why = "site directory " + site_root + " belongs to unknown uid " + std::to_string(st.st_uid);
        return false;
    }
    const std::string owner = pw->pw_name;
    if (owner == cfg.user) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
        return true;
    }
    return site_account(cfg, owner, uid, gid, why);
}

// Runs `work` in a child that has become the given account (setgroups, setgid, setuid,
// root not regainable); the reply comes back through a pipe as one JSON line. Bounded
// by a deadline. `extra_fd` (an upload) is closed in the parent afterwards.
json::Value run_as_account(uid_t uid, gid_t gid, int helper_fd, int extra_fd, const std::function<json::Value()>& work,
                           std::chrono::seconds limit = std::chrono::minutes(20)) {
    json::Value reply = json::Value::object();
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        if (extra_fd >= 0) ::close(extra_fd);
        return reply.set("ok", false).set("error", std::string("pipe: ") + std::strerror(errno));
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        if (extra_fd >= 0) ::close(extra_fd);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return reply.set("ok", false).set("error", std::string("fork: ") + std::strerror(errno));
    }
    if (pid == 0) {
        ::close(helper_fd);
        ::close(pipefd[0]);
        ::umask(0);  // the extractor and the copy set exact modes; nothing else is created here
        json::Value out = json::Value::object();
        if (::setgroups(0, nullptr) != 0 || ::setgid(gid) != 0 || ::setuid(uid) != 0 || ::setuid(0) == 0 || ::geteuid() != uid)
            out.set("ok", false).set("error", std::string("cannot become uid ") + std::to_string(uid) + ": " + std::strerror(errno));
        else
            out = work();
        const std::string text = out.dump() + "\n";
        (void)!::write(pipefd[1], text.data(), text.size());
        ::_exit(0);
    }
    ::close(pipefd[1]);
    if (extra_fd >= 0) ::close(extra_fd);
    std::string in;
    char buf[4096];
    const auto deadline = std::chrono::steady_clock::now() + limit;
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            ::kill(pid, SIGKILL);
            reply.set("ok", false).set("error", "the operation did not finish within " + std::to_string(limit.count() / 60) + " minutes; stopped");
            break;
        }
        struct pollfd pfd {pipefd[0], POLLIN, 0};
        const int pr = ::poll(&pfd, 1, static_cast<int>(std::min<long long>(left, 60000)));
        if (pr == 0) continue;
        if (pr < 0 && errno == EINTR) continue;
        const ssize_t n = ::read(pipefd[0], buf, sizeof buf);
        if (n <= 0) break;
        in.append(buf, static_cast<std::size_t>(n));
        if (in.size() > (4u << 20)) break;  // a task's answer carries up to 64 KB of output, escaped
    }
    ::close(pipefd[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    if (reply["ok"].is_null()) {
        std::string err;
        const std::size_t nl = in.find('\n');
        if (nl == std::string::npos || !json::parse(in.substr(0, nl), reply, err))
            reply = json::Value::object().set("ok", false).set("error", "the process ended without a result" + (WIFSIGNALED(status) ? std::string(" (signal ") + std::to_string(WTERMSIG(status)) + ")" : ""));
    }
    return reply;
}

// app_install: the site's account installs an archive (install::execute) in a child.
json::Value app_install(const json::Value& req, const Config& cfg, int helper_fd) {
    json::Value reply = json::Value::object();
    const std::string target(req.get("target")), user(req.get("user")), upload(req.get("upload")), site_root(req.get("site_root"));
    uid_t uid = 0;
    gid_t gid = 0;
    std::string why;
    if (!install_account(cfg, site_root, user, uid, gid, why)) return reply.set("ok", false).set("error", why);
    if (uid == 0) return reply.set("ok", false).set("error", "refusing to install as root");
    // ruby_check: the Ruby of [control] runtimes in root's file on disk, held to the
    // interpreter rule here, so the install child asks a trusted program for its version.
    std::string ruby, node;
    for (const char* runtime : {"ruby", "node"})
        if (req[std::string(runtime) + "_check"].boolean()) {
            try {
                const Config fresh = load_config(cfg.config_path);
                std::string canonical;
                bool missing = false;
                if (tasks::trusted_program(runtime_dir(fresh.control, runtime) + "/" + runtime, provision::sites_root(cfg), canonical, missing).empty())
                    (std::string_view(runtime) == "ruby" ? ruby : node) = canonical;
            } catch (const std::exception&) {
            }
        }
    int upload_fd = -1;
    if (!upload.empty()) {
        const std::string path = provision::uploads_dir(cfg) + "/" + upload;
        upload_fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (upload_fd < 0) return reply.set("ok", false).set("error", "upload " + upload + ": " + std::strerror(errno));
    }
    return run_as_account(uid, gid, helper_fd, upload_fd, [&] {
        install::Request r;
        r.site_root = site_root;
        r.target = target;
        r.create_path = req["create_path"].boolean();
        r.dry_run = req["dry_run"].boolean();
        r.url = std::string(req.get("url"));
        r.upload_fd = upload_fd;
        r.upload_name = upload;
        r.sha256 = std::string(req.get("sha256"));
        r.strip = req["strip"].is_null() ? -1 : static_cast<int>(req["strip"].num());
        r.allow_private = cfg.control.install_private;
        r.ca_file = cfg.control.install_ca;
        r.ruby = ruby;
        r.node = node;
        for (const auto& sec : req["secrets"].items()) r.secrets.push_back(sec.str());
        return install::execute(r);
    });
}

// file_copy (F9b): the site's account copies one of the site's files to another path of
// the same site (install::copy_file) in a child; narrower than app_install in every way.
json::Value file_copy(const json::Value& req, const Config& cfg, int helper_fd) {
    json::Value reply = json::Value::object();
    const std::string site_root(req.get("site_root")), user(req.get("user"));
    uid_t uid = 0;
    gid_t gid = 0;
    std::string why;
    if (!install_account(cfg, site_root, user, uid, gid, why)) return reply.set("ok", false).set("error", why);
    if (uid == 0) return reply.set("ok", false).set("error", "refusing to copy as root");
    return run_as_account(uid, gid, helper_fd, -1, [&] {
        install::CopyRequest r;
        r.site_root = site_root;
        r.from = std::string(req.get("from"));
        r.to = std::string(req.get("to"));
        r.overwrite = req["overwrite"].boolean();
        r.dry_run = req["dry_run"].boolean();
        r.max_bytes = cfg.control.upload_max;
        for (const auto& sec : req["secrets"].items()) r.secrets.push_back(sec.str());
        return install::copy_file(r);
    });
}

// The account's home, <state_dir>/<account> (useradd gave it; for an account without a PHP
// pool nothing created it), and its tmp/, for the programs a task runs (gem and bundler
// write below HOME): created 0700 as the account when missing. An existing one must be a
// directory the account owns; one this call did not create is never handed over.
bool ensure_home(const Config& cfg, const std::string& name, uid_t uid, gid_t gid, std::string& why) {
    const int sfd = ::open(cfg.state_dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (sfd < 0) {
        why = "state directory " + cfg.state_dir + ": " + std::strerror(errno);
        return false;
    }
    auto own = [&](int parent, const std::string& leaf, const std::string& path) {
        bool created = false;
        if (::mkdirat(parent, leaf.c_str(), 0700) == 0) created = true;
        else if (errno != EEXIST) {
            why = "mkdir " + path + ": " + std::strerror(errno);
            return -1;
        }
        const int fd = ::openat(parent, leaf.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            why = path + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
            return -1;
        }
        struct stat st {};
        if (created && ::fchown(fd, uid, gid) != 0) {
            why = path + ": " + std::strerror(errno);
            ::close(fd);
            return -1;
        }
        if (::fstat(fd, &st) != 0 || st.st_uid != uid) {
            why = path + " belongs to uid " + std::to_string(st.st_uid) + ", not to " + name + "; refused";
            ::close(fd);
            return -1;
        }
        return fd;
    };
    const int hfd = own(sfd, name, cfg.state_dir + "/" + name);
    ::close(sfd);
    if (hfd < 0) return false;
    const int tfd = own(hfd, "tmp", cfg.state_dir + "/" + name + "/tmp");
    ::close(hfd);
    if (tfd < 0) return false;
    ::close(tfd);
    return true;
}

// env_read and env_write: a site's application environment (services/appenv.*), the file
// root's under <config dir>/env/. The site comes from the configuration on disk and must be
// one agensio runs an application for (app = "rails" or "proxy"); its first host name
// names the file, so an alias reaches the same one.
json::Value env_op(const json::Value& req, const Config& cfg) {
    json::Value reply = json::Value::object();
    auto fail = [&](std::string why) { return reply.set("ok", false).set("error", std::move(why)); };
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return fail(std::string("the configuration on disk does not load: ") + e.what());
    }
    const std::string name(req.get("site"));
    const SiteConfig* site = control::find_site(fresh, name);
    if (!site) return fail("no site " + name + " in the configuration on disk");
    if (!proxy_app(site->app)) return fail("site " + name + " has app = \"" + site->app + "\"; a site's environment is for applications agensio runs (rails, redmine, django, wagtail, node, proxy)");
    const std::string key = site->server_names.front();
    const std::string dir = appenv::dir_of(cfg.config_path);
    if (req.get("op") == "env_read") {
        // Names, lengths and fingerprints; a value only when named in reveal (the owner's
        // decision of 2026-09-27: a secret leaves the helper only when asked for).
        std::vector<std::string> reveal;
        for (const auto& r : req["reveal"].items()) reveal.emplace_back(r.str());
        return appenv::describe(dir, key, 0, reveal);
    }
    appenv::Change change;
    if (std::string bad = appenv::parse_change(req, change); !bad.empty()) return fail(bad);
    if (std::string bad = appenv::check_change_for_app(site->app, change); !bad.empty()) return fail(bad);
    return appenv::apply(dir, key, 0, change).set("site", key);
}

// app_status and app_logs: a Rails site's application service (the unit site_service_unit
// renders, agensio-app-<user>.service), read-only, root running systemctl and journalctl
// by absolute path with fixed arguments (2026-09-27 report: when Puma did not come up, its
// cause was in a journal no tool could read). The unit comes from the site's account in the
// configuration on disk, never from the request.
// The state of every unit in `units` from one `systemctl show` (health asks for all of a
// server's Rails sites at once and must not fork per site): {unit: {property: value}}, or
// null with `why` when systemctl is missing.
json::Value unit_states(const std::vector<std::string>& units, std::string& why) {
    const char* systemctl = find_binary({"/usr/bin/systemctl", "/bin/systemctl"});
    if (!systemctl) {
        why = "systemctl not available on this host";
        return json::Value(nullptr);
    }
    std::vector<std::string> args{"show"};
    args.insert(args.end(), units.begin(), units.end());
    for (const char* a : {"--no-pager", "-p",
                          "Id,LoadState,ActiveState,SubState,Result,MainPID,ExecMainStatus,ExecMainCode,ActiveEnterTimestamp,InactiveEnterTimestamp,MemoryCurrent,NRestarts,UnitFileState"})
        args.emplace_back(a);
    std::string out;
    run(systemctl, args, out, 16384 * (units.size() + 1));
    // Blocks of NAME=value lines separated by a blank line, one per unit, each with its Id.
    json::Value states = json::Value::object();
    json::Value block = json::Value::object();
    auto close_block = [&] {
        const std::string id(block.get("Id"));
        if (std::find(units.begin(), units.end(), id) != units.end()) states.set(id, std::move(block));
        block = json::Value::object();
    };
    std::size_t p = 0;
    while (p < out.size()) {
        std::size_t nl = out.find('\n', p);
        if (nl == std::string::npos) nl = out.size();
        const std::string line = out.substr(p, nl - p);
        p = nl + 1;
        if (line.empty()) {
            close_block();
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq != std::string::npos && eq > 0) block.set(line.substr(0, eq), tasks::clean_text(line.substr(eq + 1)));
    }
    close_block();
    if (states.members().empty()) {  // no block at all: systemctl's own words (no systemd as init, no bus)
        const std::string first = tasks::clean_text(out.substr(0, out.find('\n')));
        why = "systemctl show answered nothing usable" + (first.empty() ? std::string() : ": " + first);
        return json::Value(nullptr);
    }
    return states;
}

// app_check: health's pass, every Rails site with its own account in the configuration on
// disk and its unit's state. {"ok", "services": [{"site", "unit", "state"}]}.
json::Value app_check(const Config& cfg) {
    json::Value reply = json::Value::object();
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return reply.set("ok", false).set("error", std::string("the configuration on disk does not load: ") + e.what());
    }
    std::vector<std::pair<std::string, std::string>> sites;  // site, unit
    std::vector<std::string> units;
    for (const auto& s : fresh.sites) {
        std::string why;
        if (!service_app(s.app) || s.user.empty() || s.server_names.empty() || !control::valid_account(s.user, why)) continue;
        const std::string unit = "agensio-app-" + s.user + ".service";
        sites.emplace_back(s.server_names.front(), unit);
        if (std::find(units.begin(), units.end(), unit) == units.end()) units.push_back(unit);
    }
    json::Value services = json::Value::array();
    if (!units.empty()) {
        std::string why;
        const json::Value states = unit_states(units, why);
        if (states.is_null()) return reply.set("ok", false).set("error", why);
        for (const auto& [site, unit] : sites)
            if (!states[unit].is_null()) services.push(json::Value::object().set("site", site).set("unit", unit).set("state", states[unit]));
    }
    return reply.set("ok", true).set("services", std::move(services));
}

json::Value app_op(const json::Value& req, const Config& cfg) {
    json::Value reply = json::Value::object();
    auto fail = [&](std::string why) { return reply.set("ok", false).set("error", std::move(why)); };
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return fail(std::string("the configuration on disk does not load: ") + e.what());
    }
    const std::string name(req.get("site"));
    const SiteConfig* site = control::find_site(fresh, name);
    if (!site) return fail("no site " + name + " in the configuration on disk");
    std::string why;
    if (!service_app(site->app) || site->user.empty() || !control::valid_account(site->user, why))
        return fail("site " + name + " has no application service: a Rails or Django site with its own account has one (agensio-app-<user>.service)");
    const std::string unit = "agensio-app-" + site->user + ".service";
    reply.set("site", site->server_names.front()).set("unit", unit);
    if (req.get("op") == "app_status") {
        json::Value states = unit_states({unit}, why);
        if (states.is_null()) return fail(why);
        if (states[unit].is_null()) return fail("systemctl show " + unit + " gave no answer");
        return reply.set("ok", true).set("state", states[unit]);
    }
    const char* journalctl = find_binary({"/usr/bin/journalctl", "/bin/journalctl"});
    if (!journalctl) return fail("journalctl not available on this host");
    const int lines = req["lines"].is_null() ? 200 : static_cast<int>(req["lines"].num());
    std::vector<std::string> args{"-u", unit, "-n", std::to_string(lines), "--no-pager", "-q", "-o", "short-iso"};
    if (const std::string since(req.get("since")); !since.empty()) args.push_back("--since=-" + since);
    std::string out;
    const int rc = run(journalctl, args, out, 256 * 1024, true);
    if (rc != 0 && out.empty()) return fail("journalctl exited " + std::to_string(rc));
    return reply.set("ok", true).set("lines", static_cast<double>(lines)).set("output", tasks::clean_text(out));
}

// task_run (F13): a named task of the site's preset (services/tasks.*) run by the site's
// account in a child. What runs is decided here, not by the server: the site (its app,
// its directory, its user) comes from the configuration file on disk, the command from the
// task table, the interpreter from root's [control] runtimes and the bounds from its
// task_limits, both read from that same file for every task (a reload changes them; only
// root's main file can hold [control], included files carry sites alone), and the site's
// environment from its root-owned file; the server sends names and parameters only.
json::Value task_run(const json::Value& req, const Config& cfg, int helper_fd) {
    json::Value reply = json::Value::object();
    auto fail = [&](std::string why) { return reply.set("ok", false).set("error", std::move(why)); };
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return fail(std::string("the configuration on disk does not load, so no task runs: ") + e.what());
    }
    const std::string name(req.get("site"));
    const SiteConfig* site = control::find_site(fresh, name);
    if (!site) return fail("no site " + name + " in the configuration on disk");
    const std::string app = site->app.empty() ? "static" : site->app;
    const tasks::Row* row = tasks::find(app, req.get("task"));
    if (!row) return fail("no task '" + std::string(req.get("task")) + "' for app = \"" + app + "\"");
    if (std::string bad = tasks::check_params(*row, req["params"]); !bad.empty()) return fail(bad);
    const std::string site_root = site->project_root.empty() ? site->root : site->project_root;
    std::string why;
    if (!control::safe_path(site_root, why)) return fail("the site's directory: " + why);
    if (!provision::under_root(site_root, provision::sites_root(cfg)) || site_root == provision::sites_root(cfg))
        return fail(site_root + " is not below " + provision::sites_root(cfg));
    uid_t uid = 0;
    gid_t gid = 0;
    if (!install_account(cfg, site_root, site->user, uid, gid, why)) return fail(why);
    if (uid == 0) return fail("refusing to run a task as root");
    const struct passwd* pw = ::getpwuid(uid);
    if (!pw) return fail("uid " + std::to_string(uid) + " has no name");
    const std::string account = pw->pw_name;
    const bool dry_run = req["dry_run"].boolean();
    if (!dry_run && !ensure_home(cfg, account, uid, pw->pw_gid, why)) return fail("the account's home: " + why);
    std::vector<appenv::Var> vars;
    // A site named "*" has no environment file (appenv names files by host name).
    appenv::Status est;
    if (appenv::valid_site(site->server_names.front()) && !appenv::read(appenv::dir_of(cfg.config_path), site->server_names.front(), 0, vars, est)) {
        reply = fail("the site's environment: " + est.error);
        if (!est.fix.empty()) reply.set("run_as_root", json::Value::array().push(est.fix));
        return reply;
    }
    tasks::Request tr;
    tr.row = row;
    tr.params = req["params"];
    tr.ctx.runtime_dir = runtime_dir(fresh.control, row->runtime);
    tr.ctx.root = site_root;
    tr.ctx.home = cfg.state_dir + "/" + account;
    // What the preset's family and a Django site's settings are told, from the site on disk.
    tr.ctx.app = app;
    tr.ctx.site = site->server_names.front();
    tr.ctx.project = site->project;
    const AppContext ac = app_context(fresh, *site);
    tr.ctx.hosts = ac.hosts;
    tr.ctx.origins = ac.origins;
    tr.ctx.base_url = ac.base_url;
    tr.ctx.https_redirect = ac.https_redirect;
    tr.ctx.hsts = ac.hsts;
    tr.ctx.timeout = std::min(row->timeout, fresh.control.task_timeout);
    tr.ctx.processes = fresh.control.task_processes;
    for (auto& v : vars) tr.ctx.app_env.emplace_back(std::move(v.name), std::move(v.value));
    tr.sites_root = provision::sites_root(cfg);
    for (const auto& abs : secret_paths(*site))
        if (provision::under_root(abs, site_root) && abs != site_root) tr.secrets.push_back(abs.substr(site_root.size() + 1));
    tr.network_allowed = fresh.control.task_network;
    tr.dry_run = dry_run;
    json::Value out = run_as_account(uid, gid, helper_fd, -1, [&] { return tasks::execute(tr); }, std::chrono::seconds(tr.ctx.timeout + 120));
    if (!est.notes.empty()) {  // the environment's directory or file, tightened on the way: said, not hidden
        json::Value notes = json::Value::array();
        for (const auto& n : est.notes) notes.push(n);
        out.set("tightened", notes);
    }
    return out;
}

// ---- the trash (F12b, 2026-09-30): a site deleted with its files ----
//
// Everything of a site goes into <sites_root>/.trash/<domain>-<stamp>/, root's alone (0700), by
// rename, so nothing is copied and a tenant cannot read another tenant's deleted files: the
// site's directory (its tree below sites_root), the account's state directory when no other
// site uses the account (else the site's virtualenv alone), its access log with its rotations,
// its environment file, and the text of its site file in the manifest. A piece on another
// filesystem (the state directory, a log) goes to a trash beside it (<state_dir>/.trash,
// <logs_root>/.trash) or, a small file, is copied. The account is kept (the owner's decision:
// the files carry its uid, and a restore needs it). Restore moves everything back only where
// nothing new stands (an empty directory at most), rewrites the site file, and the caller
// reloads. Expiry after [control] trash_keep days, hourly from worker 0.
namespace {
using provision::logs_root;
using provision::sites_root;
using provision::site_tree;
using provision::trash_dir;
using provision::under_root;
using provision::valid_trash_entry;

std::string iso_time(std::time_t t) {
    std::tm tm{};
    ::gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::time_t parse_iso(const std::string& s) {
    std::tm tm{};
    if (s.size() != 20 || !::strptime(s.c_str(), "%Y-%m-%dT%H:%M:%SZ", &tm)) return 0;
    return ::timegm(&tm);
}

// Opens `dir` as a directory that is root's alone, never through a symlink, creating it 0700
// when `create` and missing. -1 with why.
int open_private_dir(const std::string& dir, bool create, std::string& why) {
    int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0 && errno == ENOENT && create) {
        if (::mkdir(dir.c_str(), 0700) != 0 && errno != EEXIST) {
            why = dir + ": " + std::strerror(errno);
            return -1;
        }
        fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0) {
        why = dir + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno));
        return -1;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || st.st_uid != 0 || (st.st_mode & 077)) {
        if (st.st_uid == 0 && ::fchmod(fd, 0700) == 0) return fd;  // ours, opened too wide: closed
        ::close(fd);
        why = dir + " must be root's alone (0700); refused";
        return -1;
    }
    return fd;
}

// Removes dir_fd/name whatever it is, never following a symlink, never leaving the tree:
// every directory is entered through its own descriptor and emptied before it is removed.
bool remove_tree(int dir_fd, const std::string& name, std::string& why) {
    struct stat st {};
    if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return errno == ENOENT || (why = name + ": " + std::strerror(errno), false);
    if (!S_ISDIR(st.st_mode)) {
        if (::unlinkat(dir_fd, name.c_str(), 0) != 0 && errno != ENOENT) {
            why = name + ": " + std::strerror(errno);
            return false;
        }
        return true;
    }
    const int fd = ::openat(dir_fd, name.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        why = name + ": " + std::strerror(errno);
        return false;
    }
    DIR* d = ::fdopendir(fd);
    if (!d) {
        ::close(fd);
        why = name + ": " + std::strerror(errno);
        return false;
    }
    std::vector<std::string> children;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
    for (const auto& c : children)
        if (!remove_tree(::dirfd(d), c, why)) {
            ::closedir(d);
            return false;
        }
    ::closedir(d);
    if (::unlinkat(dir_fd, name.c_str(), AT_REMOVEDIR) != 0 && errno != ENOENT) {
        why = name + ": " + std::strerror(errno);
        return false;
    }
    return true;
}

// Bytes of the regular files below `path` (a file's own size when it is one), and their count.
void tree_size(const std::string& path, std::uint64_t& bytes, std::uint64_t& files, int depth = 0) {
    struct stat st {};
    if (depth > 64 || files > 500000 || ::lstat(path.c_str(), &st) != 0) return;
    if (S_ISREG(st.st_mode)) {
        bytes += static_cast<std::uint64_t>(st.st_size);
        ++files;
        return;
    }
    if (!S_ISDIR(st.st_mode)) return;
    if (DIR* d = ::opendir(path.c_str())) {
        std::vector<std::string> children;
        while (const struct dirent* e = ::readdir(d))
            if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") children.emplace_back(e->d_name);
        ::closedir(d);
        for (const auto& c : children) tree_size(path + "/" + c, bytes, files, depth + 1);
    }
}

// Copies a regular file (never through a symlink) with its mode and owner, then removes the
// original: the way a small file crosses a filesystem boundary (a log, an environment file).
bool copy_then_remove(const std::string& from, const std::string& to, std::string& why) {
    const int in = ::open(from.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st {};
    if (in < 0 || ::fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) {
        if (in >= 0) ::close(in);
        why = from + ": not a regular file";
        return false;
    }
    const int out = ::open(to.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, st.st_mode & 0777);
    if (out < 0) {
        ::close(in);
        why = to + ": " + std::strerror(errno);
        return false;
    }
    char buf[65536];
    bool ok = true;
    for (ssize_t n; ok && (n = ::read(in, buf, sizeof buf)) != 0;) {
        if (n < 0) {
            ok = errno == EINTR;
            continue;
        }
        for (ssize_t off = 0; ok && off < n;) {
            const ssize_t w = ::write(out, buf + off, static_cast<std::size_t>(n - off));
            if (w < 0 && errno == EINTR) continue;
            ok = w > 0;
            if (ok) off += w;
        }
    }
    ok = ok && ::fchown(out, st.st_uid, st.st_gid) == 0 && ::fsync(out) == 0;
    const int e = errno;
    ::close(in);
    ::close(out);
    if (!ok) {
        ::unlink(to.c_str());
        why = "copy " + from + ": " + std::strerror(e);
        return false;
    }
    if (::unlink(from.c_str()) != 0) {
        why = "remove " + from + " after copying: " + std::strerror(errno);
        return false;
    }
    return true;
}

// Moves `from` to `to`, whose parent must exist: by rename, or a copy for a regular file on
// another filesystem. A directory on another filesystem is EXDEV to the caller.
bool move_path(const std::string& from, const std::string& to, std::string& why, bool& exdev) {
    exdev = false;
    if (::rename(from.c_str(), to.c_str()) == 0) return true;
    if (errno != EXDEV) {
        why = "move " + from + " to " + to + ": " + std::strerror(errno);
        return false;
    }
    struct stat st {};
    if (::lstat(from.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return copy_then_remove(from, to, why);
    exdev = true;
    why = "move " + from + ": another filesystem";
    return false;
}

// The manifest of an entry, read from <entry dir>/manifest.json; null with why.
json::Value read_manifest(const std::string& entry_dir, std::string& why) {
    const int fd = ::open((entry_dir + "/manifest.json").c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        why = entry_dir + "/manifest.json: " + std::strerror(errno);
        return json::Value(nullptr);
    }
    std::string text;
    char buf[8192];
    for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) > 0 && text.size() < 4u << 20;) text.append(buf, static_cast<std::size_t>(n));
    ::close(fd);
    json::Value m;
    std::string err;
    if (!json::parse(text, m, err) || !m.is_object() || !control::valid_domain(m.get("site"))) {
        why = entry_dir + "/manifest.json does not parse (" + err + ")";
        return json::Value(nullptr);
    }
    return m;
}

// The places other than the primary entry directory a piece may sit in: a trash beside the
// state directory or the logs, named <base>/.trash/<entry>; nothing else is ever removed.
bool secondary_location_ok(const Config& cfg, const std::string& entry, const std::string& to) {
    for (const std::string base : {cfg.state_dir, logs_root(cfg)})
        if (!base.empty() && under_root(to, base + "/.trash/" + entry) && to != base + "/.trash/" + entry) return true;
    return false;
}

// Removes one entry: its directory under the trash, and every piece the manifest put beside
// the state directory or the logs. `why` on the first failure.
bool remove_entry(const Config& cfg, const std::string& entry, std::string& why) {
    const std::string tdir = trash_dir(cfg);
    const int tfd = open_private_dir(tdir, false, why);
    if (tfd < 0) return false;
    if (const json::Value m = read_manifest(tdir + "/" + entry, why); !m.is_null())
        for (const auto& p : m["pieces"].items()) {
            const std::string to(p.get("to"));
            if (!under_root(to, tdir + "/" + entry) && secondary_location_ok(cfg, entry, to)) {
                const std::string parent = to.substr(0, to.rfind('/')), leaf = to.substr(to.rfind('/') + 1);
                std::string w;
                const int pfd = open_private_dir(parent, false, w);
                if (pfd >= 0) {
                    remove_tree(pfd, leaf, w);
                    ::close(pfd);
                    ::rmdir(parent.c_str());  // the per-entry directory beside the state or the logs, once empty
                }
            }
        }
    const bool ok = remove_tree(tfd, entry, why);
    ::close(tfd);
    return ok;
}

// The entry's expiry from its manifest and the trash_keep in force (0: never).
std::time_t expires_at(const json::Value& manifest, unsigned keep_days) {
    if (keep_days == 0) return 0;
    const std::time_t deleted = parse_iso(std::string(manifest.get("deleted_at")));
    return deleted ? deleted + static_cast<std::time_t>(keep_days) * 86400 : 0;
}

// A directory that is missing or empty: the one place a restore puts files back into.
bool absent_or_empty_dir(const std::string& path, bool& exists) {
    struct stat st {};
    exists = ::lstat(path.c_str(), &st) == 0;
    if (!exists) return true;
    if (!S_ISDIR(st.st_mode)) return false;
    DIR* d = ::opendir(path.c_str());
    if (!d) return false;
    bool empty = true;
    while (const struct dirent* e = ::readdir(d))
        if (std::string_view(e->d_name) != "." && std::string_view(e->d_name) != "..") empty = false;
    ::closedir(d);
    return empty;
}

// Creates the missing directories above `path` (root's, 0755; the logs' parent 0750 with the
// server's group, which reads its logs through it).
bool ensure_parent(const std::string& path, gid_t server_gid, bool logs, std::string& why) {
    const std::string parent = path.substr(0, path.rfind('/'));
    if (parent.empty()) return true;
    struct stat st {};
    if (::lstat(parent.c_str(), &st) == 0) return S_ISDIR(st.st_mode) || (why = parent + " is not a directory", false);
    if (!ensure_parent(parent, server_gid, logs, why)) return false;
    if (::mkdir(parent.c_str(), logs ? 0750 : 0755) != 0 && errno != EEXIST) {
        why = parent + ": " + std::strerror(errno);
        return false;
    }
    if (logs) (void)::chown(parent.c_str(), 0, server_gid);
    return true;
}

json::Value site_trash(const json::Value& req, const Config& cfg) {
    json::Value reply = json::Value::object();
    auto fail = [&](std::string why) { return reply.set("ok", false).set("error", std::move(why)); };
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return fail(std::string("the configuration on disk does not load: ") + e.what());
    }
    const std::string name(req.get("site"));
    const SiteConfig* site = control::find_site(fresh, name);
    if (!site) return fail("no site " + name + " in the configuration on disk");
    const std::string domain = site->server_names.front();
    if (!control::valid_domain(domain)) return fail("site " + domain + " has no host name a trash entry can carry");
    std::string why;
    const std::string tree = site_tree(fresh, *site, why);
    if (tree.empty()) return fail(why);
    const std::string tdir = trash_dir(fresh);
    for (const auto& s : fresh.sites) {
        const std::string r = s.project_root.empty() ? s.root : s.project_root;
        if (!r.empty() && under_root(r, tdir)) return fail("a site's directory (" + r + ") lies inside the trash directory " + tdir + "; refused");
    }
    // The site file, whose text the manifest keeps (the server removes the file afterwards).
    const fs::path sfile = control::site_file(fresh, domain);
    std::string site_file_path, site_file_text;
    for (const fs::path& candidate : {sfile, fs::path(sfile.string() + ".disabled")}) {
        std::ifstream in(candidate);
        if (!in) continue;
        site_file_path = candidate.string();
        site_file_text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
        break;
    }
    if (site_file_path.empty()) return fail("no managed site file for " + domain + " under " + control::sites_dir(fresh).string() + " (a hand-written site is removed by hand)");
    // A running service would keep writing into the trash: root stops it first.
    json::Value root_cmds = json::Value::array();
    if (service_app(site->app) && !site->user.empty()) {
        const std::string unit = "agensio-app-" + site->user + ".service";
        std::string w;
        const json::Value states = unit_states({unit}, w);
        if (!states.is_null() && !states[unit].is_null()) {
            const std::string active(states[unit].get("ActiveState")), load(states[unit].get("LoadState"));
            if (active == "active" || active == "activating" || active == "reloading" || active == "deactivating")
                return reply.set("ok", false)
                    .set("error", "the site's service " + unit + " is " + active + ": its files cannot be moved while it runs from them")
                    .set("run_as_root", json::Value::array().push("systemctl disable --now " + unit).push("rm /etc/systemd/system/" + unit).push("systemctl daemon-reload"));
            if (load != "not-found") root_cmds.push("systemctl disable " + unit).push("rm /etc/systemd/system/" + unit).push("systemctl daemon-reload");
        }
    }
    // The account and the pieces.
    uid_t uid = 0;
    gid_t gid = 0;
    bool account_shared = false;
    if (!site->user.empty()) {
        if (!site_account(fresh, site->user, uid, gid, why)) return fail(why);
        for (const auto& s : fresh.sites)
            if (s.user == site->user && !(s.server_names == site->server_names)) account_shared = true;
    } else {
        struct stat st {};
        if (::lstat(tree.c_str(), &st) == 0) {
            uid = st.st_uid;
            gid = st.st_gid;
        }
    }
    struct Piece {
        std::string kind, from, name;
    };
    std::vector<Piece> pieces;
    {
        struct stat st {};
        if (::lstat(tree.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return fail("the site's directory " + tree + " is missing or not a directory; nothing moved");
        pieces.push_back({"site", tree, "site"});
    }
    if (!site->user.empty() && !fresh.state_dir.empty()) {
        const std::string state = fresh.state_dir + "/" + site->user;
        struct stat st {};
        if (!account_shared && ::lstat(state.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) pieces.push_back({"state", state, "state"});
        else if (const std::string venv = state + "/venvs/" + domain; ::lstat(venv.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) pieces.push_back({"venv", venv, "venv"});
    }
    if (!site->access_log.empty() && under_root(site->access_log, logs_root(fresh))) {
        const fs::path log = site->access_log;
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(log.parent_path(), ec)) {
            const std::string n = e.path().filename().string();
            if ((n == log.filename().string() || n.starts_with(log.filename().string() + ".")) && e.is_regular_file(ec) && !e.is_symlink(ec))
                pieces.push_back({"log", e.path().string(), "logs/" + n});
        }
    }
    if (appenv::valid_site(domain)) {
        const std::string env = appenv::dir_of(fresh.config_path) + "/" + domain + ".env";
        struct stat st {};
        if (::lstat(env.c_str(), &st) == 0 && S_ISREG(st.st_mode)) pieces.push_back({"env", env, "env/" + domain + ".env"});
    }
    // The entry: <domain>-<stamp>, root's 0700, in the trash (created likewise).
    const int tfd = open_private_dir(tdir, true, why);
    if (tfd < 0) return fail(why);
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    ::gmtime_r(&now, &tm);
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%Y%m%d-%H%M%S", &tm);
    std::string entry = domain + "-" + stamp;
    if (::mkdirat(tfd, entry.c_str(), 0700) != 0) {
        const int e = errno;
        ::close(tfd);
        return fail(tdir + "/" + entry + ": " + std::strerror(e));
    }
    ::close(tfd);
    const std::string edir = tdir + "/" + entry;
    for (const char* sub : {"logs", "env"}) ::mkdir((edir + "/" + sub).c_str(), 0700);
    json::Value moved = json::Value::array();
    std::vector<std::pair<std::string, std::string>> done;  // to, from: undone on a failure
    for (const auto& p : pieces) {
        std::string to = edir + "/" + p.name;
        bool exdev = false;
        if (!move_path(p.from, to, why, exdev)) {
            if (!exdev) break;
            // A directory on another filesystem (the account's state directory, usually): a trash
            // beside it, <base>/.trash/<entry>/<name>, root's alone as well.
            const std::string base = p.kind == "state" || p.kind == "venv" ? fresh.state_dir : logs_root(fresh);
            const std::string side = base + "/.trash";
            std::string w;
            const int sfd = open_private_dir(side, true, w);
            if (sfd < 0 || (::mkdirat(sfd, entry.c_str(), 0700) != 0 && errno != EEXIST)) {
                if (sfd >= 0) ::close(sfd);
                why = w.empty() ? side + "/" + entry + ": " + std::strerror(errno) : w;
                break;
            }
            ::close(sfd);
            to = side + "/" + entry + "/" + p.name.substr(p.name.rfind('/') == std::string::npos ? 0 : p.name.rfind('/') + 1);
            if (!move_path(p.from, to, why, exdev)) break;
        }
        why.clear();
        done.emplace_back(to, p.from);
        moved.push(json::Value::object().set("kind", p.kind).set("from", p.from).set("to", to));
    }
    if (!why.empty()) {  // put back what was moved, remove the entry, report
        for (auto it = done.rbegin(); it != done.rend(); ++it) ::rename(it->first.c_str(), it->second.c_str());
        std::string w;
        remove_entry(fresh, entry, w);
        return fail(why + "; nothing was moved");
    }
    json::Value manifest = json::Value::object()
                               .set("site", domain).set("app", site->app.empty() ? "static" : site->app).set("account", site->user)
                               .set("uid", static_cast<double>(uid)).set("gid", static_cast<double>(gid)).set("deleted_at", iso_time(now))
                               .set("trash_keep", static_cast<double>(fresh.control.trash_keep))
                               .set("site_file", json::Value::object().set("path", site_file_path).set("text", site_file_text))
                               .set("pieces", moved);
    {
        const std::string text = manifest.dump();
        const int mf = ::open((edir + "/manifest.json").c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        bool ok = mf >= 0;
        for (std::size_t off = 0; ok && off < text.size();) {
            const ssize_t n = ::write(mf, text.data() + off, text.size() - off);
            if (n < 0 && errno == EINTR) continue;
            ok = n > 0;
            if (ok) off += static_cast<std::size_t>(n);
        }
        ok = ok && ::fsync(mf) == 0;
        if (mf >= 0) ::close(mf);
        if (!ok) {
            const int e = errno;
            for (auto it = done.rbegin(); it != done.rend(); ++it) ::rename(it->first.c_str(), it->second.c_str());
            std::string w;
            remove_entry(fresh, entry, w);
            return fail("manifest: " + std::string(std::strerror(e)) + "; nothing was moved");
        }
    }
    reply.set("ok", true).set("entry", entry).set("directory", edir).set("site", domain).set("account", site->user)
        .set("account_shared", account_shared).set("pieces", moved).set("site_file", site_file_path).set("site_file_text", site_file_text)
        .set("deleted_at", iso_time(now));
    if (const std::time_t exp = expires_at(manifest, fresh.control.trash_keep)) reply.set("expires_at", iso_time(exp));
    else reply.set("expires_at", json::Value(nullptr));
    if (!root_cmds.items().empty()) reply.set("run_as_root", root_cmds);
    return reply;
}

json::Value site_restore(const json::Value& req, const Config& cfg) {
    json::Value reply = json::Value::object();
    auto fail = [&](std::string why) { return reply.set("ok", false).set("error", std::move(why)); };
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return fail(std::string("the configuration on disk does not load: ") + e.what());
    }
    const std::string entry(req.get("entry"));
    const std::string tdir = trash_dir(fresh), edir = tdir + "/" + entry;
    std::string why;
    const int tfd = open_private_dir(tdir, false, why);
    if (tfd < 0) return fail("the trash is empty (" + why + ")");
    ::close(tfd);
    const json::Value m = read_manifest(edir, why);
    if (m.is_null()) return fail("no trash entry " + entry + (why.empty() ? "" : " (" + why + ")"));
    const std::string domain(m.get("site")), account(m.get("account"));
    if (!entry.starts_with(domain + "-")) return fail("entry " + entry + " does not belong to " + domain);
    // The site must not exist again, and its file's place must be free.
    if (control::find_site(fresh, domain)) return fail("a site " + domain + " exists again; delete it first, or restore under another name by hand");
    const fs::path sfile = control::site_file(fresh, domain);
    std::error_code ec;
    if (fs::exists(sfile, ec) || fs::exists(sfile.string() + ".disabled", ec)) return fail(sfile.string() + " exists; the restore would overwrite it");
    // The account, with the uid the files carry.
    const uid_t uid = static_cast<uid_t>(m["uid"].num());
    if (!account.empty()) {
        const struct passwd* pw = ::getpwnam(account.c_str());
        if (!pw)
            return reply.set("ok", false)
                .set("error", "the account " + account + " no longer exists, and the files belong to uid " + std::to_string(uid))
                .set("run_as_root", json::Value::array().push("useradd --system --no-create-home --home-dir " + fresh.state_dir + "/" + account +
                                                              " --shell /usr/sbin/nologin --uid " + std::to_string(uid) + " " + account));
        if (pw->pw_uid != uid)
            return fail("the account " + account + " has uid " + std::to_string(pw->pw_uid) + " now, but the files belong to uid " + std::to_string(uid) +
                        "; a restore needs the same uid (chown the trash entry by hand, or recreate the account with --uid " + std::to_string(uid) + ")");
    }
    // Every piece's original place must be free: missing, or an empty directory (the owner's
    // rule: never merge into files that appeared since).
    for (const auto& p : m["pieces"].items()) {
        const std::string from(p.get("from")), to(p.get("to"));
        if (!under_root(to, edir) && !secondary_location_ok(fresh, entry, to)) return fail("the manifest names a piece outside the trash (" + to + "); refused");
        bool exists = false;
        if (!absent_or_empty_dir(from, exists)) return fail(from + " exists and is not empty: the site is restored only into an empty place");
    }
    gid_t server_gid = 0;
    if (const struct group* gr = ::getgrnam((fresh.group.empty() ? fresh.user : fresh.group).c_str())) server_gid = gr->gr_gid;
    else if (const struct passwd* pw = ::getpwnam(fresh.user.c_str())) server_gid = pw->pw_gid;
    std::vector<std::pair<std::string, std::string>> done;  // from, to (as moved back): undone on a failure
    json::Value restored = json::Value::array();
    for (const auto& p : m["pieces"].items()) {
        const std::string from(p.get("from")), to(p.get("to")), kind(p.get("kind"));
        bool exists = false;
        absent_or_empty_dir(from, exists);
        if (exists) ::rmdir(from.c_str());
        if (!ensure_parent(from, server_gid, kind == "log", why)) break;
        bool exdev = false;
        if (!move_path(to, from, why, exdev)) break;
        done.emplace_back(to, from);
        restored.push(json::Value::object().set("kind", kind).set("path", from));
    }
    if (!why.empty()) {
        for (auto it = done.rbegin(); it != done.rend(); ++it) ::rename(it->second.c_str(), it->first.c_str());
        return fail(why + "; nothing was restored");
    }
    // The site file back, owned as its directory is (the server's account), 0640.
    {
        struct stat st {};
        const fs::path dir = control::sites_dir(fresh);
        if (::stat(dir.c_str(), &st) != 0) {
            for (auto it = done.rbegin(); it != done.rend(); ++it) ::rename(it->second.c_str(), it->first.c_str());
            return fail(dir.string() + ": " + std::strerror(errno) + "; nothing was restored");
        }
        const std::string text(m["site_file"].get("text"));
        const int f = ::open(sfile.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0640);
        bool ok = f >= 0;
        for (std::size_t off = 0; ok && off < text.size();) {
            const ssize_t n = ::write(f, text.data() + off, text.size() - off);
            if (n < 0 && errno == EINTR) continue;
            ok = n > 0;
            if (ok) off += static_cast<std::size_t>(n);
        }
        ok = ok && ::fchown(f, st.st_uid, st.st_gid) == 0 && ::fsync(f) == 0;
        const int e = errno;
        if (f >= 0) ::close(f);
        if (!ok) {
            ::unlink(sfile.c_str());
            for (auto it = done.rbegin(); it != done.rend(); ++it) ::rename(it->second.c_str(), it->first.c_str());
            return fail("write " + sfile.string() + ": " + std::strerror(e) + "; nothing was restored");
        }
    }
    std::string w;
    remove_entry(fresh, entry, w);  // the manifest and the empty directories
    return reply.set("ok", true).set("entry", entry).set("site", domain).set("account", account).set("site_file", sfile.string()).set("restored", restored)
        .set("app", m.get("app"));
}

json::Value trash_list(const Config& cfg) {
    json::Value reply = json::Value::object();
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return reply.set("ok", false).set("error", std::string("the configuration on disk does not load: ") + e.what());
    }
    json::Value entries = json::Value::array();
    const std::string tdir = trash_dir(fresh);
    std::string why;
    const int tfd = open_private_dir(tdir, false, why);
    if (tfd < 0) return reply.set("ok", true).set("entries", entries).set("directory", tdir).set("trash_keep", static_cast<double>(fresh.control.trash_keep));
    std::vector<std::string> names;
    if (DIR* d = ::fdopendir(tfd)) {
        while (const struct dirent* e = ::readdir(d))
            if (valid_trash_entry(e->d_name)) names.emplace_back(e->d_name);
        ::closedir(d);
    } else {
        ::close(tfd);
    }
    std::sort(names.begin(), names.end());
    const std::time_t now = std::time(nullptr);
    for (const auto& n : names) {
        std::string w;
        const json::Value m = read_manifest(tdir + "/" + n, w);
        json::Value item = json::Value::object().set("entry", n);
        if (m.is_null()) {
            entries.push(item.set("error", w));
            continue;
        }
        std::uint64_t bytes = 0, files = 0;
        for (const auto& p : m["pieces"].items()) tree_size(std::string(p.get("to")), bytes, files);
        const std::string account(m.get("account"));
        bool in_use = false;
        for (const auto& s : fresh.sites) in_use = in_use || (!account.empty() && s.user == account);
        const std::time_t exp = expires_at(m, fresh.control.trash_keep);
        item.set("site", m.get("site")).set("app", m.get("app")).set("account", account).set("account_in_use", in_use)
            .set("deleted_at", m.get("deleted_at")).set("expires_at", exp ? json::Value(iso_time(exp)) : json::Value(nullptr))
            .set("expired", exp != 0 && exp <= now).set("bytes", static_cast<double>(bytes)).set("files", static_cast<double>(files));
        json::Value pieces = json::Value::array();
        for (const auto& p : m["pieces"].items()) pieces.push(json::Value::object().set("kind", p.get("kind")).set("from", p.get("from")));
        item.set("pieces", std::move(pieces));
        entries.push(std::move(item));
    }
    return reply.set("ok", true).set("entries", entries).set("directory", tdir).set("trash_keep", static_cast<double>(fresh.control.trash_keep));
}

json::Value trash_delete(const json::Value& req, const Config& cfg) {
    json::Value reply = json::Value::object();
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return reply.set("ok", false).set("error", std::string("the configuration on disk does not load: ") + e.what());
    }
    const std::string entry(req.get("entry"));
    std::string why;
    struct stat st {};
    if (::lstat((trash_dir(fresh) + "/" + entry).c_str(), &st) != 0) return reply.set("ok", false).set("error", "no trash entry " + entry);
    if (!remove_entry(fresh, entry, why)) return reply.set("ok", false).set("error", why);
    return reply.set("ok", true).set("entry", entry).set("removed", true);
}

json::Value trash_expire(const Config& cfg) {
    json::Value reply = json::Value::object();
    const json::Value list = trash_list(cfg);
    if (!list["ok"].boolean()) return list;
    Config fresh;
    try {
        fresh = load_config(cfg.config_path);
    } catch (const std::exception& e) {
        return reply.set("ok", false).set("error", e.what());
    }
    json::Value removed = json::Value::array(), failed = json::Value::array();
    std::size_t kept = 0;
    for (const auto& e : list["entries"].items()) {
        if (!e["expired"].boolean()) {
            ++kept;
            continue;
        }
        std::string why;
        if (remove_entry(fresh, std::string(e.get("entry")), why)) removed.push(std::string(e.get("entry")));
        else failed.push(std::string(e.get("entry")) + ": " + why);
    }
    return reply.set("ok", true).set("removed", removed).set("failed", failed).set("kept", static_cast<double>(kept));
}

}  // namespace

// The helper's loop: one JSON line in, one out, until the server closes its end.
void helper_loop(int fd, const Config& cfg) {
    // A root process that must not inherit the listeners or anything else: only the socket
    // (stdio points at /dev/null; program output comes back through our own pipe).
    for (int i = 3; i < 1024; ++i)
        if (i != fd) ::close(i);
    const int devnull = ::open("/dev/null", O_RDWR | O_CLOEXEC);
    if (devnull >= 0) {
        ::dup2(devnull, 0);
        ::dup2(devnull, 1);
        ::dup2(devnull, 2);
        ::close(devnull);
    }
    uid_t server_uid = 0;
    if (!cfg.user.empty())
        if (const struct passwd* pw = ::getpwnam(cfg.user.c_str())) server_uid = pw->pw_uid;
    auto last_restart = std::chrono::steady_clock::time_point{};
    std::string in;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::read(fd, buf, sizeof buf);
        if (n <= 0) break;
        in.append(buf, static_cast<std::size_t>(n));
        std::size_t nl;
        while ((nl = in.find('\n')) != std::string::npos) {
            const std::string line = in.substr(0, nl);
            in.erase(0, nl + 1);
            json::Value req, reply = json::Value::object();
            std::string err;
            if (!json::parse(line, req, err)) {
                reply.set("ok", false).set("error", "bad request: " + err);
            } else if (const std::string bad = provision::validate(req, cfg); !bad.empty()) {
                reply.set("ok", false).set("error", bad);
            } else {
                const std::string op(req.get("op"));
                std::string out, why;
                if (op == "ping") {
                    reply.set("ok", true);
                } else if (op == "account_add") {
                    const std::string name(req.get("name"));
                    if (::getpwnam(name.c_str())) {
                        reply.set("ok", true).set("output", "account exists");
                    } else if (const char* useradd = find_binary({"/usr/sbin/useradd", "/sbin/useradd"})) {
                        const int rc = run(useradd, {"--system", "--no-create-home", "--home-dir", cfg.state_dir + "/" + name,
                                                     "--shell", "/usr/sbin/nologin", name}, out);
                        reply.set("ok", rc == 0).set("output", out);
                        if (rc != 0) reply.set("error", "useradd exited " + std::to_string(rc));
                    } else {
                        reply.set("ok", false).set("error", "useradd not found");
                    }
                } else if (op == "site_layout") {
                    uid_t uid = 0;
                    gid_t gid = 0;
                    const std::string owner(req.get("owner"));
                    gid_t server_gid = 0;
                    if (const struct group* gr = ::getgrnam((cfg.group.empty() ? cfg.user : cfg.group).c_str())) server_gid = gr->gr_gid;
                    else if (const struct passwd* pw = ::getpwnam(cfg.user.c_str())) server_gid = pw->pw_gid;
                    if (!site_account(cfg, owner, uid, gid, why) || !lay_out(cfg, std::string(req.get("dir")), uid, server_gid, server_uid, why))
                        reply.set("ok", false).set("error", why);
                    else
                        reply.set("ok", true);
                } else if (op == "log_own") {
                    const std::string file(req.get("file")), group(req.get("group"));
                    const struct group* gr = ::getgrnam(group.c_str());
                    const int f = gr ? ::open(file.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
                    if (!gr) reply.set("ok", false).set("error", "group " + group + " does not exist");
                    else if (f < 0) reply.set("ok", false).set("error", file + ": " + std::strerror(errno));
                    else {
                        struct stat st {};
                        if (::fstat(f, &st) == 0 && S_ISREG(st.st_mode) && ::fchown(f, server_uid, gr->gr_gid) == 0 && ::fchmod(f, 0640) == 0)
                            reply.set("ok", true);
                        else
                            reply.set("ok", false).set("error", file + ": " + std::strerror(errno));
                        ::close(f);
                    }
                } else if (op == "pools_apply") {
                    try {
                        const Config fresh = load_config(cfg.config_path);
                        const auto errors = check_hosting(fresh, system_facts());
                        if (!errors.empty()) {
                            reply.set("ok", false).set("error", "hosting rules: " + errors.front());
                        } else {
                            std::string version;
                            for (const auto& s : fresh.sites)
                                if (s.pool.generated && !s.pool.version.empty()) version = s.pool.version;
                            const fs::path dir = pools_dir(fresh, version);
                            std::ostringstream log;
                            const int rc = dir.empty() ? 1 : write_pools(fresh, dir, false, log);
                            std::string text = log.str();
                            if (rc == 3) {
                                const std::string cmd = control::php_fpm_reload_command(fresh, version);  // "systemctl reload phpX-fpm"
                                const std::size_t sp = cmd.rfind(' ');
                                const std::string unit = sp == std::string::npos ? "" : cmd.substr(sp + 1);
                                if (const char* systemctl = find_binary({"/usr/bin/systemctl", "/bin/systemctl"}); systemctl && !unit.empty()) {
                                    std::string o;
                                    const int r = run(systemctl, {"reload", unit}, o);
                                    text += (r == 0 ? "reloaded " + unit + " (a php-fpm reload cuts PHP requests in flight on every site unless php-fpm.conf sets process_control_timeout; health reports it)"
                                                    : "could not reload " + unit + " (" + o + ")") + "\n";
                                } else {
                                    text += "systemctl not available: reload php-fpm by hand\n";
                                }
                            }
                            reply.set("ok", rc == 0 || rc == 3).set("output", text);
                            if (rc == 1) reply.set("error", "agensio pools failed");
                        }
                    } catch (const std::exception& e) {
                        reply.set("ok", false).set("error", e.what());
                    }
                } else if (op == "app_install") {
                    reply = app_install(req, cfg, fd);
                } else if (op == "file_copy") {
                    reply = file_copy(req, cfg, fd);
                } else if (op == "task_run") {
                    reply = task_run(req, cfg, fd);
                } else if (op == "env_read" || op == "env_write") {
                    reply = env_op(req, cfg);
                } else if (op == "app_status" || op == "app_logs") {
                    reply = app_op(req, cfg);
                } else if (op == "app_check") {
                    reply = app_check(cfg);
                } else if (op == "site_trash") {
                    reply = site_trash(req, cfg);
                } else if (op == "site_restore") {
                    reply = site_restore(req, cfg);
                } else if (op == "trash_list") {
                    reply = trash_list(cfg);
                } else if (op == "trash_delete") {
                    reply = trash_delete(req, cfg);
                } else if (op == "trash_expire") {
                    reply = trash_expire(cfg);
                } else if (op == "env_check") {
                    // Health's read-only pass over the sites' environment files (appenv::inspect),
                    // the sites from the configuration on disk; no value leaves the helper.
                    try {
                        const Config fresh = load_config(cfg.config_path);
                        std::vector<std::string> sites;
                        for (const auto& s : fresh.sites)
                            if (proxy_app(s.app) && !s.server_names.empty() &&
                                std::find(sites.begin(), sites.end(), s.server_names.front()) == sites.end())
                                sites.push_back(s.server_names.front());
                        reply = appenv::inspect(appenv::dir_of(cfg.config_path), 0, sites);
                    } catch (const std::exception& e) {
                        reply.set("ok", false).set("error", e.what());
                    }
                } else if (op == "service_restart") {
                    const auto now = std::chrono::steady_clock::now();
                    if (now - last_restart < std::chrono::seconds(60)) {
                        reply.set("ok", false).set("error", "a restart was requested less than a minute ago");
                    } else if (const char* systemctl = find_binary({"/usr/bin/systemctl", "/bin/systemctl"})) {
                        last_restart = now;
                        reply.set("ok", true).set("output", "restart requested");
                        const std::string text = reply.dump() + "\n";
                        (void)!::write(fd, text.data(), text.size());
                        std::string o;
                        run(systemctl, {"restart", "agensio"}, o);  // the helper dies with the service
                        continue;
                    } else {
                        reply.set("ok", false).set("error", "systemctl not available: restart the service by hand");
                    }
                }
            }
            const std::string text = reply.dump() + "\n";
            if (::write(fd, text.data(), text.size()) < 0) break;
        }
    }
    ::_exit(0);
}

}  // namespace

bool Provisioner::start(const Config& cfg, ErrorLog& log) {
    if (::geteuid() != 0) {
        log.info("provisioning helper not started: the server does not start as root");
        return false;
    }
    int pair[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) != 0) {
        log.error(std::string("provisioning helper: socketpair: ") + std::strerror(errno));
        return false;
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        log.error(std::string("provisioning helper: fork: ") + std::strerror(errno));
        ::close(pair[0]);
        ::close(pair[1]);
        return false;
    }
    if (pid == 0) {
        ::close(pair[0]);
        helper_loop(pair[1], cfg);
    }
    ::close(pair[1]);
    fd_ = pair[0];
    pid_ = pid;
    log.info("provisioning helper started (pid " + std::to_string(pid) + "): accounts, site layout, pools, restart, application install on request");
    return true;
}

json::Value Provisioner::try_request(const json::Value& req) {
    std::unique_lock lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) return json::Value::object().set("ok", false).set("busy", true);
    return exchange(req);  // under the lock taken here: nothing can slip in and make this wait
}

json::Value Provisioner::request(const json::Value& req) {
    std::lock_guard lock(mutex_);
    return exchange(req);
}

json::Value Provisioner::exchange(const json::Value& req) {
    json::Value reply = json::Value::object();
    if (fd_ < 0) return reply.set("ok", false).set("error", "no provisioning helper");
    const std::string text = req.dump() + "\n";
    if (::write(fd_, text.data(), text.size()) < 0) return reply.set("ok", false).set("error", "helper gone");
    std::string in;
    char buf[4096];
    while (in.find('\n') == std::string::npos) {
        const ssize_t n = ::read(fd_, buf, sizeof buf);
        if (n <= 0) return reply.set("ok", false).set("error", "helper gone");
        in.append(buf, static_cast<std::size_t>(n));
    }
    std::string err;
    if (!json::parse(in.substr(0, in.find('\n')), reply, err)) return json::Value::object().set("ok", false).set("error", "bad reply: " + err);
    return reply;
}

void Provisioner::stop() noexcept {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (pid_ > 0) {
        int status = 0;
        ::waitpid(pid_, &status, WNOHANG);
        pid_ = -1;
    }
}

#else
bool Provisioner::start(const Config&, ErrorLog& log) {
    log.info("provisioning helper: not available on this platform");
    return false;
}
json::Value Provisioner::request(const json::Value&) { return json::Value::object().set("ok", false).set("error", "not available"); }
json::Value Provisioner::try_request(const json::Value&) { return json::Value::object().set("ok", false).set("error", "not available"); }
void Provisioner::stop() noexcept {}
#endif

Provisioner::~Provisioner() { stop(); }

}  // namespace agensio
