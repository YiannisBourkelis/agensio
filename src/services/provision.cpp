#include "services/provision.hpp"

#ifndef _WIN32
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
#include <cstring>
#include <filesystem>
#include <sstream>

#include "control/sites.hpp"
#include "services/fetch.hpp"
#include "services/install.hpp"
#include "services/pools.hpp"

namespace agensio {

namespace fs = std::filesystem;

namespace provision {

std::string sites_root(const Config& cfg) { return cfg.control.sites_root.empty() ? std::string("/var/www") : cfg.control.sites_root; }

std::string logs_root(const Config& cfg) {
    if (cfg.log.access.empty() || cfg.log.access == "off") return "/var/log/agensio";
    return fs::path(cfg.log.access).parent_path().string();
}

std::string uploads_dir(const Config& cfg) { return cfg.state_dir + "/uploads"; }

namespace {
bool under(const std::string& path, const std::string& root) {
    return path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/');
}
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
        for (const char* flag : {"create_path", "dry_run"})
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
        return "";
    }
    if (op == "pools_apply" || op == "service_restart" || op == "ping") return "";
    return "unknown operation '" + op + "'";
}

}  // namespace provision

#ifndef _WIN32

namespace {

// Runs a program by absolute path with a fixed argv and an empty environment; the
// combined output and the exit status come back. Never a shell.
int run(const char* path, const std::vector<std::string>& args, std::string& output) {
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
        if (output.size() > 8192) break;
    }
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

// Runs install::execute in a child that has become the installing account; the reply
// comes back through a pipe as one JSON line. Bounded by a deadline.
json::Value app_install(const json::Value& req, const Config& cfg, int helper_fd) {
    json::Value reply = json::Value::object();
    const std::string target(req.get("target")), user(req.get("user")), upload(req.get("upload")), site_root(req.get("site_root"));
    uid_t uid = 0;
    gid_t gid = 0;
    std::string why;
    if (!install_account(cfg, site_root, user, uid, gid, why)) return reply.set("ok", false).set("error", why);
    if (uid == 0) return reply.set("ok", false).set("error", "refusing to install as root");
    int upload_fd = -1;
    if (!upload.empty()) {
        const std::string path = provision::uploads_dir(cfg) + "/" + upload;
        upload_fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (upload_fd < 0) return reply.set("ok", false).set("error", "upload " + upload + ": " + std::strerror(errno));
    }
    int pipefd[2];
    if (::pipe(pipefd) != 0) {
        if (upload_fd >= 0) ::close(upload_fd);
        return reply.set("ok", false).set("error", std::string("pipe: ") + std::strerror(errno));
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        if (upload_fd >= 0) ::close(upload_fd);
        ::close(pipefd[0]);
        ::close(pipefd[1]);
        return reply.set("ok", false).set("error", std::string("fork: ") + std::strerror(errno));
    }
    if (pid == 0) {
        ::close(helper_fd);
        ::close(pipefd[0]);
        ::umask(0);  // the extractor sets exact modes; nothing else is created here
        json::Value out = json::Value::object();
        if (::setgroups(0, nullptr) != 0 || ::setgid(gid) != 0 || ::setuid(uid) != 0 || ::setuid(0) == 0 || ::geteuid() != uid) {
            out.set("ok", false).set("error", std::string("cannot become uid ") + std::to_string(uid) + ": " + std::strerror(errno));
        } else {
            install::Request r;
            r.site_root = std::string(req.get("site_root"));
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
            out = install::execute(r);
        }
        const std::string text = out.dump() + "\n";
        (void)!::write(pipefd[1], text.data(), text.size());
        ::_exit(0);
    }
    ::close(pipefd[1]);
    if (upload_fd >= 0) ::close(upload_fd);
    std::string in;
    char buf[4096];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::minutes(20);
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0) {
            ::kill(pid, SIGKILL);
            reply.set("ok", false).set("error", "the installation did not finish within 20 minutes; stopped");
            break;
        }
        struct pollfd pfd {pipefd[0], POLLIN, 0};
        const int pr = ::poll(&pfd, 1, static_cast<int>(std::min<long long>(left, 60000)));
        if (pr == 0) continue;
        if (pr < 0 && errno == EINTR) continue;
        const ssize_t n = ::read(pipefd[0], buf, sizeof buf);
        if (n <= 0) break;
        in.append(buf, static_cast<std::size_t>(n));
        if (in.size() > 65536) break;
    }
    ::close(pipefd[0]);
    int status = 0;
    ::waitpid(pid, &status, 0);
    if (reply["ok"].is_null()) {
        std::string err;
        const std::size_t nl = in.find('\n');
        if (nl == std::string::npos || !json::parse(in.substr(0, nl), reply, err))
            reply = json::Value::object().set("ok", false).set("error", "the install process ended without a result" + (WIFSIGNALED(status) ? std::string(" (signal ") + std::to_string(WTERMSIG(status)) + ")" : ""));
    }
    return reply;
}

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
                                    text += (r == 0 ? "reloaded " + unit : "could not reload " + unit + " (" + o + ")") + "\n";
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

json::Value Provisioner::request(const json::Value& req) {
    std::lock_guard lock(mutex_);
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
void Provisioner::stop() noexcept {}
#endif

Provisioner::~Provisioner() { stop(); }

}  // namespace agensio
