#include "services/tasks.hpp"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifndef _WIN32
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "services/pools.hpp"

namespace agensio::tasks {

namespace {

bool alpha(unsigned char c) noexcept { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
bool digit(unsigned char c) noexcept { return c >= '0' && c <= '9'; }

// ^[A-Za-z][A-Za-z0-9_]{0,63}$: a Ruby constant's worth of name, never an option.
bool app_name(std::string_view v) noexcept {
    if (v.empty() || v.size() > 64 || !alpha(static_cast<unsigned char>(v[0]))) return false;
    for (unsigned char c : v)
        if (!alpha(c) && !digit(c) && c != '_') return false;
    return true;
}

// ^8(\.[0-9]{1,4}){1,3}$: an exact Rails 8 release. The rails_new row's options are Rails
// 8's (--skip-thruster, --skip-ci), so no other major is offered.
bool rails_version(std::string_view v) noexcept {
    if (v.size() < 3 || v[0] != '8' || v[1] != '.') return false;
    int groups = 0, run = 0;
    for (std::size_t i = 1; i < v.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(v[i]);
        if (c == '.') {
            if (i > 1 && run == 0) return false;
            ++groups;
            run = 0;
        } else if (digit(c)) {
            if (++run > 4) return false;
        } else {
            return false;
        }
    }
    return run > 0 && groups >= 1 && groups <= 3;
}

const std::vector<Family>& families() {
    static const std::vector<Family> f = {
        {"rails",
         // Production throughout: bundle install skips the development and test groups, so
         // anything Rails loads must be the production environment's.
         {{"RAILS_ENV", "production"}, {"GEM_HOME", "{gem_home}"}, {"BUNDLE_PATH", "vendor/bundle"}, {"BUNDLE_WITHOUT", "development:test"}},
         {"config/credentials.yml.enc", "config/credentials/*.key", ".env.*", "db/*.sqlite3", "storage/*.sqlite3", "storage/*.sqlite3-wal",
          "storage/*.sqlite3-shm", ".kamal/secrets*"}},
    };
    return f;
}

}  // namespace

const std::vector<Row>& rows() {
    static const std::vector<Row> r = {
        {"rails", "gem_install_rails",
         "Installs Rails 8 into the account's own gem directory (<home>/gems): the rails command rails_new runs. Downloads from rubygems.org "
         "and compiles native extensions; a few minutes.",
         "ruby", "gem",
         {{"install"}, {"rails"}, {"--no-document"}, {"--version"}, {"{version}", "version"}, {"~> 8.0", nullptr, "version"}},
         {{"version", "An exact Rails 8 release, e.g. 8.1.4; default the newest 8.x.", "^8(\\.[0-9]{1,4}){1,3}$", rails_version, false}},
         {},
         true, false, 3600},
        // Not --skip-bundle: Rails 8 skips its importmap, Hotwire and Solid Cache/Queue/Cable
        // installers when the bundle is skipped, and the application it leaves behind fails in
        // production. The bundle it installs goes to vendor/bundle (the preset's environment).
        // Not --skip-kamal either: Rails 8.1's database.yml writes the production databases'
        // paths (storage/production*.sqlite3) only when Kamal's files are generated, and leaves
        // them commented out for the operator otherwise, so db:prepare fails on the fresh
        // application (found by tests/rails.sh); Kamal's deploy.yml and gem just sit there.
        {"rails", "rails_new",
         "Creates a new Rails application with SQLite in the site's directory, which must be empty, and installs its gems into vendor/bundle "
         "(production gems only). Downloads; a few minutes. Needs gem_install_rails first.",
         "ruby", "ruby",
         {{"{gem_home}/bin/rails"}, {"new"}, {"."}, {"--name={name}"}, {"--database=sqlite3"}, {"--skip-git"}, {"--skip-docker"},
          {"--skip-thruster"}, {"--skip-ci"}},
         {{"name", "The application's name (its Ruby module): a letter, then letters, digits and underscores.", "^[A-Za-z][A-Za-z0-9_]{0,63}$", app_name, true}},
         {},
         true, true, 3600},
        {"rails", "bundle_install",
         "Installs the gems of the application's Gemfile into vendor/bundle (production gems only): after a Gemfile change, or after an "
         "application was installed from an archive. Downloads.",
         "ruby", "bundle", {{"install"}}, {}, {}, true, false, 3600},
        {"rails", "db_prepare",
         "Creates the production databases when they are missing and loads the schema, else runs pending migrations (bin/rails db:prepare).",
         "ruby", "bundle", {{"exec"}, {"rails"}, {"db:prepare"}}, {}, {}, false, false, 1800},
        {"rails", "db_migrate", "Runs pending migrations on the production databases (bin/rails db:migrate).",
         "ruby", "bundle", {{"exec"}, {"rails"}, {"db:migrate"}}, {}, {}, false, false, 1800},
        // SECRET_KEY_BASE_DUMMY: compiling assets needs no real secret, and an application
        // installed from an archive has no config/master.key (it is never committed).
        {"rails", "assets_precompile", "Builds the assets into public/assets (bin/rails assets:precompile).",
         "ruby", "bundle", {{"exec"}, {"rails"}, {"assets:precompile"}}, {}, {{"SECRET_KEY_BASE_DUMMY", "1"}}, false, false, 3600},
    };
    return r;
}

const Row* find(std::string_view app, std::string_view task) noexcept {
    for (const auto& r : rows())
        if (app == r.app && task == r.name) return &r;
    return nullptr;
}

const Family* family(std::string_view app) noexcept {
    for (const auto& f : families())
        if (app == f.app) return &f;
    return nullptr;
}

bool has_tasks(std::string_view app) noexcept {
    for (const auto& r : rows())
        if (app == r.app) return true;
    return false;
}

std::vector<std::string> names(std::string_view app) {
    std::vector<std::string> out;
    for (const auto& r : rows())
        if (app == r.app) out.emplace_back(r.name);
    return out;
}

std::vector<std::string> all_names() {
    std::vector<std::string> out;
    for (const auto& r : rows())
        if (std::find(out.begin(), out.end(), r.name) == out.end()) out.emplace_back(r.name);
    return out;
}

std::vector<const Param*> all_params() {
    std::vector<const Param*> out;
    for (const auto& r : rows())
        for (const auto& p : r.params)
            if (std::none_of(out.begin(), out.end(), [&](const Param* q) { return std::string_view(q->name) == p.name; })) out.push_back(&p);
    return out;
}

json::Value catalog(std::string_view app) {
    json::Value list = json::Value::array();
    for (const auto& r : rows()) {
        if (app != r.app) continue;
        json::Value params = json::Value::array();
        for (const auto& p : r.params)
            params.push(json::Value::object().set("name", p.name).set("description", p.description).set("pattern", p.pattern).set("required", p.required));
        list.push(json::Value::object().set("task", r.name).set("summary", r.summary).set("runtime", r.runtime).set("params", std::move(params))
                      .set("network", r.network).set("needs_empty", r.needs_empty).set("timeout", static_cast<double>(r.timeout)));
    }
    return list;
}

std::string check_params(const Row& row, const json::Value& params) {
    if (!params.is_null() && !params.is_object()) return "params must be an object of strings, e.g. {\"name\": \"blog\"}";
    for (const auto& m : params.members()) {
        const Param* def = nullptr;
        for (const auto& p : row.params)
            if (m.first == p.name) def = &p;
        if (!def) {
            std::string known;
            for (const auto& p : row.params) known += (known.empty() ? "" : ", ") + std::string(p.name);
            return "task " + std::string(row.name) + " takes no parameter '" + m.first + "'" + (known.empty() ? " (it takes none)" : " (it takes: " + known + ")");
        }
        if (!m.second.is_string()) return "parameter " + m.first + " must be a string";
        if (!def->valid(m.second.str())) return "parameter " + m.first + " = '" + m.second.str().substr(0, 80) + "' does not match " + def->pattern + ": " + def->description;
    }
    for (const auto& p : row.params)
        if (p.required && !params[p.name].is_string()) return "task " + std::string(row.name) + " needs the parameter " + p.name + ": " + p.description;
    return "";
}

namespace {

// {home}, {gem_home} and parameter names; the parameters were checked, so none holds a brace.
std::string expand(std::string_view text, const json::Value& params, const Context& ctx) {
    std::string out;
    for (std::size_t i = 0; i < text.size();) {
        const std::size_t open = text.find('{', i);
        if (open == std::string_view::npos) {
            out.append(text.substr(i));
            break;
        }
        const std::size_t close = text.find('}', open);
        if (close == std::string_view::npos) {
            out.append(text.substr(i));
            break;
        }
        out.append(text.substr(i, open - i));
        const std::string_view key = text.substr(open + 1, close - open - 1);
        if (key == "home") out += ctx.home;
        else if (key == "gem_home") out += ctx.home + "/gems";
        else out += params.get(key);
        i = close + 1;
    }
    return out;
}

}  // namespace

Plan build(const Row& row, const json::Value& params, const Context& ctx, const std::string& program) {
    Plan plan;
    plan.argv.push_back(program);
    for (const auto& a : row.args) {
        if (a.only_if && !params[a.only_if].is_string()) continue;
        if (a.unless && params[a.unless].is_string()) continue;
        plan.argv.push_back(expand(a.text, params, ctx));
    }
    // The environment is built, never inherited: the runtime's directory first on PATH, the
    // account's home and its tmp/, a UTF-8 locale, then the preset's and the row's variables.
    std::vector<std::string> path{ctx.runtime_dir};
    for (const char* d : {"/usr/local/bin", "/usr/bin", "/bin"})
        if (std::find(path.begin(), path.end(), d) == path.end()) path.emplace_back(d);
    std::string joined;
    for (const auto& d : path) joined += (joined.empty() ? "" : ":") + d;
    plan.env = {"PATH=" + joined, "HOME=" + ctx.home, "TMPDIR=" + ctx.home + "/tmp", "LANG=C.UTF-8"};
    if (const Family* f = family(row.app))
        for (const auto& [k, v] : f->env) plan.env.push_back(std::string(k) + "=" + expand(v, params, ctx));
    for (const auto& [k, v] : row.env) plan.env.push_back(std::string(k) + "=" + expand(v, params, ctx));
    plan.cwd = ctx.root;
    plan.timeout = std::min(row.timeout, ctx.timeout);
    plan.processes = ctx.processes;
    return plan;
}

void Capture::add(const char* p, std::size_t n) {
    total_ += n;
    if (head_.size() < head_cap_) {
        const std::size_t k = std::min(n, head_cap_ - head_.size());
        head_.append(p, k);
        p += k;
        n -= k;
    }
    if (n == 0) return;
    tail_.append(p, n);
    if (tail_.size() > 2 * tail_cap_) tail_.erase(0, tail_.size() - tail_cap_);
}

std::string Capture::text() const {
    if (total_ <= head_cap_ + tail_cap_) return head_ + tail_;
    return head_ + "\n[... " + std::to_string(total_ - head_cap_ - tail_cap_) + " bytes not shown ...]\n" + tail_.substr(tail_.size() - tail_cap_);
}

std::string clean_text(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size();) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        if (c == 0x1b) {  // ESC: a CSI sequence (colours, cursor moves) up to its final byte, or ESC and one byte
            if (i + 1 < in.size() && in[i + 1] == '[') {
                std::size_t j = i + 2;
                while (j < in.size() && !(static_cast<unsigned char>(in[j]) >= 0x40 && static_cast<unsigned char>(in[j]) <= 0x7e)) ++j;
                i = j < in.size() ? j + 1 : j;
            } else {
                i += i + 1 < in.size() ? 2 : 1;
            }
            continue;
        }
        if (c < 0x80) {
            out.push_back(static_cast<char>(c));
            ++i;
            continue;
        }
        const std::size_t len = (c >= 0xc2 && c <= 0xdf) ? 2 : (c >= 0xe0 && c <= 0xef) ? 3 : (c >= 0xf0 && c <= 0xf4) ? 4 : 0;
        bool ok = len != 0 && i + len <= in.size();
        for (std::size_t k = 1; ok && k < len; ++k) ok = (static_cast<unsigned char>(in[i + k]) & 0xc0) == 0x80;
        if (ok && len >= 3) {
            const unsigned char c1 = static_cast<unsigned char>(in[i + 1]);
            if ((c == 0xe0 && c1 < 0xa0) || (c == 0xed && c1 >= 0xa0) || (c == 0xf0 && c1 < 0x90) || (c == 0xf4 && c1 >= 0x90)) ok = false;
        }
        if (ok) {
            out.append(in.substr(i, len));
            i += len;
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return out;
}

std::string install_hint(std::string_view runtime) {
#ifndef _WIN32
    if (runtime == "ruby") {
        // Headers and a compiler: gem and bundle build native extensions (psych, bigdecimal,
        // bootsnap, nio4r); libyaml's headers for psych.
        if (::access("/usr/bin/apt-get", X_OK) == 0) return "apt-get install -y ruby ruby-dev ruby-bundler build-essential libyaml-dev";
        if (::access("/usr/bin/dnf", X_OK) == 0) return "dnf install -y ruby ruby-devel rubygem-bundler gcc gcc-c++ make redhat-rpm-config libyaml-devel";
    }
#else
    (void)runtime;
#endif
    return "";
}

#ifndef _WIN32

namespace {

std::string octal(unsigned mode) {
    char buf[8];
    std::snprintf(buf, sizeof buf, "%04o", mode & 07777);
    return buf;
}

std::string account_name(uid_t uid) {
    if (const struct passwd* pw = ::getpwuid(uid)) return pw->pw_name;
    return "uid " + std::to_string(uid);
}

bool below(const std::string& path, const std::string& root) {
    if (root == "/") return !path.empty() && path[0] == '/';
    return !root.empty() && (path == root || (path.size() > root.size() && path.compare(0, root.size(), root) == 0 && path[root.size()] == '/'));
}

// Every component of an absolute path, as lstat sees it: owned by root, and a directory
// writable by nobody but root. `leaf` (the last component) may be a symlink or a file.
std::string root_only(const std::string& path, bool& missing) {
    std::vector<std::string> prefixes{"/"};
    for (std::size_t pos = 1; pos <= path.size(); ++pos)
        if (pos == path.size() || path[pos] == '/')
            if (path[pos - 1] != '/') prefixes.push_back(path.substr(0, pos));
    for (const auto& so_far : prefixes) {
        struct stat st {};
        if (::lstat(so_far.c_str(), &st) != 0) {
            missing = errno == ENOENT;
            return so_far + ": " + std::strerror(errno);
        }
        if (st.st_uid != 0)
            return so_far + " belongs to " + account_name(st.st_uid) + ", not root: a runtime's files and directories must be root's alone, or a site could choose what runs";
        if (!S_ISLNK(st.st_mode) && (st.st_mode & 022))
            return so_far + " is writable by its group or by others (mode " + octal(st.st_mode) + "): a runtime's files and directories must be writable by root alone";
    }
    return "";
}

}  // namespace

std::string trusted_program(const std::string& path, const std::string& sites_root, std::string& canonical, bool& missing) {
    missing = false;
    if (path.empty() || path[0] != '/') return path + " is not an absolute path";
    if (std::string why = root_only(path, missing); !why.empty()) return why;
    char buf[PATH_MAX];
    if (!::realpath(path.c_str(), buf)) {
        missing = errno == ENOENT;
        return path + ": " + std::strerror(errno);
    }
    canonical = buf;
    if (std::string why = root_only(canonical, missing); !why.empty()) return why;
    struct stat st {};
    if (::stat(canonical.c_str(), &st) != 0) return canonical + ": " + std::strerror(errno);
    if (!S_ISREG(st.st_mode) || !(st.st_mode & 0111)) return canonical + " is not an executable file";
    if (below(canonical, sites_root)) return canonical + " is below sites_root " + sites_root + ", where a site could write";
    return "";
}

namespace {

// Closes every descriptor from `from` up (in the child, before exec).
void close_from(int from) noexcept {
#if defined(__linux__) && defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 34))
    if (::close_range(static_cast<unsigned>(from), ~0U, 0) == 0) return;
#endif
    const long max = ::sysconf(_SC_OPEN_MAX);
    for (int fd = from; fd < (max > 0 && max < 65536 ? static_cast<int>(max) : 65536); ++fd) ::close(fd);
}

}  // namespace

json::Value run(const Plan& plan, int cwd_fd) {
    json::Value r = json::Value::object();
    if (plan.argv.empty()) return r.set("error", "nothing to run");
    std::vector<char*> argv, envp;
    for (const auto& a : plan.argv) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    for (const auto& e : plan.env) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);
    int out[2];
    if (::pipe(out) != 0) return r.set("error", std::string("pipe: ") + std::strerror(errno));
    ::fcntl(out[0], F_SETFD, FD_CLOEXEC);
    const int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    struct rlimit files {};
    ::getrlimit(RLIMIT_NOFILE, &files);
    const rlim_t want_files = files.rlim_max == RLIM_INFINITY ? plan.open_files : std::min<rlim_t>(plan.open_files, files.rlim_max);
    const auto started = std::chrono::steady_clock::now();
    const pid_t pid = ::fork();
    if (pid < 0) {
        const int e = errno;
        ::close(out[0]);
        ::close(out[1]);
        if (devnull >= 0) ::close(devnull);
        return r.set("error", std::string("fork: ") + std::strerror(e));
    }
    if (pid == 0) {  // the child: async-signal-safe calls only until exec
        ::setpgid(0, 0);
        struct sigaction dfl {};
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        for (int sig : {SIGPIPE, SIGINT, SIGQUIT, SIGHUP, SIGTERM, SIGCHLD, SIGUSR1, SIGUSR2, SIGALRM}) ::sigaction(sig, &dfl, nullptr);
        sigset_t none;
        sigemptyset(&none);
        ::sigprocmask(SIG_SETMASK, &none, nullptr);
        if (devnull >= 0) ::dup2(devnull, 0);
        ::dup2(out[1], 1);
        ::dup2(out[1], 2);
        if (::fchdir(cwd_fd) != 0) ::_exit(126);
        ::umask(027);
        struct rlimit rl {};
        rl.rlim_cur = rl.rlim_max = plan.processes;
        ::setrlimit(RLIMIT_NPROC, &rl);
        rl.rlim_cur = rl.rlim_max = want_files;
        ::setrlimit(RLIMIT_NOFILE, &rl);
        rl.rlim_cur = rl.rlim_max = 0;
        ::setrlimit(RLIMIT_CORE, &rl);
        close_from(3);
        ::execve(argv[0], argv.data(), envp.data());
        static const char msg[] = "agensio: the program could not be executed\n";
        (void)!::write(2, msg, sizeof msg - 1);
        ::_exit(127);
    }
    ::setpgid(pid, pid);  // from this side too, so the group exists before any kill
    ::close(out[1]);
    if (devnull >= 0) ::close(devnull);
    ::fcntl(out[0], F_SETFL, ::fcntl(out[0], F_GETFL) | O_NONBLOCK);
    Capture cap;
    using clock = std::chrono::steady_clock;
    const auto deadline = started + std::chrono::seconds(plan.timeout);
    clock::time_point term_at{}, exit_at{}, kill_at{};
    bool eof = false, exited = false, timed_out = false, killed = false, stuck = false;
    char buf[16384];
    for (;;) {
        if (!exited) {
            // WNOWAIT: the program stays a zombie, so its process group cannot be reused
            // before the stragglers in it are killed below.
            siginfo_t info {};
            if (::waitid(P_PID, static_cast<id_t>(pid), &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == pid) {
                exited = true;
                exit_at = clock::now();
            }
        }
        const auto now = clock::now();
        if (exited && (eof || now - exit_at >= std::chrono::seconds(plan.drain))) break;
        if (!exited && !timed_out && now >= deadline) {
            timed_out = true;
            term_at = now;
            ::kill(-pid, SIGTERM);
        }
        if (timed_out && !killed && now - term_at >= std::chrono::seconds(plan.term_grace)) {
            killed = true;
            kill_at = now;
            ::kill(-pid, SIGKILL);
        }
        if (killed && !exited && now - kill_at >= std::chrono::seconds(10)) {
            stuck = true;  // in the kernel and not coming back; stop waiting for it
            break;
        }
        if (eof) {
            ::poll(nullptr, 0, 50);
            continue;
        }
        struct pollfd p {out[0], POLLIN, 0};
        if (::poll(&p, 1, 100) > 0) {
            for (;;) {
                const ssize_t n = ::read(out[0], buf, sizeof buf);
                if (n > 0) {
                    cap.add(buf, static_cast<std::size_t>(n));
                    continue;
                }
                if (n == 0) eof = true;
                break;
            }
        }
    }
    ::kill(-pid, SIGKILL);  // whatever the program started in its group
    ::close(out[0]);
    int status = 0;
    const bool reaped = ::waitpid(pid, &status, stuck ? WNOHANG : 0) == pid;
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - started).count();
    r.set("timed_out", timed_out).set("duration_ms", static_cast<double>(ms));
    if (reaped && WIFEXITED(status)) r.set("exit", WEXITSTATUS(status));
    else if (reaped && WIFSIGNALED(status)) r.set("signal", WTERMSIG(status));
    else r.set("exit", json::Value(nullptr));
    r.set("output", clean_text(cap.text())).set("output_bytes", static_cast<double>(cap.total())).set("truncated", cap.truncated());
    return r;
}

namespace {

// Opens `rel` (a cleaned relative directory path, "" for the root itself) below `root_fd`,
// never through a symlink; -1 when a component is missing, a symlink or not a directory.
int open_below(int root_fd, const std::string& rel) {
    int cur = ::dup(root_fd);
    std::size_t pos = 0;
    while (cur >= 0 && pos < rel.size()) {
        const std::size_t slash = rel.find('/', pos);
        const std::string part = rel.substr(pos, slash == std::string::npos ? std::string::npos : slash - pos);
        pos = slash == std::string::npos ? rel.size() : slash + 1;
        if (part.empty() || part == "." || part == "..") {
            ::close(cur);
            return -1;
        }
        const int next = ::openat(cur, part.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        ::close(cur);
        cur = next;
    }
    return cur;
}

void split(const std::string& rel, std::string& dir, std::string& leaf) {
    const std::size_t slash = rel.rfind('/');
    dir = slash == std::string::npos ? "" : rel.substr(0, slash);
    leaf = slash == std::string::npos ? rel : rel.substr(slash + 1);
}

// "*.sqlite3" and ".env.*": one '*', anything (and nothing) in its place.
bool matches(std::string_view name, std::string_view pattern) {
    const std::size_t star = pattern.find('*');
    if (star == std::string_view::npos) return name == pattern;
    const std::string_view pre = pattern.substr(0, star), post = pattern.substr(star + 1);
    return name.size() >= pre.size() + post.size() && name.substr(0, pre.size()) == pre && name.substr(name.size() - post.size()) == post;
}

}  // namespace

json::Value sweep(int root_fd, const std::string& root, const std::vector<std::string>& secrets, const std::vector<const char*>& patterns) {
    json::Value secured = json::Value::array(), exposed = json::Value::array();
    const uid_t me = ::geteuid();
    auto one = [&](int dir_fd, const std::string& dir, const std::string& name) {
        const std::string rel = dir.empty() ? name : dir + "/" + name;
        struct stat st {};
        if (::fstatat(dir_fd, name.c_str(), &st, AT_SYMLINK_NOFOLLOW) != 0) return;  // not there: nothing to secure
        if (S_ISLNK(st.st_mode) || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode))) return;  // never followed
        if (st.st_uid != me) {
            exposed.push(root + "/" + rel + " belongs to " + account_name(st.st_uid) + ", not to " + account_name(me));
            return;
        }
        const unsigned want = S_ISDIR(st.st_mode) ? secret_dir_mode(st.st_mode & 07777) : 0600u;
        if ((st.st_mode & 07777) == want) return;
        const int f = ::openat(dir_fd, name.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        struct stat fs {};
        if (f < 0 || ::fstat(f, &fs) != 0 || fs.st_ino != st.st_ino || fs.st_dev != st.st_dev || ::fchmod(f, want) != 0) {
            exposed.push(root + "/" + rel + ": " + (f < 0 ? std::strerror(errno) : "changed while it was secured"));
            if (f >= 0) ::close(f);
            return;
        }
        ::close(f);
        secured.push(root + "/" + rel);
    };
    for (const auto& s : secrets) {
        std::string dir, leaf;
        split(s, dir, leaf);
        const int d = open_below(root_fd, dir);
        if (d < 0) continue;
        one(d, dir, leaf);
        ::close(d);
    }
    for (const char* p : patterns) {
        std::string dir, leaf;
        split(p, dir, leaf);
        const int d = open_below(root_fd, dir);
        if (d < 0) continue;
        if (leaf.find('*') == std::string::npos) {
            one(d, dir, leaf);
        } else if (const int dd = ::dup(d); dd >= 0) {
            std::vector<std::string> found;
            if (DIR* listing = ::fdopendir(dd)) {
                while (const struct dirent* e = ::readdir(listing)) {
                    const std::string_view n = e->d_name;
                    if (n != "." && n != ".." && matches(n, leaf)) found.emplace_back(n);
                }
                ::closedir(listing);
            } else {
                ::close(dd);
            }
            for (const auto& n : found) one(d, dir, n);
        }
        ::close(d);
    }
    return json::Value::object().set("secured", std::move(secured)).set("exposed", std::move(exposed));
}

namespace {

json::Value refusal(std::string why) { return json::Value::object().set("ok", false).set("error", std::move(why)); }

// A directory of this account: kept when it is one, created 0700 when missing and
// `create`; false with why otherwise. Never through a symlink.
bool own_dir(const std::string& path, bool create, bool& would_create, std::string& why) {
    struct stat st {};
    if (::lstat(path.c_str(), &st) != 0) {
        if (errno != ENOENT) {
            why = path + ": " + std::strerror(errno);
            return false;
        }
        if (!create) {
            would_create = true;
            return true;
        }
        if (::mkdir(path.c_str(), 0700) != 0) {
            why = path + " does not exist and " + account_name(::geteuid()) + " cannot create it (" + std::strerror(errno) + ")";
            return false;
        }
        return true;
    }
    if (!S_ISDIR(st.st_mode)) {
        why = path + " is not a directory (or is a symlink); refused";
        return false;
    }
    if (st.st_uid != ::geteuid()) {
        why = path + " belongs to " + account_name(st.st_uid) + ", not to " + account_name(::geteuid()) + "; refused";
        return false;
    }
    return true;
}

}  // namespace

json::Value execute(const Request& req) {
    if (!req.row) return refusal("no task");
    const Row& row = *req.row;
    const uid_t me = ::geteuid();
    if (me == 0) return refusal("refusing to run a task as root");
    const std::string account = account_name(me);
    if (std::string bad = check_params(row, req.params); !bad.empty()) return refusal(bad);
    if (row.network && !req.network_allowed)
        return refusal("task " + std::string(row.name) + " downloads, and downloads by tasks are off on this server ([control] task_network = false)");
    // The site's directory: opened without following a symlink, and this account's.
    const int root_fd = ::open(req.ctx.root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root_fd < 0)
        return refusal("site directory " + req.ctx.root + ": " + (errno == ELOOP || errno == ENOTDIR ? std::string("a symlink or not a directory; refused") : std::strerror(errno)));
    struct stat st {};
    if (::fstat(root_fd, &st) != 0 || st.st_uid != me) {
        ::close(root_fd);
        return refusal("site directory " + req.ctx.root + " belongs to " + account_name(st.st_uid) + ", not to the account running the task (" + account + "); refused");
    }
    if (row.needs_empty) {
        const int dd = ::dup(root_fd);
        std::string first;
        std::size_t count = 0;
        if (DIR* d = dd >= 0 ? ::fdopendir(dd) : nullptr) {
            while (const struct dirent* e = ::readdir(d)) {
                const std::string_view n = e->d_name;
                if (n == "." || n == "..") continue;
                if (first.empty()) first = n;
                ++count;
            }
            ::closedir(d);
        } else if (dd >= 0) {
            ::close(dd);
        }
        if (count) {
            ::close(root_fd);
            return refusal(std::string(row.name) + " creates the application in an empty directory, and " + req.ctx.root + " holds " + std::to_string(count) +
                           " entr" + (count == 1 ? "y" : "ies") + " (" + first + (count > 1 ? ", ..." : "") + "); nothing ran");
        }
    }
    // The account's home and its tmp/: made by the helper (as root) when this account could
    // not; made here when it can (a server without the helper, in its own state directory).
    bool would_create = false;
    std::string why;
    for (const std::string& d : {req.ctx.home, req.ctx.home + "/tmp"})
        if (!own_dir(d, !req.dry_run, would_create, why)) {
            ::close(root_fd);
            return refusal("the account's home: " + why);
        }
    // The interpreter: root's alone, or nothing runs.
    std::string program;
    bool missing = false;
    const std::string configured = req.ctx.runtime_dir + "/" + row.program;
    if (std::string bad = trusted_program(configured, req.sites_root, program, missing); !bad.empty()) {
        ::close(root_fd);
        json::Value f = refusal("the " + std::string(row.runtime) + " runtime: " + bad);
        f.set("hint", "the interpreter comes from [control] runtimes in root's configuration file (" + std::string(row.runtime) + " = \"" + req.ctx.runtime_dir +
                          "\"); agensio never runs one a site could have written");
        if (missing)
            if (const std::string cmd = install_hint(row.runtime); !cmd.empty()) f.set("run_as_root", cmd);
        return f;
    }
    const Plan plan = build(row, req.params, req.ctx, program);
    json::Value argv = json::Value::array(), env = json::Value::array();
    for (const auto& a : plan.argv) argv.push(a);
    for (const auto& e : plan.env) env.push(e);
    json::Value r = json::Value::object().set("task", row.name).set("as", account).set("cwd", plan.cwd).set("argv", std::move(argv)).set("env", std::move(env))
                        .set("network", row.network)
                        .set("limits", json::Value::object().set("timeout", static_cast<double>(plan.timeout)).set("processes", static_cast<double>(plan.processes))
                                           .set("open_files", static_cast<double>(plan.open_files)));
    if (req.dry_run) {
        ::close(root_fd);
        json::Value wc = json::Value::array();
        if (would_create) {
            wc.push(req.ctx.home);
            wc.push(req.ctx.home + "/tmp");
        }
        return r.set("ok", true).set("dry_run", true).set("would_create", std::move(wc));
    }
    json::Value result = run(plan, root_fd);
    if (!result["error"].is_null()) {
        ::close(root_fd);
        return refusal(std::string(result.get("error")));
    }
    for (const auto& m : result.members()) r.set(m.first, m.second);
    r.set("ran", true);
    const Family* fam = family(row.app);
    const json::Value swept = sweep(root_fd, req.ctx.root, req.secrets, fam ? fam->secret_patterns : std::vector<const char*>{});
    ::close(root_fd);
    r.set("secured", swept["secured"]).set("exposed", swept["exposed"]);
    const bool timed_out = result["timed_out"].boolean();
    const json::Value& exit = result["exit"];
    const bool clean = exit.type() == json::Value::Type::number && exit.num() == 0;
    const bool ok = clean && !timed_out && swept["exposed"].items().empty();
    r.set("ok", ok);
    if (!ok) {
        std::string what;
        if (timed_out) what = "stopped after its time limit of " + std::to_string(plan.timeout) + " s ([control] task_limits.timeout)";
        else if (!result["signal"].is_null()) what = "killed by signal " + std::to_string(static_cast<int>(result["signal"].num()));
        else if (!clean) what = exit.is_null() ? "did not end after SIGKILL" : "exited with status " + std::to_string(static_cast<int>(exit.num()));
        else what = "ran, but credential files could not be made private: " + swept["exposed"].items().front().str();
        r.set("error", "task " + std::string(row.name) + " " + what + "; the output says why");
    }
    return r;
}

#else
std::string trusted_program(const std::string&, const std::string&, std::string&, bool& missing) {
    missing = false;
    return "not available on this platform";
}
json::Value run(const Plan&, int) { return json::Value::object().set("error", "not available on this platform"); }
json::Value sweep(int, const std::string&, const std::vector<std::string>&, const std::vector<const char*>&) {
    return json::Value::object().set("secured", json::Value::array()).set("exposed", json::Value::array());
}
json::Value execute(const Request&) { return json::Value::object().set("ok", false).set("error", "not available on this platform"); }
#endif

}  // namespace agensio::tasks
