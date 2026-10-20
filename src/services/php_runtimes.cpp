#include "services/php_runtimes.hpp"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "config.hpp"

namespace agensio::php {

namespace fs = std::filesystem;

namespace {

bool digits(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); });
}

// "8.4" from "8.4", "84" or "8.4.24": major and minor, or "" when it is no version.
std::string major_minor(std::string_view v) {
    if (const std::size_t dot = v.find('.'); dot != std::string_view::npos) {
        const std::size_t second = v.find('.', dot + 1);
        const std::string_view major = v.substr(0, dot), minor = v.substr(dot + 1, second == std::string_view::npos ? std::string_view::npos : second - dot - 1);
        return digits(major) && digits(minor) ? std::string(major) + "." + std::string(minor) : std::string();
    }
    return v.size() == 2 && digits(v) ? std::string(1, v[0]) + "." + std::string(1, v[1]) : std::string();
}

// Versions compared as numbers: "8.10" after "8.9".
bool older(const std::string& a, const std::string& b) {
    auto parts = [](const std::string& v) {
        const std::size_t dot = v.find('.');
        return std::pair{std::atoi(v.substr(0, dot).c_str()), dot == std::string::npos ? 0 : std::atoi(v.substr(dot + 1).c_str())};
    };
    return parts(a) < parts(b);
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// Each line of a program's output.
template <typename F>
void lines(std::string_view text, F&& each) {
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        each(text.substr(0, nl));
        if (nl == std::string_view::npos) break;
        text.remove_prefix(nl + 1);
    }
}

}  // namespace

Fs system_fs() {
    Fs f;
    f.is_file = [](const std::string& p) {
        std::error_code ec;
        return fs::is_regular_file(p, ec);
    };
    f.is_dir = [](const std::string& p) {
        std::error_code ec;
        return fs::is_directory(p, ec);
    };
    f.list = [](const std::string& dir) {
        std::vector<std::string> out;
        std::error_code ec;
        for (const auto& e : fs::directory_iterator(dir, ec)) out.push_back(e.path().filename().string());
        return out;
    };
    return f;
}

std::vector<Runtime> discover(const Config& cfg, const Fs& f) {
    std::map<std::string, Runtime, decltype(&older)> found(&older);
    auto add = [&](Runtime r) {
        if (r.version.empty() || !f.is_file(r.fpm) || !f.is_file(r.conf)) return;
        found.try_emplace(r.version, std::move(r));  // the first layout of a version wins
    };
    // Debian and Ubuntu: /etc/php/8.4/fpm/{php-fpm.conf,pool.d}, /usr/sbin/php-fpm8.4, php8.4-fpm.
    for (const std::string& v : f.list("/etc/php")) {
        const std::string mm = major_minor(v);
        if (mm != v) continue;
        add({mm, "/usr/sbin/php-fpm" + mm, "/etc/php/" + mm + "/fpm/php-fpm.conf", "/etc/php/" + mm + "/fpm/pool.d", "php" + mm + "-fpm",
             f.is_file("/usr/bin/php" + mm) ? "/usr/bin/php" + mm : std::string(), false});
    }
    // RHEL with Remi's repository: /etc/opt/remi/php85/php-fpm.conf, /opt/remi/php85/root/usr/sbin/php-fpm.
    for (const std::string& n : f.list("/etc/opt/remi")) {
        if (!n.starts_with("php")) continue;
        const std::string mm = major_minor(std::string_view(n).substr(3));
        if (mm.empty()) continue;
        add({mm, "/opt/remi/" + n + "/root/usr/sbin/php-fpm", "/etc/opt/remi/" + n + "/php-fpm.conf", "/etc/opt/remi/" + n + "/php-fpm.d",
             n + "-php-fpm", f.is_file("/opt/remi/" + n + "/root/usr/bin/php") ? "/opt/remi/" + n + "/root/usr/bin/php" : std::string(), false});
    }
    // Alpine: /etc/php84/php-fpm.conf, /usr/sbin/php-fpm84 (OpenRC, so no systemd unit).
    for (const std::string& n : f.list("/etc")) {
        if (!n.starts_with("php") || n.size() != 5) continue;
        const std::string mm = major_minor(std::string_view(n).substr(3));
        if (mm.empty()) continue;
        add({mm, "/usr/sbin/php-fpm" + n.substr(3), "/etc/" + n + "/php-fpm.conf", "/etc/" + n + "/php-fpm.d", "",
             f.is_file("/usr/bin/" + n) ? "/usr/bin/" + n : std::string(), false});
    }
    // Homebrew: <prefix>/etc/php/8.4/php-fpm.conf, <prefix>/opt/php@8.4/sbin/php-fpm (brew services).
    for (const char* prefix : {"/opt/homebrew", "/usr/local"}) {
        const std::string base = std::string(prefix) + "/etc/php";
        for (const std::string& v : f.list(base)) {
            const std::string mm = major_minor(v);
            if (mm != v) continue;
            const std::string opt = std::string(prefix) + "/opt/php@" + mm;
            add({mm, opt + "/sbin/php-fpm", base + "/" + mm + "/php-fpm.conf", base + "/" + mm + "/php-fpm.d", "",
                 f.is_file(opt + "/bin/php") ? opt + "/bin/php" : std::string(), false});
        }
    }
    std::vector<Runtime> out;
    for (auto& [v, r] : found) out.push_back(std::move(r));
    // Root's own (a build under /opt, a second instance for the tests) replace a discovered one.
    for (const auto& c : cfg.php_runtimes) {
        Runtime r{c.version, c.fpm, c.conf, c.pools, c.unit, c.cli, true};
        auto it = std::find_if(out.begin(), out.end(), [&](const Runtime& x) { return x.version == c.version; });
        if (it != out.end()) *it = std::move(r);
        else out.push_back(std::move(r));
    }
    std::sort(out.begin(), out.end(), [](const Runtime& a, const Runtime& b) { return older(a.version, b.version); });
    return out;
}

const Runtime* find(const std::vector<Runtime>& runtimes, std::string_view version) {
    for (const auto& r : runtimes)
        if (r.version == version) return &r;
    return nullptr;
}

std::string pid_file(std::string_view conf_text) {
    bool global = true;  // before any section: php-fpm reads it as [global]
    std::string found;
    lines(conf_text, [&](std::string_view line) {
        const std::size_t a = line.find_first_not_of(" \t");
        if (a == std::string_view::npos) return;
        line.remove_prefix(a);
        if (line.front() == ';' || line.front() == '#') return;
        if (line.front() == '[') {
            global = line.starts_with("[global]");
            return;
        }
        if (!global || !line.starts_with("pid")) return;
        std::string_view rest = line.substr(3);
        rest.remove_prefix(std::min(rest.find_first_not_of(" \t"), rest.size()));
        if (rest.empty() || rest.front() != '=') return;
        rest.remove_prefix(1);
        rest.remove_prefix(std::min(rest.find_first_not_of(" \t"), rest.size()));
        rest = rest.substr(0, rest.find_first_of(" \t;\r"));
        found = std::string(rest);
    });
    if (found.empty() || found.front() != '/' || found.find("/../") != std::string::npos || found.ends_with("/..")) return {};
    return found;
}

bool master_running(const Runtime& r) {
    std::ifstream conf(r.conf);
    const std::string file = pid_file(std::string((std::istreambuf_iterator<char>(conf)), {}));
    if (file.empty()) return false;
    std::ifstream pf(file);
    long pid = 0;
    if (!(pf >> pid) || pid <= 1) return false;
    std::ifstream cmd("/proc/" + std::to_string(pid) + "/cmdline");
    std::string title;
    std::getline(cmd, title, '\0');
    return title.starts_with("php-fpm: master process");
}

std::string parse_version(std::string_view v_output) {
    // "PHP 8.4.24 (fpm-fcgi) (built: ...)"
    const std::size_t at = v_output.find("PHP ");
    if (at == std::string_view::npos) return {};
    std::string_view rest = v_output.substr(at + 4);
    const std::size_t end = rest.find_first_not_of("0123456789.");
    rest = rest.substr(0, end);
    return major_minor(rest).empty() ? std::string() : std::string(rest);
}

std::vector<std::string> parse_modules(std::string_view m_output) {
    std::vector<std::string> out;
    lines(m_output, [&](std::string_view line) {
        line = trim(line);
        if (line.empty() || line.front() == '[') return;  // [PHP Modules], [Zend Modules]
        std::string name = lower(line);
        if (std::find(out.begin(), out.end(), name) == out.end()) out.push_back(std::move(name));
    });
    std::sort(out.begin(), out.end());
    return out;
}

std::string ini_value(std::string_view i_output, std::string_view name) {
    std::string value;
    lines(i_output, [&](std::string_view line) {
        if (!value.empty() || !line.starts_with(name)) return;
        std::string_view rest = line.substr(name.size());
        if (!rest.starts_with(" => ")) return;
        rest.remove_prefix(4);
        const std::size_t next = rest.find(" => ");
        value = std::string(trim(rest.substr(0, next)));
    });
    return value;
}

void parse_fpm_test(std::string_view tt_output, Facts& f) {
    f.tested = true;
    lines(tt_output, [&](std::string_view line) {
        // "[20-Oct-2026 18:05:12] NOTICE: \tprocess_control_timeout = 0s"
        if (const std::size_t k = line.find("process_control_timeout = "); k != std::string_view::npos && f.control_timeout.empty())
            f.control_timeout = std::string(trim(line.substr(k + 26)));
        if (line.find("test is successful") != std::string_view::npos) f.config_ok = true;
        if (const std::size_t e = line.find("ERROR: "); e != std::string_view::npos) {
            if (!f.config_error.empty()) f.config_error += "; ";
            f.config_error += std::string(trim(line.substr(e + 7)));
        }
    });
    if (!f.config_error.empty()) f.config_ok = false;
}

Facts gather(const Runtime& r, const Exec& exec, bool as_root, const std::string& systemctl) {
    Facts f;
    std::string out;
    if (exec(r.fpm, {"-v"}, out) != 0) {
        f.error = r.fpm + " -v failed: " + std::string(trim(out.substr(0, 200)));
        return f;
    }
    f.exact = parse_version(out);
    out.clear();
    if (exec(r.fpm, {"-m"}, out) == 0) f.modules = parse_modules(out);
    out.clear();
    if (exec(r.fpm, {"-i"}, out) == 0) {
        const std::string on = lower(ini_value(out, "opcache.enable"));
        f.opcache = on == "on" || on == "1";
        f.opcache_memory = ini_value(out, "opcache.memory_consumption");
        const std::string vp = lower(ini_value(out, "opcache.validate_permission"));
        f.validate_permission = vp == "on" || vp == "1";
    }
    if (as_root) {  // the test opens php-fpm's own log, which only root may
        out.clear();
        (void)exec(r.fpm, {"-tt", "-y", r.conf}, out);
        parse_fpm_test(out, f);
    }
    if (!systemctl.empty() && !r.unit.empty()) {
        out.clear();
        if (exec(systemctl, {"show", r.unit + ".service", "--property=ActiveState,UnitFileState"}, out) == 0)
            lines(out, [&](std::string_view line) {
                if (line.starts_with("ActiveState=")) f.unit_active = std::string(trim(line.substr(12)));
                else if (line.starts_with("UnitFileState=")) f.unit_enabled = std::string(trim(line.substr(14)));
            });
    }
    return f;
}

std::string unit_state(const Runtime& r, const Exec& exec, const std::string& systemctl) {
    if (systemctl.empty() || r.unit.empty()) return {};
    std::string out, state;
    if (exec(systemctl, {"show", r.unit + ".service", "--property=ActiveState"}, out) != 0) return {};
    lines(out, [&](std::string_view line) {
        if (line.starts_with("ActiveState=")) state = std::string(trim(line.substr(12)));
    });
    return state;
}

std::string first_program(std::initializer_list<const char*> candidates) {
#ifndef _WIN32
    for (const char* c : candidates)
        if (::access(c, X_OK) == 0) return c;
#else
    (void)candidates;
#endif
    return {};
}

Loaded loaded(const Runtime& r, const Exec& exec) {
    Loaded l;
    std::string out;
    if (exec(r.fpm, {"-v"}, out) != 0) return l;
    l.exact = parse_version(out);
    out.clear();
    if (exec(r.fpm, {"-m"}, out) != 0) return l;
    l.modules = parse_modules(out);
    l.known = !l.exact.empty() && !l.modules.empty();
    return l;
}

Declared declared_on_disk(const std::vector<std::string>& dirs) {
    auto read = [](const std::string& path) {
        std::string text;
#ifndef _WIN32
        const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) return text;
        struct stat st {};
        if (::fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size <= 512 * 1024) {
            char buf[16384];
            for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) > 0 && text.size() <= 512 * 1024;) text.append(buf, static_cast<std::size_t>(n));
        }
        ::close(fd);
#else
        (void)path;
#endif
        return text;
    };
    // The first composer.json that declares something: the project's, the served root's, Drupal's
    // core/composer.json (its project's declares no PHP).
    std::string composer, wp;
    for (const auto& d : dirs)
        for (const char* rel : {"/composer.json", "/core/composer.json"}) {
            if (!composer.empty()) break;
            std::string text = read(d + rel);
            if (const Declared c = parse_composer(text); !c.php.empty() || !c.ext.empty()) composer = std::move(text);
        }
    for (const auto& d : dirs)
        if (wp.empty()) wp = read(d + "/wp-includes/version.php");
    return declared_from(composer, wp);
}

std::string systemctl() {
    std::error_code ec;
    if (!fs::is_directory("/run/systemd/system", ec)) return {};
    return first_program({"/usr/bin/systemctl", "/bin/systemctl"});
}

Exec system_exec() {
    return [](const std::string& path, const std::vector<std::string>& args, std::string& out) -> int {
#ifdef _WIN32
        (void)path;
        (void)args;
        out = "not supported on Windows";
        return -1;
#else
        // Everything the child needs is built before fork: in a threaded process it may only make
        // async-signal-safe calls until execve.
        std::vector<char*> argv;
        argv.push_back(const_cast<char*>(path.c_str()));
        for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
        argv.push_back(nullptr);
        static const char* const env[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C", nullptr};
        int pipefd[2];
        if (::pipe2(pipefd, O_CLOEXEC) != 0) {
            out = std::strerror(errno);
            return -1;
        }
        const int devnull = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        const pid_t pid = ::fork();
        if (pid < 0) {
            out = std::strerror(errno);
            ::close(pipefd[0]);
            ::close(pipefd[1]);
            if (devnull >= 0) ::close(devnull);
            return -1;
        }
        if (pid == 0) {
            if (devnull >= 0) ::dup2(devnull, 0);
            ::dup2(pipefd[1], 1);
            ::dup2(pipefd[1], 2);
            ::execve(argv[0], argv.data(), const_cast<char* const*>(env));
            ::_exit(127);
        }
        ::close(pipefd[1]);
        if (devnull >= 0) ::close(devnull);
        char buf[4096];
        for (;;) {
            const ssize_t n = ::read(pipefd[0], buf, sizeof buf);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            if (out.size() < 512 * 1024) out.append(buf, static_cast<std::size_t>(n));
        }
        ::close(pipefd[0]);
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    };
}

const std::vector<Release>& releases() {
    // php.net/supported-versions.php and /eol.php, checked 2026-10-20. The branches past their end
    // of life are listed with that date alone (their active support ended before it).
    static const std::vector<Release> table = {
        {"7.0", "", "2019-01-10"}, {"7.1", "", "2019-12-01"}, {"7.2", "", "2020-11-30"}, {"7.3", "", "2021-12-06"},
        {"7.4", "", "2022-11-28"}, {"8.0", "", "2023-11-26"}, {"8.1", "", "2025-12-31"},
        {"8.2", "2024-12-31", "2026-12-31"}, {"8.3", "2025-12-31", "2027-12-31"}, {"8.4", "2026-12-31", "2028-12-31"},
        {"8.5", "2027-12-31", "2029-12-31"},
    };
    return table;
}

const Release* release(std::string_view version) {
    for (const auto& r : releases())
        if (version == r.version) return &r;
    return nullptr;
}

std::string support_status(std::string_view version, std::time_t now) {
    const Release* r = release(version);
    if (!r) {
        const std::string mm = major_minor(version);
        // Newer than the table: a release after it was written, supported; older: long gone.
        return !mm.empty() && older(releases().back().version, mm) ? "unknown" : "eol";
    }
    char today[11];
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &now);
#else
    gmtime_r(&now, &tm);
#endif
    std::strftime(today, sizeof today, "%Y-%m-%d", &tm);
    if (std::string_view(today) > r->security_until) return "eol";
    if (*r->active_until && std::string_view(today) <= r->active_until) return "active";
    return "security";
}

std::string apt_candidate(std::string_view policy_output) {
    std::string candidate;
    lines(policy_output, [&](std::string_view line) {
        line = trim(line);
        if (candidate.empty() && line.starts_with("Candidate:")) {
            const std::string_view v = trim(line.substr(10));
            if (v != "(none)") candidate = std::string(v);
        }
    });
    return candidate;
}

std::vector<std::string> installable(const Exec& exec, const std::vector<Runtime>& installed, const std::string& apt_cache) {
    std::vector<std::string> out;
    if (apt_cache.empty()) return out;
    for (const auto& r : releases()) {
        if (find(installed, r.version)) continue;
        std::string policy;
        if (exec(apt_cache, {"policy", std::string("php") + r.version + "-fpm"}, policy) == 0 && !apt_candidate(policy).empty())
            out.push_back(r.version);
    }
    return out;
}

}  // namespace agensio::php
