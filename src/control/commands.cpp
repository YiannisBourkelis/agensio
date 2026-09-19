#include "control/commands.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

#include "services/acme.hpp"
#include "services/pools.hpp"

namespace agensio::control {

namespace fs = std::filesystem;

namespace {

int month_of(std::string_view m) {
    static const char* names[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i)
        if (m == names[i]) return i;
    return -1;
}

bool digits(std::string_view s, std::size_t pos, std::size_t n, int& out) {
    if (pos + n > s.size()) return false;
    out = 0;
    for (std::size_t i = 0; i < n; ++i) {
        const char c = s[pos + i];
        if (c < '0' || c > '9') return false;
        out = out * 10 + (c - '0');
    }
    return true;
}

std::time_t local_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
    tm.tm_isdst = -1;
    return std::mktime(&tm);
}

std::time_t utc_to_time(int y, int mo, int d, int h, int mi, int s) {
    std::tm tm{};
    tm.tm_year = y - 1900;
    tm.tm_mon = mo;
    tm.tm_mday = d;
    tm.tm_hour = h;
    tm.tm_min = mi;
    tm.tm_sec = s;
#ifdef _WIN32
    return _mkgmtime(&tm);
#else
    return timegm(&tm);
#endif
}

// "+0300" or "+03:00" -> seconds east of UTC.
bool zone_offset(std::string_view z, long& out) {
    if (z.size() < 5 || (z[0] != '+' && z[0] != '-')) return false;
    int h = 0, m = 0;
    if (!digits(z, 1, 2, h)) return false;
    const std::size_t mpos = z[3] == ':' ? 4 : 3;
    if (!digits(z, mpos, 2, m)) return false;
    out = (h * 3600 + m * 60) * (z[0] == '-' ? -1 : 1);
    return true;
}

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

}  // namespace

// ---- log lines ----

bool parse_log_line(std::string_view line, LogLine& out) {
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    if (line.empty()) return false;
    out = LogLine{};
    out.text = std::string(line);
    int y, mo, d, h, mi, s;
    // Error log: "2026/09/18 21:44:39 [warn] message"
    if (line.size() > 22 && line[4] == '/' && line[7] == '/' && line[10] == ' ' && line[13] == ':' && line[16] == ':' &&
        digits(line, 0, 4, y) && digits(line, 5, 2, mo) && digits(line, 8, 2, d) && digits(line, 11, 2, h) &&
        digits(line, 14, 2, mi) && digits(line, 17, 2, s) && line.substr(20, 1) == "[") {
        const std::size_t close = line.find(']', 21);
        if (close == std::string_view::npos) return false;
        out.time = local_to_time(y, mo - 1, d, h, mi, s);
        out.level = std::string(line.substr(21, close - 21));
        out.source = "error";
        return true;
    }
    // JSON access log: {"time":"2026-09-18T21:44:39+03:00",...,"status":404,...}
    if (line.front() == '{') {
        json::Value v;
        std::string err;
        if (!json::parse(line, v, err)) return false;
        const std::string_view t = v.get("time");
        long off = 0;
        if (t.size() < 19 || !digits(t, 0, 4, y) || !digits(t, 5, 2, mo) || !digits(t, 8, 2, d) ||
            !digits(t, 11, 2, h) || !digits(t, 14, 2, mi) || !digits(t, 17, 2, s) || !zone_offset(t.substr(19), off))
            return false;
        out.time = utc_to_time(y, mo - 1, d, h, mi, s) - off;
        out.status = static_cast<int>(v["status"].num());
        return true;
    }
    // Combined: remote - - [18/Sep/2026:21:44:39 +0300] "GET / HTTP/1.1" 404 153 "-" "-"
    const std::size_t open = line.find(" [");
    if (open == std::string_view::npos) return false;
    const std::string_view stamp = line.substr(open + 2);
    long off = 0;
    if (stamp.size() < 26 || !digits(stamp, 0, 2, d) || stamp[2] != '/' || stamp[6] != '/' || !digits(stamp, 7, 4, y) ||
        !digits(stamp, 12, 2, h) || !digits(stamp, 15, 2, mi) || !digits(stamp, 18, 2, s) ||
        (mo = month_of(stamp.substr(3, 3))) < 0 || !zone_offset(stamp.substr(21, 5), off))
        return false;
    out.time = utc_to_time(y, mo, d, h, mi, s) - off;
    // The status is the first number after the closing quote of the request.
    const std::size_t q1 = line.find('"', open);
    const std::size_t q2 = q1 == std::string_view::npos ? q1 : line.find('"', q1 + 1);
    if (q2 == std::string_view::npos || q2 + 2 >= line.size() || !digits(line, q2 + 2, 3, out.status)) return false;
    return true;
}

bool parse_since(std::string_view text, std::time_t now, std::time_t& out) {
    if (text.empty()) return false;
    if (text.size() >= 19 && text[4] == '-' && text[10] == 'T') {
        int y, mo, d, h, mi, s;
        if (!digits(text, 0, 4, y) || !digits(text, 5, 2, mo) || !digits(text, 8, 2, d) || !digits(text, 11, 2, h) ||
            !digits(text, 14, 2, mi) || !digits(text, 17, 2, s))
            return false;
        out = local_to_time(y, mo - 1, d, h, mi, s);
        return true;
    }
    long n = 0;
    std::size_t i = 0;
    for (; i < text.size() && text[i] >= '0' && text[i] <= '9'; ++i) n = n * 10 + (text[i] - '0');
    if (i == 0) return false;
    long unit = 1;
    if (i < text.size()) {
        if (i + 1 != text.size()) return false;
        switch (text[i]) {
            case 's': unit = 1; break;
            case 'm': unit = 60; break;
            case 'h': unit = 3600; break;
            case 'd': unit = 86400; break;
            case 'w': unit = 7 * 86400; break;
            default: return false;
        }
    }
    out = now - n * unit;
    return true;
}

void scan_log(const fs::path& file, std::string_view source, const LogQuery& q, std::vector<LogLine>& out,
              bool& truncated) {
    std::ifstream in(file, std::ios::binary);
    if (!in) return;
    in.seekg(0, std::ios::end);
    const std::streamoff size = in.tellg();
    std::streamoff start = 0;
    if (size > static_cast<std::streamoff>(q.max_bytes)) {
        start = size - static_cast<std::streamoff>(q.max_bytes);
        truncated = true;
    }
    in.seekg(start);
    std::string buf(static_cast<std::size_t>(size - start), '\0');
    in.read(buf.data(), static_cast<std::streamsize>(buf.size()));
    buf.resize(static_cast<std::size_t>(in.gcount()));
    std::size_t end = buf.size();
    if (start > 0) {  // drop the partial first line
        const std::size_t nl = buf.find('\n');
        if (nl == std::string::npos) return;
        buf.erase(0, nl + 1);
        end = buf.size();
    }
    std::vector<LogLine> found;
    int older = 0;
    while (end > 0 && found.size() < q.limit) {
        if (buf[end - 1] == '\n') {  // the terminator of the line before
            --end;
            continue;
        }
        const std::size_t nl = buf.rfind('\n', end - 1);
        const std::size_t begin = nl == std::string::npos ? 0 : nl + 1;
        const std::string_view line(buf.data() + begin, end - begin);
        end = begin;
        LogLine l;
        if (line.empty() || !parse_log_line(line, l)) continue;
        if (q.since && l.time < q.since) {  // buffers of several workers may interleave a little
            if (++older > 50) break;
            continue;
        }
        older = 0;
        if (l.source == "error") {
            const bool keep = q.level == "info" || l.level == "error" || (q.level != "error" && l.level == "warn");
            if (!keep) continue;
        } else {
            l.source = std::string(source);
            if (l.status < q.status_min) continue;
        }
        found.push_back(std::move(l));
    }
    std::reverse(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
}

json::Value logs(const Config& cfg, const LogQuery& q) {
    std::vector<LogLine> lines;
    bool truncated = false;
    json::Value files = json::Value::array();
    std::vector<std::string> seen;
    auto scan = [&](const std::string& path, std::string_view source) {
        if (path.empty() || path == "stderr" || path == "off") return;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) return;
        seen.push_back(path);
        files.push(path);
        scan_log(path, source, q, lines, truncated);
    };
    if (q.site.empty()) {
        scan(cfg.log.error, "error");
        for (const auto& s : cfg.sites) scan(s.access_log, s.server_names.front());
    } else {
        const SiteConfig* s = find_site(cfg, q.site);
        if (s) {
            scan(s->access_log, s->server_names.front());
            // The error log's lines about this site name.
            std::vector<LogLine> err;
            if (!cfg.log.error.empty() && cfg.log.error != "stderr") {
                files.push(cfg.log.error);
                scan_log(cfg.log.error, "error", q, err, truncated);
            }
            for (auto& l : err)
                if (l.text.find(s->server_names.front()) != std::string::npos) lines.push_back(std::move(l));
        }
    }
    std::stable_sort(lines.begin(), lines.end(), [](const LogLine& a, const LogLine& b) { return a.time < b.time; });
    if (lines.size() > q.limit) lines.erase(lines.begin(), lines.end() - static_cast<std::ptrdiff_t>(q.limit));
    json::Value out = json::Value::object();
    out.set("files", std::move(files));
    out.set("since", static_cast<double>(q.since));
    out.set("truncated", truncated);
    json::Value arr = json::Value::array();
    for (const auto& l : lines) {
        json::Value v = json::Value::object();
        v.set("time", static_cast<double>(l.time)).set("source", l.source);
        if (!l.level.empty()) v.set("level", l.level);
        if (l.status) v.set("status", l.status);
        v.set("text", l.text);
        arr.push(std::move(v));
    }
    out.set("count", static_cast<double>(lines.size()));
    out.set("lines", std::move(arr));
    return out;
}

// ---- sites ----

CertificateState certificate_state(const TlsConfig& tls, std::time_t now) {
    CertificateState st;
#ifdef AGENSIO_HAS_TLS
    acme::CertInfo info;
    if (!acme::certificate_info(tls.cert, info, st.error)) return st;
    st.present = true;
    st.placeholder = info.placeholder;
    st.issuer = info.issuer;
    st.names = info.names;
    st.not_after = std::chrono::system_clock::to_time_t(info.not_after);
    st.days_left = static_cast<long>((st.not_after - now) / 86400);
#else
    (void)tls;
    (void)now;
    st.error = "built without TLS";
#endif
    return st;
}

// Several sites may carry the name (the :80 redirect and the :443 site of an HTTPS-only
// setup): the one that serves content wins, then the TLS one, then the first.
const SiteConfig* find_site(const Config& cfg, std::string_view name) {
    const std::string want = lower(name);
    const SiteConfig* best = nullptr;
    int best_score = -1;
    for (const auto& s : cfg.sites)
        for (const auto& n : s.server_names)
            if (n == want) {
                const int score = (s.redirect.empty() ? 2 : 0) + (s.tls ? 1 : 0);
                if (score > best_score) {
                    best = &s;
                    best_score = score;
                }
            }
    return best;
}

namespace {

json::Value strings(const std::vector<std::string>& v) {
    json::Value a = json::Value::array();
    for (const auto& s : v) a.push(s);
    return a;
}

json::Value tls_json(const SiteConfig& s, std::time_t now) {
    json::Value t = json::Value::object();
    if (!s.tls) return t.set("mode", "none");
    t.set("mode", s.tls->automatic ? "auto" : "manual").set("cert", s.tls->cert.string()).set("key", s.tls->key.string());
    const CertificateState st = certificate_state(*s.tls, now);
    t.set("present", st.present);
    if (!st.present) return t.set("error", st.error);
    t.set("placeholder", st.placeholder).set("issuer", st.issuer).set("names", strings(st.names));
    t.set("not_after", static_cast<double>(st.not_after)).set("days_left", static_cast<double>(st.days_left));
    return t;
}

json::Value site_summary(const SiteConfig& s, std::time_t now) {
    json::Value v = json::Value::object();
    v.set("server_name", strings(s.server_names)).set("listen", strings(s.listen));
    v.set("root", s.root).set("app", s.app).set("user", s.user).set("group", s.group);
    if (!s.redirect.empty()) v.set("redirect", s.redirect);
    v.set("access_log", s.access_log);
    v.set("tls", tls_json(s, now));
    return v;
}

json::Value upstream_json(const UpstreamConfig& u) {
    json::Value a = json::Value::array();
    for (const auto& addr : u.addresses) a.push(addr.key);
    if (u.addresses.empty() && u.configured) a.push(u.address.key);
    return a;
}

}  // namespace

json::Value sites(const Config& cfg, std::time_t now) {
    json::Value arr = json::Value::array();
    for (const auto& s : cfg.sites) arr.push(site_summary(s, now));
    return json::Value::object().set("count", static_cast<double>(cfg.sites.size())).set("sites", std::move(arr));
}

json::Value site(const Config& cfg, const SiteConfig& s, std::time_t now) {
    json::Value v = site_summary(s, now);
    v.set("index", strings(s.index));
    if (s.php.configured) {
        json::Value php = json::Value::object().set("socket", s.php.address.key);
        if (s.pool.generated) php.set("pool", s.pool.name).set("state_dir", s.pool.state_dir);
        v.set("php", std::move(php));
    }
    if (s.proxy.configured) v.set("upstream", upstream_json(s.proxy));
    json::Value locs = json::Value::array();
    for (const auto& l : s.locations) {
        json::Value loc = json::Value::object().set("path", l.path);
        loc.set("match", l.exact ? "exact" : l.suffix ? "suffix" : "prefix").set("handler", l.handler);
        if (!l.origin.empty()) loc.set("from", l.origin);
        if (!l.alias.empty()) loc.set("alias", l.alias);
        else if (l.root != s.root) loc.set("root", l.root);
        if (l.kind == HandlerKind::proxy) loc.set("upstream", upstream_json(l.proxy));
        if (l.kind == HandlerKind::fastcgi) loc.set("socket", l.fastcgi.address.key);
        if (!l.add_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.add_headers) h.set(n, val);
            loc.set("add_headers", std::move(h));
        }
        locs.push(std::move(loc));
    }
    v.set("locations", std::move(locs));
    (void)cfg;
    return v;
}

// ---- validation and health ----

std::vector<std::string> restart_needed(const Config& fresh, const Config& running) {
    std::vector<std::string> out;
    if (fresh.workers != running.workers) out.push_back("workers");
    if (fresh.reuse_port != running.reuse_port) out.push_back("reuse_port");
    if (fresh.user != running.user) out.push_back("user");
    if (fresh.group != running.group) out.push_back("group");
    if (fresh.sendfile != running.sendfile) out.push_back("sendfile");
    if (fresh.cache_max_size != running.cache_max_size || fresh.cache_max_file_size != running.cache_max_file_size)
        out.push_back("cache sizes");
    if (fresh.control.enabled != running.control.enabled || fresh.control.socket != running.control.socket)
        out.push_back("control");
    return out;
}

json::Value validate(const fs::path& path, const Config& running) {
    json::Value v = json::Value::object().set("path", path.string());
    json::Value errors = json::Value::array();
    Config fresh;
    try {
        fresh = load_config(path);
    } catch (const std::exception& e) {
        errors.push(e.what());
        return v.set("ok", false).set("errors", std::move(errors));
    }
    for (const auto& e : check_hosting(fresh, system_facts())) errors.push(e);
    const bool ok = errors.items().empty();
    v.set("ok", ok).set("errors", std::move(errors)).set("sites", static_cast<double>(fresh.sites.size()));
    v.set("restart_needed", strings(restart_needed(fresh, running)));
    return v;
}

std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now) {
    std::vector<Finding> out;
    auto add = [&](std::string sev, std::string code, std::string site, std::string msg, std::string fix = "") {
        out.push_back(Finding{std::move(sev), std::move(code), std::move(site), std::move(msg), std::move(fix)});
    };
    // The file on disk.
    try {
        const Config fresh = load_config(running.config_path);
        for (const auto& e : check_hosting(fresh, system_facts()))
            add("error", "hosting_rule", "", e, "fix the ownership, then agensio -t");
        const auto restart = restart_needed(fresh, boot);
        if (!restart.empty()) {
            std::string keys;
            for (const auto& k : restart) keys += (keys.empty() ? "" : ", ") + k;
            add("warn", "restart_needed", "", "restart-only settings changed on disk: " + keys, "restart the service");
        }
    } catch (const std::exception& e) {
        add("error", "config_invalid", "", std::string("the configuration file does not load: ") + e.what(),
            "fix it and run agensio -t; the running server keeps its last good configuration");
    }
    if (as_root && boot.user.empty())
        add("error", "running_as_root", "", "the server runs as root", "set [server] user = \"agensio\" and restart");
    if (running.sites.empty()) add("info", "no_sites", "", "no site is configured", "add a [[site]]");

    // Certificates, redirects and port 80.
    auto has_plain = [&](const SiteConfig& tls_site, bool need_redirect, bool need_port_80) {
        for (const auto& p : running.sites) {
            if (p.tls) continue;
            if (need_redirect && p.redirect.empty()) continue;
            bool covers = true;
            for (const auto& n : tls_site.server_names)
                covers = covers && std::find(p.server_names.begin(), p.server_names.end(), n) != p.server_names.end();
            if (!covers) continue;
            if (need_port_80) {
                bool on_80 = false;
                for (const auto& a : p.listen) on_80 = on_80 || a.ends_with(":80");
                if (!on_80) continue;
            }
            return true;
        }
        return false;
    };
    for (const auto& s : running.sites) {
        if (!s.tls) continue;
        const std::string name = s.server_names.front();
        const CertificateState st = certificate_state(*s.tls, now);
        if (!st.present) {
            add("error", "certificate_unreadable", name, "certificate cannot be read: " + st.error, "check tls.cert");
        } else if (st.placeholder) {
            add("error", "certificate_not_issued", name,
                "still on the placeholder certificate; the ACME order has not succeeded",
                "make sure the names resolve here and port 80 is reachable, then read the acme lines in the error log");
        } else if (st.days_left < 0) {
            add("error", "certificate_expired", name, "certificate expired", s.tls->automatic ? "read the acme lines in the error log" : "install a new certificate and reload");
        } else if (!s.tls->automatic && st.days_left < 14) {
            add("warn", "certificate_expiring", name, "certificate expires in " + std::to_string(st.days_left) + " days",
                "renew it and reload, or switch to tls = \"auto\"");
        }
        if (s.tls->automatic && !has_plain(s, false, true))
            add("warn", "acme_needs_port_80", name, "tls = \"auto\" but no plain site on port 80 covers these names",
                "add a [[site]] on 0.0.0.0:80 with the same server_name (redirect = \"https\")");
        if (!has_plain(s, true, false))
            add("info", "no_http_redirect", name, "no plain site redirects these names to https",
                "add a [[site]] on port 80 with redirect = \"https\"");
    }

    // Shared account: several application sites without a user.
    std::size_t apps = 0, without_user = 0;
    for (const auto& s : running.sites) {
        bool app = s.php.configured || s.proxy.configured;
        for (const auto& l : s.locations) app = app || l.kind != HandlerKind::static_;
        if (!app) continue;
        ++apps;
        if (s.user.empty()) ++without_user;
    }
    if (apps >= 2 && without_user >= 2)
        add("info", "shared_account", "", std::to_string(without_user) + " application sites run under the server's own account",
            "give each site a user = \"...\" (docs/configuration.md section 11)");

    // Stale generated pools.
    bool any_generated = false;
    for (const auto& s : running.sites) any_generated = any_generated || s.pool.generated;
    if (any_generated) {
        const fs::path dir = pools_dir(running, "");
        if (dir.empty()) {
            add("warn", "pools_dir_unknown", "", "no php-fpm pool directory found for the generated pools", "set [server] pools");
        } else {
            std::ostringstream sink;
            if (write_pools(running, dir, true, sink) == 3)
                add("warn", "pools_stale", "", "generated php-fpm pool files differ from the configuration",
                    "run agensio pools, then reload php-fpm");
        }
    }

    // Recent errors.
    LogQuery q;
    q.level = "error";
    q.since = now - 24 * 3600;
    q.limit = 1000;
    std::vector<LogLine> lines;
    bool truncated = false;
    if (!running.log.error.empty() && running.log.error != "stderr") scan_log(running.log.error, "error", q, lines, truncated);
    if (!lines.empty())
        add("warn", "recent_errors", "", std::to_string(lines.size()) + (truncated ? "+" : "") + " error(s) in the last 24 hours; last: " + lines.back().text,
            "agensio ctl logs --since 24h --level error");
    return out;
}

json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now) {
    const auto findings = health_findings(running, boot, as_root, now);
    json::Value arr = json::Value::array();
    bool ok = true;
    for (const auto& f : findings) {
        if (f.severity != "info") ok = false;
        json::Value v = json::Value::object().set("severity", f.severity).set("code", f.code);
        if (!f.site.empty()) v.set("site", f.site);
        v.set("message", f.message);
        if (!f.fix.empty()) v.set("fix", f.fix);
        arr.push(std::move(v));
    }
    return json::Value::object().set("ok", ok).set("count", static_cast<double>(findings.size())).set("findings", std::move(arr));
}

std::string query_value(std::string_view target, std::string_view key) {
    const std::size_t qm = target.find('?');
    if (qm == std::string_view::npos) return {};
    std::string_view q = target.substr(qm + 1);
    while (!q.empty()) {
        const std::size_t amp = q.find('&');
        const std::string_view pair = q.substr(0, amp);
        q = amp == std::string_view::npos ? std::string_view() : q.substr(amp + 1);
        const std::size_t eq = pair.find('=');
        if (pair.substr(0, eq) != key) continue;
        std::string_view raw = eq == std::string_view::npos ? std::string_view() : pair.substr(eq + 1);
        std::string out;
        for (std::size_t i = 0; i < raw.size(); ++i) {
            if (raw[i] == '+') out.push_back(' ');
            else if (raw[i] == '%' && i + 2 < raw.size() && std::isxdigit(static_cast<unsigned char>(raw[i + 1])) &&
                     std::isxdigit(static_cast<unsigned char>(raw[i + 2]))) {
                out.push_back(static_cast<char>(std::stoi(std::string(raw.substr(i + 1, 2)), nullptr, 16)));
                i += 2;
            } else out.push_back(raw[i]);
        }
        return out;
    }
    return {};
}

}  // namespace agensio::control
