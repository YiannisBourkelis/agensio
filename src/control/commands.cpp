#include "control/commands.hpp"

#include "core/access.hpp"
#include "core/redirect.hpp"
#include "core/refuse.hpp"
#include "core/router.hpp"
#include "core/script_split.hpp"
#include "handlers/static.hpp"
#include "core/strings.hpp"

#include "control/protection.hpp"
#include "control/settings.hpp"
#include "control/sites.hpp"
#include "control/sql_scan.hpp"

#ifndef _WIN32
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <set>
#include <sstream>

#include "services/acme.hpp"
#include "services/appenv.hpp"
#include "services/certificates.hpp"
#include "services/pools.hpp"

namespace agensio::control {

namespace fs = std::filesystem;

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

}  // namespace

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
        l.text = utf8_escaped(l.text);  // older files and the error log may hold a client's raw bytes
        found.push_back(std::move(l));
    }
    std::reverse(found.begin(), found.end());
    out.insert(out.end(), found.begin(), found.end());
}

// alpha.72 report: "5xx", the documented default given explicitly, went to atoi as 5, so every line
// was shown as an error; any other value it did not know was read as something else too.
bool status_filter(std::string_view status, int& min) {
    if (status.empty()) return true;
    auto lower = [](char c) { return c >= 'A' && c <= 'Z' ? static_cast<char>(c + 32) : c; };
    if (status.size() == 3 && lower(status[0]) == 'a' && lower(status[1]) == 'l' && lower(status[2]) == 'l') {
        min = 0;
        return true;
    }
    if (status.size() == 3 && status[0] >= '1' && status[0] <= '5' && lower(status[1]) == 'x' && lower(status[2]) == 'x') {
        min = (status[0] - '0') * 100;
        return true;
    }
    if (status.size() > 3 || !std::all_of(status.begin(), status.end(), [](char c) { return c >= '0' && c <= '9'; })) return false;
    min = std::atoi(std::string(status).c_str());
    return true;
}

json::Value logs(const Config& cfg, const LogQuery& q) {
    std::vector<LogLine> lines;
    bool truncated = false;
    json::Value files = json::Value::array();
    json::Value sources = json::Value::array();
    std::vector<std::string> seen;
    // Who writes into which access log. The [log] access default is the server-wide file:
    // every site without an access_log of its own writes there (the catch-all, the redirects,
    // scanners hitting the bare address), so its lines carry the source "access", never a
    // site's name; a site is named only on a file it alone writes to (2026-10-02 report
    // against alpha.42: 292 lines of the port-80 catch-all were labelled with the first site
    // that shared the default, and a reader took that site for the one being scanned).
    std::vector<std::pair<std::string, std::vector<std::string>>> writers;
    for (const auto& s : cfg.sites) {
        if (s.access_log.empty() || s.server_names.empty()) continue;
        auto it = std::find_if(writers.begin(), writers.end(), [&](const auto& w) { return w.first == s.access_log; });
        if (it == writers.end()) writers.emplace_back(s.access_log, std::vector<std::string>{s.server_names.front()});
        else if (std::find(it->second.begin(), it->second.end(), s.server_names.front()) == it->second.end()) it->second.push_back(s.server_names.front());
    }
    auto sites_of = [&](const std::string& path) -> const std::vector<std::string>* {
        for (const auto& w : writers)
            if (w.first == path) return &w.second;
        return nullptr;
    };
    auto label = [&](const std::string& path) -> std::string {
        const auto* w = sites_of(path);
        if (path == cfg.log.access || !w || w->size() != 1) return "access";
        return w->front();
    };
    auto scan = [&](const std::string& path, std::string_view source) {
        if (path.empty() || path == "stderr" || path == "off") return;
        if (std::find(seen.begin(), seen.end(), path) != seen.end()) return;
        seen.push_back(path);
        files.push(path);
        json::Value src = json::Value::object().set("file", path).set("source", std::string(source));
        if (const auto* w = sites_of(path)) {
            json::Value names = json::Value::array();
            for (const auto& n : *w) names.push(n);
            src.set("sites", std::move(names));
        }
        sources.push(std::move(src));
        scan_log(path, source, q, lines, truncated);
    };
    json::Value out = json::Value::object();
    if (q.site.empty()) {
        scan(cfg.log.error, "error");
        scan(cfg.log.access, "access");
        for (const auto& s : cfg.sites) scan(s.access_log, label(s.access_log));
    } else {
        const SiteConfig* s = find_site(cfg, q.site);
        if (s) {
            const std::string source = label(s->access_log);
            scan(s->access_log, source);
            if (source == "access" && !s->access_log.empty()) {
                // A shared file: JSON lines carry the Host and are kept for this site's names
                // (a catch-all keeps what no other site's name claims); combined lines carry no
                // host, so they stay, labelled honestly, with the note.
                const std::vector<std::string>* w = sites_of(s->access_log);
                std::vector<std::string> others;
                if (w)
                    for (const auto& n : *w)
                        if (n != s->server_names.front()) others.push_back(n);
                std::vector<std::string> other_names;  // every name of every other site on the file
                for (const auto& o : cfg.sites)
                    if (&o != s && o.access_log == s->access_log)
                        for (const auto& n : o.server_names) other_names.push_back(n);
                const bool catch_all = is_catch_all(*s);
                const bool json_lines = std::any_of(lines.begin(), lines.end(), [](const LogLine& l) { return !l.host.empty(); });
                if (json_lines)
                    lines.erase(std::remove_if(lines.begin(), lines.end(),
                                               [&](const LogLine& l) {
                                                   if (l.host.empty()) return false;
                                                   const bool mine = std::find(s->server_names.begin(), s->server_names.end(), l.host) != s->server_names.end();
                                                   const bool theirs = std::find(other_names.begin(), other_names.end(), l.host) != other_names.end();
                                                   return !(mine || (catch_all && !theirs));
                                               }),
                                lines.end());
                json::Value shared = json::Value::array();
                for (const auto& o : others) shared.push(o);
                out.set("shared", true).set("shared_with", std::move(shared));
                out.set("note", s->server_names.front() + " has no access log of its own: it writes into the server-wide log " + s->access_log + " with " +
                                    std::to_string(others.size()) + " other site(s)" + (json_lines ? ", whose JSON lines carry the host, so these are the lines for its names" + std::string(catch_all ? " and for every host no other site claims" : "")
                                                                                                   : "; the combined format carries no host name, so these lines cannot be attributed to this site alone") +
                                    ". A site with its own access_log (site_update access_log, or the key in its file) is queried alone" + (json_lines ? "." : "; [log] format = \"json\" puts the host into every line."));
            }
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
    out.set("files", std::move(files));
    out.set("sources", std::move(sources));
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
    st.not_before = std::chrono::system_clock::to_time_t(info.not_before);
    st.not_after = std::chrono::system_clock::to_time_t(info.not_after);
    st.days_left = static_cast<long>((st.not_after - now) / 86400);
    st.fingerprint = info.fingerprint;
#else
    (void)tls;
    (void)now;
    st.error = "built without TLS";
#endif
    return st;
}

// Several sites may carry the name (a site on other addresses, a whole-domain redirect beside
// it): the one that serves content wins, then the TLS one, then the first.
bool is_catch_all(const SiteConfig& s) {
    return s.is_default || std::find(s.server_names.begin(), s.server_names.end(), "*") != s.server_names.end();
}

bool listener_has_catch_all(const Config& cfg, const std::string& address) {
    for (const auto& s : cfg.sites) {
        if (!is_catch_all(s)) continue;
        const std::vector<std::string> at = site_addresses(s);
        if (std::find(at.begin(), at.end(), address) != at.end()) return true;
    }
    return false;
}

const SiteConfig* find_site(const Config& cfg, std::string_view name) {
    const std::string want = lower(name);
    const SiteConfig* best = nullptr;
    int best_score = -1;
    for (const auto& s : cfg.sites)
        for (const auto& n : s.server_names)
            if (n == want) {
                const int score = (s.redirects_all ? 0 : 2) + (s.tls ? 1 : 0);
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

// The file on disk, and with the running server's facts the certificate it serves (step T2):
// `served.same_as_disk` false means a newer file waits (or one that could not be loaded).
json::Value tls_json(const SiteConfig& s, std::time_t now, const TlsFacts* tls) {
    json::Value t = json::Value::object();
    if (!s.tls) return t.set("mode", "none");
    t.set("mode", s.tls->automatic ? "auto" : "manual").set("cert", s.tls->cert.string()).set("key", s.tls->key.string());
    const CertificateState st = certificate_state(*s.tls, now);
    if (tls)
        if (auto it = tls->served.find(s.tls->cert.string() + '\n' + s.tls->key.string()); it != tls->served.end() && it->second.present) {
            const CertificateState& sv = it->second;
            t.set("served", json::Value::object().set("issuer", sv.issuer).set("placeholder", sv.placeholder).set("names", strings(sv.names))
                                .set("not_after", static_cast<double>(sv.not_after)).set("days_left", static_cast<double>(sv.days_left))
                                .set("same_as_disk", st.present && st.fingerprint == sv.fingerprint));
        }
    t.set("present", st.present);
    if (!st.present) return t.set("error", st.error);
    t.set("placeholder", st.placeholder).set("issuer", st.issuer).set("names", strings(st.names));
    t.set("not_after", static_cast<double>(st.not_after)).set("days_left", static_cast<double>(st.days_left));
    return t;
}

json::Value site_summary(const SiteConfig& s, std::time_t now, const TlsFacts* tls = nullptr) {
    json::Value v = json::Value::object();
    v.set("server_name", strings(s.server_names)).set("listen", strings(s.listen));
    v.set("root", s.root).set("app", s.app).set("user", s.user).set("group", s.group);
    v.set("encoded_slashes", s.encoded_slashes_allow ? "allow" : "deny");
    v.set("trusted_proxies", s.own_trusted_proxies ? strings(s.trusted_proxies_text) : json::Value(nullptr));  // null: [server]'s list
    v.set("http", http_mode(s)).set("http_listen", strings(s.http_listen));  // what plain HTTP gets, and where (docs/redirects.md 2)
    v.set("redirects", static_cast<double>(s.redirects.rules.size()));  // [[site.redirect]] rules (docs/redirects.md 5)
    if (s.redirects_all) v.set("redirects_all", true);  // a rule from "/" answers every request
    v.set("catch_all", is_catch_all(s));
    if (s.carried) v.set("last_good_version", true);  // its file was set aside on reload (design section 26)
    v.set("access_log", s.access_log);
    v.set("tls", tls_json(s, now, tls));
    return v;
}

// A [[site.redirect]] rule as site_show and path_check give it (docs/redirects.md 5): as written,
// with the lifetime it sends.
json::Value redirect_rule_json(const RedirectRule& r) {
    json::Value j = json::Value::object().set("from", r.text).set("match", r.exact ? "exact" : "prefix").set("status", r.status);
    if (r.status != 410) j.set("to", r.to);
    if (!r.exact && r.status != 410 && !r.keep_remainder) j.set("remainder", "drop");
    if (r.status != 410 && r.keep_query == !r.params.empty()) j.set("query", r.keep_query ? "keep" : "drop");
    j.set("cache_control", r.cache_control.empty() ? json::Value(nullptr) : json::Value(r.cache_control));
    return j;
}

json::Value upstream_json(const UpstreamConfig& u) {
    json::Value a = json::Value::array();
    for (const auto& addr : u.addresses) a.push(addr.key);
    if (u.addresses.empty() && u.configured) a.push(u.address.key);
    return a;
}

}  // namespace

std::vector<Finding> notice_findings(const Config& cfg, const std::vector<SiteNotice>& notices, std::time_t now) {
    std::vector<Finding> out;
    auto at = [](std::time_t t) {
        std::tm tm{};
        gmtime_r(&t, &tm);
        char buf[32];
        std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M UTC", &tm);
        return std::string(buf);
    };
    for (const auto& n : notices) {
        const SiteConfig* site = find_site(cfg, n.site);
        if (!site) continue;
        if (n.code == "proxy_scheme_missing") {
            if (now - n.last > 3600 || !site->http_redirect) continue;
            asio::error_code ec;
            const asio::ip::address proxy = asio::ip::make_address(n.subject, ec);
            if (ec || !in_any(site->own_trusted_proxies ? site->trusted_proxies : cfg.trusted_proxies, proxy)) continue;
            out.push_back({"warn", "proxy_scheme_missing", n.site,
                           "the trusted proxy " + n.subject + " sends no X-Forwarded-Proto to " + n.site + " (last at " + at(n.last) +
                               "): agensio takes its requests as plain HTTP, never as HTTPS on a guess, and redirects them to https://, so a visitor "
                               "who used HTTPS at the proxy comes back through it as plain HTTP and loops (too many redirects)",
                           "make the proxy send X-Forwarded-Proto (nginx: proxy_set_header X-Forwarded-Proto $scheme; HAProxy: http-request "
                           "set-header X-Forwarded-Proto https if { ssl_fc }), or connect it to the site over TLS (tls on the site; Cloudflare's "
                           "Full (strict) mode) (docs/redirects.md 2.4)"});
        } else if (n.code == "hsts_narrows_application") {
            if (site->tls_fields.hsts.empty() || !hsts_stronger(n.subject, site->tls_fields.hsts)) continue;
            out.push_back({"warn", "hsts_narrows_application", n.site,
                           "the application sends Strict-Transport-Security: " + n.subject + " (noted " + at(n.last) +
                               "), which commits browsers to more than the site's hsts (" + site->tls_fields.hsts +
                               "); the site's replaces it, so visitors get the weaker one",
                           "if the application's value is meant: the site's hsts set to match (hsts = { max_age = \"2y\", subdomains = true } in "
                           "a hand-written site file), or hsts = false (site_update with hsts: false on a managed site) to let the application's "
                           "through unchanged; if the site's is meant, nothing to do (docs/redirects.md 4.1)"});
        }
    }
    return out;
}

json::Value redirect_notes_json(const SiteConfig& s) {
    json::Value notes = json::Value::array();
    for (const auto& [code, text] : s.redirect_notes) notes.push(json::Value::object().set("code", code).set("text", text));
    return notes;
}

json::Value header_notes_json(const SiteConfig& s) {
    json::Value notes = json::Value::array();
    for (const auto& [code, text] : s.header_notes) notes.push(json::Value::object().set("code", code).set("text", text));
    return notes;
}

namespace {

// One written [[site.response_headers]] rule in the form site_update takes (docs/headers.md 6).
json::Value response_header_rule_json(const HeaderRule& r) {
    json::Value v = json::Value::object().set("path", r.path.size() > 1 && !r.exact ? r.path + "/" : r.path);
    if (r.exact) v.set("match", "exact");
    if (r.success_only) v.set("when", "success");
    if (!r.endings.empty()) {
        json::Value e = json::Value::array();
        for (const auto& x : r.endings) e.push(x);
        v.set("endings", std::move(e));
    }
    for (const auto& [verb, list] : {std::pair{"set", &r.set}, std::pair{"default", &r.fallback}}) {
        if (list->empty()) continue;
        json::Value fields = json::Value::object();
        for (const auto& [name, value] : *list) fields.set(name, value);
        v.set(verb, std::move(fields));
    }
    if (!r.remove.empty()) {
        json::Value names = json::Value::array();
        for (const auto& n : r.remove) names.push(n);
        v.set("remove", std::move(names));
    }
    return v;
}

}  // namespace

json::Value sites(const Config& cfg, std::time_t now, const TlsFacts* tls) {
    json::Value arr = json::Value::array();
    for (const auto& s : cfg.sites) arr.push(site_summary(s, now, tls));
    return json::Value::object().set("count", static_cast<double>(cfg.sites.size())).set("sites", std::move(arr));
}

namespace {

json::Value access_rule_json(const AccessRule& r, const std::string& from) {
    json::Value allow = json::Value::array();
    for (const auto& a : r.allow_text) allow.push(a);
    json::Value v = json::Value::object().set("path", r.path).set("match", r.exact ? "exact" : "prefix").set("allow", std::move(allow));
    v.set("mode", r.report ? "report" : "enforce");
    if (!from.empty()) v.set("from", from);
    return v;
}

// "rules" when the managed site's rules.restricted wrote it, the preset's name when a preset
// added it, "" for a rule written by hand.
std::string access_rule_from(const AccessRule& r, const SiteSpec* managed) {
    if (!r.origin.empty()) return r.origin;
    if (managed && managed->rules.is_object()) {
        for (const auto& m : managed->rules["restricted"].items()) {
            std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && p.size() == r.path.size() && access::iequal_prefix(p, r.path)) return "rules";
        }
        const json::Value admin = admin_rules(*managed);  // kept alive for the loop: items() refers into it
        for (const auto& m : admin.items()) {
            std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && p.size() == r.path.size() && access::iequal_prefix(p, r.path)) return "rules.admin";
        }
    }
    return "";
}

std::string access_rule_text(const AccessRule& r) {
    std::string t = r.path + (r.exact ? " (exact)" : "") + " (allow ";
    for (std::size_t i = 0; i < r.allow_text.size(); ++i) t += (i ? ", " : "") + r.allow_text[i];
    return t + ")";
}

// A user who can log in at `now`: not locked, not past the day `expires` names.
bool usable(const auth::User& u, std::time_t now) { return !u.locked && (u.expires == 0 || now < u.expires); }

// A [[site.auth]] rule as site_show and path_check show it (2026-10-09): never a hash or a name,
// only the file and how many of its users can log in now (site_auth_users lists them, admin).
json::Value auth_rule_json(const AuthRule& r, const std::string& from, std::time_t now) {
    json::Value v = json::Value::object().set("path", r.path).set("match", r.exact ? "exact" : "prefix").set("open", r.open);
    if (!r.open) {
        v.set("realm", r.realm).set("users", r.users_path);
        std::size_t total = 0, can = 0;
        if (r.users)
            for (const auto& u : r.users->users) {
                ++total;
                if (usable(u, now)) ++can;
            }
        v.set("users_count", static_cast<double>(total)).set("usable", static_cast<double>(can));
        json::Value skip = json::Value::array();
        for (const auto& t : r.skip_text) skip.push(t);
        v.set("skip_for", std::move(skip)).set("plain_http", r.plain_http);
        v.set("credentials", r.credentials == AuthRule::Credentials::pass ? "pass" : "strip");
        if (!r.forward_user.empty()) v.set("forward_user", r.forward_user);
    }
    if (!from.empty()) v.set("from", from);
    return v;
}

// "rules" when a managed site's rules.auth wrote it, the preset's name for an opening a preset
// added (WordPress's admin-ajax.php below a protected /wp-admin), "" for one written by hand.
std::string auth_rule_from(const AuthRule& r, const SiteSpec* managed) {
    if (!r.origin.empty()) return r.origin;
    if (managed && managed->rules.is_object())
        for (const auto& m : managed->rules["auth"].items()) {
            const std::string p(m.get("path"));
            if ((m.get("match") == "exact") == r.exact && m["open"].boolean() == r.open && p.size() == r.path.size() && access::iequal_prefix(p, r.path))
                return "rules";
        }
    return "";
}

}  // namespace

json::Value access_check(const Config& cfg, const SiteConfig& site, std::string_view raw_path, std::string_view address_text, std::string& error) {
    std::string path;
    if (raw_path.empty() || !normalize_target(raw_path, path)) {
        error = "path must be a request path starting with '/', such as /wp-admin/post.php";
        return {};
    }
    asio::error_code ec;
    const asio::ip::address given = asio::ip::make_address(std::string(address_text), ec);
    if (ec || address_text.find('%') != std::string_view::npos) {
        error = "address must be an IPv4 or IPv6 address, such as 203.0.113.7 or 2001:db8::7";
        return {};
    }
    const asio::ip::address a = unmapped(given);
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, site.server_names.front()), managed);
    std::string scratch;
    const access::Decision d = access::decide(site, path, [&]() -> const asio::ip::address& { return a; }, scratch);
    json::Value v = json::Value::object().set("site", site.server_names.front()).set("path", path).set("address", a.to_string());
    std::string summary;
    if (d.rule) {
        v.set("decision", d.refuse() ? "refused" : "report").set("rule", access_rule_json(*d.rule, access_rule_from(*d.rule, is_managed ? &managed : nullptr)));
        const bool other = !access::covers(*d.rule, path);  // the path as an origin may read it fell under the rule
        summary = std::string(d.refuse() ? "refused by " : "report (served, logged as refused) by ") + access_rule_text(*d.rule) + ": " + a.to_string() +
                  " is in none of its entries" + (other ? ", for the way an origin may read " + path + " (a ;parameter, a second decoding or the path after a script)" : "");
    } else if (const AccessRule* r = access::rule_for(site, path)) {
        v.set("decision", "allowed").set("rule", access_rule_json(*r, access_rule_from(*r, is_managed ? &managed : nullptr)));
        summary = "allowed by " + access_rule_text(*r) + (r->any ? ": open to anyone" : ": " + a.to_string() + " is in it");
    } else {
        v.set("decision", "allowed");
        summary = "allowed: no access rule covers " + path;
    }
    v.set("summary", summary);
    return v;
}

// The fields the site decides for path_check's answer (docs/headers.md 7): each with its verb, value
// and the deciding rule, and a line to tell the user; HSTS first, over HTTPS. An application's answer
// gets the fields of a successful one and, where they differ, those of any other status; agensio's
// own answer the kind its status is; a file it serves the fields for its ending.
void header_fields(json::Value& v, const SiteConfig& site, const HeaderNode* node, std::string_view decision, int status, std::string_view file) {
    const bool app = decision == "runs" || decision == "proxied" || decision == "handled";
    const EndingSets* es = node && !file.empty() ? response_rules::ending_sets(*node, file) : nullptr;
    auto list = [&](bool success) {
        json::Value out = json::Value::array();
        if (!site.tls_fields.hsts.empty())
            out.push(json::Value::object()
                         .set("field", "Strict-Transport-Security")
                         .set("verb", "set")
                         .set("value", site.tls_fields.hsts)
                         .set("rule", "hsts")
                         .set("text", "strict-transport-security: " + site.tls_fields.hsts + " (hsts, over HTTPS)"));
        if (!node) return out;
        const HeaderSet& hs = es ? (success ? es->success : es->other) : (success ? node->success : node->other);
        for (const FieldDecision& d : hs.fields) {
            if (app && d.own_only) continue;  // the baseline's nosniff: agensio's own answers, never the application's
            const HeaderRule& r = site.response_headers.rules[d.rule];
            const char* verb = d.verb == FieldDecision::Verb::set ? "set" : d.verb == FieldDecision::Verb::fallback ? "default" : "remove";
            json::Value rule = json::Value::object().set("path", r.path).set("match", r.exact ? "exact" : "prefix");
            const std::string baseline = r.baseline ? (site.app.empty() ? std::string("static") : site.app) : std::string();
            if (r.baseline) rule.set("baseline", baseline);
            if (r.success_only) rule.set("when", "success");
            std::string files;
            if (!r.endings.empty()) {
                json::Value endings = json::Value::array();
                for (const auto& e : r.endings) {
                    endings.push(e);
                    files += (files.empty() ? "." : ", .") + e;
                }
                rule.set("endings", std::move(endings));
            }
            std::string lower = d.name;
            for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            std::string text = lower + ": " + (d.verb == FieldDecision::Verb::remove ? std::string("removed")
                                               : d.verb == FieldDecision::Verb::fallback ? d.value + " unless the answer has its own" : d.value);
            text += (r.baseline ? " (baseline " + baseline : " (rule " + r.path + (r.exact ? " exact" : "")) + (r.success_only ? ", success only" : "") +
                    (files.empty() ? "" : ", " + files + " files") + (d.own_only ? ", on the files and error pages agensio serves" : "") + ")";
            json::Value item = json::Value::object().set("field", d.name).set("verb", verb);
            if (d.verb != FieldDecision::Verb::remove) item.set("value", d.value);
            out.push(item.set("rule", std::move(rule)).set("text", text));
        }
        return out;
    };
    if (app) {
        json::Value ok = list(true), other = list(false);
        if (other.dump() != ok.dump()) v.set("response_headers_on_error", std::move(other));
        v.set("response_headers", std::move(ok));
        v.set("response_headers_note", "the application's answer: its own fields go out, then these decide (set replaces its copy, default only fills a "
                                       "gap, remove drops it); response_headers_on_error for a status other than 2xx and 304");
    } else {
        v.set("response_headers", list((status >= 200 && status < 300) || status == 304));
    }
    // The fields of docs/headers.md 4.1 the baseline leaves to the owner, when nothing the site decides
    // sends them on this page's answer: what the agent offers, one at a time, with what each could
    // break (headers.md 6). The application may send some itself; nothing is fetched here.
    if (!app && decision != "static") return;
    const HeaderSet* hs = node ? (es ? &es->success : &node->success) : nullptr;
    auto decided = [&](std::string_view name) {
        if (hs)
            for (const auto& f : hs->fields)
                if (Headers::iequals(f.name, name)) return !(app && f.own_only);  // the baseline's nosniff is not the application's
        return false;
    };
    bool frame_ancestors = false;
    if (hs)
        for (const auto& f : hs->fields)
            frame_ancestors = frame_ancestors || (Headers::iequals(f.name, "content-security-policy") && f.value.find("frame-ancestors") != std::string::npos);
    json::Value offer = json::Value::array();
    const auto& declined = site.response_headers_offer_declined;  // the owner's no (response_headers_offer_declined)
    auto add = [&](const char* field, std::string breaks) {
        if (std::find(declined.begin(), declined.end(), field) == declined.end())
            offer.push(json::Value::object().set("field", field).set("breaks", std::move(breaks)));
    };
    if (!decided("X-Frame-Options") && !frame_ancestors)
        add("X-Frame-Options", "every embedding of these pages on another site: WordPress post embeds, a status page, a widget or a booking form; ask "
                               "whether another site frames them. SAMEORIGIN keeps the site's own frames (frame-ancestors 'self' in a CSP does the same)");
    if (!decided("Content-Security-Policy") && !decided("Content-Security-Policy-Report-Only"))
        add("Content-Security-Policy", "whatever the policy does not foresee: inline scripts, an analytics or chat tag, a payment form; offer it as "
                                       "Content-Security-Policy-Report-Only first, as a default so the application's own policy wins, and enforce it once "
                                       "the browser console stays clean on the main pages");
    if (!decided("Permissions-Policy"))
        add("Permissions-Policy", "a browser feature the site uses: the camera or microphone of a video call, geolocation for a store finder, payment; "
                                  "name only features it does not use (camera=(), microphone=(), geolocation=())");
    if (!decided("X-Content-Type-Options"))
        add("X-Content-Type-Options", app ? "a script the application sends with the wrong type (JavaScript printed under text/html, JSONP as "
                                            "application/json) stops working; on the application's answers only when its scripts carry their types"
                                          : "nothing on the files agensio serves, whose type it sets itself: the baseline sends it (response_headers_baseline)");
    if (site.tls && site.tls_fields.hsts.empty() && site.hsts != SiteConfig::Hsts::off)
        add("Strict-Transport-Security", "plain HTTP, and clicking past a certificate warning, for its whole max-age; the site's hsts field, never a rule");
    if (!offer.items().empty()) v.set("response_headers_offer", std::move(offer));
    if (!declined.empty()) {
        json::Value list = json::Value::array();
        for (const auto& d : declined) list.push(d);
        v.set("response_headers_offer_declined", std::move(list));
    }
}

// path_check (2026-10-08, docs/configuration.md 6b): what a site does with one GET for a path,
// in the order a worker decides it, and why: the refuse patterns, the location, its refusals
// by name, try_files and the index, every internal redirect again, then the file served, the
// script run or the origin it goes to. A description, never a request: it reads the running
// configuration and stats files as the worker would, and contacts no upstream. The access rules
// depend on the client and are only named here (access_check decides them for an address).
json::Value path_check(const Config& cfg, const SiteConfig& site, std::string_view raw_path, std::string& error) {
    std::string path;
    bool encoded = false;
    if (raw_path.empty() || raw_path.front() != '/' || !normalize_target(raw_path, path, &encoded)) {
        error = "path must be a request path starting with '/', such as /typo3conf/ext/news/Configuration/setup.typoscript";
        return {};
    }
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, site.server_names.front()), managed);
    std::vector<RuleLocation> ruled;
    if (is_managed) ruled = rule_locations(managed);
    json::Value v = json::Value::object().set("site", site.server_names.front()).set("path", path);
    // What the same GET gets over plain HTTP (docs/redirects.md 1, 2), the steps below being the
    // HTTPS answer: the redirect, or under the certificate validation prefixes the files only.
    if (site.tls || site.http_redirect) {
        const bool validation = path.starts_with("/.well-known/acme-challenge/") || path.starts_with("/.well-known/pki-validation/");
        if (site.http_redirect && validation)
            v.set("plain_http", site.validation.root.empty()
                                    ? "404: certificate validation over plain HTTP is answered from the site's files, and this site serves none from its project directory"
                                    : "a regular file under the root, else 404: certificate validation over plain HTTP, nothing runs and nothing falls back");
        else if (site.http_redirect)
            v.set("plain_http", std::string("308 to https (http = \"redirect\")"));
        else if (site.http == SiteConfig::Http::serve)
            v.set("plain_http", std::string("the same answer (http = \"serve\")"));
        else
            v.set("plain_http", std::string("no plain listener (http = \"off\")"));
    }
    json::Value steps = json::Value::array();
    auto from_of = [&](const LocationConfig& l) -> std::string {
        if (!l.origin.empty()) return l.origin;
        for (const RuleLocation& rl : ruled)
            if (rl.path == l.path && rl.exact == l.exact && rl.suffix == l.suffix) return "rules";
        return "";
    };
    auto describe = [&](const LocationConfig& l) {
        const std::string from = from_of(l);
        return "location " + l.path + " (" + (l.exact ? "exact" : l.suffix ? "suffix" : "prefix") + ", " + l.handler + (from.empty() ? "" : ", from " + from) + ")";
    };
    // [[site.response_headers]] match the path asked for, never an internal target (docs/headers.md 1).
    const HeaderNode* header_node = site.response_headers.lookup(path);
    auto finish = [&](const char* decision, int status, const std::string& summary, std::string_view file = {}) {
        v.set("decision", decision);
        if (status) v.set("status", status);
        v.set("summary", summary).set("steps", std::move(steps));
        const std::string_view d = decision;
        const bool page = d == "static" || d == "runs" || d == "proxied" || d == "handled";  // for response_headers_offer
        if (header_node || !site.tls_fields.hsts.empty() || page) header_fields(v, site, header_node, decision, status, file);
        return v;
    };
    auto stat_is = [](const std::string& f, bool dir) {
        struct stat st {};
        return ::stat(f.c_str(), &st) == 0 && (dir ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
    };
    std::string scratch;
    for (int hop = 0; hop <= StaticHandler::kMaxInternalRedirects; ++hop) {
        if (const RefusePattern* p = refuse::decide(site.refuse, path, scratch)) {
            v.set("refused_by", p->text);
            const bool other = refuse::match(site.refuse, path) == nullptr;
            return finish("refused", 404, "404: " + path + " is refused by the site's refuse pattern '" + p->text + "'" +
                                              (other ? ", for the way an application may read it (a ;parameter, a second decoding or the path after a script)" : ""));
        }
        if (!site.refuse.empty()) steps.push(path + ": no refuse pattern matches");
        // Path redirects (docs/redirects.md 5): after refuse, before the access and password rules,
        // on the path the client asked for only, never a target try_files or an index reached.
        if (hop == 0 && !site.redirects.empty()) {
            const std::size_t qm = raw_path.find('?');
            const std::string_view query = qm == std::string_view::npos ? std::string_view() : raw_path.substr(qm + 1);
            if (const RedirectRule* r = redirect::match(site.redirects, path, query, encoded)) {
                v.set("redirect", redirect_rule_json(*r));
                if (r->status == 410) return finish("gone", 410, "410: the rule from \"" + r->text + "\" answers that " + path + " is gone, with no new address");
                std::string loc;
                redirect::write_location(loc, *r, path, query, "");
                v.set("redirect_location", loc);
                const bool validation = path.starts_with("/.well-known/acme-challenge/") || path.starts_with("/.well-known/pki-validation/");
                if (site.http_redirect && !validation) {  // from plain HTTP: scheme and rule in one hop (docs/redirects.md 1)
                    std::string name = site.canonical.empty() ? site.server_names.front() : site.canonical;
                    if (name == "*") name = "<the name asked>";
                    std::string origin = "https://" + name + (site.https_port != 443 ? ":" + std::to_string(site.https_port) : std::string());
                    std::string hop_loc;
                    redirect::write_location(hop_loc, *r, path, query, origin);
                    v.set("plain_http", std::to_string(r->status) + " to " + hop_loc + " in one hop: the scheme and the rule");
                }
                return finish("redirect", r->status,
                              std::to_string(r->status) + " to " + loc + " by the rule from \"" + r->text + "\"" + (r->exact ? " (exact)" : "") +
                                  (r->cache_control.empty() ? std::string() : ", which browsers keep (" + r->cache_control + ")") +
                                  "; it answers before the site's access and password rules");
            }
            steps.push(path + ": no redirect rule matches");
        }
        // The script the path runs, which an exact rule judges too (access::script_of, the alpha.58
        // report's finding 1): named, and a rule that covers it shown as the path's.
        std::string script;
        const bool scripted = access::script_of(site, path, script);
        if (scripted && v["script"].is_null()) {
            v.set("script", script);
            steps.push(path + ": runs the script " + script + ", which the access and password rules judge too");
        }
        const AccessRule* ar = access::rule_for(site, path);
        if ((!ar || ar->any) && scripted)
            if (const AccessRule* sr = access::rule_for(site, script); sr && !sr->any) ar = sr;
        if (ar && !ar->any && v["access"].is_null())
            v.set("access", access_rule_json(*ar, access_rule_from(*ar, is_managed ? &managed : nullptr)))
                .set("access_note", "an access rule covers " + path + ": clients outside it get 403 (access_check decides it for an address)");
        // Passwords (2026-10-09), checked after the access rules as the dispatcher does.
        const AuthRule* pr = access::auth_rule_for(site, path);
        if ((!pr || pr->open) && scripted)
            if (const AuthRule* sr = access::auth_rule_for(site, script); sr && !sr->open) pr = sr;
        if (const AuthRule* r = pr; r && v["auth"].is_null()) {
            v.set("auth", auth_rule_json(*r, auth_rule_from(*r, is_managed ? &managed : nullptr), std::time(nullptr)));
            v.set("auth_note", r->open ? path + " is open: the rule " + r->path + " frees it below a password rule, so nobody is asked"
                                       : "a password rule covers " + path + ": a request without the password of one of its users gets 401 (realm \"" + r->realm +
                                             "\")" + (r->skip_text.empty() ? std::string() : ", except from the addresses of skip_for") +
                                             (r->plain_http ? std::string() : "; over plain HTTP from another host it gets 403 and is never asked"));
        }
        const LocationConfig& loc = Router::location(site, path);
        steps.push(path + ": " + describe(loc));
        json::Value lj = json::Value::object().set("path", loc.path).set("match", loc.exact ? "exact" : loc.suffix ? "suffix" : "prefix").set("handler", loc.handler);
        if (const std::string from = from_of(loc); !from.empty()) lj.set("from", from);
        v.set("location", std::move(lj));
        if (encoded && loc.kind != HandlerKind::proxy && !site.encoded_slashes_allow)
            return finish("not_found", 404, "404: the path spells a separator as a percent escape (%2F, %5C), never a file here");
        auto fs_of = [&](const std::string& p) {
            return loc.alias.empty() ? loc.root + p : loc.alias + p.substr(std::min(p.size(), loc.path.size() - 1));
        };
        if (loc.kind == HandlerKind::proxy) {
            if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
                return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses before the application sees it");
            v.set("upstream", upstream_json(loc.proxy));
            return finish("proxied", 0, path + " goes to the application (" + describe(loc) + "), which answers it");
        }
        if (loc.kind == HandlerKind::fastcgi || loc.kind == HandlerKind::cgi) {
            if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
                return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses");
            // The script and its path info as the handler splits them (core/script_split.hpp, one place:
            // before alpha.71 a CGI path with path info was taken whole for the script here).
            std::string script = path, info;
            if (loc.kind == HandlerKind::fastcgi && loc.fastcgi.options.path_info)
                if (const std::size_t p = script_split::php_end(script); p != std::string::npos) {
                    info = script.substr(p);
                    script.resize(p);
                }
            if (script.back() == '/') script += loc.index.empty() ? (loc.kind == HandlerKind::cgi ? "index.cgi" : "index.php") : loc.index.front();
            if (loc.kind == HandlerKind::cgi) {  // the longest leading part that is a file (Apache's rule)
                std::string scratch;
                if (const std::size_t cut = script_split::cgi_end(loc, script, scratch, [&](const std::string& f) { return stat_is(f, false); }); cut != 0) {
                    info = script.substr(cut);
                    script.resize(cut);
                }
            }
            const std::string file = fs_of(script);
            v.set("file", file);
            if (!stat_is(file, false)) return finish("not_found", 404, "404: no script " + file + " for " + describe(loc) + ", answered before the application");
            return finish("runs", 0, "runs " + script + (info.empty() ? "" : " with PATH_INFO " + info) + " (" + describe(loc) + ")");
        }
        if (loc.kind != HandlerKind::static_) return finish("handled", 0, path + " is answered by the " + loc.handler + " handler (" + describe(loc) + ")");
        // The static handler: its refusals by name, then try_files or the plain rule.
        if (!loc.hidden_files && has_hidden_segment(path)) return finish("refused", 404, "404: " + path + " has a dot segment (a hidden file), which " + describe(loc) + " never serves");
        if (!loc.deny_suffixes.empty() && refused_suffix(path, loc.deny_suffixes))
            return finish("refused", 404, "404: " + path + " ends with an ending " + describe(loc) + " refuses (deny_suffixes)");
        if (!loc.allow_suffixes.empty() && !refused_suffix(path, loc.allow_suffixes))
            return finish("refused", 404, "404: " + describe(loc) + " serves certain endings only (allow_suffixes), and " + path + " has none of them");
        if (!loc.protects.empty() && backup_of_protected(path, loc.protects))
            return finish("refused", 404, "404: " + path + " is a backup spelling of a name the site never serves");
        const bool dir_uri = path.back() == '/';
        // The index of a directory, as StaticHandler::index_lookup decides it: one the site
        // refuses by name is passed over as if missing; another location's is routed there.
        auto index_of = [&](std::string& file) -> int {
            for (const auto& i : loc.index) {
                const std::string candidate = path + i;
                if (!stat_is(fs_of(candidate), false)) continue;
                const LocationConfig& owner = Router::location(site, candidate);
                if (refused_request(site, owner, candidate)) {
                    steps.push(path + ": its index " + i + " exists but the site refuses it by name, so it is passed over as if missing");
                    continue;
                }
                if (&owner != &loc) {
                    steps.push(path + ": its index " + i + " belongs to " + describe(owner) + ", routed there");
                    path = candidate;
                    return 2;
                }
                if (!site.access.empty() && access::rule_for(site, candidate) != access::rule_for(site, path)) {
                    steps.push(path + ": another access rule decides its index " + i + ", so it is routed as a request for " + candidate);
                    path = candidate;
                    return 2;
                }
                file = fs_of(candidate);
                return 1;
            }
            return 0;
        };
        std::string file;
        bool next = false;
        if (loc.try_files.empty()) {
            if (dir_uri) {
                const int r = index_of(file);
                if (r == 1) {
                    v.set("file", file);
                    return finish("static", 200, "200: the index " + file + " (" + describe(loc) + ")", file);
                }
                if (r == 2) continue;
                if (stat_is(fs_of(path), true)) return finish("forbidden", 403, "403: a directory without an index file");
                return finish("not_found", 404, "404: no such directory");
            }
            file = fs_of(path);
            if (stat_is(file, false)) {
                v.set("file", file);
                return finish("static", 200, "200: the file " + file + " (" + describe(loc) + ")", file);
            }
            if (stat_is(file, true)) return finish("redirect", 301, "301 to " + path + "/: a directory");
            return finish("not_found", 404, "404: no file " + file);
        }
        for (const TryStep& step : loc.try_files) {
            switch (step.kind) {
                case TryStep::Kind::uri:
                    if (!dir_uri && stat_is(fs_of(path), false)) {
                        v.set("file", fs_of(path));
                        return finish("static", 200, "200: the file " + fs_of(path) + " (" + describe(loc) + ")", fs_of(path));
                    }
                    break;
                case TryStep::Kind::uri_dir:
                    if (dir_uri) {
                        const int r = index_of(file);
                        if (r == 1) {
                            v.set("file", file);
                            return finish("static", 200, "200: the index " + file + " (" + describe(loc) + ")", file);
                        }
                        if (r == 2) next = true;
                    } else if (stat_is(fs_of(path), true)) {
                        return finish("redirect", 301, "301 to " + path + "/: a directory");
                    }
                    break;
                case TryStep::Kind::status:
                    return finish(step.status == 404 ? "not_found" : "status", step.status,
                                  std::to_string(step.status) + (loc.handler == "deny" ? ": " + describe(loc) + " answers 404 whatever exists"
                                                                                       : ": try_files of " + describe(loc) + " ends in =" + std::to_string(step.status)));
                case TryStep::Kind::fallback:
                    steps.push(path + ": no file or directory, so try_files sends it to " + step.target);
                    path = step.target;
                    next = true;
                    break;
            }
            if (next) break;
        }
        if (!next) return finish("not_found", 404, "404: try_files of " + describe(loc) + " found nothing");
    }
    return finish("error", 500, "500: more than " + std::to_string(StaticHandler::kMaxInternalRedirects) + " internal redirects");
}

json::Value site(const Config& cfg, const SiteConfig& s, std::time_t now, const TlsFacts* tls) {
    json::Value v = site_summary(s, now, tls);
    v.set("index", strings(s.index));
    v.set("settings", effective_settings(s, cfg));  // each with its value and where it comes from
    if (s.php.configured) {
        json::Value php = json::Value::object().set("socket", s.php.address.key);
        if (s.pool.generated) php.set("pool", s.pool.name).set("state_dir", s.pool.state_dir);
        v.set("php", std::move(php));
    }
    if (s.proxy.configured) v.set("upstream", upstream_json(s.proxy));
    // The login paths the rendered fail2ban jail counts attempts on (docs/configuration.md 18):
    // the preset's known ones and the site's own `login_paths`.
    {
        std::vector<std::string> lp = preset_login_paths(s.app);
        for (const auto& p : s.login_paths)
            if (std::find(lp.begin(), lp.end(), p) == lp.end()) lp.push_back(p);
        if (!lp.empty()) v.set("login_paths", strings(lp));
    }
    // The archives and dumps served on purpose, so an agent changing the list sees what it replaces
    // (the alpha.97 report).
    if (!s.public_archives.empty()) v.set("public_archives", strings(s.public_archives));
    // The locations a managed site's rules render are hand-written to the loader; labelled
    // "rules" here, beside preset:<app> and root:<file>, so an agent can tell them apart
    // (2026-10-02 report: 17 of a Kanboard site's 19 locations said nothing).
    std::vector<RuleLocation> ruled;
    SiteSpec managed;
    const bool is_managed = read_managed(site_file(cfg, s.server_names.front()), managed);
    if (is_managed) ruled = rule_locations(managed);
    json::Value locs = json::Value::array();
    for (const auto& l : s.locations) {
        json::Value loc = json::Value::object().set("path", l.path);
        loc.set("match", l.exact ? "exact" : l.suffix ? "suffix" : "prefix").set("handler", l.handler);
        if (!l.script_dir.empty()) loc.set("scripts_only_directly_in", l.script_dir);  // Drupal: PHP below any other directory refused
        if (!l.deny_suffixes.empty()) loc.set("refuses", strings(l.deny_suffixes));  // endings answered 404 here
        if (!l.allow_suffixes.empty()) loc.set("serves_only", strings(l.allow_suffixes));  // no other ending is
        if (!l.origin.empty()) loc.set("from", l.origin);
        else
            for (const RuleLocation& rl : ruled)
                if (rl.path == l.path && rl.exact == l.exact && rl.suffix == l.suffix) {
                    loc.set("from", "rules");
                    break;
                }
        if (!l.alias.empty()) loc.set("alias", l.alias);
        else if (l.root != s.root) loc.set("root", l.root);
        if (l.kind == HandlerKind::proxy) loc.set("upstream", upstream_json(l.proxy));
        if (l.kind == HandlerKind::fastcgi) loc.set("socket", l.fastcgi.address.key);
        if (!l.add_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.add_headers) h.set(n, val);
            loc.set("add_headers", std::move(h));
        }
        if (!l.hashed_headers.empty()) {
            json::Value h = json::Value::object();
            for (const auto& [n, val] : l.hashed_headers) h.set(n, val);
            loc.set("add_headers_hashed_names", std::move(h));
        }
        locs.push(std::move(loc));
    }
    v.set("locations", std::move(locs));
    // Access by client address: the rules in force, longest path first, each with where it
    // comes from (rules = the managed site's rules.restricted, preset:<app>, or nothing for a
    // hand-written one).
    if (!s.access.empty()) {
        json::Value acc = json::Value::array();
        for (const auto& r : s.access) acc.push(access_rule_json(r, access_rule_from(r, is_managed ? &managed : nullptr)));
        v.set("access", std::move(acc));
    }
    // Passwords: the rules in force, longest first, each with where it comes from and how many of
    // its users can log in now; the names are site_auth_users' (admin).
    if (!s.auth.empty()) {
        json::Value list = json::Value::array();
        for (const auto& r : s.auth) list.push(auth_rule_json(r, auth_rule_from(r, is_managed ? &managed : nullptr), now));
        v.set("auth", std::move(list));
    }
    // `refuse`: the patterns in force, as written (a managed site's come from rules.refuse).
    if (!s.refuse.empty()) {
        json::Value list = json::Value::array();
        for (const auto& p : s.refuse.patterns) list.push(p.text);
        v.set("refuse", std::move(list));
    }
    // Path redirects (docs/redirects.md 5): the rules in force, and what the load noted about them.
    if (!s.redirects.empty()) {
        json::Value list = json::Value::array();
        for (const auto& r : s.redirects.rules) list.push(redirect_rule_json(r));
        v.set("redirects", std::move(list));
        if (!s.redirect_notes.empty()) v.set("redirect_notes", redirect_notes_json(s));
    }
    // Response headers (docs/headers.md 2, 4, 6): the rules written, in the form site_update takes,
    // whether the preset's baseline is on, and what the load noted.
    {
        json::Value list = json::Value::array();
        bool baseline = false;
        for (const auto& r : s.response_headers.rules) {
            if (r.baseline) baseline = true;
            else list.push(response_header_rule_json(r));
        }
        if (!list.items().empty()) v.set("response_headers", std::move(list));
        v.set("response_headers_baseline", baseline);
        if (!s.response_headers_offer_declined.empty()) {
            json::Value declined = json::Value::array();
            for (const auto& d : s.response_headers_offer_declined) declined.push(d);
            v.set("response_headers_offer_declined", std::move(declined));
        }
        if (!s.header_notes.empty()) v.set("response_header_notes", header_notes_json(s));
    }
    (void)cfg;
    return v;
}

// ---- validation and health ----

// The restart-only keys the file changed, each by name: the reference rows whose `applies` is
// restart (2026-10-09, the cookbook's finding: the [cache] keys, stream_chunk_size,
// sendfile_max_chunk, tcp_nodelay and pid_file kept their start values on a reload while the
// reference said reload, and nothing said so). The reload's warning, validate and health read it.
std::vector<std::string> restart_needed(const Config& fresh, const Config& running) {
    std::vector<std::string> out;
    auto kept = [&](bool changed, const char* key) {
        if (changed) out.push_back(key);
    };
    kept(fresh.workers != running.workers, "workers");
    kept(fresh.reuse_port != running.reuse_port, "reuse_port");
    kept(fresh.user != running.user, "user");
    kept(fresh.group != running.group, "group");
    kept(fresh.sendfile != running.sendfile, "sendfile");
    kept(fresh.sendfile_max_chunk != running.sendfile_max_chunk, "sendfile_max_chunk");
    kept(fresh.tcp_nodelay != running.tcp_nodelay, "tcp_nodelay");
    kept(fresh.pid_file != running.pid_file, "pid_file");
    kept(fresh.cache_max_file_size != running.cache_max_file_size, "cache.max_file_size");
    kept(fresh.cache_max_size != running.cache_max_size, "cache.max_size");
    kept(fresh.cache_evict_fraction != running.cache_evict_fraction, "cache.evict_fraction");
    kept(fresh.cache_revalidate_s != running.cache_revalidate_s, "cache.revalidate_interval");
    kept(fresh.stream_chunk_size != running.stream_chunk_size, "cache.stream_chunk_size");
    kept(fresh.cache_sendfile_min_size != running.cache_sendfile_min_size, "cache.sendfile_min_size");
    kept(fresh.cache_max_open_files != running.cache_max_open_files, "cache.max_open_files");
    kept(fresh.cache_precompressed != running.cache_precompressed, "cache.precompressed");
    kept(fresh.control.enabled != running.control.enabled, "control");
    kept(fresh.control.enabled && running.control.enabled && fresh.control.socket != running.control.socket, "control.socket");
    kept(fresh.control.provision != running.control.provision, "control.provision");
    // Not the task keys (runtimes, task_limits, task_network): the helper reads them from
    // root's file for every task, and the server from the configuration it runs, so a
    // reload changes them (2026-09-27 Writebook report: a new Ruby cost every site a restart).
    return out;
}

json::Value validate(const fs::path& path, const Config& running, const Config* current) {
    json::Value v = json::Value::object().set("path", path.string());
    json::Value errors = json::Value::array();
    Config fresh;
    std::vector<std::string> hosting;
    try {
        fresh = load_config(path, current);
        hosting = isolate_hosting(fresh, system_facts(), current);  // a site breaking one is set aside (held_back)
        check_certificates(fresh, current);  // and one whose certificate and key do not load, as the reload loads them
    } catch (const std::exception& e) {
        errors.push(e.what());
        return v.set("ok", false).set("errors", std::move(errors));
    }
    for (const auto& e : hosting) errors.push(e);
    const bool ok = errors.items().empty();
    v.set("ok", ok).set("errors", std::move(errors)).set("sites", static_cast<double>(fresh.sites.size()));
    // Site files a reload would set aside (design section 26): the rest loads, so ok stays true.
    json::Value held = json::Value::array();
    for (const auto& h : fresh.held_back)
        held.push(json::Value::object().set("file", h.file).set("error", h.error).set("keeps_running_version", h.carried).set("hosting_rule", h.hosting)
                      .set("certificate", h.certificate));
    v.set("held_back", std::move(held));
    v.set("restart_needed", strings(restart_needed(fresh, running)));
    return v;
}

bool php_fpm_hard_reload(const Config& cfg, std::string& file) {
    const fs::path dir = pools_dir(cfg, "");
    if (dir.empty()) return false;
    std::error_code ec;
    for (const fs::path& candidate :
         {dir.parent_path() / "php-fpm.conf", dir.parent_path().parent_path() / "php-fpm.conf"}) {
        if (!fs::is_regular_file(candidate, ec)) continue;
        file = candidate.string();
        std::ifstream in(candidate);
        std::string line;
        while (std::getline(in, line)) {
            const std::size_t start = line.find_first_not_of(" \t");
            if (start == std::string::npos || line[start] == ';' || line[start] == '#') continue;
            if (line.compare(start, 23, "process_control_timeout") != 0) continue;
            const std::size_t eq = line.find('=', start);
            if (eq == std::string::npos) continue;
            std::string value = line.substr(eq + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            const std::size_t end = value.find_first_of(" \t;#\r");
            if (end != std::string::npos) value.erase(end);
            return value.empty() || value == "0" || value == "0s";
        }
        return true;  // the file exists and never sets it: php-fpm's default of 0
    }
    return false;
}

// Files under a site's document root that the server's own account cannot open: they
// answer 404 with nothing in any log. Sampled with a budget, the application's upload
// directory first (the preset knows it), hidden entries and the preset's credential files
// left out (never served, 0600 by design). Runs as whoever the server runs as, so the
// answer is what a request would meet.
struct UnreadableFiles {
    std::size_t seen = 0, unreadable = 0;
    std::string example;
    FileFacts example_facts;
};

UnreadableFiles unreadable_files(const SiteConfig& site, const std::vector<std::string>& secrets, std::size_t budget) {
    UnreadableFiles r;
    if (site.root.empty()) return r;
    std::vector<fs::path> starts;
    const std::string up = preset_uploads(site.app);
    if (!up.empty()) starts.push_back(site.root + up);
    starts.push_back(site.root);
    std::error_code ec;
    for (const auto& start : starts) {
        if (!fs::is_directory(start, ec)) continue;
        for (fs::recursive_directory_iterator it(start, fs::directory_options::skip_permission_denied, ec), end; it != end && r.seen < budget; it.increment(ec)) {
            if (ec) break;
            const std::string name = it->path().filename().string();
            if (!name.empty() && name[0] == '.') {  // hidden: never served, so never a finding
                if (it->is_directory(ec)) it.disable_recursion_pending();
                continue;
            }
            if (it.depth() >= 8) it.disable_recursion_pending();
            if (!it->is_regular_file(ec)) continue;
            ++r.seen;
            const std::string path = it->path().string();
            if (std::find(secrets.begin(), secrets.end(), path) != secrets.end()) continue;
#ifndef _WIN32
            if (::access(path.c_str(), R_OK) == 0) continue;
#else
            continue;
#endif
            if (r.unreadable++ == 0) {
                r.example = path;
                system_facts().stat(path, r.example_facts);
            }
        }
    }
    return r;
}

namespace {

// Files an application writes under its own tree with an archive's ending and nothing of the site in
// them, by preset, path as served and a size no real archive fits in: Grav's API plugin writes
// user/data/grav-security-probe.zip (32 bytes, with .dat, .json and .txt siblings) to check that
// user/data is not public, and writes it again when it is deleted (the alpha.97 report: health told
// the owner to delete it, and Grav's next update put it back).
struct ProbeFile {
    const char* app;
    const char* served;
    std::uintmax_t max_bytes;
};
constexpr ProbeFile kProbeFiles[] = {
    {"grav", "/user/data/grav-security-probe.zip", 1024},
};

bool application_probe(const SiteConfig& site, std::string_view served, std::uintmax_t bytes) {
    for (const ProbeFile& p : kProbeFiles)
        if (site.app == p.app && served == p.served && bytes <= p.max_bytes) return true;
    return false;
}

// SQL an application ships with its code, which holds no copy of the site (the alpha.95 report: TYPO3's
// typo3/sysext/extbase/ext_tables.sql named as a dump). The names TYPO3 reserves in an extension's
// directory for its tables and their static rows count only there, beside the extension's
// ext_emconf.php or composer.json, so a dump given such a name elsewhere is still found.
bool application_schema(const fs::path& file, std::string_view lower) {
    if (lower != "ext_tables.sql" && lower != "ext_tables_static+adt.sql") return false;
    std::error_code ec;
    const fs::path dir = file.parent_path();
    return fs::is_regular_file(dir / "ext_emconf.php", ec) || fs::is_regular_file(dir / "composer.json", ec);
}

// An uncompressed .sql file of at most 64 KB whose statements all define tables (control/sql_scan.hpp)
// holds no rows and no credential, so nothing of the site is in it: an application's schema or upgrade
// file. A larger file, one that cannot be read, one that ends inside a quote or a comment and one with
// any other statement count (the alpha.96 report: a file of UPDATE statements with a password hash and
// a key passed the keyword rule of alpha.96).
bool sql_without_rows(const fs::path& file) {
    constexpr std::size_t kMax = 64 * 1024;
    std::ifstream in(file, std::ios::binary);
    if (!in) return false;
    std::string text(kMax + 1, '\0');
    in.read(text.data(), static_cast<std::streamsize>(text.size()));
    text.resize(static_cast<std::size_t>(in.gcount()));
    if (text.size() > kMax) return false;
    const sql::Scan scan = sql::scan(text);
    return scan.definitions_only && !scan.open;
}

}  // namespace

// Backup archives and database dumps under a document root (2026-09-23 live report: a
// Grav site's backup/ held a 23 MB zip with the admin account and the salt, and the log
// that named it was served). Bounded like unreadable_files; hidden directories skipped.
ArchivesInRoot archives_in_root(const SiteConfig& site, std::size_t budget) {
    ArchivesInRoot r;
    if (site.root.empty()) return r;
    static const char* const kArchives[] = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".rar"};
    // Dumps and database files themselves (the alpha.96 report: a static site serves them as they are;
    // the PHP presets refuse .sqlite, .sqlite3 and .db), and the same inside one archive or compression,
    // which leaves them dumps (the alpha.97 report: phpMyAdmin's zipped export, export.sql.zip, and a
    // backup.sql.tar.gz were taken for downloads on a static site).
    static const char* const kDumps[] = {".sql", ".sqlite", ".sqlite3", ".db", ".dump"};
    static const char* const kWrappers[] = {".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".rar", ".gz", ".bz2", ".xz", ".zst"};
    r.dumps_only = site.app.empty() || site.app == "static";
    std::string root = site.root;
    while (root.size() > 1 && root.back() == '/') root.pop_back();
    const auto listed_public = [&](std::string_view served) {
        for (const auto& a : site.public_archives)
            if (a.back() == '/' ? served.starts_with(a) : served == a) return true;
        return false;
    };
    // "/db" for a directory accepts nothing below it, only "/db/" does (the alpha.97 report): the
    // finding says how to write it.
    for (const auto& a : site.public_archives) {
        std::error_code dec;
        if (a.back() != '/' && fs::is_directory(root + a, dec)) r.unslashed.push_back(a);
    }
    std::error_code ec;
    if (!fs::is_directory(site.root, ec)) return r;
    // Directories the preset never answers (Grav's backup/, logs/) are not one path away
    // from public; they are not searched.
    std::vector<std::string> skip;
    for (const auto& loc : site.locations)
        if (loc.handler == "deny" && !loc.exact && loc.path.size() > 1 && loc.path.back() == '/') skip.push_back(site.root + loc.path.substr(0, loc.path.size() - 1));
    for (fs::recursive_directory_iterator it(site.root, fs::directory_options::skip_permission_denied, ec), end; it != end && r.seen < budget; it.increment(ec)) {
        if (ec) break;
        const std::string name = it->path().filename().string();
        if (it->is_directory(ec)) {
            if ((!name.empty() && name[0] == '.') || it.depth() >= 8 || std::find(skip.begin(), skip.end(), it->path().string()) != skip.end())
                it.disable_recursion_pending();
            continue;
        }
        if (!name.empty() && name[0] == '.') continue;
        if (!it->is_regular_file(ec)) continue;
        ++r.seen;
        std::string lower = name;
        for (char& c : lower) c = (c >= 'A' && c <= 'Z') ? static_cast<char>(c + 32) : c;
        const auto ends_in = [](std::string_view n, const char* e) {
            const std::size_t k = std::strlen(e);
            return n.size() > k && n.compare(n.size() - k, k, e) == 0;
        };
        const auto ends = [&](const char* e) { return ends_in(lower, e); };
        const auto a_dump = [&](std::string_view n) { return std::any_of(std::begin(kDumps), std::end(kDumps), [&](const char* e) { return ends_in(n, e); }); };
        const bool dump = a_dump(lower) || std::any_of(std::begin(kWrappers), std::end(kWrappers), [&](const char* w) {
                              return ends(w) && a_dump(std::string_view(lower).substr(0, lower.size() - std::strlen(w)));
                          });
        if (!dump && (r.dumps_only || !std::any_of(std::begin(kArchives), std::end(kArchives), ends))) continue;
        if (lower == "thumbs.db") continue;  // Windows' thumbnail cache, uploaded with the pictures
        if (application_schema(it->path(), lower)) continue;
        if (lower.ends_with(".sql") && sql_without_rows(it->path())) continue;
        const std::string path = it->path().string();
        const std::string served = path.size() > root.size() && path.compare(0, root.size(), root) == 0 ? path.substr(root.size()) : "/" + name;
        if (std::error_code sec; application_probe(site, served, it->file_size(sec)) && !sec) continue;
        if (listed_public(served)) {
            ++r.listed_public;
            continue;
        }
        const std::uintmax_t size = it->file_size(ec);
        if (r.count++ < ArchivesInRoot::kKept) r.files.push_back({path, served, ec ? 0 : static_cast<std::uint64_t>(size)});
    }
    return r;
}

ArchiveExposure archive_exposure(const Config& cfg, const SiteConfig& site, const std::string& served) {
    std::string error;
    const json::Value pc = path_check(cfg, site, served, error);
    if (!error.empty() || !pc.is_object()) return ArchiveExposure::served;  // cannot tell: the safe side
    if (!pc["refused_by"].is_null()) return ArchiveExposure::owner;          // the site's own refuse pattern
    if (pc.get("decision") == "static") {                                     // the file itself, 200
        const AccessRule* ar = access::rule_for(site, served);
        const AuthRule* pr = access::auth_rule_for(site, served);
        return (ar && !ar->any) || (pr && !pr->open) ? ArchiveExposure::restricted : ArchiveExposure::served;
    }
    // Refused, not found or redirected: by a location the preset brought, or by the owner's (the site
    // file's, a managed site's rules, root additions; a redirect rule is the owner's too).
    return pc["location"].get("from").starts_with("preset:") ? ArchiveExposure::preset : ArchiveExposure::owner;
}

namespace {

// public_archives entries that name a directory without its "/", for the finding's message.
std::string unslashed_note(const std::vector<std::string>& dirs) {
    std::string out;
    for (const auto& d : dirs) out += "; '" + d + "' is a directory: write '" + d + "/' in public_archives for all below it";
    return out;
}

}  // namespace

// The pm the pool file on disk says: php-fpm runs that one until `agensio pools` and a
// reload, whatever the configuration means to (2026-09-23 live report: two pools still
// static on disk held 681 MB while the configuration already said ondemand).
std::string pool_file_pm(const Config& cfg, const PhpPool& pool) {
    const fs::path dir = pools_dir(cfg, "");
    if (dir.empty()) return {};
    std::ifstream in(dir / (pool.name + ".conf"));
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("pm = ", 0) == 0) return line.substr(5);
        if (line.rfind("pm=", 0) == 0) return line.substr(3);
    }
    return {};
}

// The PHP processes of one php-fpm pool, from /proc (Linux; elsewhere none are found):
// php-fpm titles each child "php-fpm: pool NAME", and /proc/PID/status gives VmRSS and
// RssAnon (the private part) for another account's process too. What a pool keeps
// resident is the number an administrator or an agent needs when the machine fills up.
PoolResidency pool_residency(const std::string& pool) {
    PoolResidency r;
#ifdef __linux__
    const std::string title = "php-fpm: pool " + pool;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator("/proc", ec)) {
        const std::string pid = e.path().filename().string();
        if (pid.empty() || !std::isdigit(static_cast<unsigned char>(pid[0]))) continue;
        std::ifstream cmd(e.path() / "cmdline", std::ios::binary);
        std::string line;
        std::getline(cmd, line, '\0');
        if (line.rfind(title, 0) != 0 || (line.size() > title.size() && line[title.size()] != ' ')) continue;
        ++r.processes;
        std::ifstream st(e.path() / "status");
        for (std::string l; std::getline(st, l);) {
            if (l.rfind("VmRSS:", 0) == 0) r.rss_kb += std::strtoull(l.c_str() + 6, nullptr, 10);
            else if (l.rfind("RssAnon:", 0) == 0) r.anon_kb += std::strtoull(l.c_str() + 8, nullptr, 10);
        }
    }
#else
    (void)pool;
#endif
    return r;
}

std::vector<Finding> health_findings(const Config& running, const Config& boot, bool as_root, std::time_t now, const TlsFacts* tls) {
    std::vector<Finding> out;
    auto add = [&](std::string sev, std::string code, std::string site, std::string msg, std::string fix = "") {
        out.push_back(Finding{std::move(sev), std::move(code), std::move(site), std::move(msg), std::move(fix)});
    };
    // Site files set aside (design section 26): by the running configuration, then by the files
    // on disk as the next reload would load them, each file once.
    // A hosting rule's (C2) is a hosting_rule finding: the fix is an owner or a mode, not the file.
    auto held_finding = [&](const Config::HeldBack& h, bool on_disk) {
        const std::string name = fs::path(h.file).filename().string();
        std::string msg = h.hosting ? h.error + "; " + h.file + (on_disk ? " is set aside at the next reload: " : " is set aside: ")
                                    : h.file + (on_disk ? " does not load as it is on disk: " : " was not loaded: ") + h.error + "; ";
        msg += on_disk ? (h.carried ? "the next reload keeps serving the version running now" : "its sites are not served after the next reload")
                       : (h.carried ? "the version loaded before keeps serving its sites" : "its sites are not served");
        if (h.hosting)
            add("error", "hosting_rule", "", std::move(msg),
                "fix the owner or mode the message names, then reload; the other sites are not affected");
        else if (SiteSpec spec; !h.certificate && read_managed(h.file, spec))  // the control plane's own file (alpha.78)
            add("error", "site_file_held_back", spec.domain, std::move(msg),
                "agensio ctl site-update " + spec.domain + " --yes (MCP site_update) renders it again from its first line with this "
                "version, which repairs a form an earlier version wrote; if the error remains, it names what to change through site-update");
        else
            add("error", "site_file_held_back", "", std::move(msg),
                "fix " + name + " (agensio -t names the error), then reload; the other sites are not affected");
    };
    for (const auto& h : running.held_back) held_finding(h, false);
    // The file on disk. Its files set aside are said after the certificates: a served site whose
    // renewed files do not load is certificate_not_loaded, said once.
    std::vector<Config::HeldBack> disk_held;
    try {
        Config fresh = load_config(running.config_path, &running);
        // The hosting rules as a reload applies them (C2): a site breaking one is set aside, named
        // below; what is left (the server's account, the main file's sites) refuses everything.
        const auto hosting = isolate_hosting(fresh, system_facts(), &running);
        check_certificates(fresh, &running);  // and the certificates as the reload loads them (C3)
        // What the next reload would set aside, unless the running server already says so: the
        // same problem may read with or without its history ("the version loaded before breaks it
        // too", the alpha.63 report's finding 2), so one containing the other is the same.
        for (const auto& h : fresh.held_back)
            if (const auto* r = running.held(h.file); !r || (r->error.find(h.error) == std::string::npos && h.error.find(r->error) == std::string::npos))
                disk_held.push_back(h);
        for (const auto& e : hosting)
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
#ifndef _WIN32
    // The site environments' directory (services/appenv.*): open to others, or not its
    // owner's, it stops the tasks of every rails and proxy site (2026-09-27 report: a mkdir
    // under a lax umask left it 0775, and no finding said why every task was refused). Its
    // owner is root when the server drops privileges (the helper writes it), else the server.
    if (std::any_of(running.sites.begin(), running.sites.end(), [](const SiteConfig& x) { return proxy_app(x.app); })) {
        const std::string dir = appenv::dir_of(running.config_path);
        const unsigned owner = boot.user.empty() ? ::geteuid() : 0u;
        struct stat sb {};
        const std::string own = owner == 0 ? "root" : "the server's account";
        if (::lstat(dir.c_str(), &sb) == 0 && !S_ISDIR(sb.st_mode)) {
            add("error", "site_env_unsafe", "", dir + " is not a directory (a symlink or a file): every task of a rails or proxy site is refused and no site environment can be written",
                "as root: mv " + dir + " " + dir + ".refused && mkdir -m 0700 " + dir);
        } else if (::lstat(dir.c_str(), &sb) == 0 && (sb.st_uid != owner || (sb.st_mode & 077) != 0)) {
            const std::string mode = std::to_string((sb.st_mode >> 6) & 7) + std::to_string((sb.st_mode >> 3) & 7) + std::to_string(sb.st_mode & 7);
            add("warn", "site_env_unsafe", "", dir + " is uid " + std::to_string(sb.st_uid) + "'s, mode " + mode + "; it must be " + own + "'s alone (0700): " +
                    (sb.st_uid == owner ? "the next task or site_env call tightens it to 0700 and says so" : "every task of a rails or proxy site is refused until it is"),
                std::string(owner == 0 ? "as root: chown root:root " + dir + " && " : "") + "chmod 0700 " + dir);
        }
    }
#endif

    // Certificates, redirects and port 80: the site's own plain addresses (http, docs/redirects.md
    // 2), or a plain site of its own covering its names.
    auto on_80 = [](const std::vector<std::string>& at) {
        for (const auto& a : at)
            if (a.ends_with(":80")) return true;
        return false;
    };
    auto has_plain = [&](const SiteConfig& tls_site, bool need_redirect, bool need_port_80) {
        if (!tls_site.http_listen.empty() && (!need_redirect || tls_site.http_redirect) && (!need_port_80 || on_80(tls_site.http_listen))) return true;
        for (const auto& p : running.sites) {
            if (p.tls) continue;
            if (need_redirect && !p.http_redirect && !p.redirects_all) continue;
            bool covers = true;
            for (const auto& n : tls_site.server_names)
                covers = covers && std::find(p.server_names.begin(), p.server_names.end(), n) != p.server_names.end();
            if (!covers) continue;
            if (need_port_80 && !on_80(p.listen)) continue;
            return true;
        }
        return false;
    };
    // A certificate or key the server's account cannot read (step T1): read as root at start, it
    // is never read again, so a renewal waits for a restart.
    for (const auto& p : tls_read_problems(running, system_facts()))
        add("warn", "tls_key_unreadable", running.sites[p.site].server_names.front(), p.message, p.fix);
    // The certificates as served (step T2): what clients get is the certificate in memory, which
    // may not be the file on disk (a reload not yet made, a key the server cannot read). Without
    // the running server's facts (the unit tests, an older caller) the file stands in for it.
    auto date = [](std::time_t t) {
        char buf[16] = {};
        std::tm tm{};
        gmtime_r(&t, &tm);
        std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm);
        return std::string(buf);
    };
    for (const auto& s : running.sites) {
        if (!s.tls) continue;
        const std::string name = s.server_names.front();
        const std::size_t findings_before = out.size();
        // With hsts on a visitor cannot click past a certificate error: the findings that lead to
        // one rise a level and say so (docs/redirects.md 4.2).
        const bool hsts = s.hsts == SiteConfig::Hsts::on;
        const std::string hsts_why = hsts ? "; hsts is on, so browsers that saw it refuse the site with a hard error once the certificate expires, "
                                            "with no way past it"
                                          : "";
        const std::string pair = s.tls->cert.string() + '\n' + s.tls->key.string();
        const CertificateState disk = certificate_state(*s.tls, now);
        const CertificateState* served = nullptr;
        if (tls)
            if (auto it = tls->served.find(pair); it != tls->served.end()) served = &it->second;
        const CertificateState& st = served ? *served : disk;
        const std::string what = served ? "the certificate served" : "certificate";
        if (!st.present) {
            add("error", "certificate_unreadable", name, "certificate cannot be read: " + st.error, "check tls.cert");
        } else if (st.placeholder) {
            add("error", "certificate_not_issued", name,
                "still on the placeholder certificate; the ACME order has not succeeded",
                "make sure the names resolve here and port 80 is reachable, then read the acme lines in the error log");
        } else if (st.days_left < 0) {
            add("error", "certificate_expired", name, what + " expired on " + date(st.not_after),
                s.tls->automatic ? "read the acme lines in the error log" : "install a new certificate and reload");
        } else if (!s.tls->automatic && st.days_left < 14) {
            add(hsts ? "error" : "warn", "certificate_expiring", name, what + " expires in " + std::to_string(st.days_left) + " days (" + date(st.not_after) + ")" + hsts_why,
                "renew it and reload, or switch to tls = \"auto\"");
        }
        // A newer certificate on disk than the one served: a reload not yet made, or one that
        // could not load it (the site's file set aside with the certificate's error, C3).
        if (served && disk.present && !disk.fingerprint.empty() && disk.fingerprint != served->fingerprint && disk.not_after > served->not_after) {
            // The server reloads changed files within the hour (the watch, step T3) and at once
            // on cert-renew; when it tried and failed, why.
            std::string reason = "the server loads it at its next hourly check of the files, or now with cert-renew";
            std::string fix = "agensio ctl cert-renew " + name + " (MCP cert_renew) loads it now";
            std::string failed;
            if (auto e = tls->load_errors.find(pair); e != tls->load_errors.end()) failed = e->second;
            for (const auto& h : running.held_back)
                if (failed.empty() && h.file == s.source && h.error.find("certificate could not be loaded") != std::string::npos) failed = h.error;
            // The next reload's view: the site's file would be set aside for it, keeping the
            // certificate served; that is this finding, so it is not said again below.
            for (auto it = disk_held.begin(); it != disk_held.end();)
                if (it->file == s.source && it->certificate && it->carried) {
                    if (failed.empty()) failed = it->error;
                    it = disk_held.erase(it);
                } else
                    ++it;
            if (!failed.empty()) {
                reason = "the server could not load it: " + failed;
                fix = "make the files readable to the server's account (tls_key_unreadable gives the lines) or correct them, then cert-renew " + name;
            }
            add(served->days_left < 7 ? "error" : "warn", "certificate_not_loaded", name,
                "the certificate on disk (valid until " + date(disk.not_after) + ") is not the one served (valid until " + date(served->not_after) +
                    "): " + reason,
                fix);
        }
        // Automatic renewal (ACME orders at a third of the lifetime left, hourly): overdue a day
        // after that point, with the last failure the manager recorded.
        if (s.tls->automatic && served && served->present && !served->placeholder && tls) {
            const std::time_t due = served->not_after - (served->not_after - served->not_before) / 3;
            std::string failure;
            if (auto f = tls->acme_failures.find(s.tls->cert.string()); f != tls->acme_failures.end()) {
                std::tm tm{};
                gmtime_r(&f->second.first, &tm);
                char at[32] = {};
                std::strftime(at, sizeof at, "%Y-%m-%d %H:%M UTC", &tm);
                failure = std::string("the last attempt failed at ") + at + ": " + f->second.second;
            }
            const std::string acme_fix = "make sure every name resolves to this host and port 80 reaches it (HTTP-01), then agensio ctl cert-renew " + name +
                                         " (MCP cert_renew) to try at once";
            if (now > due + 86400)
                add("error", "acme_renewal_overdue", name,
                    "the automatic renewal is overdue: the certificate served expires in " + std::to_string(served->days_left) + " days (" +
                        date(served->not_after) + "), renewal was due on " + date(due) + "; " +
                        (failure.empty() ? std::string("no failed attempt since the start: read the acme lines of the error log") : failure),
                    acme_fix);
            else if (!failure.empty())
                add(hsts ? "error" : "warn", "acme_renewal_failed", name,
                    failure + "; the manager tries again every hour, the certificate served expires in " + std::to_string(served->days_left) + " days (" +
                        date(served->not_after) + ")" + hsts_why,
                    acme_fix);
        }
        if (s.tls->automatic && !has_plain(s, false, true))
            add("warn", "acme_needs_port_80", name, "tls = \"auto\" but nothing answers plain HTTP on port 80 for these names (the CA's HTTP-01 check)",
                s.http == SiteConfig::Http::off && s.http_given ? "remove http = \"off\" (a site on port 443 listens on port 80 beside it), or name the address: http = { listen = [\"0.0.0.0:80\"] }"
                                                                : "name port 80 for the site: http = { listen = [\"0.0.0.0:80\"] }");
        if (!s.http_given && !has_plain(s, true, false))
            add("info", "no_http_redirect", name, "plain HTTP is not redirected to HTTPS for these names: the site listens on no port 443, so it opens no plain listener",
                "name one, and the redirect keeps the site's TLS port: http = { listen = [\"0.0.0.0:80\"] }");
        // hsts_suggested (docs/redirects.md 4.2): HTTPS has proven itself, a real certificate for a
        // week with nothing open about it, and the site has not decided (no hsts line; false is a
        // decided no). Never for a site serving plain HTTP on purpose.
        bool cert_trouble = false;
        for (std::size_t i = findings_before; i < out.size(); ++i)
            cert_trouble = cert_trouble || out[i].code.starts_with("certificate_") || out[i].code.starts_with("acme_renewal");
        // An application that sends its own (Kanboard's ENABLE_HSTS, Rails' force_ssl) is said instead:
        // hsts = true would replace its field, and with a weaker one when it commits to more (the
        // alpha.86 report).
        const auto sent = tls ? tls->application_hsts.find(name) : decltype(tls->application_hsts)::const_iterator{};
        const bool app_sends = tls && sent != tls->application_hsts.end();
        if (s.hsts == SiteConfig::Hsts::unset && s.http != SiteConfig::Http::serve && st.present && !st.placeholder && !cert_trouble &&
            st.not_before > 0 && now - st.not_before >= 7 * 86400 && app_sends) {
            const std::string& value = sent->second.first;
            const HstsValue v = parse_hsts(value);
            const std::string decided = "nothing is needed; hsts = false records that the application's field is the one and silences this "
                                        "(site_update with hsts: false on a managed site)";
            std::string fix;
            if (hsts_stronger(value, "max-age=31536000"))
                fix = decided + "; hsts = true would replace it with a weaker one (a year, this host only), which hsts_narrows_application then reports. "
                      "For agensio to send it on every answer, error pages and files included, match it in a hand-written site file: hsts = { max_age = " +
                      std::to_string(v.max_age) + (v.subdomains ? ", subdomains = true" : "") + " }" +
                      (v.preload ? " (preload, which agensio does not send, stays the application's alone: keep hsts = false for it)" : "");
            else
                fix = decided + "; hsts = true makes agensio send max-age=31536000 on every answer instead, error pages and files included, replacing "
                      "the application's";
            add("info", "hsts_from_application", name,
                "the application sends Strict-Transport-Security: " + value + " itself (seen " + date(sent->second.second) +
                    ") and agensio passes it on, so browsers that see it already keep to HTTPS for this site",
                fix);
        } else if (s.hsts == SiteConfig::Hsts::unset && s.http != SiteConfig::Http::serve && st.present && !st.placeholder && !cert_trouble &&
                   st.not_before > 0 && now - st.not_before >= 7 * 86400)
            add("info", "hsts_suggested", name,
                "HTTPS has served a real certificate since " + date(st.not_before) + " with nothing to report: hsts would tell browsers to use only HTTPS "
                "for this site from their first visit on, and to refuse it on a certificate error rather than let a visitor click past it",
                "when the user agrees: hsts = true in the site file (site_update with hsts: true on a managed site), a year; hsts = false records a "
                "decided no and silences this");
    }
    // The watch of the certificate files (step T3) late by more than one run: a certificate another
    // tool renews (certbot) waits until cert-renew. Said once, for the server; never with nothing served.
    if (tls && tls->watch.interval_s > 0 && !tls->served.empty() && tls->watch.since_s > 2 * tls->watch.interval_s) {
        const auto& w = tls->watch;
        const std::size_t n = tls->served.size();
        add("warn", "certificate_watch_stalled", "",
            std::string(w.runs ? "the certificate watch last ran " + ago_text(static_cast<double>(w.since_s)) + " ago"
                               : "the certificate watch has not run since the start, " + ago_text(static_cast<double>(w.since_s)) + " ago") +
                "; it checks the files of " + std::to_string(n) + (n == 1 ? " certificate " : " certificates ") +
                (w.interval_s == 3600 ? std::string("every hour") : "every " + ago_text(static_cast<double>(w.interval_s))) +
                ", so a certificate renewed on disk by another tool (certbot) is not loaded until it runs",
            "agensio ctl cert-renew NAME --yes (MCP cert_renew) loads a site's renewed files now; a restart of the server starts the watch "
            "again. A watch that stops is a bug: the error log around its last run may say why");
    }
    for (const auto& h : disk_held) held_finding(h, true);  // the next reload's, not said above

    // A per-site log the site user cannot read (created by a reload after the privilege
    // drop, which cannot chown): stands until a restart hands it over.
    {
        const HostFacts facts = system_facts();
        for (const auto& s : running.sites) {
            if (s.user.empty() || s.access_log.empty()) continue;
            unsigned uid = 0, gid = 0;
            if (!facts.user(s.user, uid, gid)) continue;
            if (!s.group.empty()) facts.group(s.group, gid);
            FileFacts f;
            if (facts.stat(s.access_log, f) && f.gid != gid)
                add("warn", "log_not_readable_by_user", s.server_names.front(),
                    s.access_log + " is not owned by group " + (s.group.empty() ? s.user : s.group) + " (gid " + std::to_string(f.gid) +
                        "), so " + s.user + " cannot read its own log",
                    "restart the service: at start the server owns per-site logs agensio:<site group> 0640, or chown it as root");
        }
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
        // PHP writes every upload to the pool's upload_tmp_dir and every session to its
        // save_path (tmp/ and sessions/ below the user's state directory) before an
        // application sees them; a missing or foreign directory fails both silently inside
        // PHP (no 413, no 502, nothing in our logs; 2026-09-20 report). The user's directory
        // is 0700, so the server can judge that directory, not what is inside it.
        const HostFacts facts = system_facts();
        for (const auto& s : running.sites) {
            if (!s.pool.generated) continue;
            unsigned uid = 0, gid = 0;
            const bool known = facts.user(s.user, uid, gid);
            const std::string d = s.pool.state_dir;
            FileFacts f;
            if (!facts.stat(d, f))
                add("error", "php_tmp_missing", s.server_names.front(), "PHP's private directory " + d + " (upload_tmp_dir and session.save_path live below it) does not exist: uploads and sessions fail inside PHP with no error from the server",
                    "agensio pools (creates it as " + s.user + " with tmp/ and sessions/)");
            else if (known && (f.uid != uid || !f.is_dir))
                add("error", "php_tmp_not_owned", s.server_names.front(), "PHP's private directory " + d + " is owned by uid " + std::to_string(f.uid) + ", not by " + s.user + ": PHP cannot write uploads or sessions there",
                    "chown -R " + s.user + " " + d + " && chmod 0700 " + d + " " + d + "/tmp " + d + "/sessions");
        }
        // What a pool keeps resident while its sites are idle (2026-09-21, a live host: 8
        // children per idle site, 150-200 MB each, a 4 GB machine full at 20 sites): static
        // keeps every child, dynamic half of them, ondemand none. One finding per pool.
        std::set<std::string> pools_seen;
        for (const auto& s : running.sites) {
            if (!s.pool.generated || !pools_seen.insert(s.pool.name).second) continue;
            // What php-fpm runs is the pool file on disk, not the configuration's intent.
            const std::string on_disk = pool_file_pm(running, s.pool);
            const std::string pm = on_disk.empty() ? s.pool.pm : on_disk;
            if (pm == "ondemand") continue;
            const bool stale = !on_disk.empty() && on_disk != s.pool.pm;
            const PoolResidency r = pool_residency(s.pool.name);
            const unsigned kept = pm == "static" ? s.pool.children : std::max(1u, s.pool.children / 2);
            std::string msg = "pool " + s.pool.name + " is pm = " + pm + (stale ? " on disk (the configuration says " + s.pool.pm + "; agensio pools has not run)" : "") +
                              ": " + (pm == "static" ? "all " : "at least ") + std::to_string(kept) + " PHP processes stay resident while the site is idle";
            if (r.processes)
                msg += " (now " + std::to_string(r.processes) + " processes, " + std::to_string((r.rss_kb + 512) / 1024) + " MB RSS, " +
                       std::to_string((r.anon_kb + 512) / 1024) + " MB private)";
            add(stale ? "warn" : "info", "php_pool_resident", s.server_names.front(), msg,
                stale ? "run agensio pools, then reload php-fpm: the pool becomes " + s.pool.pm + " as configured"
                      : "site-update " + s.server_names.front() + " --set pm=ondemand (a child starts on the first request and exits after 60 s idle), or keep " +
                            pm + " for a site that must not pay a fork on its first request");
        }
        std::string conf;
        if (php_fpm_hard_reload(running, conf))
            add("info", "php_fpm_hard_reload", "", "php-fpm.conf does not set process_control_timeout, so a php-fpm reload (site-create writing a pool, agensio pools) kills PHP requests in flight on every site",
                "set process_control_timeout = 10s in " + conf + " and reload php-fpm once");
    }

    // A document root whose files belong to another application than the preset says: the
    // borrowed preset's refusals do not fit, and what the application's own .htaccess would
    // have protected is served (2026-09-23: Grav on the drupal preset published its backup).
    for (const auto& s : running.sites) {
        if (s.root.empty() || s.redirects_all || s.app.empty() || s.app == "static" || proxy_app(s.app)) continue;
        const std::string detected = detect_app(s.project_root.empty() ? s.root : s.project_root);
        if (detected.empty() || detected == s.app || detected == "static" || detected == "proxy" || detected == "node" || detected == "php") continue;
        add("warn", "preset_mismatch", s.server_names.front(),
            "the files under " + (s.project_root.empty() ? s.root : s.project_root) + " look like " + detected + " (" + detect_app_marker(detected) +
                "), but app = \"" + s.app + "\": the " + s.app + " preset's refusals do not fit them, and what " + detected +
                "'s own .htaccess would protect may be served",
            "set app = \"" + detected + "\" (site-update " + s.server_names.front() + " with app: " + detected + " for a managed site)");
    }
    // Backup archives and database dumps inside a served tree, each judged by what a request for it gets
    // today (2026-10-17, the alpha.97 discussion): served to anyone, a warning; kept by the preset's
    // defaults alone or served only to some, information (a preset or location change would serve it);
    // refused by the owner's own rule, nothing to say. A static site and one without app for their
    // dumps alone (the alpha.96 report: a dump was downloadable there and health said nothing). What the
    // owner publishes on purpose is listed in public_archives, what stays in the tree goes in refuse.
    for (const auto& s : running.sites) {
        if (s.root.empty() || s.redirects_all || proxy_app(s.app)) continue;
        const ArchivesInRoot a = archives_in_root(s, 2000);
        if (a.count == 0) continue;
        std::vector<const ArchivesInRoot::Found*> open, kept;
        for (const auto& f : a.files) switch (archive_exposure(running, s, f.served)) {
                case ArchiveExposure::served: open.push_back(&f); break;
                case ArchiveExposure::preset:
                case ArchiveExposure::restricted: kept.push_back(&f); break;
                case ArchiveExposure::owner: break;
            }
        const std::size_t unjudged = a.count - a.files.size();  // beyond the files judged: taken as served, the safe side
        const std::size_t open_n = open.size() + unjudged;
        if (open_n == 0 && kept.empty()) continue;
        const auto size = [](std::uint64_t b) {
            return b >= 1024 * 1024 ? std::to_string((b + 512 * 1024) / (1024 * 1024)) + " MB" : std::to_string((b + 512) / 1024) + " KB";
        };
        const auto example = [&](const ArchivesInRoot::Found& f) { return ", e.g. " + f.path + " (served as " + f.served + ", " + size(f.bytes) + ")"; };
        const std::string kind = a.dumps_only ? "database dump(s)" : "archive(s) or database dump(s)";
        const std::string name = s.server_names.empty() ? std::string("*") : s.server_names.front();
        std::string message;
        if (open_n)
            message = std::to_string(open_n) + " " + kind + " under the document root served as they stand: anyone can download them" +
                      (open.empty() ? std::string() : example(*open.front())) +
                      (unjudged ? " (" + std::to_string(unjudged) + " beyond the first " + std::to_string(ArchivesInRoot::kKept) + " not judged, taken as served)" : "");
        if (!kept.empty())
            message += (open_n ? "; " + std::to_string(kept.size()) + " more not served today" : std::to_string(kept.size()) + " " + kind +
                                                                                                  " under the document root not served today") +
                       " (refused by the preset's defaults, or kept to the addresses or the password of a rule, which a change of preset or location would undo)" +
                       example(*kept.front());
        if (a.listed_public) message += ", " + std::to_string(a.listed_public) + " more public on purpose (public_archives)";
        if (a.seen >= 2000) message += ", the first 2000 files looked at";
        message += unslashed_note(a.unslashed);
        const std::string path = json::Value((open.empty() ? kept.front() : open.front())->served).dump();
        add(open_n ? "warn" : "info", "archives_in_root", name, message,
            "ask the owner what each file is, and never decide it alone: a backup or a dump nobody needs is moved out of the document root or deleted "
            "(a backup plugin's directory too), since nothing served should hold a copy of the site; a file published for download on purpose goes in "
            "the site's public_archives, as served: [" + path + "]; a file the application needs where it is, which nobody downloads, goes in refuse: [" +
                path + "], which answers 404 for it and stops this naming it. A directory ending in / covers all below it; a backup or a dump of the "
                "site's own data is never public. A managed site: site_update public_archives or rules.refuse (agensio ctl site-update " + name +
                " --public-archive PATH or --refuse PATH); otherwise the site file's keys");
    }
    // A server that trusts several proxies (two or more named sets: CDNs in front of different
    // sites): a site naming none of its own believes them all, so the customers of one CDN can name
    // the client of a site behind another (2026-10-13, docs/redirects.md 2.4).
    if (std::count_if(running.trusted_proxies_text.begin(), running.trusted_proxies_text.end(), [](const std::string& t) { return !t.empty() && t[0] == '@'; }) >= 2) {
        std::string sites;
        std::size_t n = 0;
        for (const auto& s : running.sites)
            if (!s.own_trusted_proxies && !s.redirects_all) sites += (n++ ? ", " : "") + s.server_names.front();
        std::string sets;
        for (const auto& t : running.trusted_proxies_text) sets += (sets.empty() ? "" : ", ") + t;
        if (n)
            add("info", "site_trusts_every_proxy", n == 1 ? sites : "",
                sites + (n == 1 ? " believes" : " believe") + " every proxy of [server] trusted_proxies (" + sets +
                    "): a request through any of them speaks for " + (n == 1 ? "it" : "them") + ", so a customer of one CDN can name the client of a site behind another",
                "give each site the proxies in front of it: trusted_proxies = [\"@set\"] (site-update NAME --trusted-proxy @set), or [] for a site whose visitors connect directly (--no-trusted-proxies)");
    }
    // Root additions whose site is gone (disabled or deleted, design section 20): the loader
    // keeps them with a warning; this says what to do.
    // Access by client address (docs/configuration.md 19): what the rules may not do as meant.
    for (const auto& n : access_notices(running)) {
        std::string fix;
        if (n.code == "access_allows_proxy") fix = "allow the clients' own addresses and ranges, not the proxy's: behind a trusted proxy the rule judges the X-Forwarded-For client";
        else if (n.code == "access_loopback") fix = "add the local proxy or tunnel to [server] trusted_proxies (127.0.0.1, ::1) so the client it carries is judged, or drop the loopback entry";
        else if (n.code == "access_ipv4_only") fix = "add the client's IPv6 range (its /64) to the rule or to its address set, if it has one";
        else if (n.code == "access_single_ipv6") fix = "allow the /64 the address belongs to";
        else if (n.code == "access_site_restricted") fix = "meant for a staging copy or an internal site; site_update with the rule on / removed when it goes public";
        else if (n.code == "exact_rule_proxied_script") fix = "if the application runs the script's path-info forms (/x.php/anything), make the rule a prefix rule (match = \"prefix\"); otherwise nothing to do";
        else if (n.code == "auth_plain_http") fix = "serve the site over https and drop plain_http from the rule, unless the network is one the user trusts (a LAN tool)";
        else if (n.code == "php_keep_conn_exceeds_children") fix = "remove keep_conn from the site's php table (off by default when the pool has fewer children than workers), or raise children to max_connections x workers";
        else if (n.code == "php_keep_conn_ondemand") fix = "remove keep_conn from the site's php table (off by default with pm = \"ondemand\"), or set pm to \"dynamic\" or \"static\" to keep it";
        else if (n.code == "auth_users_mixed_methods") fix = "give every user of the file one method and cost: agensio passwd NAME writes yescrypt (a managed site's tools always do), then reload";
        add(n.severity == "warning" ? "warn" : "info", n.code, n.site, n.text, fix);
    }
    for (auto& f : auth_findings(running, now)) out.push_back(std::move(f));
    for (const auto& o : running.orphan_additions) {
        std::error_code ec;
        const fs::path f = o.file;
        const bool disabled = fs::exists(f.parent_path() / (o.site + ".toml.disabled"), ec);
        add("warn", "root_additions_orphan", o.site,
            o.file + " holds root additions for site " + o.site + ", which is " + (disabled ? "disabled" : "not in the configuration") + ": its locations are ignored",
            disabled ? "site-enable " + o.site + " brings the site back with its additions; or remove the file"
                     : "remove the file (rm " + o.file + "), or create the site again under that name");
    }
    // Files the server cannot read under a document root (2026-09-20: every upload of every
    // site with a user was 0640 user:user after move_uploaded_file, 404 with no log line).
    {
        const ServerAccount server = server_account(running, system_facts());
        for (const auto& s : running.sites) {
            // A proxy-family site serves nothing from its root (every request goes to the
            // upstream), so what the server cannot read there answers no 404.
            if (s.root.empty() || s.redirects_all || proxy_app(s.app)) continue;
            const UnreadableFiles u = unreadable_files(s, secret_paths(s), 2000);
            if (u.unreadable == 0) continue;
            const FileFacts& f = u.example_facts;
            char mode[8];
            std::snprintf(mode, sizeof mode, "%04o", f.mode & 07777);
            const HostFacts facts = system_facts();
            std::string user = facts.user_name ? facts.user_name(f.uid) : "", group = facts.group_name ? facts.group_name(f.gid) : "";
            const std::string owner = (user.empty() ? std::to_string(f.uid) : user) + ":" + (group.empty() ? std::to_string(f.gid) : group) + " " + mode;
            // The remedy from the example's actual defect: the group, the group-read bit, or both.
            const std::string dir = fs::path(u.example).parent_path().string();
            const std::string sgroup = server.group.empty() ? std::to_string(server.gid) : server.group;
            const bool group_wrong = server.known && f.gid != server.gid, mode_wrong = !(f.mode & 0040);
            std::string fix;
            if (group_wrong && mode_wrong) fix = "chgrp -R " + sgroup + " " + dir + " && chmod -R g+r " + dir;
            else if (group_wrong) fix = "give them the server's group: chgrp -R " + sgroup + " " + dir;
            else if (mode_wrong) fix = "the group is right, the mode is not: chmod -R g+r " + dir;
            else fix = "make " + dir + " readable by " + (server.user.empty() ? "uid " + std::to_string(server.uid) : server.user) + " (a parent directory may lack the execute bit)";
            add("error", "files_unreadable", s.server_names.front(),
                std::to_string(u.unreadable) + " of " + std::to_string(u.seen) + " sampled files under " + s.root + " cannot be read by the server's account (" +
                    (server.user.empty() ? "uid " + std::to_string(server.uid) : server.user) + ") and answer 404 with no log line; for example " + u.example + " (" + owner + ")",
                fix + "; uploads made after agensio pools ran on this build carry the server's group already");
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
    // The files root loads or runs that agensio renders (the alpha.94 report): the fail2ban jail, the
    // firewall ruleset and its unit, the sites' application units, the generated php-fpm pools.
    {
        std::vector<std::string> files{std::string(kJailFile), protection_input(running).firewall_file, "/etc/systemd/system/" + std::string(kFirewallUnit)};
        for (const auto& s : running.sites)
            if (!s.user.empty() && service_app(s.app)) files.push_back("/etc/systemd/system/agensio-app-" + s.user + ".service");
        if (const fs::path dir = pools_dir(running, ""); !dir.empty())
            for (const auto& s : running.sites)
                if (s.pool.generated) files.push_back((dir / (s.pool.name + ".conf")).string());
        std::sort(files.begin(), files.end());
        files.erase(std::unique(files.begin(), files.end()), files.end());
        for (auto& f : root_file_findings(files, system_facts())) out.push_back(std::move(f));
    }
    return out;
}

std::vector<Finding> root_file_findings(const std::vector<std::string>& files, const HostFacts& facts) {
    std::vector<Finding> out;
    for (const auto& f : files) {
        FileFacts st;
        if (!facts.stat || !facts.stat(f, st) || st.is_dir || (st.mode & 022) == 0) continue;
        char mode[8] = {};
        std::snprintf(mode, sizeof mode, "%04o", st.mode & 07777);
        const bool anyone = (st.mode & 002) != 0;
        std::string group = facts.group_name ? facts.group_name(st.gid) : std::string();
        if (group.empty()) group = "gid " + std::to_string(st.gid);
        out.push_back(Finding{anyone ? "error" : "warn", "root_file_writable", "",
                              f + " is " + mode + ": root loads or runs it, so " + (anyone ? std::string("anyone on the host") : "any member of group " + group) +
                                  " can change what root does (a shell's `>` gives the file root's umask; agensio writes it 0644 with --out)",
                              "as root: chmod go-w " + f});
    }
    return out;
}

std::vector<Finding> auth_findings(const Config& cfg, std::time_t now) {
    std::vector<Finding> out;
    auto day = [](std::int64_t t) {
        const std::time_t tt = static_cast<std::time_t>(t);
        std::tm tm{};
        ::gmtime_r(&tt, &tm);
        char buf[16];
        return std::string(buf, std::strftime(buf, sizeof buf, "%Y-%m-%d", &tm));
    };
    auto joined = [](const std::vector<std::string>& v) {
        std::string t;
        for (const auto& x : v) t += (t.empty() ? "" : ", ") + x;
        return t;
    };
    const fs::path config_dir = cfg.config_path.parent_path().empty() ? fs::path(".") : cfg.config_path.parent_path();
    std::error_code ec;
    for (const auto& s : cfg.sites) {
        if (s.auth.empty() || s.server_names.empty()) continue;
        const std::string site = s.server_names.front();
        const std::string own = fs::absolute(config_dir / "auth" / (site + ".users"), ec).lexically_normal().string();
        std::vector<std::string> files;
        for (const auto& r : s.auth) {
            if (r.open || !r.users || std::find(files.begin(), files.end(), r.users_path) != files.end()) continue;
            files.push_back(r.users_path);
            std::vector<std::string> paths;
            for (const auto& q : s.auth)
                if (!q.open && q.users_path == r.users_path) paths.push_back(q.path);
            const std::string where = joined(paths);
            const bool managed = fs::absolute(r.users_path, ec).lexically_normal().string() == own;
            if (const std::string why = auth_users_problem(r.users_path, cfg); !why.empty()) {
                // A site file is set aside without it (design section 26); the main file fails whole.
                const bool in_main = s.source.empty() || s.source == cfg.config_path.string();
                out.push_back(Finding{"error", "auth_users_unloadable", site,
                                      "the users file of " + where + " would be refused by the next load, " +
                                          (in_main ? std::string("so a reload is refused and a restart does not start the server: ")
                                                   : std::string("so a reload keeps this site's running version and a restart does not serve the site: ")) +
                                          why + ". The running server still asks with the users it loaded",
                                      managed ? "put the file back (root keeps it under " + (config_dir / "auth").string() + "), or correct what the message names; "
                                                "`agensio -t` says when the next load accepts it"
                                              : "correct what the message names (root's file, chmod 640, `agensio passwd USER` for a line); `agensio -t` says when "
                                                "the next load accepts it"});
                continue;
            }
            std::vector<std::string> expired, locked;
            std::size_t can = 0;
            for (const auto& u : r.users->users) {
                if (u.locked) locked.push_back(u.name);
                else if (u.expires && now >= u.expires) expired.push_back(u.name + " (expired " + day(u.expires) + ")");
                else ++can;
            }
            if (can == 0) {
                std::vector<std::string> who = expired;
                for (const auto& l : locked) who.push_back(l + " (locked)");
                out.push_back(Finding{"warn", "auth_no_valid_user", site,
                                      "every login on " + where + " fails: no user of " + r.users_path + " can log in (" + joined(who) + "), so the browser asks and asks",
                                      managed ? "site_auth_user_set " + site + " USER with locked: false or a later expires, or a new user with generate: true; "
                                                "or site_update without the rule if the area is closed for good"
                                              : "unlock or extend a user in the file (`agensio passwd USER` for a new line), or remove the rule"});
                continue;
            }
            if (!expired.empty())
                out.push_back(Finding{"info", "auth_users_expired", site, joined(expired) + " can no longer log in on " + where,
                                      managed ? "site_auth_user_delete " + site + " for each one who is gone, or site_auth_user_set with a later expires"
                                              : "remove their lines from " + r.users_path + ", or change their :expires= field"});
        }
        // Plain HTTP on a listener the network reaches: config.cpp access_notices (auth_plain_http), so -t says it too.
    }
    // Users files no site owns: a deleted site's (site_delete without files leaves it). A site
    // created again under the name with a password rule would let those users in.
    const fs::path adir = config_dir / "auth";
    for (const auto& e : fs::directory_iterator(adir, ec)) {
        const std::string name = e.path().filename().string();
        if (!name.ends_with(".users") || !e.is_regular_file(ec)) continue;
        const std::string stem = name.substr(0, name.size() - 6);
        const std::string abs = fs::absolute(e.path(), ec).lexically_normal().string();
        bool used = false;
        for (const auto& s : cfg.sites) {
            used = used || (!s.server_names.empty() && s.server_names.front() == stem);
            for (const auto& r : s.auth) used = used || (!r.users_path.empty() && fs::absolute(r.users_path, ec).lexically_normal().string() == abs);
        }
        if (!used)
            out.push_back(Finding{"info", "auth_users_orphan", "",
                                  e.path().string() + " belongs to no configured site (a deleted site's password users): a site created again as " + stem +
                                      " with a password rule would let them in",
                                  "as root: rm " + e.path().string() + " (unless the site comes back; site_delete with files moves this file into the trash)"});
    }
    return out;
}

std::vector<Finding> env_findings(const json::Value& inspected) {
    std::vector<Finding> out;
    if (inspected["busy"].boolean()) {
        out.push_back(Finding{"info", "site_env_unchecked", "", "the sites' environment files were not checked: the provisioning helper is running a task", "run health_check again when it ends"});
        return out;
    }
    if (!inspected["ok"].boolean()) {
        out.push_back(Finding{"info", "site_env_unchecked", "", "the sites' environment files could not be checked: " + std::string(inspected.get("error")), ""});
        return out;
    }
    for (const auto& f : inspected["sites"].items()) {
        // A site_env_set call is the admin's tool, not a root command: "as root" goes with
        // the chown, chmod and rm lines only (2026-09-27 report: it steered an agent to hand
        // the user a terminal for a tool call).
        const std::string fix(f.get("fix"));
        out.push_back(Finding{std::string(f.get("severity")), "site_env_unsafe", std::string(f.get("site")), std::string(f.get("problem")),
                              fix.empty() ? std::string("fix the file as root, or remove it and set the variables again with site_env_set")
                              : fix.starts_with("site_env_set") ? fix : "as root: " + fix});
    }
    for (const auto& o : inspected["orphans"].items()) {
        const std::string file(o.is_string() ? o.str() : o.get("file"));
        std::string names;
        for (const auto& n : o["exposed"].items()) names += (names.empty() ? "" : ", ") + std::string(n.str());
        if (names.empty())
            out.push_back(Finding{"info", "site_env_orphan", "", file + " belongs to no configured site (a deleted site's environment: its secrets)",
                                  "as root, when the site is gone for good: rm -f " + file});
        else {
            const bool one = o["exposed"].items().size() == 1;  // "KEY_B in it was ... that value", as the other ledger texts agree
            out.push_back(Finding{"warn", "site_env_orphan", "", file + " belongs to no configured site, and " + names + " in it " + (one ? "was" : "were") +
                                      " readable by others and never rotated: bringing the site back with this file brings " + (one ? "that value" : "those values") + " back",
                                  std::string("rotate ") + (one ? "it" : "them") + " after bringing the site back (site_env_set), or as root, when the site is gone for good: rm -f " + file});
        }
    }
    return out;
}

std::vector<Finding> service_findings(const json::Value& check) {
    std::vector<Finding> out;
    if (!check["ok"].boolean()) return out;  // busy, or no systemctl: nothing to say about it
    for (const auto& r : check["services"].items()) {
        const std::string site(r.get("site")), unit(r.get("unit"));
        const json::Value& st = r["state"];
        const std::string load(st.get("LoadState")), active(st.get("ActiveState")), sub(st.get("SubState")), result(st.get("Result"));
        if (load == "not-found") {
            out.push_back(Finding{"info", "site_service_missing", site, "no unit " + unit + ": nothing runs the application, and every request to it answers 502",
                                  "site_service_unit " + site + " renders it; root installs it with the commands in its answer"});
        } else if (active == "failed") {
            out.push_back(Finding{"warn", "site_service_failed", site, unit + " failed (" + result + ", status " + std::string(st.get("ExecMainStatus")) + ", since " +
                                                                            std::string(st.get("InactiveEnterTimestamp")) + "): every request to the site answers 502",
                                  "site_service_logs " + site + " shows why; after the fix, as root: systemctl restart " + unit});
        } else if (active == "inactive") {
            out.push_back(Finding{"warn", "site_service_down", site, unit + " is stopped: every request to the site answers 502",
                                  "as root: systemctl enable --now " + unit + " (site_service_logs " + site + " shows its last run)"});
        } else if (active == "activating" && sub == "auto-restart") {
            out.push_back(Finding{"warn", "site_service_failed", site, unit + " keeps failing and systemd restarts it (" + std::string(st.get("NRestarts")) + " restarts)",
                                  "site_service_logs " + site + " shows why"});
        }
    }
    return out;
}

std::string ago_text(double s) {
    if (s < 60) return std::to_string(static_cast<long>(s)) + " s";
    if (s < 3600) return std::to_string(static_cast<long>(s / 60)) + " min";
    if (s < 86400) return std::to_string(static_cast<long>(s / 3600)) + " h";
    return std::to_string(static_cast<long>(s / 86400)) + " d";
}

Finding refusal_finding(const RefusalReport& r) {
    std::string from;
    for (std::size_t i = 0; i < r.addresses.size() && i < 3; ++i) from += (i ? ", " : "") + r.addresses[i].first + " x" + std::to_string(r.addresses[i].second);
    if (r.addresses.size() > 3) from += " and " + std::to_string(r.addresses.size() - 3) + " more address" + (r.addresses.size() > 4 ? "es" : "");
    else if (r.more_addresses) from += " and more addresses";
    std::string on;
    for (const auto& l : r.listeners) on += (on.empty() ? "" : ", ") + l.first + (r.listeners.size() > 1 ? " x" + std::to_string(l.second) : "");
    const std::uint64_t capacity = r.ceiling * r.workers;
    const std::string msg = std::to_string(r.refused) + " connection(s) refused at the ceiling since start (first " + ago_text(r.first_s_ago) + " ago, last " + ago_text(r.last_s_ago) +
                            " ago)" + (on.empty() ? "" : " on " + on) + (from.empty() ? "" : ", from " + from) + "; the workers hold " + std::to_string(r.connections) + " of " +
                            std::to_string(capacity) + " connections, " + std::to_string(r.idle) + " idle for 2 s or more (server.max_connections " + std::to_string(r.ceiling) +
                            " per worker)";
    const std::uint64_t top = r.addresses.empty() ? 0 : r.addresses.front().second;
    std::string fix;
    if (r.refused >= 2 && top * 2 >= r.refused)
        fix = "most refusals came from " + r.addresses.front().first + ": the ceiling did its job; limit that address in the firewall (the per-address limits protection_show renders: "
              "nftables, ct count per source) and let fail2ban ban repeat offenders from the access log; nothing to raise (docs/configuration.md 18)";
    else if (capacity && r.connections * 10 >= capacity * 9 && r.idle * 2 >= r.connections)
        fix = "the workers are full of idle connections: slow or stuck clients, or a client keeping connections open; compare with the request rate (logs_query on the access log), "
              "lower server.idle_timeout (15 s by default), and limit connections per address in the firewall (docs/configuration.md 18)";
    else
        fix = "legitimate load from many addresses: raise the open-file limit (LimitNOFILE in the unit) or server.max_connections, then reload (docs/configuration.md 18)";
    return Finding{"warn", "connections_refused", "", msg, fix};
}

json::Value health(const Config& running, const Config& boot, bool as_root, std::time_t now, const std::vector<Finding>& extra,
                   const TlsFacts* tls) {
    auto findings = health_findings(running, boot, as_root, now, tls);
    findings.insert(findings.end(), extra.begin(), extra.end());
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
