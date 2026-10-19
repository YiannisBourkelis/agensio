#include "control/probe.hpp"

#include <algorithm>
#include <cstring>
#include <thread>

#ifndef _WIN32
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#ifdef AGENSIO_HAS_TLS
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

namespace agensio::control {

namespace {

std::string lower(std::string_view s) {
    std::string out(s);
    for (auto& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return out;
}

// The application's own address setting, for the fix.
std::string setting_of(const CanonicalProbe& p, const std::string& url) {
    if (p.app == "wordpress")
        return "set WordPress's own address to " + url + ": Settings > General, both WordPress Address (URL) and Site Address (URL), or "
               "wp option update home " + url + " and wp option update siteurl " + url + " (WP_HOME and WP_SITEURL in wp-config.php win when set)";
    if (p.app == "laravel") return "set APP_URL=" + url + " in the application's .env, then php artisan config:clear";
    if (p.app == "drupal") return "set $base_url = '" + url + "' in settings.php, or remove it so Drupal takes the name it is asked";
    if (p.app == "grav") return "set custom_base_url: '" + url + "' in user/config/system.yaml, or remove it";
    if (p.app == "django" || p.app == "wagtail")
        return "the project's own redirect (PREPEND_WWW, a middleware) or Wagtail's Site hostname and WAGTAILADMIN_BASE_URL: make them " + url;
    if (p.app == "redmine") return "Redmine's Administration > Settings > Host name: " + url.substr(url.find("://") + 3);
    return "set the application's own address (its base URL) to " + url;
}

#ifndef _WIN32
// A blocking request over loopback with a deadline per step; "" on any failure.
std::string fetch_head(const CanonicalProbe& p, int timeout_ms) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    if (::getaddrinfo(p.host.c_str(), p.port.c_str(), &hints, &res) != 0 || !res) return {};
    const int fd = ::socket(res->ai_family, res->ai_socktype | SOCK_CLOEXEC, res->ai_protocol);
    if (fd < 0) {
        ::freeaddrinfo(res);
        return {};
    }
    // Connect without blocking past the deadline, then block with timeouts on each read and write.
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
    int rc = ::connect(fd, res->ai_addr, res->ai_addrlen);
    ::freeaddrinfo(res);
    if (rc != 0 && errno == EINPROGRESS) {
        pollfd pf{fd, POLLOUT, 0};
        int err = 0;
        socklen_t len = sizeof err;
        rc = (::poll(&pf, 1, timeout_ms) == 1 && ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) ? 0 : -1;
    }
    if (rc != 0) {
        ::close(fd);
        return {};
    }
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    const std::string request = "GET / HTTP/1.1\r\nHost: " + p.canonical + "\r\nUser-Agent: agensio-health\r\nAccept: */*\r\nConnection: close\r\n\r\n";
    std::string head;
    char buf[4096];
    auto done = [&] { return head.find("\r\n\r\n") != std::string::npos || head.size() > 16384; };
    if (!p.tls) {
        if (::send(fd, request.data(), request.size(), MSG_NOSIGNAL) == static_cast<ssize_t>(request.size()))
            while (!done()) {
                const ssize_t n = ::recv(fd, buf, sizeof buf, 0);
                if (n <= 0) break;
                head.append(buf, static_cast<std::size_t>(n));
            }
        ::close(fd);
        return head;
    }
#ifdef AGENSIO_HAS_TLS
    // Our own listener: nothing to verify, the name only chooses the site's certificate (SNI).
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (ssl && SSL_set_tlsext_host_name(ssl, p.canonical.c_str()) == 1 && SSL_set_fd(ssl, fd) == 1 && SSL_connect(ssl) == 1 &&
        SSL_write(ssl, request.data(), static_cast<int>(request.size())) == static_cast<int>(request.size()))
        while (!done()) {
            const int n = SSL_read(ssl, buf, sizeof buf);
            if (n <= 0) break;
            head.append(buf, static_cast<std::size_t>(n));
        }
    ERR_clear_error();
    if (ssl) SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
#endif
    ::close(fd);
    return head;
}
#endif

#ifndef _WIN32
// Every probe's head, the requests at the same time (at most 32 at once), so health waits for the
// slowest site, not the sum of them.
std::vector<std::string> fetch_heads(const std::vector<CanonicalProbe>& probes, int timeout_ms) {
    std::vector<std::string> heads(probes.size());
    for (std::size_t from = 0; from < probes.size(); from += 32) {
        std::vector<std::thread> batch;
        for (std::size_t i = from; i < std::min(probes.size(), from + 32); ++i)
            batch.emplace_back([&probes, &heads, i, timeout_ms] { heads[i] = fetch_head(probes[i], timeout_ms); });
        for (auto& t : batch) t.join();
    }
    return heads;
}
#endif

// A site's listener as a probe asks it: its first address, a wildcard one over loopback.
void probe_address(const SiteConfig& s, CanonicalProbe& p) {
    const std::string& at = s.listen.front();  // normalised "host:port", an IPv6 host unbracketed
    const std::size_t colon = at.rfind(':');
    p.host = at.substr(0, colon);
    p.port = at.substr(colon + 1);
    if (p.host == "0.0.0.0") p.host = "127.0.0.1";
    else if (p.host == "::") p.host = "::1";
}

}  // namespace

std::vector<CanonicalProbe> canonical_probes(const Config& cfg) {
    std::vector<CanonicalProbe> out;
    for (const auto& s : cfg.sites) {
        if (!s.canonical_redirect || s.listen.empty()) continue;
#ifndef AGENSIO_HAS_TLS
        if (s.tls) continue;
#endif
        CanonicalProbe p;
        p.site = s.server_names.front();
        p.canonical = s.canonical;
        p.app = s.app;
        p.names = s.server_names;
        p.tls = s.tls.has_value();
        probe_address(s, p);
        out.push_back(std::move(p));
    }
    return out;
}

std::optional<Finding> judge_canonical_answer(const CanonicalProbe& p, int status, std::string_view location) {
    if (status < 300 || status > 399) return std::nullopt;
    const std::size_t scheme = location.find("://");
    if (scheme == std::string_view::npos || location.substr(0, scheme).find_first_of("/?#") != std::string_view::npos) return std::nullopt;
    std::string_view authority = location.substr(scheme + 3);
    authority = authority.substr(0, std::min(authority.find_first_of("/?#"), authority.size()));
    if (const std::size_t at = authority.rfind('@'); at != std::string_view::npos) authority.remove_prefix(at + 1);
    std::string_view host = authority;
    if (const std::size_t colon = host.rfind(':'); colon != std::string_view::npos && host.find(']') == std::string_view::npos) host = host.substr(0, colon);
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    const std::string name = lower(host);
    if (name == p.canonical || std::find(p.names.begin(), p.names.end(), name) == p.names.end()) return std::nullopt;
    const std::string url = std::string(p.tls ? "https://" : "http://") + p.canonical;
    return Finding{"warn", "app_redirects_elsewhere", p.site,
                   "the application answers " + url + "/ with a " + std::to_string(status) + " to " + std::string(location) + ", another of the site's names, which " +
                       "agensio sends back to " + p.canonical + " (canonical): browsers go round until they give up (too many redirects)",
                   setting_of(p, url)};
}

std::vector<Finding> run_canonical_probes(const std::vector<CanonicalProbe>& probes, int timeout_ms) {
    std::vector<Finding> out;
#ifndef _WIN32
    const std::vector<std::string> heads = fetch_heads(probes, timeout_ms);
    for (std::size_t n = 0; n < probes.size(); ++n) {
        const CanonicalProbe& p = probes[n];
        const std::string& head = heads[n];
        if (!head.starts_with("HTTP/1.")) continue;
        const std::size_t sp = head.find(' ');
        const int status = sp == std::string::npos ? 0 : std::atoi(head.c_str() + sp + 1);
        std::string location;
        for (std::size_t at = head.find("\r\n"); at != std::string::npos && at + 2 < head.size(); at = head.find("\r\n", at + 2)) {
            const std::size_t end = head.find("\r\n", at + 2);
            const std::string_view line = std::string_view(head).substr(at + 2, end == std::string::npos ? std::string_view::npos : end - at - 2);
            if (line.empty()) break;
            if (line.size() > 9 && lower(line.substr(0, 9)) == "location:") {
                std::string_view v = line.substr(9);
                while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
                location = std::string(v);
            }
        }
        if (auto f = judge_canonical_answer(p, status, location)) out.push_back(std::move(*f));
    }
#else
    (void)probes;
    (void)timeout_ms;
#endif
    return out;
}

std::vector<CanonicalProbe> hsts_probes(const Config& cfg, const TlsFacts& tls, std::time_t now) {
    std::vector<CanonicalProbe> out;
#ifdef AGENSIO_HAS_TLS
    for (const auto& s : cfg.sites) {
        // As hsts_suggested: no hsts line, plain HTTP not served on purpose; an application that can
        // send a field of its own; a real certificate served for a week.
        if (!s.tls || s.hsts != SiteConfig::Hsts::unset || s.http == SiteConfig::Http::serve || s.app.empty() || s.app == "static" || s.listen.empty())
            continue;
        const std::string& name = s.server_names.front();
        if (name == "*" || tls.application_hsts.count(name)) continue;  // already known
        const auto st = tls.served.find(s.tls->cert.string() + '\n' + s.tls->key.string());
        if (st == tls.served.end() || !st->second.present || st->second.placeholder || st->second.not_before <= 0 || now - st->second.not_before < 7 * 86400)
            continue;
        if (auto p = application_hsts_probe(s)) out.push_back(std::move(*p));
    }
#else
    (void)cfg;
    (void)tls;
    (void)now;
#endif
    return out;
}

std::optional<CanonicalProbe> application_hsts_probe(const SiteConfig& s) {
#ifdef AGENSIO_HAS_TLS
    if (!s.tls || s.app.empty() || s.app == "static" || s.listen.empty() || s.server_names.empty() || s.server_names.front() == "*") return std::nullopt;
    CanonicalProbe p;
    p.site = s.server_names.front();
    p.canonical = s.canonical_redirect ? s.canonical : p.site;  // another name is redirected before the application sees it
    p.app = s.app;
    p.names = s.server_names;
    p.tls = true;
    probe_address(s, p);
    return p;
#else
    (void)s;
    return std::nullopt;
#endif
}

void run_hsts_probes(const std::vector<CanonicalProbe>& probes, int timeout_ms) {
#ifndef _WIN32
    (void)fetch_heads(probes, timeout_ms);  // the answers went through the request path, which noted the fields
#else
    (void)probes;
    (void)timeout_ms;
#endif
}

std::vector<CanonicalProbe> header_probes(const Config& cfg, const TlsFacts& tls, std::time_t now) {
    std::vector<CanonicalProbe> out;
#ifdef AGENSIO_HAS_TLS
    for (const auto& s : cfg.sites) {
        if (!s.tls || s.app.empty() || s.listen.empty() || s.redirects_all) continue;
        const std::string& name = s.server_names.front();
        if (name == "*") continue;
        const auto st = tls.served.find(s.tls->cert.string() + '\n' + s.tls->key.string());
        if (st == tls.served.end() || !st->second.present || st->second.placeholder || st->second.not_before <= 0 || now - st->second.not_before < 7 * 86400)
            continue;
        CanonicalProbe p;
        p.site = name;
        p.canonical = s.canonical_redirect ? s.canonical : name;  // another name is redirected before the page
        p.app = s.app;
        p.names = s.server_names;
        p.tls = true;
        p.declined = s.response_headers_offer_declined;
        probe_address(s, p);
        out.push_back(std::move(p));
    }
#else
    (void)cfg;
    (void)tls;
    (void)now;
#endif
    return out;
}

std::optional<Finding> judge_header_answer(const CanonicalProbe& p, int status, const std::vector<std::pair<std::string, std::string>>& fields) {
    if (status < 200 || status > 299) return std::nullopt;  // a redirect, a login, an error: not the page a scanner grades
    auto has = [&](std::string_view name) {
        for (const auto& [n, v] : fields)
            if (lower(n) == name) return true;
        return false;
    };
    bool frame_ancestors = false;
    for (const auto& [n, v] : fields) frame_ancestors = frame_ancestors || (lower(n) == "content-security-policy" && lower(v).find("frame-ancestors") != std::string::npos);
    std::vector<std::string> missing;
    auto need = [&](const char* field, bool present) {
        if (!present && std::find(p.declined.begin(), p.declined.end(), field) == p.declined.end()) missing.emplace_back(field);
    };
    need("X-Frame-Options", has("x-frame-options") || frame_ancestors);
    need("Content-Security-Policy", has("content-security-policy") || has("content-security-policy-report-only"));
    need("Permissions-Policy", has("permissions-policy"));
    need("X-Content-Type-Options", has("x-content-type-options"));
    if (missing.empty()) return std::nullopt;
    std::string list;
    for (const auto& m : missing) list += (list.empty() ? "" : ", ") + m;
    auto missed = [&](const char* f) { return std::find(missing.begin(), missing.end(), f) != missing.end(); };
    std::string fix = "offer them to the user one at a time, with what each could break (path_check on / lists them under response_headers_offer), "
                      "and add the ones agreed through site_update with response_headers";
    if (missed("X-Frame-Options")) fix += "; a frame field only after asking whether another site embeds the pages (WordPress post embeds, a status page, a widget)";
    if (missed("Content-Security-Policy")) fix += "; a CSP as Content-Security-Policy-Report-Only first, as a default, enforced once the browser console stays clean";
    if (missed("X-Content-Type-Options")) fix += "; nosniff on the application's answers only when its scripts carry their types";
    fix += ". A field the user does not want goes in response_headers_offer_declined, which stops this naming it";
    return Finding{"info", "response_headers_suggested", p.site,
                   "the home page (https://" + p.canonical + "/) goes without " + list +
                       ": the application sends none of them and no rule adds them; scanners such as securityheaders.com mark each one missing",
                   fix};
}

std::vector<Finding> run_header_probes(const std::vector<CanonicalProbe>& probes, int timeout_ms) {
    std::vector<Finding> out;
#ifndef _WIN32
    const std::vector<std::string> heads = fetch_heads(probes, timeout_ms);
    for (std::size_t n = 0; n < probes.size(); ++n) {
        const std::string& head = heads[n];
        if (!head.starts_with("HTTP/1.")) continue;  // no answer: health has its own findings for that
        const std::size_t sp = head.find(' ');
        const int status = sp == std::string::npos ? 0 : std::atoi(head.c_str() + sp + 1);
        std::vector<std::pair<std::string, std::string>> fields;
        for (std::size_t at = head.find("\r\n"); at != std::string::npos && at + 2 < head.size(); at = head.find("\r\n", at + 2)) {
            const std::size_t end = head.find("\r\n", at + 2);
            const std::string_view line = std::string_view(head).substr(at + 2, end == std::string::npos ? std::string_view::npos : end - at - 2);
            if (line.empty()) break;
            const std::size_t colon = line.find(':');
            if (colon == std::string_view::npos || colon == 0) continue;
            std::string_view v = line.substr(colon + 1);
            while (!v.empty() && (v.front() == ' ' || v.front() == '\t')) v.remove_prefix(1);
            fields.emplace_back(std::string(line.substr(0, colon)), std::string(v));
        }
        if (auto f = judge_header_answer(probes[n], status, fields)) out.push_back(std::move(*f));
    }
#else
    (void)probes;
    (void)timeout_ms;
#endif
    return out;
}

}  // namespace agensio::control
