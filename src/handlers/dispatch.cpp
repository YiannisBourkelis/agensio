#include "handlers/dispatch.hpp"

#include <cstdio>
#include <ctime>

#include "response.hpp"

#include "core/access.hpp"
#include "core/redirect.hpp"
#include "core/refuse.hpp"
#include "core/site_notices.hpp"
#include "path.hpp"

namespace agensio {

namespace {

// The address an access rule judges: the client a trusted proxy forwarded, else the peer.
const asio::ip::address& client_ip(ConnectionInfo& c) {
    static const asio::ip::address none;  // a connection that cannot say (never in practice): matches no entry
    if (!c.client_address.empty()) return c.client_ip;
    return c.peer ? c.peer->peer_ip() : none;
}

// A site's own trusted_proxies (2026-10-13, docs/redirects.md 2.4): a proxy the server believes and
// this site does not speaks for nobody here, so the request is the peer's own: its address and its
// scheme, for the access and password rules, the logs, PHP and the origin alike.
void apply_site_trust(ConnectionInfo& c, const SiteConfig& site) {
    if (c.peer && in_any(site.trusted_proxies, c.peer->peer_ip())) return;
    c.trusted_peer = false;
    c.client_address = {};
    c.client_ip = asio::ip::address();
    c.forwarded_https = false;
}

// [[site.auth]]: the rule that asks for a password on some reading of the path, or null. An open
// rule decides its path only when no other reading falls under a rule that asks: the stricter wins.
const AuthRule* protecting_rule(const SiteConfig& site, std::string_view path, std::string& scratch) {
    return access::auth_protecting_rule(site, path, scratch);  // shared with path_check and the tests
}

// The location route() returns while a password is being verified: never configured, never served.
const LocationConfig& auth_pending() {
    static const LocationConfig loc = [] {
        LocationConfig l;
        l.path = "/";
        l.kind = HandlerKind::auth;
        l.handler = "auth";
        return l;
    }();
    return loc;
}

// A user name as the log line writes it: quotes, backslashes and bytes outside printable ASCII
// escaped, so a name a client chose cannot forge another field of the line.
std::string log_text(std::string_view v) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const char ch : v.substr(0, 128)) {
        const auto c = static_cast<unsigned char>(ch);
        if (c < 0x20 || c >= 0x7f || c == '"' || c == '\\') {
            out += "\\x";
            out.push_back(kHex[c >> 4]);
            out.push_back(kHex[c & 15]);
        } else {
            out.push_back(ch);
        }
    }
    return out;
}

}  // namespace

// [[site.access]] (core/access.hpp, docs/configuration.md 19). The address is asked for only
// when a rule covers some reading of the path, so a public page of a site with rules costs a
// bit test. One error-log line a second per worker, with the count of those not written.
bool Dispatcher::admit(Stream& s, const SiteConfig& site, std::string_view path, WorkerState& ws) {
    const asio::ip::address* addr = nullptr;
    auto address = [&]() -> const asio::ip::address& {
        if (!addr) addr = &client_ip(s.conn);
        return *addr;
    };
    const access::Decision d = access::decide(site, path, address, ws.access_scratch);
    if (!d.rule) return true;
    const std::string text = address().to_string();
    if (log_ && log_->enabled(LogLevel::warn)) {
        auto line = [&](std::string_view head) {
            std::string l(head);
            l.append(site.server_names.front()).append(" rule ").append(d.rule->path);
            if (d.rule->exact) l.append(" (exact)");
            l.append(" allows ");
            for (std::size_t i = 0; i < d.rule->allow_text.size(); ++i) l.append(i ? ", " : "").append(d.rule->allow_text[i]);
            l.append("; client ").append(text);
            if (!s.conn.client_address.empty() && s.conn.peer)
                l.append(" (from X-Forwarded-For; peer ").append(s.conn.peer->peer_ip().to_string()).append(")");
            l.append(" ").append(s.request.method_name).append(" ").append(path.substr(0, 200));
            return l;
        };
        WorkerState::AccessLog& al = ws.access_log;
        if (d.refuse()) {
            if (ws.now != al.refused_at) {
                std::string l = line("access refused: site ");
                if (al.refused_held) l.append(" (").append(std::to_string(al.refused_held)).append(" more refusals since the last such line, not written)");
                log_->warn(l);
                al.refused_at = ws.now;
                al.refused_held = 0;
            } else {
                ++al.refused_held;
            }
        } else {
            // Report mode: named once a minute per rule and client, at most 16 lines a second.
            const Cidr::Key key = Cidr::key_of(address());
            WorkerState::AccessLog::Seen* slot = nullptr;
            WorkerState::AccessLog::Seen* oldest = &al.seen[0];
            for (auto& e : al.seen) {
                if (e.rule == d.rule && e.client.v6 == key.v6 && e.client.hi == key.hi && e.client.lo == key.lo) slot = &e;
                if (e.at < oldest->at) oldest = &e;
            }
            if (slot && ws.now - slot->at < 60) {
                ++slot->repeats;
            } else {
                if (ws.now != al.report_second) {
                    al.report_second = ws.now;
                    al.report_in_second = 0;
                }
                if (al.report_in_second < 16) {
                    ++al.report_in_second;
                    std::string l = line("access would refuse: site ");
                    if (slot && slot->repeats)
                        l.append(" (").append(std::to_string(slot->repeats)).append(" more requests from this client since its last line)");
                    log_->warn(l);
                    if (!slot) slot = oldest;
                    slot->rule = d.rule;
                    slot->client = key;
                    slot->at = ws.now;
                    slot->repeats = 0;
                } else {
                    ++al.report_unnamed;
                }
            }
        }
    }
    if (!d.refuse()) return true;
    refuse_access(s, text);
    return false;
}

void Dispatcher::access_log_tick(WorkerState& ws, std::time_t now) {
    WorkerState::AccessLog& al = ws.access_log;
    if (!log_ || !log_->enabled(LogLevel::warn)) {
        al.refused_held = al.report_unnamed = 0;
        return;
    }
    if (al.refused_held && now != al.refused_at) {
        log_->warn("access refused: " + std::to_string(al.refused_held) +
                   " more refusals since the last such line, not written (the access log has each 403 with its client)");
        al.refused_held = 0;
        al.refused_at = now;
    }
    if (al.report_unnamed && now != al.report_second) {
        log_->warn("access would refuse: " + std::to_string(al.report_unnamed) +
                   " more requests in report mode since the last such line, not named (more than 16 new clients a second)");
        al.report_unnamed = 0;
    }
}

// [[site.auth]] (design section 25). The client must be on a secure link to be asked: TLS, a
// trusted proxy that forwarded https, or this host itself (behind a trusted proxy, the client it
// names); otherwise it gets 403 unless the rule
// says plain_http = "allow". skip_for lets its clients in without a password. A remembered login
// (this worker's cache) is let in at once; anything else is verified on the pool: the request
// waits, never the worker. Every failure is one `auth failed` line; the challenge is none.
Dispatcher::AuthOutcome Dispatcher::check_auth(Stream& s, const SiteConfig& site, const AuthRule& rule, WorkerState& ws) {
    s.auth.protected_path = true;
    if (!rule.forward_user.empty()) {  // only the server sets this field: a client's own goes
        s.auth.forward_field = rule.forward_user;
        s.request.headers.remove(rule.forward_user);
    }
    auto strip = [&] {
        if (rule.credentials == AuthRule::Credentials::strip) s.request.headers.remove("authorization");
    };
    if (!rule.skip.empty() && in_any(rule.skip, client_ip(s.conn))) {
        // Let in without being asked, so nothing it sends as Authorization was verified: it never
        // reaches the application, whatever `credentials` says (2026-10-09, the alpha.58 report's
        // finding 3: on a site that passes credentials, PHP built PHP_AUTH_USER from any name such
        // a client chose, which an application cannot tell from a verified one).
        s.request.headers.remove("authorization");
        return AuthOutcome::allowed;
    }
    // Secure, or this host itself. Behind a trusted proxy the proxy's report decides: https only
    // when it says the client came over https (X-Forwarded-Proto), local only when the client it
    // names is this host; its own loopback address says nothing (2026-10-09, the alpha.58
    // report's finding 2: a tunnel or TLS terminator on this host relaying a client's plain-HTTP
    // request got it asked, the password then crossing the network in clear).
    const bool via_proxy = s.conn.trusted_peer;
    const bool secure = via_proxy ? s.conn.forwarded_https : s.conn.tls;
    const bool local = via_proxy ? client_ip(s.conn).is_loopback() : s.conn.peer && s.conn.peer->peer_ip().is_loopback();
    if (!rule.plain_http && !secure && !local) {
        auth_plain_http(s);
        return AuthOutcome::answered;
    }
#ifdef AGENSIO_HAS_AUTH
    const std::string_view header = s.request.headers.get("authorization");
    AuthMemo* memo = s.conn.auth_memo;
    if (memo && !header.empty() && memo->users_id == rule.users->id && ws.now < memo->until && memo->value == header &&
        s.auth.result == AuthState::Result::none) {  // this connection's last verified login, the same header: one comparison
        s.auth.user = memo->user;
        strip();
        return AuthOutcome::allowed;
    }
    auto remember = [&](std::string_view user, std::int64_t expires) {
        if (!memo) return;
        memo->value.assign(header);
        memo->users_id = rule.users->id;
        memo->user.assign(user);
        memo->until = expires != 0 ? std::min<std::int64_t>(ws.now + 300, expires) : ws.now + 300;
    };
    const asio::ip::address& client = client_ip(s.conn);
    auth::Credentials c;
    const auth::Parsed parsed = auth::parse_basic(header, ws.auth_scratch, c);
    if (parsed == auth::Parsed::none) {
        auth_challenge(s, rule);
        return AuthOutcome::answered;
    }
    if (parsed == auth::Parsed::malformed) {
        auth_failed_line(client.to_string(), site.server_names.front(), rule.realm, "", "malformed credentials", s.request.method_name, ws.path);
        auth_challenge(s, rule);
        return AuthOutcome::answered;
    }
    switch (s.auth.result) {
        case AuthState::Result::verified: {
            s.auth.user = std::string(c.user);
            std::int64_t expires = 0;
            for (const auth::User& u : rule.users->users)
                if (u.name == c.user) expires = u.expires;
            remember(c.user, expires);
            strip();
            return AuthOutcome::allowed;
        }
        case AuthState::Result::failed:  // logged when the verification ended
            auth_challenge(s, rule);
            return AuthOutcome::answered;
        case AuthState::Result::busy:
            auth_busy(s);
            return AuthOutcome::answered;
        case AuthState::Result::none: break;
    }
    const auth::User* user = nullptr;
    const auth::User* stand_in = nullptr;  // an unknown user is checked against a real entry: the same time
    for (const auth::User& u : rule.users->users) {
        if (!user && u.name == c.user) user = &u;
        if (!stand_in && !u.locked) stand_in = &u;
    }
    const std::string& hash = user ? user->hash : stand_in ? stand_in->hash : rule.users->users.front().hash;
    const auth::Key key = auth::cache_key(c.user, hash, c.password);
    if (user && !user->locked && (user->expires == 0 || ws.now < user->expires) && ws.auth_cache.find(key, ws.now)) {
        s.auth.user = std::string(c.user);
        remember(c.user, user->expires);
        strip();
        return AuthOutcome::allowed;
    }
    if (!verifier_ || ws.auth_inflight >= 8) {  // at most eight hashes per worker at a time; guessing waits its turn
        auth_busy(s);
        return AuthOutcome::answered;
    }
    WorkerState::AuthJob& job = ws.auth_job;
    job.pending = true;
    job.password.assign(c.password);
    job.hash = hash;
    job.user.assign(c.user);
    job.site = site.server_names.front();
    job.realm = rule.realm;
    job.client = client.to_string();
    job.method.assign(s.request.method_name);
    job.path = ws.path;
    job.key = key;
    job.known = user != nullptr;
    job.locked = user && user->locked;
    job.expires = user ? user->expires : 0;
    return AuthOutcome::pending;
#else
    (void)site;
    (void)ws;
    auth_challenge(s, rule);
    return AuthOutcome::answered;
#endif
}

void Dispatcher::start_auth(WorkerState& ws, asio::io_context& ctx, std::function<void(AuthState::Result)> done) {
#ifdef AGENSIO_HAS_AUTH
    auto job = std::make_shared<WorkerState::AuthJob>(std::move(ws.auth_job));
    ws.auth_job = {};
    std::string password = std::move(job->password);
    job->password.clear();
    ++ws.auth_inflight;
    auto finish = [this, &ws, &ctx, job, done](bool ok) {
        asio::post(ctx, [this, &ws, job, done, ok] {
            --ws.auth_inflight;
            const std::time_t now = std::time(nullptr);
            const char* reason = !job->known ? "unknown user" : job->locked ? "locked user" : !ok ? "wrong password"
                                 : (job->expires != 0 && now >= job->expires) ? "expired" : nullptr;
            if (!reason) {
                const std::int64_t until = now + 300;
                ws.auth_cache.insert(job->key, job->expires != 0 ? std::min<std::int64_t>(until, job->expires) : until);
                done(AuthState::Result::verified);
                return;
            }
            auth_failed_line(job->client, job->site, job->realm, job->user, reason, job->method, job->path);
            done(AuthState::Result::failed);
        });
    };
    if (!verifier_ || !verifier_->submit(std::move(password), job->hash, std::move(finish))) {
        --ws.auth_inflight;
        asio::post(ctx, [done] { done(AuthState::Result::busy); });
    }
#else
    (void)ws;
    asio::post(ctx, [done] { done(AuthState::Result::failed); });
#endif
}

// 401 with the challenge (RFC 7617: the realm, charset UTF-8), never stored by a cache; one page
// for a missing, a malformed and a wrong login, so the answer does not tell which it was.
void Dispatcher::auth_challenge(Stream& s, const AuthRule& rule) {
    Response& r = s.response;
    r.reset();
    r.status = 401;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.buffer.assign("<!doctype html><html><head><title>401 Unauthorized</title></head><body><center><h1>401 Unauthorized</h1></center>"
                    "<p><center>This page needs a user name and a password.</center></p><hr><center>agensio</center></body></html>\n");
    r.scratch.assign("Content-Type: text/html; charset=utf-8\r\nWWW-Authenticate: Basic realm=\"");
    r.scratch.append(rule.realm).append("\", charset=\"UTF-8\"\r\nCache-Control: no-store\r\nContent-Length: ");
    r.scratch.append(std::to_string(r.buffer.size())).append("\r\n");
    r.prebuilt_headers = r.scratch;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{std::string_view(r.buffer)};
}

// Over plain HTTP the browser would send the password in clear: no challenge, a page that says so.
void Dispatcher::auth_plain_http(Stream& s) {
    Response& r = s.response;
    r.reset();
    r.status = 403;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.buffer.assign("<!doctype html><html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center>"
                    "<p><center>This page needs a password, which is asked over https only. Open it with https://.</center></p>"
                    "<hr><center>agensio</center></body></html>\n");
    r.scratch.assign("Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: ");
    r.scratch.append(std::to_string(r.buffer.size())).append("\r\n");
    r.prebuilt_headers = r.scratch;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{std::string_view(r.buffer)};
}

// The worker's verifications are all in flight (or the pool's queue is full): try again shortly.
void Dispatcher::auth_busy(Stream& s) {
    Response& r = s.response;
    r.reset();
    r.status = 503;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.buffer.assign("<!doctype html><html><head><title>503 Service Unavailable</title></head><body><center><h1>503 Service Unavailable</h1>"
                    "</center><hr><center>agensio</center></body></html>\n");
    r.scratch.assign("Content-Type: text/html; charset=utf-8\r\nRetry-After: 1\r\nCache-Control: no-store\r\nContent-Length: ");
    r.scratch.append(std::to_string(r.buffer.size())).append("\r\n");
    r.prebuilt_headers = r.scratch;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{std::string_view(r.buffer)};
}

// One line per failed login, for the owner and fail2ban: the client first (a name the client
// chose comes later and is escaped, so it cannot pass for another address), never the password.
void Dispatcher::auth_failed_line(std::string_view client, std::string_view site, std::string_view realm, std::string_view user,
                                  std::string_view reason, std::string_view method, std::string_view path) {
    if (!log_ || !log_->enabled(LogLevel::warn)) return;
    std::string line = "auth failed: client ";
    line.append(client).append(" site ").append(site).append(" realm \"").append(log_text(realm)).append("\" user \"");
    line.append(log_text(user)).append("\" (").append(reason).append(") ").append(log_text(method)).append(" ").append(log_text(path.substr(0, 200)));
    log_->warn(line);
}

// 403 with the address that was tested, so a user whose address changed can say which one the
// server saw; never stored by a shared cache (it differs per client).
void Dispatcher::refuse_access(Stream& s, std::string_view address) {
    Response& r = s.response;
    r.reset();
    r.status = 403;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.buffer.assign("<!doctype html><html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center>"
                    "<p><center>This page is open to some addresses only. Yours, ");
    r.buffer.append(address).append(", is not one of them.</center></p><hr><center>agensio</center></body></html>\n");
    r.scratch.assign("Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: ");
    r.scratch.append(std::to_string(r.buffer.size())).append("\r\n");
    r.prebuilt_headers = r.scratch;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{std::string_view(r.buffer)};
}

namespace {

// A redirect answer: the canned page for its status, the Location, and the cache lifetime when given.
void redirect_answer(Stream& s, int status, std::string_view location, std::string_view cache_control) {
    Response& r = s.response;
    const ErrorPage& page = error_page(status);
    r.status = status;
    r.head = s.request.method == Method::head;
    r.headers.add("Location", location);
    if (!cache_control.empty()) r.headers.add("Cache-Control", cache_control);
    r.prebuilt_headers = page.headers;
    r.prebuilt_h2 = page.h2_headers;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{page.body};
}

void append_target(std::string& location, std::string_view target) {
    if (!target.empty() && target.front() == '/') location.append(target);
    else location.push_back('/');
}

// Certificate validation (docs/redirects.md 1): the ACME HTTP-01 tokens (RFC 8555 8.3) and a CA's
// file check, which a certificate tool writes into the site's root; answered over plain HTTP from
// the site's files before any redirect, so no setting can break a certificate's issue or renewal,
// and from its files only (SiteConfig::validation), so no application runs over plain HTTP there.
bool certificate_validation(std::string_view path) noexcept {
    return path.starts_with("/.well-known/acme-challenge/") || path.starts_with("/.well-known/pki-validation/");
}

}  // namespace

namespace {

// The Host field's name and port ("example.com:8080", "[::1]:8080"), the name without a final dot.
void split_host(std::string_view host, std::string_view& name, std::string_view& port) {
    const std::size_t bracket = host.rfind(']');
    const std::size_t colon = host.rfind(':');
    port = {};
    if (colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket)) {
        port = host.substr(colon + 1);
        host = host.substr(0, colon);
    }
    if (!host.empty() && host.back() == '.') host.remove_suffix(1);
    name = host;
}

// The site's own spelling of `name` when it lists it, else null.
const std::string* listed_name(const SiteConfig& site, std::string_view name) {
    for (const auto& n : site.server_names)
        if (n != "*" && Headers::iequals(n, name)) return &n;
    return nullptr;
}

std::string_view query_of(std::string_view target) noexcept {
    const std::size_t q = target.find('?');
    return q == std::string_view::npos ? std::string_view() : target.substr(q + 1);
}

}  // namespace

// A path rule for this request (docs/redirects.md 5), or null: none on a path `refuse` answers (a
// refused path is never redirected; the route checks it itself before the rules' own step).
const RedirectRule* Dispatcher::path_rule(const SiteConfig& site, Stream& s, WorkerState& ws, bool check_refuse) {
    if (site.redirects.empty()) return nullptr;
    if (check_refuse && !site.refuse.empty() && refuse::decide(site.refuse, ws.path, ws.access_scratch)) return nullptr;
    return redirect::match(site.redirects, ws.path, query_of(s.request.target), ws.encoded_separator);
}

// A rule's answer: 410 Gone, or its status with the Location core/redirect.hpp writes (`origin`
// before a target of the site when the scheme or the host changes in the same hop) and its lifetime.
void Dispatcher::answer_rule(Stream& s, const RedirectRule& r, std::string_view path, std::string_view origin) {
    if (r.status == 410) {
        static_.error(s, 410, s.request.keep_alive);
        return;
    }
    redirect::write_location(s.response.scratch, r, path, query_of(s.request.target), origin);
    redirect_answer(s, r.status, s.response.scratch, r.cache_control);
}

// http = "redirect" (docs/redirects.md 2, 7): 308 to the same name and target over https, on the
// site's TLS port. A name the site lists is written as listed and the answer kept a day (without a
// lifetime Chromium keeps a permanent redirect forever, and a mistake could not be undone); a name
// only a catch-all took is the client's own choice, written as sent and never stored. With
// `canonical`, another listed name goes straight to the canonical one (scheme and host in one hop,
// 1), unless hsts is on: then to its own HTTPS first, so it learns HSTS too (4.3). A path rule joins
// the same hop with its own status (1). An HTTP/1.0 request without Host gets the site's first name.
void Dispatcher::redirect_https(Stream& s, const SiteConfig& site, WorkerState& ws) {
    const Request& req = s.request;
    if (s.conn.trusted_peer) note_scheme_missing(s, site, ws);  // a proxy's request redirected: did it say the scheme?
    std::string_view host, port;
    split_host(req.host.empty() ? std::string_view(site.server_names.front()) : req.host, host, port);
    if (host.empty() || host == "*") {
        static_.error(s, 400, false);
        return;
    }
    const std::string* listed = listed_name(site, host);
    const bool same_name_first = listed && site.canonical_redirect && site.hsts == SiteConfig::Hsts::on && *listed != site.canonical;
    if (listed) host = (site.canonical_redirect && !same_name_first) ? std::string_view(site.canonical) : std::string_view(*listed);
    std::string& origin = ws.redirect_origin;
    origin.assign("https://").append(host);
    if (site.https_port != 443) origin.append(":").append(std::to_string(site.https_port));
    if (!same_name_first)
        if (const RedirectRule* rule = path_rule(site, s, ws, true)) {
            answer_rule(s, *rule, ws.path, origin);
            return;
        }
    std::string& location = s.response.scratch;
    location.assign(origin);
    append_target(location, req.target);
    redirect_answer(s, 308, location, listed ? "max-age=86400" : "no-store");
}

// A trusted proxy that sends no X-Forwarded-Proto (docs/redirects.md 2.4): its requests are taken as
// plain HTTP, never served as HTTPS by guess, so a site that redirects plain HTTP sends every visitor
// who used HTTPS at the proxy round again. The cause goes to health and, once a minute, the error
// log; this worker writes it at most once a minute per site, from its own gate.
void Dispatcher::note_scheme_missing(const Stream& s, const SiteConfig& site, WorkerState& ws) {
    if (s.request.headers.contains("x-forwarded-proto") || site.server_names.empty()) return;
    const std::time_t now = std::time(nullptr);
    WorkerState::NoticeGate* gate = &ws.scheme_noted[0];
    for (auto& g : ws.scheme_noted)
        if (g.site == &site) {
            gate = &g;
            break;
        } else if (g.at < gate->at) {
            gate = &g;
        }
    if (gate->site == &site && now - gate->at < 60) return;
    gate->site = &site;
    gate->at = now;
    const std::string proxy = s.conn.peer ? s.conn.peer->peer_ip().to_string() : std::string(s.conn.remote_address);
    const std::string& name = site.server_names.front();
    if (site_notices().note("proxy_scheme_missing", name, proxy, now) && log_ && log_->enabled(LogLevel::warn))
        log_->warn("proxy " + proxy + " sends no X-Forwarded-Proto to " + name + ", which redirects plain HTTP: its requests are taken as plain HTTP "
                   "and redirected to https://, so a visitor who used HTTPS at the proxy comes back through it and loops; make the proxy send "
                   "X-Forwarded-Proto, or connect it to the site over TLS (docs/redirects.md 2.4)");
}

// canonical (docs/redirects.md 3): a listed name that is not the canonical one gets a 308 to it,
// with the scheme and the port the client used, path and query kept, a day, or a path rule's answer
// under the canonical name in the same hop. False, nothing answered, for the canonical name, a name
// the site does not list (a catch-all's) or none.
bool Dispatcher::redirect_host(Stream& s, const SiteConfig& site, WorkerState& ws) {
    std::string_view host, port;
    split_host(s.request.host, host, port);
    if (host.empty() || Headers::iequals(host, site.canonical) || !listed_name(site, host)) return false;
    std::string& origin = ws.redirect_origin;
    origin.assign(s.conn.tls || s.conn.forwarded_https ? "https://" : "http://").append(site.canonical);
    if (!port.empty() && port.find_first_not_of("0123456789") == std::string_view::npos) origin.append(":").append(port);
    if (const RedirectRule* rule = path_rule(site, s, ws, true)) {
        answer_rule(s, *rule, ws.path, origin);
        return true;
    }
    std::string& location = s.response.scratch;
    location.assign(origin);
    append_target(location, s.request.target);
    redirect_answer(s, 308, location, "max-age=86400");
    return true;
}

// 421 Misdirected Request (RFC 9110 15.5.22): this listener, or on TLS this connection's
// certificate, is not authoritative for the
// name in Host. Constant body, never cacheable, so a proxy or an HTTP/2 client that
// coalesced connections retries on a fresh connection instead of remembering a 404.
void Dispatcher::misdirected(Stream& s) {
    static_.error(s, 421, s.request.keep_alive);
    s.response.headers.add("Cache-Control", "no-store");
}

const LocationConfig* Dispatcher::route(Stream& s, const Router& router, WorkerState& ws) {
    const Request& req = s.request;
    Response& r = s.response;
    r.reset();
    r.keep_alive = req.keep_alive;

    // Bodies on requests nobody reads are drained by the connection after the response
    // (nginx behaviour); oversize bodies were already refused with 413 before we ran.
    if (req.version_minor == 1 && req.host.empty()) {
        static_.error(s, 400, false);
        return nullptr;
    }
    // On TLS the connection is authoritative only for the names of the certificate it
    // presented (RFC 9110 7.4, RFC 6125): a Host outside them is 421 whichever sites the
    // listener holds. A request without a Host (HTTP/1.0) claims no name and goes to the
    // catch-all as before. Plain listeners have no certificate and keep the listener rule.
    const bool unauthoritative = s.conn.cert && !req.host.empty() && !s.conn.cert->covers(req.host);
    if (req.method == Method::options && req.target == "*") {  // server-wide OPTIONS
        const SiteConfig* site = router.site(req.host);
        ws.site = site;
        if (!site || unauthoritative) {
            misdirected(s);
            return nullptr;
        }
        static_.no_content(s, Router::location(*site, "/").allow);
        return nullptr;
    }
    if (!normalize_target(req.target, ws.path, &ws.encoded_separator)) {
        static_.error(s, 400, false);
        return nullptr;
    }
#ifdef _WIN32
    if (!windows_path_ok(ws.path)) {
        static_.error(s, 400, false);
        return nullptr;
    }
#endif
    // ACME HTTP-01 (RFC 8555 section 8.3): the CA fetches the token over plain HTTP on any
    // host, so this runs before site routing and only for the challenge prefix.
    constexpr std::string_view kChallenge = "/.well-known/acme-challenge/";
    if (acme_ && ws.path.starts_with(kChallenge) && acme_->lookup(ws.path.substr(kChallenge.size()), r.buffer)) {
        ws.site = router.site(req.host);
        r.scratch = "Content-Type: text/plain\r\nContent-Length: " + std::to_string(r.buffer.size()) + "\r\n\r\n";
        r.prebuilt_headers = r.scratch;
        r.prebuilt_terminated = true;
        r.head = req.method == Method::head;
        r.body = MemoryBody{std::string_view(r.buffer)};
        return nullptr;
    }
    const SiteConfig* site = router.site(req.host);
    ws.site = site;
    if (!site || unauthoritative) {
        misdirected(s);
        return nullptr;
    }
    if (site->own_trusted_proxies && s.conn.trusted_peer) apply_site_trust(s.conn, *site);  // one flag test elsewhere
    // The site's fields for an HTTPS answer (its hsts, docs/redirects.md 4): from here on every answer
    // carries them, the error pages and redirects below included; a plain one never does (RFC 6797 7.2).
    // A site with no hsts line watches what its application sends instead (4.2), for health.
    if (s.conn.tls || s.conn.forwarded_https) {
        if (!site->tls_fields.empty()) s.fields = &site->tls_fields;
        else if (site->tls_fields.watch_application) s.watch_fields = &site->tls_fields;
    }
    // http = "redirect" (docs/redirects.md 2): plain HTTP, or a request a trusted proxy did not mark
    // https, goes to HTTPS; certificate validation gets the site's files there and nothing else
    // (its validation location, below). canonical (3): another of the site's names goes to the
    // canonical one, with the scheme in one hop; certificate validation over plain HTTP is answered
    // on every name (1). One flag test for a site that does neither.
    bool validation = false;
    if (site->before_routing) {
        const bool plain = !s.conn.tls && !s.conn.forwarded_https;
        const bool validating = plain && certificate_validation(ws.path);
        if (plain && site->http_redirect) {
            if (!validating) {
                redirect_https(s, *site, ws);
                return nullptr;
            }
            validation = true;
        } else {
            if (site->http_redirect) s.https_site = site;  // its application's http:// Locations go out as https:// (2.5)
            if (site->canonical_redirect && !validating && redirect_host(s, *site, ws)) return nullptr;
        }
    }
    // `refuse` and [[site.access]] before any location is chosen: whichever would serve the
    // path (a .php suffix, a proxy) cannot step around them, nginx's regex-location trap. A
    // refused path is 404 for everyone, so it goes first: a restricted client learns nothing.
    if (!site->refuse.empty() && refuse::decide(site->refuse, ws.path, ws.access_scratch)) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    // [[site.redirect]] (docs/redirects.md 5): after refuse, before the access and password rules (a
    // redirect reveals no content, and its target meets its own rules); certificate validation over
    // plain HTTP is answered before any rule (1). One test of an empty set for a site without rules.
    if (!site->redirects.empty() && !(!s.conn.tls && !s.conn.forwarded_https && certificate_validation(ws.path)))
        if (const RedirectRule* rule = redirect::match(site->redirects, ws.path, query_of(req.target), ws.encoded_separator)) {
            answer_rule(s, *rule, ws.path, "");
            return nullptr;
        }
    if (!site->access.empty() && !admit(s, *site, ws.path, ws)) return nullptr;
    // [[site.auth]] after the address rules, before any location is chosen.
    if (!site->auth.empty())
        if (const AuthRule* rule = protecting_rule(*site, ws.path, ws.access_scratch)) switch (check_auth(s, *site, *rule, ws)) {
                case AuthOutcome::allowed: break;
                case AuthOutcome::answered: return nullptr;
                case AuthOutcome::pending: return &auth_pending();
            }
    const LocationConfig* loc = validation ? &site->validation : &Router::location(*site, ws.path);
    // A separator spelled as a percent escape (%2F, %5C) never names a file: 404 before any
    // handler that resolves paths on disk runs, Apache's AllowEncodedSlashes Off (2026-10-02
    // alpha.45 report: /x%2F..%2Fwp-login.php reached the script). A proxied application
    // gets the raw target as nginx hands it on, undecoded, and decides itself (GitLab's API
    // encodes group%2Fproject inside a path segment). One predictable test per request; the
    // site's encoded_slashes = "allow" (Apache's NoDecode, for a front controller that reads
    // REQUEST_URI) is read only once the escape was seen.
    if (ws.encoded_separator && loc->kind != HandlerKind::proxy && !site->encoded_slashes_allow) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    if (!check_method(s, *loc, ws)) return nullptr;
    // Endings refused before an application sees the request (a Rails site's databases,
    // logs and keys wherever they live): the static handler checks its own locations.
    if (loc->kind != HandlerKind::static_ && !loc->deny_suffixes.empty() && refused_suffix(ws.path, loc->deny_suffixes)) {
        static_.error(s, 404, req.keep_alive);
        return nullptr;
    }
    // Static locations answer OPTIONS themselves; an application (FastCGI) gets to see it.
    if (req.method == Method::options && loc->kind == HandlerKind::static_) {
        static_.no_content(s, loc->allow);
        return nullptr;
    }
    return loc;
}

bool Dispatcher::check_method(Stream& s, const LocationConfig& loc, WorkerState& ws) {
    const Request& req = s.request;
    // Methods are a per-location policy: what the handler implements, narrowed by `methods`.
    // TRACE and CONNECT are in no set, so they are always 405.
    ws.method_allowed = (loc.methods & method_bit(req.method)) != 0;
    if (ws.method_allowed) return true;
    const bool application_method = req.method == Method::post || req.method == Method::put ||
                                    req.method == Method::del || req.method == Method::patch;
    bool has_fallback = false;
    for (const TryStep& step : loc.try_files)
        if (step.kind == TryStep::Kind::fallback) has_fallback = true;
    if (loc.kind == HandlerKind::static_ && application_method && has_fallback) return true;
    // A method token nobody knows is syntactically valid, so it is a 405; but it is also
    // what a corrupted request line looks like, so the line is logged, escaped.
    if (req.method == Method::other && log_ && log_->enabled(LogLevel::warn)) {
        std::string line;
        for (unsigned char c : req.method_name) {
            if (c >= 0x20 && c < 0x7f && c != '\\') line.push_back(static_cast<char>(c));
            else { char h[5]; std::snprintf(h, sizeof h, "\\x%02x", c); line += h; }
        }
        log_->warn("unrecognised method '" + line + "' for " + std::string(req.target) + " from " + std::string(s.conn.remote_address) + " (405)");
    }
    static_.error(s, 405, req.keep_alive, loc.allow);
    return false;
}

const LocationConfig* Dispatcher::serve_static(Stream& s, const LocationConfig& loc, WorkerState& ws, int& hops) {
    if (static_.serve_location(s, loc, ws) == StaticHandler::Outcome::done) return nullptr;
    // try_files fallback: ws.path is the new target; route it again, bounded so two
    // locations pointing at each other cannot loop.
    if (++hops > StaticHandler::kMaxInternalRedirects) {
        static_.error(s, 500, s.request.keep_alive);
        return nullptr;
    }
    const auto* site = static_cast<const SiteConfig*>(ws.site);
    if (!site->refuse.empty() && refuse::decide(site->refuse, ws.path, ws.access_scratch)) {  // nor into a refused one
        static_.error(s, 404, s.request.keep_alive);
        return nullptr;
    }
    if (!site->access.empty() && !admit(s, *site, ws.path, ws)) return nullptr;  // a fallback cannot step into a restricted path
    if (!site->auth.empty())  // nor around a password
        if (const AuthRule* rule = protecting_rule(*site, ws.path, ws.access_scratch)) switch (check_auth(s, *site, *rule, ws)) {
                case AuthOutcome::allowed: break;
                case AuthOutcome::answered: return nullptr;
                case AuthOutcome::pending: return &auth_pending();
            }
    const LocationConfig* next = &Router::location(*site, ws.path);
    if (!check_method(s, *next, ws)) return nullptr;
    return next;
}

}  // namespace agensio
