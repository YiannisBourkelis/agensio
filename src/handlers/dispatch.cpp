#include "handlers/dispatch.hpp"

#include <cstdio>
#include <ctime>

#include "response.hpp"

#include "core/access.hpp"
#include "core/refuse.hpp"
#include "path.hpp"

namespace agensio {

namespace {

// The address an access rule judges: the client a trusted proxy forwarded, else the peer.
const asio::ip::address& client_ip(ConnectionInfo& c) {
    static const asio::ip::address none;  // a connection that cannot say (never in practice): matches no entry
    if (!c.client_address.empty()) return c.client_ip;
    return c.peer ? c.peer->peer_ip() : none;
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
        strip();
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

// `redirect = "https"`: 301 to the same host and target over https. The host comes from
// the Host header without its port (the target listens on 443), or from the configured
// prefix; an HTTP/1.0 request without Host gets the site's first name.
void Dispatcher::redirect_https(Stream& s, const SiteConfig& site) {
    const Request& req = s.request;
    Response& r = s.response;
    std::string& location = r.scratch;
    if (site.redirect == "https") {
        std::string_view host = req.host;
        if (host.empty()) host = site.server_names.front();
        const std::size_t bracket = host.rfind(']');
        const std::size_t colon = host.rfind(':');
        if (colon != std::string_view::npos && (bracket == std::string_view::npos || colon > bracket))
            host = host.substr(0, colon);
        if (host.empty() || host == "*") {
            static_.error(s, 400, false);
            return;
        }
        location.assign("https://").append(host);
    } else {
        location.assign(site.redirect);
    }
    if (!req.target.empty() && req.target.front() == '/') location.append(req.target);
    else location.push_back('/');
    const ErrorPage& page = error_page(301);
    r.status = 301;
    r.head = req.method == Method::head;
    r.headers.add("Location", location);
    r.prebuilt_headers = page.headers;
    r.prebuilt_h2 = page.h2_headers;
    r.content_type = "text/html; charset=utf-8";
    r.body = MemoryBody{page.body};
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
    if (!site->redirect.empty()) {
        redirect_https(s, *site);
        return nullptr;
    }
    // `refuse` and [[site.access]] before any location is chosen: whichever would serve the
    // path (a .php suffix, a proxy) cannot step around them, nginx's regex-location trap. A
    // refused path is 404 for everyone, so it goes first: a restricted client learns nothing.
    if (!site->refuse.empty() && refuse::decide(site->refuse, ws.path, ws.access_scratch)) {
        static_.error(s, 404, req.keep_alive);
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
    const LocationConfig* loc = &Router::location(*site, ws.path);
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
