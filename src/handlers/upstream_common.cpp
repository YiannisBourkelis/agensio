#include "handlers/upstream_common.hpp"
#include "compress.hpp"
#include "handlers/compress_answer.hpp"

#include <algorithm>
#include <cerrno>
#include <ctime>
#include <string>
#include <system_error>

#include "core/private_cache.hpp"
#include "core/response_fields.hpp"
#include "core/site_notices.hpp"
#include "core/strings.hpp"
#include "response.hpp"

namespace agensio {

void upstream_error(Stream& s, int status, std::string_view retry_after) {
    Response& r = s.response;
    r.reset();
    const ErrorPage& page = error_page(status);
    r.status = status;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.prebuilt_headers = page.headers;
    r.prebuilt_h2 = page.h2_headers;
    r.prebuilt_h3 = page.h3_headers;
    r.content_type = "text/html; charset=utf-8";
    if (!retry_after.empty()) r.headers.add("Retry-After", retry_after);
    r.body = MemoryBody{page.body};
}

namespace {

struct BodyReader {
    static void step(Stream& s, UpstreamBodyInput& body, std::size_t memory_max, std::vector<char>& chunk,
                     std::shared_ptr<void> holder, std::function<void(bool)> then) {
        StreamBody* src = s.request.body;
        src->async_read(chunk.data(), chunk.size(),
                        [&s, &body, memory_max, &chunk, holder, then = std::move(then)](std::error_code ec,
                                                                                      std::size_t n) mutable {
                            if (ec) return;  // the connection closed itself; nothing to answer
                            if (n == 0) {
                                then(true);
                                return;
                            }
                            body.size += n;
                            if (body.spill.is_open() || body.memory.size() + n > memory_max) {
                                if (!body.spill.is_open()) body.spill = File::temporary();
                                if (!body.spill.is_open() || !body.spill.append(chunk.data(), n)) {
                                    upstream_error(s, 502);
                                    s.response.upstream = "spill_error";
                                    then(false);
                                    return;
                                }
                            } else {
                                body.memory.append(chunk.data(), n);
                            }
                            step(s, body, memory_max, chunk, std::move(holder), std::move(then));
                        });
    }
};

}  // namespace

void collect_request_body(Stream& s, UpstreamBodyInput& body, std::size_t memory_max, std::vector<char>& chunk,
                          std::shared_ptr<void> holder, std::function<void(bool)> then) {
    chunk.resize(64 * 1024);
    BodyReader::step(s, body, memory_max, chunk, std::move(holder), std::move(then));
}

namespace {

// "http(s)://<origin address><rewrite prefix>rest" -> "<scheme>://<host><location prefix>rest".
// The scheme is the origin's: an https origin's redirects name https (before 2026-10-09 they were
// never rewritten, its key carrying the scheme). Without a URI part the origin was asked the path
// untouched, so its root is the site's root and the path stays as it is, nginx's proxy_redirect
// default for a proxy_pass without a URI (before alpha.62 the location's prefix was added again:
// /app/app/landing, the alpha.61 report).
bool rewrite_location(std::string& out, std::string_view value, const Stream& s, const LocationConfig& loc) {
    const bool tls = value.starts_with("https://");
    if (!tls && !value.starts_with("http://")) return false;
    std::string_view rest = value.substr(tls ? 8 : 7);
    std::size_t authority = 0;  // the origin's authority at the start of `rest`, its length; 0 for none
    for (const auto& a : loc.proxy.addresses)
        if (!a.unix && a.tls == tls && rest.starts_with(a.authority())) authority = a.authority().size();
    // The name given to the origin as its Host (host = "<name>"): the origin builds its absolute
    // redirects from it, so a Location naming it points at the origin too, either scheme (alpha.71;
    // nginx and Apache rewrite only the upstream's own URL unless told another name).
    const std::string_view named = loc.proxy.host;
    if (authority == 0 && named != "pass" && named != "upstream" && !named.empty() && rest.size() >= named.size() &&
        Headers::iequals(rest.substr(0, named.size()), named))
        authority = named.size();
    if (authority == 0) return false;
    rest.remove_prefix(authority);
    if (!rest.empty() && rest.front() != '/') return false;  // a longer host name
    const bool https = s.conn.tls || s.conn.forwarded_https;
    if (loc.proxy.rewrite.empty()) {
        out.append(https ? "https://" : "http://").append(s.request.host).append(rest.empty() ? std::string_view("/") : rest);
        return true;
    }
    const std::string_view prefix = loc.proxy.rewrite;
    if (rest.starts_with(prefix)) rest.remove_prefix(prefix.size());
    else if (rest.empty() || rest == "/") rest = {};
    else return false;  // outside the mapped prefix: leave it
    out.append(https ? "https://" : "http://").append(s.request.host).append(loc.path);
    if (!loc.path.empty() && loc.path.back() != '/' && !rest.empty()) out.push_back('/');
    out.append(rest);
    return true;
}

// hsts_narrows_application (docs/redirects.md 4.1): the site's hsts replaces the application's own,
// and one that committed browsers to more is noted, once per generation of the site, so nobody
// weakens it unknowingly. A weaker or equal one is judged again on later answers.
void note_hsts_narrowed(const SiteFields& f, std::string_view app, ErrorLog* log) {
    if (!hsts_stronger(app, f.hsts) || f.hsts_noted.done.exchange(true, std::memory_order_relaxed)) return;
    if (site_notices().note("hsts_narrows_application", f.site, app, std::time(nullptr)) && log && log->enabled(LogLevel::warn))
        log->warn(f.site + ": the application sent Strict-Transport-Security: " + std::string(app) + ", stronger than the site's hsts (" + f.hsts +
                  "), which replaced it; set the site's hsts to the value meant, or hsts = \"application\" to let the application's through (docs/redirects.md 4.1)");
}

// The HSTS a site's application sends where agensio replaces or removes it, noted once per generation
// of the site: a managed site's next change of hsts counts it (docs/redirects.md 4.5) and site_show
// names it. Where it goes out unchanged, health's own request reads it (control/probe.hpp).
void note_application_hsts(const SiteFields& f, std::string_view app) {
    if (!f.application_noted.done.exchange(true, std::memory_order_relaxed))
        site_notices().note("hsts_from_application", f.site, app, std::time(nullptr));
}

bool hidden(std::string_view name, const LocationConfig& loc) {
    for (const auto& h : loc.proxy.hide)
        if (Headers::iequals(h, name)) return true;
    return false;
}

}  // namespace

bool upgrade_location(std::string& out, std::string_view value, const SiteConfig& site) {
    if (value.size() < 8 || !Headers::iequals(value.substr(0, 7), "http://")) return false;
    const std::string_view rest = value.substr(7);
    const std::size_t end = std::min(rest.find_first_of("/?#"), rest.size());
    const std::string_view authority = rest.substr(0, end);
    std::string_view host = authority;
    if (const std::size_t colon = authority.rfind(':'); colon != std::string_view::npos) {
        const std::string_view port = authority.substr(colon + 1);
        host = authority.substr(0, colon);
        if (port != "80" && port != std::to_string(site.https_port)) return false;  // another service's port
    }
    bool named = false;
    for (const auto& n : site.server_names) named = named || (n != "*" && Headers::iequals(n, host));
    if (!named) return false;
    out.append("https://").append(host);
    if (site.https_port != 443) out.append(":").append(std::to_string(site.https_port));
    out.append(rest.substr(end));
    return true;
}

// A Vary value names Accept-Encoding already (case-insensitive, as a member of the list).
static bool vary_lists_accept_encoding(std::string_view v) noexcept {
    std::size_t i = 0;
    while (i <= v.size()) {
        std::size_t j = v.find(',', i);
        if (j == std::string_view::npos) j = v.size();
        std::string_view m = v.substr(i, j - i);
        while (!m.empty() && (m.front() == ' ' || m.front() == '\t')) m.remove_prefix(1);
        while (!m.empty() && (m.back() == ' ' || m.back() == '\t')) m.remove_suffix(1);
        if (Headers::iequals(m, "accept-encoding") || m == "*") return true;
        i = j + 1;
    }
    return false;
}

void apply_upstream_result(Stream& s, UpstreamResult& res, std::unique_ptr<StreamBody> source, const char* log_name,
                           const LocationConfig& loc, ErrorLog* log) {
    Response& r = s.response;
    const bool proxied = loc.kind == HandlerKind::proxy;
    r.reset();
    r.status = res.status;
    r.keep_alive = s.request.keep_alive;
    r.head = s.request.method == Method::head;
    r.upstream = log_name;
    // Head: every upstream field except the ones the writer owns (framing, connection) and
    // the ones we set ourselves (Server, Date), as nginx hides them by default.
    const bool no_body_status = res.status == 204 || res.status == 304 || res.status < 200;
    // A password-protected path (core/private_cache.hpp): the answer is never one a shared cache
    // may keep, whatever the application said; an open path pays one test per field.
    const bool guarded = s.auth.protected_path;
    // The site's hsts replaces the application's own (docs/redirects.md 4.1): one field, the site's;
    // hsts = "none" removes it (4.2).
    const bool site_hsts = s.fields && (!s.fields->hsts.empty() || s.fields->strip_hsts);
    // The site's [[site.response_headers]] for the path (docs/headers.md 2), decided here, in the loop
    // that reads every field the application sent: set and remove drop its copies, a copy answers a
    // default, then the rules' own lines, then the guards. Never on a 1xx.
    const HeaderSet* rules = s.header_node && res.status >= 200
                                 ? (response_fields::success(res.status) ? &s.header_node->success : &s.header_node->other)
                                 : nullptr;
    if (rules && rules->empty()) rules = nullptr;
    // Configured response fields, on the statuses nginx's add_header applies to.
    const int st = res.status;
    const bool add_status = st == 200 || st == 201 || st == 204 || st == 206 || st == 301 || st == 302 || st == 303 || st == 304 ||
                            st == 307 || st == 308;
    // A rule's cache decision reads what the answer says to caches first (docs/headers.md 2.4): the
    // application's restrictions stand, and an answer that is one user's gets no shared lifetime.
    response_fields::Upstream seen;
    if (rules && rules->cache_watch && !guarded) {
        for (const HeaderField& h : res.headers)
            if (!(proxied && hidden(h.name, loc))) response_fields::note_cache(*rules, h.name, h.value, seen);
        if (add_status)
            for (const auto& h : loc.add_headers) response_fields::note_cache(*rules, h.first, h.second, seen);
        seen.personal = seen.personal || !s.request.headers.get("authorization").empty();
        response_fields::settle(*rules, seen);
    }
    r.fields_decided = true;
    // response_compression (docs/design-compression.md 6): the fields the decision reads, gathered in
    // one pass the loop below repeats; a site without the key pays one null test. A buffered answer
    // that qualifies is compressed whole after the loop; its ETag is weakened and Vary merged inside it.
    compress_answer::Answer ca;
    ca.status = res.status;
    ca.body_size = res.body_size;
    ca.streamed = res.streamed;
    ca.head = s.request.method == Method::head;
    if (s.site_compression) {
        for (const HeaderField& h : res.headers) {
            if (Headers::iequals(h.name, "content-type")) ca.content_type = h.value;
            else if (Headers::iequals(h.name, "content-encoding")) ca.content_encoding = h.value;
            else if (Headers::iequals(h.name, "cache-control")) ca.cache_control = h.value;
            else if (Headers::iequals(h.name, "content-range")) ca.content_range = true;
        }
    }
    const compress_answer::Reason why = compress_answer::decide(s, ca);
    // The coding is the client's choice among the site's, made once at routing (Stream::coding). A
    // HEAD gets the GET's negotiation (docs/design-compression.md 8): the same head, nothing to compress.
    const bool compressing = why == compress_answer::Reason::compress || why == compress_answer::Reason::head;
    const Encoding coding = static_cast<Encoding>(s.coding);
    // An answer that could have been compressed for another client gets Vary too (RFC 9110 12.5.5):
    // one for a client without an acceptable coding, a HEAD, one the application compressed itself
    // (PHP's zlib layer leaves Vary off the identity variant), one under min_size, one above the
    // whole-answer limit (compressed from step 6 on).
    const bool vary = s.site_compression && (compressing || why == compress_answer::Reason::no_accept || why == compress_answer::Reason::head ||
                                             why == compress_answer::Reason::already_encoded || why == compress_answer::Reason::large ||
                                             (why == compress_answer::Reason::size && ca.body_size > 0));
    bool vary_seen = false;
    const bool rewrite = proxied && loc.proxy.rewrite_redirects;
    std::string kept;  // the application's Cache-Control directives a protected answer keeps
    r.scratch.reserve(res.head.size() + 64);
    // The application's Content-Length is the body's on a GET (written below from what was
    // collected) and the GET's length on a HEAD, kept when it is a number (RFC 9110 8.6).
    std::string_view app_length;
    for (const HeaderField& h : res.headers) {
        if (Headers::iequals(h.name, "content-length")) {
            if (ca.head && !h.value.empty() && h.value.find_first_not_of("0123456789") == std::string_view::npos) app_length = h.value;
            continue;
        }
        if (Headers::iequals(h.name, "transfer-encoding") || Headers::iequals(h.name, "connection") ||
            Headers::iequals(h.name, "keep-alive") || Headers::iequals(h.name, "server") || Headers::iequals(h.name, "date"))
            continue;
        // A field the proxy hides is gone before anything looks at it: no rule's default takes it for
        // the application's copy (before 2026-10-18 a hidden field and a default on it sent neither),
        // and neither the password guard nor the HSTS notes read it.
        if (proxied && hidden(h.name, loc)) continue;
        if (site_hsts && Headers::iequals(h.name, "strict-transport-security")) {
            if (!s.fields->hsts.empty() && h.value != s.fields->hsts && !s.fields->hsts_noted.done.load(std::memory_order_relaxed))
                note_hsts_narrowed(*s.fields, h.value, log);
            // Replaced or removed, but known: a managed site's next change counts it (docs/redirects.md 4.5).
            if (!s.fields->application_noted.done.load(std::memory_order_relaxed)) note_application_hsts(*s.fields, h.value);
            continue;
        }
        if (rules && !response_fields::keep_upstream(*rules, h.name, guarded, seen)) continue;
        if (guarded) {
            if (Headers::iequals(h.name, "cache-control")) {
                private_cache::keep_directives(h.value, kept);
                continue;
            }
            if (private_cache::shared_only_field(h.name)) continue;
        }
        if (s.site_compression) {
            if (vary && Headers::iequals(h.name, "vary")) {  // merged into the application's one field
                vary_seen = true;
                r.scratch.append("Vary: ").append(h.value);
                if (!vary_lists_accept_encoding(h.value)) r.scratch.append(", Accept-Encoding");
                r.scratch.append("\r\n");
                continue;
            }
            if (Headers::iequals(h.name, "content-encoding") && Headers::iequals(h.value, "identity")) continue;  // the application's opt-out, dropped (RFC 9110 8.4)
            if (compressing) {
                if (Headers::iequals(h.name, "etag") && !(h.value.size() >= 2 && h.value[0] == 'W' && h.value[1] == '/')) {
                    r.scratch.append("ETag: W/").append(h.value).append("\r\n");  // the coded representation shares it: weak (RFC 9110 8.8.1)
                    continue;
                }
                if (Headers::iequals(h.name, "accept-ranges") || Headers::iequals(h.name, "content-md5")) continue;  // of the identity bytes
            }
        }
        // A Location naming the origin is the site's (proxy.redirects); one naming the site over
        // http:// on a site whose plain HTTP redirects is https:// (docs/redirects.md 2.5).
        if ((rewrite || s.https_site) && Headers::iequals(h.name, "location")) {
            r.scratch.append("Location: ");
            if (!(rewrite && rewrite_location(r.scratch, h.value, s, loc)) && !(s.https_site && upgrade_location(r.scratch, h.value, *s.https_site)))
                r.scratch.append(h.value);
            r.scratch.append("\r\n");
            continue;
        }
        r.scratch.append(h.name).append(": ").append(h.value).append("\r\n");
    }
    // 101: the writer adds no framing (no body) and the client needs the switch confirmed.
    if (res.upgraded) r.scratch.append("Connection: upgrade\r\n");
    if (add_status)
        for (const auto& h : loc.add_headers) {
            if (rules && !response_fields::keep_upstream(*rules, h.first, guarded, seen)) continue;
            if (guarded && Headers::iequals(h.first, "cache-control")) {
                private_cache::keep_directives(h.second, kept);
                continue;
            }
            if (guarded && private_cache::shared_only_field(h.first)) continue;
            r.scratch.append(h.first).append(": ").append(h.second).append("\r\n");
        }
    if (rules) response_fields::append_upstream(r.scratch, *rules, guarded, seen);
    if (guarded) r.scratch.append("Cache-Control: private").append(kept.empty() ? "" : ", ").append(kept).append("\r\n");
    if (vary && !vary_seen) r.scratch.append("Vary: Accept-Encoding\r\n");
    if (compressing && ca.head) {
        // The coding the GET would carry, no Content-Length: the compressed length is not known from
        // the head alone, and 0, the length of an empty encoded stream, would be a lie (RFC 9110 8.6).
        r.scratch.append("Content-Encoding: ").append(encoding_name(coding)).append("\r\n");
        r.prebuilt_headers = r.scratch;
        return;
    }
    if (compressing && !no_body_status && !res.spill.is_open()) {
        // The whole buffered body through the coding's encoder (docs/design-compression.md 6), padded
        // by a length drawn per answer where the site compresses signed-in visitors' answers too
        // (design 7); the compressed bytes replace it, with their exact length. A failure, or no
        // gain, sends the body as it came (the head has no coding line yet).
        const auto* site = static_cast<const SiteConfig::Compression*>(s.site_compression);
        const auto* root = static_cast<const CompressionConfig*>(s.root_compression);
        std::string& out = r.buffer;
        const unsigned padding = site->signed_in ? padding_length() : 0;
        if (compress_buffered(coding, compress_answer::level_for(*root, coding), padding, res.body, out) && out.size() < res.body.size()) {
            r.scratch.append("Content-Encoding: ").append(encoding_name(coding)).append("\r\nContent-Length: ");
            append_number(r.scratch, out.size());
            r.scratch.append("\r\n");
            r.prebuilt_headers = r.scratch;
            r.body = MemoryBody{std::string_view(r.buffer)};
            return;
        }
        out.clear();
    }
    if (res.streamed) {  // buffering off, or the temp-file cap switched it mid-response
        r.prebuilt_headers = r.scratch;  // the writer adds Content-Length or chunked framing
        if (!no_body_status) r.body = std::move(source);
        return;
    }
    if (!no_body_status) {
        // A HEAD's collected body is empty (php-fpm runs the script and sends its headers alone, the
        // HTTP client reads no body after a HEAD) and its length is not the GET's: the application's
        // own Content-Length when it sent one, else none, as nginx does (RFC 9110 8.6). Until
        // 2026-10-30 every HEAD answered here said Content-Length: 0, and a cache refreshing its
        // copy of the page with a HEAD takes a differing length as an invalidation (RFC 9111 4.3.5).
        if (!r.head) {
            r.scratch.append("Content-Length: ");
            append_number(r.scratch, res.body_size);
            r.scratch.append("\r\n");
        } else if (!app_length.empty()) {
            r.scratch.append("Content-Length: ").append(app_length).append("\r\n");
        }
    }
    r.prebuilt_headers = r.scratch;
    if (no_body_status) return;
    if (res.spill.is_open()) {
        r.owned_file = std::move(res.spill);
        r.body = FileBody{&r.owned_file, res.body_size, 0};
    } else {
        r.buffer = std::move(res.body);
        r.body = MemoryBody{std::string_view(r.buffer)};
    }
}

}  // namespace agensio
