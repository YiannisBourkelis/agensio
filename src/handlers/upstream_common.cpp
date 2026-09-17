#include "handlers/upstream_common.hpp"

#include <cerrno>
#include <system_error>

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

// "http://<origin address><rewrite prefix>rest" -> "<scheme>://<host><location prefix>rest".
bool rewrite_location(std::string& out, std::string_view value, const Stream& s, const LocationConfig& loc) {
    if (!value.starts_with("http://")) return false;
    std::string_view rest = value.substr(7);
    const UpstreamAddress* origin = nullptr;
    for (const auto& a : loc.proxy.addresses)
        if (!a.unix && rest.starts_with(a.key)) origin = &a;
    if (!origin) return false;
    rest.remove_prefix(origin->key.size());
    if (!rest.empty() && rest.front() != '/') return false;  // a longer host name
    const std::string_view prefix = loc.proxy.rewrite.empty() ? std::string_view("/") : loc.proxy.rewrite;
    if (rest.starts_with(prefix)) rest.remove_prefix(prefix.size());
    else if (rest.empty() || rest == "/") rest = {};
    else return false;  // outside the mapped prefix: leave it
    const bool https = s.conn.tls || s.conn.forwarded_https;
    out.append(https ? "https://" : "http://").append(s.request.host).append(loc.path);
    if (!loc.path.empty() && loc.path.back() != '/' && !rest.empty()) out.push_back('/');
    out.append(rest);
    return true;
}

bool hidden(std::string_view name, const LocationConfig& loc) {
    for (const auto& h : loc.proxy.hide)
        if (Headers::iequals(h, name)) return true;
    return false;
}

}  // namespace

void apply_upstream_result(Stream& s, UpstreamResult& res, std::unique_ptr<StreamBody> source, const char* log_name,
                           const LocationConfig& loc) {
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
    r.scratch.reserve(res.head.size() + 64);
    for (const HeaderField& h : res.headers) {
        if (Headers::iequals(h.name, "content-length") || Headers::iequals(h.name, "transfer-encoding") ||
            Headers::iequals(h.name, "connection") || Headers::iequals(h.name, "keep-alive") ||
            Headers::iequals(h.name, "server") || Headers::iequals(h.name, "date"))
            continue;
        if (proxied && hidden(h.name, loc)) continue;
        if (proxied && loc.proxy.rewrite_redirects && Headers::iequals(h.name, "location")) {
            r.scratch.append("Location: ");
            if (!rewrite_location(r.scratch, h.value, s, loc)) r.scratch.append(h.value);
            r.scratch.append("\r\n");
            continue;
        }
        r.scratch.append(h.name).append(": ").append(h.value).append("\r\n");
    }
    // 101: the writer adds no framing (no body) and the client needs the switch confirmed.
    if (res.upgraded) r.scratch.append("Connection: upgrade\r\n");
    // Configured response fields, on the statuses nginx's add_header applies to.
    const int st = res.status;
    if (st == 200 || st == 201 || st == 204 || st == 206 || st == 301 || st == 302 || st == 303 || st == 304 ||
        st == 307 || st == 308)
        for (const auto& h : loc.add_headers) r.scratch.append(h.first).append(": ").append(h.second).append("\r\n");
    if (res.streamed) {  // buffering off, or the temp-file cap switched it mid-response
        r.prebuilt_headers = r.scratch;  // the writer adds Content-Length or chunked framing
        if (!no_body_status) r.body = std::move(source);
        return;
    }
    if (!no_body_status) {
        r.scratch.append("Content-Length: ");
        append_number(r.scratch, res.body_size);
        r.scratch.append("\r\n");
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
