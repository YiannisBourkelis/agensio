#include "handlers/httparena.hpp"

#include <charconv>
#include <fstream>
#include <sstream>

#include "core/strings.hpp"
#include "http2/hpack.hpp"
#include "services/json.hpp"

namespace agensio {

namespace {

// The arena's integer: optional blanks, an optional minus, digits; anything else ends it.
std::int64_t parse_int(std::string_view s) noexcept {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
    bool neg = false;
    if (i < s.size() && s[i] == '-') {
        neg = true;
        ++i;
    }
    std::int64_t n = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9') n = n * 10 + (s[i++] - '0');
    return neg ? -n : n;
}

// The sum of every argument's value, whatever its name: "a=13&b=42" is 55.
std::int64_t sum_args(std::string_view query) noexcept {
    std::int64_t sum = 0;
    while (!query.empty()) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq == std::string_view::npos) break;
        sum += parse_int(pair.substr(eq + 1));
        if (amp == std::string_view::npos) break;
        query.remove_prefix(amp + 1);
    }
    return sum;
}

std::string_view query_of(std::string_view target) noexcept {
    const std::size_t q = target.find('?');
    return q == std::string_view::npos ? std::string_view{} : target.substr(q + 1);
}

std::string_view arg(std::string_view query, std::string_view name) noexcept {
    while (!query.empty()) {
        const std::size_t amp = query.find('&');
        const std::string_view pair = query.substr(0, amp);
        const std::size_t eq = pair.find('=');
        if (eq != std::string_view::npos && pair.substr(0, eq) == name) return pair.substr(eq + 1);
        if (amp == std::string_view::npos) break;
        query.remove_prefix(amp + 1);
    }
    return {};
}

void append_int(std::string& out, std::int64_t v) {
    char buf[24];
    const auto end = std::to_chars(buf, buf + sizeof buf, v).ptr;
    out.append(buf, end);
}

void append_json_string(std::string& out, std::string_view s) {
    out.push_back('"');
    for (const unsigned char c : s) {
        switch (c) {
            case '"': out.append("\\\""); break;
            case '\\': out.append("\\\\"); break;
            case '\n': out.append("\\n"); break;
            case '\r': out.append("\\r"); break;
            case '\t': out.append("\\t"); break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof buf, "\\u%04x", c);
                    out.append(buf);
                } else out.push_back(static_cast<char>(c));
        }
    }
    out.push_back('"');
}

// A small text answer: the head in scratch, the body in buffer (both owned by the response).
// The head for a body of `length` bytes: the HTTP/1 text block, and behind it in the same
// scratch the HTTP/2 tail (content-length as an HPACK literal; the type goes through the
// connection's table), so neither protocol parses text per answer.
void head(Response& r, int status, std::string_view type, std::size_t length) {
    r.status = status;
    r.scratch.assign("Content-Type: ").append(type).append("\r\nContent-Length: ");
    append_number(r.scratch, length);
    r.scratch.append("\r\n\r\n");
    const std::size_t text = r.scratch.size();
    char digits[24];
    const auto end = std::to_chars(digits, digits + sizeof digits, length).ptr;
    hpack::append_literal(r.scratch, 28, std::string_view(digits, static_cast<std::size_t>(end - digits)));  // 28: content-length
    r.prebuilt_headers = std::string_view(r.scratch).substr(0, text);
    r.prebuilt_terminated = true;
    r.prebuilt_h2 = std::string_view(r.scratch).substr(text);
    r.content_type = type;
    r.body = MemoryBody{std::string_view(r.buffer)};
}

void answer(Response& r, int status, std::string_view type, std::string_view body) {
    r.buffer.assign(body);
    head(r, status, type, body.size());
}

// The body is already in r.buffer: the head goes around it.
void answer_buffer(Response& r, int status, std::string_view type) { head(r, status, type, r.buffer.size()); }

void answer_sum(Response& r, std::int64_t sum) {
    char digits[24];
    const auto end = std::to_chars(digits, digits + sizeof digits, sum).ptr;
    answer(r, 200, "text/plain", std::string_view(digits, static_cast<std::size_t>(end - digits)));
}

// A POST's body, at most 64 bytes of it like the nginx module keeps, read through the
// connection's pull source; one small allocation per POST for the continuation.
struct PostRead {
    Stream* s;
    std::int64_t sum;
    std::function<void()> done;
    std::size_t len = 0;
};

void read_post(std::shared_ptr<PostRead> st) {
    Stream& s = *st->s;
    Response& r = s.response;
    if (r.buffer.size() < 64) r.buffer.resize(64);
    if (st->len >= 64) {
        r.buffer.resize(st->len);
        const std::int64_t sum = st->sum + parse_int(r.buffer);
        answer_sum(r, sum);
        st->done();
        return;
    }
    s.request.body->async_read(r.buffer.data() + st->len, 64 - st->len, [st](std::error_code ec, std::size_t n) {
        if (ec) return;  // the client vanished: the connection closes on its own
        if (n == 0) {
            Response& rr = st->s->response;
            rr.buffer.resize(st->len);
            const std::int64_t sum = st->sum + (st->len ? parse_int(rr.buffer) : 0);
            answer_sum(rr, sum);
            st->done();
            return;
        }
        st->len += n;
        read_post(st);
    });
}

}  // namespace

std::shared_ptr<const HttparenaDataset> load_httparena_dataset(const std::string& path, std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open " + path;
        return nullptr;
    }
    std::stringstream text;
    text << in.rdbuf();
    json::Value root;
    if (!json::parse(text.str(), root, error) || !root.is_array()) {
        if (error.empty()) error = "not a JSON array";
        error = path + ": " + error;
        return nullptr;
    }
    auto ds = std::make_shared<HttparenaDataset>();
    for (const json::Value& it : root.items()) {
        HttparenaDataset::Item item;
        const std::int64_t price = static_cast<std::int64_t>(it["price"].num());
        const std::int64_t quantity = static_cast<std::int64_t>(it["quantity"].num());
        item.pq = price * quantity;
        std::string& p = item.prefix;
        p.append("{\"id\":");
        append_int(p, static_cast<std::int64_t>(it["id"].num()));
        p.append(",\"name\":");
        append_json_string(p, it.get("name"));
        p.append(",\"category\":");
        append_json_string(p, it.get("category"));
        p.append(",\"price\":");
        append_int(p, price);
        p.append(",\"quantity\":");
        append_int(p, quantity);
        p.append(",\"active\":").append(it["active"].boolean() ? "true" : "false").append(",\"tags\":[");
        bool first = true;
        for (const json::Value& t : it["tags"].items()) {
            if (!first) p.push_back(',');
            first = false;
            append_json_string(p, t.str());
        }
        p.append("],\"rating\":{\"score\":");
        append_int(p, static_cast<std::int64_t>(it["rating"]["score"].num()));
        p.append(",\"count\":");
        append_int(p, static_cast<std::int64_t>(it["rating"]["count"].num()));
        p.append("},\"total\":");
        ds->max_body += p.size() + 24;
        ds->items.push_back(std::move(item));
    }
    if (ds->items.empty()) {
        error = path + ": no items";
        return nullptr;
    }
    ds->max_body += 40;
    return ds;
}

void HttparenaHandler::start(Stream& s, const LocationConfig& loc, WorkerState& ws, std::function<void()> done) {
    const Request& req = s.request;
    Response& r = s.response;
    r.head = req.method == Method::head;
    const std::string_view path = ws.path;
    const std::string_view query = query_of(req.target);
    if (path == "/pipeline") {
        answer(r, 200, "text/plain", "ok");
        done();
        return;
    }
    if (path == "/baseline11" || path == "/baseline2") {
        const std::int64_t sum = sum_args(query);
        if (req.method == Method::post && req.has_body && req.body) {
            r.buffer.clear();
            read_post(std::make_shared<PostRead>(PostRead{&s, sum, std::move(done)}));
            return;
        }
        answer_sum(r, sum);
        done();
        return;
    }
    if (path.starts_with("/json/")) {
        const std::shared_ptr<const HttparenaDataset>& ds = loc.httparena;
        if (!ds) {
            answer(r, 500, "text/plain", "dataset unavailable");
            done();
            return;
        }
        std::int64_t count = 0;
        const std::string_view digits = path.substr(6);
        const auto res = std::from_chars(digits.data(), digits.data() + digits.size(), count);
        if (digits.empty() || res.ec != std::errc() || res.ptr != digits.data() + digits.size() || count < 1 ||
            count > static_cast<std::int64_t>(ds->items.size())) {
            answer(r, 400, "text/plain", "Bad Request");
            done();
            return;
        }
        const std::string_view mv = arg(query, "m");
        const std::int64_t m = mv.empty() ? 1 : parse_int(mv);
        std::string& body = r.buffer;
        body.clear();
        body.reserve(ds->max_body);
        body.append("{\"items\":[");
        for (std::int64_t i = 0; i < count; ++i) {
            const HttparenaDataset::Item& it = ds->items[static_cast<std::size_t>(i)];
            if (i) body.push_back(',');
            body.append(it.prefix);
            append_int(body, it.pq * m);
            body.push_back('}');
        }
        body.append("],\"count\":");
        append_int(body, count);
        body.push_back('}');
        answer_buffer(r, 200, "application/json");
        done();
        return;
    }
    answer(r, 404, "text/plain", "Not Found");
    done();
}

}  // namespace agensio
