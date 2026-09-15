// Microbenchmark: cost of assembling a cached-200 response header, three styles.
#include <chrono>
#include <cstdio>
#include <string>
#include <string_view>

int main() {
    const std::string date = "Tue, 15 Sep 2026 10:29:21 GMT";
    const std::string mime = "text/html; charset=utf-8", size = "993";
    const std::string lm = "Tue, 15 Sep 2026 00:57:06 GMT", etag = "\"6aa897e2-3e1\"";
    const std::string entry_block = "Content-Type: " + mime + "\r\nContent-Length: " + size + "\r\nLast-Modified: " + lm + "\r\nETag: " + etag + "\r\n\r\n";
    const std::string prefix = "HTTP/1.1 200 OK\r\nServer: agensio\r\nDate: " + date + "\r\n";
    const std::string server_line = "Server: agensio\r\n";
    constexpr int N = 20'000'000;
    std::string h;
    h.reserve(512);
    std::size_t sink = 0;

    auto run = [&](const char* name, auto&& fn) {
        auto t0 = std::chrono::steady_clock::now();
        for (int i = 0; i < N; ++i) sink += fn();
        auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now() - t0).count();
        std::printf("%-44s %6.1f ns/header\n", name, static_cast<double>(ns) / N);
    };

    run("old: 11 appends of fragments + values", [&] {
        h.clear();
        h.append("HTTP/1.1 200 OK\r\nServer: agensio\r\nDate: ").append(date).append("\r\nContent-Type: ").append(mime)
         .append("\r\nContent-Length: ").append(size).append("\r\nLast-Modified: ").append(lm)
         .append("\r\nETag: ").append(etag).append("\r\n\r\n");
        return h.size();
    });
    run("previous: 6 appends + prebuilt entry block", [&] {
        h.clear();
        h.append("HTTP/1.1 200 OK\r\n").append(server_line).append("Date: ").append(date).append("\r\n").append(entry_block);
        return h.size();
    });
    run("now: assign cached prefix + borrow entry block", [&] {
        h.assign(prefix);
        std::string_view h2 = entry_block;
        return h.size() + h2.size();
    });
    return sink == 0;
}
