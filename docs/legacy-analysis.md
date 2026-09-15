# Legacy code analysis: open-web-server-asio (2018–2022)

Source: https://github.com/YiannisBourkelis/open-web-server-asio (GPL-3.0, Qt 5 + Boost.Asio 1.66, C++17, qmake).
About 3,500 lines excluding the bundled `json.hpp` (nlohmann). This document records what the
old server does, what agensio keeps, what it drops, and the bugs found, so nobody has to
re-read the old code.

## 1. Runtime model

| Piece | Old implementation |
|---|---|
| Entry | `main.cpp`: `QCoreApplication` + `rocket::takeoff()` |
| Event loop | One global `boost::asio::io_service`, `hardware_concurrency()` threads all calling `run()` (work-stealing pool, no strands) |
| Listeners | `AsioServerPlain` / `AsioServerEncrypted` per port, created by the config parser. IPv4 only, `TCP_NODELAY` set on the acceptor and each socket |
| Sessions | `ClientSessionPlain` / `ClientSessionEncrypted` (Boost.Asio SSL stream). Raw `new` per accept, `delete this` on error or on `Connection: close` |
| Threads and Qt | Qt event loop is not run. A 2 s Asio timer calls `QCoreApplication::processEvents()` so `QFileSystemWatcher` signals get delivered |

## 2. Request path (`ClientSessionBase`)

1. `async_read_some` into a 1 KB `std::vector<char>` owned by `ClientRequest`; buffer grows by 1 KB while the parser reports `incomplete`. No upper bound.
2. `ClientRequest::parse` is a hand-written, resumable, byte-at-a-time state machine (about 110 states in `parser_enums.h`). It recognises `GET`/`POST`, the request-target and query string, `HTTP/1.0|1.1`, and the headers Host, Accept, Accept-Charset, Accept-Encoding, Accept-Language, Content-Length, Content-Type, Cookie, Connection, User-Agent. Header names are matched by first letter plus length, not by full compare. Body is copied when Content-Length > 0. Old note in the source: about 460k parsed requests/s on the 2018 Mac.
3. `process_client_request`:
   - Cache lookup keyed by `hostname + request_uri` (the raw target, query string included) under a `shared_lock`. Hit: build a 200 header from prebuilt string fragments and send header + cached body as two `const_buffer`s (scatter-gather, body is not copied).
   - Miss: resolve the virtual host (`Host` header, `"*"` fallback), reject paths containing `..`, open the file with `QFile`, try the configured index files if the path is not a file, else directory listing (if allowed) or 404.
   - If the file is at most `max_file_size` (20 MB) and fits in `cache_max_size` (400 MB): read whole file, look up MIME via `QMimeDatabase`, format Last-Modified via `QLocale`, assign a counter ETag, insert. If it does not fit, evict the oldest 20 % (by `last_access_time`) and serve uncached this time.
   - Uncached: stream in 32 KB chunks. Each chunk **reopens the file** and seeks.
4. `handle_write`: keep-alive re-arms the read; otherwise close and delete.

## 3. Cache (`Cache`, `CacheKey`, `CacheContent`, `CacheRemove`)

- `std::unordered_map<CacheKey, CacheContent>` guarded by `std::shared_mutex`.
- Entry holds: file bytes, MIME type, Last-Modified string, ETag string, cached size-as-string, `last_access_time`.
- Invalidation: `QFileSystemWatcher::fileChanged` removes the entry; a change to the config file re-parses the config and drops index entries.
- Eviction: sort all entries by `last_access_time`, remove until 20 % of `cache_max_size` is freed.

## 4. Config (`ServerConfig*`, `server_config.json`)

JSON, loaded from `<exe dir>/../config/server_config.json`. Shape:

```json
{ "http": [ { "virtual_host": { "server_name": ["localhost"], "listen": [{"port": 12343}, {"port": 12347, "encryption": true, "certificate_chain_file": "...", "private_key_file": "..."}], "document_root": "...", "directory_listing": true } } ],
  "server": { "cache": {"total_size": "102400", "maximum_file_size": "5120", "cleanup_percentage": "15"}, "send_file_chunk_size": "32768", "indexes": ["index.html"] } }
```

Only `server_name`, `listen[].port`, `listen[].encryption`, cert/key paths, `document_root`, `directory_listing` and `server.indexes` are read. `server.cache.*` and `send_file_chunk_size` are parsed into nothing; the cache limits are hard-coded in `cache.h`. `location`, `proxy_pass`, `cgi`, `tcp_nodelay`, `ssl_protocols` are ignored. The parser also *creates the listeners* as a side effect of parsing.

## 5. Other pieces

- `http_response_templates.*`: prebuilt header fragments for 200 (cached / not cached), 206, 301/302/303, 400, 404, directory listing HTML. `Server: openw/1.10.1`.
- `rocket::get_gmt_date_time`: `Date:` header string refreshed at most once per second (shared static, not thread-safe).
- `rocket::get_next_etag`: global counter; the ETag restarts at 1 on every server start.
- `cgi_service.*`: blocking `php-cgi` via a static `QProcess`; the call site is commented out. `ClientResponse::parse` parses CGI `Status:`/`Location:` headers.
- Range requests: 206 response code exists but `is_range_request` is never set by the parser, so it is dead code.

## 6. Bugs and hazards found (do not carry over)

1. **Use after free on cache eviction.** `send_file_from_cache` captures pointers into the cached `std::vector<char>`, then the `shared_lock` is released before the async write completes. Eviction by another thread frees the buffer mid-write.
2. **Unsynchronised shared state**: `cache_current_size`, `last_access_time`, the Date cache, the ETag counter and `file_system_watcher->addPath` are all touched from several threads without locks.
3. **`Connection:` header never parsed**: the code compares the byte at the `\r` position with `'e'`/`'o'`, so it always yields `unknown` and falls back to the HTTP-version default. `Connection: close` on HTTP/1.1 is ignored.
4. **Only GET and POST**: `HEAD` (and anything else) leaves the parser in `state_start`, scanning for the next `G` or `P` anywhere in the request.
5. **No request size limit and no idle timeout**: a slow or malicious client can grow the buffer forever and hold a thread's session objects indefinitely.
6. **No percent-decoding, no path normalisation**: `%2e%2e/` bypasses the `..` check; `/a//b`, `/./` and symlinks are not handled. Non-ASCII file names are not supported.
7. **Pipelined requests are dropped**: bytes after the first `\r\n\r\n` in the buffer are discarded when `cleanup()` resets `buffer_position`.
8. **Cache key includes the query string**: `/a.css?v=1` and `/a.css?v=2` are cached twice.
9. **Uncached streaming reopens the file per 32 KB chunk** and does not check the read succeeded.
10. **Content-Length body handling** stores a POST body but nothing consumes it; POST to a static file returns the file.
11. **`delete this` from within handlers** while other handlers may be queued (e.g. after a write error while a read is pending on the TLS path).
12. **Counter ETag** breaks browser conditional requests across restarts; nginx-style `mtime-size` is stable and free.
13. IPv4 only; `reuse_address` not set, so a restart within TIME_WAIT fails to bind.

## 7. What agensio keeps (the ideas, rewritten)

- One acceptor per listening port, sessions own their receive buffer and reuse it across keep-alive requests.
- Hand-written incremental HTTP/1.1 parser (no external parser dependency), but written over `std::string_view` with `memchr`-style scanning instead of per-byte states.
- In-memory file cache with size caps and LRU eviction; hits are served with one scatter-gather write of a prebuilt header plus the shared body buffer.
- Prebuilt header fragments, one-second Date cache, precomputed `Content-Length`/`Last-Modified`/`ETag` strings per cache entry.
- `TCP_NODELAY`, keep-alive by default for HTTP/1.1, index-file fallback, `..` rejection (extended with decoding and normalisation).
- Chunked streaming for files too large to cache (keep the file open across chunks; on Linux use `sendfile`).
- Virtual hosts keyed by `Host`, a `*` default host.

## 8. What agensio drops

- Qt entirely (`QCoreApplication`, `QFile`, `QFileSystemWatcher`, `QMimeDatabase`, `QLocale`, `QDir`, `QProcess`, `QString`).
- Boost (`boost::asio` becomes standalone `asio`, `boost::bind` becomes lambdas, `boost::thread_group` becomes `std::jthread`).
- The parser-base/JSON-parser class hierarchy, `ServerConfigVirtualHostPortInfo`, `qt_event_loop_init`, `qstring_hash_specialization`, `cache_remove`.
- CGI (`php-cgi`) and the CGI response parser: out of scope until the FastCGI phase.
- Directory listing: out of scope for the benchmark phase.
