# agensio

[agensio](https://github.com/YiannisBourkelis/agensio) is a static-file and reverse-proxy
server written in C++ on standalone Asio, with its own HTTP/1.1, TLS (OpenSSL) and HTTP/2
layers. One event loop per worker, each with its own `SO_REUSEPORT` acceptor; a connection
never leaves its worker. Files are served from a cache whose per-worker index is lock-free
over one shared store, with the response header block prebuilt at insert.

## Stack

- **Language:** C++
- **Engine:** agensio v0.1.0-alpha.20, built from the tag with `-march=native`
- **TLS:** OpenSSL 3 (Debian trixie), TLS 1.2 and 1.3, tickets on
- **Build:** Debian trixie, runtime `debian:trixie-slim`

## Listeners

| Port | Protocols | Profiles |
|------|-----------|----------|
| 8080 | HTTP/1.1 | pipelined |
| 8081 | HTTP/1.1 + TLS (ALPN offers `http/1.1` only) | static-tls |
| 8443 | h2 + HTTP/1.1 over TLS | static-h2 |

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/pipeline` | GET | `ok`, text/plain (a cached file) |
| `/static/{filename}` | GET | Served from the mounted `/data/static` through the cache; MIME types from the built-in table |

## Notes

- Two processes (`start.sh`): `protocols` is server-wide in this release, and the arena wants
  HTTP/1.1-only TLS on 8081 next to h2 on 8443. Each process runs one worker per CPU of the
  container's cpuset; only one listener is under load at a time.
- No pre-compressed `.br`/`.gz` siblings are served yet: every static file goes out as stored.
- No HTTP/3 yet. The baseline and JSON endpoints need agensio's benchmark handler module,
  which arrives with the next release; until then the entry subscribes to the static and
  pipelined profiles only.
- The cache revalidates a file at most once a second (`stat`, mtime and size), so a replaced
  file is served fresh within a second.
