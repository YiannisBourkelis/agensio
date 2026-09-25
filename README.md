# agensio

agensio is a web server built to be very fast while asking very little of the machine.
It serves static sites and dynamic applications with as little CPU and memory per
request as possible, so the same program suits a small VPS with one core and a few
hundred megabytes as well as a many-core server carrying a busy site: either way the
hardware goes to the site, not to the server in front of it. On one core of a desktop
Ryzen it answers about half a million small requests a second in plain HTTP and a third
of a million over TLS, in about fifteen megabytes of memory.

Under the hood it is a C++ program on standalone [Asio](https://think-async.com/Asio/):
an event loop per core, a lock-free in-memory file cache, and its own HTTP/1.1, HTTP/2
and HTTP/3 (QUIC) layers, with no framework and no protocol library in between.

It serves static sites, PHP applications (Laravel, Statamic, WordPress, Drupal, Grav and
plain PHP) through FastCGI with a preset per application that carries that application's
own hardening rules, and anything else through its reverse proxy (Node, Rails, Go, Java,
WebSockets). It obtains and renews its own TLS certificates, reloads without dropping a
connection, and can be configured by an AI agent through a built-in
[MCP server](docs/mcp.md) over SSH.

**Status: pre-alpha** (`0.1.0-alpha.23`). It runs real applications and uses less CPU
per request than nginx on nearly every row of its benchmark harness, but it has had few
users. It aims to be cross-platform; **only Linux is supported at the moment** (macOS
builds and runs and Windows compiles, but neither is tested release by release). See the
known limitations below before putting it in front of anything that matters, and please
report what you find.

See [CLAUDE.md](CLAUDE.md) for the design and measurements, [docs/ROADMAP.md](docs/ROADMAP.md)
for what comes next, and [docs/legacy-analysis.md](docs/legacy-analysis.md) for its 2018 ancestor.

## Build

Requirements: a C++20 compiler (GCC 12+, Clang 16+, Apple clang 15+, MSVC 2022), CMake 3.24+,
Asio headers (fetched automatically if not installed), OpenSSL 3 for TLS (optional; 3.5 or
later for HTTP/3, which Debian 13 and Fedora 42 ship).

```sh
# macOS
brew install cmake ninja asio openssl@3
# Debian / Ubuntu
sudo apt install cmake ninja-build libasio-dev libssl-dev zlib1g-dev
# Arch
sudo pacman -S cmake ninja asio openssl

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
./build/agensio_tests
./build/agensio -c config/agensio.toml
```

## Configuration

One TOML file. Paths are relative to the file's directory. Extra site files can be dropped
into an include directory, one per virtual host, which is what hosting panels do.

```toml
[server]
workers = 0            # 0 = one per hardware thread
idle_timeout = 15

[cache]
max_file_size = "4MB"  # bigger files stream from disk
max_size = "256MB"

[log]
access = "/var/log/agensio/access.log"  # combined format; a site can override with access_log = "..." or "off"
error = "stderr"

include = ["sites.d/*.toml"]

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/example"
index = ["index.html"]

[[site]]
server_name = ["example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example"
tls = { cert = "/etc/ssl/example/fullchain.pem", key = "/etc/ssl/example/privkey.pem" }
try_files = ["$uri", "$uri/", "/index.html"]   # single-page app: unknown paths get the app shell

[[site.location]]            # exact matches win, then suffixes, then the longest prefix; "/" is implicit
path = "/assets/"
alias = "/var/www/example-assets"   # /assets/x.png -> /var/www/example-assets/x.png
try_files = ["$uri", "=404"]

[[site]]                     # a Laravel project: the preset is the whole configuration
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app"      # the project; the preset serves its public/
app = "laravel"
php = { socket = "unix:/run/php/php8.4-fpm.sock" }
# app = "php" runs any .php under the root instead; `agensio -t --explain` shows the expansion
```

`agensio -t -c file.toml` validates a configuration without starting; `-t --explain`
prints what the presets expanded to. Worked examples for static sites, plain PHP,
Laravel, Statamic, WordPress, Node, Rails and more, with every option you can change,
are in [docs/configuration.md](docs/configuration.md) and [docs/examples/](docs/examples/).

## First site on a server

The short version of [docs/install.md](docs/install.md), which has the directory layout
per platform, the service user, the systemd unit and log rotation:

```sh
sudo useradd --system --home /var/lib/agensio --shell /usr/sbin/nologin agensio
sudo install -d -o root -g agensio -m 0750 /etc/agensio
sudo install -d -o agensio -g agensio -m 0750 /etc/agensio/sites.d /var/log/agensio
sudo install -d -o agensio -g agensio -m 0751 /var/lib/agensio
```

`/etc/agensio/agensio.toml`:

```toml
include = ["sites.d/*.toml"]

[server]
user = "agensio"
acme = { email = "admin@example.com" }   # certificates from Let's Encrypt, renewed automatically

[log]
access = "/var/log/agensio/access.log"
error = "/var/log/agensio/error.log"

[control]                                 # `agensio ctl` and the MCP server; root and agensio are admins
admins = "agensio-admin"
```

`/etc/agensio/sites.d/example.com.toml`, an HTTPS-only site:

```toml
[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:80"]
redirect = "https"

[[site]]
server_name = ["example.com", "www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/example.com/web"
tls = "auto"
```

Then `sudo agensio -t`, start it as root (it binds, opens the logs and becomes `agensio`),
and the certificate arrives within a minute. Change the file, `sudo agensio -t`,
`sudo agensio reload`: no connection is dropped. `agensio ctl health` tells you what to
look at; `agensio ctl logs --since 3h` shows recent errors.

## Let an agent do it

`agensio mcp` exposes the same commands as Model Context Protocol tools. From your
laptop, with Claude Code or Claude Desktop, one entry per server:

```json
{ "mcpServers": { "vps1": { "command": "ssh", "args": ["admin@vps1.example.com", "agensio", "mcp"] } } }
```

The agent runs as your SSH account, sees only the tools your role allows, asks before
every change, and hands anything that needs root back to you as commands. How it is
wired and why it is safe: [docs/mcp.md](docs/mcp.md) and
[docs/security-control-plane.md](docs/security-control-plane.md).

## Known limitations (pre-alpha)

**Alpha software, use at your own risk.** agensio is a few weeks old and has been run by
a handful of people. It has been careful about the things a web server must get right
(request framing, paths, credentials files, privilege drop, what PHP may execute), and
every problem found on a live host so far has become a test the same day, but there will
be bugs nobody has hit yet, some of them security bugs. Until a stable release: keep it
off anything you cannot afford to have exposed or down, keep backups, watch the error log
and `agensio ctl health`, upgrade on every alpha (each one fixes something found live),
and read the changelog before you do. There is no warranty of any kind (see the licence).
Reports are the most useful thing you can send.

- HTTP/2 and HTTP/3 are agensio's own implementations (conformance-tested with h2spec,
  the QUIC interop runner and their attack suites) and a few weeks old. HTTP/3 needs
  OpenSSL 3.5 or later at build time; without it the server speaks HTTP/1.1 and HTTP/2.
  Not yet in HTTP/3: 0-RTT, ECN, active connection migration.
- No on-the-fly response compression (pre-compressed `.br` and `.gz` files beside the
  originals are served), no directory listing, no rate limiting yet.
- Certificates: HTTP-01 only, so port 80 must be reachable; no wildcards (DNS-01), no
  OCSP stapling.
- The control API is a unix socket; use it locally or over SSH. No TCP transport yet.
- Linux only for now: macOS builds and runs but its defaults for logs and state still
  point at the Linux paths unless set in the configuration; Windows compiles but is
  untested.
- Single-machine benchmarks only so far. Numbers from your workload are welcome.

## Benchmark

The harness runs agensio, nginx and Caddy one at a time on the same machine, plain and
TLS, over HTTP/1.1 (wrk), HTTP/2 (h2load) and HTTP/3 (h2load over QUIC), verifies the
bodies before measuring, and stores the raw output under `bench/results/`. The
comparison is meant to be fair to servers that have set the standard for years: nginx
runs with the tuning its documentation recommends for static files, Caddy with its
defaults, and the metric is the server's own CPU per request, not only requests per
second.

```sh
brew install nginx caddy wrk        # the servers agensio is compared with, and the load generator
bench/run.sh                        # 15 s runs, plain and TLS, results in bench/results/
bench/run.sh -d 30s -s "agensio nginx" -p http -u "/:256"
bench/h2/run.sh                     # the HTTP/2 rows; bench/h3/run.sh needs an h2load built with QUIC
```

`bench/httparena/` is agensio's entry for [HttpArena](https://www.http-arena.com), the
public board where web servers and frameworks are measured on one machine;
`bench/httparena/local.sh` runs the arena's own validator and benchmark locally.

## License

MIT, see [LICENSE](LICENSE).
