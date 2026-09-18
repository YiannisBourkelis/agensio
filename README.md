# agensio

A very fast, small, cross-platform web server written in C++20 on top of standalone
[Asio](https://think-async.com/Asio/). No Qt, no Boost, no framework: an event loop per
core, a zero-copy in-memory file cache, and a hand-written HTTP/1.1 parser.

It serves static sites, PHP applications (Laravel, Statamic, WordPress, plain PHP) through
FastCGI, and anything else through its reverse proxy (Node, Rails, Go, Java, WebSockets),
obtains its own TLS certificates, reloads without dropping a connection, and can be
configured by an AI agent through a built-in [MCP server](docs/mcp.md) over SSH.

**Status: pre-alpha** (`0.1.0-alpha.1`). It runs real applications on Linux and macOS
and beats nginx on CPU per request in every row of the benchmark harness, but it has
had few users. See the known limitations below before putting it in front of anything
that matters, and please report what you find.

See [CLAUDE.md](CLAUDE.md) for the design and measurements, [docs/ROADMAP.md](docs/ROADMAP.md)
for what comes next, and [docs/legacy-analysis.md](docs/legacy-analysis.md) for its 2018 ancestor.

## Build

Requirements: a C++20 compiler (Apple clang 15+, GCC 12+, Clang 16+, MSVC 2022), CMake 3.24+,
Asio headers (fetched automatically if not installed), OpenSSL 3 for TLS (optional).

```sh
# macOS
brew install cmake ninja asio openssl@3
# Debian / Ubuntu
sudo apt install cmake ninja-build libasio-dev libssl-dev
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
sudo install -d -o agensio -g agensio -m 0750 /etc/agensio/sites.d /var/log/agensio /var/lib/agensio
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

- HTTP/1.1 only. HTTP/2 and HTTP/3 are phases G and I of the roadmap.
- No response compression, no directory listing, no rate limiting yet.
- Certificates: HTTP-01 only, so port 80 must be reachable; no wildcards (DNS-01), no
  OCSP stapling.
- The control API is a unix socket; use it locally or over SSH. No TCP transport yet.
- Windows compiles but is untested; the macOS defaults for logs and state still point at
  the Linux paths unless set in the configuration.
- Single-machine benchmarks only so far. Numbers from your workload are welcome.

## Benchmark

```sh
brew install nginx caddy wrk        # competitors and load generator
bench/run.sh                        # 15 s runs, plain and TLS, results in bench/results/
bench/run.sh -d 30s -s "agensio nginx" -p http -u "/:256"
```

## License

MIT, see [LICENSE](LICENSE).
