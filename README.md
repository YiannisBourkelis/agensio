# agensio

A very fast, small, cross-platform web server written in C++20 on top of standalone
[Asio](https://think-async.com/Asio/). No Qt, no Boost, no framework: an event loop per
core, a zero-copy in-memory file cache, and a hand-written HTTP/1.1 parser.

Phase 1 serves static files over HTTP and HTTPS and ships with a benchmark harness against
nginx and Caddy. See [CLAUDE.md](CLAUDE.md) for the design and
[docs/legacy-analysis.md](docs/legacy-analysis.md) for its 2018 ancestor.

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

[[site]]                     # PHP application through php-fpm
server_name = ["app.example.com"]
listen = ["0.0.0.0:80"]
root = "/var/www/app/public"
index = ["index.php"]
try_files = ["$uri", "$uri/", "/index.php?$query_string"]
php = { socket = "unix:/run/php/php8.4-fpm.sock" }

[[site.location]]
path = ".php"
match = "suffix"
handler = "fastcgi"        # buffered by default; fastcgi = { buffering = false } streams (SSE)
```

`agensio -t -c file.toml` validates a configuration without starting.

## Benchmark

```sh
brew install nginx caddy wrk        # competitors and load generator
bench/run.sh                        # 15 s runs, plain and TLS, results in bench/results/
bench/run.sh -d 30s -s "agensio nginx" -p http -u "/:256"
```

## License

MIT, see [LICENSE](LICENSE).
