# Protocols and capacity: HTTP/2, HTTP/3, limits

Recipes for what clients speak to the server and how much one host takes: HTTP/2 and HTTP/3,
the connection ceiling, request limits, the file cache, and applying a change without dropping
anyone. Most keys here are root's, in the main file: no site tool changes them, and
`agensio ctl reference` (MCP `config_reference`) shows each one's running value and whether it
needs a reload or a restart. The [cookbook's index](../examples.md) says how a recipe is laid
out and how to apply one.

## HTTP/2 on every HTTPS site

**When:** always; this is the default. Read it to know what a client gets and which keys
shape HTTP/2.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
protocols = ["h2", "h1"]                   # the default: what TLS listeners offer, in order of preference
http2 = { max_concurrent_streams = 128 }   # the default: requests one client may run at once on a connection
```

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com", "example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.com/web"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
```

**What it does.** A client that offers `h2` in the TLS handshake (every current browser, curl)
gets HTTP/2; any other gets HTTP/1.1 on the same port. Plain HTTP stays HTTP/1.1: browsers use
HTTP/2 only over TLS. There is nothing per site to set: the HTTP/2 limits come from keys you
already have, `max_header_size` for the header block, `max_requests_per_connection` for the
streams before a `GOAWAY`, `idle_timeout`, `body_timeout`, and the site's body limit for the
upload windows, so uploads are not slower than over HTTP/1.1. A stream beyond
`max_concurrent_streams` is refused and the connection stays; the default is nginx's. A browser
may reuse one HTTP/2 connection for every name the certificate covers; a request for a name no
site on that listener serves, or that the certificate does not cover, gets `421`, and the browser
retries on a new connection. Requests are logged as `HTTP/2.0`, and PHP sees
`SERVER_PROTOCOL=HTTP/2.0`.

**Check it.**

```sh
curl -sI --http2 https://www.example.com/ | head -1      # HTTP/2 200
curl -sI --http1.1 https://www.example.com/ | head -1    # HTTP/1.1 200 OK: the same port, for clients without h2
agensio ctl status                                       # each listener's protocols: h2 and h1 on TLS, h1 on plain
tail -n 3 /var/log/agensio/access.log                    # "GET / HTTP/2.0"
```

**MCP:** `server_status` lists each listener's protocols; `config_reference` shows `protocols`
and `http2` with their running values. Both keys are in root's main file, which no tool edits.

**Reference:** [HTTP/2](../configuration.md#16-http2), [which site answers](../configuration.md#1b-which-site-answers-a-request) (the `421`).

## Switch HTTP/2 off while a client misbehaves

**When:** users report pages that fail only over HTTP/2, or a client keeps tripping the HTTP/2
limits, and you want everyone on HTTP/1.1 while you find out why.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
protocols = ["h1"]          # every TLS listener offers HTTP/1.1 alone; ["h2", "h1"] puts HTTP/2 back

[log]
level = "info"              # a line for every GOAWAY and RST_STREAM the server sends, with the client and the reason
```

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.com/web"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
```

**What it does.** After `agensio reload`, new connections negotiate HTTP/1.1. Connections
already on HTTP/2 carry on until they close (after `idle_timeout`, or after
`max_requests_per_connection` streams); a restart ends them at once. A site that names its own
`protocols` keeps them: the server's list is only the default for sites without one. At level
`info` the error log names every connection the server ended and every stream it reset
(`http2 198.51.100.7: GOAWAY after stream ...`, `... stream 5: RST_STREAM ...`). The server
already closes a connection on its own budgets (100 protocol errors, 128 streams cancelled within
a second); switching HTTP/2 off is for a client that stays within them and still fails. Level
`info` also logs reloads and certificate work; set it back to `warn` afterwards.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
curl -sI --http2 https://www.example.com/ | head -1       # HTTP/1.1 200 OK although curl offered h2
agensio ctl logs --level info --since 1h | grep 'http2 '   # who was cut off before, and why
```

**MCP:** `logs_query` with `level` = `info` for the HTTP/2 lines; the switch is root's line in
the main file, then `reload`.

**Reference:** [HTTP/2](../configuration.md#16-http2), [Logging](../configuration.md#8-logging).

## HTTP/2 without TLS on a backend network

**When:** agensio sits behind a load balancer on a private network, the balancer ends TLS and
can speak HTTP/2 to its backends in clear (HAProxy's `proto h2` on a `server` line), and you want
one multiplexed connection instead of many.

```toml
# /etc/agensio/sites.d/app.example.com.toml
[[site]]
server_name = ["app.example.com"]
listen = ["198.51.100.10:8080"]      # the address the load balancer reaches; never a public one
root = "/var/www/app.example.com/web"
protocols = ["h2c", "h1"]            # HTTP/2 with prior knowledge on this listener, and HTTP/1.1 as before
default = true                       # the listener's catch-all: it answers whatever Host the balancer sends
```

**What it does.** h2c is HTTP/2 without encryption, with prior knowledge only: the client opens
the connection with the HTTP/2 preface. A client that sends HTTP/1.1 on the same port is served
as before, and one that asks to switch with `Upgrade: h2c` stays on HTTP/1.1 (the upgrade is not
implemented). Browsers never use h2c, so it is off by default and belongs on a network you
trust: everything on it, cookies included, travels in clear. The key on the site keeps h2c to
this one listener; `"h2c"` in `[server] protocols` would turn it on for every plain listener,
port 80 included. Without `default = true`, a Host the site does not list gets `421`. For the
client addresses in the logs and access rules, trust the balancer:
[trusted_proxies](protection.md#judge-the-real-client-behind-a-cdn-or-load-balancer).

**Check it.**

```sh
curl -sI --http2-prior-knowledge --resolve app.example.com:8080:198.51.100.10 http://app.example.com:8080/ | head -1   # HTTP/2 200
curl -sI --resolve app.example.com:8080:198.51.100.10 http://app.example.com:8080/ | head -1                           # HTTP/1.1 200 OK
agensio ctl status                                       # the listener's protocols: h2c, h1
```

**Reference:** [HTTP/2](../configuration.md#16-http2), [which site answers](../configuration.md#1b-which-site-answers-a-request).

## HTTP/3 next to HTTP/2

**When:** you want HTTP/3 (QUIC over UDP) for the visitors whose browsers use it, and the
host's firewall can pass UDP.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
protocols = ["h2", "h1", "h3"]               # h2 and h1 over TCP, h3 over UDP on the same port numbers
http3 = { retry = "auto", alt_svc = true }   # the defaults; retry = "always" under a flood of handshakes
```

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com", "example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.com/web"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
```

Root's steps on the host, before the reload:

```sh
ufw allow 443/udp                    # or the same in your firewall: UDP on every TLS port
sysctl -w net.core.rmem_max=8388608 net.core.wmem_max=8388608
printf 'net.core.rmem_max = 8388608\nnet.core.wmem_max = 8388608\n' > /etc/sysctl.d/90-agensio-quic.conf
```

**What it does.** Every TLS listener also answers on the same port number over UDP, and every
HTTP/1 and HTTP/2 answer it gives carries `alt-svc: h3=":443"; ma=86400`: that is how a browser
learns about HTTP/3, so the first visit is over TCP and the next connection switches. With UDP
closed nothing fails: the TCP port keeps answering. The QUIC sockets ask the kernel for 4 MB
buffers and an untuned Linux grants 208 KB; a burst of new connections larger than that loses
handshake packets, which the clients resend one to three seconds later. The sysctl lines raise
the cap; a socket takes its buffer when it opens (at start, or at the reload that adds h3), so
run them first. With `retry = "auto"` a worker asks new clients to prove their address only once
it has 512 handshakes in progress; `"always"` asks every new client, one extra round trip each,
for a host under a handshake flood. The limits come from the HTTP/2 and connection keys
(`http2.max_concurrent_streams` is the streams per connection here too). `"h3"` needs a build
with OpenSSL 3.5 or later on Linux; `agensio -t` refuses it on any other. On a single site
instead of the whole server, see the next recipe.

If the firewall table comes from `agensio ctl protection`, render it again: it then limits QUIC
handshakes per address too, and health reports `firewall_quic_unlimited` until it does.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && agensio reload
curl -sI https://www.example.com/ | grep -i '^alt-svc'      # alt-svc: h3=":443"; ma=86400
curl -sI --http3-only https://www.example.com/ | head -1    # HTTP/3 200; from another host, so the firewall is on the path
agensio ctl status                                          # the listener's protocols: h2, h1, h3
sysctl net.core.rmem_max                                    # 8388608; 212992 is the untuned cap
agensio ctl protection --nft > /etc/agensio/firewall.nft    # only if you use agensio's table: then nft -f it again
```

curl needs HTTP/3 support for `--http3-only` (`curl -V` lists `HTTP3`).

**MCP:** `server_status` for the protocols, `health_check` for the firewall, `protection_show`
for the ruleset; the keys and the sysctl are root's.

**Reference:** [HTTP/3](../configuration.md#17-http3), [host protection](../configuration.md#18-connection-limits).

## Different protocols for one site

**When:** one name must differ from the others: a fleet of devices whose old HTTP library offers
HTTP/2 and then mishandles it, or one site you want on HTTP/3 before the rest.

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com"]
listen = ["203.0.113.10:443"]
root = "/var/www/www.example.com/web"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
# no protocols: the server's list, ["h2", "h1"] by default
```

```toml
# /etc/agensio/sites.d/devices.example.com.toml
[[site]]
server_name = ["devices.example.com"]
listen = ["203.0.113.20:443"]        # an address of its own: the name resolves to it
root = "/var/www/devices.example.com/web"
tls = { cert = "/etc/ssl/devices.example.com/fullchain.pem", key = "/etc/ssl/devices.example.com/privkey.pem" }
protocols = ["h1"]                   # HTTP/1.1 only on this address, whatever a client offers
```

**What it does.** The protocol is agreed in the TLS handshake for the address, so a site's
`protocols` really sets its listeners: every site on one address must list the same, in the same
order, and a site without the key counts as listing the server's. Two sites that share an
address and differ are refused by `agensio -t` (`... share 203.0.113.10:443 but list different
protocols; sites on one address must agree`). So the site that differs needs an address or a
port of its own; another port means the clients must use it in their URLs. The same key gives
HTTP/3 to one address alone, `protocols = ["h2", "h1", "h3"]`, on a TLS site only. A managed
site takes the server's list: `protocols` is not a field of `site-update`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml
curl -sI --http2 https://devices.example.com/ | head -1   # HTTP/1.1 200 OK
curl -sI --http2 https://www.example.com/ | head -1       # HTTP/2 200
agensio ctl status                                        # protocols per listener
```

**Reference:** [HTTP/2](../configuration.md#16-http2) (`protocols` on a `[[site]]`).

## Workers and connection limits on a small VPS

**When:** one machine with two vCPUs and a few GB of memory runs agensio, PHP and the database,
and you want agensio to leave them room and to hold no more connections than memory allows.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
workers = 1                          # one core for agensio, the other for PHP and the database (restart)
max_connections = 10000              # per worker; unset, it follows the open-file limit
idle_timeout = 15                    # the default: an idle keep-alive connection closes after 15 s
max_requests_per_connection = 1000   # the default: then Connection: close (HTTP/2: GOAWAY)
```

```toml
# /etc/agensio/sites.d/www.example.com.toml
[[site]]
server_name = ["www.example.com", "example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/www.example.com/web"
app = "wordpress"
user = "www"
tls = { cert = "/etc/ssl/www.example.com/fullchain.pem", key = "/etc/ssl/www.example.com/privkey.pem" }
```

**What it does.** A worker is a thread with its own event loop (on Linux its own accepting
socket too), and a connection stays on the worker that accepted it. The default, `workers = 0`,
is one per CPU the process may run on; fewer leave cores to PHP and the database. `workers` is
read at start only.

`max_connections` is per worker and counts TCP and QUIC connections together. Unset, it is
`(open-file limit - 2048) / workers`, and with the packaged unit's `LimitNOFILE=1048576` that is
about a million: more than a small machine has memory for. An idle HTTP/1 connection costs about
13 KB and an HTTP/2 one about 19 KB, so 10,000 idle HTTP/2 connections are about 190 MB. A
connection above the ceiling is refused at once: a plain listener answers `503 Service
Unavailable` with `Retry-After: 2` and closes, a TLS listener closes before the handshake (the
browser shows a connection error). The error log says so once per worker per ten seconds
(`... at its connection ceiling: ...`), naming the addresses refused most. The ceiling is
not a per-address limit: one client holding thousands of connections is the firewall's to stop,
and `agensio ctl protection` renders a table that does it.

`idle_timeout` closes a connection with nothing to do (over HTTP/2, no stream open; it is also
HTTP/3's idle timeout). It never cuts a request that PHP or an origin is still working on: their
own `read_timeout` bounds those (504 beyond). Lower it when health says the workers are full of
idle connections. `max_requests_per_connection` makes a client open a new connection after that
many requests; 0 means no limit.

**Check it.**

```sh
systemctl restart agensio          # for workers; the other three apply with agensio reload
agensio ctl status                 # workers, max_connections (per worker), connections, connections_idle, connections_refused
agensio ctl health                 # connections_refused once anyone was turned away, with the likely cause
agensio ctl logs --level warn --since 1d | grep 'connection ceiling'
```

Health's `connections_refused` fix follows from who was refused: most refusals from one address
(the firewall's job, nothing to raise), workers full of idle connections (lower `idle_timeout`),
or load from many addresses (raise `max_connections`, or `LimitNOFILE` in the unit).

**MCP:** `server_status` for the ceiling and the refusals per worker, with the addresses and
listeners they came from; `health_check` for the cause; the keys are root's (`config_reference`).

**Reference:** [Connection limits](../configuration.md#18-connection-limits), [keys](../keys.md) (`[server]`).

## Request size and time limits

**When:** an application takes large uploads (a media library, file sharing), or its cookies or
URLs outgrow the default 16 KB request head, or uploads from slow links fail.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[server]
max_header_size = "32KB"    # request line and fields; 431 above (default 16KB)
max_body_size = "8MB"       # the body limit of every site without its own; 413 above (default 1MB)
body_timeout = 60           # the default: longest wait between two reads of a body
```

```toml
# /etc/agensio/sites.d/media.example.com.toml
[[site]]
server_name = ["media.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/media.example.com/web"
app = "wordpress"
user = "media"
tls = { cert = "/etc/ssl/media.example.com/fullchain.pem", key = "/etc/ssl/media.example.com/privkey.pem" }
max_body_size = "200MB"     # this site's uploads; also its PHP pool's upload_max_filesize and post_max_size
```

**What it does.** A request head above `max_header_size` gets `431` and the connection closes
over HTTP/1.1; over HTTP/2 a header block above it closes the connection. More than 100 header
fields is a `431` whatever their size. A body above the site's `max_body_size` (or the server's,
for a site without one) gets `413`: when the client declares its length, before the application
sees anything; when it sends the body in chunks without a length, as soon as the body passes
the limit (over HTTP/1.1 the connection then closes). The error log names the site, the size,
the client and the limit (`... refused with 413: its max_body_size is 200 MB ...`). On a site
with its own PHP pool, the same value becomes the pool's `upload_max_filesize` and
`post_max_size`, so PHP does not refuse what agensio let through. Over HTTP/2 and HTTP/3 the
upload windows follow the limit too.

`body_timeout` is the longest wait between two reads of a body, not a limit on the whole upload:
a slow upload that keeps sending is never cut; one that stops for that long fails (HTTP/1.1
closes the connection, HTTP/2 cancels the stream). A slow application is a different limit:
`php = { read_timeout }` and `proxy = { read_timeout }`, 504 beyond.

**Check it.**

```sh
head -c 210M /dev/zero > /tmp/210M.bin
curl -s -o /dev/null -w '%{http_code}\n' --data-binary @/tmp/210M.bin https://media.example.com/   # 413
curl -s -o /dev/null -w '%{http_code}\n' --http1.1 -H "Cookie: big=$(head -c 40000 /dev/zero | tr '\0' a)" https://media.example.com/   # 431
agensio ctl logs --level warn --since 1h | grep 'refused with 413'
```

**On a managed site.** A site's body limit is one of its settings, within the ceiling
`[control] site_limits` sets (512 MB by default; root raises it in the main file):

```sh
agensio ctl settings media.example.com                  # each limit, its value, where it comes from, the ceiling
agensio ctl site-update media.example.com --set max_body_size=200MB --yes --reason "video uploads"
```

The answer lists what was reloaded: agensio, and the site's PHP pool with php-fpm.

**MCP:** `site_settings_list` with `name`, then `site_update` with `settings` =
`{"max_body_size": "200MB"}`.

**Reference:** [Hosting: one user per site](../configuration.md#11-hosting-one-user-per-site) (the site's limit and its pool), [HTTP/2](../configuration.md#16-http2), [keys](../keys.md).

## The file cache for a site with many large files

**When:** a site serves many files of a few MB (photo galleries, documentation with large images)
or many large downloads at once, and the host has memory to spare.

```toml
# /etc/agensio/agensio.toml: the main file, root's (once per host)
include = ["sites.d/*.toml"]

[cache]
max_size = "1GB"           # file content kept in memory, all sites and workers together (default 256MB)
max_file_size = "16MB"     # larger files are not loaded: they stream from an open descriptor (default 4MB)
max_open_files = 4096      # descriptors kept open for those streamed files (default 1024)
revalidate_interval = 1    # the default: a cached file is checked against the disk at most once a second
```

```toml
# /etc/agensio/sites.d/files.example.com.toml
[[site]]
server_name = ["files.example.com"]
listen = ["0.0.0.0:443"]
root = "/var/www/files.example.com/web"
tls = { cert = "/etc/ssl/files.example.com/fullchain.pem", key = "/etc/ssl/files.example.com/privkey.pem" }
```

**What it does.** A file up to `max_file_size` is read into memory on its first request and
served from there by every worker. A larger file is not loaded: the cache keeps its descriptor
open with its headers ready, so a download costs no open or stat per request, and the body goes
out with sendfile over plain HTTP and in 64 KB reads over TLS. Memory (`max_size`) and
descriptors (`max_open_files`) are separate budgets; when one is full, the least recently used
entries of that budget are dropped, a fifth of it at a time. A `name.br` or `name.gz` beside a
cached file counts with it. `max_size` is file content only; connections and buffers come on top.

Raising `max_file_size` turns more files into memory hits, at the cost of reading each whole file
on its first request; keep it well below `max_size`, or a few large files push everything else
out. Raise `max_open_files` when many different large files are downloaded at once. Each is a
descriptor held open, and the derived connection ceiling keeps only 2,048 descriptors for these,
the logs and the connections to PHP and origins: above that, give the unit a larger `LimitNOFILE`
or set `max_connections`. `revalidate_interval` bounds how long a file replaced on disk is still
served from memory; raise it where a stat is costly (a network filesystem) and a deploy can wait
that long. Do not set it to 0: that turns the check off, and a replaced file stays cached until it
is evicted or a reload empties the site's cache.

The cache is built at start: a change to this table needs `systemctl restart agensio`. A reload
keeps the running values and names each key it kept in the error log (`reload: cache.max_size,
cache.max_open_files changed on disk and take effect at a restart ...`); `agensio ctl validate`
lists them under `restart_needed`.

**Check it.**

```sh
agensio -t -c /etc/agensio/agensio.toml && systemctl restart agensio
agensio ctl reference                    # [cache] with the running values ("running")
ps -o rss= -C agensio                    # resident memory in KB, growing toward max_size as files are cached
```

**MCP:** `config_reference` for the running values; the table is root's.

**Reference:** [Static site](../configuration.md#1-static-site) (what is cached), [Reload without restart](../configuration.md#12b-reload-without-restart), [keys](../keys.md) (`[cache]`).

## Reload without dropping a connection

**When:** you changed a site, a limit or a certificate and visitors are mid-request: uploads,
downloads, WebSockets.

```sh
agensio -t -c /etc/agensio/agensio.toml   # the file exactly as the reload will check it
agensio ctl validate                      # the same, plus restart_needed: what a reload would keep
agensio reload                            # or: systemctl reload agensio; the result goes to the error log
agensio ctl logs --level error --since 10m | grep 'reload refused'   # empty when it applied
```

**What it does.** The server loads the file and checks it as `-t` does, reads the certificates
and binds new listen addresses; only then does every worker switch, between requests:

- a request in progress, an exchange with PHP or an origin, a CGI process, a WebSocket tunnel
  finish on the configuration they started with;
- a keep-alive connection takes the new configuration at its next request;
- a listen address that was removed stops accepting at once, and its connections finish their
  current request, then close;
- a broken file, an unreadable certificate or a port that cannot be bound refuses the whole
  reload (`reload refused: ...` in the error log), and the old configuration keeps serving.

Restart-only, by `keys.md`'s `applies` column: `workers`, `reuse_port`, `sendfile`,
`sendfile_max_chunk`, `tcp_nodelay`, `user`, `group`, `pid_file`, the whole `[cache]` table,
`[control] socket` and `provision`, and a new listen port below 1024 (once the server runs as
`server.user` it cannot bind one). A reload keeps those as they are and names each one it kept in
the error log, and `agensio ctl validate` lists them under `restart_needed`; a restart ends every
open connection. The control plane's role groups apply on reload. A site's static files are read from disk again on their first
request after a reload: its cache starts empty.

**Check it.** `agensio ctl reload` runs the same reload and answers with the result itself
instead of leaving it to the error log:

```sh
agensio ctl reload --yes --reason "new site"
```

**MCP:** `config_validate` first (it names what would need a restart), then `reload` with
`confirm` and `reason`.

**Reference:** [Reload without restart](../configuration.md#12b-reload-without-restart), [keys](../keys.md) (the `applies` column).
