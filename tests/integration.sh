#!/usr/bin/env bash
# End-to-end checks against a running agensio built from this tree.
# usage: tests/integration.sh <path-to-agensio-binary>
set -uo pipefail
BIN="${1:-build/agensio}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
[ -f bench/www/big.bin ] && [ -L bench/www/outside.txt ] || bench/gen-www.sh >/dev/null
[ -f bench/certs/cert.pem ] || bench/certs/gen-cert.sh >/dev/null
printf '<html><body>sub index</body></html>\n' > bench/www/sub/index.html
printf '<html><body>app shell</body></html>\n' > bench/www/app.html

mkdir -p bench/tmp
rm -f bench/tmp/access.log bench/tmp/access.log.1 bench/tmp/error.log
# php-fpm for the FastCGI checks (skipped when not installed): a pool on a unix socket in bench/tmp.
PHPFPM=$(command -v php-fpm8.4 || command -v php-fpm8.3 || command -v php-fpm || true)
FPM_PID=""
if [ -n "$PHPFPM" ]; then
  mkdir -p bench/tmp/php
  cat > bench/tmp/php/fpm.conf <<FPMCONF
[global]
pid = $ROOT/bench/tmp/php/fpm.pid
error_log = $ROOT/bench/tmp/php/fpm.log
daemonize = no
[www]
listen = $ROOT/bench/tmp/php/fpm.sock
listen.mode = 0666
pm = static
pm.max_children = 4
catch_workers_output = yes
php_admin_flag[display_errors] = off
FPMCONF
  "$PHPFPM" -y bench/tmp/php/fpm.conf -F -p "$ROOT/bench/tmp/php" >/dev/null 2>&1 &
  FPM_PID=$!
  for _ in $(seq 1 50); do [ -S bench/tmp/php/fpm.sock ] && break; sleep 0.1; done
  printf '<?php echo "hello ", $_SERVER["REQUEST_METHOD"], " ", $_GET["x"] ?? "-";\n' > bench/www/hello.php
fi
sed "s#@WORKERS@#0#g; s#@BENCH@#$ROOT/bench#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g; s#@ACCESS_LOG@#$ROOT/bench/tmp/access.log#; s#^tcp_nodelay = true#tcp_nodelay = true\ntrusted_proxies = [\"127.0.0.1\"]#" bench/agensio.toml > bench/tmp/agensio-test.toml
printf '\n[control]\nsocket = "%s/bench/tmp/control.sock"\naudit = "%s/bench/tmp/audit.log"\nupload_max = "1M"\n' "$ROOT" "$ROOT" >> bench/tmp/agensio-test.toml
sed -i "s#^\[server\]#[server]\nstate_dir = \"$ROOT/bench/tmp/state\"#" bench/tmp/agensio-test.toml
rm -rf bench/tmp/state bench/tmp/inst; mkdir -p bench/tmp/state bench/tmp/inst
rm -rf bench/tmp/sites.d; mkdir -p bench/tmp/sites.d bench/tmp/sites/created.test/web; echo created > bench/tmp/sites/created.test/web/index.html
sed -i '1i include = ["sites.d/*.toml"]' bench/tmp/agensio-test.toml
# Locations (A4) on the plain site: an SPA fallback, an aliased root, an exact match and a
# try_files status. Inserted after the site's `default = true` line.
mkdir -p bench/tmp/certs-b
[ -f bench/tmp/certs-b/cert.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout bench/tmp/certs-b/key.pem -out bench/tmp/certs-b/cert.pem -days 30 -subj "/CN=b.test" >/dev/null 2>&1
# A SAN certificate covering a.test and b.test (connection coalescing), a wildcard one, and
# a copy of b's to swap back after the renewal-during-a-connection check.
mkdir -p bench/tmp/certs-ab bench/tmp/certs-wild bench/tmp/certs-live
[ -f bench/tmp/certs-ab/cert.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout bench/tmp/certs-ab/key.pem -out bench/tmp/certs-ab/cert.pem -days 30 -subj "/CN=a.test" -addext "subjectAltName=DNS:a.test,DNS:b.test" >/dev/null 2>&1
[ -f bench/tmp/certs-wild/cert.pem ] || openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout bench/tmp/certs-wild/key.pem -out bench/tmp/certs-wild/cert.pem -days 30 -subj "/CN=*.wild.test" -addext "subjectAltName=DNS:*.wild.test" >/dev/null 2>&1
cp bench/tmp/certs-b/cert.pem bench/tmp/certs-b/key.pem bench/tmp/certs-live/
python3 - bench/tmp/agensio-test.toml "$ROOT/bench/www" "$ROOT" <<'PY'
import sys
path, www, root = sys.argv[1], sys.argv[2], sys.argv[3]
block = f"""default = true
php = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock", read_timeout = 3 }}

[[site.location]]
path = "/php/"
alias = "{root}/tests/php"
index = ["index.php"]
handler = "fastcgi"

[[site.location]]
path = "/phpstream/"
alias = "{root}/tests/php"
handler = "fastcgi"
fastcgi = {{ buffering = false }}

[[site.location]]
path = "/phpcap/"
alias = "{root}/tests/php"
handler = "fastcgi"
fastcgi = {{ buffer_max = "64KB", buffer_file_max = "1MB" }}

[[site.location]]
path = "/phpslow/"
alias = "{root}/tests/php"
handler = "fastcgi"
fastcgi = {{ read_timeout = 1 }}

[[site.location]]
path = "/app/"
try_files = ["$uri", "$uri/", "/app.html"]

[[site.location]]
path = "/alias/"
alias = "{www}/sub"

[[site.location]]
path = "/spa/"
try_files = ["$uri", "/sub/index.html"]

[[site.location]]
path = "/sub/index.html"
match = "exact"
add_headers = {{ "X-Loc" = "exact" }}

[[site.location]]
path = "/private/"
try_files = ["=403"]

[[site.location]]
path = "/uploads/"
alias = "{root}/tests/php"
final = true
deny_suffixes = [".php"]

[[site.location]]
path = "/readonly/"
alias = "{www}/sub"
methods = ["GET", "HEAD"]
"""
import os
text = open(path).read().replace("default = true\n", block, 1)
# The TLS site gets the same php upstream and a /php/ location (HTTPS=on check).
tls_line = [l for l in text.splitlines() if l.startswith("tls = ")][0]
text = text.replace(tls_line + "\n", tls_line + f'\nphp = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock" }}\n\n[[site.location]]\npath = "/php/"\nalias = "{root}/tests/php"\nindex = ["index.php"]\nhandler = "fastcgi"\n', 1)
text = text.replace("[log]\n", f'[log]\nerror = "{root}/bench/tmp/error.log"\n', 1)
# A Laravel-shaped project through the preset, on its own port.
text += f"""
[[site]]
server_name = ["laravel.test"]
default = true
listen = ["127.0.0.1:8090"]
root = "{root}/tests/laravel"
app = "laravel"
php = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock" }}
"""
# Drupal-shaped and WordPress-shaped projects through their presets (2026-09-19 source
# disclosure regression), each on its own port.
text += f"""
[[site]]
server_name = ["drupal.test"]
default = true
listen = ["127.0.0.1:8095"]
root = "{root}/tests/drupal"
app = "drupal"
php = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock" }}

[[site]]
server_name = ["wp.test"]
default = true
listen = ["127.0.0.1:8096"]
root = "{root}/tests/wordpress"
app = "wordpress"
php = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock" }}
"""
# Strict host matching (2026-09-19): a listener with a named site only, and a TLS listener
# with two named sites and two certificates chosen by SNI (the second one made by the shell above).
text += f"""
[[site]]
server_name = ["strict.test"]
listen = ["127.0.0.1:8099"]
root = "{root}/bench/www"

[[site]]
server_name = ["a.test"]
listen = ["127.0.0.1:8446"]
root = "{root}/bench/www"
tls = {{ cert = "{root}/bench/tmp/certs-ab/cert.pem", key = "{root}/bench/tmp/certs-ab/key.pem" }}

[[site]]
server_name = ["b.test"]
listen = ["127.0.0.1:8446"]
root = "{root}/bench/www"
tls = {{ cert = "{root}/bench/tmp/certs-live/cert.pem", key = "{root}/bench/tmp/certs-live/key.pem" }}

[[site]]
server_name = ["x.wild.test"]
listen = ["127.0.0.1:8449"]
root = "{root}/bench/www"
tls = {{ cert = "{root}/bench/tmp/certs-wild/cert.pem", key = "{root}/bench/tmp/certs-wild/key.pem" }}

[[site]]
server_name = ["y.wild.test"]
listen = ["127.0.0.1:8449"]
root = "{root}/bench/www"
tls = {{ cert = "{root}/bench/tmp/certs-wild/cert.pem", key = "{root}/bench/tmp/certs-wild/key.pem" }}

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8448"]
root = "{root}/bench/www"
tls = {{ cert = "{root}/bench/tmp/certs-b/cert.pem", key = "{root}/bench/tmp/certs-b/key.pem" }}
"""
# HTTPS-only sites (H3): the plain listener redirects, to the Host or to a fixed prefix.
text += f"""
[[site]]
server_name = ["redir.test"]
listen = ["127.0.0.1:8092"]
default = true
redirect = "https"

[[site]]
server_name = ["fixed.test"]
listen = ["127.0.0.1:8092"]
redirect = "https://secure.test:8443"
"""
# The reverse proxy (D1) in front of the benchmark upstream on 127.0.0.1:9107, on its own port.
if os.path.exists(f"{root}/build/agensio_upstream"):
    text += f"""
[[site]]
server_name = ["proxy.test"]
default = true
listen = ["127.0.0.1:8091"]
root = "{root}/bench/www"

[[site.location]]
path = "/api/"
upstream = "http://127.0.0.1:9107/"
proxy = {{ read_timeout = 1 }}

[[site.location]]
path = "/stream/"
upstream = "http://127.0.0.1:9107/"
proxy = {{ buffering = false, request_buffering = false }}

[[site.location]]
path = "/down/"
upstream = "http://127.0.0.1:9199"

[[site.location]]                       # D2: header policy
path = "/policy/"
upstream = "http://127.0.0.1:9107/"
proxy = {{ host = "app.internal", forwarded = "both", headers = {{ "X-Real-IP" = "$remote_addr", "X-Site" = "$scheme://$host", "Accept" = "" }}, hide = ["X-Powered-By"] }}

[[site.location]]                       # D4: a group of two origins, round-robin
path = "/group/"
upstream = ["http://127.0.0.1:9107/", "http://127.0.0.1:9108/"]

[[site.location]]                       # D4: one dead member, skipped after max_fails
path = "/failover/"
upstream = ["http://127.0.0.1:9199/", "http://127.0.0.1:9108/"]
proxy = {{ max_fails = 2, fail_timeout = 30 }}

[[site.location]]                       # D4b: TLS to an origin (this suite's own HTTPS site), self-signed
path = "/tls/"
upstream = "https://127.0.0.1:8443/"
proxy = {{ tls = {{ verify = false }} }}

[[site.location]]                       # D4b: verified against the bench CA with its name
path = "/tlsverify/"
upstream = "https://127.0.0.1:8443/"
proxy = {{ tls = {{ ca = "{root}/bench/certs/cert.pem", server_name = "localhost" }} }}

[[site.location]]                       # D4b: verification against the system store must fail
path = "/tlsbad/"
upstream = "https://127.0.0.1:8443/"

[[site.location]]                       # D5: CGI scripts, a process per request
path = "/cgi-bin/"
alias = "{root}/tests/cgi"
index = ["index.cgi"]
cgi = {{ env = {{ "APP_ENV" = "test" }} }}

[[site.location]]                       # D5: a short timeout and a cap of one process
path = "/cgi-slow/"
alias = "{root}/tests/cgi"
cgi = {{ read_timeout = 1, max_connections = 1, queue_depth = 0 }}

[[site.location]]                       # E9: one slot, no queue (its own origin: pool limits are per upstream)
path = "/abort/"
upstream = "http://127.0.0.1:9109/"
proxy = {{ max_connections = 1, queue_depth = 0 }}

[[site.location]]                       # D2: redirects passed through untouched
path = "/raw/"
upstream = "http://127.0.0.1:9107/"
proxy = {{ redirects = "pass" }}

[[site.location]]
path = "/"
upstream = "http://127.0.0.1:9107"
"""
open(path, "w").write(text)
PY
UP_PID=""; UP2_PID=""; UP3_PID=""
if [ -x build/agensio_upstream ]; then
  build/agensio_upstream -p 9107 >/dev/null 2>&1 &
  UP_PID=$!
  build/agensio_upstream -p 9108 >/dev/null 2>&1 &
  UP2_PID=$!
  build/agensio_upstream -p 9109 >/dev/null 2>&1 &
  UP3_PID=$!
fi
"$BIN" -c bench/tmp/agensio-test.toml >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null; [ -n "$FPM_PID" ] && kill $FPM_PID 2>/dev/null; [ -n "$UP_PID" ] && kill $UP_PID 2>/dev/null; [ -n "$UP2_PID" ] && kill $UP2_PID 2>/dev/null; [ -n "$UP3_PID" ] && kill $UP3_PID 2>/dev/null; true' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 0.1; done

fails=0
failed_names=""
check() {  # name expected actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$2] got [$3]"; fails=$((fails+1)); failed_names="$failed_names
  - $1"; fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
if command -v sha256sum >/dev/null; then sum() { sha256sum | cut -c1-16; }; else sum() { shasum -a 256 | cut -c1-16; }; fi
# Debian's netcat-openbsd needs -q to exit after stdin EOF; macOS nc has no -q.
if nc -h 2>&1 | grep -q -- '-q'; then ncq() { nc -q 1 "$@"; }; else ncq() { nc "$@"; }; fi
BIG=$(sum < bench/www/big.bin); CSS=$(sum < bench/www/style.css); IDX=$(sum < bench/www/index.html); IDXLEN=$(stat -c %s bench/www/index.html)

for base in http://127.0.0.1:8080 https://127.0.0.1:8443; do
  p=${base%%:*}
  check "$p index body"         "$IDX" "$(curl -sSk $base/ | sum)"
  check "$p cached 100KB body"  "$CSS" "$(curl -sSk $base/style.css | sum)"
  check "$p streamed 10MB body" "$BIG" "$(curl -sSk $base/big.bin | sum)"
  check "$p content-length big" "10485760" "$(curl -sSkI $base/big.bin | tr -d '\r' | awk '/^Content-Length/{print $2}')"
  check "$p HEAD has no body"   "0" "$(curl -sSk -I $base/ -o /dev/null -w '%{size_download}')"
  check "$p 404"                "404" "$(code -k $base/nope)"
  check "$p 405 POST"           "405" "$(code -k -X POST -d x=1 $base/)"
  check "$p dir redirect"       "301 /sub/" "$(curl -sSkI $base/sub | tr -d '\r' | awk '/^HTTP/{c=$2} /^Location/{l=$2} END{print c, l}')"
  check "$p index in subdir"    "sub index" "$(curl -sSk $base/sub/ | sed 's/<[^>]*>//g')"
  check "$p traversal raw"      "400" "$(code -k --path-as-is $base/../etc/passwd)"
  check "$p traversal encoded"  "400" "$(code -k --path-as-is $base/%2e%2e/etc/passwd)"
  ET=$(curl -sSkI $base/ | tr -d '\r' | awk '/^ETag/{print $2}')
  check "$p 304 etag"           "304" "$(code -k -H "If-None-Match: $ET" $base/)"
  LM=$(curl -sSkI $base/ | tr -d '\r' | sed -n 's/^Last-Modified: //p')
  check "$p 304 last-modified"  "304" "$(code -k -H "If-Modified-Since: $LM" $base/)"
  check "$p keep-alive reuse"   "1 0" "$(curl -sSk -o /dev/null -o /dev/null -w '%{num_connects} ' $base/ $base/style.css | sed 's/ $//' | tr '\n' ' ' | sed 's/ $//')"
  check "$p 3 x 10MB one conn"  "$BIG $BIG $BIG" "$(curl -sSk $base/big.bin $base/big.bin $base/big.bin | (a=$(head -c 10485760 | sum); b=$(head -c 10485760 | sum); c=$(sum); echo "$a $b $c"))"
done
# ---- strict host matching: 421 for a Host no site lists, "*" / default = true is the only catch-all ----
S=http://127.0.0.1:8099
check "strict: the named site answers its own name" "200" "$(code -H 'Host: strict.test' $S/)"
check "strict: a Host no site lists is 421 with no-store, not served" "421 no-store" "$(curl -sSi -H 'Host: evil.example.com' $S/ | tr -d '\r' | awk 'NR==1{c=$2} tolower($1)=="cache-control:"{h=$2} END{print c, h}')"
check "strict: the IP address as Host is 421 too" "421" "$(code $S/)"
check "strict: the 421 body is constant and says nothing about other sites" "yes" "$(a=$(curl -sS -H 'Host: x.invalid' $S/); b=$(curl -sS -H 'Host: y.invalid' $S/other); [ "$a" = "$b" ] && ! echo "$a" | grep -q 'strict\|laravel' && echo yes)"
check "strict: HTTP/1.0 without Host on a listener without catch-all is 421, keep-alive unaffected" "421" "$(printf 'GET / HTTP/1.0\r\n\r\n' | ncq 127.0.0.1 8099 | head -1 | awk '{print $2}')"
check "strict: HTTP/1.1 without Host stays 400" "400" "$(printf 'GET / HTTP/1.1\r\n\r\n' | ncq 127.0.0.1 8099 | head -1 | awk '{print $2}')"
check "strict: a listener with a catch-all serves unknown Hosts as before" "200" "$(code -H 'Host: evil.example.com' http://127.0.0.1:8080/)"
check "strict: OPTIONS * with an unknown Host is 421" "421" "$(printf 'OPTIONS * HTTP/1.1\r\nHost: nobody.invalid\r\n\r\n' | ncq 127.0.0.1 8099 | head -1 | awk '{print $2}')"
sni() { echo | openssl s_client -connect 127.0.0.1:8446 "$@" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//'; }
check "sni: each site gets its own certificate" "a.test b.test" "$(sni -servername a.test) $(sni -servername b.test)"
check "sni: a name no site lists is refused, no other site's certificate shown" "" "$(sni -servername c.test)"
check "sni: no SNI on a listener without catch-all is refused" "" "$(sni -noservername)"
check "sni: no SNI on a listener with a catch-all gets its certificate" "b.test" "$(echo | openssl s_client -connect 127.0.0.1:8448 -noservername 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | sed 's/.*CN *= *//')"
check "sni: the matched site serves over TLS" "200" "$(curl -sSk -o /dev/null -w '%{http_code}' --resolve b.test:8446:127.0.0.1 https://b.test:8446/)"
# Authority (2026-09-20): on TLS a connection answers only names the certificate it presented
# covers, whatever sites the listener holds (RFC 9110 7.4, RFC 6125).
hostcode() { curl -sSk -o /dev/null -w '%{http_code}' --resolve "$1:$3:127.0.0.1" -H "Host: $2" "https://$1:$3/"; }
check "authority: SNI b, Host a: b's certificate does not cover a.test, so 421 although the listener holds a.test" "421 no-store" "$(curl -sSik --resolve b.test:8446:127.0.0.1 -H 'Host: a.test' https://b.test:8446/ | tr -d '\r' | awk 'NR==1{c=$2} tolower($1)=="cache-control:"{h=$2} END{print c, h}')"
check "authority: the 421 body is the constant one, nothing about either site" "yes" "$(a=$(curl -sSk --resolve b.test:8446:127.0.0.1 -H 'Host: a.test' https://b.test:8446/); b=$(curl -sS -H 'Host: nobody.test' http://127.0.0.1:8099/); [ "$a" = "$b" ] && ! echo "$a" | grep -qi 'a.test\|b.test' && echo yes)"
check "authority: SNI a, Host b: a's SAN certificate covers both, so served (the coalescing case)" "200" "$(hostcode a.test b.test 8446)"
check "authority: a wildcard certificate covers the sibling site" "200 200" "$(hostcode x.wild.test y.wild.test 8449) $(hostcode y.wild.test x.wild.test 8449)"
check "authority: the bare domain is not covered by the wildcard (no site either)" "421" "$(hostcode x.wild.test wild.test 8449)"
check "authority: a Host no site lists over a valid TLS connection is still 421" "421" "$(hostcode b.test c.test 8446)"
check "authority: case, a trailing dot and a port in Host match as before" "200 200 200" "$(hostcode b.test B.TEST 8446) $(hostcode b.test b.test. 8446) $(hostcode b.test b.test:8446 8446)"
check "authority: no SNI, the catch-all's certificate is presented: a Host it covers is served, another is 421" "200 421" "$(curl -sSk -o /dev/null -w '%{http_code}' -H 'Host: b.test' https://127.0.0.1:8448/) $(curl -sSk -o /dev/null -w '%{http_code}' -H 'Host: other.test' https://127.0.0.1:8448/)"
check "authority: HTTP/1.0 without Host over TLS still reaches the catch-all (no name claimed); HTTP/1.1 without Host stays 400" "200 400" "$(printf 'GET / HTTP/1.0\r\n\r\n' | openssl s_client -quiet -connect 127.0.0.1:8448 -noservername 2>/dev/null | head -1 | awk '{print $2}') $(printf 'GET / HTTP/1.1\r\n\r\n' | openssl s_client -quiet -connect 127.0.0.1:8448 -noservername 2>/dev/null | head -1 | awk '{print $2}')"
check "authority: plain HTTP is unchanged: any site on the listener, 421 for none" "200 421" "$(code -H 'Host: strict.test' $S/) $(code -H 'Host: a.test' $S/)"
check "authority: a certificate renewed during an open connection: the connection keeps the one it presented, a new connection gets the new one" "200 421 421 200" "$(python3 - "$ROOT" "$BIN" <<'PYT'
import socket, ssl, subprocess, shutil, sys
root, binary = sys.argv[1], sys.argv[2]
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def get(conn, host):
    conn.sendall(("GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % host).encode())
    data = b""
    while b"\r\n\r\n" not in data: data += conn.recv(65536)
    head, body = data.split(b"\r\n\r\n", 1)
    length = int([l for l in head.decode().split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
    while len(body) < length: body += conn.recv(65536)
    return head.split(b" ")[1].decode()
def connect():
    return ctx.wrap_socket(socket.create_connection(("127.0.0.1", 8446)), server_hostname="b.test")
kept = connect()
out = [get(kept, "b.test"), get(kept, "a.test")]
# b.test's certificate is renewed as one that also covers a.test; the running server reloads.
for f in ("cert.pem", "key.pem"): shutil.copy(root + "/bench/tmp/certs-ab/" + f, root + "/bench/tmp/certs-live/" + f)
subprocess.run([binary, "ctl", "reload", "--yes", "--reason", "renewal", "--socket", root + "/bench/tmp/control.sock"], capture_output=True)
out.append(get(kept, "a.test"))          # the kept connection presented the old certificate: still 421
fresh = connect()
out.append(get(fresh, "a.test"))         # a new handshake presents the renewed one: served
kept.close(); fresh.close()
for f in ("cert.pem", "key.pem"): shutil.copy(root + "/bench/tmp/certs-b/" + f, root + "/bench/tmp/certs-live/" + f)
subprocess.run([binary, "ctl", "reload", "--yes", "--reason", "renewal-back", "--socket", root + "/bench/tmp/control.sock"], capture_output=True)
print(" ".join(out))
PYT
)"
echo "skip authority: HTTP/2 connection coalescing retry after 421 (HTTP/2 not implemented yet: a client that reuses the 8446 a.test connection for b.test, which a.test's SAN certificate covers, is served; one that reuses a connection whose certificate does not cover the origin gets 421 and must succeed on a new connection)"
check "control: status names each listener's catch-all or none" "8099=none 8080=localhost 8448=*" "$(curl -sS --unix-socket bench/tmp/control.sock http://control/v1/status | python3 -c 'import json,sys; d={l["address"]:l["catch_all"] for l in json.load(sys.stdin)["listeners"]}; print("8099=%s 8080=%s 8448=%s" % (d["127.0.0.1:8099"] or "none", d["127.0.0.1:8080"], d["127.0.0.1:8448"]))')"

# ---- locations and try_files (A4) ----
check "location: SPA fallback serves the app shell for a missing path" "app shell" "$(curl -sS http://127.0.0.1:8080/app/some/route | sed 's/<[^>]*>//g')"
check "location: SPA fallback for the directory URI" "app shell" "$(curl -sS http://127.0.0.1:8080/app/ | sed 's/<[^>]*>//g')"
check "location: alias replaces the prefix" "sub index" "$(curl -sS http://127.0.0.1:8080/alias/ | sed 's/<[^>]*>//g')"
check "location: alias file path" "sub index" "$(curl -sS http://127.0.0.1:8080/alias/index.html | sed 's/<[^>]*>//g')"
check "location: fallback is routed again (hits the exact location, its header added)" "sub index exact" "$(curl -sSi http://127.0.0.1:8080/spa/missing | tr -d '\r' | awk '/^X-Loc:/{h=$2} /<body>/{gsub(/<[^>]*>/,""); b=$0} END{print b, h}')"
check "location: exact match wins over the root prefix" "sub index exact" "$(curl -sSi http://127.0.0.1:8080/sub/index.html | tr -d '\r' | awk '/^X-Loc:/{h=$2} /<body>/{gsub(/<[^>]*>/,""); b=$0} END{print b, h}')"
check "location: directory index is routed to the location owning it" "exact" "$(curl -sSI http://127.0.0.1:8080/sub/ | tr -d '\r' | awk '/^X-Loc:/{print $2}')"
check "location: exact does not prefix-match" "404" "$(code http://127.0.0.1:8080/sub/index.htmlx)"
check "location: root prefix still serves the site" "$IDX" "$(curl -sS http://127.0.0.1:8080/ | sum)"
check "location: try_files =403" "403" "$(code http://127.0.0.1:8080/private/anything)"
check "location: final prefix keeps .php out of the suffix location, deny_suffixes gives 404" "404" "$(code http://127.0.0.1:8080/uploads/index.php)"
check "location: fallback result served again (cache hit on the target)" "app shell" "$(curl -sS http://127.0.0.1:8080/app/some/route | sed 's/<[^>]*>//g')"
check "dotfile hidden (404)" "404" "$(code http://127.0.0.1:8080/.env)"
check "dot-directory hidden (404)" "404" "$(code http://127.0.0.1:8080/.git/config)"
check "symlink outside root served with symlinks=allow" "200" "$(code http://127.0.0.1:8080/outside.txt)"
check "smuggling CL+TE rejected" "HTTP/1.1 400 Bad Request" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nGET /sub/ HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "smuggling: connection closed after 400" "1" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\nGET /sub/ HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c '^HTTP/1.1')"
check "obs-fold rejected" "HTTP/1.1 400 Bad Request" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nX: a\r\n b\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "pipelining" "2" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\n\r\nGET /sub/ HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c 'HTTP/1.1 200')"
check "bad request" "HTTP/1.1 400 Bad Request" "$(printf 'GARBAGE\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "tls 1.2 accepted" "200" "$(code -k --tls-max 1.2 https://127.0.0.1:8443/)"
# -brief prints the protocol at connect time; the SSL-Session block only appears once a
# ticket arrived, which OpenSSL 3.0 (Ubuntu 24.04) does not wait for when stdin is closed.
check "tls 1.3 negotiated" "TLSv1.3" "$(echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 -brief 2>&1 | sed -n 's/^Protocol version: //p' | head -1)"
check "no plain http on tls port" "000" "$(code http://127.0.0.1:8443/ 2>/dev/null)"
# ---- methods (B1): OPTIONS answered, others 405 with the location's Allow ----
check "OPTIONS /: 204 with Allow" "204 GET, HEAD, OPTIONS" "$(curl -sSi -X OPTIONS http://127.0.0.1:8080/ | tr -d '\r' | awk '/^HTTP/{s=$2} /^Allow:/{sub(/^Allow: /,""); a=$0} END{print s, a}')"
check "OPTIONS * (server-wide): 204" "HTTP/1.1 204 No Content" "$(printf 'OPTIONS * HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "OPTIONS: no body, keep-alive works" "204 200" "$(printf 'OPTIONS / HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | awk '/^HTTP\/1.1/{printf "%s ", $2}' | sed 's/ $//')"
check "TRACE: 405" "405 GET, HEAD, OPTIONS" "$(curl -sSi -X TRACE http://127.0.0.1:8080/ | tr -d '\r' | awk '/^HTTP/{s=$2} /^Allow:/{sub(/^Allow: /,""); a=$0} END{print s, a}')"
check "DELETE: 405 with Allow" "405 GET, HEAD, OPTIONS" "$(curl -sSi -X DELETE http://127.0.0.1:8080/style.css | tr -d '\r' | awk '/^HTTP/{s=$2} /^Allow:/{sub(/^Allow: /,""); a=$0} END{print s, a}')"
check "PUT with body: 405, connection reused" "405 200" "$(printf 'PUT /x HTTP/1.1\r\nHost: l\r\nContent-Length: 2\r\n\r\nhiGET / HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | awk '/^HTTP\/1.1/{printf "%s ", $2}' | sed 's/ $//')"
check "unknown method: 405" "405" "$(code -X PURGE http://127.0.0.1:8080/)"
check "location methods: OPTIONS refused where narrowed" "405 GET, HEAD" "$(curl -sSi -X OPTIONS http://127.0.0.1:8080/readonly/ | tr -d '\r' | awk '/^HTTP/{s=$2} /^Allow:/{sub(/^Allow: /,""); a=$0} END{print s, a}')"
check "location methods: GET still served" "sub index" "$(curl -sS http://127.0.0.1:8080/readonly/ | sed 's/<[^>]*>//g')"
BIGMD5=$(python3 -c "import hashlib,sys; print(hashlib.md5(b'0123456789abcdef'*196608).hexdigest())")
# ---- FastCGI (C1): php-fpm behind /php/ (buffered), /phpstream/ (streaming), a .php suffix location ----
if [ -n "$FPM_PID" ]; then
check "php: index via directory URI" "index ok" "$(curl -sS http://127.0.0.1:8080/php/)"
check "php: status and content type" "200 text/html; charset=UTF-8" "$(curl -sSi http://127.0.0.1:8080/php/ | tr -d '\r' | awk '/^HTTP/{s=$2} tolower($0) ~ /^content-type:/{sub(/^[Cc]ontent-[Tt]ype: /,""); c=$0} END{print s, c}')"
P=$(curl -sS -H 'X-Test: yes' 'http://127.0.0.1:8080/php/params.php?a=1&b=2')
check "php: QUERY_STRING" "yes" "$(echo "$P" | grep -q '"QUERY_STRING":"a=1&b=2"' && echo yes)"
check "php: SCRIPT_FILENAME under the alias" "yes" "$(echo "$P" | grep -q "\"SCRIPT_FILENAME\":\"$ROOT/tests/php/params.php\"" && echo yes)"
check "php: REMOTE_ADDR and SERVER_PORT" "yes" "$(echo "$P" | grep -q '"REMOTE_ADDR":"127.0.0.1"' && echo "$P" | grep -q '"SERVER_PORT":"8080"' && echo yes)"
check "php: HTTP_ header passed" "yes" "$(echo "$P" | grep -q '"HTTP_X_TEST":"yes"' && echo yes)"
check "php: SERVER_NAME from the site" "yes" "$(echo "$P" | grep -q '"SERVER_NAME":"localhost"' && echo yes)"
check "php: no HTTPS on plain" "yes" "$(echo "$P" | grep -qv '"HTTPS"' && echo yes)"
check "php: HTTPS=on over TLS" "yes" "$(curl -sSk https://127.0.0.1:8443/php/params.php | grep -q '"HTTPS":"on"' && echo yes)"
check "php: OPTIONS reaches the application" "yes" "$(curl -sS -X OPTIONS http://127.0.0.1:8080/php/params.php | grep -q '"REQUEST_METHOD":"OPTIONS"' && echo yes)"
check "php: TRACE still 405" "405" "$(code -X TRACE http://127.0.0.1:8080/php/params.php)"
check "php: POST form body" "7 $(printf 'a=1&b=2' | md5sum | cut -d' ' -f1) a=1&b=2" "$(curl -sS -d 'a=1&b=2' http://127.0.0.1:8080/php/post.php)"
head -c 600000 /dev/urandom > bench/tmp/big-post.bin
check "php: large POST body spilled to a temp file, intact" "600000 $(md5sum < bench/tmp/big-post.bin | cut -d' ' -f1) " "$(curl -sS -H 'Content-Type: application/octet-stream' --data-binary @bench/tmp/big-post.bin http://127.0.0.1:8080/php/post.php)"
check "php: request fields intact after a body that arrives late (Expect)" "yes" "$(curl -sS -H 'Expect: 100-continue' -d 'a=1' 'http://127.0.0.1:8080/php/params.php?late=1' | grep -q '"REQUEST_URI":"/php/params.php?late=1"' && echo yes)"
check "php: request fields intact after a body larger than the head buffer" "yes" "$(curl -sS -H 'Content-Type: application/octet-stream' --data-binary @bench/tmp/big-post.bin 'http://127.0.0.1:8080/php/params.php?big=1' | grep -q '"REQUEST_URI":"/php/params.php?big=1"' && echo yes)"
check "php: chunked request body" "7 $(printf 'a=1&b=2' | md5sum | cut -d' ' -f1) a=1&b=2" "$(curl -sS -H 'Transfer-Encoding: chunked' -H 'Content-Type: application/x-www-form-urlencoded' -d 'a=1&b=2' http://127.0.0.1:8080/php/post.php)"
H=$(curl -sSi http://127.0.0.1:8080/php/headers.php | tr -d '\r')
check "php: Status from the script" "201" "$(echo "$H" | awk '/^HTTP/{print $2}')"
check "php: custom and repeated headers passed through" "2 1" "$(echo "$H" | grep -c '^Set-Cookie: ') $(echo "$H" | grep -c '^X-Custom: v')"
check "php: Location alone means 302" "302 /php/index.php" "$(curl -sSi http://127.0.0.1:8080/php/redirect.php | tr -d '\r' | awk '/^HTTP/{s=$2} /^Location:/{l=$2} END{print s, l}')"
check "php: http_response_code(404) with body" "404 custom 404" "$(curl -sS -w ' %{http_code}' http://127.0.0.1:8080/php/status404.php | awk '{print $NF, $1, $2}')"
check "php: 3 MB response spilled to a temp file, intact" "$BIGMD5 3145728" "$(curl -sS -o bench/tmp/big.out -w '%{size_download}' http://127.0.0.1:8080/php/big.php | (read n; echo "$(md5sum < bench/tmp/big.out | cut -d' ' -f1) $n"))"
check "php: HEAD answered without a body" "200 0" "$(curl -sSI -o /dev/null -w '%{http_code} %{size_download}' http://127.0.0.1:8080/php/big.php)"
check "php: streaming location sends chunked" "yes" "$(curl -sSi http://127.0.0.1:8080/phpstream/stream.php | tr -d '\r' | grep -q '^Transfer-Encoding: chunked' && echo yes)"
check "php: streaming body intact" "chunk0 chunk1 chunk2 chunk3 chunk4" "$(curl -sS http://127.0.0.1:8080/phpstream/stream.php | tr '\n' ' ' | sed 's/ $//')"
check "php: streamed Content-Length enforced: surplus cut, connection reusable" "xxxxxHTTP/1.1 200 OK" "$(printf 'GET /phpstream/wronglen.php?m=long HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | tr -d '\r' | grep -o 'x\+HTTP/1.1 200 OK')"
check "php: streamed Content-Length enforced: short body closes the connection" "18" "$(curl -s -o /dev/null --max-time 5 http://127.0.0.1:8080/phpstream/wronglen.php?m=short; echo $?)"
check "php: temp-file cap switches to streaming, body intact" "$BIGMD5 chunked" "$(curl -sS http://127.0.0.1:8080/phpcap/big.php -o bench/tmp/cap.out -D bench/tmp/cap.hdr; md5sum < bench/tmp/cap.out | cut -d' ' -f1) $(grep -qi '^Transfer-Encoding: chunked' bench/tmp/cap.hdr && echo chunked)"
check "php: Proxy header never forwarded (httpoxy)" "yes" "$(curl -sS -H 'Proxy: http://evil.example/' http://127.0.0.1:8080/php/params.php | grep -qv 'HTTP_PROXY' && echo yes)"
check "php: repeated header joined" "yes" "$(curl -sS -H 'X-Dup: a' -H 'X-Dup: b' http://127.0.0.1:8080/php/params.php | grep -q '"HTTP_X_DUP":"a, b"' && echo yes)"
check "php: read_timeout gives 504" "504" "$(code 'http://127.0.0.1:8080/phpslow/slow.php?s=2')"
check "php: timeout reason in the error log" "yes" "$(grep -q 'read_timeout' bench/tmp/error.log && echo yes)"
check "php: missing script is 404 before fpm" "404" "$(code http://127.0.0.1:8080/php/missing.php)"
check "php: fatal error gives PHP's 500" "500" "$(code http://127.0.0.1:8080/php/fatal.php)"
check "php: stderr of the fatal error logged" "yes" "$(grep -q 'undefined_function_xyz' bench/tmp/error.log && echo yes)"
check "php: keep-alive reuse across requests" "index okindex okindex ok" "$(curl -sS http://127.0.0.1:8080/php/ http://127.0.0.1:8080/php/ http://127.0.0.1:8080/php/)"
PI=$(curl -sS 'http://127.0.0.1:8080/php/params.php/extra/path?q=1')
check "php: PATH_INFO split off the script" "yes" "$(echo "$PI" | grep -q '"SCRIPT_NAME":"/php/params.php"' && echo "$PI" | grep -q '"PATH_INFO":"/extra/path"' && echo yes)"
check "php: PATH_TRANSLATED and REQUEST_URI keep the whole path" "yes" "$(echo "$PI" | grep -q "\"PATH_TRANSLATED\":\"$ROOT/tests/php/extra/path\"" && echo "$PI" | grep -q '"REQUEST_URI":"/php/params.php/extra/path?q=1"' && echo yes)"
check "php: REDIRECT_STATUS present" "yes" "$(echo "$PI" | grep -q '"REDIRECT_STATUS":"200"' && echo yes)"
FW=$(curl -sS -H 'X-Forwarded-For: 203.0.113.9, 127.0.0.1' -H 'X-Forwarded-Proto: https' http://127.0.0.1:8080/php/params.php)
check "php: trusted proxy: REMOTE_ADDR from X-Forwarded-For" "yes" "$(echo "$FW" | grep -q '"REMOTE_ADDR":"203.0.113.9"' && echo yes)"
check "php: trusted proxy: HTTPS from X-Forwarded-Proto" "yes" "$(echo "$FW" | grep -q '"HTTPS":"on"' && echo yes)"
check "php: forwarded headers still passed as HTTP_" "yes" "$(echo "$FW" | grep -q '"HTTP_X_FORWARDED_FOR"' || echo "$FW" | grep -q 'X_FORWARDED' || curl -sS -H 'X-Forwarded-For: 1.2.3.4' http://127.0.0.1:8080/php/params.php | grep -q '"REMOTE_ADDR":"1.2.3.4"' && echo yes)"
else
  echo "skip php-fpm checks (php-fpm not installed)"
fi
# ---- presets (C3): app = "laravel" ----
if [ -n "$FPM_PID" ]; then
check "laravel: any route reaches the front controller" "laravel /some/route?x=1 /index.php -" "$(curl -sS 'http://127.0.0.1:8090/some/route?x=1')"
check "laravel: root goes to index.php" "laravel / /index.php -" "$(curl -sS http://127.0.0.1:8090/)"
check "laravel: static asset served from public/ with immutable caching" "console.log(\"app\"); public, max-age=31536000, immutable" "$(curl -sS http://127.0.0.1:8090/build/app.js | tr -d '\n') $(curl -sSI http://127.0.0.1:8090/build/app.js | tr -d '\r' | awk '/^Cache-Control:/{sub(/^Cache-Control: /,""); print}')"
check "laravel: dotfiles in public/ hidden" "404" "$(code http://127.0.0.1:8090/.env)"
check "laravel: project files outside public/ unreachable" "400" "$(code --path-as-is 'http://127.0.0.1:8090/../.env')"
check "laravel: a .php that does not exist is refused, not routed" "404" "$(code http://127.0.0.1:8090/anything.php)"
# The regression: a second .php under public/ was served as a download with its source.
check "laravel: an existing second .php is refused (404), never executed, never disclosed" "404 no-source" "$(code http://127.0.0.1:8090/admin.php) $(curl -sS http://127.0.0.1:8090/admin.php | grep -q '<?php\|hunter2\|second-entry' && echo LEAK || echo no-source)"
check "laravel: /index.php/extra also lands in the front controller" "laravel /index.php/extra /index.php -" "$(curl -sS 'http://127.0.0.1:8090/index.php/extra')"
fi
"$BIN" -t --explain -c bench/tmp/agensio-test.toml > bench/tmp/explain.out 2>bench/tmp/explain.err
check "explain: preset expansion is printed" "yes" "$(grep -q '# from preset:laravel' bench/tmp/explain.out && echo yes)"
check "explain: -t reports OK" "yes" "$("$BIN" -t -c bench/tmp/agensio-test.toml 2>/dev/null | grep -q 'is OK' && echo yes)"
# ---- HTTPS only (H3): redirect = "https" on the plain site ----
R=http://127.0.0.1:8092
check "redirect: 301 to https on the same host, port dropped, query kept" "301 https://redir.test/a/b?x=1" "$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: redir.test:8092' "$R/a/b?x=1")"
check "redirect: fixed prefix with a port" "301 https://secure.test:8443/p?q" "$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: fixed.test' "$R/p?q")"
check "redirect: POST is redirected too, HEAD has no body" "301 301 0" "$(curl -sS -o /dev/null -w '%{http_code} ' -X POST -d a=b "$R/x" -H 'Host: redir.test')$(curl -sS -I -o /dev/null -w '%{http_code} %{size_download}' "$R/x" -H 'Host: redir.test')"
check "redirect: HTTP/1.0 without Host uses the site's name" "https://redir.test/y" "$(printf 'GET /y HTTP/1.0\r\n\r\n' | ncq 127.0.0.1 8092 | tr -d '\r' | awk '/^Location:/{print $2}')"
check "redirect: an unknown ACME token is redirected, not served" "301" "$(code -H 'Host: redir.test' "$R/.well-known/acme-challenge/nothing")"
check "redirect: keep-alive survives" "301 1 301 0" "$(curl -sS -o /dev/null -o /dev/null -w '%{http_code} %{num_connects} ' -H 'Host: redir.test' "$R/1" "$R/2" | sed 's/ $//')"

# ---- control socket (F0/F1): status as the server's own user, roles, JSON errors ----
CS=bench/tmp/control.sock
check "control: status answers JSON with our role" "yes" "$(curl -sS --unix-socket $CS http://control/v1/status | grep -q '"version":"' && curl -sS --unix-socket $CS http://control/v1/status | grep -q '"role":"admin"' && echo yes)"
check "control: status lists the sites and listeners" "yes" "$(curl -sS --unix-socket $CS http://control/v1/status | grep -q '"listeners":\[{"address":"127.0.0.1:8080"' && echo yes)"
check "control: unknown command is a JSON 404" '404 {"error":"unknown command","path":"/v1/nothing"}' "$(curl -sS -o /dev/null -w '%{http_code} ' --unix-socket $CS http://control/v1/nothing)$(curl -sS --unix-socket $CS http://control/v1/nothing | tr -d '\n')"
check "control: POST to a read command is 405 with Allow" "405 GET, HEAD" "$(curl -sSi -X POST --unix-socket $CS http://control/v1/status | tr -d '\r' | awk 'NR==1{c=$2} /^Allow:/{a=$2" "$3} END{print c" "a}')"
check "control: agensio ctl status uses the socket" "0 yes" "$("$BIN" ctl status --socket $CS > bench/tmp/ctl.out; echo -n "$? "; grep -q '"pid":' bench/tmp/ctl.out && echo yes)"
check "control: sites lists every site with its tls mode" "yes" "$(curl -sS --unix-socket $CS http://control/v1/sites | grep -q '"server_name":\["laravel.test"\]' && echo yes)"
check "control: site shows the preset's locations" "yes" "$(curl -sS --unix-socket $CS http://control/v1/sites/laravel.test | grep -q '"path":"/index.php".*"handler":"fastcgi".*"from":"preset:laravel"' && echo yes)"
check "control: unknown site is a 404" "404" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS http://control/v1/sites/nope.test)"
check "control: validate reads the file on disk" "yes" "$(curl -sS --unix-socket $CS http://control/v1/config/validate | grep -q '"ok":true' && echo yes)"
curl -sS -o /dev/null http://127.0.0.1:8080/control-probe-404 >/dev/null; sleep 1.2
check "control: logs finds the 404 just made" "yes" "$(curl -sS --unix-socket $CS 'http://control/v1/logs?since=1m&status=4xx' | grep -q 'control-probe-404' && echo yes)"
check "control: presets catalogue comes from the preset table" "6 drupal yes" "$(curl -sS --unix-socket $CS http://control/v1/presets | python3 -c 'import json,sys; d=json.load(sys.stdin); p={x["app"]:x for x in d["presets"]}; print(len(p), "drupal" if "drupal" in p else "-", "yes" if "web/" in p["drupal"]["root"] and "/core/lib/" in p["drupal"]["no_php_under"] and p["laravel"]["php"].startswith("only /index.php") else "no")')"
check "control: health answers with findings" "yes" "$(curl -sS --unix-socket $CS http://control/v1/health | grep -q '"findings":\[' && echo yes)"
check "control: ctl logs and health through the client" "0 0" "$("$BIN" ctl logs --since 5m --status all --socket $CS > /dev/null; echo -n "$? "; "$BIN" ctl health --socket $CS > /dev/null; echo $?)"
# Mutations (F3): confirm required, the decision form, create, update, disable, enable, delete, reload.
cpost() { curl -sS -o bench/tmp/ctl-reply.json -w '%{http_code}' --unix-socket $CS -X POST -H 'Content-Type: application/json' -d "$2" "http://control$1"; }
check "control: a mutation without confirm is 428" "428" "$(cpost /v1/reload '{}')"
check "control: reload through the socket" "200 yes" "$(cpost /v1/reload '{"confirm":true,"reason":"test"}') $(grep -q 'role=admin reload (test): ok' bench/tmp/audit.log && echo yes)"
check "control: site-create asks for the open decisions" "422 https root app user" "$(cpost /v1/sites '{"domain":"created.test","confirm":true}') $(grep -o '"field":"[a-z_]*"' bench/tmp/ctl-reply.json | cut -d'"' -f4 | tr '\n' ' ' | sed 's/ $//')"
check "control: site-create refuses a bad domain" "400" "$(cpost /v1/sites '{"domain":"Bad_Host","confirm":true}')"
check "control: dry_run lists every problem at once and writes nothing" "200 root_missing yes no" "$(cpost /v1/sites "{\"domain\":\"dry.test\",\"https\":\"none\",\"user\":null,\"app\":\"static\",\"root\":\"$ROOT/bench/tmp/sites/nothere/web\",\"listen_plain\":\"127.0.0.1:8094\",\"dry_run\":true,\"confirm\":true}") $(python3 -c 'import json; d=json.load(open("bench/tmp/ctl-reply.json")); print(",".join(p["code"] for p in d["problems"]))') $(grep -q '"would_write":"# agensio:managed' bench/tmp/ctl-reply.json && echo yes) $([ -f bench/tmp/sites.d/dry.test.toml ] && echo yes || echo no)"
check "control: prerequisites come with codes and are all listed in one answer" "409 missing_account,root_missing" "$(cpost /v1/sites "{\"domain\":\"dry.test\",\"https\":\"none\",\"user\":\"nosuchuser\",\"app\":\"static\",\"root\":\"$ROOT/bench/tmp/sites/nothere/web\",\"listen_plain\":\"127.0.0.1:8094\",\"confirm\":true}") $(python3 -c 'import json; d=json.load(open("bench/tmp/ctl-reply.json")); print(",".join(p["code"] for p in d["problems"]))')"
check "control: the string \"null\" is not a user name; no command is generated" "400 yes no" "$(cpost /v1/sites '{"domain":"created.test","https":"none","app":"static","root":"/var/www/html","user":"null","confirm":true}') $(grep -q 'no_user: true' bench/tmp/ctl-reply.json && echo yes) $(grep -q 'useradd\|chown' bench/tmp/ctl-reply.json && echo yes || echo no)"
check "control: a shell metacharacter in root is refused before any command" "400 no" "$(cpost /v1/sites '{"domain":"created.test","https":"none","app":"static","user":null,"root":"/var/www/x;id","confirm":true}') $(grep -q 'chown' bench/tmp/ctl-reply.json && echo yes || echo no)"
check "control: no_user together with a user is refused" "400" "$(cpost /v1/sites '{"domain":"created.test","https":"none","app":"static","root":"/var/www/html","user":"web9","no_user":true,"confirm":true}')"
check "control: site-create names the root work still missing" "409 yes" "$(cpost /v1/sites "{\"domain\":\"created.test\",\"https\":\"none\",\"user\":null,\"app\":\"static\",\"root\":\"$ROOT/bench/tmp/sites/nothere/web\",\"confirm\":true}") $(grep -q '"run_as_root":\["mkdir -p' bench/tmp/ctl-reply.json && echo yes)"
check "control: site-create writes the file, reloads, the site answers" "201 created" "$(cpost /v1/sites "{\"domain\":\"created.test\",\"aliases\":[\"www.created.test\"],\"https\":\"none\",\"user\":null,\"app\":\"static\",\"root\":\"$ROOT/bench/tmp/sites/created.test/web\",\"listen_plain\":\"127.0.0.1:8094\",\"confirm\":true,\"reason\":\"test\"}") $(curl -sS -H 'Host: www.created.test' http://127.0.0.1:8094/)"
check "control: site-create warns that the new listener has no catch-all" "yes" "$(grep -q '"warnings":\["requests to 127.0.0.1:8094 with a Host this site does not list answer 421' bench/tmp/ctl-reply.json && echo yes)"
check "control: the managed file carries its spec and is listed by sites" "yes yes" "$(head -1 bench/tmp/sites.d/created.test.toml | grep -q '^# agensio:managed {"domain":"created.test"' && echo yes) $(curl -sS --unix-socket $CS http://control/v1/sites | grep -q '"server_name":\["created.test","www.created.test"\]' && echo yes)"
check "control: no_user: true on update is accepted and keeps the site without an account" "200 true" "$(cpost /v1/sites/created.test '{"no_user":true,"confirm":true}') $(python3 -c 'import json; print(str(json.load(open("bench/tmp/ctl-reply.json"))["spec"]["no_user"]).lower())')"
check "control: site-update adds an alias without re-asking decided fields" "200 created" "$(cpost /v1/sites/created.test '{"aliases":["www.created.test","m.created.test"],"confirm":true}') $(curl -sS -H 'Host: m.created.test' http://127.0.0.1:8094/)"
check "control: a hand-written site cannot be updated" "409" "$(cpost /v1/sites/laravel.test '{"aliases":["x.test"],"confirm":true}')"
check "control: site-disable stops serving, keeps the file" "200 000 yes" "$(cpost /v1/sites/created.test/disable '{"confirm":true}') $(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8094/ 2>/dev/null) $([ -f bench/tmp/sites.d/created.test.toml.disabled ] && echo yes)"
check "control: site-enable brings it back" "200 created" "$(cpost /v1/sites/created.test/enable '{"confirm":true}') $(curl -sS -H 'Host: created.test' http://127.0.0.1:8094/)"
check "control: cert-renew on a site without automatic TLS is refused" "409" "$(cpost /v1/sites/created.test/renew '{"confirm":true}')"
check "control: site-delete keeps a .bak and reloads" "200 yes 000" "$(cpost /v1/sites/created.test/delete '{"confirm":true}') $([ -f bench/tmp/sites.d/created.test.toml.bak ] && [ ! -f bench/tmp/sites.d/created.test.toml ] && echo yes) $(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:8094/ 2>/dev/null)"
printf '[[site]\n' > bench/tmp/sites.d/broken.toml
check "control: reload with a broken file on disk is refused, old configuration serves" "409 200" "$(cpost /v1/reload '{"confirm":true}') $(code http://127.0.0.1:8080/)"
rm -f bench/tmp/sites.d/broken.toml
check "control: ctl site-create through the client reports the decisions" "1 yes" "$("$BIN" ctl site-create --domain cli.test --yes --socket $CS > bench/tmp/ctl.out 2>&1; echo -n "$? "; grep -q 'decisions needed' bench/tmp/ctl.out && echo yes)"
check "control: audit has every mutation with its result" "yes" "$(grep -q 'sites (test): created' bench/tmp/audit.log && grep -q 'sites/created.test/delete: delete' bench/tmp/audit.log && grep -q 'reload: .*broken.toml' bench/tmp/audit.log && echo yes)"
# One rule set for hosting (2026-09-19): the ownership rules and the server's account live in
# services/pools.* only; a second implementation anywhere else fails this check.
check "hosting rules: one implementation, the server's account derived in one place" "1 1" "$(grep -l 'expected group\|readable by other users' src/*.cpp src/*/*.cpp | wc -l | tr -d ' ') $(grep -l 'current_group_name()' src/*.cpp src/*/*.cpp | wc -l | tr -d ' ')"

# ---- uploads and site-install (F9): as the server's own account (no helper here) ----
tar czf bench/tmp/inst/wp.tgz -C tests wordpress
head -c 2097152 /dev/zero > bench/tmp/inst/big.bin
rm -rf bench/tmp/sites/inst.test bench/tmp/sites/wpinst.test; mkdir -p bench/tmp/sites/inst.test/web bench/tmp/sites/wpinst.test
check "install: an upload is stored under the state directory, 0600, and listed" "0 yes 600 yes" "$("$BIN" ctl upload wp.tgz bench/tmp/inst/wp.tgz --socket $CS > bench/tmp/ctl.out; echo -n "$? "; grep -q '"file":"wp.tgz"' bench/tmp/ctl.out && echo -n yes; echo -n " $(stat -c %a bench/tmp/state/uploads/wp.tgz 2>/dev/null || stat -f %Lp bench/tmp/state/uploads/wp.tgz) "; "$BIN" ctl uploads --socket $CS | grep -q '"file":"wp.tgz","bytes":' && echo yes)"
check "install: the uploads directory is the server's own, 0700" "700" "$(stat -c %a bench/tmp/state/uploads 2>/dev/null || stat -f %Lp bench/tmp/state/uploads)"
check "install: an upload above upload_max is refused with 413 before it is stored" "413 no" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X PUT --data-binary @bench/tmp/inst/big.bin http://control/v1/uploads/big.bin 2>/dev/null) $([ -e bench/tmp/state/uploads/big.bin ] && echo yes || echo no)"
check "install: an upload name with a slash or a leading dot is refused" "400 400" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X PUT --data-binary @bench/tmp/inst/wp.tgz http://control/v1/uploads/.hidden) $(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X PUT --data-binary @bench/tmp/inst/wp.tgz 'http://control/v1/uploads/')"
cpost /v1/sites "{\"domain\":\"inst.test\",\"https\":\"none\",\"user\":null,\"app\":\"static\",\"root\":\"$ROOT/bench/tmp/sites/inst.test/web\",\"listen_plain\":\"127.0.0.1:8096\",\"confirm\":true,\"reason\":\"install\"}" > /dev/null
check "install: site-install without a source on a static site asks for one" "422" "$(cpost /v1/sites/inst.test/install '{"confirm":true,"reason":"t"}')"
check "install: a plain http url is refused, a private https address is fenced" "400 409 yes" "$(cpost /v1/sites/inst.test/install '{"url":"http://127.0.0.1/x.tgz","confirm":true}') $(cpost /v1/sites/inst.test/install '{"url":"https://127.0.0.1:8443/wp.tgz","confirm":true}') $(grep -q 'private or local address' bench/tmp/ctl-reply.json && echo yes)"
check "install: dry_run names the target, the account and the source without installing" "200 yes yes" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","dry_run":true,"confirm":true}') $(grep -q "\"target\":\"$ROOT/bench/tmp/sites/inst.test/web\"" bench/tmp/ctl-reply.json && echo yes) $([ -z "$(ls -A bench/tmp/sites/inst.test/web)" ] && echo yes)"
check "install: from the upload: files land in the site, the top directory unwrapped, next steps given" "201 wordpress 644 yes" "$("$BIN" ctl site-install inst.test --file wp.tgz --yes --reason t --socket $CS > bench/tmp/ctl.out; python3 -c 'import json; d=json.load(open("bench/tmp/ctl.out")); print(201 if d["ok"] else d, d.get("unwrapped"))' | tr -d '\n') $(stat -c %a bench/tmp/sites/inst.test/web/index.php 2>/dev/null || stat -f %Lp bench/tmp/sites/inst.test/web/index.php) $(grep -q '"next_steps":\[' bench/tmp/ctl.out && echo yes)"
check "install: the site serves what was installed" "200" "$(code -H 'Host: inst.test' http://127.0.0.1:8096/wp-login.php)"
check "install: a second install into the same directory is refused" "409 yes" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","confirm":true}') $(grep -q 'not empty' bench/tmp/ctl-reply.json && echo yes)"
check "install: a wrong sha256 is refused and leaves nothing behind" "409 yes yes" "$(rm -rf bench/tmp/sites/inst.test/web/*; cpost /v1/sites/inst.test/install "{\"file\":\"wp.tgz\",\"sha256\":\"$(printf '0%.0s' $(seq 1 64))\",\"confirm\":true}") $(grep -q 'sha256 mismatch' bench/tmp/ctl-reply.json && echo yes) $([ -z "$(ls -A bench/tmp/sites/inst.test/web)" ] && echo yes)"
check "install: the right sha256 passes" "201" "$(cpost /v1/sites/inst.test/install "{\"file\":\"wp.tgz\",\"sha256\":\"$(sha256sum bench/tmp/inst/wp.tgz | cut -c1-64)\",\"confirm\":true}")"
check "install: a plugin path that does not exist is refused without create_path, and dry_run says the same" "409 yes 409 yes" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"plugins/demo","confirm":true}') $(grep -q 'send create_path' bench/tmp/ctl-reply.json && echo yes) $(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"plugins/demo","dry_run":true,"confirm":true}') $(grep -q '"dry_run":true' bench/tmp/ctl-reply.json && echo yes)"
check "install: dry_run with create_path lists what would be created and makes nothing" "200 2 no" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"plugins/demo","create_path":true,"dry_run":true,"confirm":true}') $(python3 -c 'import json; print(len(json.load(open("bench/tmp/ctl-reply.json"))["would_create"]))') $([ -e bench/tmp/sites/inst.test/web/plugins ] && echo yes || echo no)"
check "install: a plugin lands in a created directory below the site, reported under created" "201 2 yes 755" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"plugins/demo","create_path":true,"confirm":true,"reason":"plugin"}') $(python3 -c 'import json; print(len(json.load(open("bench/tmp/ctl-reply.json"))["created"]))') $([ -f bench/tmp/sites/inst.test/web/plugins/demo/index.php ] && echo yes) $(stat -c %a bench/tmp/sites/inst.test/web/plugins/demo 2>/dev/null || stat -f %Lp bench/tmp/sites/inst.test/web/plugins/demo)"
ln -s /tmp bench/tmp/sites/inst.test/web/out
check "install: a symlinked component, a '..' path and a refused multi-level creation leave nothing" "409 400 409 no" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"out/x","create_path":true,"confirm":true}') $(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","path":"plugins/../../x","create_path":true,"confirm":true}') $(cpost /v1/sites/inst.test/install "{\"file\":\"wp.tgz\",\"path\":\"themes/contrib/bad\",\"create_path\":true,\"sha256\":\"$(printf '0%.0s' $(seq 1 64))\",\"confirm\":true}") $([ -e bench/tmp/sites/inst.test/web/themes ] && echo yes || echo no)"
check "install: the audit log records the created directories" "yes" "$(grep -q 'install (plugin): installed .* created .*/plugins/demo' bench/tmp/audit.log && echo yes)"
# site-copy (F9b): a drop-in from the plugin into an existing directory, as the site's account.
check "copy: dry_run reports the resolved paths and mode without writing" "200 yes no" "$(cpost /v1/sites/inst.test/install '{"file":"wp.tgz","confirm":true}' > /dev/null; cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/index.php","to":"wp-content/dropin.php","dry_run":true,"confirm":true}') $(grep -q "\"to\":\"$ROOT/bench/tmp/sites/inst.test/web/wp-content/dropin.php\"" bench/tmp/ctl-reply.json && echo yes) $([ -e bench/tmp/sites/inst.test/web/wp-content/dropin.php ] && echo yes || echo no)"
check "copy: the file lands with the directory's pattern and the same bytes; 201; audited" "0 201 yes yes 644" "$("$BIN" ctl site-copy inst.test --from plugins/demo/index.php --to wp-content/dropin.php --yes --reason dropin --socket $CS > bench/tmp/ctl.out; echo -n "$? "; echo -n "$(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/index.php","to":"wp-content/dropin2.php","confirm":true,"reason":"dropin"}') "; cmp -s bench/tmp/sites/inst.test/web/plugins/demo/index.php bench/tmp/sites/inst.test/web/wp-content/dropin.php && echo -n yes; echo -n " "; grep -q 'copy (dropin): wrote .*wp-content/dropin.php from .*plugins/demo/index.php' bench/tmp/audit.log && echo -n yes; echo " $(stat -c %a bench/tmp/sites/inst.test/web/wp-content/dropin.php 2>/dev/null || stat -f %Lp bench/tmp/sites/inst.test/web/wp-content/dropin.php)")"
check "copy: an existing destination (the fixture's db.php) is refused, replaced with overwrite (old size reported, 200)" "409 yes 200 yes" "$(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/index.php","to":"wp-content/db.php","confirm":true}') $(grep -q 'send overwrite' bench/tmp/ctl-reply.json && echo yes) $(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/wp-login.php","to":"wp-content/db.php","overwrite":true,"confirm":true}') $(grep -q '"replaced":{"bytes":' bench/tmp/ctl-reply.json && echo yes)"
check "copy: '..', a missing source, a directory, a missing destination directory and a symlinked component are refused" "400 409 409 409 409 yes" "$(cpost /v1/sites/inst.test/copy '{"from":"../x","to":"wp-content/a","confirm":true}') $(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/nope.php","to":"wp-content/a","confirm":true}') $(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo","to":"wp-content/a","confirm":true}') $(cpost /v1/sites/inst.test/copy '{"from":"plugins/demo/index.php","to":"wp-content/cache/a","confirm":true}') $(cpost /v1/sites/inst.test/copy '{"from":"out/passwd","to":"wp-content/a","confirm":true}') $(grep -q 'symlink' bench/tmp/ctl-reply.json && echo yes)"
check "copy: nothing was written for any refusal, no temporary file left" "0" "$(ls -A bench/tmp/sites/inst.test/web/wp-content | grep -c 'agensio-copy\|^a$\|^cache$')"
check "install: a wordpress site picks the preset's official archive by itself (dry run)" "201 200 https://wordpress.org/wordpress-6.7.1.tar.gz" "$(cpost /v1/sites "{\"domain\":\"wpinst.test\",\"https\":\"none\",\"user\":null,\"app\":\"wordpress\",\"root\":\"$ROOT/bench/tmp/sites/wpinst.test\",\"php_socket\":\"unix:$ROOT/bench/tmp/php/fpm.sock\",\"listen_plain\":\"127.0.0.1:8096\",\"confirm\":true}")$(grep -q '"ok":true' bench/tmp/ctl-reply.json || cat bench/tmp/ctl-reply.json) $(cpost /v1/sites/wpinst.test/install '{"version":"6.7.1","dry_run":true,"confirm":true}') $(python3 -c 'import json; print(json.load(open("bench/tmp/ctl-reply.json"))["source"])')"
sed -i 's/^\[control\]$/[control]\ninstall = false/' bench/tmp/agensio-test.toml; cpost /v1/reload '{"confirm":true}' > /dev/null
check "install: with [control] install = false a download is refused and the upload path is offered" "403 yes 200" "$(cpost /v1/sites/wpinst.test/install '{"url":"https://wordpress.org/latest.tar.gz","confirm":true}') $(grep -q 'upload the archive' bench/tmp/ctl-reply.json && echo yes) $(cpost /v1/sites/wpinst.test/install '{"file":"wp.tgz","dry_run":true,"confirm":true}')"
sed -i '/^install = false$/d' bench/tmp/agensio-test.toml; cpost /v1/reload '{"confirm":true}' > /dev/null
check "secrets: installing WordPress makes wp-config.php 0600 (reported under secured), the configuration validates" "201 yes 600 true" "$(cpost /v1/sites/wpinst.test/install '{"file":"wp.tgz","confirm":true,"reason":"wp"}') $(grep -q "\"secured\":\[\"$ROOT/bench/tmp/sites/wpinst.test/wp-config.php\"\]" bench/tmp/ctl-reply.json && echo yes) $(stat -c %a bench/tmp/sites/wpinst.test/wp-config.php 2>/dev/null || stat -f %Lp bench/tmp/sites/wpinst.test/wp-config.php) $(curl -sS --unix-socket $CS http://control/v1/config/validate | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')"
check "secrets: a copy onto wp-config.php is 0600 whatever the directory's pattern; health has no hosting finding" "200 0600 true 600 0" "$(cpost /v1/sites/wpinst.test/copy '{"from":"index.php","to":"wp-config.php","overwrite":true,"confirm":true,"reason":"cfg"}') $(python3 -c 'import json; d=json.load(open("bench/tmp/ctl-reply.json")); print(d["mode"], str(d["secured"]).lower())') $(stat -c %a bench/tmp/sites/wpinst.test/wp-config.php 2>/dev/null || stat -f %Lp bench/tmp/sites/wpinst.test/wp-config.php) $(curl -sS --unix-socket $CS http://control/v1/health | grep -o '"code":"hosting_rule"' | wc -l | tr -d ' ')"
# Per-site settings (F10): an allowlist within root's ceilings, discoverable, per site.
head -c 3145728 /dev/zero > bench/tmp/inst/3mb.bin; head -c 1572864 /dev/zero > bench/tmp/inst/1.5mb.bin
check "settings: the catalogue lists every key with unit, default, ceiling and cost" "max_body_size,memory_limit,max_execution_time,max_input_time,children,pm,max_requests 512MB 1MB yes" "$(curl -sS --unix-socket $CS http://control/v1/settings | python3 -c 'import json,sys; d=json.load(sys.stdin)["settings"]; m=[x for x in d if x["key"]=="max_body_size"][0]; print(",".join(x["key"] for x in d), m["maximum"], m["default"], "yes" if all(x["applies"] and x["meaning"] and x["type"] for x in d) else "no")')"
check "settings: site-update raises one site's max_body_size; the other site keeps the server's 1 MB" "200 413 405 413" "$("$BIN" ctl site-update inst.test --set max_body_size=2MB --yes --reason limit --socket $CS > bench/tmp/ctl.out; echo -n "$? " | sed 's/^0 /200 /'; curl -sS -o /dev/null -w '%{http_code} ' -H 'Host: inst.test' --data-binary @bench/tmp/inst/3mb.bin http://127.0.0.1:8096/; curl -sS -o /dev/null -w '%{http_code} ' -H 'Host: inst.test' --data-binary @bench/tmp/inst/1.5mb.bin http://127.0.0.1:8096/; curl -sS -o /dev/null -w '%{http_code}' --data-binary @bench/tmp/inst/1.5mb.bin http://127.0.0.1:8080/)"
check "settings: the answer says what was written and reloaded; site NAME shows the value and its source" "yes 2MB site 1MB server" "$(grep -q '"done":\["site file .*written, agensio reloaded"' bench/tmp/ctl.out && echo yes) $(curl -sS --unix-socket $CS http://control/v1/sites/inst.test | python3 -c 'import json,sys; d=json.load(sys.stdin)["settings"]["max_body_size"]; print(d["value"], d["source"])') $(curl -sS --unix-socket $CS http://control/v1/sites/strict.test | python3 -c 'import json,sys; d=json.load(sys.stdin)["settings"]["max_body_size"]; print(d["value"], d["source"])')"
check "settings: a value above the ceiling is refused naming key, value and ceiling; nothing written" "400 yes 2MB" "$(cpost /v1/sites/inst.test '{"settings":{"max_body_size":"10GB"},"confirm":true}') $(grep -q 'max_body_size: 10GB is above the ceiling 512MB' bench/tmp/ctl-reply.json && echo yes) $(grep -o 'max_body_size = .*' bench/tmp/sites.d/inst.test.toml | head -1 | cut -d= -f2 | tr -d ' \"')"
check "settings: every ini key outside the allowlist is refused as unknown, through settings" "400 400 400 400 400 400 yes" "$(for k in sendmail_path auto_prepend_file extension disable_functions open_basedir extra; do cpost /v1/sites/inst.test "{\"settings\":{\"$k\":\"/bin/sh\"},\"confirm\":true}"; echo -n ' '; done; grep -q 'unknown setting' bench/tmp/ctl-reply.json && echo yes)"
check "settings: pool keys need a site with its own user; the refusal says so" "400 yes" "$(cpost /v1/sites/inst.test '{"settings":{"memory_limit":"512M"},"confirm":true}') $(grep -q 'needs a site with its own user' bench/tmp/ctl-reply.json && echo yes)"
check "settings: the MCP schema, the catalogue and what site_update accepts are one set" "same same" "$(python3 - "$BIN" "$ROOT/bench/tmp/control.sock" <<'PYT'
import json, subprocess, sys, urllib.request
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"); p.stdin.flush()
tools = {t["name"]: t for t in json.loads(p.stdout.readline())["result"]["tools"]}
schema = set(tools["site_update"]["inputSchema"]["properties"]["settings"]["properties"])
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "site_settings_list", "arguments": {}}}) + "\n"); p.stdin.flush()
catalogue = set(x["key"] for x in json.loads(p.stdout.readline())["result"]["structuredContent"]["settings"])
accepted = set()
for k in schema | catalogue | {"bogus_key"}:
    p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "site_update", "arguments": {"name": "inst.test", "settings": {k: 1}, "confirm": True, "reason": "drift"}}}) + "\n"); p.stdin.flush()
    text = json.loads(p.stdout.readline())["result"]["content"][0]["text"]
    if "unknown setting" not in text: accepted.add(k)
p.stdin.close(); p.wait()
print("same" if schema == catalogue else "schema!=catalogue", "same" if accepted == catalogue else "accepted!=catalogue %s" % sorted(accepted ^ catalogue))
PYT
)"
"$BIN" ctl site-update inst.test --set max_body_size=1MB --yes --reason back --socket $CS > /dev/null
check "secrets: the presets catalogue lists each preset's credential files" "/wp-config.php /sites/default/settings.php" "$(curl -sS --unix-socket $CS http://control/v1/presets | python3 -c 'import json,sys; p={x["app"]:x for x in json.load(sys.stdin)["presets"]}; print(p["wordpress"]["secrets"][0], p["drupal"]["secrets"][0])')"
check "install: uploads-delete removes the file; the list is empty" "0 no 0" "$("$BIN" ctl uploads-delete wp.tgz --yes --reason done --socket $CS > /dev/null; echo -n "$? "; [ -e bench/tmp/state/uploads/wp.tgz ] && echo -n yes || echo -n no; echo -n " "; "$BIN" ctl uploads --socket $CS | grep -o '"file":' | wc -l | tr -d ' ')"
check "install: every step is in the audit log" "yes yes yes" "$(grep -q 'uploads/wp.tgz: stored' bench/tmp/audit.log && echo yes) $(grep -q 'sites/inst.test/install (t): installed' bench/tmp/audit.log && echo yes) $(grep -q 'uploads/wp.tgz/delete (done): deleted' bench/tmp/audit.log && echo yes)"
cpost /v1/sites/inst.test/delete '{"confirm":true}' > /dev/null; cpost /v1/sites/wpinst.test/delete '{"confirm":true}' > /dev/null

# ---- read boundaries (2026-09-20, the "GETGET" report): every split of a request line,
# hundreds of requests on one connection, two requests in one write, and the exact
# trigger: a request answered after the abort watch of a slow exchange was armed. ----
boundary=$(python3 - "$ROOT" <<'PYT'
import os, socket, ssl, sys, time
root = sys.argv[1]
INDEX = os.path.getsize(root + "/bench/www/index.html"); CSS = os.path.getsize(root + "/bench/www/style.css")
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
def read_response(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(65536)
        if not chunk: return None, b""
        data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    length = int([l for l in head.decode().split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
    while len(body) < length: body += conn.recv(65536)
    return head.split(b"\r\n")[0].decode(), body
def plain(): return socket.create_connection(("127.0.0.1", 8080))
def tls(): return ctx.wrap_socket(socket.create_connection(("127.0.0.1", 8443)), server_hostname="localhost")
out = []
req = b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\n"
# A: every split point of the request, plain and TLS, one connection each.
for name, connect in (("plain", plain), ("tls", tls)):
    bad = []
    for i in range(1, len(req)):
        c = connect(); c.settimeout(5)
        c.sendall(req[:i]); time.sleep(0.02); c.sendall(req[i:])
        status, body = read_response(c)
        c.close()
        if status != "HTTP/1.1 200 OK" or len(body) != INDEX: bad.append(i)
    out.append("%s-splits=%s" % (name, "ok" if not bad else "bad@%s" % bad[:5]))
# B: 240 requests down one keep-alive connection, varied method, path length and headers.
c = plain(); c.settimeout(5); wrong = 0
for i in range(240):
    path = "/index.html" if i % 3 else "/style.css"
    extra = "".join("X-H%d: %s\r\n" % (k, "v" * (i % 17)) for k in range(i % 7))
    q = "?" + "a" * (i % 53)
    c.sendall(("HEAD" if i % 5 == 4 else "GET").encode() + b" " + (path + q).encode() + b" HTTP/1.1\r\nHost: localhost\r\n" + extra.encode() + b"\r\n")
    data = b""
    while b"\r\n\r\n" not in data: data += c.recv(65536)
    head, body = data.split(b"\r\n\r\n", 1)
    length = int([l for l in head.decode().split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
    if i % 5 != 4:
        while len(body) < length: body += c.recv(65536)
    want = INDEX if path == "/index.html" else CSS
    if not head.startswith(b"HTTP/1.1 200") or length != want: wrong += 1
c.close(); out.append("keepalive-wrong=%d" % wrong)
# C: two requests in one write, answered in order.
c = plain(); c.settimeout(5)
c.sendall(b"GET /index.html HTTP/1.1\r\nHost: localhost\r\n\r\nGET /style.css HTTP/1.1\r\nHost: localhost\r\n\r\n")
s1, b1 = read_response(c); s2, b2 = read_response(c); c.close()
out.append("pipelined=%s" % ("ok" if s1 == s2 == "HTTP/1.1 200 OK" and len(b1) == INDEX and len(b2) == CSS else "bad %s %d %s %d" % (s1, len(b1), s2, len(b2))))
# D: the trigger. A proxied request slow enough for the abort watch (one pool tick), then,
# only after its answer, a request of a different length on the same connection.
def proxied(path, extra=b""):
    c = socket.create_connection(("127.0.0.1", 8091)); c.settimeout(10)
    c.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: proxy.test\r\n" + extra + b"\r\n")
    r = read_response(c); c.close(); return r
JSON = proxied(b"/api/json"); BIG = proxied(b"/api/big")
c = socket.create_connection(("127.0.0.1", 8091)); c.settimeout(10)
c.sendall(b"GET /api/slow?ms=600 HTTP/1.1\r\nHost: proxy.test\r\n\r\n")
s1, b1 = read_response(c)
c.sendall(b"GET /api/json HTTP/1.1\r\nHost: proxy.test\r\nX-Pad: abc\r\n\r\n")  # a different length from the slow request
s2, b2 = read_response(c)
c.sendall(b"GET /api/big HTTP/1.1\r\nHost: proxy.test\r\n\r\n")
s3, b3 = read_response(c); c.close()
out.append("after-slow=%s" % ("ok" if s1 == "HTTP/1.1 200 OK" and (s2, b2) == JSON and (s3, b3) == BIG else "bad %s %s %d %s %d" % (s1, s2, len(b2), s3, len(b3))))
print(" ".join(out))
PYT
)
check "boundaries: every split of the request line on plain and TLS, 240 keep-alive requests, two in one write, a request after a slow exchange" "plain-splits=ok tls-splits=ok keepalive-wrong=0 pipelined=ok after-slow=ok" "$boundary"
check "boundaries: an unrecognised method is 405 and the line is logged, escaped; a malformed line is 400 and logged" "405 400 yes yes" "$(printf 'GETGET /x HTTP/1.1\r\nHost: localhost\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | awk '{print $2}') $(printf 'GET\x01 /x HTTP/1.1\r\nHost: localhost\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | awk '{print $2}') $(grep -q "unrecognised method 'GETGET' for /x from 127.0.0.1 (405)" bench/tmp/error.log && echo yes) $(grep -q 'request line did not parse from 127.0.0.1: GET\\x01 /x HTTP/1.1' bench/tmp/error.log && echo yes)"

# Static rules of the control plane (F7): nothing there spawns a process or opens a port.
check "control: no process spawning anywhere under src/control" "0" "$(grep -E 'system\(|popen\(|execv|execl|fork\(|posix_spawn' src/control/*.cpp src/control/*.hpp | wc -l | tr -d ' ')"
check "control: no TCP listener in the control plane" "0" "$(grep -E 'ip::tcp::acceptor' src/control/*.cpp src/control/*.hpp | wc -l | tr -d ' ')"

# The MCP bridge (F5): JSON-RPC on stdin/stdout, tools gated by role, calls forwarded to the socket.
mcp=$(python3 - "$BIN" "$ROOT/bench/tmp/control.sock" <<'PYT'
import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
def rpc(i, method, params=None):
    msg = {"jsonrpc": "2.0", "id": i, "method": method}
    if params is not None: msg["params"] = params
    p.stdin.write(json.dumps(msg) + "\n"); p.stdin.flush()
    return json.loads(p.stdout.readline())
out = []
r = rpc(1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
out.append(r["result"]["serverInfo"]["name"])
p.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n"); p.stdin.flush()
tools = rpc(2, "tools/list")["result"]["tools"]
out.append(str(len(tools)))
out.append(str([t["annotations"]["readOnlyHint"] for t in tools if t["name"] == "health_check"][0]))
r = rpc(3, "tools/call", {"name": "site_show", "arguments": {"name": "laravel.test"}})
out.append("laravel" if not r["result"]["isError"] and r["result"]["structuredContent"]["app"] == "laravel" else "bad")
r = rpc(4, "tools/call", {"name": "reload", "arguments": {"reason": "mcp"}})
out.append("428" if r["result"]["isError"] and "confirm required" in r["result"]["content"][0]["text"] else "bad")
r = rpc(5, "tools/call", {"name": "reload", "arguments": {"confirm": True, "reason": "mcp"}})
out.append("reloaded" if not r["result"]["isError"] else "bad")
r = rpc(6, "tools/call", {"name": "site_create", "arguments": {"domain": "mcp.test", "confirm": True, "reason": "mcp"}})
out.append(",".join(n["field"] for n in r["result"]["structuredContent"]["needs"]))
out.append(str(rpc(7, "nope")["error"]["code"]))
out.append(str(len(rpc(8, "prompts/list")["result"]["prompts"])))
p.stdin.close(); p.wait()
print(" ".join(out))
PYT
)
check "mcp: initialize, tool list with annotations, calls, confirm, decisions, prompts" "agensio 20 True laravel 428 reloaded https,root,app,user -32601 2" "$mcp"
check "mcp: site_install and the upload tools are exposed with their arguments" "file url,file,version,sha256 True" "$(python3 - "$BIN" "$ROOT/bench/tmp/control.sock" <<'PYT'
import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"); p.stdin.flush()
tools = {t["name"]: t for t in json.loads(p.stdout.readline())["result"]["tools"]}
props = tools["site_install"]["inputSchema"]["properties"]
out = [",".join(tools["upload_delete"]["inputSchema"]["required"][:1]), ",".join(k for k in ["url", "file", "version", "sha256"] if k in props)]
out.append(str(tools["upload_delete"]["annotations"]["destructiveHint"]))
p.stdin.close(); p.wait()
print(" ".join(out))
PYT
)"
check "mcp: the site_create app options are exactly the presets the server accepts" "same" "$(python3 - "$BIN" "$ROOT/bench/tmp/control.sock" <<'PYT'
import json, subprocess, sys
p = subprocess.Popen([sys.argv[1], "mcp", "--socket", sys.argv[2]], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"); p.stdin.flush()
tools = json.loads(p.stdout.readline())["result"]["tools"]
enum = set(next(t for t in tools if t["name"] == "site_create")["inputSchema"]["properties"]["app"]["enum"])
p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "presets_list", "arguments": {}}}) + "\n"); p.stdin.flush()
names = set(x["app"] for x in json.loads(p.stdout.readline())["result"]["structuredContent"]["presets"])
p.stdin.close(); p.wait()
print("same" if enum == names else "differ %s %s" % (sorted(enum), sorted(names)))
PYT
)"
check "mcp: the reload through the bridge is in the audit log" "yes" "$(grep -q 'reload (mcp): ok' bench/tmp/audit.log && echo yes)"
if ssh -o BatchMode=yes -o ConnectTimeout=2 localhost true >/dev/null 2>&1; then
  check "mcp: over ssh localhost" "agensio" "$(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}\n' | ssh -o BatchMode=yes localhost "$BIN" mcp --socket "$ROOT/bench/tmp/control.sock" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["result"]["serverInfo"]["name"])')"
else
  echo "skip mcp: over ssh localhost (no sshd on this host)"
fi
check "ctl: --help on a change command prints usage, exit 0, no confirm needed" "0 yes" "$("$BIN" ctl site-update --help > bench/tmp/ctl-help.out 2>&1; echo -n "$? "; grep -q '^usage: agensio ctl' bench/tmp/ctl-help.out && echo yes)"
check "ctl: bare ctl and ctl --help print the command list" "yes yes" "$({ "$BIN" ctl 2>&1 || true; } | grep -q 'site-create' && echo yes) $({ "$BIN" ctl --help 2>&1 || true; } | grep -q 'site-create' && echo yes)"
check "ctl: a change without --yes says how to confirm" "yes" "$({ "$BIN" ctl reload --socket $CS 2>&1 >/dev/null || true; } | grep -q 'add --yes' && echo yes)"
check "control: socket file mode and no access-log line for it" "666 no" "$(stat -c %a $CS 2>/dev/null || stat -f %Lp $CS) $(grep -q 'v1/status' bench/tmp/access.log && echo yes || echo no)"

# ---- presets: Drupal (many entry points) and WordPress, what executes and what is refused ----
if [ -n "$FPM_PID" ]; then
  D=http://127.0.0.1:8095
  mkdir -p tests/drupal/web/.git; printf '[core]\n' > tests/drupal/web/.git/config; printf 'SECRET=1\n' > tests/drupal/web/.env; printf 'sqlite db\n' > tests/drupal/web/sites/default/files/.ht.sqlite
  no_source() { curl -sS "$1" | grep -q '<?php\|hunter2\|s3cret' && echo LEAK || echo no-source; }
  check "drupal: front controller executes" "drupal front /" "$(curl -sS $D/)"
  check "drupal: a missing path goes to the front controller" "drupal front /node/1" "$(curl -sS $D/node/1)"
  check "drupal: a second .php entry point executes, no source, text/html" "drupal second entry point ok no-source text/html" "$(curl -sS $D/admin.php) $(no_source $D/admin.php) $(curl -sSI $D/admin.php | tr -d '\r' | awk 'tolower($1)=="content-type:"{print $2}' | cut -d';' -f1)"
  check "drupal: core/install.php is an entry point and executes" "drupal install entry point ok" "$(curl -sS $D/core/install.php)"
  check "drupal: library PHP under core/lib is refused" "404 no-source" "$(code $D/core/lib/Drupal.php) $(no_source $D/core/lib/Drupal.php)"
  check "drupal: settings.php is a 404, never executed or shown" "404 no-source" "$(code $D/sites/default/settings.php) $(no_source $D/sites/default/settings.php)"
  check "drupal: PHP under files/ is refused" "404" "$(code $D/sites/default/files/x.php)"
  # An image-style derivative or an aggregate that exists serves statically; once deleted, the
  # same URL, query string included, reaches index.php, which is what regenerates it
  # (2026-09-20 report: a deleted derivative was a 404 from us for ever). A missing PHP-like
  # file below files/ stays a 404 that never reaches PHP.
  DF=tests/drupal/web/sites/default/files
  check "drupal: an existing image-style derivative and aggregate serve statically" "200 image/jpeg JPEGDATA 200 text/css" "$(curl -sSi "$D/sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls" | tr -d '\r' | awk 'NR==1{c=$2} tolower($1)=="content-type:"{t=$2} END{printf "%s %s ", c, t}'; curl -sS "$D/sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls"; echo -n " "; curl -sSi $D/sites/default/files/css/agg.css | tr -d '\r' | awk 'NR==1{c=$2} tolower($1)=="content-type:"{t=$2} END{printf "%s %s", c, t}' | tr -d ';')"
  # Deleted on disk; the cache revalidates an entry at most once a second, so wait that out.
  mv $DF/styles/thumb/pic.jpg bench/tmp/pic.jpg.away; mv $DF/css/agg.css bench/tmp/agg.css.away; sleep 1.2
  check "drupal: a deleted derivative and aggregate reach the front controller with the query string (itok) intact" "drupal front /sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls | drupal front /sites/default/files/css/css_abc.css?delta=0" "$(curl -sS "$D/sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls"; echo -n " | "; curl -sS "$D/sites/default/files/css/css_abc.css?delta=0")"
  check "drupal: a missing PHP-like file below files/ is still a 404 that never reaches PHP" "404 404" "$(code $D/sites/default/files/styles/evil.php) $(code $D/sites/default/files/css/x.phtml)"
  mv bench/tmp/pic.jpg.away $DF/styles/thumb/pic.jpg; mv bench/tmp/agg.css.away $DF/css/agg.css
  check "drupal: restored, the derivative serves statically again" "200 JPEGDATA" "$(curl -sS -o /dev/null -w '%{http_code} ' "$D/sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls"; curl -sS "$D/sites/default/files/styles/thumb/pic.jpg?itok=S02fzuls")"
  check "drupal: the presets catalogue says which directory regenerates on a miss" "/sites/default/files/" "$(curl -sS --unix-socket bench/tmp/control.sock http://control/v1/presets | python3 -c 'import json,sys; p={x["app"]:x for x in json.load(sys.stdin)["presets"]}; print(p["drupal"]["missing_reaches_front_controller"][0], end=""); assert p["wordpress"]["missing_reaches_front_controller"] == []')"
  check "drupal: .ht.sqlite, .htaccess, .env, .git/config are 404" "404 404 404 404" "$(code $D/sites/default/files/.ht.sqlite) $(code $D/.htaccess) $(code $D/.env) $(code $D/.git/config)"
  check "drupal: a .sqlite dump and composer files are refused" "404 404" "$(code $D/data.sqlite) $(code $D/composer.json)"
  check "drupal: plain static files still serve" "public readme" "$(curl -sS $D/README.txt)"
  # What site-show reports as "deny" answers 404; what it reports as "static" with no refusal serves the file.
  check "drupal: every location reported as deny answers 404; the reported names are exact" "9 9 static" "$(curl -sS --unix-socket bench/tmp/control.sock http://control/v1/sites/drupal.test | python3 -c '
import json,sys,urllib.request
locs=json.load(sys.stdin)["locations"]
deny=[l["path"] for l in locs if l["handler"]=="deny"]
n404=0
for p in deny:
    try:
        urllib.request.urlopen("http://127.0.0.1:8095"+p); 
    except urllib.error.HTTPError as e:
        n404+= e.code==404
readme=[l for l in locs if l["path"]=="/" and l["handler"]=="static"]
print(len(deny), n404, readme[0]["handler"] if readme else "-")')"
  check "drupal: a missing .php is a 404 before php-fpm" "404" "$(code $D/nothere.php)"
  W=http://127.0.0.1:8096
  check "wordpress: front controller and pretty permalink" "wordpress front / wordpress front /hello-world/" "$(curl -sS $W/) $(curl -sS $W/hello-world/)"
  check "wordpress: wp-login.php executes, no source" "wp-login ok no-source" "$(curl -sS $W/wp-login.php) $(no_source $W/wp-login.php)"
  check "wordpress: every real entry point executes (xmlrpc, cron, admin-ajax, comments, signup, activate, trackback)" "7 0" "$(for f in xmlrpc.php wp-cron.php wp-admin/admin-ajax.php wp-comments-post.php wp-signup.php wp-activate.php wp-trackback.php; do curl -sS $W/$f; echo; done | grep -c 'entry ok') $(for f in xmlrpc.php wp-cron.php wp-admin/admin-ajax.php wp-comments-post.php wp-signup.php wp-activate.php wp-trackback.php; do curl -sS $W/$f; done | grep -c '<?php')"
  check "wordpress: wp-config.php is a 404, never shown" "404 no-source" "$(code $W/wp-config.php) $(no_source $W/wp-config.php)"
  check "wordpress: readme.html and license.txt (the version fingerprint) are 404 although present" "404 404 yes" "$(code $W/readme.html) $(code $W/license.txt) $([ -f tests/wordpress/readme.html ] && echo yes)"
  check "wordpress: the wp-content drop-ins (db.php, advanced-cache.php, object-cache.php) are 404, never executed; the SQLite file is hidden" "404 404 404 404 no" "$(code $W/wp-content/db.php) $(code $W/wp-content/advanced-cache.php) $(code $W/wp-content/object-cache.php) $(code $W/wp-content/database/.ht.sqlite) $(curl -sS $W/wp-content/db.php | grep -q 'drop-in ran' && echo yes || echo no)"
  check "wordpress: PHP under uploads and wp-includes refused, assets served" "404 404 200" "$(code $W/wp-content/uploads/shell.php) $(code $W/wp-includes/x.php) $(code $W/wp-includes/wp.js)"
  rm -rf tests/drupal/web/.git tests/drupal/web/.env tests/drupal/web/sites/default/files/.ht.sqlite
fi

# ---- request bodies (A3): decoded, limited, drained after the response ----
check "body on GET: served, drained, pipelined request answered" "2" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 5\r\n\r\nhelloGET /sub/ HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c 'HTTP/1.1 200')"
check "POST with body: 405, then keep-alive" "405 200" "$(printf 'POST / HTTP/1.1\r\nHost: l\r\nContent-Length: 3\r\n\r\nx=1GET / HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | awk '/^HTTP\/1.1/{printf "%s ", $2}' | sed 's/ $//')"
check "chunked body on GET: drained, pipelined request answered" "2" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nGET /sub/ HTTP/1.1\r\nHost: l\r\nConnection: close\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c 'HTTP/1.1 200')"
check "malformed chunked body: response, then close" "1" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nGET /sub/ HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c '^HTTP/1.1')"
check "Content-Length above max_body_size: 413" "HTTP/1.1 413 Content Too Large" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 999999999\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "413 closes the connection" "1" "$(printf 'GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 999999999\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080 | grep -c '^HTTP/1.1')"
check "Expect: 100-continue not read by handler: final answer, no 100, close" "405 close" "$(printf 'POST / HTTP/1.1\r\nHost: l\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n' | ncq 127.0.0.1 8080 | tr -d '\r' | awk '/^HTTP\/1.1/{s=$2} /^Connection:/{c=$2} END{print s, c}')"
check "unknown transfer coding: 501" "HTTP/1.1 501 Not Implemented" "$(printf 'POST / HTTP/1.1\r\nHost: l\r\nTransfer-Encoding: gzip\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "Expect other than 100-continue: 417" "HTTP/1.1 417 Expectation Failed" "$(printf 'POST / HTTP/1.1\r\nHost: l\r\nContent-Length: 1\r\nExpect: x\r\n\r\n' | ncq 127.0.0.1 8080 | head -1 | tr -d '\r')"
check "curl POST 405 keeps the connection for the next request" "0" "$(curl -sS -o /dev/null -o /dev/null -w '%{num_connects}\n' -d 'a=b' http://127.0.0.1:8080/ http://127.0.0.1:8080/ | tail -1)"
# ---- access log (A5): combined format, buffered per worker, flushed each second ----
curl -sS -o /dev/null -A 'agensio-test/1.0' -e 'http://ref.example/' http://127.0.0.1:8080/
curl -sS -o /dev/null -I http://127.0.0.1:8080/
curl -sS -o /dev/null http://127.0.0.1:8080/nope
sleep 1.2
IDXLEN=$(wc -c < bench/www/index.html | tr -d ' ')
check "access log: GET line with status, size, referer, agent" "1" "$(grep -c "^127.0.0.1 - - \[.*\] \"GET / HTTP/1.1\" 200 $IDXLEN \"http://ref.example/\" \"agensio-test/1.0\"$" bench/tmp/access.log)"
check "access log: HEAD counts no body bytes" "yes" "$(grep -q '"HEAD / HTTP/1.1" 200 0 ' bench/tmp/access.log && echo yes)"
check "access log: 404 logged" "yes" "$(grep -q '"GET /nope HTTP/1.1" 404 ' bench/tmp/access.log && echo yes)"
check "access log: 405 POST logged" "yes" "$(grep -q '"POST / HTTP/1.1" 405 ' bench/tmp/access.log && echo yes)"
check "access log: streamed 10MB logs its size" "yes" "$(grep -q '"GET /big.bin HTTP/1.1" 200 10485760 ' bench/tmp/access.log && echo yes)"
check "access log: unparsable request logged as 400" "yes" "$(grep -q '"-" 400 ' bench/tmp/access.log && echo yes)"
check "access log: 501 logged with its request line" "yes" "$(grep -q '"POST / HTTP/1.1" 501 ' bench/tmp/access.log && echo yes)"
mv bench/tmp/access.log bench/tmp/access.log.1
kill -USR1 $PID; sleep 0.3
curl -sS -o /dev/null http://127.0.0.1:8080/style.css; sleep 1.2
check "access log: SIGUSR1 reopens the file" "yes" "$([ -s bench/tmp/access.log ] && grep -q '"GET /style.css HTTP/1.1" 200 ' bench/tmp/access.log && echo yes)"
curl -sS -o /dev/null -H 'X-Forwarded-For: 198.51.100.7' http://127.0.0.1:8080/style.css; sleep 1.2
check "access log: client address from a trusted proxy" "yes" "$(grep -q '^198.51.100.7 - - .*"GET /style.css' bench/tmp/access.log && echo yes)"
printf '<html><body>changed</body></html>\n' > bench/www/sub/index.html; sleep 1.2
check "revalidation picks up change" "changed" "$(curl -sS http://127.0.0.1:8080/sub/ | sed 's/<[^>]*>//g')"
printf '<html><body>sub index</body></html>\n' > bench/www/sub/index.html
# Streamed files (above cache.max_file_size = 4MB) keep a cached descriptor; a replaced file
# with a different size must be picked up after the revalidate interval.
head -c 5242880 /dev/urandom > bench/www/stream.bin
S1=$(sum < bench/www/stream.bin)
check "streamed file body" "$S1" "$(curl -sS http://127.0.0.1:8080/stream.bin | sum)"
check "streamed file body again (cached descriptor)" "$S1" "$(curl -sSk https://127.0.0.1:8443/stream.bin | sum)"
head -c 6291456 /dev/urandom > bench/www/stream.bin.new && mv -f bench/www/stream.bin.new bench/www/stream.bin; sleep 1.2
S2=$(sum < bench/www/stream.bin)
check "streamed file replaced: new body" "$S2" "$(curl -sS http://127.0.0.1:8080/stream.bin | sum)"
check "streamed file replaced: new length" "6291456" "$(curl -sSI http://127.0.0.1:8080/stream.bin | tr -d '\r' | awk '/^Content-Length/{print $2}')"
rm -f bench/www/stream.bin

kill $PID; wait $PID 2>/dev/null

# Second instance with symlinks = "deny", hidden_files = true and a 2-request keep-alive cap.
# One worker here: the FastCGI pool limits are per worker, so the 503 check needs both
# requests on the same worker.
sed 's/^workers = .*/workers = 1/; s/^default = true/default = true\nsymlinks = "deny"\nhidden_files = true/; s/^max_requests_per_connection = .*/max_requests_per_connection = 2\nbody_timeout = 1/; s/^access = \(.*\)/access = \1\nformat = "json"/' bench/tmp/agensio-test.toml > bench/tmp/agensio-test2.toml
# A ".php" suffix location on the plain site (suffix beats prefix, like an nginx regex
# location, so it lives in this instance where no aliased PHP prefix must win).
python3 - bench/tmp/agensio-test2.toml <<'PY'
import sys
path = sys.argv[1]
text = open(path).read()
i = text.find("[[site]]", text.find("[[site]]") + 1)  # before the second site: the block joins the first
text = text[:i] + '[[site.location]]\npath = ".php"\nmatch = "suffix"\nhandler = "fastcgi"\n\n' + text[i:]
# Pool bounds are per upstream: set them once on the site so every location agrees.
text = text.replace('php = { socket = ', 'php = { max_connections = 1, queue_depth = 0, socket = ')
open(path, "w").write(text)
PY
"$BIN" -c bench/tmp/agensio-test2.toml >/dev/null 2>&1 &
PID=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && break; sleep 0.1; done
check "symlink outside root refused with symlinks=deny" "404" "$(code http://127.0.0.1:8080/outside.txt)"
check "regular file still served with symlinks=deny" "200" "$(code http://127.0.0.1:8080/)"
check "dotfile served with hidden_files=true" "200" "$(code http://127.0.0.1:8080/.env)"
three=$(printf 'GET / HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080)
check "request cap: 2 responses then close" "2" "$(echo "$three" | grep -c '^HTTP/1.1 200')"
check "request cap: Connection: close on last" "1" "$(echo "$three" | grep -c '^Connection: close')"
sleep 1.2
check "access log: json format" "yes" "$(grep -q '^{"time":"[0-9T:+-]*","remote":"127.0.0.1","host":"127.0.0.1:8080","method":"GET","target":"/","proto":"HTTP/1.1","status":200,"bytes":[0-9]*,"referer":"","user_agent":"curl/[^"]*"}$' bench/tmp/access.log && echo yes)"
if [ -n "$FPM_PID" ]; then
  check "php: suffix location under the site root" "hello GET 5" "$(curl -sS 'http://127.0.0.1:8080/hello.php?x=5')"
  check "php: the executed script never shows its source" "no-source" "$(curl -sS http://127.0.0.1:8080/hello.php | grep -q '<?php' && echo LEAK || echo no-source)"
  check "php: suffix location with PATH_INFO" "hello GET 6" "$(curl -sS 'http://127.0.0.1:8080/hello.php/more/path?x=6')"
  check "php: suffix beats prefix (documented, like nginx regex)" "yes" "$(curl -sS 'http://127.0.0.1:8080/app/x.php' | grep -q '404 Not Found' && echo yes)"
  cp tests/php/slow.php bench/www/slow.php
  curl -sS -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:8080/slow.php?s=1' > bench/tmp/q1.txt &
  QPID=$!
  sleep 0.3
  curl -sSi 'http://127.0.0.1:8080/slow.php?s=1' | tr -d '\r' > bench/tmp/q2.txt
  wait $QPID
  check "php: pool of 1 with no queue: second request gets 503 at once" "200 503" "$(cat bench/tmp/q1.txt) $(awk '/^HTTP/{print $2}' bench/tmp/q2.txt)"
  check "php: 503 carries Retry-After" "yes" "$(grep -q '^Retry-After: ' bench/tmp/q2.txt && echo yes)"
  check "php: pool_saturated reason logged" "yes" "$(grep -q 'pool_saturated' bench/tmp/error.log && echo yes)"
  curl -sS -o /dev/null http://127.0.0.1:8080/php/; sleep 1.2
  check "access log: upstream field for php" "yes" "$(grep -q '"target":"/php/".*"upstream":"ok"}$' bench/tmp/access.log && echo yes)"
  kill $FPM_PID; wait $FPM_PID 2>/dev/null; FPM_PID=""; sleep 0.3
  check "php: fpm gone gives 502" "502" "$(code http://127.0.0.1:8080/php/)"
  check "-t warns about the unreachable upstream" "yes" "$("$BIN" -t -c bench/tmp/agensio-test.toml 2>&1 >/dev/null | grep -q 'warning: fastcgi upstream' && echo yes)"
  check "php: 502 reason names the socket" "yes" "$(grep -q -E 'socket_missing|connect_refused' bench/tmp/error.log && echo yes)"
fi
# Range requests (E1) on a cached file (1 KB index, served from memory), a cached file above
# the sendfile threshold (100 KB css, sent by the kernel from the entry's descriptor) and a
# streamed file (10 MB): the slice bytes, Content-Range, 416, If-Range, suffix and open ranges.
for f in index.html:/ style.css:/style.css big.bin:/big.bin; do
  name=${f%%:*}; url=http://127.0.0.1:8080${f#*:}; size=$(stat -c %s bench/www/$name)
  check "range: $name bytes 10-19" "206 bytes 10-19/$size $(dd if=bench/www/$name bs=1 skip=10 count=10 2>/dev/null | sum)" "$(curl -sS -r 10-19 -o bench/tmp/range.bin -w '%{http_code} ' $url)$(curl -sS -r 10-19 -D - -o /dev/null $url | tr -d '\r' | awk '/^Content-Range:/{print $2" "$3}') $(sum < bench/tmp/range.bin)"
  check "range: $name last 7 bytes" "$(tail -c 7 bench/www/$name | sum)" "$(curl -sS -H 'Range: bytes=-7' $url | sum)"
  check "range: $name open-ended from the middle" "$(tail -c +$((size/2 + 1)) bench/www/$name | sum)" "$(curl -sS -H "Range: bytes=$((size/2))-" $url | sum)"
  check "range: $name past the end is 416 with the size" "416 bytes */$size" "$(curl -sS -H "Range: bytes=$size-" -D - -o /dev/null $url | tr -d '\r' | awk '/^HTTP/{c=$2} /^Content-Range:/{r=$2" "$3} END{print c, r}')"
done
check "range: 200 advertises Accept-Ranges" "Accept-Ranges: bytes" "$(curl -sSI http://127.0.0.1:8080/ | tr -d '\r' | grep '^Accept-Ranges')"
check "range: If-Range with the current ETag gives the slice" "206" "$(ET=$(curl -sSI http://127.0.0.1:8080/ | tr -d '\r' | awk '/^ETag/{print $2}'); code -r 0-9 -H "If-Range: $ET" http://127.0.0.1:8080/)"
check "range: If-Range with another ETag gives the whole body" "200" "$(code -r 0-9 -H 'If-Range: "nope"' http://127.0.0.1:8080/)"
check "range: several ranges give the whole body" "200" "$(code -H 'Range: bytes=0-1,5-6' http://127.0.0.1:8080/)"
check "range: HEAD with a range has the headers and no body" "206 0" "$(curl -sS -I -r 0-9 -o /dev/null -w '%{http_code} %{size_download}' http://127.0.0.1:8080/)"
check "range: slice over TLS" "$(dd if=bench/www/big.bin bs=1 skip=5000000 count=100 2>/dev/null | sum)" "$(curl -sSk -r 5000000-5000099 https://127.0.0.1:8443/big.bin | sum)"
check "range: keep-alive after a partial answer" "1 0" "$(curl -sS -r 0-9 -o /dev/null -o /dev/null -w '%{num_connects} ' http://127.0.0.1:8080/ http://127.0.0.1:8080/style.css | sed 's/ $//')"
# Reverse proxy (D1) against the benchmark upstream: bodies of every framing, streaming,
# forwarded request bodies (memory, spilled, chunked, streamed), errors, keep-alive reuse.
if [ -n "$UP_PID" ]; then
  P=http://127.0.0.1:8091
  UPS=http://127.0.0.1:9107
  check "proxy: json passthrough" '{"ok":true,"service":"upstream"}' "$(curl -sS $P/json)"
  check "proxy: status and length of a 100 KB body" "200 102399" "$(curl -sS -o /dev/null -w '%{http_code} %{size_download}' $P/big)"
  check "proxy: chunked upstream body re-framed with Content-Length" "Content-Length: 32" "$(curl -sSi $P/chunked | tr -d '\r' | grep '^Content-Length')"
  check "proxy: chunked body content" '{"ok":true,"service":"upstream"}' "$(curl -sS $P/chunked)"
  check "proxy: streaming location passes a chunked body through as chunked" "Transfer-Encoding: chunked" "$(curl -sSi $P/stream/chunked | tr -d '\r' | grep -i '^Transfer-Encoding')"
  check "proxy: streaming body content" '{"ok":true,"service":"upstream"}' "$(curl -sS $P/stream/chunked)"
  check "proxy: streamed 100 KB body" "102399" "$(curl -sS $P/stream/big | wc -c | tr -d ' ')"
  check "proxy: upstream Connection: close answered, client kept" "200 1 200 0" "$(curl -sS -o /dev/null -o /dev/null -w '%{http_code} %{num_connects} ' $P/close $P/json | sed 's/ $//')"
  check "proxy: location prefix replaced by the upstream URI" "200" "$(code "$P/api/json")"
  check "proxy: HEAD has no body" "200 0" "$(curl -sS -I $P/json -o /dev/null -w '%{http_code} %{size_download}')"
  check "proxy: upstream 404 passed through" "404" "$(code $P/nope)"
  check "proxy: upstream Server and Date replaced by ours" "1 1" "$(curl -sSi $P/json | tr -d '\r' | awk '/^Server:/{s++} /^Date:/{d++} END{print s, d}')"
  check "proxy: POST body forwarded (memory)" "hello proxy" "$(printf 'hello proxy' | curl -sS --data-binary @- $P/echo)"
  head -c 300000 /dev/urandom > bench/tmp/proxy-blob
  check "proxy: POST 300 KB forwarded (spilled)" "same" "$(curl -sS --data-binary @bench/tmp/proxy-blob $P/echo | cmp -s - bench/tmp/proxy-blob && echo same)"
  check "proxy: chunked request body forwarded with a length" "same" "$(curl -sS -H 'Transfer-Encoding: chunked' --data-binary @bench/tmp/proxy-blob $P/echo | cmp -s - bench/tmp/proxy-blob && echo same)"
  check "proxy: streamed request body (request_buffering off)" "same" "$(curl -sS --data-binary @bench/tmp/proxy-blob $P/stream/echo | cmp -s - bench/tmp/proxy-blob && echo same)"
  check "proxy: streamed chunked request body goes out chunked" "same" "$(curl -sS -H 'Transfer-Encoding: chunked' --data-binary @bench/tmp/proxy-blob $P/stream/echo | cmp -s - bench/tmp/proxy-blob && echo same)"
  check "proxy: slow upstream within the timeout" "200" "$(code "$P/slow?ms=100")"
  check "proxy: read timeout gives 504" "504" "$(code "$P/api/slow?ms=1500")"
  check "proxy: origin down gives 502" "502" "$(code $P/down/json)"
  check "proxy: 502 reason in the error log" "yes" "$(grep -q 'proxy 127.0.0.1:9199 connect_refused' bench/tmp/error.log && echo yes)"
  before=$(curl -sS $UPS/stats | sed 's/.*"connections":\([0-9]*\).*/\1/')
  for _ in 1 2 3 4 5 6 7 8 9 10; do curl -sS -o /dev/null $P/json; done
  after=$(curl -sS $UPS/stats | sed 's/.*"connections":\([0-9]*\).*/\1/')
  check "proxy: 10 client connections open at most one upstream connection" "yes" "$([ $((after - before - 1)) -le 1 ] && echo yes)"
  # Header policy (D2). 127.0.0.1 is a trusted proxy in this configuration, so a client's
  # X-Forwarded-For is appended to; the origin echoes the head it received.
  H=$(curl -sS -H 'X-Forwarded-For: 10.0.0.1' -H 'Accept: text/x' -H 'X-Forwarded-Proto: https' $P/headers | tr -d '\r')
  check "proxy: Host passed through" "Host: 127.0.0.1:8091" "$(echo "$H" | grep '^Host:')"
  check "proxy: X-Forwarded-For appended behind a trusted proxy" "X-Forwarded-For: 10.0.0.1, 127.0.0.1" "$(echo "$H" | grep '^X-Forwarded-For:')"
  check "proxy: X-Forwarded-Proto believed from a trusted proxy" "X-Forwarded-Proto: https" "$(echo "$H" | grep '^X-Forwarded-Proto:')"
  check "proxy: X-Forwarded-Proto is ours when the client sends none" "X-Forwarded-Proto: http" "$(curl -sS $P/headers | tr -d '\r' | grep '^X-Forwarded-Proto:')"
  check "proxy: no X-Forwarded-Host while Host passes through" "0" "$(echo "$H" | grep -c '^X-Forwarded-Host:')"
  check "proxy: no Forwarded by default, client fields kept" "0 Accept: text/x" "$(echo "$H" | grep -c '^Forwarded:') $(echo "$H" | grep '^Accept:')"
  check "proxy: no Connection field toward the origin (HTTP/1.1 persistent by default), no hop-by-hop leak" "0" "$(echo "$H" | grep -c '^Connection:')"
  H=$(curl -sS -H 'Accept: text/x' $P/policy/headers | tr -d '\r')
  check "proxy: host rewritten" "Host: app.internal" "$(echo "$H" | grep '^Host:')"
  check "proxy: X-Forwarded-Host carries the original when Host is rewritten" "X-Forwarded-Host: 127.0.0.1:8091" "$(echo "$H" | grep '^X-Forwarded-Host:')"
  check "proxy: RFC 7239 Forwarded added" "Forwarded: for=127.0.0.1;proto=http;host=127.0.0.1:8091" "$(echo "$H" | grep '^Forwarded:')"
  check "proxy: configured fields with variables" "X-Real-IP: 127.0.0.1 X-Site: http://127.0.0.1:8091" "$(echo "$H" | grep -E '^X-(Real-IP|Site):' | paste -sd' ')"
  check "proxy: configured empty value removes the client's field" "0" "$(echo "$H" | grep -c '^Accept:')"
  R=$(curl -sS -i $P/api/redirect | tr -d '\r')
  check "proxy: Location pointing at the origin rewritten to this site" "Location: http://127.0.0.1:8091/api/json" "$(echo "$R" | grep '^Location:')"
  check "proxy: origin header visible without hide" "1" "$(echo "$R" | grep -c '^X-Powered-By:')"
  R=$(curl -sS -i $P/policy/redirect | tr -d '\r')
  check "proxy: hidden field dropped" "0" "$(echo "$R" | grep -c '^X-Powered-By:')"
  check "proxy: redirects = pass leaves Location alone" "Location: http://127.0.0.1:9107/json" "$(curl -sS -i $P/raw/redirect | tr -d '\r' | grep '^Location:')"
  # CGI (D5): the script's output, environment, PATH_INFO, body on stdin, status and
  # Location handling, stderr in the log, an exit without output, a timeout, the cap.
  check "cgi: environment and PATH_INFO" "method=GET path_info=/extra/bit query=a=1 script=/cgi-bin/env.cgi x_test=yes" "$(curl -sS -H 'X-Test: yes' "$P/cgi-bin/env.cgi/extra/bit?a=1" | tr '\n' ' ' | sed 's/ cwd=.*//')"
  check "cgi: runs in the script's directory" "yes" "$(curl -sS $P/cgi-bin/env.cgi | grep -q 'cwd=.*/tests/cgi$' && echo yes)"
  check "cgi: directory index" "index cgi" "$(curl -sS $P/cgi-bin/)"
  check "cgi: POST body on stdin, echoed" "same" "$(curl -sS --data-binary @bench/tmp/proxy-blob $P/cgi-bin/echo.cgi | cmp -s - bench/tmp/proxy-blob && echo same)"
  check "cgi: 3 MB output spilled and intact" "3000000" "$(curl -sS $P/cgi-bin/big.cgi | wc -c | tr -d ' ')"
  check "cgi: Status from the script" "404" "$(code $P/cgi-bin/status.cgi)"
  check "cgi: Location alone is a 302" "302 /moved" "$(curl -sSi $P/cgi-bin/redirect.cgi | tr -d '\r' | awk '/^HTTP/{c=$2} /^Location:/{l=$2} END{print c, l}')"
  check "cgi: stderr logged, output still served" "ok despite stderr yes" "$(curl -sS $P/cgi-bin/stderr.cgi | tr -d '\n') $(grep -q 'stderr.cgi stderr: something went sideways' bench/tmp/error.log && echo yes)"
  check "cgi: exit without a header block is a 502" "502" "$(code $P/cgi-bin/crash.cgi)"
  check "cgi: the crash's stderr and reason logged" "yes" "$(grep -q 'crash.cgi stderr: boom' bench/tmp/error.log && grep -q 'crash.cgi closed_early' bench/tmp/error.log && echo yes)"
  check "cgi: missing script is 404" "404" "$(code $P/cgi-bin/nope.cgi)"
  check "cgi: timeout kills the script, 504" "504" "$(code $P/cgi-slow/slow.cgi)"
  check "cgi: process cap with no queue: 503 at once" "503" "$( (curl -sS -o /dev/null $P/cgi-slow/slow.cgi &) ; sleep 0.3; code $P/cgi-slow/slow.cgi)"
  sleep 1.5
  # TLS to the origin (D4b): the suite's HTTPS site is the origin; the body is the docroot's index.
  check "proxy: https origin, verification off" "$IDX" "$(curl -sS $P/tls/ | sum)"
  check "proxy: https origin verified against the configured CA and name" "$IDX" "$(curl -sS $P/tlsverify/ | sum)"
  check "proxy: https origin failing verification is a 502" "502" "$(code $P/tlsbad/)"
  check "proxy: tls_error logged with the hint" "yes" "$(grep -q 'https://127.0.0.1:8443 tls_error .*proxy.tls' bench/tmp/error.log && echo yes)"
  check "proxy: https origin keeps its connection (one handshake for three requests)" "$IDX $IDX $IDX" "$(curl -sS $P/tls/ $P/tls/ $P/tls/ | (a=$(head -c $IDXLEN | sum); b=$(head -c $IDXLEN | sum); c=$(sum); echo "$a $b $c"))"
  # Groups (D4): one keep-alive client connection stays on one worker, whose rotation
  # alternates the members; the dead member of the failover group is tried, marked down
  # after max_fails, and then skipped; a POST is retried too (a connect failure sent nothing).
  check "proxy: group round-robin alternates the members" "yes" "$(curl -sS -i $P/group/json $P/group/json $P/group/json $P/group/json | tr -d '\r' | awk '/^X-Upstream-Port:/{print $2}' | paste -sd' ' | grep -Eq '^(9107 9108 9107 9108|9108 9107 9108 9107)$' && echo yes)"
  check "proxy: failover group answers from the live member" "200 200 200 | 3" "$(curl -sS -o /dev/null -o /dev/null -o /dev/null -w '%{http_code} ' $P/failover/json $P/failover/json $P/failover/json | sed 's/ $//') | $(curl -sS -i $P/failover/json $P/failover/json $P/failover/json | tr -d '\r' | grep -c '^X-Upstream-Port: 9108')"
  check "proxy: dead member marked down after max_fails" "yes" "$(grep -q '127.0.0.1:9199 marked down for 30 s after 2 failure' bench/tmp/error.log && echo yes)"
  check "proxy: POST retried on the next member after a connect failure" "abc 9108" "$(printf abc | curl -sS -i --data-binary @- $P/failover/echo | tr -d '\r' | awk '/^X-Upstream-Port:/{p=$2} END{print $0, p}')"
  check "proxy: -t warns about every dead member" "yes" "$("$BIN" -t -c bench/tmp/agensio-test.toml 2>&1 >/dev/null | grep -c 'proxy upstream 127.0.0.1:9199' | grep -Eq '^[1-9]' && echo yes)"
  # Client abort (E9): a client that leaves while its request waits on the origin gives the
  # pool slot back within a tick; the next client gets it instead of a 503. Without the
  # watch the slot stays held until the origin answers 1.5 s later.
  abort=$(python3 - <<'PYT'
import socket, time, subprocess
s = socket.create_connection(("127.0.0.1", 8091))
s.sendall(b"GET /abort/slow?ms=1500 HTTP/1.1\r\nHost: a\r\n\r\n")
time.sleep(0.1)
s.close()  # the client gives up
time.sleep(0.5)  # a tick (250 ms) plus margin for the watch to notice the EOF
t0 = time.time()
out = subprocess.run(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}", "http://127.0.0.1:8091/abort/slow?ms=100"], capture_output=True, text=True).stdout
print(out, "fast" if time.time() - t0 < 1.0 else "slow")
PYT
)
  check "proxy: an abandoned request frees its pool slot within a tick" "200 fast" "$abort"
  check "proxy: the abandoned request was cancelled, not answered" "yes" "$(grep -q '"target":"/abort/slow?ms=1500".*"status":0' bench/tmp/access.log 2>/dev/null && echo yes || { sleep 1.2; grep -q '"target":"/abort/slow?ms=1500"' bench/tmp/access.log && echo yes; })"
  # Upgrade tunnelling (D3): 101 passed through with Upgrade/Connection, bytes flow both
  # ways (including the ones sent right behind the request head), the origin's close ends it.
  tunnel=$(python3 - <<'PYT'
import socket
s = socket.create_connection(("127.0.0.1", 8091)); s.settimeout(5)
s.sendall(b"GET /tunnel HTTP/1.1\r\nHost: t\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\nearly")
data = b""
while b"\r\n\r\n" not in data: data += s.recv(4096)
head, rest = data.split(b"\r\n\r\n", 1)
lines = head.decode().split("\r\n")
status = lines[0]; fields = {l.split(":")[0].lower(): l.split(":", 1)[1].strip() for l in lines[1:]}
while len(rest) < 5: rest += s.recv(4096)
s.sendall(b"ping-" * 20000)  # 100 KB through the tunnel
got = rest[5:]
while len(got) < 100000: got += s.recv(65536)
s.shutdown(socket.SHUT_WR)
tail = b""
try:
    while True:
        c = s.recv(4096)
        if not c: break
        tail += c
    closed = "closed"
except socket.timeout:
    closed = "open"
print(status, fields.get("upgrade"), fields.get("connection"), "content-length" in fields, rest[:5].decode(), got == b"ping-" * 20000, closed)
PYT
)
  check "proxy: Upgrade tunnel: 101, fields, early bytes, 100 KB both ways, close follows" "HTTP/1.1 101 Switching Protocols echo upgrade False early True closed" "$tunnel"
  check "proxy: Upgrade to an origin path that ignores it is a normal answer" "200" "$(code -H 'Connection: Upgrade' -H 'Upgrade: websocket' $P/json)"
  sleep 1.2
  check "access log: the 101 logged with upstream=upgrade" "yes" "$(grep -q '"target":"/tunnel".*"status":101.*"upstream":"upgrade"' bench/tmp/access.log && echo yes)"
  check "proxy: -t warns about the unreachable origin" "yes" "$("$BIN" -t -c bench/tmp/agensio-test.toml 2>&1 >/dev/null | grep -q 'warning: proxy upstream 127.0.0.1:9199' && echo yes)"
  sleep 1.2
  check "access log: upstream field for the proxy" "yes" "$(grep -q '"target":"/json".*"upstream":"ok"}$' bench/tmp/access.log && echo yes)"
fi
# Body timeout (1 s here): the response is served, then the missing body bytes never come
# and the server closes the connection instead of waiting for the idle timeout (65 s).
# (nc cannot be used here: it stays up while its stdin is open even after the peer closes.)
slow=$(python3 - <<'PY'
import socket, time
s = socket.create_connection(("127.0.0.1", 8080)); s.settimeout(5)
s.sendall(b"GET / HTTP/1.1\r\nHost: l\r\nContent-Length: 10\r\n\r\nabc")
t0 = time.time(); data = b""
try:
    while True:
        chunk = s.recv(65536)
        if not chunk: break
        data += chunk
    closed = "closed"
except socket.timeout:
    closed = "still open"
print(data.split(b"\r\n")[0].decode(), closed, "within 4s" if time.time() - t0 <= 4 else "late")
PY
)
check "body timeout: response served, then the server closes" "HTTP/1.1 200 OK closed within 4s" "$slow"
kill $PID; wait $PID 2>/dev/null
[ $fails -eq 0 ] && echo "integration: all passed" || { echo "integration: $fails failure(s):$failed_names"; exit 1; }
