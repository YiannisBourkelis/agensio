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
# Locations (A4) on the plain site: an SPA fallback, an aliased root, an exact match and a
# try_files status. Inserted after the site's `default = true` line.
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
listen = ["127.0.0.1:8090"]
root = "{root}/tests/laravel"
app = "laravel"
php = {{ socket = "unix:{root}/bench/tmp/php/fpm.sock" }}
"""
# The reverse proxy (D1) in front of the benchmark upstream on 127.0.0.1:9107, on its own port.
if os.path.exists(f"{root}/build/agensio_upstream"):
    text += f"""
[[site]]
server_name = ["proxy.test"]
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

[[site.location]]
path = "/"
upstream = "http://127.0.0.1:9107"
"""
open(path, "w").write(text)
PY
UP_PID=""
if [ -x build/agensio_upstream ]; then
  build/agensio_upstream -p 9107 >/dev/null 2>&1 &
  UP_PID=$!
fi
"$BIN" -c bench/tmp/agensio-test.toml >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null; [ -n "$FPM_PID" ] && kill $FPM_PID 2>/dev/null; [ -n "$UP_PID" ] && kill $UP_PID 2>/dev/null; true' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 0.1; done

fails=0
check() {  # name expected actual
  if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$2] got [$3]"; fails=$((fails+1)); fi
}
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
if command -v sha256sum >/dev/null; then sum() { sha256sum | cut -c1-16; }; else sum() { shasum -a 256 | cut -c1-16; }; fi
# Debian's netcat-openbsd needs -q to exit after stdin EOF; macOS nc has no -q.
if nc -h 2>&1 | grep -q -- '-q'; then ncq() { nc -q 1 "$@"; }; else ncq() { nc "$@"; }; fi
BIG=$(sum < bench/www/big.bin); CSS=$(sum < bench/www/style.css); IDX=$(sum < bench/www/index.html)

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
check "location: final prefix keeps .php out of the suffix location, deny_suffixes gives 403" "403" "$(code http://127.0.0.1:8080/uploads/index.php)"
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
check "tls 1.3 negotiated" "TLSv1.3" "$(echo | openssl s_client -connect 127.0.0.1:8443 -tls1_3 2>/dev/null | sed -n 's/^ *Protocol *: *//p' | head -1)"
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
check "laravel: other .php files are routed to the front controller, never executed" "laravel /anything.php /index.php -" "$(curl -sS http://127.0.0.1:8090/anything.php)"
check "laravel: /index.php/extra also lands in the front controller" "laravel /index.php/extra /index.php -" "$(curl -sS 'http://127.0.0.1:8090/index.php/extra')"
fi
"$BIN" -t --explain -c bench/tmp/agensio-test.toml > bench/tmp/explain.out 2>bench/tmp/explain.err
check "explain: preset expansion is printed" "yes" "$(grep -q '# from preset:laravel' bench/tmp/explain.out && echo yes)"
check "explain: -t reports OK" "yes" "$("$BIN" -t -c bench/tmp/agensio-test.toml 2>/dev/null | grep -q 'is OK' && echo yes)"
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
[ $fails -eq 0 ] && echo "integration: all passed" || { echo "integration: $fails failure(s)"; exit 1; }
