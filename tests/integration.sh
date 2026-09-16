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
rm -f bench/tmp/access.log bench/tmp/access.log.1
sed "s#@WORKERS@#0#g; s#@BENCH@#$ROOT/bench#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g; s#@ACCESS_LOG@#$ROOT/bench/tmp/access.log#" bench/agensio.toml > bench/tmp/agensio-test.toml
# Locations (A4) on the plain site: an SPA fallback, an aliased root, an exact match and a
# try_files status. Inserted after the site's `default = true` line.
python3 - bench/tmp/agensio-test.toml "$ROOT/bench/www" <<'PY'
import sys
path, www = sys.argv[1], sys.argv[2]
block = f"""default = true

[[site.location]]
path = "/app/"
try_files = ["$uri", "$uri/", "/app.html"]

[[site.location]]
path = "/alias/"
alias = "{www}/sub"

[[site.location]]
path = "/spa/"
try_files = ["$uri", "/index.html"]

[[site.location]]
path = "/index.html"
match = "exact"
root = "{www}/sub"

[[site.location]]
path = "/private/"
try_files = ["=403"]

[[site.location]]
path = "/readonly/"
alias = "{www}/sub"
methods = ["GET", "HEAD"]
"""
text = open(path).read().replace("default = true\n", block, 1)
open(path, "w").write(text)
PY
"$BIN" -c bench/tmp/agensio-test.toml >/dev/null 2>&1 &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT
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
check "location: fallback is routed again (hits the exact /index.html location)" "sub index" "$(curl -sS http://127.0.0.1:8080/spa/missing | sed 's/<[^>]*>//g')"
check "location: exact match wins over the root prefix" "sub index" "$(curl -sS http://127.0.0.1:8080/index.html | sed 's/<[^>]*>//g')"
check "location: exact does not prefix-match" "404" "$(code http://127.0.0.1:8080/index.htmlx)"
check "location: root prefix still serves the site" "$IDX" "$(curl -sS http://127.0.0.1:8080/ | sum)"
check "location: try_files =403" "403" "$(code http://127.0.0.1:8080/private/anything)"
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
sed 's/^default = true/default = true\nsymlinks = "deny"\nhidden_files = true/; s/^max_requests_per_connection = .*/max_requests_per_connection = 2\nbody_timeout = 1/; s/^access = \(.*\)/access = \1\nformat = "json"/' bench/tmp/agensio-test.toml > bench/tmp/agensio-test2.toml
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
