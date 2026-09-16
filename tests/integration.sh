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

mkdir -p bench/tmp
sed "s#@WORKERS@#0#g; s#@BENCH@#$ROOT/bench#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g" bench/agensio.toml > bench/tmp/agensio-test.toml
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
printf '<html><body>changed</body></html>\n' > bench/www/sub/index.html; sleep 1.2
check "revalidation picks up change" "changed" "$(curl -sS http://127.0.0.1:8080/sub/ | sed 's/<[^>]*>//g')"
printf '<html><body>sub index</body></html>\n' > bench/www/sub/index.html

kill $PID; wait $PID 2>/dev/null

# Second instance with symlinks = "deny", hidden_files = true and a 2-request keep-alive cap.
sed 's/^default = true/default = true\nsymlinks = "deny"\nhidden_files = true/; s/^max_requests_per_connection = .*/max_requests_per_connection = 2/' bench/tmp/agensio-test.toml > bench/tmp/agensio-test2.toml
"$BIN" -c bench/tmp/agensio-test2.toml >/dev/null 2>&1 &
PID=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && break; sleep 0.1; done
check "symlink outside root refused with symlinks=deny" "404" "$(code http://127.0.0.1:8080/outside.txt)"
check "regular file still served with symlinks=deny" "200" "$(code http://127.0.0.1:8080/)"
check "dotfile served with hidden_files=true" "200" "$(code http://127.0.0.1:8080/.env)"
three=$(printf 'GET / HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\n\r\nGET / HTTP/1.1\r\nHost: l\r\n\r\n' | ncq 127.0.0.1 8080)
check "request cap: 2 responses then close" "2" "$(echo "$three" | grep -c '^HTTP/1.1 200')"
check "request cap: Connection: close on last" "1" "$(echo "$three" | grep -c '^Connection: close')"
kill $PID; wait $PID 2>/dev/null
[ $fails -eq 0 ] && echo "integration: all passed" || { echo "integration: $fails failure(s)"; exit 1; }
