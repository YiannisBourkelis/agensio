#!/usr/bin/env bash
# An origin's answer on its way to the client (docs/design-proxy-streaming.md): the same bytes
# whatever the path. A private server in front of tests/stream-origin.py, which sends bodies of
# every size around the buffers' sizes in each framing (a length, chunked, to the connection's
# close; whole with the head or after it), through a streaming site and a buffered one, plain and
# over TLS, HTTP/1.1, HTTP/2 (over TLS and h2c) and HTTP/3 where this curl speaks it. Then the
# clients that are not polite: one that reads slowly, one that leaves mid-body, and an origin that
# breaks off.
# usage: tests/proxy-streaming.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/proxy-streaming; rm -rf "$T"; mkdir -p "$T/www" "$T/certs"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
OP=19151; CS="$T/control.sock"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/certs/key.pem" -out "$T/certs/cert.pem" -days 2 -subj "/CN=stream.test" -addext "subjectAltName=IP:127.0.0.1,DNS:stream.test" >/dev/null 2>&1   # the address named: a certificate that does not name what is asked is a 421
site() {  # port tls proxy-table
  printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:%s"]\nroot = "%s/www"\nproxy = { %s }\n' "$1" "$T" "$3"
  [ "$2" = tls ] && printf 'tls = { cert = "%s/certs/cert.pem", key = "%s/certs/key.pem" }\n' "$T" "$T"
  printf '\n[[site.location]]\npath = "/"\nupstream = "http://127.0.0.1:%s"\n' $OP
}
{
  printf '[server]\nworkers = 2\nprotocols = ["h1", "h2", "h2c", "h3"]\npid_file = "%s/agensio.pid"\n[log]\naccess = "off"\nerror = "%s/error.log"\nlevel = "info"\n[control]\nsocket = "%s"\n' "$T" "$T" "$CS"
  site 18481 plain 'buffering = false, max_connections = 16'
  site 18482 tls   'buffering = false, max_connections = 16'
  site 18483 plain 'max_connections = 16'
  site 18484 tls   'max_connections = 16'
} > "$T/agensio.toml"
python3 -I tests/stream-origin.py $OP > "$T/origin.log" 2>&1 & OPID=$!
"$BIN" -c "$T/agensio.toml" > "$T/server.log" 2>&1 & SPID=$!
trap 'kill $SPID $OPID 2>/dev/null; wait $SPID $OPID 2>/dev/null' EXIT
for _ in $(seq 1 100); do nc -z 127.0.0.1 18484 2>/dev/null && nc -z 127.0.0.1 $OP 2>/dev/null && break; sleep 0.1; done
H3=no; curl -sk --http3-only --max-time 5 -o /dev/null "https://127.0.0.1:18482/whole/10" 2>/dev/null && H3=yes

SIZES="0 1 700 16383 16384 16385 65535 65536 65537 100000 1000000 3000000"
declare -A SHA
for n in $SIZES 300000; do SHA[$n]=$(curl -s "http://127.0.0.1:$OP/sha/$n"); done
# The body's sha256, and curl's complaint when the transfer did not end cleanly: every byte arriving
# is not enough, the stream must end (the alpha.148 report's F1: an h2c stream whose END_STREAM never
# came gave the whole body and curl's exit 92 at the server's idle timeout).
got() { { curl -sk --max-time 20 "$@" || echo "curl exit $?"; } | sha256sum | cut -d' ' -f1; }
# Every size in every framing through one site and protocol: how many bodies differed.
sweep() {  # url-base curl-options...
  local base=$1 bad=0 kind n; shift
  for kind in whole len chunked close; do
    for n in $SIZES; do
      [ "$(got "$@" "$base/$kind/$n")" = "${SHA[$n]}" ] || { bad=$((bad+1)); echo "  differs: $base/$kind/$n $*" >&2; }
    done
  done
  echo $bad
}
check "streaming, HTTP/1.1: every size in every framing arrives byte for byte"          "0" "$(sweep http://127.0.0.1:18481)"
check "streaming, HTTPS (HTTP/1.1): the same"                                            "0" "$(sweep https://127.0.0.1:18482 --http1.1)"
check "streaming, HTTP/2: the same"                                                      "0" "$(sweep https://127.0.0.1:18482 --http2)"
check "streaming, h2c (HTTP/2 without TLS): the same"                                    "0" "$(sweep http://127.0.0.1:18481 --http2-prior-knowledge)"
check "buffered, HTTP/1.1: the same (3 MB goes through the temp file)"                   "0" "$(sweep http://127.0.0.1:18483)"
check "buffered, HTTPS (HTTP/1.1): the same"                                             "0" "$(sweep https://127.0.0.1:18484 --http1.1)"
check "buffered, HTTP/2: the same"                                                       "0" "$(sweep https://127.0.0.1:18484 --http2)"
check "buffered, h2c (HTTP/2 without TLS): the same"                                     "0" "$(sweep http://127.0.0.1:18483 --http2-prior-knowledge)"
if [ $H3 = yes ]; then
  check "streaming, HTTP/3: the same"                                                    "0" "$(sweep https://127.0.0.1:18482 --http3-only)"
  check "buffered, HTTP/3: the same"                                                     "0" "$(sweep https://127.0.0.1:18484 --http3-only)"
else
  echo "skip HTTP/3 rows: this curl does not speak it"
fi

# Ten HTTP/2 streams at once on one connection, each a different size: none takes another's bytes.
check "streaming, HTTP/2: ten streams at once on one connection each get their own body" "0" "$(
  bad=0; i=0; args=()
  for n in 1 700 16384 16385 65536 65537 100000 300000 1000000 3000000; do args+=(-o "$T/par-$i" "https://127.0.0.1:18482/len/$n"); i=$((i+1)); done
  curl -sk --http2 --parallel --parallel-max 10 --max-time 30 "${args[@]}"
  i=0; for n in 1 700 16384 16385 65536 65537 100000 300000 1000000 3000000; do [ "$(sha256sum < "$T/par-$i" | cut -d' ' -f1)" = "${SHA[$n]}" ] || bad=$((bad+1)); i=$((i+1)); done
  echo $bad)"

# A HEAD, and the framing the client sees: a length for an answer that arrived whole (the origin's own,
# or the one agensio counted for a chunked answer), chunked for a body still on its way.
check "streaming: a HEAD is answered with the length and no body" "200 100000 0" \
  "$(curl -s -I -o "$T/head.txt" -w '%{http_code}' "http://127.0.0.1:18481/len/100000") $(grep -i '^content-length' "$T/head.txt" | tr -dc 0-9) $(curl -s -I "http://127.0.0.1:18481/len/100000" | sed '1,/^\r$/d' | wc -c)"
fields() { curl -s -D - -o /dev/null "$1" | tr -d '\r' | tr 'A-Z' 'a-z' | grep -oE '^(content-length|transfer-encoding: chunked)' | sed 's/transfer-encoding: //' | paste -sd, -; }
check "streaming: an answer that arrived whole goes out with its length, declared or counted; a chunked one still arriving goes out chunked" "content-length content-length chunked" \
  "$(fields "http://127.0.0.1:18481/whole/700") $(fields "http://127.0.0.1:18481/wchunked/700") $(fields "http://127.0.0.1:18481/chunked/300000")"

# Keep-alive to the origin survives every path: forty answers of mixed kinds open few connections.
a=$(curl -s "http://127.0.0.1:$OP/stats")
for i in $(seq 1 10); do for u in whole/700 len/100000 chunked/65537 len/16385; do curl -s -o /dev/null "http://127.0.0.1:18481/$u"; done; done
b=$(curl -s "http://127.0.0.1:$OP/stats")
check "streaming: forty answers in a row reuse the origin's connections (at most one per worker opened)" "yes" "$([ $((b - a - 1)) -le 2 ] && echo yes || echo "$((b - a - 1)) opened")"

# A slow client still gets all of it, over each protocol.
check "streaming: a client reading at 400 KB/s gets a 300 KB slow answer whole (HTTP/1.1, HTTP/2)" "${SHA[300000]} ${SHA[300000]}" \
  "$(got --limit-rate 400k "http://127.0.0.1:18481/slow/300000") $(got --http2 --limit-rate 400k "https://127.0.0.1:18482/slow/300000")"

# An origin that breaks off: a streamed answer is cut (curl says so), a buffered one is the 502 page.
check "an origin that closes halfway: streamed, the client sees a short body; buffered, a 502" "short 502" \
  "$(curl -s -o /dev/null --max-time 10 "http://127.0.0.1:18481/cut/200000"; [ $? -ne 0 ] && echo -n short || echo -n whole) $(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://127.0.0.1:18483/cut/200000")"

# An origin's head whose framing cannot be trusted is discarded and answered 502, streamed or buffered
# (RFC 9112 6.3): a Content-Length that is no number agensio can hold, two that disagree, a 101 nobody
# asked for. Until 0.1.0-alpha.149 a streaming site sent the first three on as a 200 (a 20-digit
# length wrapped past 2^64, the others chunked and cut), the alpha.148 report's F2.
check "an origin's invalid framing is a 502 on a streaming site as on a buffered one" "502 502 502 502 502 502 502 502 502 502 502 502" \
  "$(for u in badlen/99999999999999999999 badlen/-1 badlen/1e9 badlen/+10 twolen upgrade; do for p in 18481 18483; do
       curl -s -o /dev/null --max-time 10 -w '%{http_code} ' "http://127.0.0.1:$p/$u"; done; done | sed 's/ $//')"

# Clients that leave mid-body, more of them than the location has connections: every slot comes
# back (a read in flight into a gone client's buffer is cancelled, the exchange ended), the server
# stands, and the next answer is whole.
leavers=()
for i in $(seq 1 40); do
  curl -s -o /dev/null --max-time 0.12 "http://127.0.0.1:18481/slow/3000000" & leavers+=($!)
  curl -sk --http2 -o /dev/null --max-time 0.12 "https://127.0.0.1:18482/slow/3000000" & leavers+=($!)
  if [ $((i % 8)) = 0 ]; then wait "${leavers[@]}" 2>/dev/null; leavers=(); fi   # never a bare wait: the server is a job of this shell too
done
sleep 0.5
check "streaming: after eighty clients left mid-body every slot is back: the next answers are whole" "${SHA[100000]} ${SHA[100000]} alive" \
  "$(got "http://127.0.0.1:18481/len/100000") $(got --http2 "https://127.0.0.1:18482/len/100000") $(kill -0 $SPID 2>/dev/null && echo alive || echo dead)"
check "the error log holds no sanitizer report and no crash" "0" "$(grep -cE 'AddressSanitizer|runtime error|ThreadSanitizer|Segmentation' "$T/server.log" "$T/error.log" | awk -F: '{s+=$2} END{print s+0}')"

echo "$pass passed, $fail failed"
[ $fail = 0 ]
