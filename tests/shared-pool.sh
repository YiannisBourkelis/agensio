#!/usr/bin/env bash
# proxy.pool = "shared" (docs/design-upstream-pool.md): idle connections to an origin a worker asks
# seldom belong to no worker, so four workers hold one connection to it where each held its own; an
# origin asked often keeps its connections in the worker. A private server with four workers, the
# benchmark upstream as an origin that counts the connections it accepted (/stats), and a TLS
# origin that serves one connection at a time, so it answers four workers only when they share one.
# usage: tests/shared-pool.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
UP=${AGENSIO_UPSTREAM:-$(dirname "$BIN")/agensio_upstream}
ROOT=$(pwd)
T=$ROOT/bench/tmp/shared-pool; rm -rf "$T"; mkdir -p "$T/www" "$T/certs"
[ -x "$UP" ] || { echo "skip: $UP not built (cmake --build build --target agensio_upstream)"; exit 0; }
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
CS="$T/control.sock"; OP=19141; TP=19142
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout "$T/certs/key.pem" -out "$T/certs/cert.pem" -days 2 -subj "/CN=origin.test" >/dev/null 2>&1
site() {  # name port upstream [proxy table]
  printf '\n[[site]]\nserver_name = ["*"]   # %s\nlisten = ["127.0.0.1:%s"]\nroot = "%s/www"\nproxy = { %s }\n\n[[site.location]]\npath = "/"\nupstream = "%s"\n' "$1" "$2" "$T" "${4:-}" "$3"
}
{
  printf '[server]\nworkers = 4\npid_file = "%s/agensio.pid"\n[log]\naccess = "off"\nerror = "%s/error.log"\nlevel = "info"\n[control]\nsocket = "%s"\n' "$T" "$T" "$CS"
  site w.test 18471 "http://127.0.0.1:$OP"                                  # each worker its own: the default
  site s.test 18472 "http://127.0.0.2:$OP" 'pool = "shared"'
  site t.test 18473 "https://127.0.0.1:$TP" 'pool = "shared", tls = { verify = false }'
  site x.test 18474 "http://127.0.0.4:$OP" 'pool = "shared", idle_timeout = 1'
} > "$T/agensio.toml"
start_origin() { "$UP" -p $OP -w 1 -a 0.0.0.0 > "$T/upstream.log" 2>&1 & OPID=$!; for _ in $(seq 1 50); do nc -z 127.0.0.1 $OP 2>/dev/null && break; sleep 0.1; done; }
start_origin
python3 -I tests/tls-origin.py $TP "$T/certs/cert.pem" "$T/certs/key.pem" > "$T/tls-origin.log" 2>&1 & TPID=$!
"$BIN" -c "$T/agensio.toml" > "$T/server.log" 2>&1 & SPID=$!
trap 'kill $SPID $OPID $TPID 2>/dev/null; wait 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 18474 2>/dev/null && nc -z 127.0.0.1 $TP 2>/dev/null && break; sleep 0.1; done

opened() { curl -s "http://127.0.0.1:$OP/stats" | sed 's/.*"connections":\([0-9]*\).*/\1/'; }   # the /stats call is itself one
# N requests to a site, each on a new client connection (so the kernel spreads them over the workers),
# 20 ms apart: sparse for every worker. Prints how many were answered 200.
sparse() {  # port n
  local ok=0 i
  for i in $(seq 1 "$2"); do [ "$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' "http://127.0.0.1:$1/json")" = 200 ] && ok=$((ok+1)); sleep 0.02; done
  echo $ok
}
stat() {  # origin field
  curl -sS --unix-socket "$CS" http://control/v1/status | python3 -c '
import json, sys
for o in json.load(sys.stdin).get("upstream_pool", {}).get("shared", []):
    if o["origin"] == sys.argv[1]: print(int(o[sys.argv[2]])); break
else: print("none")' "$1" "$2"
}
fds() { ls /proc/$SPID/fd | wc -l; }

# 1. The default: the workers that served each opened a connection of their own.
a=$(opened); n=$(sparse 18471 40); b=$(opened)
check "pool = worker: 40 requests over four workers are answered, by more than one origin connection" "40 yes" "$n $([ $((b - a - 1)) -ge 2 ] && echo yes || echo "$((b - a - 1)) connections")"
check "pool = worker: the store is not used" "none" "$(stat 127.0.0.1:$OP idle)"

# 2. Shared: one connection for all four.
a=$(opened); n=$(sparse 18472 40); b=$(opened)
check "pool = shared: 40 requests over four workers are answered by one origin connection" "40 1" "$n $((b - a - 1))"
check "pool = shared: status shows the store: one idle, given and taken for nearly every request" "1 yes yes" \
  "$(stat 127.0.0.2:$OP idle) $([ "$(stat 127.0.0.2:$OP given)" -ge 39 ] && echo yes) $([ "$(stat 127.0.0.2:$OP taken)" -ge 30 ] && echo yes)"

# 3. An origin a worker asks often keeps its connection in the worker: of 400 requests back to back
#    on one client connection only the first few dozen are handed to the store (until the worker's
#    average gap to the origin is under a millisecond); a tick after they end the connection is
#    there for the other workers, who open none.
g0=$(stat 127.0.0.2:$OP given); a=$(opened)
dense=$(python3 - <<'PY'
import http.client
c = http.client.HTTPConnection("127.0.0.1", 18472); ok = 0
for _ in range(400):
    c.request("GET", "/json"); r = c.getresponse(); r.read(); ok += r.status == 200
print(ok)
PY
)
g1=$(stat 127.0.0.2:$OP given); sleep 0.7; n=$(sparse 18472 12); b=$(opened)
check "pool = shared, dense: of 400 requests in a row at most 60 are handed to the store, the rest stay on the worker's own connection; no new origin connection then or after" \
  "400 yes 12 0" "$dense $([ $((g1 - g0)) -le 60 ] && echo yes || echo "$((g1 - g0)) given") $n $((b - a - 1))"

# 4. A TLS origin that serves one connection at a time: four workers are answered because they share
#    one connection, its TLS session moving with it.
n=0; for i in $(seq 1 30); do [ "$(curl -s -o /dev/null --max-time 5 -w '%{http_code}' http://127.0.0.1:18473/x)" = 200 ] && n=$((n+1)); sleep 0.02; done
check "pool = shared, https origin: 30 requests over four workers through one connection, the TLS session taken from the store" "30 1 yes" \
  "$n $(stat https://127.0.0.1:$TP idle) $([ "$(stat https://127.0.0.1:$TP taken)" -ge 20 ] && echo yes)"

# 5. Expiry: idle_timeout = 1 closes the store's connection; the next request opens one.
n=$(sparse 18474 3); i0=$(stat 127.0.0.4:$OP idle); sleep 2.8
a=$(opened); i1=$(stat 127.0.0.4:$OP idle); e1=$(stat 127.0.0.4:$OP expired); n2=$(sparse 18474 1); b=$(opened)
check "pool = shared: a connection idle past idle_timeout is closed in the store, and the next request opens a new one" "3 1 0 yes 1 1" \
  "$n $i0 $i1 $([ "$e1" -ge 1 ] && echo yes) $n2 $((b - a - 1))"

# 6. Descriptors: 200 more requests leave the server with as many as before.
f0=$(fds); n=$(sparse 18472 200); f1=$(fds)
check "pool = shared: 200 requests later the server holds the descriptors it held (no leak)" "200 yes" "$n $([ $((f1 - f0)) -ge -2 ] && [ $((f1 - f0)) -le 2 ] && echo yes || echo "$f0 then $f1")"

# 7. Every descriptor that is a socket carries O_NONBLOCK, the moved ones included (hardening item 7).
check "pool = shared: every socket of the server carries O_NONBLOCK" "all-nonblocking" "$(python3 - $SPID <<'PY'
import os, sys
pid = sys.argv[1]; bad = 0
for fd in os.listdir(f"/proc/{pid}/fd"):
    try:
        if not os.readlink(f"/proc/{pid}/fd/{fd}").startswith("socket:"): continue
        flags = int([l for l in open(f"/proc/{pid}/fdinfo/{fd}") if l.startswith("flags:")][0].split()[1], 8)
    except OSError:
        continue
    bad += not (flags & 0o4000)
print("all-nonblocking" if bad == 0 else f"{bad} blocking")
PY
)"

# 8. A reload keeps the store: served as before, no new origin connection.
a=$(opened); kill -HUP $SPID; sleep 0.5; n=$(sparse 18472 12); b=$(opened)
check "pool = shared: after a reload the workers go on sharing the connection the store holds" "12 0" "$n $((b - a - 1))"

# 9. The origin restarts: the store's connection is found closed before a request is written to it,
#    and the request is answered on a new one.
kill $OPID; wait $OPID 2>/dev/null; start_origin; sleep 0.6
d0=$(stat 127.0.0.2:$OP dead); n=$(sparse 18472 6); d1=$(stat 127.0.0.2:$OP dead)
check "pool = shared: the origin restarted: the store's connection is found closed, the requests are answered on a new one" "6 yes" "$n $([ $((d1 - d0)) -ge 1 ] && echo yes || echo "dead $d0 then $d1")"

# 10. Stopping the server closes what the store holds: the origin sees its connections go.
kill $SPID; wait $SPID 2>/dev/null
check "the server stopped cleanly" "0" "$(grep -c 'AddressSanitizer\|runtime error\|ThreadSanitizer' "$T/server.log")"

# 11. One worker has nobody to share with: pool = "shared" then keeps the connection in the worker,
#     the store is never used, and the requests are answered through one origin connection.
sed 's/^workers = 4$/workers = 1/' "$T/agensio.toml" > "$T/one.toml"
"$BIN" -c "$T/one.toml" > "$T/server-one.log" 2>&1 & SPID=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 18472 2>/dev/null && break; sleep 0.1; done
a=$(opened); n=$(sparse 18472 20); b=$(opened)
check "pool = shared with one worker: the store is not used, one origin connection serves" "20 1 none" "$n $((b - a - 1)) $(stat 127.0.0.2:$OP idle)"
kill $SPID; wait $SPID 2>/dev/null

echo "shared-pool: $pass passed, $fail failed"
[ $fail = 0 ]
