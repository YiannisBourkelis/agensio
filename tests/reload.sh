#!/usr/bin/env bash
# Reload without restart (H1): the configuration file is rewritten and the running server
# is told to switch (`agensio reload`, i.e. SIGHUP). Checks that a keep-alive connection
# opened before the reload serves the new configuration on its next request without
# reconnecting, that a request in flight during the reload finishes, that a listener can
# be added and removed, that a connection on a removed listener finishes its request and
# is then closed, that a broken file is refused and the old configuration keeps serving,
# and that a wrk load across a reload sees no error at all.
# usage: tests/reload.sh build/agensio   (needs build/agensio_upstream and wrk)
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/reload; rm -rf "$T"; mkdir -p "$T/v1" "$T/v2" "$T/logs"
echo "version one" > "$T/v1/index.html"; echo "version two" > "$T/v2/index.html"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
write_config() {  # root [extra-site-toml]
  cat > "$T/agensio.toml" <<EOF
[server]
workers = 2
pid_file = "$T/agensio.pid"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8097"]
root = "$1"
${2:-}
EOF
}
"$ROOT/build/agensio_upstream" -p 9110 >/dev/null 2>&1 & UP=$!
write_config "$T/v1"
"$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!
trap 'kill $SRV $UP 2>/dev/null; wait $SRV $UP 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8097 2>/dev/null && break; sleep 0.1; done
B=http://127.0.0.1:8097
check "v1 served" "version one" "$(curl -sS $B/)"
check "pid file written" "$SRV" "$(cat "$T/agensio.pid")"

# A keep-alive connection across the reload: opened on v1, second request after the switch.
write_config "$T/v2" "
[[site.location]]
path = \"/slow/\"
upstream = \"http://127.0.0.1:9110/\"

[[site]]
server_name = [\"*\"]
listen = [\"127.0.0.1:8098\"]
root = \"$T/v2\""
ka=$(python3 - <<PYT
import socket, subprocess, time
s = socket.create_connection(("127.0.0.1", 8097)); s.settimeout(5)
def get(path):
    s.sendall(("GET %s HTTP/1.1\\r\\nHost: k\\r\\n\\r\\n" % path).encode())
    data = b""
    while b"\\r\\n\\r\\n" not in data: data += s.recv(4096)
    head, body = data.split(b"\\r\\n\\r\\n", 1)
    length = int([l for l in head.decode().split("\\r\\n") if l.lower().startswith("content-length")][0].split(":")[1])
    while len(body) < length: body += s.recv(4096)
    return head.split(b"\\r\\n")[0].decode(), body.decode().strip(), b"connection: close" in head.lower()
first = get("/")
r = subprocess.run(["$BIN", "reload", "-c", "$T/agensio.toml"], capture_output=True, text=True)
time.sleep(0.5)
second = get("/")
print(first[1], "|", second[1], "|", "closed" if second[2] else "kept", "|", r.returncode)
PYT
)
check "keep-alive connection serves v2 after the reload, no close" "version one | version two | kept | 0" "$ka"
check "new listener 8098 answers" "version two" "$(curl -sS http://127.0.0.1:8098/)"
check "reload with no arguments finds ./agensio.toml" "0" "$(cd "$T" && "$BIN" reload > /dev/null 2>&1; echo $?)"
check "new proxy location works" '{"ok":true,"service":"upstream"}' "$(curl -sS $B/slow/json)"
check "reload logged" "yes" "$(grep -q 'reloaded .*2 site(s), 2 listener(s), 2 bound, 0 closed' "$T/logs/error.log" && echo yes)"

# A request in flight (1.5 s at the origin) survives a reload that removes its location
# and the 8098 listener; a keep-alive connection on 8098 finishes and is then closed.
write_config "$T/v2"
inflight=$(python3 - <<PYT
import socket, subprocess, time
s = socket.create_connection(("127.0.0.1", 8097)); s.settimeout(10)
s.sendall(b"GET /slow/slow?ms=1500 HTTP/1.1\\r\\nHost: i\\r\\n\\r\\n")
r = socket.create_connection(("127.0.0.1", 8098)); r.settimeout(5)
r.sendall(b"GET / HTTP/1.1\\r\\nHost: r\\r\\n\\r\\n")
d = b""
while b"version two" not in d: d += r.recv(4096)
time.sleep(0.2)
subprocess.run(["$BIN", "reload", "-c", "$T/agensio.toml"], capture_output=True)
time.sleep(0.3)
data = b""
while b"\\r\\n\\r\\n" not in data: data += s.recv(4096)
status = data.split(b"\\r\\n")[0].decode()
r.sendall(b"GET / HTTP/1.1\\r\\nHost: r\\r\\n\\r\\n")
d = b""
try:
    while True:
        c = r.recv(4096)
        if not c: break
        d += c
    closed = "then closed"
except socket.timeout:
    closed = "still open"
served = "served" if b"version two" in d else "not served"
print(status, "|", "close-header" if b"connection: close" in d.lower() else "no-close-header", served, closed)
PYT
)
check "in-flight request finished on the old configuration; removed listener's connection served once, told to close, closed" "HTTP/1.1 200 OK | close-header served then closed" "$inflight"
check "removed listener refuses new connections" "000" "$(code --max-time 2 http://127.0.0.1:8098/ 2>/dev/null)"
check "removed location is gone" "404" "$(code $B/slow/json)"

# A broken file is refused by the command before signalling, and by the server if signalled.
printf '[[site]]\nlisten = ["127.0.0.1:8097"]\nroot = "%s"\n[[site]\n' "$T/v2" > "$T/agensio.toml"
"$BIN" reload -c "$T/agensio.toml" > "$T/reload.out" 2>&1; rc=$?
check "reload command refuses a broken file" "1" "$rc"
kill -HUP $SRV; sleep 0.3
check "server refuses a broken file on SIGHUP, keeps serving" "version two yes" "$(curl -sS $B/) $(grep -q 'reload refused' "$T/logs/error.log" && echo yes)"
# A privileged port as an unprivileged user cannot be bound (the upstream's port would
# bind: both sides set SO_REUSEPORT).
printf '[[site]]\nlisten = ["127.0.0.1:8097"]\nroot = "%s"\n[[site]]\nlisten = ["127.0.0.1:80"]\nroot = "%s"\n' "$T/v2" "$T/v2" > "$T/agensio.toml"
kill -HUP $SRV; sleep 0.3
if [ "$(id -u)" != 0 ]; then
check "a listener that cannot bind refuses the reload, nothing changed" "version two yes" "$(curl -sS $B/) $(grep -q 'reload refused: cannot bind 127.0.0.1:80' "$T/logs/error.log" && echo yes)"
fi

# Load across reloads: wrk hammers 8097 while the configuration flips between v1 and v2
# three times; every response is a 2xx and no socket error happens.
write_config "$T/v2"
wrk -t4 -c64 -d6s --latency $B/ > "$T/wrk.txt" 2>&1 &
W=$!
for i in 1 2 3; do sleep 1; write_config "$T/v1"; kill -HUP $SRV; sleep 1; write_config "$T/v2"; kill -HUP $SRV; done
wait $W
check "wrk across six reloads: no errors, no non-2xx, enough requests" "yes" "$(grep -qE 'Socket errors|Non-2xx' "$T/wrk.txt" && echo no || { awk '/requests in/{print ($1 > 10000) ? "yes" : "too few"}' "$T/wrk.txt"; })"
check "the server survived" "version two" "$(curl -sS $B/)"
echo "reload: $pass passed, $fail failed  ($(awk '/Requests\/sec/{print $2}' "$T/wrk.txt") req/s during the reload storm)"
[ $fail = 0 ]
