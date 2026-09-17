#!/usr/bin/env bash
# Live checks of a Node.js application (Uptime Kuma) behind agensio's proxy preset: the
# UI talks Socket.IO over a WebSocket, so this proves the Upgrade tunnel with real traffic.
# Skips when the bed is not running (bench/uptime-kuma/setup.sh). Usage: tests/uptime-kuma.sh build/agensio
set -uo pipefail
BIN=${1:-build/agensio}
curl -fs -o /dev/null http://127.0.0.1:3011/ 2>/dev/null || { echo "uptime-kuma: bed not running, skipped"; exit 0; }
"$BIN" -c bench/uptime-kuma/agensio.toml > bench/tmp/kuma-agensio.log 2>&1 & PID=$!
trap 'kill $PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8076 2>/dev/null && break; sleep 0.1; done
B=http://127.0.0.1:8076
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }  # name expected actual
check "root redirects to the app (setup or dashboard) on this host" "302 http://127.0.0.1:8076/" "$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' $B/ | sed 's#8076/.*#8076/#')"
check "app shell served" "200 yes" "$(curl -sS -L -o bench/tmp/kuma-home.html -w '%{http_code}' $B/) $(grep -qi 'uptime kuma' bench/tmp/kuma-home.html && echo yes)"
js=$(grep -o 'src="/assets/[^"]*\.js"' bench/tmp/kuma-home.html | head -1 | sed 's/src="//; s/"$//')
check "bundle served through the proxy" "200" "$(curl -sS -o /dev/null -w '%{http_code}' "$B$js")"
check "socket.io long-polling handshake" "yes" "$(curl -sS "$B/socket.io/?EIO=4&transport=polling" | grep -q '^0{"sid"' && echo yes)"
ws=$(python3 - <<'PYT'
import socket, base64, os
s = socket.create_connection(("127.0.0.1", 8076)); s.settimeout(10)
key = base64.b64encode(os.urandom(16)).decode()
s.sendall(("GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: 127.0.0.1:8076\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n").encode())
data = b""
while b"\r\n\r\n" not in data: data += s.recv(4096)
head, rest = data.split(b"\r\n\r\n", 1)
status = head.split(b"\r\n")[0].decode()
while len(rest) < 2: rest += s.recv(4096)
frame_ok = rest[0] == 0x81  # a text frame from the server: the engine.io open packet
# reply with a masked "40" (socket.io connect) and expect a "40{...}" answer
payload = b"40"; mask = os.urandom(4)
s.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
more = b""
try:
    while b"40" not in more: more += s.recv(4096)
    connected = "connected"
except socket.timeout:
    connected = "timeout"
print(status, "text-frame" if frame_ok else "no-frame", connected)
PYT
)
check "socket.io over a WebSocket through the tunnel" "HTTP/1.1 101 Switching Protocols text-frame connected" "$ws"
echo "uptime-kuma: $pass passed, $fail failed"; [ $fail = 0 ]
