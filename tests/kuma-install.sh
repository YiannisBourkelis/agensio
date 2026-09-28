#!/usr/bin/env bash
# Uptime Kuma installed through the control plane alone (2026-09-28, the Node "wall 1" report):
# as root in a devbox with Debian's nodejs and npm and access to GitHub and the npm registry, a
# site with app = "node" and its own account gets Kuma's release archive (site-install), its
# dependencies from the lockfile (npm_ci), its prebuilt frontend (npm_run download-dist), its
# data directory in the account's home and SQLite chosen (site-env-set), its entry
# (site-update); node is then started with the very unit `agensio ctl site-unit` renders (its
# Environment lines, its EnvironmentFile, its ExecStart, as the site's account), and agensio
# serves Kuma over TLS: its pages and assets, socket.io's polling and its WebSocket upgrade,
# the project's own files refused at the edge. Skipped without node and npm or the network.
#   docker run --rm --init --user root --dns-option single-request-reopen --cpuset-cpus=0-3 \
#     -v "$PWD:$PWD" -w "$PWD" agensio-devbox:node tests/kuma-install.sh build/agensio
# agensio-devbox:node is agensio-devbox plus Debian's nodejs and npm:
#   printf 'FROM agensio-devbox\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends nodejs npm && rm -rf /var/lib/apt/lists/*\n' \
#     | docker build -t agensio-devbox:node -
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
VERSION=${KUMA_VERSION:-2.5.5}
[ "$(id -u)" = 0 ] || { echo "kuma: needs root; skipped"; exit 0; }
[ -x /usr/bin/node ] && [ -x /usr/bin/npm ] || { echo "kuma: no node/npm in /usr/bin; skipped"; exit 0; }
curl -sSf -o /dev/null --max-time 10 https://registry.npmjs.org/ || { echo "kuma: registry.npmjs.org unreachable; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-kuma.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; pkill -9 -u k9 2>/dev/null; sleep 0.3; userdel k9 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=kuma.test -addext subjectAltName=DNS:kuma.test -keyout $T/certs/key.pem -out $T/certs/cert.pem 2>/dev/null
chown agensio:agensio $T/certs/key.pem; chmod 640 $T/certs/key.pem; chmod 644 $T/certs/cert.pem
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
state_dir = "$T/state"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
task_limits = { timeout = 600 }
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18997"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/kuma.test/app
task() {  # task NAME [--param k=v]: runs it, prints ok exit seconds, keeps the answer in $T/out
    ctl site-task kuma.test "$@" --yes --reason live > $T/out
    cp $T/out $T/out-$1.json
    j 'd["ok"], d.get("exit"), int(d.get("duration_ms", 0) / 1000)'
    python3 -c "import json; d=json.load(open('$T/out')); o=d.get('output', ''); print(d.get('error', '')); print(d.get('hint', '')); print(o)" > $T/last-$1.txt
}

out=$(ctl site-create --domain kuma.test --app node --root $APP --user k9 --upstream http://127.0.0.1:18909 --cert $T/certs/cert.pem --key $T/certs/key.pem --listen-plain 127.0.0.1:18980 --listen-tls 127.0.0.1:18943 --yes --reason live)
check "site-create: app = node, its own account" "yes k9" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c %U $APP)"
check "site-tasks: npm and node accepted, nothing for root to install" "True no" "$(ctl site-tasks kuma.test > $T/out; j 'all(t["interpreter"]["ok"] for t in d["tasks"])') $(j '"yes" if "run_as_root" in d else "no"')"
ctl site-install kuma.test --url https://codeload.github.com/louislam/uptime-kuma/tar.gz/refs/tags/$VERSION --yes --reason live > $T/out
check "site-install $VERSION from GitHub: package.json read, the entry guessed, Debian's node matched against engines" "True uptime-kuma server/server.js True True" "$(j 'd["ok"], d["facts"].get("package_name"), d["facts"].get("entry_guess"), d["facts"].get("lockfile"), d["facts"].get("engines_match")')"
check "its next steps name npm_ci, download-dist, DATA_DIR and the first visit" "yes yes yes yes" "$(for k in 'site_task npm_ci' 'download-dist' 'DATA_DIR' 'whoever opens the site first'; do j '"yes" if any('"'$k'"' in x for x in d["next_steps"]) else "no"' | tr '\n' ' '; done | sed 's/ $//')"
r=$(task npm_ci); check "npm_ci: the dependencies from the lockfile, as k9, npm's cache in its home" "True 0 yes yes" "$(echo $r | cut -d' ' -f1-2) $([ -d $APP/node_modules/socket.io ] && [ "$(stat -c %U $APP/node_modules)" = k9 ] && echo yes) $([ -d $T/state/k9/.npm ] && echo yes)"
echo "     npm_ci took $(echo $r | cut -d' ' -f3) s: $(python3 -c "import json; print(json.load(open('$T/out-npm_ci.json')).get('summary', ''))")"
r=$(task npm_run --param script=download-dist); check "npm_run download-dist: Kuma's prebuilt frontend in dist/" "True 0 yes" "$(echo $r | cut -d' ' -f1-2) $([ -f $APP/dist/index.html ] && echo yes)"
ctl site-env-set kuma.test --set DATA_DIR=$T/state/k9/data/ --set UPTIME_KUMA_DB_TYPE=sqlite --yes --reason live > /dev/null
check "the site's environment cannot unbind it: HOST refused" "1" "$(ctl site-env-set kuma.test --set HOST=0.0.0.0 --yes --reason live > /dev/null 2>&1; echo $?)"
ctl site-update kuma.test --entry server/server.js --yes --reason live > /dev/null

# node with the unit site-unit renders: its Environment lines, its EnvironmentFile (read as
# root, as systemd does), its WorkingDirectory and ExecStart, as its User.
ctl site-unit kuma.test --raw > $T/unit
wd=$(sed -n 's/^WorkingDirectory=//p' $T/unit); ex=$(sed -n 's/^ExecStart=//p' $T/unit); user=$(sed -n 's/^User=//p' $T/unit)
envs=$(sed -n 's/^Environment=//p' $T/unit | tr '\n' ' ')
envfile=$(sed -n 's/^EnvironmentFile=-//p' $T/unit)
fileenv=$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)="\(.*\)"$/\1=\2/p' "$envfile" | tr '\n' ' ')
check "the rendered unit: k9, root's node on the entry, HOST and PORT from the upstream" "k9 yes yes" "$user $([ "$ex" = "/usr/bin/node $APP/server/server.js" ] && echo yes) $(echo "$envs" | grep -q 'HOST=127.0.0.1 PORT=18909' && echo yes)"
runuser -u "$user" -- /usr/bin/env -i $envs $fileenv /bin/sh -c "cd $wd && umask 027 && exec $ex" > $T/node.out 2>&1 &
for _ in $(seq 1 200); do curl -s -o /dev/null http://127.0.0.1:18909/ && break; sleep 0.3; done
check "Kuma listens on the upstream's loopback address only, its database in the account's home" "yes yes no" "$(ss -ltn | grep -q '127.0.0.1:18909 ' && echo yes) $([ -f $T/state/k9/data/kuma.db ] && echo yes) $([ -e $APP/data/kuma.db ] && echo yes || echo no)"
H="--resolve kuma.test:18943:127.0.0.1 -k"
page=$(curl -sS $H -L -o $T/home.html -w '%{http_code}' https://kuma.test:18943/)
check "agensio serves Kuma's page over TLS through node" "200 yes" "$page $(grep -qi 'uptime kuma' $T/home.html && echo yes)"
js=$(grep -o 'src="/assets/[^"]*\.js"' $T/home.html | head -1 | sed 's/src="//; s/"$//')
check "a script the page names comes through node" "200" "$(curl -sS $H -o /dev/null -w '%{http_code}' "https://kuma.test:18943$js")"
check "socket.io's polling handshake through agensio" "200 yes" "$(curl -sS $H -o $T/eio.txt -w '%{http_code}' 'https://kuma.test:18943/socket.io/?EIO=4&transport=polling') $(head -c 2 $T/eio.txt | grep -q '^0{' && echo yes)"
check "socket.io's WebSocket upgrade through agensio over TLS: 101, then Kuma's engine.io open frame through the tunnel" "HTTP/1.1 101 Switching Protocols yes" "$(python3 - <<'PY'
import socket, ssl
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", 18943), timeout=5), server_hostname="kuma.test")
s.sendall(b"GET /socket.io/?EIO=4&transport=websocket HTTP/1.1\r\nHost: kuma.test:18943\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
          b"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
data = b""
while b"\r\n\r\n" not in data:
    data += s.recv(4096)
head, rest = data.split(b"\r\n\r\n", 1)
while len(rest) < 4:
    rest += s.recv(4096)
# a text frame (0x81), unmasked, short length: engine.io's open packet "0{...sid...}"
n = rest[1] & 0x7f
start = 2 if n < 126 else 4
while len(rest) < start + 2:
    rest += s.recv(4096)
print(head.split(b"\r\n")[0].decode(), "yes" if rest[0] == 0x81 and rest[start:start + 2] == b"0{" else repr(rest[:40]))
PY
)"
check "the project's files are refused at the edge, never forwarded" "404 404 404 404" "$(for p in /package.json /package-lock.json /node_modules/socket.io/package.json /data/kuma.db; do curl -sS $H -o /dev/null -w '%{http_code} ' https://kuma.test:18943$p; done | sed 's/ $//')"
check "every task is in the audit log" "2" "$(grep -c 'sites/kuma.test/task (live): ran as k9 .* -> exit 0' $T/logs/audit.log)"

echo "kuma: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then
    for f in $T/last-*.txt; do echo "--- $f"; head -20 "$f"; echo "..."; tail -15 "$f"; done
    echo "--- node"; tail -40 $T/node.out
    echo "--- error.log"; tail -20 $T/logs/error.log
fi
[ "$fail" = 0 ]
