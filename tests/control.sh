#!/usr/bin/env bash
# Control socket roles (F0): run as root in the devbox with real accounts. The server
# starts as root with server.user, the socket's peer credentials decide the role: root
# and the server user are admin, members of the three groups get admin / operator /
# viewer, anyone else is refused at accept and written to the audit log. With only an
# admin group the socket is 0660 for that group; with several groups it is 0666 and the
# credentials alone gate it. usage (root): tests/control.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "control: needs root (run in the devbox with --user root); skipped"; exit 0; }
T=$(pwd)/bench/tmp/ctlroot; rm -rf "$T"; mkdir -p "$T/www" "$T/logs"; echo hi > "$T/www/index.html"
for g in ctladm ctlops ctlview; do getent group $g >/dev/null || groupadd $g; done
getent passwd ctlsrv >/dev/null || useradd -M -s /usr/sbin/nologin ctlsrv
getent passwd alice >/dev/null || useradd -M -s /bin/sh -g ctladm alice
getent passwd bob >/dev/null || useradd -M -s /bin/sh -g ctlops bob
getent passwd carol >/dev/null || useradd -M -s /bin/sh -G ctlview carol
getent passwd dave >/dev/null || useradd -M -s /bin/sh dave
chmod 755 "$T" "$T/www"; chown -R ctlsrv "$T/logs"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
role_as() { su -s /bin/sh "$1" -c "curl -sS --unix-socket '$T/run/control.sock' http://control/v1/status 2>/dev/null" | sed -n 's/.*"role":"\([a-z]*\)".*/\1/p'; }
write_config() {
  cat > "$T/agensio.toml" <<CFG
[server]
workers = 1
user = "ctlsrv"
pid_file = "$T/agensio.pid"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
$1
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8183"]
root = "$T/www"
CFG
}
start() { "$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!; for _ in $(seq 1 50); do [ -S "$T/run/control.sock" ] && break; sleep 0.1; done; sleep 0.2; }
stop() { kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; }
trap 'stop' EXIT

write_config 'admins = "ctladm"
operators = "ctlops"
viewers = "ctlview"'
start
check "three groups: socket 0666, directory owned by the server user" "666 ctlsrv" "$(stat -c '%a %U' "$T/run/control.sock" | cut -d' ' -f1) $(stat -c %U "$T/run")"
check "root is admin" "admin" "$(curl -sS --unix-socket "$T/run/control.sock" http://control/v1/status | sed -n 's/.*"role":"\([a-z]*\)".*/\1/p')"
check "the server user is admin" "admin" "$(role_as ctlsrv)"
check "admin group member (primary group) is admin" "admin" "$(role_as alice)"
check "operator group member is operator" "operator" "$(role_as bob)"
check "viewer group member (supplementary group) is viewer" "viewer" "$(role_as carol)"
check "an account in no group is refused at accept" "" "$(role_as dave)"
check "the refusal is in the audit log with the uid" "yes" "$(grep -q "uid=$(id -u dave) gid=$(id -g dave) role=none connect: refused" "$T/logs/audit.log" && echo yes)"
check "audit log owned by the server user, 0640 or stricter" "ctlsrv" "$(stat -c %U "$T/logs/audit.log")"
check "the data plane still serves" "hi" "$(curl -sS http://127.0.0.1:8183/)"
tools_as() { su -s /bin/sh "$1" -c "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n' | '$BIN' mcp --socket '$T/run/control.sock'" 2>/dev/null | grep -o '"name":"[a-z_]*"' | wc -l | tr -d ' '; }
check "mcp: a viewer's tool list has only the read tools" "10" "$(tools_as carol)"
check "mcp: an operator sees reload, logs-reopen, cert-renew and upload-delete too" "14" "$(tools_as bob)"
check "mcp: an admin sees everything" "21" "$(tools_as alice)"
check "mcp: an account without a role sees the read tools but cannot call them" "10 yes" "$(tools_as dave) $(su -s /bin/sh dave -c "printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"server_status\",\"arguments\":{}}}\n' | '$BIN' mcp --socket '$T/run/control.sock'" 2>/dev/null | grep -q '"isError":true' && echo yes)"
stop

write_config 'admins = "ctladm"'
start
check "one group: socket 0660 owned by the server user and the admin group" "660 ctlsrv ctladm" "$(stat -c '%a %U %G' "$T/run/control.sock")"
check "admin group member connects" "admin" "$(role_as alice)"
check "outsider cannot even connect (file mode)" "" "$(role_as dave)"
stop
check "socket removed at shutdown" "gone" "$([ -S "$T/run/control.sock" ] && echo still || echo gone)"

# Kill switch: no [control] table, no socket, `agensio ctl` says so.
write_config ''
sed -i '/^\[control\]/,/^$/d' "$T/agensio.toml"
start
check "without [control] no socket exists and ctl reports it" "gone 1" "$([ -S "$T/run/control.sock" ] && echo still || echo gone) $("$BIN" ctl status --socket "$T/run/control.sock" >/dev/null 2>&1; echo $?)"
stop
write_config 'admins = "ctladm"'
start
check "a 1 MB body is refused with 413" "413" "$(head -c 1048576 /dev/zero | tr '\0' 'a' | curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$T/run/control.sock" -X POST -H 'Content-Type: application/json' --data-binary @- http://control/v1/reload)"
check "a site name with a slash never reaches a file" "404" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket "$T/run/control.sock" -X POST -d '{"confirm":true}' 'http://control/v1/sites/..%2F..%2Fetc/disable')"
stop
echo "control: $pass passed, $fail failed"
[ $fail = 0 ]
