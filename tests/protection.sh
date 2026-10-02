#!/usr/bin/env bash
# Host protection (2026-10-02, docs/configuration.md 18) against the real nft and fail2ban: as
# root in a devbox with both installed (agensio-devbox:host) and CAP_NET_ADMIN, so nft loads
# rules into the container's own network namespace. The server runs as root with the helper
# and a site on 0.0.0.0 (public-shaped); health reports both pieces missing with root's
# commands; the rendered ruleset loads (twice: idempotent) and health sees it covering the
# port, whether it survives a reboot unknown (no systemd here); the shipped filters and the
# rendered jail start a fail2ban that reads the site's access log and bans an address after
# ten POSTs to a login path, which health and protection report; a site added later makes the
# loaded table and the installed jail stale, rendering again heals both; host_protection =
# "external" turns the findings informational, "off" removes them. Skipped without root, nft
# or fail2ban (the plain devbox has neither).
#   docker run --rm --init --user root --cap-add NET_ADMIN -v "$PWD:$PWD" -w "$PWD" agensio-devbox:host tests/protection.sh build/agensio
# agensio-devbox:host is agensio-devbox plus nftables, fail2ban and iproute2:
#   printf 'FROM agensio-devbox\nUSER root\nRUN apt-get update && apt-get install -y --no-install-recommends nftables fail2ban iproute2 && rm -rf /var/lib/apt/lists/*\nUSER dev\n' \
#     | docker build -t agensio-devbox:host -
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
[ "$(id -u)" = 0 ] || { echo "protection: needs root; skipped"; exit 0; }
command -v nft >/dev/null || { echo "protection: no nft; skipped"; exit 0; }
command -v fail2ban-client >/dev/null || { echo "protection: no fail2ban; skipped"; exit 0; }
nft list ruleset >/dev/null 2>&1 || { echo "protection: nft cannot list the ruleset (run with --cap-add NET_ADMIN); skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-prot.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() {
  [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null
  fail2ban-client stop >/dev/null 2>&1
  nft delete table inet agensio 2>/dev/null; nft delete table inet f2b-table 2>/dev/null
  rm -f /etc/fail2ban/jail.d/agensio.conf /etc/fail2ban/jail.d/zz-agensio-test.conf
  sleep 0.3; rm -rf "$T"
}
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/www2; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
echo hi > $T/www/index.html; echo hi2 > $T/www2/index.html
write_config() {
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
$1
[[site]]
server_name = ["*"]
listen = ["0.0.0.0:18880"]
root = "$T/www"
login_paths = ["/login"]
CFG
}
write_config ""
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
codes() { ctl health | python3 -c 'import json,sys; d=json.load(sys.stdin); print(" ".join(f["severity"] + ":" + f["code"] for f in d["findings"] if f["code"].startswith(("firewall_", "fail2ban_", "protection_"))))'; }
prot() { ctl protection > $T/prot.json; python3 -c "import json; d=json.load(open('$T/prot.json')); print($1)"; }

# 1. Nothing in place: both missing, with root's commands.
check "health: a public listener without firewall limits or a fail2ban jail: both missing (fail2ban installed but not running), the fixes are root's trial and install commands" "warn:firewall_limits_missing warn:fail2ban_missing yes yes" "$(codes) $(ctl health | grep -q "nft -f $T/firewall.nft; systemd-run --on-active=10min --unit agensio-firewall-trial" && echo yes) $(ctl health | grep -q 'fail2ban is installed but not running' && echo yes)"
check "protection: checked through the helper; nft present, no table, port 18880 uncovered; fail2ban present; the rendered files name the host's port, log and login path; the trial writes the config directory's firewall.nft; the unit's keep step renders the unit for that path" "True True False False [18880] True no-limit yes yes yes 4" "$(prot 'd["firewall"]["detected"]["checked"], d["firewall"]["detected"]["nft_available"], d["firewall"]["detected"]["table_loaded"], d["firewall"]["detected"]["covered"], d["firewall"]["detected"]["uncovered_tcp_ports"], d["fail2ban"]["detected"]["fail2ban_available"], "no-limit" if d["summary"].startswith("no per-address limit on port(s) 18880") else d["summary"]') $(grep -q 'tcp dport { 18880 }' <(ctl protection --nft) && echo yes) $(ctl protection --jail | grep -q "^logpath   = $T/logs/access.log" && ctl protection --jail | grep -q 'agensio-login\[paths="/login"\]' && echo yes) $(ctl protection --unit | grep -q "ConditionPathExists=$T/firewall.nft" && echo yes) $(prot 'len(d["firewall"]["keep"])')"

# 2. The ruleset loaded (twice: the file is idempotent): covered; a reboot's fate unknown here.
ctl protection --nft > $T/firewall.nft
check "the rendered ruleset loads, and loads again over itself; the table carries its four counted rules" "0 0 4" "$(nft -f $T/firewall.nft; echo -n "$? "; nft -f $T/firewall.nft; echo -n "$? "; nft list table inet agensio | grep -c 'comment "agensio:')"
check "health: the limits are loaded and cover the port; whether they survive a reboot could not be told (no systemd here), so the keep commands are the fix; the file on disk is current" "info:firewall_limits_unsaved warn:fail2ban_missing True True [18880] 4 True True yes" "$(codes) $(prot 'd["firewall"]["detected"]["table_loaded"], d["firewall"]["detected"]["covered"], d["firewall"]["detected"]["limited_tcp_ports"], len(d["firewall"]["detected"]["rules"]), d["firewall"]["file_present"], d["firewall"]["file_current"]') $(ctl health | grep -q 'could not be told' && echo yes)"

# 3. fail2ban with the shipped filters and the rendered jail, reading the site's access log.
install -m 644 $ROOT/packaging/fail2ban/filter.d/agensio-login.conf $ROOT/packaging/fail2ban/filter.d/agensio-auth.conf $ROOT/packaging/fail2ban/filter.d/agensio-scan.conf $ROOT/packaging/fail2ban/filter.d/agensio-post.conf /etc/fail2ban/filter.d/
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf
printf '[DEFAULT]\nignoreip =\nignoreself = false\nbackend = polling\n[sshd]\nenabled = false\n' > /etc/fail2ban/jail.d/zz-agensio-test.conf   # loopback bannable here (ignoreself is on by default), no inotify, no sshd log
mkdir -p /run/fail2ban
fail2ban-client -x start > $T/f2b-start.out 2>&1
for _ in $(seq 1 50); do fail2ban-client status >/dev/null 2>&1 && break; sleep 0.2; done
check "fail2ban runs the four agensio jails over the site's access log" "agensio-auth, agensio-login, agensio-post, agensio-scan yes" "$(fail2ban-client status | sed -n 's/.*Jail list:[[:space:]]*//p') $(fail2ban-client status agensio-login | grep -q "File list:.*$T/logs/access.log" && echo yes)"
check "health: fail2ban covers the logs now; protection names the jails that read them and the installed jail file matches the rendering" "info:firewall_limits_unsaved True same 4 reads" "$(codes) $(prot 'd["fail2ban"]["detected"]["covered"], d["fail2ban"]["installed_jail"], len([j for j in d["fail2ban"]["detected"]["jails"] if j["reads_agensio_logs"]]), "reads" if "fail2ban reads the access logs" in d["summary"] else d["summary"]')"

# 4. Ten POSTs to the login path from one address: banned through nftables, seen by protection.
for _ in $(seq 1 11); do curl -sS -o /dev/null -X POST --max-time 3 http://127.0.0.1:18880/login; done
for _ in $(seq 1 60); do [ "$(fail2ban-client status agensio-login | sed -n 's/.*Currently banned:[[:space:]]*//p')" = 1 ] && break; sleep 0.25; done
check "eleven POSTs to /login from 127.0.0.1 ban it: fail2ban counts one, the site no longer answers that address, protection reports the ban" "1 refused 1 1" "$(fail2ban-client status agensio-login | sed -n 's/.*Currently banned:[[:space:]]*//p') $(curl -sS -o /dev/null --max-time 3 http://127.0.0.1:18880/ 2>/dev/null && echo answered || echo refused) $(prot 'd["fail2ban"]["detected"]["banned"], d["fail2ban"]["detected"]["total_banned"]')"
fail2ban-client set agensio-login unbanip 127.0.0.1 > /dev/null
check "unbanned: the site answers again" "200" "$(curl -sS -o /dev/null -w '%{http_code}' --max-time 3 http://127.0.0.1:18880/)"

# 5. A site added later: the loaded table misses its port and the installed jail is stale; rendering again heals both.
ctl site-create --domain lp.test --app static --no-user --https none --root $T/www2 --listen-plain 0.0.0.0:18881 --login-path /signin --login-path '/?controller=AuthController&action=check' --yes --reason prot > $T/create.json
check "a second site on another port with its own login paths (one through the query string) is created; health: the loaded table covers no limit on 18881 and the jail file is stale" "True warn:firewall_limits_missing info:fail2ban_jail_stale yes yes" "$(python3 -c "import json; print(json.load(open('$T/create.json'))['ok'])") $(codes) $(ctl health | grep -q 'covers no limit on port(s) 18881' && echo yes) $(ctl protection --jail | grep -q 'paths="/\\?controller=AuthController&action=check|/login|/signin"' && echo yes)"
printf '203.0.113.9 - - [02/Oct/2026:10:00:01 +0000] "POST /?controller=AuthController&action=check HTTP/1.1" 302 0 "-" "x"\n203.0.113.9 - - [02/Oct/2026:10:00:02 +0000] "POST /?controller=AuthController&action=check&csrf=1 HTTP/2.0" 302 0 "-" "x"\n203.0.113.9 - - [02/Oct/2026:10:00:03 +0000] "POST /?controller=TaskController&action=save HTTP/1.1" 302 0 "-" "x"\n203.0.113.9 - - [02/Oct/2026:10:00:04 +0000] "POST /signinx HTTP/1.1" 200 0 "-" "x"\n203.0.113.9 - - [02/Oct/2026:10:00:05 +0000] "POST /signin?next=/ HTTP/1.1" 200 0 "-" "x"\n' > $T/q.log
PATHS=$(ctl protection --jail | sed -n 's/^filter    = agensio-login\[paths="\(.*\)"\]$/\1/p' | head -1)
check "the rendered login filter matches the Kanboard login with and without further parameters and /signin with a query, not the task save or /signinx" "3 matched" "$(fail2ban-regex $T/q.log "agensio-login[paths=\"$PATHS\"]" 2>&1 | sed -n 's/^Lines: [0-9]* lines, [0-9]* ignored, \([0-9]* matched\), .*/\1/p')"
ctl protection --nft > $T/firewall.nft && nft -f $T/firewall.nft
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null
sleep 0.5
check "rendered and loaded again: both ports covered, the jail current" "info:firewall_limits_unsaved [18880, 18881] same" "$(codes) $(prot 'd["firewall"]["detected"]["limited_tcp_ports"], d["fail2ban"]["installed_jail"]')"

# 6. host_protection = "external" and "off".
nft delete table inet agensio
write_config 'host_protection = "external"'; ctl reload --yes --reason prot > /dev/null
check "external: the missing firewall limits are informational and say so" "info:firewall_limits_missing yes" "$(codes) $(ctl health | grep -q 'managed outside agensio' && echo yes)"
write_config 'host_protection = "off"'; ctl reload --yes --reason prot > /dev/null
check "off: no protection finding; the files are still rendered" "- off yes" "$(c=$(codes); echo "${c:--}") $(prot 'd["host_protection"]') $(ctl protection --nft | grep -q 'tcp dport { 18880, 18881 }' && echo yes)"
check "audit: the helper's host_protection runs are read-only and the health calls left no mutation line for them" "0" "$(grep -c 'host_protection' $T/logs/audit.log)"

echo "protection: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then echo "--- error.log"; tail -20 $T/logs/error.log; echo "--- fail2ban"; tail -20 $T/f2b-start.out; fail2ban-client status 2>&1 | tail -5; fi
[ "$fail" = 0 ]
