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
  rm -f /etc/fail2ban/jail.d/agensio.conf /etc/fail2ban/jail.d/zz-agensio-test.conf /etc/fail2ban/filter.d/wordpress-soft.conf /etc/fail2ban/filter.d/wordpress-hard.conf /run/rsyslogd.pid
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
app = "php"
php = { socket = "unix:$T/run/none.sock" }
login_paths = ["/login", "/?controller=AuthController&action=check"]
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
check "protection: checked through the helper; nft present, no table, port 18880 uncovered; fail2ban present; the rendered files name the host's port, log and login path; the trial writes the config directory's firewall.nft; the unit's keep step renders the unit for that path" "True True False False [18880] True no-limit yes yes yes 4" "$(prot 'd["firewall"]["detected"]["checked"], d["firewall"]["detected"]["nft_available"], d["firewall"]["detected"]["table_loaded"], d["firewall"]["detected"]["covered"], d["firewall"]["detected"]["uncovered_tcp_ports"], d["fail2ban"]["detected"]["fail2ban_available"], "no-limit" if d["summary"].startswith("no per-address limit on port(s) 18880") else d["summary"]') $(grep -q 'tcp dport { 18880 }' <(ctl protection --nft) && echo yes) $(ctl protection --jail | grep -q "^logpath   = $T/logs/access.log" && ctl protection --jail | grep -qF 'agensio-login[paths="' && ctl protection --jail | grep -qF '(?:l|\x25[46]C)(?:o|\x25[46]F)(?:g|\x25[46]7)(?:i|\x25[46]9)(?:n|\x25[46]E)' && echo yes) $(ctl protection --unit | grep -q "ConditionPathExists=$T/firewall.nft" && echo yes) $(prot 'len(d["firewall"]["keep"])')"

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
check "a second site on another port with its own login paths (one through the query string) is created; its answer's next_steps carry root's re-render lines for the jail and the ruleset; health: the loaded table covers no limit on 18881 and the jail file is stale" "True jail+nft warn:firewall_limits_missing info:fail2ban_jail_stale yes yes" "$(python3 -c "import json; d=json.load(open('$T/create.json')); print(d['ok']); ns=' '.join(d['next_steps']); print(('jail' if 'fail2ban jail on disk is older' in ns and 'agensio ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf; fail2ban-client reload' in ns else 'nojail') + '+' + ('nft' if 'firewall ruleset on disk is older' in ns and 'nft -f $T/firewall.nft' in ns else 'nonft'))" | tr '\n' ' ' | sed 's/ $//') $(codes) $(ctl health | grep -q 'covers no limit on port(s) 18881' && echo yes) $(ctl protection --jail | grep -c '^filter    = agensio-login\[paths="' | sed 's/^1$/yes/')"
# The alpha.44 report's spellings: the log holds the request as the client sent it, so the
# rendered filter must match every spelling the server and the applications accept.
: > $T/spell.log; i=0
for p in '/?controller=AuthController&action=check' '/index.php?controller=AuthController&action=check' '/?controller=Auth%43ontroller&action=check' '/?action=check&controller=AuthController' \
         '/?controller=AuthController&action=check&csrf=1' '/?controller=%61uthController&action=%43HECK' '/LOGIN' '//login' '/./login' '/x/../login' '/x/%2e%2e/login' '/%4Cogin' '/%2Flogin' \
         '/login?next=/' '/index.php/login' '/signin/' '/%73ignin'; do
  i=$((i+1)); printf '203.0.113.9 - - [02/Oct/2026:10:00:%02d +0000] "POST %s HTTP/1.1" 302 0 "-" "x"\n' $i "$p" >> $T/spell.log; done
for p in '/login.html' '/login/x' '/signinx' '/?controller=TaskController&action=save' '/signin/reset' '/index.php' '/index.php?option=com_content&task=article.save' '/index.php?controller=BoardAjaxController&action=save'; do
  i=$((i+1)); printf '203.0.113.9 - - [02/Oct/2026:10:00:%02d +0000] "POST %s HTTP/1.1" 302 0 "-" "x"\n' $i "$p" >> $T/spell.log; done
printf '203.0.113.9 - - [02/Oct/2026:10:00:40 +0000] "GET /login HTTP/1.1" 200 0 "-" "x"\n' >> $T/spell.log
PATHS=$(ctl protection --jail | sed -n 's/^filter    = agensio-login\[paths="\(.*\)"\]$/\1/p' | head -1)
check "the rendered login filter matches all seventeen spellings of the sites' logins (percent-encoding in either case, encoded slashes and dots, repeated slashes, dot segments, case, trailing slash, the PHP front controller before the path, query order and extra parameters) and none of the nine that are not logins (a format suffix or path info on a plain path, index.php alone or with another query)" "17 matched, 9 missed" "$(fail2ban-regex $T/spell.log "agensio-login[paths=\"$PATHS\"]" 2>&1 | sed -n 's/^Lines: [0-9]* lines, [0-9]* ignored, \([0-9]* matched, [0-9]* missed\)$/\1/p')"
# The alpha.45 report's pathological lines: "./" repeated to 4, 8 and 16 KB and "a/../" to 16 KB before
# the login path; the grammar is unambiguous, so all four match within the time limit (2.3 s and worse before).
python3 - "$T/slow.log" <<'PYT'
import sys
lines = ["/" + "./" * 2048 + "login", "/" + "./" * 4096 + "login", "/" + "./" * 8192 + "login", "/" + "a/../" * 3277 + "login",
         # the alpha.46 report: the query login's root run against a line of slashes, with and without a query
         "/" + "%2F" * 3200 + "x", "/" * 3200 + "x", "/" + "./" * 8000 + "x", "/" + "%2F" * 1600 + "?controller=AuthController&action=check",
         "/" * 3200 + "?action=check&controller=AuthController&x=1", "/" + "./" * 8000 + "?controller=AuthController&action=check&" + "a=b&" * 2000]
with open(sys.argv[1], "w") as f:
    for i, p in enumerate(lines): f.write('203.0.113.9 - - [02/Oct/2026:10:01:%02d +0000] "POST %s HTTP/1.1" 302 0 "-" "x"\n' % (i, p))
PYT
check "ten request lines of up to 16 KB of slashes and dot segments, with and without the query login's parameters, are decided within 5 s, linear time (the alpha.45 grammar took seconds, the alpha.46 one minutes for the query login)" "7 matched, 3 missed" "$(timeout 5 fail2ban-regex $T/slow.log "agensio-login[paths=\"$PATHS\"]" 2>&1 | sed -n 's/^Lines: [0-9]* lines, [0-9]* ignored, \([0-9]* matched, [0-9]* missed\)$/\1/p')"
ctl protection --nft > $T/firewall.nft && nft -f $T/firewall.nft
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null
sleep 0.5
check "rendered and loaded again: both ports covered, the jail current" "info:firewall_limits_unsaved [18880, 18881] same" "$(codes) $(prot 'd["firewall"]["detected"]["limited_tcp_ports"], d["fail2ban"]["installed_jail"]')"

# 5b. An upgrade changed a shipped filter (the alpha.44 report): the installed copy is stale, health
# and protection say which, and every re-render line starts with the install line.
cp /etc/fail2ban/filter.d/agensio-auth.conf $T/auth.bak; printf '[Definition]\nfailregex = ^<HOST> old\n' > /etc/fail2ban/filter.d/agensio-auth.conf
ctl site-update lp.test --login-path /other --yes --reason prot > $T/update.json
check "an installed filter of an older build: health warns naming it (and the jail is stale from the new login path), protection reports it stale, and the site change's re-render step starts with the install line" "info:firewall_limits_unsaved warn:fail2ban_filter_stale info:fail2ban_jail_stale stale agensio-auth yes" "$(codes) $(prot 'd["fail2ban"]["installed_filters"]["state"], ",".join(d["fail2ban"]["installed_filters"]["stale"])') $(python3 -c "import json; ns=[x for x in json.load(open('$T/update.json'))['next_steps'] if 'fail2ban jail on disk' in x]; print('yes' if ns and 'as root: install -m 644 /usr/share/agensio/fail2ban/filter.d/agensio-login.conf' in ns[0] and ns[0].find('install -m 644') < ns[0].find('agensio ctl protection --jail') else ns)")"
cp $T/auth.bak /etc/fail2ban/filter.d/agensio-auth.conf; ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null; sleep 0.5
check "filters and jail reinstalled: back to the one informational finding" "info:firewall_limits_unsaved same same" "$(codes) $(prot 'd["fail2ban"]["installed_filters"]["state"], d["fail2ban"]["installed_jail"]')"

# 5c. The failure tier (2026-10-03): a WordPress site brings the WP fail2ban plugin's two jails and a
# Drupal site fail2ban's drupal-auth, each disabled with the user's steps until the filter and the log
# exist; agensio installs nothing. The plugin's filters are stood in for by two minimal files here;
# the Drupal filter is fail2ban's own, run on a line in the Syslog module's format.
mkdir -p $T/www3 $T/www4
ctl site-create --domain wp.test --app wordpress --php-socket unix:$T/run/none.sock --no-user --https none --root $T/www3 --listen-plain 0.0.0.0:18883 --yes --reason prot > $T/wp.json
ctl site-create --domain dr.test --app drupal --php-socket unix:$T/run/none.sock --no-user --https none --root $T/www4 --listen-plain 0.0.0.0:18884 --yes --reason prot > $T/dr.json
rm -f /var/log/auth.log /var/log/syslog /run/rsyslogd.pid
# No syslog daemon writes files in this container (the alpha.47 report's journald-only host): the
# failure jails read the journal, drupal-auth enabled at once since fail2ban ships its filter, the
# WordPress jails waiting for the plugin's filters, which root takes from the plugin's release.
check "a journald-only host: the failure jails read the journal (backend systemd; Drupal's identity, the php-fpm unit or the plugin's identity per site name), drupal-auth is enabled at once, the WordPress ones wait for the plugin's filters taken from its release" "3 yes yes True False yes" "$(ctl protection --jail | grep -c '^backend   = systemd') $(ctl protection --jail | grep -q '^journalmatch = SYSLOG_IDENTIFIER=drupal$' && echo yes) $(ctl protection --jail | grep -q '^journalmatch = _SYSTEMD_UNIT=php.*-fpm.service + SYSLOG_IDENTIFIER=wordpress(wp.test)$' && echo yes) $(prot '[f["enabled"] for f in d["failure_jails"] if f["app"] == "drupal"][0], [f["enabled"] for f in d["failure_jails"] if f["app"] == "wordpress"][0]') $(ctl protection --jail | grep -q 'https://downloads.wordpress.org/plugin/wp-fail2ban.latest-stable.zip' && echo yes)"
# The journal itself (alpha.48 report): drupal-auth is enabled before the Syslog module is, so
# health asks the journal through the helper for one line of the application; none here (the
# container has no journal), so the finding stays with the module's step; a journalctl that
# answers a line (a script standing in for it) ends it.
drupal_unseen() { ctl health | python3 -c 'import json,sys; d=json.load(sys.stdin); f=[x for x in d["findings"] if x["code"] == "fail2ban_failures_unseen" and "(drupal)" in x["message"]]; print(len(f), "journal" if f and "read the journal and it holds no line matching SYSLOG_IDENTIFIER=drupal from the last 30 days, so Drupal" in f[0]["message"] else "-", "module" if f and f[0]["fix"].startswith("enable Drupal") and "render the jail again" not in f[0]["fix"] else "-")'; }
check "journald-only host, nothing from Drupal in the journal: the enabled drupal-auth jail keeps the finding, with the Syslog module alone as the fix; protection says journal_seen false; two findings, one per application" "1 journal module False 2" "$(drupal_unseen) $(prot '[f["journal_seen"] for f in d["failure_jails"] if f["app"] == "drupal"][0]') $(codes | tr ' ' '\n' | grep -c fail2ban_failures_unseen)"
mv /usr/bin/journalctl /usr/bin/journalctl.real
printf '#!/bin/sh\ncase "$*" in *SYSLOG_IDENTIFIER=drupal*) echo "https://dr.test|1696327202|user|203.0.113.9|https://dr.test/user/login|https://dr.test/user/login|0||Login attempt failed for admin.";; esac\n' > /usr/bin/journalctl; chmod 755 /usr/bin/journalctl
check "a journal with one Drupal line: the finding is gone and journal_seen is true; the WordPress jails still wait for their filters" "0 - - True 1" "$(drupal_unseen) $(prot '[f["journal_seen"] for f in d["failure_jails"] if f["app"] == "drupal"][0]') $(codes | tr ' ' '\n' | grep -c fail2ban_failures_unseen)"
mv /usr/bin/journalctl.real /usr/bin/journalctl
# With a syslog daemon present (its pid file here), the jails read the files, absent for now.
touch /run/rsyslogd.pid
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null; sleep 0.5
check "a WordPress and a Drupal site with a syslog daemon but no log files: three failure jails render disabled with the needs (the plugin from the admin panel, root's filter copy from the release, the Syslog module, the daemon's file), fail2ban accepts the file, health says the failed logins are counted only as attempts" "True True 3 3 yes yes yes 2" "$(python3 -c "import json; print(json.load(open('$T/wp.json'))['ok'], json.load(open('$T/dr.json'))['ok'])") $(grep -c -E '^\[agensio-(wordpress-soft|wordpress-hard|drupal-auth)\]' /etc/fail2ban/jail.d/agensio.conf) $(grep -A12 '^\[agensio-' /etc/fail2ban/jail.d/agensio.conf | grep -c '^# Disabled: the filter\|^# Disabled: the log') $(grep -q '^#   install and activate the WP fail2ban plugin from the WordPress admin panel' /etc/fail2ban/jail.d/agensio.conf && echo yes) $(grep -q "or read $T/www3/wp-content/plugins/wp-fail2ban/filters.d/wordpress-hard.conf" /etc/fail2ban/jail.d/agensio.conf && echo yes) $(grep -q '^#   enable Drupal.s Syslog module' /etc/fail2ban/jail.d/agensio.conf && echo yes) $(codes | tr ' ' '\n' | grep -c fail2ban_failures_unseen)"
check "protection lists the failure jails with their state and needs (fail2ban ships drupal-auth, so that filter is installed; the plugin's are not)" "agensio-wordpress-soft:False:False agensio-wordpress-hard:False:False agensio-drupal-auth:False:True" "$(prot '" ".join(f["name"] + ":" + str(f["enabled"]) + ":" + str(f["filter_installed"]) for f in d["failure_jails"])')"
printf '[Definition]\nfailregex = ^.*wordpress\\(\\S+\\)\\[\\d+\\]: Authentication failure for \\S+ from <HOST>$\nignoreregex =\n' > /etc/fail2ban/filter.d/wordpress-soft.conf
printf '[Definition]\nfailregex = ^.*wordpress\\(\\S+\\)\\[\\d+\\]: Blocked user enumeration attempt from <HOST>$\nignoreregex =\n' > /etc/fail2ban/filter.d/wordpress-hard.conf
printf 'Oct  3 10:00:01 host wordpress(wp.test)[123]: Authentication failure for admin from 203.0.113.9\n' > /var/log/auth.log
printf 'Oct  3 10:00:02 host drupal: https://dr.test|1696327202|user|203.0.113.9|https://dr.test/user/login|https://dr.test/user/login|0||Login attempt failed for admin.\n' > /var/log/syslog
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null; sleep 0.5
check "with the filters and the logs in place: the three jails render enabled, fail2ban runs them, the plugin's line and Drupal's Syslog line match (fail2ban's own drupal-auth filter), the finding is gone" "3 3 yes 1 1 0" "$(grep -A4 -E '^\[agensio-(wordpress-soft|wordpress-hard|drupal-auth)\]' /etc/fail2ban/jail.d/agensio.conf | grep -c '^enabled   = true') $(fail2ban-client status | sed -n 's/.*Jail list:[[:space:]]*//p' | tr ',' '\n' | grep -c -E 'agensio-(wordpress-soft|wordpress-hard|drupal-auth)') $(prot '"yes" if all(f["enabled"] for f in d["failure_jails"]) else d["failure_jails"]') $(fail2ban-regex /var/log/auth.log wordpress-soft 2>&1 | sed -n 's/^Lines: [0-9]* lines, [0-9]* ignored, \([0-9]*\) matched, .*/\1/p') $(fail2ban-regex /var/log/syslog drupal-auth 2>&1 | sed -n 's/^Lines: [0-9]* lines, [0-9]* ignored, \([0-9]*\) matched, .*/\1/p') $(codes | tr ' ' '\n' | grep -c fail2ban_failures_unseen)"
rm -f /etc/fail2ban/filter.d/wordpress-soft.conf /etc/fail2ban/filter.d/wordpress-hard.conf /run/rsyslogd.pid
ctl site-delete wp.test --yes --reason prot > /dev/null; ctl site-delete dr.test --yes --reason prot > /dev/null
ctl protection --jail > /etc/fail2ban/jail.d/agensio.conf && fail2ban-client reload > /dev/null; sleep 0.5
check "the two sites deleted and the jail rendered again: no failure jail, no finding about them" "0 0" "$(grep -c -E '^\[agensio-(wordpress|drupal)' /etc/fail2ban/jail.d/agensio.conf) $(codes | tr ' ' '\n' | grep -c fail2ban_failures_unseen)"

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
