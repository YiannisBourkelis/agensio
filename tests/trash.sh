#!/usr/bin/env bash
# The trash (F12b, 2026-09-30): a site deleted with its files, through the provisioning helper as
# root in the devbox. Two Rails sites share an account; deleting one with --files moves its
# directory, its virtualenv (the account's state stays while another site uses it), its access
# log with its rotation and its environment file into <sites_root>/.trash/<entry>, root's alone,
# and keeps the site file's text in the manifest; the second delete takes the whole state
# directory. Refused while the site's service runs (a fake systemctl says so). `trash` lists the
# entries with their size, account and expiry; site-restore puts everything back, into an empty
# place only; trash-delete removes an entry now; trash-expire removes what trash_keep has aged
# out. The account is never removed.
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/trash.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "trash: needs root; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-trash.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { for b in systemctl; do [ -e /usr/bin/$b.agensio-orig ] && mv -f /usr/bin/$b.agensio-orig /usr/bin/$b; done; [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; sleep 0.3; for u in t1; do pkill -9 -u $u 2>/dev/null; userdel $u 2>/dev/null; done; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
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
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18597"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
A=$T/www/a.test/app; B=$T/www/b.test/app; TR=$T/www/.trash
FAKE=no
if [ -f /.dockerenv ] && [ "$(cat /proc/1/comm)" != systemd ]; then
  FAKE=yes
  [ -e /usr/bin/systemctl ] && [ ! -e /usr/bin/systemctl.agensio-orig ] && mv /usr/bin/systemctl /usr/bin/systemctl.agensio-orig
  cat > /usr/bin/systemctl <<SH
#!/bin/sh
state=\$(cat $T/unit-state 2>/dev/null || echo missing)
for u in "\$@"; do
  case "\$u" in agensio-app-*) ;; *) continue ;; esac
  case "\$state" in
    active) printf 'Id=%s\\nLoadState=loaded\\nActiveState=active\\nSubState=running\\nMainPID=4242\\n\\n' "\$u" ;;
    *) printf 'Id=%s\\nLoadState=not-found\\nActiveState=inactive\\nSubState=dead\\n\\n' "\$u" ;;
  esac
done
SH
  chmod 755 /usr/bin/systemctl
fi

for site in a b; do
  ctl site-create --domain $site.test --app rails --root $T/www/$site.test/app --user t1 --upstream http://127.0.0.1:1850$([ $site = a ] && echo 1 || echo 2) --https none --listen-plain 127.0.0.1:18500 --yes --reason trash > $T/out
done
check "two rails sites on one account, laid out t1" "t1 t1" "$(stat -c %U $A) $(stat -c %U $B)"
# What a site accumulates: files in its directory, the account's gems and its virtualenv, a log
# with a rotation, secrets in its environment.
echo 'gem "rails"' > $A/Gemfile; echo 'gem "rails"' > $B/Gemfile; chown t1:agensio $A/Gemfile $B/Gemfile
mkdir -p $T/state/t1/gems $T/state/t1/venvs/a.test/bin; echo x > $T/state/t1/gems/rails; echo x > $T/state/t1/venvs/a.test/bin/python; chown -R t1:t1 $T/state/t1
mkdir -p $T/logs/sites; for s in a b; do echo 'GET / 502' > $T/logs/sites/$s.test.log; done; echo old > $T/logs/sites/a.test.log.1; chown -R agensio:agensio $T/logs/sites
ctl site-env-set a.test --generate SECRET_KEY_BASE --yes --reason trash > /dev/null
check "the environment file is root's, in root's directory" "root 600" "$(stat -c '%U %a' $T/env/a.test.env)"

if [ $FAKE = yes ]; then
  echo active > $T/unit-state
  check "delete with files while the site's service runs: refused with root's lines; nothing moved" "1 yes yes yes" "$(ctl site-delete a.test --files --yes --reason trash > $T/out; echo -n "$? "; j '"yes" if "systemctl disable --now agensio-app-t1.service" in d["run_as_root"] and "cannot be moved while it runs" in d["error"] else d') $([ -f $A/Gemfile ] && echo yes) $(ctl sites | grep -q '"a.test"' && echo yes)"
  echo missing > $T/unit-state
fi

# Root additions beside the managed file (design section 20): root's alone, moved with the site.
printf 'site = "a.test"\n\n[[location]]\npath = "/ra/"\nadd_headers = { "X-RA" = "1" }\n' > $T/sites.d/a.test.root.toml; chmod 644 $T/sites.d/a.test.root.toml
check "root additions owned by the tenant are refused with the rule (their site set aside: -t --strict fails); root's load, and site shows them after a reload" "1 yes 0 True 1" "$(chown t1 $T/sites.d/a.test.root.toml; "$BIN" -t --strict -c $T/agensio.toml > /dev/null 2> $T/t.err; echo -n "$? "; grep -q 'must belong to the owner of agensio.toml' $T/t.err && echo -n yes; chown root $T/sites.d/a.test.root.toml; "$BIN" -t -c $T/agensio.toml > /dev/null 2>&1; echo -n " $? "; ctl reload --yes --reason ra > /dev/null; ctl site a.test > $T/out; j 'd["root_additions"]["present"], int(d["root_additions"]["locations"])')"
ctl site-auth-user-set a.test anna --generate --yes --reason trash > /dev/null   # its password users (2026-10-09) go with it too
ctl site-delete a.test --files --yes --reason trash > $T/out
E1=$(j 'd["entry"]')
check "the site's users file moved with it, root's 0640 in the entry, so a site created again under the name inherits no users" "yes no root 640" \
  "$([ -f $TR/$E1/auth/a.test.users ] && echo yes) $([ -e $T/auth/a.test.users ] && echo yes || echo no) $(stat -c '%U %a' $TR/$E1/auth/a.test.users)"
check "site-delete --files: ok, an entry <domain>-<date>-<time>, the site gone from the configuration and its file gone" "True yes no no" "$(j 'd["ok"]') $(echo "$E1" | grep -qE '^a\.test-[0-9]{8}-[0-9]{6}$' && echo yes) $(ctl sites | grep -q '"a.test"' && echo yes || echo no) $([ -e $T/sites.d/a.test.toml ] && echo yes || echo no)"
check "the trash and the entry are root's alone (0700); the whole domain directory moved, its files still t1's" "root 700 root 700 no yes t1" "$(stat -c '%U %a' $TR) $(stat -c '%U %a' $TR/$E1) $([ -e $T/www/a.test ] && echo yes || echo no) $([ -f $TR/$E1/site/app/Gemfile ] && echo yes) $(stat -c %U $TR/$E1/site/app/Gemfile)"
check "the account is shared with b.test: its virtualenv moved, its gems stayed; the log with its rotation and the environment file moved" "yes yes yes yes yes no" "$([ -f $TR/$E1/venv/bin/python ] && echo yes) $([ -f $T/state/t1/gems/rails ] && echo yes) $([ -f $TR/$E1/logs/a.test.log ] && echo yes) $([ -f $TR/$E1/logs/a.test.log.1 ] && echo yes) $([ -f $TR/$E1/env/a.test.env ] && echo yes) $([ -e $T/env/a.test.env ] && echo yes || echo no)"
check "the manifest holds the site file's text, the account, the uid; the answer says restore, expiry and that the account is kept and shared" "yes t1 $(id -u t1) yes yes yes" "$(python3 -c "import json; m=json.load(open('$TR/$E1/manifest.json')); print('yes' if 'server_name = [\"a.test\"]' in m['site_file']['text'] else m['site_file'], m['account'], int(m['uid']))") $(j '"yes" if any("site_restore '$E1'" in x for x in d["next_steps"]) else d["next_steps"]') $(j '"yes" if d["expires_at"] and any("removed on" in x for x in d["next_steps"]) else d') $(j '"yes" if any("other sites still use it" in x for x in d["next_steps"]) else d["next_steps"]')"
check "another tenant and the server's own account cannot look into the trash" "no no" "$(su -s /bin/sh agensio -c "ls $TR" > /dev/null 2>&1 && echo yes || echo no) $(su -s /bin/sh t1 -c "ls $TR/$E1" > /dev/null 2>&1 && echo yes || echo no)"
check "trash lists the entry: site, account still in use, size and files, expiry, the pieces' kinds" "1 a.test t1 True yes yes site,venv,log,log,env,auth,root" "$(ctl trash > $T/out; j 'len(d["entries"]), d["entries"][0]["site"], d["entries"][0]["account"], d["entries"][0]["account_in_use"], "yes" if d["entries"][0]["bytes"] > 0 and d["entries"][0]["files"] >= 5 else d["entries"][0], "yes" if d["entries"][0]["expires_at"] and not d["entries"][0]["expired"] else d["entries"][0], ",".join(p["kind"] for p in d["entries"][0]["pieces"])')"
check "the audit log: the delete with every path moved and the account kept" "yes" "$(grep -q "sites/a.test/delete (trash): deleted with its files: $T/www/a.test, $T/state/t1/venvs/a.test, $T/logs/sites/a.test.log.*-> $TR/$E1; the account t1 kept" $T/logs/audit.log && echo yes)"
mkdir -p $T/www/a.test/app; echo new > $T/www/a.test/app/index.html
check "site-restore into a place that is not empty: refused naming it; nothing moved" "1 yes yes" "$(ctl site-restore $E1 --yes --reason trash > $T/out; echo -n "$? "; j '"yes" if "'$T'/www/a.test exists and is not empty" in d["error"] else d') $([ -f $TR/$E1/site/app/Gemfile ] && echo yes)"
rm -rf $T/www/a.test
ctl site-restore $E1 --yes --reason trash > $T/restore.json; cp $T/restore.json $T/out
check "site-restore into an empty place: the directory, the virtualenv, the logs, the environment and the site file back, the site served again; the entry gone" "True t1 yes yes yes yes yes 0" "$(j 'd["ok"]') $(stat -c %U $A/Gemfile) $([ -f $T/state/t1/venvs/a.test/bin/python ] && echo yes) $([ -f $T/logs/sites/a.test.log.1 ] && echo yes) $([ "$(stat -c '%U %a' $T/env/a.test.env)" = 'root 600' ] && echo yes) $([ -f $T/sites.d/a.test.toml ] && [ "$(stat -c %U $T/sites.d/a.test.toml)" = agensio ] && echo yes) $(ctl sites | grep -q '"a.test"' && echo yes) $(ctl trash > $T/out; j 'len(d["entries"])')"
check "the restore's answer says the service must be rendered again; the audit log has the restore" "yes yes" "$(python3 -c "import json; d=json.load(open('$T/restore.json')); print('yes' if any('site_service_unit a.test' in x for x in d['next_steps']) else d['next_steps'])") $(grep -q "trash/$E1/restore (trash): restored a.test: $T/www/a.test" $T/logs/audit.log && echo yes)"
check "the users file came back: root's, the server's group, 0640, and site-auth-users lists anna" "root agensio 640 yes" \
  "$(stat -c '%U %G %a' $T/auth/a.test.users) $(ctl site-auth-users a.test | grep -q '"name":"anna"' && echo yes)"
check "the root additions file came back beside the site file, root's, and the site shows it again" "root 644 True 1" "$(stat -c '%U %a' $T/sites.d/a.test.root.toml) $(ctl site a.test > $T/out; j 'd["root_additions"]["present"], int(d["root_additions"]["locations"])')"
check "restoring an entry that does not exist: 409 naming it" "1 yes" "$(ctl site-restore a.test-20260101-000000 --yes --reason trash > $T/out; echo -n "$? "; j '"yes" if "no trash entry a.test-20260101-000000" in d["error"] else d')"
check "an entry name that is not one: 400 before the helper" "400" "$(curl -sS -o /dev/null -w '%{http_code}' --unix-socket $CS -X POST -d '{"confirm":true}' http://control/v1/trash/evil/restore)"
# The second site goes, then the first: the account's whole state directory moves with the last
# site that used it; both entries name an account no site uses.
ctl site-delete b.test --files --yes --reason trash > $T/out; E2=$(j 'd["entry"]')
ctl site-delete a.test --files --yes --reason trash > $T/out; E3=$(j 'd["entry"]'); cp $T/out $T/del3.json
check "the last site of the account takes the state directory whole; trash shows two entries whose account no site uses; the answer says root may remove it" "no yes yes 2 False False yes" "$([ -e $T/state/t1 ] && echo yes || echo no) $([ -f $TR/$E3/state/gems/rails ] && echo yes) $([ -f $TR/$E3/state/venvs/a.test/bin/python ] && echo yes) $(ctl trash > $T/out; j 'len(d["entries"]), d["entries"][0]["account_in_use"], d["entries"][1]["account_in_use"]') $(grep -q 'root may remove it: userdel t1' $T/del3.json && echo yes || echo no)"
check "the account itself is kept" "yes" "$(id -u t1 > /dev/null 2>&1 && echo yes)"
check "trash-delete removes one entry for good; the other stays" "True 1 $E2" "$(ctl trash-delete $E3 --yes --reason trash > $T/out; j 'd["ok"]') $(ctl trash > $T/out; j 'len(d["entries"]), d["entries"][0]["entry"]')"
python3 - "$TR/$E2/manifest.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["deleted_at"] = "2026-01-01T00:00:00Z"; json.dump(m, open(p, "w"))
PY
check "an entry older than trash_keep shows as expired; trash-expire removes it and nothing else" "True 1 $E2 0" "$(ctl trash > $T/out; j 'd["entries"][0]["expired"]') $(ctl trash-expire --yes --reason trash > $T/out; j 'len(d["removed"]), d["removed"][0]') $(ctl trash > $T/out; j 'len(d["entries"])')"
check "the state directory the entry held is gone with it, in its own trash beside the state directory or the main one" "no no" "$([ -e $TR/$E2 ] && echo yes || echo no) $(ls -d $T/state/.trash/$E2 2>/dev/null | grep -q . && echo yes || echo no)"
check "a site without files (--files absent) still leaves its files and a .bak, as before" "yes yes" "$(ctl site-create --domain c.test --app static --root $T/www/c.test/web --user t1 --https none --listen-plain 127.0.0.1:18500 --yes --reason trash > /dev/null; echo hi > $T/www/c.test/web/index.html; ctl site-delete c.test --yes --reason trash > /dev/null; [ -f $T/www/c.test/web/index.html ] && echo yes) $([ -f $T/sites.d/c.test.toml.bak ] && echo yes)"

echo "trash: $pass passed, $fail failed"
[ "$fail" = 0 ]
