#!/usr/bin/env bash
# Redmine installed through the control plane alone (2026-09-27 report, "wall 1"): as root in the Ruby
# devbox with access to redmine.org and rubygems.org, a site with app = "redmine" and its
# own account gets Redmine's release archive (site-install --version), its database from
# DATABASE_URL in the site's environment (database_config), Puma through gemfile_local, its
# bundle, schema, default data and assets through site-task; Puma is then started with the
# very unit `agensio ctl site-unit` renders (its Environment lines, its ExecStart, as the
# site's account), and agensio serves Redmine's login page over TLS. Skipped without Ruby or
# the network. Several minutes (gems are compiled).
#   docker run --rm --init --user root --dns-option single-request-reopen --cpuset-cpus=0-3 \
#     -v "$PWD:$PWD" -w "$PWD" agensio-devbox:ruby tests/redmine-install.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
VERSION=${REDMINE_VERSION:-7.0.1}
[ "$(id -u)" = 0 ] || { echo "redmine: needs root; skipped"; exit 0; }
[ -x /usr/bin/ruby ] && [ -x /usr/bin/bundle ] || { echo "redmine: no ruby/bundle in /usr/bin; skipped"; exit 0; }
curl -sSf -o /dev/null --max-time 10 https://www.redmine.org/ || { echo "redmine: redmine.org unreachable; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-redmine.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; pkill -9 -u rm7 2>/dev/null; sleep 0.3; userdel rm7 2>/dev/null; rm -rf "$T"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $T/certs; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=rm7.test -addext subjectAltName=DNS:rm7.test -keyout $T/certs/key.pem -out $T/certs/cert.pem 2>/dev/null
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
task_limits = { timeout = 300 }
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18697"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/rm7.test/app
task() {  # task NAME [--param k=v]: runs it, prints ok exit seconds, keeps the answer in $T/out
    ctl site-task rm7.test "$@" --yes --reason live > $T/out
    cp $T/out $T/out-$1.json
    j 'd["ok"], d.get("exit"), int(d.get("duration_ms", 0) / 1000)'
    python3 -c "import json; d=json.load(open('$T/out')); o=d.get('output', ''); print(d.get('error', '')); print(o if len(o) < 6000 else o[:3000] + '\n[...]\n' + o[-3000:])" > $T/last-$1.txt
}

out=$(ctl site-create --domain rm7.test --app redmine --root $APP --user rm7 --upstream http://127.0.0.1:18607 --cert $T/certs/cert.pem --key $T/certs/key.pem --listen-plain 127.0.0.1:18680 --listen-tls 127.0.0.1:18643 --yes --reason live)
check "site-create: app = redmine with its own account" "yes rm7" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c %U $APP)"
ctl site-install rm7.test --version $VERSION --yes --reason live > $T/out
check "site-install --version: Redmine's release archive from redmine.org, as rm7; facts see Redmine and no database.yml" "True True False" "$(j 'd["ok"], d["facts"]["redmine"], d["facts"]["database_yml"]')"
check "the next steps start with the database, then Redmine's own tasks" "yes" "$(j '"yes" if any("database_config" in x and "gemfile_local" in x and "load_default_data" in x for x in d["next_steps"]) else d["next_steps"]')"
ctl site-env-set rm7.test --set DATABASE_URL=sqlite3:db/production.sqlite3 --yes --reason live > /dev/null
r=$(task database_config); check "database_config: config/database.yml from the fixed template, 0600" "True 600" "$(echo $r | cut -d' ' -f1) $(stat -c %a $APP/config/database.yml)"
r=$(task gemfile_local); check "gemfile_local: Gemfile.local with Puma" "True yes" "$(echo $r | cut -d' ' -f1) $(grep -q '^gem "puma"' $APP/Gemfile.local && echo yes)"
r=$(task bundle_install); check "bundle_install: the bundle with the sqlite3 driver (from DATABASE_URL) and Puma" "True 0 yes yes" "$(echo $r | cut -d' ' -f1-2) $(ls $APP/vendor/bundle/ruby/*/gems | grep -q '^sqlite3-' && echo yes) $(ls $APP/vendor/bundle/ruby/*/gems | grep -q '^puma-' && echo yes)"
echo "     bundle_install took $(echo $r | cut -d' ' -f3) s"
r=$(task db_migrate); check "db_migrate: the production database, 0600" "True 0 600" "$(echo $r | cut -d' ' -f1-2) $(stat -c %a $APP/db/production.sqlite3 2>/dev/null)"
r=$(task load_default_data --param lang=en); check "load_default_data lang=en: trackers, statuses, roles" "True 0" "$(echo $r | cut -d' ' -f1-2)"
r=$(task assets_precompile); check "assets_precompile" "True 0" "$(echo $r | cut -d' ' -f1-2)"
sm() { python3 -c "import json; print(json.load(open('$T/out-$1.json')).get('summary', ''))"; }
check "the answers lead with a summary: the bundle, the migrations applied, the default data, the assets built" "yes yes yes yes" "$(sm bundle_install | grep -q '^Bundle complete!' && echo yes) $(sm db_migrate | grep -q '^[0-9][0-9]* migrations applied$' && echo yes) $([ "$(sm load_default_data)" = 'Default configuration data loaded.' ] && echo yes) $(sm assets_precompile | grep -q '^public/assets holds [1-9][0-9]* files$' && echo yes)"
check "a successful task's answer is short, the whole output stays readable" "yes yes" "$(python3 -c "import json; d=json.load(open('$T/out-bundle_install.json')); print('yes' if len(d['output']) <= 4200 else len(d['output']))") $(ctl site-task-output rm7.test > $T/out; python3 -c "import json; d=json.load(open('$T/out')); print('yes' if d['task'] == 'assets_precompile' and d['kept_all'] else d)")"

# Puma with the unit site-unit renders: its Environment lines, its EnvironmentFile (read as
# root, as systemd does), its WorkingDirectory and ExecStart, as its User.
ctl site-unit rm7.test --raw > $T/unit
wd=$(sed -n 's/^WorkingDirectory=//p' $T/unit); ex=$(sed -n 's/^ExecStart=//p' $T/unit); user=$(sed -n 's/^User=//p' $T/unit)
envs=$(sed -n 's/^Environment=//p' $T/unit | tr '\n' ' ')
envfile=$(sed -n 's/^EnvironmentFile=-//p' $T/unit)
fileenv=$(sed -n 's/^\([A-Z_][A-Z0-9_]*\)="\(.*\)"$/\1=\2/p' "$envfile" | tr '\n' ' ')
check "the rendered unit: rm7, the runtime's bundle, the site's port" "rm7 yes" "$user $(echo "$ex" | grep -q '^/usr/bin/bundle exec puma -e production -b tcp://127.0.0.1:18607$' && echo yes)"
runuser -u "$user" -- /usr/bin/env -i $envs $fileenv /bin/sh -c "cd $wd && umask 027 && exec $ex" > $T/puma.out 2>&1 &
for _ in $(seq 1 100); do curl -s -o /dev/null http://127.0.0.1:18607/login && break; sleep 0.3; done
H="--resolve rm7.test:18643:127.0.0.1 -k"
check "agensio serves Redmine's login page over TLS" "200 yes" "$(curl -sS $H -o $T/login.html -w '%{http_code}' https://rm7.test:18643/login) $(grep -qi 'redmine' $T/login.html && echo yes)"
check "Redmine's database, settings and Gemfile.local are refused at the edge" "404 404 404" "$(curl -sS $H -o /dev/null -w '%{http_code}' https://rm7.test:18643/config/database.yml) $(curl -sS $H -o /dev/null -w '%{http_code}' https://rm7.test:18643/db/production.sqlite3) $(curl -sS $H -o /dev/null -w '%{http_code}' https://rm7.test:18643/Gemfile.local)"
check "every task and template is in the audit log" "6" "$(grep -c 'sites/rm7.test/task (live): \(ran as rm7 .* -> exit 0\|wrote \)' $T/logs/audit.log)"

echo "redmine: $pass passed, $fail failed"
if [ "$fail" != 0 ]; then
    for f in $T/last-*.txt; do echo "--- $f"; head -30 "$f"; echo "..."; tail -10 "$f"; done
    echo "--- puma"; tail -40 $T/puma.out
fi
[ "$fail" = 0 ]
