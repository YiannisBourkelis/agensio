#!/usr/bin/env bash
# Site tasks (F13) through the provisioning helper: as root in the devbox, a rails site with
# its own account runs its preset's named tasks as that account, in its directory, with an
# interpreter from a root-owned [control] runtimes directory. The interpreters here are fake
# ruby, gem and bundle scripts that report what they were given and leave files behind, so
# every rule is checked without Ruby: the argv, the account, the directory, the environment,
# the umask, the limits, the output cap, the time limit that kills the process group, what a
# task leaves running, the credential sweep, one task per site, the audit lines, and the
# refusals. tests/rails.sh runs the same tasks with real Ruby and Rails.
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/tasks.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
[ "$(id -u)" = 0 ] || { echo "tasks: needs root; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-tasks.XXXXXX); chmod 755 "$T"
RT=/opt/agensio-tasks-rt   # not below /tmp: every directory above a runtime must be writable by root alone
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; sleep 0.3; for u in r1 r2 r3; do pkill -9 -u $u 2>/dev/null; userdel $u 2>/dev/null; done; rm -rf "$T" "$RT"; }
trap cleanup EXIT
id -u agensio >/dev/null 2>&1 || useradd -r -M -s /usr/sbin/nologin agensio
mkdir -p $T/sites.d $T/logs $T/run $T/state $T/www $T/default $RT; chown agensio:agensio $T/sites.d $T/logs $T/state; chmod 751 $T/state; chmod 755 $RT

# The fake runtime: root's files in a root-owned directory, as [control] runtimes requires.
cat > $RT/ruby <<'SH'
#!/bin/sh
echo "prog=ruby"; echo "args=$*"; echo "uid=$(id -un) cwd=$(pwd) umask=$(umask)"; env | sort | sed 's/^/env: /'
if [ "$2" = new ]; then
  mkdir -p config storage db public bin
  echo secret > config/master.key; chmod 644 config/master.key
  printf 'production:\n  adapter: sqlite3\n' > config/database.yml
  echo "source 'https://rubygems.org'" > Gemfile
  echo '<h1>fake rails</h1>' > public/index.html
  echo 'SECRET=1' > .env
fi
SH
cat > $RT/gem <<'SH'
#!/bin/sh
echo "prog=gem"; echo "args=$*"; echo "uid=$(id -un) GEM_HOME=$GEM_HOME HOME=$HOME TMPDIR=$TMPDIR"
mkdir -p "$GEM_HOME/bin" && echo '# fake rails' > "$GEM_HOME/bin/rails"
SH
cat > $RT/bundle <<'SH'
#!/bin/sh
echo "prog=bundle"; echo "args=$*"
echo "uid=$(id -un) cwd=$(pwd) BUNDLE_PATH=$BUNDLE_PATH BUNDLE_WITHOUT=$BUNDLE_WITHOUT RAILS_ENV=$RAILS_ENV DUMMY=${SECRET_KEY_BASE_DUMMY:-}"
echo "limits=$(awk '/^Max processes/{p=$(NF-2)} /^Max open files/{n=$(NF-2)} /^Max core file size/{c=$(NF-2)} END{print p, n, c}' /proc/self/limits)"
case "$*" in
  "exec rails db:prepare") echo db > storage/production.sqlite3; chmod 644 storage/production.sqlite3 ;;
  "exec rails assets:precompile")
    [ -e slow ] && { echo sleeping; exec sleep 60; }
    [ -e loud ] && { i=0; while [ $i -lt 3000 ]; do echo 0123456789012345678901234567890123456789012345678901234567890123456789; i=$((i+1)); done; }
    [ -e daemon ] && { (sleep 300 &); echo detached; }
    [ -e fail ] && { echo "cannot load such file -- bootsnap" >&2; exit 1; }
    mkdir -p public/assets; echo asset > public/assets/app.css ;;
esac
SH
chmod 755 $RT/ruby $RT/gem $RT/bundle

write_config() {
cat > $T/agensio.toml <<CFG
include = ["sites.d/*.toml"]
[server]
workers = 1
user = "agensio"
pid_file = "$T/agensio.pid"
pools_run = "$T/run"
state_dir = "$T/state"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[control]
socket = "$T/run/control.sock"
audit = "$T/logs/audit.log"
sites_root = "$T/www"
runtimes = { ruby = "$RT" }
task_limits = { timeout = 5, processes = 256 }
$1
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18397"]
root = "$T/default"
CFG
}
write_config ''
# LEAK must never reach a task: the environment is built, not inherited.
start() { LEAK=from-the-server "$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 & for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2; }
stop() { kill "$(cat $T/agensio.pid)" 2>/dev/null; for _ in $(seq 1 50); do [ -S $T/run/control.sock ] || break; sleep 0.1; done; sleep 0.3; }
start
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
APP=$T/www/r1.test/app

out=$(ctl site-create --domain r1.test --app rails --root $APP --user r1 --upstream http://127.0.0.1:18398 --https none --listen-plain 127.0.0.1:18399 --yes --reason tasks)
check "site-create: a rails site with its own account in one call, laid out r1:agensio 2750, no php-fpm pool" "yes r1 agensio 2750 | r1 agensio 2750 no" "$(echo "$out" | grep -q '"ok":true' && echo yes) $(stat -c '%U %G %a' $T/www/r1.test) | $(stat -c '%U %G %a' $APP) $(echo "$out" | grep -q 'php-fpm pool' && echo yes || echo no)"
check "site-tasks lists the preset's six tasks, run as r1 in the app directory" "6 r1 yes" "$(ctl site-tasks r1.test > $T/out; j 'len(d["tasks"]), d["runs_as"], "yes" if d["directory"] == "'$APP'" else d["directory"]')"
ctl site-task r1.test rails_new --param name=blog --dry-run --yes --reason dry > $T/out
check "dry run: the exact argv from the table, as r1 in its directory, the home it would make; nothing created" "$RT/ruby $T/state/r1/gems/bin/rails new . --name=blog r1 $APP $T/state/r1 0 no" "$(j '" ".join(d["argv"][:5]), d["as"], d["cwd"], d["would_create"][0]') $(ls -A $APP | wc -l | tr -d ' ') $([ -e $T/state/r1 ] && echo yes || echo no)"

ctl site-task r1.test gem_install_rails --yes --reason gems > $T/out
check "gem_install_rails: runs gem as r1 into the account's own gem directory; the helper made the home 0700 r1:r1" "True install rails --no-document --version ~> 8.0 | uid=r1 GEM_HOME=$T/state/r1/gems HOME=$T/state/r1 TMPDIR=$T/state/r1/tmp | r1 r1 700 r1 700" "$(j 'd["ok"], " ".join(d["argv"][1:])') | $(j 'd["output"].splitlines()[2]') | $(stat -c '%U %G %a' $T/state/r1) $(stat -c '%U %a' $T/state/r1/tmp)"

ctl site-task r1.test rails_new --param name=blog --yes --reason new > $T/out
check "rails_new: as r1, in the site's directory, umask 0027, from the runtime directory" "True uid=r1 cwd=$APP umask=0027 $RT/ruby" "$(j 'd["ok"], d["output"].splitlines()[2], d["argv"][0]')"
check "rails_new: the environment is exactly the table's; nothing of the server's (LEAK) reaches the task" "HOME LANG PATH PWD BUNDLE_PATH BUNDLE_WITHOUT GEM_HOME RAILS_ENV TMPDIR | no" "$(j '" ".join(sorted(set(l[5:].split("=")[0] for l in d["output"].splitlines() if l.startswith("env: ")) - {"OLDPWD","SHLVL","_"}, key=lambda k: (k not in ("HOME","LANG","PATH","PWD"), k)))') | $(grep -q LEAK $T/out && echo yes || echo no)"
check "rails_new: files belong to r1 with the server's group, served files 0640 and readable by the server" "r1 agensio 640 yes" "$(stat -c '%U %G %a' $APP/public/index.html) $(su -s /bin/sh agensio -c "cat $APP/public/index.html" > /dev/null 2>&1 && echo yes)"
check "rails_new: the credential sweep: master.key, database.yml, .env 0600, storage/ 0710 (the kernel drops set-gid for an account outside the group); the server cannot read the key" "600 600 600 710 no" "$(stat -c %a $APP/config/master.key) $(stat -c %a $APP/config/database.yml) $(stat -c %a $APP/.env) $(stat -c %a $APP/storage) $(su -s /bin/sh agensio -c "cat $APP/config/master.key" > /dev/null 2>&1 && echo yes || echo no)"
check "rails_new: the answer lists what was secured, and the configuration validates" "4 true" "$(j 'len(d["secured"])') $(ctl validate | python3 -c 'import json,sys; print(str(json.load(sys.stdin)["ok"]).lower())')"
check "rails_new a second time: refused, the directory is not empty, nothing ran" "1 yes" "$(ctl site-task r1.test rails_new --param name=blog --yes --reason again > $T/out; echo -n "$? "; grep -q 'creates the application in an empty directory' $T/out && echo yes)"

ctl site-task r1.test bundle_install --yes --reason bundle > $T/out
check "bundle_install: production gems into vendor/bundle, the limits set (processes 256, open files 4096, no core)" "True uid=r1 cwd=$APP BUNDLE_PATH=vendor/bundle BUNDLE_WITHOUT=development:test RAILS_ENV=production DUMMY= | limits=256 4096 0" "$(j 'd["ok"], d["output"].splitlines()[2]') | $(j 'd["output"].splitlines()[3]')"
ctl site-task r1.test db_prepare --yes --reason db > $T/out
check "db_prepare: the SQLite database it made is swept to 0600" "True 600 yes" "$(j 'd["ok"]') $(stat -c %a $APP/storage/production.sqlite3) $(j '"yes" if "'$APP'/storage/production.sqlite3" in d["secured"] else d["secured"]')"
ctl site-task r1.test assets_precompile --yes --reason assets > $T/out
check "assets_precompile: SECRET_KEY_BASE_DUMMY set for it alone; assets written" "True DUMMY=1 yes" "$(j 'd["ok"], d["output"].splitlines()[2].split()[-1]') $([ -f $APP/public/assets/app.css ] && echo yes)"

touch $APP/fail
check "a failing task: 409, the exit status and the program's own words come back" "1 False 1 yes" "$(ctl site-task r1.test assets_precompile --yes --reason fail > $T/out; echo -n "$? "; j 'd["ok"], int(d["exit"]), "yes" if "cannot load such file -- bootsnap" in d["output"] and "exited with status 1" in d["error"] else d')"
rm -f $APP/fail; touch $APP/loud
check "a loud task: the output is cut to its head and tail, the total counted" "True True yes yes" "$(ctl site-task r1.test assets_precompile --yes --reason loud > $T/out; j 'd["ok"], d["truncated"], "yes" if d["output_bytes"] >= 213000 else d["output_bytes"], "yes" if len(d["output"]) < 66000 and "bytes not shown" in d["output"] else len(d["output"])')"
rm -f $APP/loud; touch $APP/daemon
check "a task that leaves a process behind: it is killed with the task's process group" "True 0" "$(ctl site-task r1.test assets_precompile --yes --reason daemon > $T/out; j 'd["ok"]') $(pgrep -u r1 -c sleep || true)"
rm -f $APP/daemon; touch $APP/slow
( ctl site-task r1.test assets_precompile --yes --reason slow > $T/slow.out ) &
SLOW=$!
sleep 1
check "one task per site: a second one while the first runs is refused naming it" "409 yes" "$(curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X POST -d '{"task":"db_migrate","confirm":true}' http://control/v1/sites/r1.test/task) $(grep -q 'already running on this site: assets_precompile' $T/out && echo yes)"
wait $SLOW   # not a bare wait: the server started by start() is a background job of this script too
check "the time limit: SIGTERM to the group at 5 s, a 409 naming the limit, nothing of r1 left running" "True yes 0" "$(python3 -c "import json; d=json.load(open('$T/slow.out')); print(d['timed_out'], 'yes' if 'time limit of 5 s' in d['error'] and 5000 <= d['duration_ms'] < 15000 else d)") $(pgrep -u r1 -c . || true)"
rm -f $APP/slow

chmod 775 $RT
check "a runtime directory another account could write is refused, naming it" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT is writable by its group or by others" $T/out && echo yes)"
chmod 755 $RT; chown nobody $RT/bundle
check "a runtime file root does not own is refused" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT/bundle belongs to nobody, not root" $T/out && echo yes)"
chown root $RT/bundle

out=$(ctl site-create --domain r2.test --app rails --root $T/www/r2.test/app --user r2 --upstream http://127.0.0.1:18400 --https none --listen-plain 127.0.0.1:18399 --yes --reason tasks)
chown root $T/www/r2.test/app
check "a site directory the site's account does not own: refused before anything runs" "1 yes" "$(ctl site-task r2.test gem_install_rails --yes --reason owner > $T/out; echo -n "$? "; grep -q 'belongs to uid 0, not to r2' $T/out && echo yes)"
check "the audit log: each run with the exact argv, the account and the outcome; each refusal with its reason" "yes yes yes" "$(grep -q "sites/r1.test/task (new): ran as r1 in $APP: $RT/ruby $T/state/r1/gems/bin/rails new . --name=blog .* -> exit 0" $T/logs/audit.log && echo yes) $(grep -q "sites/r1.test/task (slow): ran as r1 .* -> stopped at the time limit" $T/logs/audit.log && echo yes) $(grep -q "sites/r2.test/task (owner): refused: .*belongs to uid 0" $T/logs/audit.log && echo yes)"
check "health: no PHP finding and no unreadable-files finding for the rails sites (nothing is served from their root); the site file names app = rails" "no yes" "$(ctl health | grep -q 'php_tmp_missing\|pools_stale\|files_unreadable' && echo yes || echo no) $(grep -q '^app = "rails"' $T/sites.d/r1.test.toml && echo yes)"

stop
write_config 'task_network = false'
start
check "task_network = false: a task that downloads is refused, one that does not still runs" "1 yes 0" "$(ctl site-task r1.test bundle_install --yes --reason net > $T/out; echo -n "$? "; grep -q 'task_network = false' $T/out && echo -n yes; echo -n ' '; ctl site-task r1.test db_migrate --yes --reason net > /dev/null; echo $?)"
stop

echo "tasks: $pass passed, $fail failed"
[ "$fail" = 0 ]
