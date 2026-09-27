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
# the version query of an install (install::app_facts): what the Ruby of [control] runtimes is
[ "$1" = "-e" ] && [ "$2" = "print RUBY_VERSION" ] && { printf '%s' "$(cat /opt/agensio-tasks-rt/version 2>/dev/null || echo 3.4.7)"; exit 0; }
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
echo "prog=gem"; echo "args=$*"; echo "uid=$(id -un) GEM_HOME=$GEM_HOME GEM_PATH=$GEM_PATH HOME=$HOME TMPDIR=$TMPDIR"
[ -e "$HOME/no-binstub" ] && { echo "1 gem installed"; exit 0; }   # what a host-wide Rails made gem do before GEM_PATH was isolated
mkdir -p "$GEM_HOME/bin" && echo '# fake rails' > "$GEM_HOME/bin/rails"
SH
cat > $RT/bundle <<'SH'
#!/bin/sh
echo "prog=bundle"; echo "args=$*"
echo "uid=$(id -un) cwd=$(pwd) BUNDLE_PATH=$BUNDLE_PATH BUNDLE_WITHOUT=$BUNDLE_WITHOUT RAILS_ENV=$RAILS_ENV DUMMY=${SECRET_KEY_BASE_DUMMY:-}"
echo "limits=$(awk '/^Max processes/{p=$(NF-2)} /^Max open files/{n=$(NF-2)} /^Max core file size/{c=$(NF-2)} END{print p, n, c}' /proc/self/limits)"
echo "appenv SECRET_KEY_BASE=${SECRET_KEY_BASE:-} DATABASE_URL=${DATABASE_URL:-}"
[ -e nosecret ] && [ -z "${SECRET_KEY_BASE:-}" ] && [ "$*" = "exec rails db:migrate" ] && { echo "ArgumentError: Missing \`secret_key_base\` for 'production' environment, set this string with \`bin/rails credentials:edit\`" >&2; exit 1; }
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
check "site-tasks: every interpreter accepted, the effective time limit (the rows' capped at task_limits' 5 s), nothing for root" "True True 5 5 False" "$(j 'all(t["interpreter"]["ok"] for t in d["tasks"]), d["tasks"][1]["interpreter"]["program"] == "'$RT'/ruby", int(d["tasks"][1]["timeout"]), int(d["tasks"][3]["timeout"]), "run_as_root" in d')"
ctl site-task r1.test gem_install_rails --dry-run --yes --reason dry > $T/out
check "dry run: the exact argv from the table, as r1 in its directory, the home it would make; nothing created" "$RT/gem install rails --no-document r1 $APP $T/state/r1 0 no" "$(j '" ".join(d["argv"][:4]), d["as"], d["cwd"], d["would_create"][0]') $(ls -A $APP | wc -l | tr -d ' ') $([ -e $T/state/r1 ] && echo yes || echo no)"
check "dry run of rails_new before gem_install_rails: refused as the real run would be, naming the missing rails command and the task to run" "1 yes" "$(ctl site-task r1.test rails_new --param name=blog --dry-run --yes --reason dry > $T/out; echo -n "$? "; grep -q "needs $T/state/r1/gems/bin/rails, which does not exist; run gem_install_rails first" $T/out && echo yes)"

ctl site-task r1.test gem_install_rails --yes --reason gems > $T/out
check "gem_install_rails: runs gem as r1 into the account's own gem directory, GEM_PATH isolated to it; the helper made the home 0700 r1:r1" "True install rails --no-document --version ~> 8.0 | uid=r1 GEM_HOME=$T/state/r1/gems GEM_PATH=$T/state/r1/gems HOME=$T/state/r1 TMPDIR=$T/state/r1/tmp | r1 r1 700 r1 700" "$(j 'd["ok"], " ".join(d["argv"][1:])') | $(j 'd["output"].splitlines()[2]') | $(stat -c '%U %G %a' $T/state/r1) $(stat -c '%U %a' $T/state/r1/tmp)"

ctl site-task r1.test rails_new --param name=blog --yes --reason new > $T/out
check "rails_new: as r1, in the site's directory, umask 0027, from the runtime directory" "True uid=r1 cwd=$APP umask=0027 $RT/ruby" "$(j 'd["ok"], d["output"].splitlines()[2], d["argv"][0]')"
check "rails_new: the environment is exactly the table's; nothing of the server's (LEAK) reaches the task" "HOME LANG PATH PWD BUNDLE_PATH BUNDLE_WITHOUT GEM_HOME GEM_PATH RAILS_ENV TMPDIR | no" "$(j '" ".join(sorted(set(l[5:].split("=")[0] for l in d["output"].splitlines() if l.startswith("env: ")) - {"OLDPWD","SHLVL","_"}, key=lambda k: (k not in ("HOME","LANG","PATH","PWD"), k)))') | $(grep -q LEAK $T/out && echo yes || echo no)"
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

# The site's environment (2026-09-27 Writebook report): a root file the tasks read, admin only.
touch $APP/nosecret
check "a task that stops on Rails' missing secret_key_base: 409 with the hint to generate one" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason nosecret > $T/out; echo -n "$? "; j '"yes" if "generate: [\"SECRET_KEY_BASE\"]" in d.get("hint", "") else d.get("hint")')"
ctl site-env-set r1.test --set DATABASE_URL=sqlite3:storage/x.sqlite3 --generate SECRET_KEY_BASE --yes --reason env > $T/out
check "site-env-set: DATABASE_URL set, SECRET_KEY_BASE generated; root's file 0600 in root's 0700 directory; no value in the answer or the audit log" "True DATABASE_URL SECRET_KEY_BASE root 600 root 700 no no" "$(j 'd["ok"], ",".join(d["set"]), ",".join(d["generated"])') $(stat -c '%U %a' $T/env/r1.test.env) $(stat -c '%U %a' $T/env) $(grep -q 'sqlite3:storage' $T/out && echo yes || echo no) $(grep -q 'sqlite3:storage' $T/logs/audit.log && echo yes || echo no)"
SKB=$(sed -n 's/^SECRET_KEY_BASE="\(.*\)"$/\1/p' $T/env/r1.test.env)
ctl site-task r1.test db_migrate --yes --reason withsecret > $T/out
check "the task gets the site's environment; its answer names the variables and shows no value" "True 128 yes sqlite3:storage/x.sqlite3 yes" "$(j 'd["ok"]') $(echo -n "$SKB" | wc -c | tr -d ' ') $(j '"yes" if "SECRET_KEY_BASE='$SKB'" in d["output"] else "no"') $(j '[l for l in d["output"].splitlines() if l.startswith("appenv")][0].split("DATABASE_URL=")[1]') $(j '"yes" if "SECRET_KEY_BASE=<site environment>" in d["env"] and not any("'$SKB'" in e for e in d["env"]) else d["env"]')"
check "site-env: names, lengths and fingerprints, no value; audited with the names" "DATABASE_URL,SECRET_KEY_BASE 128 16 False no yes" "$(ctl site-env r1.test > $T/out; j '",".join(v["name"] for v in d["variables"]), int(d["variables"][1]["length"]), len(d["variables"][1]["fingerprint"]), "value" in d["variables"][1]') $(grep -q "$SKB" $T/out && echo yes || echo no) $(grep -q 'sites/r1.test/env: read the names of DATABASE_URL, SECRET_KEY_BASE$' $T/logs/audit.log && echo yes)"
check "site-env --reveal: that one value, audited as REVEALED, never the value in the audit log" "yes False yes no" "$(ctl site-env r1.test --reveal SECRET_KEY_BASE > $T/out; j '"yes" if d["variables"][1]["value"] == "'$SKB'" else d') $(j '"value" in d["variables"][0]') $(grep -q 'env: read the names of DATABASE_URL, SECRET_KEY_BASE; REVEALED the value of SECRET_KEY_BASE' $T/logs/audit.log && echo yes) $(grep -q "$SKB" $T/logs/audit.log && echo yes || echo no)"
check "generate keeps an existing secret; unset and generate in one call rotate it" "SECRET_KEY_BASE yes" "$(ctl site-env-set r1.test --generate SECRET_KEY_BASE --yes --reason keep > $T/out; j '",".join(d["kept"])') $(ctl site-env-set r1.test --unset SECRET_KEY_BASE --generate SECRET_KEY_BASE --yes --reason rotate > /dev/null; [ "$(sed -n 's/^SECRET_KEY_BASE="\(.*\)"$/\1/p' $T/env/r1.test.env)" != "$SKB" ] && echo yes)"
check "site-env-set refuses a name that changes what runs" "1 yes" "$(ctl site-env-set r1.test --set LD_PRELOAD=/tmp/x.so --yes --reason bad > $T/out; echo -n "$? "; grep -q 'LD_PRELOAD is agensio' $T/out && echo yes)"
chmod 664 $T/env/r1.test.env
check "an environment file others could write: the task is refused naming it, with the root command; nothing runs" "1 yes yes" "$(ctl site-task r1.test db_migrate --yes --reason unsafe > $T/out; echo -n "$? "; grep -q "r1.test.env must be a regular file with one link, root's, mode 0600" $T/out && echo -n yes; echo -n ' '; j '"yes" if "chmod 0600" in d["run_as_root"][0] else d')"
check "health sees that file through the helper, though the directory is right: site_env_unsafe for r1.test with the chmod line" "yes yes" "$(ctl health > $T/out; j '"yes" if any(f["code"] == "site_env_unsafe" and f.get("site") == "r1.test" and "chmod 0600" in f.get("fix", "") for f in d["findings"]) else d["findings"]') $([ "$(stat -c %a $T/env)" = 700 ] && echo yes)"
chmod 644 $T/env/r1.test.env
check "a file others could only read is made 0600 by the helper, and the task says so; no rotation advice under a 0700 directory" "True 600 yes" "$(ctl site-task r1.test db_migrate --yes --reason readable > $T/out; j 'd["ok"]') $(stat -c %a $T/env/r1.test.env) $(j '"yes" if "made 0600" in d["tightened"][0] and "nothing to rotate" in d["tightened"][0] else d.get("tightened")')"
chmod 775 $T/env   # the 2026-09-27 report: a mkdir -p under a lax umask
check "health names an environment directory open to others; the next task tightens it and says so" "yes True 700 yes" "$(ctl health | grep -q site_env_unsafe && echo yes) $(ctl site-task r1.test db_migrate --yes --reason dir775 > $T/out; j 'd["ok"]') $(stat -c %a $T/env) $(j '"yes" if "made 0700" in " ".join(d["tightened"]) else d.get("tightened")')"
rm -f $APP/nosecret

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
touch $T/state/r1/no-binstub; rm -f $T/state/r1/gems/bin/rails
check "gem_install_rails that exits 0 without the rails command: 409 naming what is missing, not ok" "1 False yes" "$(ctl site-task r1.test gem_install_rails --yes --reason nobin > $T/out; echo -n "$? "; j 'd["ok"], "yes" if "exited 0, but '$T'/state/r1/gems/bin/rails does not exist" in d["error"] else d["error"]')"
rm -f $T/state/r1/no-binstub
check "run again, it leaves the command behind and answers ok" "True" "$(ctl site-task r1.test gem_install_rails --yes --reason again > $T/out; j 'd["ok"]')"

chmod 775 $RT
check "a runtime directory another account could write is refused, naming it" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT is writable by its group or by others" $T/out && echo yes)"
chmod 755 $RT; chown nobody $RT/bundle
check "a runtime file root does not own is refused" "1 yes" "$(ctl site-task r1.test db_migrate --yes --reason rt > $T/out; echo -n "$? "; grep -q "$RT/bundle belongs to nobody, not root" $T/out && echo yes)"
chown root $RT/bundle

out=$(ctl site-create --domain r2.test --app rails --root $T/www/r2.test/app --user r2 --upstream http://127.0.0.1:18400 --https none --listen-plain 127.0.0.1:18399 --yes --reason tasks)
check "db_prepare in a directory with no application: refused before anything runs, dry run or not" "1 1 yes" "$(ctl site-task r2.test db_prepare --dry-run --yes --reason noapp > /dev/null; echo -n "$? "; ctl site-task r2.test db_prepare --yes --reason noapp > $T/out; echo -n "$? "; grep -q "needs $T/www/r2.test/app/Gemfile, which does not exist; the site's directory holds no application yet" $T/out && echo yes)"
# An application from an archive that came without Rails credentials (Writebook): the
# install generates its SECRET_KEY_BASE and names the steps that fit it.
mkdir -p $T/wb/writebook-1.2.2/config && echo "source 'https://rubygems.org'" > $T/wb/writebook-1.2.2/Gemfile && echo 3.4.7 > $T/wb/writebook-1.2.2/.ruby-version && echo x > $T/wb/writebook-1.2.2/config/application.rb
tar -C $T/wb -cf $T/wb.tar writebook-1.2.2
ctl upload wb.tar $T/wb.tar > /dev/null
echo 3.3.8 > $RT/version   # the runtime's Ruby, as the fake reports it: not the pinned one
ctl site-install r2.test --file wb.tar --yes --reason archive > $T/out
rm -f $RT/version
check "site-install of a Rails archive without credentials: SECRET_KEY_BASE generated into the site's environment; next steps name the pinned Ruby against the runtime's (3.3.8 here), the bundle tasks and the body limit" "yes yes yes yes 600" "$(j '"yes" if any("SECRET_KEY_BASE generated" in x for x in d.get("done", [])) else d') $(j '"yes" if any("pins Ruby 3.4.7 (.ruby-version), but the Ruby of [control] runtimes ('$RT') is 3.3.8" in x for x in d["next_steps"]) else d["next_steps"]') $(j '"yes" if any(x.startswith("site_task bundle_install") for x in d["next_steps"]) else d["next_steps"]') $(j '"yes" if any("up to 1MB, the server" in x for x in d["next_steps"]) else d["next_steps"]') $(stat -c %a $T/env/r2.test.env)"
check "site-update of a site that holds an application: the next steps are the bundle tasks, not rails_new" "yes no" "$(ctl site-update r2.test --upstream http://127.0.0.1:18401 --yes --reason next > $T/out; j '"yes" if any("in place: site-task r2.test bundle_install" in x for x in d["next_steps"]) else d["next_steps"]') $(grep -q rails_new $T/out && echo yes || echo no)"
chown root $T/www/r2.test/app
check "a site directory the site's account does not own: refused before anything runs" "1 yes" "$(ctl site-task r2.test gem_install_rails --yes --reason owner > $T/out; echo -n "$? "; grep -q 'belongs to uid 0, not to r2' $T/out && echo yes)"
check "the audit log: each run with the exact argv, the account and the outcome; each refusal with its reason" "yes yes yes" "$(grep -q "sites/r1.test/task (new): ran as r1 in $APP: $RT/ruby $T/state/r1/gems/bin/rails new . --name=blog .* -> exit 0" $T/logs/audit.log && echo yes) $(grep -q "sites/r1.test/task (slow): ran as r1 .* -> stopped at the time limit" $T/logs/audit.log && echo yes) $(grep -q "sites/r2.test/task (owner): refused: .*belongs to uid 0" $T/logs/audit.log && echo yes)"
check "site-delete of a rails site names the environment file it keeps, with the root line that removes it" "yes yes yes" "$(ctl site-delete r2.test --yes --reason gone > $T/out; j '"yes" if "'$T'/env/r2.test.env" in d["kept"][0] else d') $(j '"yes" if d["run_as_root"] == ["rm -f '$T'/env/r2.test.env"] else d') $([ -f $T/env/r2.test.env ] && echo yes)"
check "health names the deleted site's environment file as an orphan, with the rm line" "yes" "$(ctl health > $T/out; j '"yes" if any(f["code"] == "site_env_orphan" and "r2.test.env" in f["message"] and "rm -f" in f.get("fix", "") for f in d["findings"]) else [f for f in d["findings"] if f["code"].startswith("site_env")]')"
check "unsetting every variable removes the file and the answer says so" "yes no" "$(ctl site-env-set r1.test --unset DATABASE_URL --unset SECRET_KEY_BASE --yes --reason empty > $T/out; j '"yes" if d["removed"].endswith("r1.test.env") and "no variables left" in d["done"][0] else d') $([ -e $T/env/r1.test.env ] && echo yes || echo no)"
check "health: no PHP finding and no unreadable-files finding for the rails sites (nothing is served from their root); the site file names app = rails" "no yes" "$(ctl health | grep -q 'php_tmp_missing\|pools_stale\|files_unreadable' && echo yes || echo no) $(grep -q '^app = "rails"' $T/sites.d/r1.test.toml && echo yes)"

stop
write_config 'task_network = false'
start
check "task_network = false: a task that downloads is refused, one that does not still runs" "1 yes 0" "$(ctl site-task r1.test bundle_install --yes --reason net > $T/out; echo -n "$? "; grep -q 'task_network = false' $T/out && echo -n yes; echo -n ' '; ctl site-task r1.test db_migrate --yes --reason net > /dev/null; echo $?)"
stop

echo "tasks: $pass passed, $fail failed"
[ "$fail" = 0 ]
