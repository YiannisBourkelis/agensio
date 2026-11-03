#!/usr/bin/env bash
# The site's files (F12, docs/design-site-operations.md 3 and 27.6) through the provisioning helper as
# root in the devbox: two static sites on two accounts (t1, t2). Every change waits for a person's
# approval and is approved with the code an authenticator app would show (tests/approve-code.py over
# root's approver); the account's part runs as the site's account (the file is the account's, the
# directory's mode), the history is root's alone (<sites_root>/.history, 0700: neither account nor the
# server's own can look in), a symlink an account planted toward another account's site is refused, a
# directory another account owns is refused, a credential file is made 0600, a deleted directory goes
# into the history whole and comes back the account's.
#   docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/files.sh build/agensio
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "files: needs root; skipped"; exit 0; }
T=$(mktemp -d /tmp/agensio-files.XXXXXX); chmod 755 "$T"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() { [ -f "$T/agensio.pid" ] && kill "$(cat "$T/agensio.pid")" 2>/dev/null; sleep 0.3; for u in t1 t2; do pkill -9 -u $u 2>/dev/null; userdel $u 2>/dev/null; done; rm -rf "$T"; }
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
file_history = { versions = 2, days = 30 }
[[site]]
server_name = ["*"]
listen = ["127.0.0.1:18611"]
root = "$T/default"
CFG
"$BIN" -c $T/agensio.toml >> $T/server.out 2>&1 &
for _ in $(seq 1 50); do [ -S $T/run/control.sock ] && break; sleep 0.1; done; sleep 0.2
CS=$T/run/control.sock
ctl() { "$BIN" ctl "$@" --socket $CS < /dev/null; }
j() { python3 -c "import json,sys; d=json.load(open('$T/out')); print($1)"; }
"$BIN" approver-add suite -c $T/agensio.toml > /dev/null
approve() { python3 "$HERE/approve-code.py" --raw $CS $T/agensio.toml "$BIN" "$@"; }
api() { curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS -X "$1" -H 'Content-Type: application/json' -d "$3" "http://control$2"; }
A=$T/www/a.test/web; B=$T/www/b.test/web; H=$T/www/.history

for s in a:t1 b:t2; do
  ctl site-create --domain ${s%%:*}.test --app static --root $T/www/${s%%:*}.test/web --user ${s##*:} --https none --listen-plain 127.0.0.1:18611 --yes --reason files > $T/out
done
check "two static sites on two accounts, laid out by the helper" "t1 t2" "$(stat -c %U $A) $(stat -c %U $B)"
check "the approver file is root's alone" "root 600 root 700" "$(stat -c '%U %a' $T/approvers/suite.totp) $(stat -c '%U %a' $T/approvers)"

printf '<html><head><title>A</title></head>\n<body>hello</body></html>\n' > $T/page.html
ctl site-file-write a.test index.html $T/page.html --yes --reason "the home page" > $T/out
check "a write through ctl without a terminal waits: pending, the server's preview with the verdict and the new text; nothing written" "True yes no" \
  "$(j 'd["pending"]') $(j '"yes" if "served as a file once written" in d["preview"] and "+<html><head><title>A</title>" in d["preview"] else d["preview"]') $([ -e $A/index.html ] && echo yes || echo no)"
approve > $T/approved
check "approved with root's approver: written as t1 with the directory's pattern, served, the audit line naming the approver" "t1 640 yes yes" \
  "$(stat -c '%U %a' $A/index.html) $(curl -sS -H 'Host: a.test' http://127.0.0.1:18611/ | grep -q '<title>A</title>' && echo yes) $(grep -q 'sites/a.test/file (the home page): write .*index.html (sha256 ' $T/logs/audit.log && grep -q 'approved by suite' $T/logs/audit.log && echo yes)"

# A dry run answers the change as the person will see it, the diff against the file there, and what the
# site does with the path; never the texts whole (the alpha.120 report, problem D: a one-word edit's
# answer carried the file twice), and queues nothing.
ctl site-file-edit a.test index.html --old '<body>hello</body>' --new '<body>hi</body>' --dry-run --yes --reason "a word" > $T/out
check "an edit's dry run: the diff (the line gone, the one in its place), the verdict, needs_approval, no whole texts, nothing queued, nothing written" "yes 200: yes no 0 hello" \
  "$(j '"yes" if "-<body>hello</body>" in d["diff"] and "+<body>hi</body>" in d["diff"] else d') $(j 'd["site_does"][:4]') $(j '"yes" if d.get("needs_approval") else "no"') $(j '"yes" if "new_text" in d or "text" in d["current"] else "no"') $(curl -sS --unix-socket $CS http://control/v1/approvals | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["waiting"]))') $(grep -o 'hello\|hi' $A/index.html)"
# A change to the page: the history keeps the one before, root's alone; the link keeps t1's ownership.
printf '<html><head><title>A2</title></head>\n<body>hello</body></html>\n' > $T/page2.html
ctl site-file-write a.test index.html $T/page2.html --overwrite --yes --reason "v2" > /dev/null; approve > /dev/null
ctl site-file-history a.test index.html > $T/out
V1=$(j 'd["versions"][0]["version"]')
check "the history: root's 0700 at every level, one version of the page kept by hard link (still t1's), neither account nor the server's own can look in" "root 700 root 700 1 t1 no no no" \
  "$(stat -c '%U %a' $H) $(stat -c '%U %a' $H/a.test) $(j 'len(d["versions"])') $(stat -c %U $H/a.test/$V1/item) $(su -s /bin/sh t1 -c "ls $H" > /dev/null 2>&1 && echo yes || echo no) $(su -s /bin/sh t2 -c "ls $H/a.test" > /dev/null 2>&1 && echo yes || echo no) $(su -s /bin/sh agensio -c "ls $H" > /dev/null 2>&1 && echo yes || echo no)"

# t1 plants a symlink toward t2's site: a write through it is refused before anything waits, and
# nothing lands in b.test; a directory t2 owns inside a.test is refused as another account's.
su -s /bin/sh t1 -c "ln -s $B $A/other"
mkdir $A/t2dir; chown t2:t2 $A/t2dir
check "a planted symlink toward another account's site, and a directory another account owns: refused, nothing written" "409 yes no 409 yes" \
  "$(api POST /v1/sites/a.test/file '{"op":"write","path":"other/index.html","content":"x","confirm":true,"reason":"x"}') $(grep -q symlink $T/out && echo yes) $([ -e $B/index.html ] && echo yes || echo no) $(api POST /v1/sites/a.test/file '{"op":"write","path":"t2dir/x","content":"x","confirm":true,"reason":"x"}') $(grep -q 'another account' $T/out && echo yes)"
check "a path that climbs out, and a listing that shows the symlink without following it" "400 symlink yes" \
  "$(api POST /v1/sites/a.test/file '{"op":"write","path":"../b.test/web/x","content":"x","confirm":true}') $(ctl site-files a.test > $T/out; j '[e for e in d["entries"] if e["name"] == "other"][0]["type"]') $(j '"yes" if [e for e in d["entries"] if e["name"] == "other"][0]["target"] == "'$B'" else d')"

# A credential file: written 0600 as t1; its read waits, and the content is handed out once by id.
printf 'API_TOKEN=t0ps3cret\n' > $T/env
ctl site-file-write a.test .env $T/env --yes --reason "token" > /dev/null; approve > /dev/null
check "a credential file is t1's, 0600" "t1 600" "$(stat -c '%U %a' $A/.env)"
ctl site-file-read a.test .env > $T/out
SID=$(j 'd["id"]')
check "its read waits, naming it; approved, the list never carries the content and GET by id hands it out once" "True yes no yes no" \
  "$(j 'd["pending"]') $(j '"yes" if "credential" in d["needs_approval"][0] else d') $(approve $SID > $T/ap; grep -q t0ps3cret $T/ap && echo yes || echo no) $(curl -sS --unix-socket $CS http://control/v1/approvals/$SID | grep -q 'API_TOKEN=t0ps3cret' && echo yes) $(curl -sS --unix-socket $CS http://control/v1/approvals/$SID | grep -q t0ps3cret && echo yes || echo no)"

# A directory deleted into the history whole (a rename by root), its files still t1's; restored, t1's.
mkdir -p $A/old; echo a > $A/old/a.txt; chown -R t1:t1 $A/old
ctl site-path-delete a.test old --recursive --yes --reason "old" > /dev/null; approve > /dev/null
ctl site-file-history a.test old > $T/out
DV=$(j 'd["versions"][0]["version"]')
check "deleted into the history whole: gone from the site, a directory version, its file still t1's inside root's version" "no directory t1" "$([ -e $A/old ] && echo yes || echo no) $(j 'd["versions"][0]["kind"]') $(stat -c %U $H/a.test/$DV/item/a.txt)"
ctl site-file-restore a.test old $DV --yes --reason back > /dev/null; approve > /dev/null
check "restored: back in the site, t1's, the version gone from the history" "a t1 0" "$(cat $A/old/a.txt) $(stat -c %U $A/old) $(ctl site-file-history a.test old > $T/out; j 'len(d["versions"])')"

# The second site's account does its own: b.test's write is t2's, and nothing of it touches a.test.
printf 'b\n' > $T/b.txt
ctl site-file-write b.test index.html $T/b.txt --yes --reason b > /dev/null; approve > /dev/null
check "b.test's file is t2's; the history keeps the sites apart" "t2 yes no" "$(stat -c %U $B/index.html) $([ -d $H/a.test ] && echo yes) $([ -d $H/b.test ] && echo yes || echo no)"

# file_history.versions = 2: two more writes of the page keep the two newest versions, the oldest going
# only once each write succeeded.
for v in 3 4; do printf "<html><title>A$v</title></html>\n" > $T/page$v.html; ctl site-file-write a.test index.html $T/page$v.html --overwrite --yes --reason "v$v" > /dev/null; approve > /dev/null; done
check "the versions kept are capped at file_history.versions, the newest first" "2 replaced by a write" "$(ctl site-file-history a.test index.html > $T/out; j 'len(d["versions"])') $(j 'd["versions"][0]["reason"]')"
echo "files: $pass passed, $fail failed"
[ $fail = 0 ]
