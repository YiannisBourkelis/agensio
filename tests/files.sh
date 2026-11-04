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
# A write of the text the file already holds changes nothing and waits for nobody (the alpha.121 report).
ctl site-file-write a.test index.html $T/page.html --overwrite --yes --reason "same" > $T/out
check "a write of the file's own text: unchanged, no diff, not pending, nothing queued, the file untouched" "True no change yes 0 hello" \
  "$(j 'd["unchanged"]') $(j 'd["diff"].strip()') $(j '"yes" if not d.get("pending") and not d.get("needs_approval") else d') $(curl -sS --unix-socket $CS http://control/v1/approvals | python3 -c 'import json,sys; print(int(json.load(sys.stdin)["waiting"]))') $(grep -o 'hello' $A/index.html)"
# A private key under a name no rule knows (2026-11-04, the grabloop.app report: shared/deploy_key was
# read with no approval): written 0600 with a preview of lengths only; its first read answers nothing of
# it and remembers it, the next waits for approval and is handed out once.
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAkeymaterial\n-----END OPENSSH PRIVATE KEY-----\n' > $T/key
ctl site-file-write a.test deploy_key $T/key --yes --reason "deploy key" > $T/out
check "a key's write waits with a preview of lengths only, no line of the key" "True no" "$(j 'd["pending"]') $(grep -q 'keymaterial\|BEGIN OPENSSH' $T/out && echo yes || echo no)"
approve > $T/ap
check "approved: the key is t1's and 0600, and the approval's answer carries none of it" "t1 600 no" "$(stat -c '%U %a' $A/deploy_key) $(grep -q 'keymaterial' $T/ap && echo yes || echo no)"
check "its first read answers nothing of it: 409, a private key by its first line" "409 no yes" \
  "$(curl -sS -o $T/out -w '%{http_code}' --unix-socket $CS 'http://control/v1/sites/a.test/files?path=deploy_key&read=1') $(grep -q 'keymaterial' $T/out && echo yes || echo no) $(grep -q 'private key' $T/out && echo yes)"
ctl site-file-read a.test deploy_key > $T/out
KID=$(j 'd["id"]')
check "the next read waits for approval; approved, the list never carries it and GET by id hands it out once" "True yes no yes no" \
  "$(j 'd["pending"]') $(j '"yes" if d.get("needs_approval") else d') $(approve $KID > $T/ap; grep -q keymaterial $T/ap && echo yes || echo no) $(curl -sS --unix-socket $CS http://control/v1/approvals/$KID | grep -q keymaterial && echo yes) $(curl -sS --unix-socket $CS http://control/v1/approvals/$KID | grep -q keymaterial && echo yes || echo no)"
# A secret goes to the account that asked for it (security page row 56): another admin account that reads
# the id in the list gets a note and an audit line, and the requester still gets it, once (the alpha.127
# report's open question: until then any admin account took it).
ctl site-file-read a.test deploy_key > $T/out
OID=$(j 'd["id"]')
approve $OID > /dev/null
check "a secret is handed out to the account that asked: another admin account (the server's) gets a note and is audited, the requester gets the content" "no yes yes yes" \
  "$(su -s /bin/sh agensio -c "curl -sS --unix-socket $CS http://control/v1/approvals/$OID" > $T/other; grep -q keymaterial $T/other && echo yes || echo no) $(grep -q 'to the account that asked for it (uid 0)' $T/other && echo yes) $(grep -q "approvals/$OID: secret not handed out: uid 0 asked for it" $T/logs/audit.log && echo yes) $(curl -sS --unix-socket $CS http://control/v1/approvals/$OID | grep -q keymaterial && echo yes)"
# An approved batch stops at its first failure (the grabloop.app answer: a deploy queues the install, the
# switch and the deletes together, and a failed install must not be followed by the switch). The write
# is bound to its file being absent; the file appears before the approval, so the write fails, and the
# directory queued after it is not made.
printf 'late\n' > $T/late.txt
ctl site-file-write a.test late.txt $T/late.txt --yes --reason "first" > $T/out; W1=$(j 'd["id"]')
ctl site-dir-create a.test after-the-failure --yes --reason "second" > $T/out; W2=$(j 'd["id"]')
su -s /bin/sh t1 -c "echo meanwhile > $A/late.txt"
approve $W1 $W2 > $T/ap
check "a batch stops at its first failure: the first failed, the second not run and said so, nothing of it made" "failed skipped yes no" \
  "$(python3 -c "import json; r={x['id']:x for x in json.load(open('$T/ap'))['results']}; print(r['$W1']['state'], r['$W2']['state'], 'yes' if '$W1' in json.dumps(r['$W2'].get('result', {})) else r['$W2'])") $([ -d $A/after-the-failure ] && echo yes || echo no)"
rm -f $A/late.txt
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
# No value of a credential file leaves the server through a preview, a dry run or a result (the
# grabloop.app report: an edit's diff showed DB_PASSWORD from its context lines, and an approved write
# answered the previous file whole, which approvals_list hands to any admin client).
printf 'APP_DEBUG=false\nDB_PASSWORD=dbs3cr3t\n' > $T/env2
ctl site-file-write a.test .env.app $T/env2 --yes --reason "app env" > $T/out
check "a credential file's write waits with a preview of names and lengths, no value" "True yes no" \
  "$(j 'd["pending"]') $(j '"yes" if "DB_PASSWORD=<8 bytes>" in d["preview"] else d["preview"]') $(grep -q 'dbs3cr3t\|false' $T/out && echo yes || echo no)"
approve > $T/ap
check "approved: written, and neither the approval's answer nor the list carries a value" "dbs3cr3t no no" \
  "$(grep -o dbs3cr3t $A/.env.app) $(grep -q dbs3cr3t $T/ap && echo yes || echo no) $(curl -sS --unix-socket $CS http://control/v1/approvals | grep -q dbs3cr3t && echo yes || echo no)"
ctl site-file-edit a.test .env.app --old 'APP_DEBUG=false' --new 'APP_DEBUG=true' --dry-run > $T/out
check "an edit's dry run of a credential file: the changed line by name and length, the context masked, no value, no text whole" "yes no no" \
  "$(j '"yes" if "-APP_DEBUG=<5 bytes>" in d["diff"] and "+APP_DEBUG=<4 bytes>" in d["diff"] and " DB_PASSWORD=<8 bytes>" in d["diff"] else d["diff"]') $(grep -q 'dbs3cr3t' $T/out && echo yes || echo no) $(j '"yes" if "new_text" in d or "text" in d["current"] else "no"')"
ctl site-file-edit a.test .env.app --old 'APP_DEBUG=false' --new 'APP_DEBUG=true' --yes --reason "debug" > /dev/null; approve > $T/ap
check "the edit approved: made, and its result carries neither the old file nor a value" "true no no" \
  "$(grep -o 'APP_DEBUG=true' $A/.env.app | cut -d= -f2) $(grep -q 'dbs3cr3t\|APP_DEBUG=false' $T/ap && echo yes || echo no) $(curl -sS --unix-socket $CS http://control/v1/approvals | grep -q 'dbs3cr3t' && echo yes || echo no)"
# Nor its sha256 (the alpha.124 report, problem B: the preview carried the plain digests of the old and
# the new file, which confirm a guessed value offline): not in the dry run, the queued answer, the list,
# the result or the audit log. The approval stays bound to the file it showed: changed meanwhile, the
# approved edit is refused.
OLD=$(sha256sum < $A/.env.app | cut -d' ' -f1)
NEW=$(sed 's/^APP_DEBUG=true$/APP_DEBUG=false/' $A/.env.app | sha256sum | cut -d' ' -f1)
ctl site-file-edit a.test .env.app --old 'APP_DEBUG=true' --new 'APP_DEBUG=false' --dry-run > $T/d1
ctl site-file-edit a.test .env.app --old 'APP_DEBUG=true' --new 'APP_DEBUG=false' --yes --reason "debug off" > $T/d2
curl -sS --unix-socket $CS http://control/v1/approvals > $T/d3
approve > $T/d4
curl -sS --unix-socket $CS http://control/v1/approvals > $T/d5
check "no sha256 of a credential file leaves: dry run, queued answer, list, result, audit log" "false no no" \
  "$(grep -o '^APP_DEBUG=false' $A/.env.app | cut -d= -f2) $(cat $T/d1 $T/d2 $T/d3 $T/d4 $T/d5 | grep -q "$OLD\|$NEW" && echo yes || echo no) $(grep -q "$OLD\|$NEW" $T/logs/audit.log && echo yes || echo no)"
ctl site-file-edit a.test .env.app --old 'APP_DEBUG=false' --new 'APP_DEBUG=true' --yes --reason "debug on" > /dev/null
printf 'MAIL_HOST=x\n' >> $A/.env.app
approve > $T/out
check "a credential file changed after the edit was queued: the approved edit is refused, naming no digest, the file as changed" "yes no false yes" \
  "$(grep -q 'changed since it was read' $T/out && echo yes) $(grep -q "$(sha256sum < $A/.env.app | cut -d' ' -f1)" $T/out && echo yes || echo no) $(grep -o '^APP_DEBUG=false' $A/.env.app | cut -d= -f2) $(grep -q '^MAIL_HOST=x' $A/.env.app && echo yes)"
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
