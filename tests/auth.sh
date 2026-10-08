#!/usr/bin/env bash
# Passwords ([[site.auth]], 2026-10-08, docs/configuration.md 19b, design section 25), end to end
# against a one-worker server, so the verification counter in `status` is exact:
#   - one slow hash per login, none per request after it (the cache), every failure verified
#     again (never cached), an unknown user verified too (no timing tells who exists);
#   - the challenge (realm, charset, no-store), one answer for a wrong password and an unknown
#     user, expiry, open paths below a protected one, skip_for, the bypass spellings;
#   - no password asked over plain HTTP from another host (403), unless plain_http = "allow";
#     loopback and TLS asked as usual;
#   - Cache-Control: private on what a password protects, the verified user in the access log,
#     one `auth failed` line per failure and none for the challenge;
#   - a reload keeps the cache, a changed password refuses the old one at once;
#   - a request on the same worker answered while a slow verification runs.
# usage: tests/auth.sh build/agensio   (a build with authentication: libxcrypt and OpenSSL)
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/auth; rm -rf "$T"; mkdir -p "$T/logs"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
if ! printf 'x\n' | "$BIN" passwd probe > /dev/null 2>&1; then echo "skip auth suite: this build has no authentication"; exit 0; fi
# Users: yescrypt (the default), a bcrypt one, an expired one, a slow one for the worker check.
{ printf 'secret\n' | "$BIN" passwd anna; echo ":note=Anna, Acme"; } | tr -d '\n' > "$T/users"; echo >> "$T/users"
printf 'p\xc3\xa4ssw\xc3\xb6rd\n' | "$BIN" passwd --method bcrypt --cost 4 jose >> "$T/users"
{ printf 'secret\n' | "$BIN" passwd old; echo ":expires=2020-01-01"; } | tr -d '\n' >> "$T/users"; echo >> "$T/users"
printf 'slow\n' | "$BIN" passwd --method bcrypt --cost 15 slow >> "$T/users"
chmod 640 "$T/users"
IP=$(hostname -I 2>/dev/null | awk '{print $1}')
cat > "$T/agensio.toml" <<EOF
[server]
workers = 1
pid_file = "$T/agensio.pid"
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
[control]
socket = "$T/control.sock"
[[site]]
server_name = ["*"]
listen = ["0.0.0.0:18130"]
root = "$ROOT/tests/authsite"

[[site.auth]]
path = "/private"
users = "$T/users"
realm = "Private"

[[site.auth]]
path = "/private/health"
match = "exact"
open = true

[[site.auth]]
path = "/office"
users = "$T/users"
skip_for = ["127.0.0.1"]

[[site.auth]]
path = "/lan"
users = "$T/users"
plain_http = "allow"

[[site]]
server_name = ["*"]
listen = ["0.0.0.0:18131"]
root = "$ROOT/tests/authsite"
tls = { cert = "$ROOT/bench/certs/cert.pem", key = "$ROOT/bench/certs/key.pem" }

[[site.auth]]
path = "/private"
users = "$T/users"
realm = "Private"
EOF
"$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 18130 2>/dev/null && break; sleep 0.1; done
B=http://127.0.0.1:18130
verifications() { curl -sS --unix-socket "$T/control.sock" http://control/v1/status | python3 -c 'import json,sys; print(json.load(sys.stdin).get("auth_verifications", "none"))'; }

# The challenge.
curl -sS -D "$T/h401" -o "$T/b401" $B/private/doc.html
check "no credentials: 401 with a Basic challenge naming the realm, charset UTF-8, not stored" "401|Basic realm=\"Private\", charset=\"UTF-8\"|no-store" \
  "$(head -1 "$T/h401" | cut -d' ' -f2)|$(grep -i '^www-authenticate:' "$T/h401" | tr -d '\r' | cut -d' ' -f2-)|$(grep -i '^cache-control:' "$T/h401" | tr -d '\r' | cut -d' ' -f2)"
check "the right password: 200 and the page; a wrong one and an unknown user: 401, the same page" "200 private doc|401 401 same" \
  "$(curl -sS -u anna:secret -w '%{http_code}' -o "$T/ok" $B/private/doc.html) $(cat "$T/ok")|$(code -u anna:wrong $B/private/doc.html) $(code -u nobody:secret $B/private/doc.html) $(cmp -s <(curl -sS -u anna:wrong $B/private/doc.html) <(curl -sS -u nobody:secret $B/private/doc.html) && echo same || echo differ)"

# The slow hash once per login, never per request.
n0=$(verifications)   # jose has not logged in yet: his first request is the one verification
urls=""; for i in $(seq 1 50); do urls="$urls $B/private/doc.html"; done
ok_keepalive=$(curl -sS -u 'jose:pässwörd' -o /dev/null -w '%{http_code}\n' $urls | grep -c '^200$')
ok_fresh=0; for i in 1 2 3 4 5; do [ "$(code -u 'jose:pässwörd' $B/private/)" = 200 ] && ok_fresh=$((ok_fresh+1)); done
n1=$(verifications)
check "one login then 50 requests on one connection and 5 new connections: all 200, one verification (the cache, not a hash per request)" "50 5 1" "$ok_keepalive $ok_fresh $((n1 - n0))"
for i in 1 2 3 4 5; do code -u anna:wrong$i $B/private/doc.html > /dev/null; done
n2=$(verifications)
check "five wrong passwords: five verifications (a failure is never remembered)" "5" "$((n2 - n1))"
code -u someone:secret $B/private/doc.html > /dev/null
n3=$(verifications)
check "an unknown user is verified too, against a real entry (timing does not tell who exists)" "1" "$((n3 - n2))"

# The rules.
check "expired, locked out even with the right password; a UTF-8 password works" "401 200" "$(code -u old:secret $B/private/doc.html) $(code -u 'jose:pässwörd' $B/private/doc.html)"
check "open below a protected path; skip_for lets 127.0.0.1 in without a password; the public part needs none" "200 200 200" "$(code $B/private/health) $(code $B/office/) $(code $B/)"
check "every spelling of a protected path asks: case, no slash, its index, dot segments, an encoded name" "401 401 401 401 401" \
  "$(code $B/PRIVATE/doc.html) $(code $B/private) $(code $B/private/) $(code --path-as-is $B/office/../private/doc.html) $(code $B/%70rivate/doc.html)"

# Plain HTTP from another host: never asked; from loopback and over TLS: asked.
if [ -n "$IP" ]; then
  curl -sS -D "$T/hplain" -o "$T/bplain" "http://$IP:18130/private/doc.html"
  check "plain HTTP from another host: 403 with no challenge and a page saying to use HTTPS; plain_http = \"allow\" asks anyway" "403 no-challenge yes 401" \
    "$(head -1 "$T/hplain" | cut -d' ' -f2) $(grep -qi '^www-authenticate:' "$T/hplain" && echo challenge || echo no-challenge) $(grep -qi 'https' "$T/bplain" && echo yes) $(code "http://$IP:18130/lan/")"
  check "over TLS from another host: asked, and the right password served" "401 200" "$(code -k --resolve localhost:18131:$IP https://localhost:18131/private/doc.html) $(code -k --resolve localhost:18131:$IP -u anna:secret https://localhost:18131/private/doc.html)"
else
  echo "skip plain-HTTP checks: no address but loopback"
fi

# What caches and logs see.
check "a protected answer is Cache-Control: private; a public one carries none" "private|" \
  "$(curl -sS -u anna:secret -D - -o /dev/null $B/private/doc.html | tr -d '\r' | grep -i '^cache-control:' | cut -d' ' -f2)|$(curl -sS -D - -o /dev/null $B/ | tr -d '\r' | grep -i '^cache-control:' | cut -d' ' -f2)"
sleep 1.2
check "the access log names the verified user, never the one a refused request claimed" "anna -" \
  "$(grep '/private/doc.html' "$T/logs/access.log" | grep '" 200 ' | tail -1 | cut -d' ' -f3) $(grep '/private/doc.html' "$T/logs/access.log" | grep '" 401 ' | tail -1 | cut -d' ' -f3)"
check "one auth failed line per failure, with the user, the client and the reason; none for the challenge; never the password" "yes yes 0" \
  "$(grep -q 'auth failed: client 127.0.0.1 site .* realm "Private" user "anna" (wrong password)' "$T/logs/error.log" && echo yes) $(grep -q 'auth failed: .*user "old" .*expired' "$T/logs/error.log" && echo yes) $(grep -c 'secret\|wrong1' "$T/logs/error.log")"

# A slow verification runs off the worker's loop.
( curl -sS -o /dev/null -u slow:slow $B/private/doc.html & )
sleep 0.2
t0=$(date +%s%N); r=$(code $B/); t1=$(date +%s%N)
check "while a slow verification runs, the same worker answers another request at once" "200 fast" "$r $( [ $(( (t1 - t0) / 1000000 )) -lt 150 ] && echo fast || echo slow)"
sleep 2

# A reload keeps what was verified; a changed password refuses the old one at once.
code -u anna:secret $B/private/doc.html > /dev/null
n4=$(verifications)
kill -HUP $SRV; sleep 0.5
check "after a reload the remembered login needs no new verification" "200 0" "$(code -u anna:secret $B/private/doc.html) $(( $(verifications) - n4 ))"
{ printf 'changed\n' | "$BIN" passwd anna; } > "$T/users.new"; grep -v '^anna:' "$T/users" >> "$T/users.new"; chmod 640 "$T/users.new"; mv "$T/users.new" "$T/users"
kill -HUP $SRV; sleep 0.5
check "a changed password: the old one refused at once, the new one served" "401 200" "$(code -u anna:secret $B/private/doc.html) $(code -u anna:changed $B/private/doc.html)"

echo "auth: $pass passed, $fail failed"
[ $fail -eq 0 ]
