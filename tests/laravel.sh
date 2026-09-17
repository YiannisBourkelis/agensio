#!/usr/bin/env bash
# Live checks against the ddev Laravel project (bench/laravel/.ddev/setup.sh first). Skips with
# exit 0 when the project is not running, so it can sit in CI next to integration.sh.
# usage: tests/laravel.sh [path-to-agensio-binary]
set -uo pipefail
BIN="${1:-build/agensio}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if ! nc -z 127.0.0.1 9000 2>/dev/null || [ ! -f bench/laravel/artisan ]; then
  echo "skip: ddev Laravel project not running (bench/laravel/.ddev/setup.sh)"; exit 0
fi
"$BIN" -t -c bench/laravel/.ddev/agensio.toml >/dev/null || { echo "config invalid"; exit 1; }
"$BIN" -c bench/laravel/.ddev/agensio.toml >/dev/null 2>bench/tmp/laravel-agensio.err &
PID=$!
trap 'kill $PID 2>/dev/null; wait $PID 2>/dev/null' EXIT
for _ in $(seq 1 50); do nc -z 127.0.0.1 8070 2>/dev/null && break; sleep 0.1; done
fails=0
check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: expected [$2] got [$3]"; fails=$((fails+1)); fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }
B=http://127.0.0.1:8070
check "welcome page" "200 yes" "$(curl -sS -o bench/tmp/laravel-welcome.html -w '%{http_code}' $B/) $(grep -qi 'laravel' bench/tmp/laravel-welcome.html && echo yes)"
check "json route" '{"ok":true,"method":"GET"}' "$(curl -sS $B/json)"
check "post with body" '"a":"hello"' "$(curl -sS -d 'a=hello' $B/echo | grep -o '"a":"hello"')"
head -c 300000 /dev/urandom > bench/tmp/upload.bin
check "file upload (300 KB, spilled request body)" '"file":300000' "$(curl -sS -F 'a=x' -F 'f=@bench/tmp/upload.bin' $B/echo | grep -o '"file":300000')"
check "client ip seen by laravel" '"ip":"127.0.0.1"' "$(curl -sS -d 'a=1' $B/echo | grep -o '"ip":"127.0.0.1"')"
check "script path mapped into the container" '"script":"\/var\/www\/html\/public\/index.php"' "$(curl -sS $B/info | grep -o '"script":"[^"]*"')"
check "static asset from public/" "200" "$(code $B/favicon.ico)"
check "unknown route is laravel's 404" "404 yes" "$(curl -sS -o bench/tmp/laravel-404.html -w '%{http_code}' $B/nope) $(grep -qi 'not found' bench/tmp/laravel-404.html && echo yes)"
check "dotfile hidden" "404" "$(code $B/.env)"
check "keep-alive across php requests" "200 200 200" "$(curl -sS -o /dev/null -o /dev/null -o /dev/null -w '%{http_code} ' $B/json $B/json $B/json | sed 's/ $//')"
[ $fails -eq 0 ] && echo "laravel: all passed" || { echo "laravel: $fails failure(s)"; cat bench/tmp/laravel-agensio.err | tail -5; exit 1; }
