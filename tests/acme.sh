#!/usr/bin/env bash
# Automatic certificates (H3) against Pebble (bench/acme/docker-compose.yml): a site with
# tls = "auto" starts on a placeholder certificate, the ACME client registers an account,
# orders, answers the HTTP-01 challenge on port 5002, downloads the chain, and the server
# reloads itself onto the issued certificate without a restart. The chain is verified
# against Pebble's root, the key file must be private, an unknown token is a 404, and the
# configuration rules for "auto" are checked with -t.
# usage: tests/acme.sh build/agensio   (needs docker compose, curl, openssl)
set -uo pipefail
BIN=$(readlink -f "${1:-build/agensio}")
ROOT=$(pwd)
T=$ROOT/bench/tmp/acme; rm -rf "$T"; mkdir -p "$T/www" "$T/logs"
echo "hello over acme" > "$T/www/index.html"
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
code() { curl -sS -o /dev/null -w '%{http_code}' "$@"; }

docker compose -f "$ROOT/bench/acme/docker-compose.yml" up -d --quiet-pull >/dev/null 2>&1 || { echo "acme: cannot start Pebble; skipped"; exit 0; }
trap 'kill $SRV 2>/dev/null; wait $SRV 2>/dev/null; docker compose -f "$ROOT/bench/acme/docker-compose.yml" down >/dev/null 2>&1' EXIT
SRV=
for _ in $(seq 1 100); do curl -sk https://127.0.0.1:14000/dir 2>/dev/null | grep -q newOrder && break; sleep 0.2; done
docker compose -f "$ROOT/bench/acme/docker-compose.yml" cp pebble:/test/certs/pebble.minica.pem "$T/pebble-ca.pem" >/dev/null 2>&1
check "Pebble is up and its CA certificate was copied" "yes" "$([ -s "$T/pebble-ca.pem" ] && echo yes)"

write_config() {  # [extra server keys]
  cat > "$T/agensio.toml" <<CFG
[server]
workers = 2
pid_file = "$T/agensio.pid"
acme = { email = "admin@example.test", directory = "https://localhost:14000/dir", ca = "$T/pebble-ca.pem", storage = "$T/certs" }
${1:-}
[log]
access = "$T/logs/access.log"
error = "$T/logs/error.log"
level = "info"
[[site]]
server_name = ["host.docker.internal"]
listen = ["0.0.0.0:5002"]
root = "$T/www"
[[site]]
server_name = ["host.docker.internal"]
listen = ["127.0.0.1:8449"]
root = "$T/www"
tls = "auto"
CFG
}
write_config
check "-t --explain shows the resolved automatic certificate" "yes" "$("$BIN" -t --explain -c "$T/agensio.toml" 2>&1 | grep -q "tls = \"auto\"  # $T/certs/host.docker.internal/fullchain.pem" && echo yes)"
printf '[[site]]\nserver_name = ["a.test"]\nlisten = ["127.0.0.1:8449"]\nroot = "%s"\ntls = "auto"\n' "$T/www" > "$T/noacme.toml"
check "tls = \"auto\" without [server] acme is refused" "yes" "$({ "$BIN" -t -c "$T/noacme.toml" 2>&1 || true; } | grep -qF 'needs [server] acme' && echo yes)"
printf '[server]\nacme = { email = "x@y.test" }\n[[site]]\nserver_name = ["*.a.test"]\nlisten = ["127.0.0.1:8449"]\nroot = "%s"\ntls = "auto"\n' "$T/www" > "$T/wild.toml"
check "a wildcard name is refused (DNS-01 not supported)" "yes" "$({ "$BIN" -t -c "$T/wild.toml" 2>&1 || true; } | grep -qF 'wildcards need DNS-01' && echo yes)"
printf '[server]\nacme = { directory = "https://x" }\n' > "$T/noemail.toml"
check "acme without email is refused" "yes" "$({ "$BIN" -t -c "$T/noemail.toml" 2>&1 || true; } | grep -qF 'server.acme.email is required' && echo yes)"

"$BIN" -c "$T/agensio.toml" > "$T/server.out" 2>&1 & SRV=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 8449 2>/dev/null && break; sleep 0.1; done
issuer() { echo | openssl s_client -connect 127.0.0.1:8449 -servername host.docker.internal 2>/dev/null | openssl x509 -noout -issuer 2>/dev/null; }
check "plain site answers on the challenge port" "hello over acme" "$(curl -sS http://127.0.0.1:5002/)"
check "an unknown token is a 404, not a hint" "404" "$(code http://127.0.0.1:5002/.well-known/acme-challenge/nothing-here)"
for _ in $(seq 1 150); do issuer | grep -q 'Pebble' && break; sleep 0.2; done
check "the issued certificate is served within 30 s, picked up by a reload" "yes" "$(issuer | grep -q 'Pebble Intermediate' && echo yes)"
check "reload logged after the issuance" "yes" "$(grep -q 'acme: certificate issued for host.docker.internal' "$T/logs/error.log" && grep -q 'reloaded ' "$T/logs/error.log" && echo yes)"
check "the listener started on a placeholder certificate, then ordered" "yes" "$(grep -q 'ordering a certificate for host.docker.internal (placeholder certificate)' "$T/logs/error.log" && echo yes)"
check "validation logged" "yes" "$(grep -q 'acme: host.docker.internal validated (http-01)' "$T/logs/error.log" && echo yes)"
curl -sk https://127.0.0.1:15000/roots/0 > "$T/pebble-root.pem"
curl -sk https://127.0.0.1:15000/intermediates/0 > "$T/pebble-int.pem"
echo | openssl s_client -connect 127.0.0.1:8449 -servername host.docker.internal -showcerts 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$T/served-chain.pem"
check "served chain verifies against Pebble's root" "yes" "$(openssl verify -CAfile "$T/pebble-root.pem" -untrusted "$T/served-chain.pem" "$T/certs/host.docker.internal/fullchain.pem" 2>/dev/null | grep -q ': OK' && echo yes)"
check "the certificate covers the name" "yes" "$(openssl x509 -in "$T/certs/host.docker.internal/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -q 'DNS:host.docker.internal' && echo yes)"
check "key files are private, chain readable" "600 600 644" "$(stat -c %a "$T/certs/account.key" "$T/certs/host.docker.internal/key.pem" "$T/certs/host.docker.internal/fullchain.pem" | tr '\n' ' ' | sed 's/ $//')"
check "https serves the site" "hello over acme" "$(curl -sS --cacert "$T/pebble-root.pem" --resolve host.docker.internal:8449:127.0.0.1 https://host.docker.internal:8449/)"
check "no client-visible error" "" "$(grep -E '\[error\]' "$T/logs/error.log")"
# A restart keeps the certificate: the file is valid, no new order.
kill $SRV; wait $SRV 2>/dev/null
"$BIN" -c "$T/agensio.toml" >> "$T/server.out" 2>&1 & SRV=$!
for _ in $(seq 1 50); do nc -z 127.0.0.1 8449 2>/dev/null && break; sleep 0.1; done
sleep 1
check "restart keeps the issued certificate without a new order" "1 yes" "$(grep -c 'acme: certificate issued' "$T/logs/error.log") $(issuer | grep -q 'Pebble Intermediate' && echo yes)"
echo "acme: $pass passed, $fail failed"
[ $fail = 0 ]
