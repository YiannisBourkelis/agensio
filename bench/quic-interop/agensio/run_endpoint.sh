#!/bin/bash
# The interop runner's entry point (server role only): the endpoint's network setup, then
# agensio on port 443 serving /www with the runner's certificate, in the mode the test case
# needs. A test case this server does not support exits 127, as the runner requires.
set -eu
/setup.sh

if [ "${ROLE:-server}" != server ]; then
  echo "agensio is a server; no client role"
  exit 127
fi

# The runner names the server's case per test: handshakeloss and handshakecorruption hand
# the server "multiconnect" (several connections in a row under loss), the rest their own name.
RETRY=never
case "${TESTCASE:-}" in
  handshake|transfer|http3|multiconnect|multiplexing|chacha20|keyupdate|amplificationlimit|blackhole|rebind-addr|rebind-port|handshakeloss|transferloss|handshakecorruption|transfercorruption|longrtt|versionnegotiation|ipv6|resumption|goodput|crosstraffic)
    ;;
  retry) RETRY=always ;;
  *)
    echo "test case ${TESTCASE:-} is not supported"
    exit 127 ;;
esac

mkdir -p /logs/qlog
cat > /tmp/agensio.toml <<TOML
[server]
workers = 2
protocols = ["h3", "hq-interop"]
http3 = { retry = "$RETRY" }
idle_timeout = 30
pid_file = "/tmp/agensio.pid"

[log]
access = "/logs/access.log"
error = "/logs/error.log"
level = "info"

[[site]]
server_name = ["*"]
listen = ["[::]:443"]
root = "/www"
tls = { cert = "/certs/cert.pem", key = "/certs/priv.key" }
TOML

echo "agensio: test case ${TESTCASE:-}, retry = $RETRY, keys to ${SSLKEYLOGFILE:-none}"
exec agensio -c /tmp/agensio.toml
