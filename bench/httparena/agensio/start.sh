#!/bin/bash
# Two agensio processes: `protocols` is server-wide in v0.1.0-alpha.20 and the arena wants
# HTTP/1.1-only TLS on 8081 next to h2 on 8443. Each gets one worker per CPU of the
# container's cpuset (nproc honours it); only one listener is under load at a time.
set -eu
W=$(nproc)
mkdir -p /run/agensio
install -m 0600 /certs/server.key /run/agensio/server.key
install -m 0644 /certs/server.crt /run/agensio/server.crt
for f in h1 h2; do sed "s/@WORKERS@/$W/" "/etc/agensio/$f.toml" > "/run/agensio/$f.toml"; done
agensio -c /run/agensio/h1.toml &
agensio -c /run/agensio/h2.toml &
wait -n
exit 1
