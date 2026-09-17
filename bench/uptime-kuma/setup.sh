#!/usr/bin/env bash
# Starts the Uptime Kuma container and waits until it answers.
# Then: build/agensio -c bench/uptime-kuma/agensio.toml
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d
for _ in $(seq 1 120); do
  curl -fs -o /dev/null http://127.0.0.1:3011/ && { echo "uptime kuma ready on 127.0.0.1:3011"; exit 0; }
  sleep 1
done
echo "uptime kuma did not come up; docker compose logs:"; docker compose logs --tail 20; exit 1
