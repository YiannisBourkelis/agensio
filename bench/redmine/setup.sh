#!/usr/bin/env bash
# Starts the Redmine container (first run pulls the image and creates the database) and
# waits until it answers. Then: build/agensio -c bench/redmine/agensio.toml
set -euo pipefail
cd "$(dirname "$0")"
docker compose up -d
for _ in $(seq 1 120); do
  curl -fs -o /dev/null http://127.0.0.1:3010/ && { echo "redmine ready on 127.0.0.1:3010 (admin / admin)"; exit 0; }
  sleep 1
done
echo "redmine did not come up; docker compose logs:"; docker compose logs --tail 20; exit 1
