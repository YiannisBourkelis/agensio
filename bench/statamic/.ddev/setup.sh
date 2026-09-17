#!/usr/bin/env bash
# Creates (once) the Statamic test bed as a ddev project, flat-file (no database), with a
# control panel super user. Idempotent.
# Control panel: http://127.0.0.1:8071/cp   login admin@admin.com / 4444
# (the login throttles after 5 wrong attempts per minute: `ddev exec php please cache:clear`
# resets it; a lost password: delete users/admin@admin.com.yaml and rerun this script)
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .ddev/config.yaml ]; then
  ddev config --project-type=laravel --docroot=public --project-name=agensio-statamic --php-version=8.3 \
    --disable-settings-management --omit-containers=db
fi
ddev start -y
if [ ! -f artisan ]; then
  ddev composer create-project statamic/statamic . --no-interaction
fi
if [ ! -f users/admin@admin.com.yaml ]; then
  ddev exec php please make:user admin@admin.com --password=4444 --super --no-interaction
  ddev exec php please stache:refresh >/dev/null 2>&1 || true
fi
ddev exec php please optimize:clear >/dev/null 2>&1 || true
echo "ready: php-fpm on 127.0.0.1:9001 (published), run: build/agensio -c bench/statamic/.ddev/agensio.toml"
echo "control panel: http://127.0.0.1:8071/cp  (admin@admin.com / 4444)"
