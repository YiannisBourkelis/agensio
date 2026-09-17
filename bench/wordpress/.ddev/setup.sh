#!/usr/bin/env bash
# Creates (once) the WordPress test bed as a ddev project (MariaDB from ddev) and installs
# WordPress with wp-cli. Idempotent.
# Site: http://wp.agensio.ddev.site:8072/   wp-admin login: admin / 4444
set -euo pipefail
cd "$(dirname "$0")/.."
if [ ! -f .ddev/config.yaml ]; then
  ddev config --project-type=wordpress --project-name=agensio-wordpress --php-version=8.3
fi
ddev start -y
if [ ! -f wp-load.php ]; then
  ddev wp core download
fi
if ! ddev wp core is-installed >/dev/null 2>&1; then
  ddev wp core install --url=http://wp.agensio.ddev.site:8072 --title=agensio --admin_user=admin \
    --admin_password=4444 --admin_email=admin@admin.com --skip-email
  ddev wp rewrite structure '/%postname%/' --hard >/dev/null
fi
# WordPress must know the URL it is served on; ddev's include defines WP_HOME from its own
# URL unless already defined, so define ours first (wp-config.php survives `ddev config`).
if ! grep -q 'agensio: served on this URL' wp-config.php; then
  python3 - <<'PY'
import re
p = 'wp-config.php'
s = open(p).read()
# Drop ddev's "#ddev-generated" marker: with it present ddev rewrites this file on every
# restart and the defines below would vanish (its own comment says removing it is the way).
s = "\n".join(l for l in s.split("\n")
              if "#ddev-generated" not in l and "ddev manages this file" not in l and "leave this file alone" not in l)
s = s.replace("<?php\n", "<?php\n// agensio: served on this URL (defined before ddev's include, whose defines are `defined() ||`)\n"
              "define('WP_HOME', 'http://wp.agensio.ddev.site:8072');\ndefine('WP_SITEURL', WP_HOME);\n"
              "define('WP_DEBUG', false);          // production settings: no errors shown to visitors\n"
              "define('WP_DEBUG_DISPLAY', false);\n", 1)
open(p, 'w').write(s)
PY
fi
echo "ready: php-fpm on 127.0.0.1:9002 (published), run: build/agensio -c bench/wordpress/.ddev/agensio.toml"
echo "site: http://wp.agensio.ddev.site:8072/   wp-admin: admin / 4444"
