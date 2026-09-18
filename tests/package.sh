#!/usr/bin/env bash
# Package test (H7): install, run, reinstall, remove and purge the .deb that `cpack -G DEB`
# built, as root, in a throwaway container (no systemd there: the maintainer scripts must
# cope). It changes the system it runs on, so it refuses to run outside a container.
# usage (devbox, root): docker run --rm --init --user root -v "$PWD:$PWD" -w "$PWD" agensio-devbox tests/package.sh
set -u
[ "$(id -u)" = 0 ] && { [ -f /.dockerenv ] || [ -n "${AGENSIO_PACKAGE_TEST:-}" ]; } || { echo "package: needs root inside a container (or AGENSIO_PACKAGE_TEST=1); skipped"; exit 0; }
cd "$(dirname "$(readlink -f "$0")")/.."
deb=$(ls "$PWD"/build/agensio_*.deb 2>/dev/null | head -1); [ -n "$deb" ] || { echo "package: no build/agensio_*.deb (run cpack -G DEB in build/); skipped"; exit 0; }
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
dpkg -i "$deb" > /tmp/dpkg.log 2>&1; check "dpkg -i succeeds" "0" "$?"
check "service account and groups" "agensio agensio agensio-admin" "$(id -un agensio) $(id -gn agensio) $(getent group agensio-admin | cut -d: -f1)"
check "directories with owners" "root:agensio 750 | agensio:agensio 750 | agensio:agensio 750 | agensio:agensio 750" "$(stat -c '%U:%G %a' /etc/agensio) | $(stat -c '%U:%G %a' /etc/agensio/sites.d) | $(stat -c '%U:%G %a' /var/log/agensio) | $(stat -c '%U:%G %a' /var/lib/agensio)"
check "main config root:agensio 0640, /var/www/html has content (placeholder or existing)" "root:agensio 640 yes" "$(stat -c '%U:%G %a' /etc/agensio/agensio.toml) $([ -n "$(ls -A /var/www/html)" ] && echo yes)"
cd /   # the default search must land on /etc/agensio/agensio.toml, not a file in the repository
check "agensio -t finds and accepts the packaged configuration" "yes" "$(agensio -t 2>&1 | grep -q '/etc/agensio/agensio.toml is OK' && echo yes)"
check "version" "agensio 0.1.0-alpha.1" "$(agensio -v | head -1)"
agensio > /tmp/agensio.out 2>&1 & P=$!; sleep 0.8
first=$(ls /var/www/html | head -1)
check "serves /var/www/html on port 80 as the agensio user" "200 agensio" "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1/$first") $(ps -o user= -p $P | tr -d ' ')"
check "control socket answers root" "admin" "$(agensio ctl status | sed -n 's/.*"role":"\([a-z]*\)".*/\1/p')"
check "logs written by the service user" "agensio" "$(stat -c %U /var/log/agensio/error.log)"
kill $P; wait $P 2>/dev/null
check "unit and logrotate files installed" "yes yes" "$([ -f /usr/lib/systemd/system/agensio.service ] && echo yes) $([ -f /etc/logrotate.d/agensio ] && echo yes)"
echo "# edited" >> /etc/agensio/agensio.toml
dpkg -i "$deb" >> /tmp/dpkg.log 2>&1
check "reinstall keeps the edited conffile" "yes" "$(grep -q '# edited' /etc/agensio/agensio.toml && echo yes)"
dpkg -r agensio >> /tmp/dpkg.log 2>&1; check "dpkg -r succeeds, config and logs stay" "0 yes yes" "$? $([ -f /etc/agensio/agensio.toml ] && echo yes) $([ -d /var/log/agensio ] && echo yes)"
dpkg -P agensio >> /tmp/dpkg.log 2>&1; check "dpkg -P removes config and logs, keeps state and content" "0 gone gone kept kept" "$? $([ -e /etc/agensio ] && echo still || echo gone) $([ -e /var/log/agensio ] && echo still || echo gone) $([ -d /var/lib/agensio ] && echo kept) $([ -n "$(ls -A /var/www/html)" ] && echo kept)"
echo "deb: $pass passed, $fail failed"; [ $fail = 0 ] || { echo "--- dpkg log"; tail -20 /tmp/dpkg.log; }
