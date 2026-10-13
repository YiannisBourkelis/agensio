#!/usr/bin/env bash
# RPM test: build packaging/rpm/agensio.spec, the spec COPR builds from the release tarball, from
# this working tree's tracked files in a Fedora container, install the package there and check what
# it holds. The GitHub release's RPM comes from `cpack -G RPM` and packs whatever CMake installs;
# this spec lists its files itself, so a file CMake installs and the spec does not name, or a
# directory the spec names and nothing creates, fails the build (alpha.88: both did).
# Needs docker; the first run makes the image agensio-rpmbuild:local (fedora:latest with the spec's
# build dependencies, from the network).
# usage: tests/rpm.sh
set -u
cd "$(dirname "$(readlink -f "$0")")/.."
command -v docker > /dev/null || { echo "rpm: no docker; skipped"; exit 0; }
if ! docker image inspect agensio-rpmbuild:local > /dev/null 2>&1; then
    docker rm -f agensio-rpm-prep > /dev/null 2>&1
    docker run --name agensio-rpm-prep -v "$PWD/packaging/rpm:/spec:ro" fedora:latest \
        bash -c 'dnf -y -q install rpm-build dnf-plugins-core && dnf -y -q builddep /spec/agensio.spec' > /dev/null 2>&1 ||
        { docker rm -f agensio-rpm-prep > /dev/null 2>&1; echo "rpm: could not make the build image (network?); skipped"; exit 0; }
    docker commit agensio-rpm-prep agensio-rpmbuild:local > /dev/null && docker rm agensio-rpm-prep > /dev/null
fi
version=$(sed -n 's/^%global upstream_version //p' packaging/rpm/agensio.spec)
work=$(mktemp -d "${TMPDIR:-/tmp}/agensio-rpm.XXXXXX")
trap 'rm -rf "$work"' EXIT
# The tarball as the tag's would be once this tree is committed: its files, tracked or new, not ignored.
git ls-files -z --cached --others --exclude-standard | tar --null -T - --transform "s,^,agensio-$version/," -czf "$work/v$version.tar.gz"
cp packaging/rpm/agensio.spec "$work/"
docker run --rm -v "$work:/w" agensio-rpmbuild:local bash -c '
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
rpmbuild -bb --define "_topdir /tmp/t" --define "_sourcedir /w" /w/agensio.spec > /tmp/build.log 2>&1
built=$?
check "rpmbuild builds the spec" "0" "$built"
if [ "$built" != 0 ]; then sed -n "/RPM build errors/,\$p" /tmp/build.log | head -30; echo "rpm: $pass passed, $fail failed"; exit 1; fi
rpm=$(ls /tmp/t/RPMS/*/agensio-[0-9]*.rpm | head -1)
dnf -y -q --setopt=tsflags= install "$rpm" > /tmp/install.log 2>&1   # the image installs with nodocs
installed=$?
check "the package installs" "0" "$installed"
if [ "$installed" != 0 ]; then tail -20 /tmp/install.log; echo "rpm: $pass passed, $fail failed"; exit 1; fi
check "the guides, as CMake installs them" "yes yes yes yes yes" "$(for f in configuration.md tls.md redirects.md keys.md examples/php.md; do [ -f /usr/share/doc/agensio/$f ] && echo -n "yes " || echo -n "no($f) "; done | sed "s/ $//")"
check "every guide marked as documentation" "0" "$(rpm -qp --list "$rpm" | grep "^/usr/share/doc/agensio/.*\.md$" | sort > /tmp/all; rpm -qp --docfiles "$rpm" | sort > /tmp/doc; comm -23 /tmp/all /tmp/doc | wc -l)"
check "directories with owners" "root:agensio 750 | agensio:agensio 750 | agensio:agensio 750 | agensio:agensio 751" "$(stat -c "%U:%G %a" /etc/agensio) | $(stat -c "%U:%G %a" /etc/agensio/sites.d) | $(stat -c "%U:%G %a" /var/log/agensio) | $(stat -c "%U:%G %a" /var/lib/agensio)"
check "main config root:agensio 0640" "root:agensio 640" "$(stat -c "%U:%G %a" /etc/agensio/agensio.toml)"
cd /
check "agensio -t accepts the packaged configuration" "yes" "$(agensio -t 2>&1 | grep -q "/etc/agensio/agensio.toml is OK" && echo yes || agensio -t 2>&1 | tail -3)"
echo "rpm: $pass passed, $fail failed"
[ "$fail" = 0 ]
'
