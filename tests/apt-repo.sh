#!/usr/bin/env bash
# The APT repository the release workflow publishes (packaging/apt-repo.sh, docs/install.md),
# built from stand-in packages with a throwaway key and installed from by Debian 12 and Debian 13
# clients in containers on a network of their own; the clients list only this repository, so no
# Debian mirror is reached. Three releases in a row:
# - each suite lists the last two, and a client installs the newest of its own suite (Debian 13
#   the +deb13 build) and goes back with agensio=<previous>;
# - what a CDN edge may serve for ten minutes after a release (GitHub Pages: max-age=600) works:
#   the previous InRelease with the new files, and the new InRelease with the previous indexes
#   at their plain paths;
# - the third release drops the first's files.
#   tests/apt-repo.sh
# Needs docker, debian:bookworm, debian:trixie and agensio-aptrepo (Debian 13 with the tools):
#   printf 'FROM debian:trixie\nRUN apt-get update && apt-get install -y --no-install-recommends gnupg apt-utils dpkg-dev python3 && rm -rf /var/lib/apt/lists/*\n' | docker build -t agensio-aptrepo -
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
ROOT=$(pwd)
command -v docker >/dev/null || { echo "apt-repo: no docker; skipped"; exit 0; }
for img in agensio-aptrepo debian:bookworm debian:trixie; do
    docker image inspect "$img" >/dev/null 2>&1 || { echo "apt-repo: image $img missing (see the header); skipped"; exit 0; }
done
mkdir -p bench/tmp
T=$(mktemp -d "$ROOT/bench/tmp/aptrepo.XXXXXX")
NET=agensio-apt-$$
SRV=agensio-aptsrv-$$
pass=0; fail=0
check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
cleanup() {
    docker rm -f "$SRV" >/dev/null 2>&1
    docker network rm "$NET" >/dev/null 2>&1
    docker run --rm -v "$ROOT:$ROOT" agensio-aptrepo rm -rf "$T"  # files the containers made are root's
}
trap cleanup EXIT

# Three releases, each two stand-in packages (no dependencies, nothing to run), and the repository
# after each one, built on the previous as the workflow does from the gh-pages branch.
docker run --rm -v "$ROOT:$ROOT" -w "$ROOT" -e GNUPGHOME="$T/gnupg" agensio-aptrepo bash -c '
set -e
mkdir -p -m 700 "$GNUPGHOME"
gpg --batch --pinentry-mode loopback --passphrase "" --quick-gen-key "agensio test <test@invalid>" ed25519 sign never 2>/dev/null
key=$(gpg --list-secret-keys --with-colons | awk -F: "/^sec/{print \$5; exit}")
for r in 1 2 3; do
    for s in "" "+deb13"; do
        p='"$T"'/pkg-$r$s; mkdir -p $p/DEBIAN '"$T"'/debs$r
        printf "Package: agensio\nVersion: 0.1.0~alpha.$r$s\nArchitecture: amd64\nMaintainer: test <test@invalid>\nDescription: stand-in\n" > $p/DEBIAN/control
        dpkg-deb -b $p '"$T"'/debs$r/agensio_0.1.0~alpha.$r${s}_amd64.deb >/dev/null
    done
done
packaging/apt-repo.sh --out '"$T"'/site1 --key $key '"$T"'/debs1/*.deb
packaging/apt-repo.sh --out '"$T"'/site2 --key $key --previous '"$T"'/site1 '"$T"'/debs2/*.deb
packaging/apt-repo.sh --out '"$T"'/site3 --key $key --previous '"$T"'/site2 '"$T"'/debs3/*.deb
# What a CDN edge may mix: the previous InRelease (and Release) with the new files, and the new
# InRelease with the previous indexes at their plain paths.
cp -a '"$T"'/site3 '"$T"'/old-inrelease; cp -a '"$T"'/site3 '"$T"'/old-indexes
for s in stable trixie; do
    cp '"$T"'/site2/apt/dists/$s/{InRelease,Release,Release.gpg} '"$T"'/old-inrelease/apt/dists/$s/
    cp '"$T"'/site2/apt/dists/$s/main/binary-amd64/Packages{,.gz} '"$T"'/old-indexes/apt/dists/$s/main/binary-amd64/
done
chmod -R a+rX '"$T"'
' > "$T/build.log" 2>&1 || { echo "FAIL building the repositories:"; cat "$T/build.log"; exit 1; }

serve() { ln -sfn "$1" "$T/www"; }  # the server resolves the link at each request
serve site3
docker network create "$NET" >/dev/null
docker run -d --name "$SRV" --network "$NET" --network-alias aptsrv -v "$ROOT:$ROOT" agensio-aptrepo python3 -m http.server 8000 --directory "$T/www" >/dev/null

# A client: only this repository, the key as docs/install.md installs it; prints what the commands print.
client() {  # image suite commands...
    local image=$1 suite=$2; shift 2
    docker run --rm --network "$NET" -v "$T:$T:ro" "$image" bash -c "
        rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
        install -m 0755 -d /etc/apt/keyrings && cp $T/site3/agensio.gpg /etc/apt/keyrings/agensio.gpg
        echo 'deb [signed-by=/etc/apt/keyrings/agensio.gpg] http://aptsrv:8000/apt $suite main' > /etc/apt/sources.list.d/agensio.list
        apt-get update -q >/tmp/update.log 2>&1 || { echo update-failed; tail -5 /tmp/update.log; exit 0; }
        $*" 2>&1
}
installed='dpkg-query -W -f "\${Version}" agensio'
for _ in $(seq 1 50); do docker run --rm --network "$NET" agensio-aptrepo python3 -c 'import urllib.request; urllib.request.urlopen("http://aptsrv:8000/")' >/dev/null 2>&1 && break; sleep 0.2; done

check "Debian 12 on stable: the suite lists the last two releases, the newest installs, agensio=<previous> goes back" \
    "0.1.0~alpha.3 0.1.0~alpha.2 | 0.1.0~alpha.3 | 0.1.0~alpha.2" \
    "$(client debian:bookworm stable "apt-cache madison agensio | awk '{print \$3}' | tr '\n' ' '; echo -n '| '; apt-get install -y -q agensio >/dev/null 2>&1; $installed; echo -n ' | '; apt-get install -y -q --allow-downgrades agensio=0.1.0~alpha.2 >/dev/null 2>&1; $installed")"
check "Debian 13 on trixie: the +deb13 build of the newest release" "0.1.0~alpha.3+deb13 0.1.0~alpha.2+deb13 | 0.1.0~alpha.3+deb13" \
    "$(client debian:trixie trixie "apt-cache madison agensio | awk '{print \$3}' | tr '\n' ' '; echo -n '| '; apt-get install -y -q agensio >/dev/null 2>&1; $installed")"
check "Debian 13 on stable (the build without HTTP/3 installs there too)" "0.1.0~alpha.3" \
    "$(client debian:trixie stable "apt-get install -y -q agensio >/dev/null 2>&1; $installed")"
serve old-inrelease
check "a CDN edge still serving the previous InRelease with the new files: apt updates and installs the release that InRelease names (its indexes and package are kept)" \
    "0.1.0~alpha.2 0.1.0~alpha.2+deb13" \
    "$(client debian:bookworm stable "apt-get install -y -q agensio >/dev/null 2>&1; $installed") $(client debian:trixie trixie "apt-get install -y -q agensio >/dev/null 2>&1; $installed")"
serve old-indexes
check "the new InRelease with the previous indexes at their plain paths: apt fetches the indexes by hash and installs the new release" \
    "0.1.0~alpha.3 0.1.0~alpha.3+deb13" \
    "$(client debian:bookworm stable "apt-get install -y -q agensio >/dev/null 2>&1; $installed") $(client debian:trixie trixie "apt-get install -y -q agensio >/dev/null 2>&1; $installed")"
check "the third release drops the first: two packages per suite, the indexes of two releases under each hash, Acquire-By-Hash, a binary key, no Jekyll" \
    "2 2 4 4 yes yes yes" \
    "$(ls "$T/site3/apt/pool/stable" | wc -l) $(ls "$T/site3/apt/pool/trixie" | wc -l) $(ls "$T/site3/apt/dists/stable/main/binary-amd64/by-hash/SHA256" | wc -l) $(ls "$T/site3/apt/dists/trixie/main/binary-amd64/by-hash/SHA512" | wc -l) $(grep -q '^Acquire-By-Hash: yes' "$T/site3/apt/dists/trixie/Release" && echo yes) $(head -c 1 "$T/site3/agensio.gpg" | od -An -tx1 | grep -qv '2d' && echo yes) $([ -f "$T/site3/.nojekyll" ] && echo yes)"
echo "apt-repo: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
