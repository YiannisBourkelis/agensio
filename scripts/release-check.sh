#!/usr/bin/env bash
# The release workflow's build jobs run here, on the working tree, before a tag: each in the image
# its job uses, all at once, so a tag never meets a compiler or library no check met. The tag of
# 0.1.0-alpha.147 did: the packages job (Ubuntu 22.04, GCC 12) failed on a library member that only
# GCC 14 has, the release check having built with GCC 14 and 16 alone, and that release went out
# without its Debian 12, Ubuntu 22.04 and Fedora packages or an APT update. scripts/release.sh runs
# this before it commits and tags (--no-check skips it). Nothing runs on GitHub.
#
# The rows mirror the jobs of .github/workflows/release.yml: a change to a job's steps or packages
# changes its row here, or bench/docker/Dockerfile.jammy / Dockerfile.trixie, in the same commit.
#   packages  Ubuntu 22.04, GCC 12, OpenSSL 3.0 (no HTTP/3): the build and the unit tests as a user
#             (the runner's way), the version, the .deb and the .rpm, the .deb installed and checked
#   debian13  Debian 13, its GCC and OpenSSL 3.5: the build with the deb13 suffix and the unit tests
#             as root (the job's container), the version, an h3 configuration accepted, the .deb
#             installed and checked
#   fedora    the packages row's .rpm installed on the day's Fedora and checked, as the job does
#   arch      scripts/arch-check.sh (its logs in bench/tmp/arch-check/)
# The rows build at once: one build waits on a few large files at its end, so two take 84 s where
# one takes 66 (2026-11-18, 24 threads); the whole check takes about as long as its arch row.
#
# The working tree is packed as it is (tracked files and new ones git does not ignore, so a change
# not committed yet is checked, as release.sh's version bump is) and never mounted. Logs in
# bench/tmp/release-check/<row>/; each row's lines in its summary.txt.
#
# usage: scripts/release-check.sh [--version V] [-j JOBS]
#   --version  the version every build must report (release.sh passes the one it tags); by default
#              AGENSIO_VERSION_STRING in CMakeLists.txt
#   -j         build jobs in each row (default ninja's own)
# Exit 0 when every row passed. Needs docker and the network (images, asio, the packages' dependencies).
set -uo pipefail

if [ "${1:-}" = "--inside" ]; then
  # In a row's container, as root. /out takes the row's logs, /src.tar.gz is the tree.
  row=$2; version=$3; jobs=$4; owner=$5
  trap 'chown -R "$owner" /out' EXIT
  pass=0; fail=0
  check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
  errors() { grep ' error: ' "$1" | awk '!seen[$0]++' | head -5 | cut -c1-240 | sed 's/^/     /'; }
  env_jobs=(); [ -n "$jobs" ] && env_jobs=("CMAKE_BUILD_PARALLEL_LEVEL=$jobs")
  echo "$row: $(. /etc/os-release; echo "$PRETTY_NAME")$(command -v openssl > /dev/null && echo ", $(openssl version | cut -d' ' -f1,2)")"

  case $row in
  packages)
    echo "     $(g++-12 --version | head -1), cmake $(cmake --version | sed -n '1s/.* //p')"
    src=/home/build/src; mkdir -p $src && tar -xzf /src.tar.gz -C $src && chown -R build $src
    cd $src || exit 1
    start=$SECONDS
    sudo -u build env CC=gcc-12 CXX=g++-12 "${env_jobs[@]}" \
      sh -c 'cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build' > /out/build.log 2>&1
    rc=$?
    check "configure and build ($((SECONDS - start)) s; build.log)" "0" "$rc"
    [ "$rc" = 0 ] || errors /out/build.log
    grep -E -- '-- (TLS|Basic authentication|HTTP/3)' /out/build.log | sed 's/^-- /     /'
    if [ "$rc" = 0 ]; then
      sudo -u build build/agensio_tests > /out/unit-tests.log 2>&1
      rc=$?
      check "the unit tests pass (unit-tests.log: $(tail -1 /out/unit-tests.log | cut -c1-80))" "0" "$rc"
      check "the binary says the version" "$version" "$(build/agensio -v | awk '{print $2}')"
      (cd build && sudo -u build cpack -G DEB && sudo -u build cpack -G RPM) > /out/cpack.log 2>&1
      check "cpack builds the .deb and the .rpm (cpack.log)" "0" "$?"
      deb=$(ls build/agensio_*_amd64.deb 2>/dev/null | head -1)
      rpm=$(ls build/agensio-*.rpm 2>/dev/null | head -1)
      [ -n "$rpm" ] && cp "$rpm" /out/   # for the fedora row
      echo "     $(basename "${deb:-no .deb}"), $(basename "${rpm:-no .rpm}")"
      if [ -n "$deb" ]; then
        dpkg -i "$deb" > /out/install.log 2>&1
        check "dpkg -i installs the .deb (install.log)" "0" "$?"
        check "account and configuration" "agensio yes yes" \
          "$(id -un agensio 2>/dev/null) $([ -f /etc/agensio/agensio.toml ] && echo yes) $([ -f /etc/agensio/sites.d/default.toml ] && echo yes)"
        check "agensio -t accepts the packaged configuration" "0" "$(/usr/sbin/agensio -t -c /etc/agensio/agensio.toml > /out/config-test.log 2>&1; echo $?)"
        check "the installed binary says the version" "$version" "$(/usr/sbin/agensio -v | awk '{print $2}')"
      fi
    fi
    ;;
  debian13)
    echo "     $(g++ --version | head -1), cmake $(cmake --version | sed -n '1s/.* //p')"
    src=/root/src; mkdir -p $src && tar -xzf /src.tar.gz -C $src
    cd $src || exit 1
    start=$SECONDS
    env "${env_jobs[@]}" sh -c 'cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DAGENSIO_DEB_SUFFIX=deb13 && cmake --build build' > /out/build.log 2>&1
    rc=$?
    check "configure and build ($((SECONDS - start)) s; build.log)" "0" "$rc"
    [ "$rc" = 0 ] || errors /out/build.log
    grep -E -- '-- (TLS|Basic authentication|HTTP/3)' /out/build.log | sed 's/^-- /     /'
    if [ "$rc" = 0 ]; then
      build/agensio_tests > /out/unit-tests.log 2>&1
      rc=$?
      check "the unit tests pass (unit-tests.log: $(tail -1 /out/unit-tests.log | cut -c1-80))" "0" "$rc"
      check "the binary says the version" "$version" "$(build/agensio -v | awk '{print $2}')"
      # The job's own test: a build without the QUIC TLS API refuses "h3" in protocols.
      d=$(mktemp -d); mkdir "$d/www"
      openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 -subj /CN=localhost -keyout "$d/key.pem" -out "$d/cert.pem" 2>/dev/null
      printf '[server]\nprotocols = ["h3", "h2", "h1"]\n[log]\naccess = "off"\n[[site]]\nserver_name = ["localhost"]\nlisten = ["127.0.0.1:8443"]\nroot = "%s/www"\ntls = { cert = "%s/cert.pem", key = "%s/key.pem" }\n' "$d" "$d" "$d" > "$d/h3.toml"
      check "the build accepts h3 in protocols (HTTP/3 built in)" "0" "$(build/agensio -t -c "$d/h3.toml" > /out/h3-test.log 2>&1; echo $?)"
      (cd build && cpack -G DEB) > /out/cpack.log 2>&1
      check "cpack builds the .deb (cpack.log)" "0" "$?"
      deb=$(ls build/agensio_*+deb13_amd64.deb 2>/dev/null | head -1)
      echo "     $(basename "${deb:-no .deb}")"
      if [ -n "$deb" ]; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "./$deb" > /out/install.log 2>&1
        check "apt-get installs the .deb (install.log)" "0" "$?"
        check "account and configuration" "agensio yes yes" \
          "$(id -un agensio 2>/dev/null) $([ -f /etc/agensio/agensio.toml ] && echo yes) $([ -f /etc/agensio/sites.d/default.toml ] && echo yes)"
        check "agensio -t accepts the packaged configuration" "0" "$(/usr/sbin/agensio -t -c /etc/agensio/agensio.toml > /out/config-test.log 2>&1; echo $?)"
        check "the installed binary says the version" "$version" "$(/usr/sbin/agensio -v | awk '{print $2}')"
      fi
    fi
    ;;
  fedora)
    rpm=$(ls /rpm/agensio-*.rpm 2>/dev/null | head -1)
    check "the packages row left an .rpm" "yes" "$([ -n "$rpm" ] && echo yes)"
    if [ -n "$rpm" ]; then
      dnf install -y "$rpm" > /out/install.log 2>&1
      check "dnf installs the .rpm (install.log)" "0" "$?"
      check "account, configuration, unit and logrotate" "agensio yes yes yes yes" \
        "$(id -un agensio 2>/dev/null) $([ -f /etc/agensio/agensio.toml ] && echo yes) $([ -f /etc/agensio/sites.d/default.toml ] && echo yes) $([ -f /usr/lib/systemd/system/agensio.service ] && echo yes) $([ -f /etc/logrotate.d/agensio ] && echo yes)"
      check "agensio -t accepts the packaged configuration" "0" "$(/usr/sbin/agensio -t -c /etc/agensio/agensio.toml > /out/config-test.log 2>&1; echo $?)"
      check "the installed binary says the version" "$version" "$(/usr/sbin/agensio -v | awk '{print $2}')"
      echo "     $(rpm -qi agensio | grep -E '^(Version|Release)' | tr -s ' ' | paste -sd ',' -)"
    fi
    ;;
  esac
  echo "$row: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

cd "$(dirname "$(readlink -f "$0")")/.."
JOBS=${CMAKE_BUILD_PARALLEL_LEVEL:-}
version=""
while [ $# -gt 0 ]; do
  case $1 in
    --version) version=${2:-}; shift 2 ;;
    -j) JOBS=${2:-}; shift 2 ;;
    *) echo "usage: scripts/release-check.sh [--version V] [-j JOBS]"; exit 2 ;;
  esac
done
[ -n "$version" ] || version=$(sed -n 's/^set(AGENSIO_VERSION_STRING "\([^"]*\)").*/\1/p' CMakeLists.txt)
command -v docker > /dev/null || { echo "release-check: needs docker"; exit 2; }

OUT=bench/tmp/release-check
rm -rf -- "${OUT:?}"; mkdir -p "$OUT"/packages "$OUT"/debian13 "$OUT"/fedora "$OUT"/arch
day=$(date +%Y-%m-%d)
for img in jammy trixie; do
  docker build -q --pull -t "agensio-$img:local" --build-arg "REFRESH=$day" -f "bench/docker/Dockerfile.$img" bench/docker > /dev/null \
    || { echo "release-check: the image did not build (bench/docker/Dockerfile.$img)"; exit 1; }
done
docker pull -q fedora:latest > /dev/null || { echo "release-check: could not pull fedora:latest"; exit 1; }

git ls-files -co --exclude-standard -z \
  | while IFS= read -r -d '' f; do { [ -e "$f" ] || [ -L "$f" ]; } && printf '%s\0' "$f"; done \
  | tar --null -T - -czf "$OUT/src.tar.gz" || { echo "release-check: could not pack the tree"; exit 1; }
cp scripts/release-check.sh "$OUT/"

owner="$(id -u):$(id -g)"
echo "release-check: $(git rev-parse --short HEAD)$(git diff --quiet HEAD 2>/dev/null || echo ' with changes not committed'), version $version, logs in $OUT/"
row() {  # name image [docker options]
  local name=$1 image=$2; shift 2
  docker run --rm --init "$@" -v "$PWD/$OUT/$name:/out" -v "$PWD/$OUT/src.tar.gz:/src.tar.gz:ro" \
    -v "$PWD/$OUT/release-check.sh:/release-check.sh:ro" "$image" \
    bash /release-check.sh --inside "$name" "$version" "$JOBS" "$owner" > "$OUT/$name/summary.txt" 2>&1
}
start=$SECONDS
row packages agensio-jammy:local & p_packages=$!
row debian13 agensio-trixie:local & p_debian13=$!
scripts/arch-check.sh ${JOBS:+-j "$JOBS"} > "$OUT/arch/summary.txt" 2>&1 & p_arch=$!

failed=()
report() {  # name status
  cat "$OUT/$1/summary.txt"
  [ "$2" = 0 ] || failed+=("$1")
}
wait $p_packages; s=$?
report packages $s
if ls "$OUT"/packages/agensio-*.rpm > /dev/null 2>&1; then
  row fedora fedora:latest -v "$PWD/$OUT/packages:/rpm:ro" & p_fedora=$!
else
  echo "fedora: not run, the packages row made no .rpm" > "$OUT/fedora/summary.txt"; p_fedora=""
fi
wait $p_debian13; s=$?; report debian13 $s
if [ -n "$p_fedora" ]; then wait $p_fedora; s=$?; else s=1; fi
report fedora $s
wait $p_arch; s=$?; report arch $s

if [ ${#failed[@]} = 0 ]; then
  echo "release-check: every row passed ($((SECONDS - start)) s)"
else
  echo "release-check: FAILED: ${failed[*]} ($((SECONDS - start)) s; logs in $OUT/)"
  exit 1
fi
