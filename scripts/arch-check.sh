#!/usr/bin/env bash
# The release workflow's `arch` job run here, on the working tree, before a tag: the package
# built by makepkg from packaging/arch/PKGBUILD on the Arch of the day, installed, one request
# over each protocol, and the unit tests. Arch is rolling, so it is the first place a new
# OpenSSL or GCC is met; the tag of 0.1.0-alpha.144 met OpenSSL 4.1 in the release job, which
# is too late (no Arch package for that release). Nothing runs on GitHub for this.
#
# The working tree is packed as it is (tracked files and new ones git does not ignore, so a
# change not yet committed is checked too) under the name the PKGBUILD downloads, which makepkg
# then takes in place of the download. The tree itself is never mounted: everything is built
# inside the container, and the logs come back to bench/tmp/arch-check/.
#
# usage: scripts/arch-check.sh [-j JOBS]
#   -j  build jobs (default $CMAKE_BUILD_PARALLEL_LEVEL, else ninja's own)
# Exit 0 when every check passed. Needs docker and the network (the image's packages).
set -uo pipefail

if [ "${1:-}" = "--inside" ]; then
  # In the container, as root. /out holds the tarball and takes the logs.
  tag=$2; jobs=$3; owner=$4
  trap 'chown -R "$owner" /out' EXIT
  pass=0; fail=0
  check() { if [ "$3" = "$2" ]; then echo "ok   $1"; pass=$((pass+1)); else echo "FAIL $1: expected [$2] got [$3]"; fail=$((fail+1)); fi; }
  build_env=(env); [ -n "$jobs" ] && build_env+=("CMAKE_BUILD_PARALLEL_LEVEL=$jobs")
  echo "arch-check: $(. /etc/os-release; echo "$PRETTY_NAME"), $(openssl version | cut -d' ' -f1,2), $(gcc --version | head -1), cmake $(cmake --version | sed -n '1s/.* //p')"

  # The job's own steps: the PKGBUILD and its install hooks beside the source, makepkg as the
  # build user with -s, so what the PKGBUILD names and the image lacks is installed as there.
  mkdir -p /home/build/src /home/build/arch
  tar -xzf "/out/agensio-$tag.tar.gz" -C /home/build/src
  src=/home/build/src/agensio-$tag
  cp "$src"/packaging/arch/* "/out/agensio-$tag.tar.gz" /home/build/arch/
  chown -R build /home/build
  cd /home/build/arch || exit 1
  start=$SECONDS
  sudo -u build "${build_env[@]}" makepkg -s --noconfirm > /out/makepkg.log 2>&1
  rc=$?
  check "makepkg builds the package ($((SECONDS - start)) s; makepkg.log)" "0" "$rc"
  [ "$rc" = 0 ] || grep -m5 ' error: ' /out/makepkg.log | cut -c1-240 | sed 's/^/     /'
  pkg=$(ls /home/build/arch/agensio-[0-9]*.pkg.tar.zst 2>/dev/null | head -1)   # not the -debug package
  check "the package file is there" "yes" "$([ -n "$pkg" ] && echo yes)"
  # Not a failure: a deprecation is the notice before a removal, to be read at the check.
  echo "     compiler warnings: $(grep -c 'warning:' /out/makepkg.log), deprecations named by OpenSSL: $(grep -c 'Since OpenSSL' /out/makepkg.log)"
  grep -o "'[^']*' is deprecated: Since OpenSSL [0-9.]*" /out/makepkg.log | sort | uniq -c | sed 's/^/     /'

  if [ -n "$pkg" ]; then
    pacman -U --noconfirm "$pkg" > /out/install.log 2>&1
    check "pacman -U installs it (install.log)" "0" "$?"
    check "account, configuration and unit" "agensio yes yes yes" "$(id -un agensio 2>/dev/null) $([ -f /etc/agensio/agensio.toml ] && echo yes) $([ -f /usr/lib/systemd/system/agensio.service ] && echo yes) $(grep -q /usr/bin/agensio /usr/lib/systemd/system/agensio.service && echo yes)"
    check "agensio -t accepts the packaged configuration" "0" "$(/usr/bin/agensio -t -c /etc/agensio/agensio.toml > /out/config-test.log 2>&1; echo $?)"
    echo "     $(/usr/bin/agensio -v | head -1)"

    # One request over each protocol against the installed binary: the handshake, HTTP/2 and
    # QUIC through this OpenSSL at run time, which the build alone does not show.
    smoke=/home/build/smoke; mkdir -p $smoke/www; echo "arch-check" > $smoke/www/index.html
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout $smoke/key.pem -out $smoke/cert.pem \
      -days 2 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" > /dev/null 2>&1
    cat > $smoke/agensio.toml <<EOF
[server]
workers = 1
protocols = ["h2", "h1", "h3"]
[log]
access = "off"
[[site]]
server_name = ["localhost"]
listen = "127.0.0.1:18443"
root = "$smoke/www"
tls = { cert = "$smoke/cert.pem", key = "$smoke/key.pem" }
default = true
EOF
    chown -R build $smoke
    sudo -u build /usr/bin/agensio -c $smoke/agensio.toml > /out/server.log 2>&1 &
    for _ in $(seq 1 50); do curl -sk -o /dev/null https://127.0.0.1:18443/ && break; sleep 0.1; done
    get() { curl -sk --max-time 10 "$@" -o /dev/null -w '%{http_version} %{http_code}' https://127.0.0.1:18443/; }
    check "HTTP/1.1 over TLS" "1.1 200" "$(get --http1.1)"
    check "HTTP/2" "2 200" "$(get --http2)"
    if curl -V | grep -q HTTP3; then check "HTTP/3" "3 200" "$(get --http3-only)"; else echo "     HTTP/3 not asked: this curl has none"; fi
    pkill -TERM -x agensio; wait 2>/dev/null
  fi

  # The unit tests, which the package build leaves out (AGENSIO_TESTS=OFF there).
  cd "$src" || exit 1
  start=$SECONDS
  sudo -u build "${build_env[@]}" sh -c "cmake -S . -B /home/build/tests -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build /home/build/tests --target agensio_tests" > /out/tests-build.log 2>&1
  rc=$?
  check "the unit tests build ($((SECONDS - start)) s; tests-build.log)" "0" "$rc"
  sudo -u build /home/build/tests/agensio_tests > /out/unit-tests.log 2>&1
  rc=$?   # taken before the label's own command substitution, which would replace it
  check "the unit tests pass (unit-tests.log: $(tail -1 /out/unit-tests.log | cut -c1-80))" "0" "$rc"

  echo "arch-check: $pass passed, $fail failed"
  [ "$fail" = 0 ]; exit
fi

cd "$(dirname "$(readlink -f "$0")")/.."
JOBS=${CMAKE_BUILD_PARALLEL_LEVEL:-}
while getopts "j:" opt; do
  case $opt in j) JOBS=$OPTARG ;; *) exit 2 ;; esac
done
command -v docker > /dev/null || { echo "arch-check: needs docker"; exit 2; }
tag=$(sed -n 's/^_tag=//p' packaging/arch/PKGBUILD)
[ -n "$tag" ] || { echo "arch-check: no _tag in packaging/arch/PKGBUILD"; exit 2; }

docker build -q --pull -t agensio-arch:local --build-arg "REFRESH=$(date +%Y-%m-%d)" -f bench/docker/Dockerfile.arch bench/docker > /dev/null \
  || { echo "arch-check: the image did not build (bench/docker/Dockerfile.arch)"; exit 1; }

OUT=bench/tmp/arch-check
rm -rf "$OUT"; mkdir -p "$OUT"
git ls-files -co --exclude-standard -z \
  | while IFS= read -r -d '' f; do { [ -e "$f" ] || [ -L "$f" ]; } && printf '%s\0' "$f"; done \
  | tar --null -T - --transform "s,^,agensio-$tag/," -czf "$OUT/agensio-$tag.tar.gz" || { echo "arch-check: could not pack the tree"; exit 1; }
cp scripts/arch-check.sh "$OUT/"

echo "arch-check: $(git rev-parse --short HEAD)$(git diff --quiet HEAD 2>/dev/null || echo ' with changes not committed'), logs in $OUT/"
docker run --rm --init -v "$PWD/$OUT:/out" agensio-arch:local bash /out/arch-check.sh --inside "$tag" "$JOBS" "$(id -u):$(id -g)" | tee "$OUT/summary.txt"
exit "${PIPESTATUS[0]}"
