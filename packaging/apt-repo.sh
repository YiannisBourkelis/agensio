#!/usr/bin/env bash
# The signed APT repository of a release (docs/install.md), published by the release workflow on
# GitHub Pages. Two suites:
#   stable  the build without HTTP/3: Debian 12, Ubuntu 22.04 and later (agensio_<v>_amd64.deb)
#   trixie  the +deb13 build with HTTP/3: Debian 13 and later (agensio_<v>+deb13_amd64.deb)
# Pages serves every file through a CDN that keeps it up to ten minutes (Cache-Control:
# max-age=600), so a host may meet the new InRelease with the old index, or the reverse. Two
# measures keep apt from failing then, as Debian's archive does: the indexes are also published
# under their hashes (Acquire-By-Hash) and the previous release's stay beside them; and each suite
# lists the previous release's package with the new one, its file kept in the pool. That also lets
# a host go back: apt install agensio=<previous version>. Older releases are dropped, so the site
# stays the size of two releases.
#
# usage: packaging/apt-repo.sh --out DIR --key KEYID [--previous DIR] DEB...
#   DEB         the release's .deb files, one per suite
#   --out       the site to publish (made empty first): DIR/apt the repository, DIR/agensio.gpg
#               the public key (binary, for signed-by), DIR/index.html, DIR/.nojekyll
#   --key       the signing key's id in gpg's keyring
#   --previous  the site as published (a checkout of the gh-pages branch); none on the first run
# Needs dpkg-deb, apt-ftparchive (apt-utils) and gpg.
set -euo pipefail

out="" key="" previous="" debs=()
while [ $# -gt 0 ]; do
    case "$1" in
        --out) out="${2:?--out needs a directory}"; shift 2;;
        --key) key="${2:?--key needs a key id}"; shift 2;;
        --previous) previous="${2:?--previous needs a directory}"; shift 2;;
        -h|--help) sed -n '2,21p' "$0" | sed 's/^# \{0,1\}//'; exit 0;;
        -*) echo "apt-repo: unknown option $1" >&2; exit 2;;
        *) debs+=("$1"); shift;;
    esac
done
[ -n "$out" ] && [ -n "$key" ] && [ "${#debs[@]}" -gt 0 ] || { echo "usage: packaging/apt-repo.sh --out DIR --key KEYID [--previous DIR] DEB..." >&2; exit 2; }

version_of() { dpkg-deb -f "$1" Version; }
suite_of() { case "$(version_of "$1")" in *+deb13) echo trixie;; *) echo stable;; esac; }

# The files of the two newest versions among the arguments, newest first; for a version given twice
# the first file wins (the release's own, which comes before the previous site's).
newest_two() {
    local files=() versions=() f v i j seen
    for f in "$@"; do
        v=$(version_of "$f"); seen=0
        for i in "${!versions[@]}"; do [ "${versions[$i]}" = "$v" ] && seen=1; done
        [ "$seen" = 1 ] && continue
        files+=("$f"); versions+=("$v")
    done
    for ((i = 0; i < ${#files[@]}; i++)); do  # selection sort, newest first: a handful of files
        for ((j = i + 1; j < ${#files[@]}; j++)); do
            if dpkg --compare-versions "${versions[$j]}" gt "${versions[$i]}"; then
                f=${files[$i]}; files[$i]=${files[$j]}; files[$j]=$f
                v=${versions[$i]}; versions[$i]=${versions[$j]}; versions[$j]=$v
            fi
        done
    done
    printf '%s\n' "${files[@]:0:2}"
}

rm -rf "$out"
mkdir -p "$out/apt"
out=$(cd "$out" && pwd)
for suite in stable trixie; do
    current=()
    for d in "${debs[@]}"; do [ "$(suite_of "$d")" = "$suite" ] && current+=("$d"); done
    [ "${#current[@]}" -eq 1 ] || { echo "apt-repo: need exactly one .deb for suite $suite, got ${#current[@]}" >&2; exit 1; }
    kept=("${current[@]}")
    if [ -n "$previous" ] && [ -d "$previous/apt/pool/$suite" ]; then
        for d in "$previous/apt/pool/$suite"/*.deb; do [ -e "$d" ] && kept+=("$d"); done
    fi
    mkdir -p "$out/apt/pool/$suite" "$out/apt/dists/$suite/main/binary-amd64"
    while IFS= read -r d; do cp "$d" "$out/apt/pool/$suite/"; done < <(newest_two "${kept[@]}")
    # The previous release's indexes under their hashes: those its Release names, no older ones.
    old="$previous/apt/dists/$suite"
    if [ -n "$previous" ] && [ -f "$old/Release" ]; then
        for alg in SHA256 SHA512; do
            mkdir -p "$out/apt/dists/$suite/main/binary-amd64/by-hash/$alg"
            sed -n "/^$alg:/,/^[^ ]/p" "$old/Release" | awk '/ main\/binary-amd64\/Packages/ {print $1}' | while read -r h; do
                f="$old/main/binary-amd64/by-hash/$alg/$h"
                [ -f "$f" ] && cp "$f" "$out/apt/dists/$suite/main/binary-amd64/by-hash/$alg/"
            done
        done
    fi
    (
        cd "$out/apt"
        apt-ftparchive packages "pool/$suite" > "dists/$suite/main/binary-amd64/Packages"
        gzip -9n -k "dists/$suite/main/binary-amd64/Packages"
        apt-ftparchive -o APT::FTPArchive::DoByHash=true \
            -o APT::FTPArchive::Release::Origin=agensio -o APT::FTPArchive::Release::Label=agensio \
            -o APT::FTPArchive::Release::Suite="$suite" -o APT::FTPArchive::Release::Codename="$suite" \
            -o APT::FTPArchive::Release::Architectures=amd64 -o APT::FTPArchive::Release::Components=main \
            -o APT::FTPArchive::Release::Description="agensio web server ($suite)" \
            release "dists/$suite" > "$out/Release.$suite"  # outside the directory it lists
        mv "$out/Release.$suite" "dists/$suite/Release"
        gpg --batch --yes -u "$key" -abs -o "dists/$suite/Release.gpg" "dists/$suite/Release"
        gpg --batch --yes -u "$key" --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
    )
    echo "apt-repo: $suite: $(ls "$out/apt/pool/$suite" | tr '\n' ' ')"
done
gpg --batch --export "$key" > "$out/agensio.gpg"  # binary: what signed-by= reads from a .gpg file
: > "$out/.nojekyll"  # Pages serves the files as they are, no Jekyll build
printf '<!doctype html><title>agensio packages</title><h1>agensio packages</h1><p>APT repository: see <a href="https://github.com/YiannisBourkelis/agensio/blob/main/docs/install.md">docs/install.md</a>.</p>\n' > "$out/index.html"
