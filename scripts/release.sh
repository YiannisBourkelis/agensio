#!/usr/bin/env bash
# Cut a release: set the version everywhere it lives, check the changelog has its
# section, build and run the unit tests, commit, tag and push. The release workflow on
# GitHub then builds the packages and attaches them to the release.
#
# usage: scripts/release.sh 0.1.0-alpha.2 [--dry-run] [--no-push]
#   version   X.Y.Z or X.Y.Z-<pre>.<n> (alpha.2, beta.1, rc.1); the tag is v<version>
#   --dry-run show what would change, touch nothing
#   --no-push commit and tag, do not push
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
version="${1:-}"; dry=0; push=1
for a in "${@:2}"; do case "$a" in --dry-run) dry=1;; --no-push) push=0;; *) echo "unknown option $a"; exit 2;; esac; done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || { echo "usage: $0 X.Y.Z[-alpha.N|-beta.N|-rc.N] [--dry-run] [--no-push]"; exit 2; }
base="${version%%-*}"                       # 0.1.0
pre="${version#"$base"}"; pre="${pre#-}"     # alpha.2 or ""
tag="v$version"
today=$(date +%Y-%m-%d)

say() { printf '%s\n' "$*"; }
fail() { say "error: $*"; exit 1; }

# 1. The changelog must already describe the version.
grep -q "^## $version " CHANGELOG.md || fail "CHANGELOG.md has no '## $version (date)' section; write it first"

# 2. What changes.
current=$(sed -n 's/^set(AGENSIO_VERSION_STRING "\([^"]*\)").*/\1/p' CMakeLists.txt)
say "release $tag  (current version string: $current)"
say "  CMakeLists.txt           AGENSIO_VERSION_STRING -> $version"
say "  packaging/arch/PKGBUILD  _tag -> $version, pkgver -> ${base}${pre//./}"
if [ -n "$pre" ]; then rpm_release="0.1.$pre"; else rpm_release="1"; fi
say "  packaging/rpm/agensio.spec  upstream_version -> $version, Version -> $base, Release -> $rpm_release, changelog entry"
say "  CHANGELOG.md             date of the $version section -> $today"
say "  git: commit 'Release $tag', annotated tag $tag$([ $push = 1 ] && echo ', push main and the tag')"
if [ $dry = 1 ]; then
    [ -z "$(git status --porcelain)" ] || say "note: the tree is not clean; commit before the real run"
    say "dry run: nothing changed"
    exit 0
fi

# 3. The tree must be committed: the release commit carries only the version bump.
[ -z "$(git status --porcelain)" ] || fail "commit or stash your changes first (git status is not clean)"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && fail "tag $tag already exists"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "release from main (you are on $(git rev-parse --abbrev-ref HEAD))"

# 4. Edit.
sed -i "s/^set(AGENSIO_VERSION_STRING \"[^\"]*\")/set(AGENSIO_VERSION_STRING \"$version\")/" CMakeLists.txt
sed -i "s/^_tag=.*/_tag=$version/; s/^pkgver=.*/pkgver=${base}${pre//./}/; s/^pkgrel=.*/pkgrel=1/" packaging/arch/PKGBUILD
sed -i "s/^%global upstream_version .*/%global upstream_version $version/; s/^Version:        .*/Version:        $base/; s/^Release:        .*/Release:        ${rpm_release}%{?dist}/" packaging/rpm/agensio.spec
entry="* $(LC_ALL=C date '+%a %b %d %Y') Yiannis Bourkelis - $base-$rpm_release\n- Release $version, see CHANGELOG.md."
sed -i "s/^%changelog$/%changelog\n$entry\n/" packaging/rpm/agensio.spec
sed -i "s/^## $version (.*)$/## $version ($today)/" CHANGELOG.md

# 5. Build and test with the new version string.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release > /dev/null
cmake --build build > /dev/null
built=$(build/agensio -v | awk '{print $2}')
[ "$built" = "$version" ] || fail "binary says $built after the bump"
build/agensio_tests | tail -1

# 6. Commit, tag, push.
git add CMakeLists.txt packaging/arch/PKGBUILD packaging/rpm/agensio.spec CHANGELOG.md
git commit -q -m "Release $tag" -m "$(sed -n "/^## $version /,/^## /p" CHANGELOG.md | sed '$d' | tail -n +2)"
git tag -a "$tag" -m "agensio $version"
say "committed and tagged $tag"
if [ $push = 1 ]; then
    git push origin main "$tag"
    say "pushed; the release workflow builds the packages: https://github.com/YiannisBourkelis/agensio/actions"
    say "then create the release page from the tag (or let the workflow's upload create it): https://github.com/YiannisBourkelis/agensio/releases/new?tag=$tag"
else
    say "not pushed (--no-push): git push origin main $tag"
fi
