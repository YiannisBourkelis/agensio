#!/usr/bin/env bash
# Cut a release: set the version everywhere it lives, check the changelog has its
# section, build and run the unit tests, commit, tag and push. The release workflow on
# GitHub then builds the packages and attaches them to the release.
#
# usage: scripts/release.sh [version] [--dry-run] [--no-push]
#   version   X.Y.Z or X.Y.Z-<pre>.<n> (alpha.2, beta.1, rc.1); the tag is v<version>.
#             Without it the next version is suggested from the current one (alpha.1 ->
#             alpha.2, 0.1.0 -> 0.1.1) and you can accept it with Enter or type another;
#             a current version that was never tagged (a run that stopped after setting it)
#             is suggested again, and skipping it needs a confirmation.
# The changelog stops a run that would publish the wrong notes: another version's section
# without a release date (renamed or merged first), or the draft this script inserts, still
# carrying its marker line (alpha.68 shipped a commit list and skipped alpha.67 that way).
#   --dry-run show what would change, touch nothing
#   --no-push commit and tag, do not push
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")/.."
version=""; dry=0; push=1
for a in "$@"; do
    case "$a" in
        --dry-run) dry=1;;
        --no-push) push=0;;
        -*) echo "unknown option $a"; exit 2;;
        *) version="$a";;
    esac
done

# The current version, from the source (what the last release set), and the next one.
current=$(sed -n 's/^set(AGENSIO_VERSION_STRING "\([^"]*\)").*/\1/p' CMakeLists.txt)
suggest() {
    local cur="$1"
    if [[ "$cur" =~ ^([0-9]+\.[0-9]+\.[0-9]+)-(alpha|beta|rc)\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}-${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
    elif [[ "$cur" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.$((BASH_REMATCH[3] + 1))"
    fi
}
# A version string without its tag was set by a run that stopped before tagging (a failing
# unit test): it is still the version to release.
untagged=""
git rev-parse -q --verify "refs/tags/v$current" > /dev/null || untagged="$current"
if [ -z "$version" ]; then
    if [ -n "$untagged" ]; then next="$current"; else next=$(suggest "$current"); fi
    [ -n "$next" ] || { echo "cannot derive the next version from '$current'; pass one"; exit 2; }
    if [ -t 0 ]; then
        read -r -p "current version is $current${untagged:+ (never tagged: a run stopped before its tag)}; next version [$next]: " answer
        version="${answer:-$next}"
    else
        version="$next"
    fi
fi
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || { echo "usage: $0 [X.Y.Z[-alpha.N|-beta.N|-rc.N]] [--dry-run] [--no-push]  (got '$version')"; exit 2; }
base="${version%%-*}"                       # 0.1.0
pre="${version#"$base"}"; pre="${pre#-}"     # alpha.2 or ""
tag="v$version"
today=$(date +%Y-%m-%d)

say() { printf '%s\n' "$*"; }
fail() { say "error: $*"; exit 1; }

if [ -n "$untagged" ] && [ "$version" != "$untagged" ]; then
    say "note: $untagged, the version in CMakeLists.txt, was never tagged; releasing $version skips it"
    if [ $dry = 0 ]; then
        [ -t 0 ] || fail "pass $untagged to release it, or run in a terminal to confirm skipping it"
        read -r -p "skip $untagged and release $version? [y/N] " answer
        [[ "$answer" =~ ^[Yy] ]] || fail "stopped; nothing changed"
    fi
fi

# 0. Every other section of the changelog is a release, with its date: one without (a version
#    planned under another number, "(unreleased)") is renamed to this version or merged into
#    it first, so its notes are not left behind.
undated=$(grep -E '^## [0-9]' CHANGELOG.md | grep -vE '\([0-9]{4}-[0-9]{2}-[0-9]{2}\)[[:space:]]*$' |
          grep -vE "^## ${version//./\\.}( \(.*\))?[[:space:]]*$" || true)
[ -z "$undated" ] || fail "CHANGELOG.md has a section for another version, not released:
$undated
rename it to $version or merge it into the $version section, then run again"
draft_mark='<!-- draft from the commit subjects: edit the notes, then delete this line -->'

# 1. The changelog must describe the version. When it does not, a draft is inserted from
#    the commit subjects since the previous tag (merges and release commits left out),
#    for you to edit; the script stops so the notes are reviewed before anything is tagged.
# A section written by hand counts whatever its heading says after the version:
# "## 0.1.0-alpha.10", "## 0.1.0-alpha.10 (unreleased)" or "## 0.1.0-alpha.10 (2026-09-20)";
# the date is stamped in below.
if grep -qE "^## $version( \(.*\))?\s*$" CHANGELOG.md; then
    section=$(awk -v v="$version" '/^## / { if (on) exit; h = $0; sub(/^## /, "", h); sub(/ \(.*\)[[:space:]]*$/, "", h); sub(/[[:space:]]+$/, "", h); on = (h == v); next } on' CHANGELOG.md)
    if grep -qF -- "$draft_mark" <<< "$section"; then
        fail "the $version section of CHANGELOG.md is still the draft of commit subjects: write the notes, delete its marker line, then run again"
    fi
    say "CHANGELOG.md has a $version section: using it as written (its date becomes $today)"
else
    say "CHANGELOG.md has no '## $version' section."
    last=$(git describe --tags --abbrev=0 2>/dev/null || true)
    range=${last:+$last..HEAD}
    draft=$(git log --no-merges --pretty='- %s' $range | grep -v '^- Release v' || true)
    [ -n "$draft" ] || draft="- "
    if [ $dry = 0 ] && [ -t 0 ]; then
        say "draft from the $(git rev-list --count --no-merges ${range:-HEAD}) commit(s) since ${last:-the beginning}:"
        say "$draft"
        read -r -p "insert this as the section at the top for you to edit, then stop? [Y/n] " answer
        if [[ ! "$answer" =~ ^[Nn] ]]; then
            { printf '# Changelog\n\n## %s (%s)\n\n%s\n\n%s\n\n' "$version" "$today" "$draft_mark" "$draft"; tail -n +2 CHANGELOG.md | sed '1{/^$/d}'; } > CHANGELOG.md.new
            mv CHANGELOG.md.new CHANGELOG.md
            say "inserted; write the notes from it, delete the marker line (no commit needed, it goes into the release commit) and run $0 $version again"
            exit 1
        fi
    fi
    fail "write the changelog section first (a draft: git log --no-merges --pretty='- %s' ${range:-HEAD})"
fi

# 2. What changes.
say "release $tag  (current version string: $current)"
say "  CMakeLists.txt           AGENSIO_VERSION_STRING -> $version"
say "  packaging/arch/PKGBUILD  _tag -> $version, pkgver -> ${base}${pre//./}"
if [ -n "$pre" ]; then rpm_release="0.1.$pre"; else rpm_release="1"; fi
say "  packaging/rpm/agensio.spec  upstream_version -> $version, Version -> $base, Release -> $rpm_release, changelog entry"
say "  CHANGELOG.md             date of the $version section -> $today"
say "  git: commit 'Release $tag', annotated tag $tag$([ $push = 1 ] && echo ', push main and the tag')"
# The release commit carries the version bump and the changelog: an edited CHANGELOG.md
# may be pending, nothing else.
pending=$(git status --porcelain | grep -v ' CHANGELOG.md$' || true)
if [ $dry = 1 ]; then
    [ -z "$pending" ] || say "note: the tree has other changes; commit them before the real run"
    say "dry run: nothing changed"
    exit 0
fi

# 3. Only the changelog may be uncommitted.
[ -z "$pending" ] || fail "commit or stash your other changes first:
$pending"
git rev-parse -q --verify "refs/tags/$tag" >/dev/null && fail "tag $tag already exists"
[ "$(git rev-parse --abbrev-ref HEAD)" = main ] || fail "release from main (you are on $(git rev-parse --abbrev-ref HEAD))"

# 4. Edit.
sed -i "s/^set(AGENSIO_VERSION_STRING \"[^\"]*\")/set(AGENSIO_VERSION_STRING \"$version\")/" CMakeLists.txt
sed -i "s/^_tag=.*/_tag=$version/; s/^pkgver=.*/pkgver=${base}${pre//./}/; s/^pkgrel=.*/pkgrel=1/" packaging/arch/PKGBUILD
sed -i "s/^%global upstream_version .*/%global upstream_version $version/; s/^Version:        .*/Version:        $base/; s/^Release:        .*/Release:        ${rpm_release}%{?dist}/" packaging/rpm/agensio.spec
entry="* $(LC_ALL=C date '+%a %b %d %Y') Yiannis Bourkelis - $base-$rpm_release\n- Release $version, see CHANGELOG.md."
# Once: a run that stopped before its commit (a failing test) has added it already.
grep -qxF -- "- Release $version, see CHANGELOG.md." packaging/rpm/agensio.spec ||
    sed -i "s/^%changelog$/%changelog\n$entry\n/" packaging/rpm/agensio.spec
sed -i -E "s/^## $version( \(.*\))?\s*$/## $version ($today)/" CHANGELOG.md

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
