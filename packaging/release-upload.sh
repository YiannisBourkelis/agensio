#!/usr/bin/env bash
# Attaches files to the GitHub release of the tag being built (.github/workflows/release.yml),
# creating the release first when no job has yet: the packages job (Ubuntu 22.04, the .deb for
# Debian 12 and later) and the debian13 job (the .deb with HTTP/3) run in parallel, so whichever
# finishes first creates it, with the version's section of CHANGELOG.md as its notes, and neither
# waits for the other. Needs GH_TOKEN, GITHUB_REF_NAME and GITHUB_REPOSITORY (the workflow sets them).
# usage: packaging/release-upload.sh FILE...
set -euo pipefail
[ $# -ge 1 ] || { echo "usage: $0 FILE..." >&2; exit 2; }
version="${GITHUB_REF_NAME#v}"
if ! gh release view "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" >/dev/null 2>&1; then
  awk -v v="$version" '$0 ~ "^## " v " " {on=1; next} /^## / {on=0} on' CHANGELOG.md > notes.md
  [ -s notes.md ] || echo "See CHANGELOG.md." > notes.md
  pre=""; case "$version" in *-*) pre="--prerelease";; esac
  # The other job may create it between the view and the create: then that release is the one.
  gh release create "$GITHUB_REF_NAME" $pre --title "$version" --notes-file notes.md -R "$GITHUB_REPOSITORY" ||
    gh release view "$GITHUB_REF_NAME" -R "$GITHUB_REPOSITORY" >/dev/null
fi
gh release upload "$GITHUB_REF_NAME" "$@" --clobber -R "$GITHUB_REPOSITORY"
