#!/usr/bin/env bash
# clang-format: `scripts/format.sh` checks, `scripts/format.sh --fix` rewrites.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
FILES=$(git ls-files 'src/*.cpp' 'src/*.hpp' 'tests/*.cpp')
if [ "${1:-}" = "--fix" ]; then
  clang-format -i $FILES
else
  clang-format --dry-run --Werror $FILES
fi
