#!/usr/bin/env bash
# clang-tidy over src/ using the compile database of the given build dir (default: build).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$ROOT/build}"
TIDY="$(command -v clang-tidy || echo /opt/homebrew/opt/llvm/bin/clang-tidy)"
[ -x "$TIDY" ] || { echo "clang-tidy not found (brew install llvm)"; exit 1; }
[ -f "$BUILD/compile_commands.json" ] || { echo "configure first: cmake -S $ROOT -B $BUILD"; exit 1; }
cd "$ROOT"
"$TIDY" -p "$BUILD" --quiet src/*.cpp "$@"
