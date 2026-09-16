#!/usr/bin/env bash
# clang-tidy over src/ using the compile database of the given build dir (default: build).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="${1:-$ROOT/build}"
TIDY="$(command -v clang-tidy || echo /opt/homebrew/opt/llvm/bin/clang-tidy)"
[ -x "$TIDY" ] || { echo "clang-tidy not found (brew install llvm)"; exit 1; }
[ -f "$BUILD/compile_commands.json" ] || { echo "configure first: cmake -S $ROOT -B $BUILD"; exit 1; }
cd "$ROOT"
EXTRA=()
if [ "$(uname)" = "Darwin" ]; then
  # Homebrew's clang-tidy does not know the Apple SDK; point it at the standard headers.
  EXTRA+=(--extra-arg="-isysroot$(xcrun --show-sdk-path)")
fi
"$TIDY" -p "$BUILD" --quiet "${EXTRA[@]}" src/*.cpp "$@"
