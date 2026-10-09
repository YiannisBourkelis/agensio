#!/usr/bin/env bash
# The configuration cookbook (docs/examples.md, docs/examples/*.md) held to the binary: every
# recipe loads with `agensio -t`, its `agensio ctl` lines and MCP names exist, its links resolve
# and the index lists it (tests/examples.py says how). Run by tests/integration.sh; alone:
# usage: tests/examples.sh build/agensio
set -uo pipefail
exec python3 -I "$(dirname "$0")/examples.py" "${1:-build/agensio}"
