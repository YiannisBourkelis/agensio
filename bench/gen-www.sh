#!/usr/bin/env bash
# Generates the static docroot used by every server in the benchmark.
set -euo pipefail
cd "$(dirname "$0")/www"

# 1 KB HTML page
{
  printf '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n<title>agensio benchmark</title>\n<link rel="stylesheet" href="/style.css">\n</head>\n<body>\n<h1>agensio benchmark page</h1>\n'
  for i in $(seq 1 12); do printf '<p>Paragraph %02d: the quick brown fox jumps over the lazy dog.</p>\n' "$i"; done
  printf '</body>\n</html>\n'
} > index.html

# ~100 KB CSS-like text
python3 - <<'PY'
lines = []
i = 0
while sum(len(l) + 1 for l in lines) < 100 * 1024:
    lines.append(f".c{i} {{ margin: {i % 17}px; padding: {i % 7}px; color: #{i % 4096:03x}; }}")
    i += 1
open("style.css", "w").write("\n".join(lines) + "\n")
PY

# 10 MB binary (above the cache max_file_size, exercises the streaming path)
head -c $((10 * 1024 * 1024)) /dev/urandom > big.bin

mkdir -p sub
printf '<html><body>sub index</body></html>\n' > sub/index.html

ls -la
