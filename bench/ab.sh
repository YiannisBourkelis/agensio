#!/usr/bin/env bash
# A/B checkpoint: the binary in build/ against one built from a base git ref, alternated
# in the same session so that run-to-run drift cancels out. This is the gate for every
# phase checkpoint and every change on the request path (see CLAUDE.md).
#
# usage: bench/ab.sh <base-ref> [-r ROUNDS] [-d DURATION] [-t THREADS] [-w WORKERS] [-2] [-3] [-P] [-A] [-C] [-u URLSPEC ...]
#   base-ref  commit, branch or tag to build as the "base" side (worktree under bench/tmp/ab/)
#   -2        HTTP/2 gate (phase G): adds the rows "h2c:/:64:1", "h2c:/:64:10", "h2:/:64:1" and
#             "h2:/:64:10" measured with h2load (proto:path:connections:streams; h2c is prior
#             knowledge on 8080, h2 is ALPN on 8443). A base without HTTP/2 gets none of them.
#             Run it for every change under src/http2/ together with the static rows, which
#             must stay flat: HTTP/1 pays nothing for HTTP/2.
#   -P        proxy gate (phase D): also start the benchmark upstream (build/agensio_upstream on
#             127.0.0.1:9100) and add the proxy rows "proxy:/json:64", "proxy:/big:64" and
#             "proxy:/slow?ms=20:256" through the proxy site of bench/proxy/ab-site.toml, on
#             127.0.0.1:8093. Run it for every change under src/upstream/http*, src/handlers/proxy*.
#             A base that cannot load the proxy site (pre-D1) runs the static rows only.
#   -A        access gate (docs/configuration.md 19): two more sites with [[site.access]] rules and
#             their rows: "access:/:64" (127.0.0.1:8094, a site with a rule on /wp-admin and an exact
#             one on /wp-login.php, benchmarked on /: a public page of a site with rules, one bit test,
#             and, since alpha.59, the router asked which script a directory runs, the cost an exact
#             rule adds, access::script_of) and "access-all:/:64"
#             (127.0.0.1:8095, the whole site restricted by 64 entries with 127.0.0.1 last: the most
#             an admitted request pays). A base without the feature ignores the rules and serves the
#             same files, so new/base is the check's cost. Run it for every change to core/access.hpp
#             and the access step of handlers/dispatch.cpp. Also "refuse:/sub/index.html:64"
#             (127.0.0.1:8097, a site with the 48 refuse patterns TYPO3's documentation lists,
#             benchmarked on a two-segment path none of them refuses: the matching's cost; a base
#             without `refuse` ignores the key and serves the same file). core/refuse.hpp too.
#             And "auth:/:64" (127.0.0.1:8096, [[site.auth]] on the whole site, wrk sending a
#             remembered login with every request): what a protected page costs per request.
#             And "hsts:/:64" (https://127.0.0.1:8449, a TLS site sending HSTS on the 1 KB answer:
#             the site's hsts key, or for a base before 0.1.0-alpha.75 a / location's add_headers):
#             what the per-request site fields cost on the HTTP/1 path.
#             And "redir-miss:/:64" (127.0.0.1:8098, a site with 1,000 exact [[site.redirect]] rules,
#             benchmarked on a path none of them names: what rules cost a request they do not meet; a
#             base before 0.1.0-alpha.82 gets the same site without rules) and "redir-hit:/x:64"
#             (127.0.0.1:8099, a rule from / to another host, a 301 per request; a base before
#             alpha.82 gets the whole-domain `redirect = "https://..."` key, the same answer).
#             And "headers:/sub/index.html:64" (127.0.0.1:8092, [[site.response_headers]] at / and
#             at /sub/, benchmarked on a file under the deeper rule: the node lookup and the fields
#             on a cached file's HTTP/1 answer, and since 0.1.0-alpha.90 a rule with endings for
#             html files; a base before endings gets that field from a rule without them, one before
#             0.1.0-alpha.89 all of them from a location's add_headers: the same bytes on both sides,
#             so the row measures the rules). And "baseline:/:64" (127.0.0.1:8090, a site with
#             app = "static" serving its cached 1 KB index.html, the same file on both sides: from
#             0.1.0-alpha.94 its security baseline, three fields through a node at / with the html
#             ending, against none before: what a static site pays for the baseline on upgrading).
#             And "exact:/sub/index.html:64" (127.0.0.1:8088, sixteen exact .php locations that deny,
#             a long rules.private, before a cached file: the router's pass over exact locations,
#             from 0.1.0-alpha.109 also asking whether the path is one's path-info form).
#             With -P also "proxy-hdr:/json:64" (127.0.0.1:8091, the benchmark
#             upstream behind a site with set, default and remove rules: the upstream loop's half)
#             and "proxy-cache:/json:64" (127.0.0.1:8089, the same site with a success-only
#             Cache-Control set too, the same bytes on both sides: from 0.1.0-alpha.99 the read of
#             the answer's fields a cache decision adds before that loop, docs/headers.md 2.4).
#   -3        HTTP/3 gate (phase I): the rows "h3:/:64:1", "h3:/:64:10", "h3:/:64:64" and
#             "h3:/style.css:64:10" with h2load over QUIC on 8443 (H2LOAD_H3); run with -r 3, two
#             rounds of the h3 rows swing 15 % on the same code (CLAUDE.md).
#   -C        response compression gate (docs/design-compression.md 10): a site with the key on
#             (127.0.0.1:8087, TLS on 8486) asked with a browser's Accept-Encoding, "comp:/:64" (the
#             1 KB page under min_size: identity with Vary, must be flat against the plain row),
#             "comp:/style.css:64" (the 100 KB CSS from its brotli copy), "comp-gzip:/style.css:64"
#             (its gzip copy, a tool taking gzip alone), "comp-plain:/style.css:64" (no header: the
#             file's own bytes with Vary, flat), "comp-tls:/style.css:64" and with -2
#             "comp-h2:/style.css:64:10" (the copy over TLS and HTTP/2). With -P the proxy site with
#             the key on (127.0.0.1:8085): "proxy-comp:/json:64" (33 bytes, the decision alone),
#             "proxy-comp:/page:64" (the upstream's 32 KB page compressed whole per request: the
#             encoder's cost), "proxy-comp:/big:64" (100 KB, above the whole-answer limit: identity
#             with Vary until step 6) and "proxy-comp-plain:/page:64" (no header, flat). A side whose
#             binary lacks the key skips the rows.
#   -r        rounds of base/new alternation (default 2)
#   -d        wrk duration per case (default 5s)
#   -t        wrk threads (default 4)
#   -w        agensio workers (default 1: one core saturated, so CPU us/req is exact)
#   -u        "proto:path:conns", repeatable; default: the four small rows plus the two streams
# The metric is server CPU microseconds per request (CPU time of the agensio process over
# wrk's request count). Summary goes to bench/results/ab-<stamp>.md, raw wrk output to
# bench/results/raw/ab-<stamp>/. Paste the summary table into the commit message.
set -euo pipefail

BENCH="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(dirname "$BENCH")"
[ $# -ge 1 ] || { sed -n '2,16p' "$0"; exit 2; }
BASE_REF="$1"; shift
ROUNDS=2; DURATION=5s; THREADS=4; WORKERS=1; SPECS=(); PROXY=0; H2=0; H3=0; ACCESS=0; COMP=0
while getopts "r:d:t:w:u:P23AC" opt; do
  case $opt in
    r) ROUNDS=$OPTARG ;; d) DURATION=$OPTARG ;; t) THREADS=$OPTARG ;; w) WORKERS=$OPTARG ;;
    u) SPECS+=("$OPTARG") ;; P) PROXY=1 ;; 2) H2=1 ;; 3) H3=1 ;; A) ACCESS=1 ;; C) COMP=1 ;; *) exit 2 ;;
  esac
done
[ ${#SPECS[@]} -eq 0 ] && SPECS=("http:/:64" "http:/style.css:64" "https:/:64" "https:/style.css:64" "http:/big.bin:16" "https:/big.bin:16")
if [ $PROXY = 1 ]; then
  [ -x "$ROOT/build/agensio_upstream" ] || { echo "build/agensio_upstream missing: cmake --build build --target agensio_upstream"; exit 1; }
  [ -f "$BENCH/proxy/ab-site.toml" ] || { echo "bench/proxy/ab-site.toml missing (the proxy site for the gate, phase D1)"; exit 1; }
  SPECS+=("proxy:/json:64" "proxy:/big:64" "proxy:/slow?ms=20:256")
  [ $ACCESS = 1 ] && SPECS+=("proxy-hdr:/json:64" "proxy-cache:/json:64")
  # -C with -P: the proxy site with response_compression on, on 8085 (docs/design-compression.md 10),
  # asked with a browser's header: the upstream's 33-byte JSON (under min_size: the decision alone,
  # must be flat), its 32 KB page compressed whole per request (the encoder's cost), its 100 KB body
  # (above the whole-answer limit: identity with Vary until step 6, must be flat), and the page
  # without a header (the decision runs, nothing is compressed, must be flat).
  [ $COMP = 1 ] && SPECS+=("proxy-comp:/json:64" "proxy-comp:/page:64" "proxy-comp:/big:64" "proxy-comp-plain:/page:64")
fi

if [ $H2 = 1 ]; then
  command -v h2load >/dev/null || { echo "missing tool: h2load (Debian: nghttp2-client)"; exit 1; }
  SPECS+=("h2c:/:64:1" "h2c:/:64:10" "h2:/:64:1" "h2:/:64:10")
fi
# HTTP/3 rows (phase I): an h2load built with QUIC (H2LOAD_H3; the devbox's /opt/nghttp2/bin/h2load),
# --alpn-list=h3 against the TLS port over UDP; a side without h3 gets no such rows.
H2LOAD_H3="${H2LOAD_H3:-$( [ -x /opt/nghttp2/bin/h2load ] && echo /opt/nghttp2/bin/h2load || echo h2load )}"
if [ $H3 = 1 ]; then
  $H2LOAD_H3 --help 2>&1 | grep -q 'udp-gso' || { echo "$H2LOAD_H3 has no QUIC support (set H2LOAD_H3)"; exit 1; }
  curl -V 2>/dev/null | grep -q HTTP3 || { echo "curl without HTTP/3: cannot probe the sides"; exit 1; }
  SPECS+=("h3:/:64:1" "h3:/:64:10" "h3:/:64:64" "h3:/style.css:64:10")
fi
for tool in wrk curl nc git cmake; do command -v "$tool" >/dev/null || { echo "missing tool: $tool"; exit 1; }; done
[ -x "$ROOT/build/agensio" ] || { echo "build the new side first: cmake --build build"; exit 1; }
[ -f "$BENCH/www/big.bin" ] || "$BENCH/gen-www.sh" >/dev/null
[ -f "$BENCH/certs/cert.pem" ] || "$BENCH/certs/gen-cert.sh" >/dev/null
ulimit -n 65536 2>/dev/null || true

# ---- base side: worktree + Release build (reuses the fetched asio of the main build) ----
# The commit, also for an annotated tag (whose own object a plain rev-parse names): the label of
# the results and the worktree's directory, shared by a tag and its commit.
BASE_SHA="$(git -C "$ROOT" rev-parse --short "$BASE_REF^{commit}")"
BASE_DIR="$BENCH/tmp/ab/$BASE_SHA"
if [ ! -d "$BASE_DIR" ]; then
  git -C "$ROOT" worktree add --detach "$BASE_DIR" "$BASE_SHA" >/dev/null
fi
if [ ! -x "$BASE_DIR/build/agensio" ]; then
  echo "building base $BASE_SHA"
  ASIO_SRC="$ROOT/build/_deps/asio-src"
  extra=""; [ -d "$ASIO_SRC" ] && extra="-DFETCHCONTENT_SOURCE_DIR_ASIO=$ASIO_SRC"
  cmake -S "$BASE_DIR" -B "$BASE_DIR/build" -G Ninja -DCMAKE_BUILD_TYPE=Release -DAGENSIO_TESTS=OFF $extra >/dev/null
  cmake --build "$BASE_DIR/build" >/dev/null
fi
NEW_SHA="$(git -C "$ROOT" rev-parse --short HEAD)$(git -C "$ROOT" diff --quiet HEAD -- src CMakeLists.txt || echo '+dirty')"

STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$BENCH/results/ab-$STAMP.md"
RAW="$BENCH/results/raw/ab-$STAMP"
mkdir -p "$RAW" "$BENCH/tmp"
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g; s#@ACCESS_LOG@#${ACCESS_LOG:-off}#g; s#@H3@##g" "$BENCH/agensio.toml" > "$BENCH/tmp/ab-agensio.toml"
# With h3 rows the TLS listener also speaks QUIC; a side whose binary refuses "h3" (a base
# before phase I) gets the plain config and no h3 rows.
sed "s#@WORKERS@#$WORKERS#g; s#@BENCH@#$BENCH#g; s#@SENDFILE_MIN@#${SENDFILE_MIN:-48KB}#g; s#@ACCESS_LOG@#${ACCESS_LOG:-off}#g; s#@H3@#, \"h3\"#g" "$BENCH/agensio.toml" > "$BENCH/tmp/ab-agensio-h3.toml"
# The access gate's two sites go into every config (before the proxy one is built from it).
if [ $ACCESS = 1 ]; then
  SPECS+=("access:/:64" "access-all:/:64" "refuse:/sub/index.html:64" "hsts:/:64" "redir-miss:/:64" "redir-hit:/x:64" "headers:/sub/index.html:64" "baseline:/:64" "exact:/sub/index.html:64")
  # Response headers (0.1.0-alpha.89, docs/headers.md 9): a rule at / and a deeper one, a file under
  # the deeper one; a base before them gets the same site without rules. With -P, a proxied answer
  # through set, default and remove rules, the base the same proxy site without them.
  hdr_site='\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8092"]\nroot = "%s/www"\n'
  # The security baseline (0.1.0-alpha.94, docs/headers.md 4): a static preset site, one config for
  # both sides; a base before the baseline serves it without the fields.
  printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8090"]\nroot = "%s/www"\napp = "static"\n' "$BENCH" > "$BENCH/tmp/ab-baseline.toml"
  printf "$hdr_site" "$BENCH" > "$BENCH/tmp/ab-hdr-none.toml"
  { printf "$hdr_site" "$BENCH"
    printf '\n[[site.response_headers]]\npath = "/"\nset = { "Referrer-Policy" = "strict-origin-when-cross-origin", "X-Content-Type-Options" = "nosniff" }\n'
    printf 'default = { "X-Frame-Options" = "SAMEORIGIN" }\nremove = ["X-Powered-By"]\n'
    printf '\n[[site.response_headers]]\npath = "/sub/"\nwhen = "success"\nset = { "Cache-Control" = "public, max-age=3600" }\n'
  } > "$BENCH/tmp/ab-hdr-base.toml"
  # endings (0.1.0-alpha.90): one more field on the html files; a base before endings gets the same
  # field from a rule without them, the same bytes, so the row measures the ending's lookup.
  { cat "$BENCH/tmp/ab-hdr-base.toml"
    printf '\n[[site.response_headers]]\npath = "/"\nendings = ["html"]\nset = { "X-Kind" = "page" }\n'
  } > "$BENCH/tmp/ab-hdr-rules.toml"
  { cat "$BENCH/tmp/ab-hdr-base.toml"
    printf '\n[[site.response_headers]]\npath = "/"\nset = { "X-Kind" = "page" }\n'
  } > "$BENCH/tmp/ab-hdr-plain.toml"
  # The same fields from a location's add_headers, the older mechanism: what a base before the rules
  # loads, so both sides write the same bytes and the row measures the rules, not the fields.
  { printf "$hdr_site" "$BENCH"
    printf '\n[[site.location]]\npath = "/"\nadd_headers = { "Referrer-Policy" = "strict-origin-when-cross-origin", "X-Content-Type-Options" = "nosniff", "X-Frame-Options" = "SAMEORIGIN", "Cache-Control" = "public, max-age=3600", "X-Kind" = "page" }\n'
  } > "$BENCH/tmp/ab-hdr-loc.toml"
  phdr_site='\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8091"]\nroot = "%s/www"\n\n[[site.location]]\npath = "/"\nupstream = "http://127.0.0.1:9100"\n'
  printf "$phdr_site" "$BENCH" > "$BENCH/tmp/ab-phdr-none.toml"
  { printf "$phdr_site" "$BENCH"
    printf '\n[[site.response_headers]]\npath = "/"\nset = { "Referrer-Policy" = "strict-origin-when-cross-origin", "Content-Security-Policy" = "default-src \x27self\x27" }\n'
    printf 'default = { "X-Frame-Options" = "SAMEORIGIN" }\nremove = ["X-Powered-By", "X-Upstream"]\n'
  } > "$BENCH/tmp/ab-phdr-rules.toml"
  pcache_site='\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8089"]\nroot = "%s/www"\n\n[[site.location]]\npath = "/"\nupstream = "http://127.0.0.1:9100"\n'
  printf "$pcache_site" "$BENCH" > "$BENCH/tmp/ab-pcache-none.toml"
  { printf "$pcache_site" "$BENCH"
    printf '\n[[site.response_headers]]\npath = "/"\nset = { "Referrer-Policy" = "strict-origin-when-cross-origin", "Content-Security-Policy" = "default-src \x27self\x27" }\n'
    printf 'default = { "X-Frame-Options" = "SAMEORIGIN" }\nremove = ["X-Powered-By", "X-Upstream"]\n'
    printf '\n[[site.response_headers]]\npath = "/"\nwhen = "success"\nset = { "Cache-Control" = "public, max-age=60" }\n'
  } > "$BENCH/tmp/ab-pcache-rules.toml"
  # Path redirects (0.1.0-alpha.82, docs/redirects.md 5): 1,000 exact rules a request does not meet,
  # and a hit; a base before them gets the same sites without rules and the whole-domain key.
  {
    printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8098"]\nroot = "%s/www"\n' "$BENCH"
    for i in $(seq 1 1000); do printf '\n[[site.redirect]]\nfrom = "/old/page-%d"\nmatch = "exact"\nto = "/new/page-%d"\nstatus = 301\n' "$i" "$i"; done
    printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8099"]\n\n[[site.redirect]]\nfrom = "/"\nto = "https://example.org"\nstatus = 301\n'
  } > "$BENCH/tmp/ab-redir-rules.toml"
  printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8098"]\nroot = "%s/www"\n\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8099"]\nredirect = "https://example.org"\n' "$BENCH" > "$BENCH/tmp/ab-redir-old.toml"
  # A TLS site on 8449 that sends HSTS on the 1 KB answer: the site's hsts key (0.1.0-alpha.75 on),
  # or for a base before it the / location's add_headers, the same field on that answer; each
  # side gets the form its binary loads (start below).
  # The lifetime named (0.1.0-alpha.101); a base before it takes hsts = true, one before alpha.75 add_headers.
  cat > "$BENCH/tmp/ab-hsts-life.toml" <<HSTS_LIFE

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8449"]
root = "$BENCH/www"
tls = { cert = "$BENCH/certs/cert.pem", key = "$BENCH/certs/key.pem" }
hsts = "1y"
HSTS_LIFE
  cat > "$BENCH/tmp/ab-hsts-key.toml" <<HSTS_KEY

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8449"]
root = "$BENCH/www"
tls = { cert = "$BENCH/certs/cert.pem", key = "$BENCH/certs/key.pem" }
hsts = true
HSTS_KEY
  cat > "$BENCH/tmp/ab-hsts-loc.toml" <<HSTS_LOC

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8449"]
root = "$BENCH/www"
tls = { cert = "$BENCH/certs/cert.pem", key = "$BENCH/certs/key.pem" }

[[site.location]]
path = "/"
add_headers = { "Strict-Transport-Security" = "max-age=31536000" }
HSTS_LOC
  # [[site.auth]] on the whole site, a remembered login sent with every request (as a browser
  # does): what a protected page costs. The user file comes from the new binary's passwd.
  if printf 'secret\n' | "$ROOT/build/agensio" passwd anna > "$BENCH/tmp/ab-users" 2>/dev/null; then
    chmod 640 "$BENCH/tmp/ab-users"
    SPECS+=("auth:/:64")
    AUTH_SITE=1
  fi
  allow=""; for i in $(seq 1 63); do allow="$allow\"10.$((i / 250)).$((i % 250)).1\", "; done; allow="$allow\"127.0.0.1\""
  for f in ab-agensio.toml ab-agensio-h3.toml; do
    cat >> "$BENCH/tmp/$f" <<ACCESS_SITES

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8094"]
root = "$BENCH/www"

[[site.access]]
path = "/wp-admin"
allow = ["10.0.0.0/8"]

[[site.access]]
path = "/wp-login.php"
match = "exact"
allow = ["10.0.0.0/8"]

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8095"]
root = "$BENCH/www"

[[site.access]]
path = "/"
allow = [$allow]

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8097"]
root = "$BENCH/www"
refuse = ["composer.json", "composer.lock", "flexform*.xml", "locallang*.xml", "locallang*.xlf", "ext_conf_template.txt",
          "ext_typoscript_*.txt", "*.bak", "*.conf", "*.cnf", "*.cfg", "*.yaml", "*.yml", "*.ts", "*.typoscript",
          "*.tsconfig", "*.dist", "*.fla", "*.inc", "*.ini", "*.log", "*.sh", "*.sql", "*.sqlite", "_recycler_/", "_temp_/",
          "/fileadmin/templates/**/*.txt", "/vendor/", "/typo3_src/", "/typo3temp/var/",
          "/typo3conf/ext/*/Configuration/", "/typo3conf/ext/*/Resources/Private/", "/typo3conf/ext/*/Tests/",
          "/typo3conf/ext/*/Test/", "/typo3conf/ext/*/docs/", "/typo3conf/ext/*/doc/",
          "/typo3/sysext/*/Configuration/", "/typo3/sysext/*/Resources/Private/", "/typo3/sysext/*/Tests/",
          "/typo3/sysext/*/Test/", "/typo3/sysext/*/docs/", "/typo3/sysext/*/doc/",
          "/typo3/ext/*/Configuration/", "/typo3/ext/*/Resources/Private/", "/typo3/ext/*/Tests/",
          "/typo3/ext/*/Test/", "/typo3/ext/*/docs/", "/typo3/ext/*/doc/"]
ACCESS_SITES
    if [ "${AUTH_SITE:-0}" = 1 ]; then
      cat >> "$BENCH/tmp/$f" <<AUTH_SITES

[[site]]
server_name = ["*"]
listen = ["127.0.0.1:8096"]
root = "$BENCH/www"

[[site.auth]]
path = "/"
users = "$BENCH/tmp/ab-users"
AUTH_SITES
    fi
    # Sixteen exact .php locations that deny, what a long rules.private renders, in front of a
    # cached file every request walks past them to (0.1.0-alpha.109): the router's pass over exact
    # locations, which since then also asks whether the path is one's path-info form.
    { printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8088"]\nroot = "%s/www"\n' "$BENCH"
      for p in /install.php /setup.php /config.php /update.php /upgrade.php /cron.php /backup.php /phpinfo.php \
               /test.php /debug.php /admin/install.php /admin/setup.php /lib/config.php /scripts/migrate.php /tools/reset.php /old/index.php; do
        printf '\n[[site.location]]\npath = "%s"\nmatch = "exact"\nhandler = "deny"\n' "$p"
      done; } >> "$BENCH/tmp/$f"
  done
fi
if [ $COMP = 1 ]; then
  # -C, response compression (docs/design-compression.md 10): a site with the key on, on 8087, asked
  # with a browser's Accept-Encoding: the 1 KB page is under min_size (identity, must be flat
  # against the plain row) and the 100 KB CSS gets its brotli copy, made once at the first fill
  # (must equal a row served from a disk twin). A side whose binary lacks the key does not load
  # the site and skips the rows, as -P skips proxy rows on a base that cannot proxy.
  # The rows: the 1 KB page under min_size (identity, Vary, flat against the plain row); the
  # 100 KB CSS from its brotli copy, from its gzip copy (a client taking gzip alone), and as
  # identity to a client sending no Accept-Encoding (curl's and most tools' case: the file's own
  # bytes with Vary, flat against the plain row); the brotli copy over TLS and over HTTP/2 at ten
  # streams, where the twin code's TLS and framing paths carry it.
  SPECS+=("comp:/:64" "comp:/style.css:64" "comp-gzip:/style.css:64" "comp-plain:/style.css:64" "comp-tls:/style.css:64")
  [ $H2 = 1 ] && SPECS+=("comp-h2:/style.css:64:10")
  printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8085"]\nroot = "%s/www"\nresponse_compression = "on"\n\n[[site.location]]\npath = "/"\nupstream = "http://127.0.0.1:9100"\n' "$BENCH" > "$BENCH/tmp/ab-comp-proxy.toml"
  printf '\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8087"]\nroot = "%s/www"\nresponse_compression = "on"\n[[site]]\nserver_name = ["*"]\nlisten = ["127.0.0.1:8486"]\nroot = "%s/www"\ntls = { cert = "%s/certs/cert.pem", key = "%s/certs/key.pem" }\nresponse_compression = "on"\n' "$BENCH" "$BENCH" "$BENCH" "$BENCH" > "$BENCH/tmp/ab-comp.toml"
fi
# The proxy gate adds a site that forwards 127.0.0.1:8093 to the upstream; a side whose
# binary cannot load it (a base before D1) gets the static-only config and no proxy rows.
UP_PID=""
if [ $PROXY = 1 ]; then
  cat "$BENCH/tmp/ab-agensio.toml" "$BENCH/proxy/ab-site.toml" > "$BENCH/tmp/ab-agensio-proxy.toml"
  nc -z 127.0.0.1 9100 2>/dev/null && { echo "port 9100 is busy; stop the running upstream first"; exit 1; }
  "$ROOT/build/agensio_upstream" -p 9100 -w 1 >>"$RAW/upstream.log" 2>&1 &
  UP_PID=$!
fi

PID=""; SIDE_PROXY=0; SIDE_H2=0; SIDE_H3=0
start() {  # binary
  for port in 8080 8443 8085 8087 8486 8088 8091 8092 8093 8094 8095 8449 8098 8099; do
    nc -z 127.0.0.1 "$port" 2>/dev/null && { echo "port $port is busy; stop the running server first"; exit 1; }
  done
  local cfg="$BENCH/tmp/ab-agensio.toml"
  SIDE_PROXY=0
  if [ $PROXY = 1 ]; then
    if "$1" -t -c "$BENCH/tmp/ab-agensio-proxy.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-agensio-proxy.toml"; SIDE_PROXY=1
    else echo "  (this side cannot load the proxy site: static rows only)"; fi
  fi
  SIDE_H3=0
  if [ $H3 = 1 ] && [ $PROXY = 0 ]; then
    if "$1" -t -c "$BENCH/tmp/ab-agensio-h3.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-agensio-h3.toml"; SIDE_H3=1
    else echo "  (this side has no HTTP/3: no h3 rows)"; fi
  fi
  if [ $ACCESS = 1 ]; then  # the HSTS site in the form this side loads
    local f
    for f in ab-hsts-life.toml ab-hsts-key.toml ab-hsts-loc.toml; do
      cat "$cfg" "$BENCH/tmp/$f" > "$BENCH/tmp/ab-side.toml"
      if "$1" -t -c "$BENCH/tmp/ab-side.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side.toml"; echo "  (hsts row: ${f#ab-hsts-})"; break; fi
    done
    for f in ab-redir-rules.toml ab-redir-old.toml; do  # the redirect sites in the form this side loads
      cat "$cfg" "$BENCH/tmp/$f" > "$BENCH/tmp/ab-side-redir.toml"
      if "$1" -t -c "$BENCH/tmp/ab-side-redir.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side-redir.toml"; echo "  (redirect rows: ${f#ab-redir-})"; break; fi
    done
    cat "$cfg" "$BENCH/tmp/ab-baseline.toml" > "$BENCH/tmp/ab-side-base.toml" && cfg="$BENCH/tmp/ab-side-base.toml"  # every side loads it
    local hdr="ab-hdr-rules.toml ab-hdr-plain.toml ab-hdr-loc.toml ab-hdr-none.toml"
    for f in $hdr; do  # the response headers site in the form this side loads
      cat "$cfg" "$BENCH/tmp/$f" > "$BENCH/tmp/ab-side-hdr.toml"
      if "$1" -t -c "$BENCH/tmp/ab-side-hdr.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side-hdr.toml"; echo "  (headers row: ${f#ab-hdr-})"; break; fi
    done
    if [ $SIDE_PROXY = 1 ]; then
      for f in ab-phdr-rules.toml ab-phdr-none.toml; do
        cat "$cfg" "$BENCH/tmp/$f" > "$BENCH/tmp/ab-side-phdr.toml"
        if "$1" -t -c "$BENCH/tmp/ab-side-phdr.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side-phdr.toml"; echo "  (proxy-hdr row: ${f#ab-phdr-})"; break; fi
      done
      for f in ab-pcache-rules.toml ab-pcache-none.toml; do
        cat "$cfg" "$BENCH/tmp/$f" > "$BENCH/tmp/ab-side-pcache.toml"
        if "$1" -t -c "$BENCH/tmp/ab-side-pcache.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side-pcache.toml"; echo "  (proxy-cache row: ${f#ab-pcache-})"; break; fi
      done
    fi
  fi
  SIDE_COMP=0
  if [ $COMP = 1 ]; then  # the compression site in the side that loads it (docs/design-compression.md 10)
    cat "$cfg" "$BENCH/tmp/ab-comp.toml" > "$BENCH/tmp/ab-side-comp.toml"
    [ $SIDE_PROXY = 1 ] && cat "$BENCH/tmp/ab-comp-proxy.toml" >> "$BENCH/tmp/ab-side-comp.toml"
    if "$1" -t -c "$BENCH/tmp/ab-side-comp.toml" >/dev/null 2>&1; then cfg="$BENCH/tmp/ab-side-comp.toml"; SIDE_COMP=1
    else echo "  (this side has no response_compression: no comp rows)"; fi
  fi
  (cd "$BENCH" && exec "$1" -c "$cfg") >>"$RAW/server.log" 2>&1 &
  PID=$!
  for _ in $(seq 1 50); do nc -z 127.0.0.1 8080 2>/dev/null && nc -z 127.0.0.1 8443 2>/dev/null && break; sleep 0.1; done
  nc -z 127.0.0.1 8080 2>/dev/null || { echo "server did not start: $1"; cat "$RAW/server.log"; exit 1; }
  # A base that ignores the `upstream` key serves the proxy site as static files (404s):
  # only a side that answers 200 through the proxy gets the proxy rows.
  if [ $SIDE_PROXY = 1 ] && [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8093/json)" != 200 ]; then
    SIDE_PROXY=0; echo "  (this side does not proxy: static rows only)"
  fi
  # A base without HTTP/2 answers the preface with 505: it gets no h2 rows.
  SIDE_H2=0
  if [ $H2 = 1 ]; then
    if [ "$(curl -s --http2-prior-knowledge -o /dev/null -w '%{http_version}' http://127.0.0.1:8080/)" = 2 ]; then SIDE_H2=1
    else echo "  (this side has no HTTP/2: no h2 rows)"; fi
  fi
}
stop() { [ -n "$PID" ] && kill "$PID" 2>/dev/null && wait "$PID" 2>/dev/null || true; PID=""; sleep 0.3; }
trap 'stop; [ -n "$UP_PID" ] && kill "$UP_PID" 2>/dev/null; true' EXIT
cpu_seconds() {  # user + system CPU of the server process
  if [ -d /proc ]; then
    awk -v tck="$(getconf CLK_TCK)" '{ printf "%.3f", ($14+$15)/tck }' "/proc/$PID/stat"
  else
    ps -o cputime= -p "$PID" | LC_NUMERIC=C awk -F'[:.]' '{ if (NF==3) s=$1*60+$2+$3/100; else s=$1*3600+$2*60+$3+$4/100 } END{printf "%.3f", s}'
  fi
}

measure() {  # side round -> appends "side round spec cpu_us rps" lines to $RAW/rows
  local side=$1 round=$2 spec proto path conns streams url t raw c0 c1 n rps rest
  for spec in "${SPECS[@]}"; do
    proto="${spec%%:*}"; rest="${spec#*:}"; streams=""
    case $proto in
      h2|h2c|h3|comp-h2) path="${rest%%:*}"; rest="${rest#*:}"; conns="${rest%%:*}"; streams="${rest#*:}" ;;
      *) conns="${rest##*:}"; path="${rest%:*}" ;;
    esac
    case $proto in
      https) url="https://127.0.0.1:8443$path" ;;
      proxy) [ $SIDE_PROXY = 1 ] || continue; url="http://127.0.0.1:8093$path" ;;
      access) url="http://127.0.0.1:8094$path" ;;
      access-all) url="http://127.0.0.1:8095$path" ;;
      refuse) url="http://127.0.0.1:8097$path" ;;
      hsts) url="https://127.0.0.1:8449$path" ;;
      redir-miss) url="http://127.0.0.1:8098$path" ;;
      redir-hit) url="http://127.0.0.1:8099$path" ;;
      headers) url="http://127.0.0.1:8092$path" ;;
      baseline) url="http://127.0.0.1:8090$path" ;;
      exact) url="http://127.0.0.1:8088$path" ;;
      proxy-hdr) [ $SIDE_PROXY = 1 ] || continue; url="http://127.0.0.1:8091$path" ;;
      proxy-cache) [ $SIDE_PROXY = 1 ] || continue; url="http://127.0.0.1:8089$path" ;;
      auth) url="http://127.0.0.1:8096$path" ;;
      comp|comp-gzip|comp-plain) [ $SIDE_COMP = 1 ] || continue; url="http://127.0.0.1:8087$path" ;;
      comp-tls) [ $SIDE_COMP = 1 ] || continue; url="https://127.0.0.1:8486$path" ;;
      proxy-comp|proxy-comp-plain) [ $SIDE_COMP = 1 ] && [ $SIDE_PROXY = 1 ] || continue; url="http://127.0.0.1:8085$path" ;;
      comp-h2) [ $SIDE_COMP = 1 ] && [ $SIDE_H2 = 1 ] || continue; url="https://127.0.0.1:8486$path" ;;
      h2c) [ $SIDE_H2 = 1 ] || continue; url="http://127.0.0.1:8080$path" ;;
      h2) [ $SIDE_H2 = 1 ] || continue; url="https://127.0.0.1:8443$path" ;;
      h3) [ $SIDE_H3 = 1 ] || continue; url="https://127.0.0.1:8443$path" ;;
      *) url="http://127.0.0.1:8080$path" ;;
    esac
    if [ "$proto" = h3 ]; then curl -sk --http3-only -o /dev/null "$url"; else curl -sk -o /dev/null "$url"; fi  # warm-up
    t=$THREADS; [ "$conns" -lt "$t" ] && t=$conns
    raw="$RAW/$side-r$round-$proto-$(echo "$path" | tr '/?=' '___')-c$conns${streams:+-m$streams}.txt"
    c0=$(cpu_seconds)
    if [ "$proto" = h3 ]; then
      $H2LOAD_H3 --alpn-list=h3 -D "${DURATION%s}" -c"$conns" -m"$streams" -t"$t" "$url" > "$raw" 2>&1 || true
      n=$(awk '/^requests:/{print $6}' "$raw"); rps=$(awk '/^finished in/{print $4}' "$raw")
    elif [ -n "$streams" ]; then
      hdr=(); [ "$proto" = comp-h2 ] && hdr=(-H "accept-encoding: gzip, deflate, br, zstd")
      h2load -D "${DURATION%s}" -c"$conns" -m"$streams" -t"$t" "${hdr[@]}" "$url" > "$raw" 2>&1 || true
      n=$(awk '/^requests:/{print $6}' "$raw"); rps=$(awk '/^finished in/{print $4}' "$raw")  # "N done", "X req/s"
    else
      hdr=(); [ "$proto" = auth ] && hdr=(-H "Authorization: Basic YW5uYTpzZWNyZXQ=")  # anna:secret
      case $proto in  # the compression rows' clients
        comp|comp-tls|proxy-comp) hdr=(-H "Accept-Encoding: gzip, deflate, br, zstd") ;;  # a browser's
        comp-gzip) hdr=(-H "Accept-Encoding: gzip") ;;                          # a tool taking gzip alone
      esac
      wrk -t"$t" -c"$conns" -d"$DURATION" "${hdr[@]}" "$url" > "$raw" 2>&1
      n=$(awk '/requests in/{print $1}' "$raw"); rps=$(awk '/^Requests\/sec/{print $2}' "$raw")
    fi
    c1=$(cpu_seconds)
    LC_NUMERIC=C awk -v a="$c0" -v b="$c1" -v n="${n:-0}" -v s="$side" -v r="$round" -v k="$proto $path $conns${streams:+x$streams}" -v q="${rps:-0}" \
      'BEGIN{ printf "%s %d %s %.2f %s\n", s, r, k, (n>0 ? (b-a)*1e6/n : -1), q }' >> "$RAW/rows"
    printf '  %-4s r%d %-5s %-11s c=%-3s%s %8.2f us/req  %s req/s\n' "$side" "$round" "$proto" "$path" "$conns" "${streams:+ m=$streams}" \
      "$(tail -1 "$RAW/rows" | awk '{print $6}')" "$rps"
  done
}

: > "$RAW/rows"
for round in $(seq 1 "$ROUNDS"); do
  echo "=== round $round: base $BASE_SHA"; start "$BASE_DIR/build/agensio"; measure base "$round"; stop
  echo "=== round $round: new $NEW_SHA";   start "$ROOT/build/agensio";     measure new  "$round"; stop
done

{
  echo "# A/B $STAMP: base $BASE_SHA vs new $NEW_SHA"
  echo
  echo "- machine: $(uname -m), $(sysctl -n machdep.cpu.brand_string 2>/dev/null || grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ *//'), $(uname -sr)"
  echo "- agensio workers=$WORKERS, wrk threads=$THREADS, duration=$DURATION, rounds=$ROUNDS; CPU us/req = server CPU time / requests"
  echo
  echo "| case | base us/req (per round) | new us/req (per round) | new/base |"
  echo "|---|---|---|---|"
  for spec in "${SPECS[@]}"; do
    proto="${spec%%:*}"; rest="${spec#*:}"; streams=""
    case $proto in
      h2|h2c|h3|comp-h2) path="${rest%%:*}"; rest="${rest#*:}"; conns="${rest%%:*}"; streams="${rest#*:}" ;;
      *) conns="${rest##*:}"; path="${rest%:*}" ;;
    esac
    LC_NUMERIC=C awk -v k="$proto $path $conns${streams:+x$streams}" -v label="$proto $path c=$conns${streams:+ m=$streams}" '
      $3" "$4" "$5==k { if ($1=="base") { b=b (b?" / ":"") sprintf("%.2f",$6); bs+=$6; bn++ } else { w=w (w?" / ":"") sprintf("%.2f",$6); ws+=$6; wn++ } }
      END { if (bn && wn) printf "| %s | %s | %s | %.3f |\n", label, b, w, (ws/wn)/(bs/bn);
            else if (wn) printf "| %s | n/a (base has neither proxy nor HTTP/2) | %s | n/a |\n", label, w }' "$RAW/rows"
  done
} > "$OUT"
echo; cat "$OUT"; echo; echo "summary written to $OUT"
