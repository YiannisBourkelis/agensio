# The release check of 0.1.0-alpha.118, corrected: built alike, alpha.118 costs what alpha.117 cost, 2026-11-01

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.113+deb13-amd64, Debian 13; inside
  `agensio-devbox` (`--network none`), the counters in `agensio-devbox-perf`; every run after both indexers
  (baloo, VS Code's cpptools) had been under 15 % for three checks 30 s apart, baloo paused by the owner
- the scripts and configuration of `release-118-rows-20261101.md` (`rows-by-hand.sh`, `perf-row.sh`,
  `bench/tmp/rows-hand.toml`), six alternations per row by hand, three for the counters

## What was wrong

`release-118-rows-20261101.md` put plain HTTP 1 KB at 1.022 against alpha.117, every round, and read
the counters as the compression code's size. Its new side was `build/agensio`, and `build/` is configured
with `-DAGENSIO_HTTPARENA=ON` (and the tests): the HttpArena benchmark handler, never in a release, is
linked in. The base, `bench/tmp/ab/1d05e429/build/agensio`, was built the way `bench/ab.sh` builds a base:
`-DAGENSIO_TESTS=OFF`, no arena handler. The handler adds no work to a request (instructions per request
equal on every side), but its code moves the rest of the binary: instruction-cache misses of one and the
same source were 279 to 292 built in the A/B worktree and 309 to 316 built in `build/`.

`bench/ab.sh` takes `build/agensio` as its new side whatever the base's options, so every A/B against a
worktree base compares an arena build with a release-shaped one while `build/` is so configured
(`ab-20261031-231944.md`, the HEAD-against-fix run below, is one).

## Built alike: alpha.117 against alpha.118

Base v0.1.0-alpha.117 (1d05e429), new c9e8d105 (the commit of the release check; its server code is
b0dd040a's), both `bench/tmp/ab/<sha>/build/agensio` with `bench/ab.sh`'s options:

| row | alpha.117 µs/req (rounds) | alpha.118 µs/req (rounds) | mean base | mean new | new/base |
|---|---|---|---|---|---|
| http://127.0.0.1:8080/ | 1.92 1.95 1.93 1.94 1.92 1.93 | 1.95 1.95 1.94 1.95 1.94 1.91 | 1.932 | 1.940 | 1.004 |
| http://127.0.0.1:8092/sub/index.html | 1.97 2.02 1.96 1.97 1.94 1.94 | 2.00 1.99 1.97 1.97 1.95 1.97 | 1.967 | 1.975 | 1.004 |
| http://127.0.0.1:8088/sub/index.html | 1.92 1.92 1.95 1.96 1.93 1.92 | 1.97 2.05 1.94 1.96 1.93 1.93 | 1.933 | 1.963 | 1.016 |
| http://127.0.0.1:8080/style.css | 5.42 5.37 5.43 5.40 5.36 5.39 | 5.40 5.43 5.41 5.36 5.41 5.54 | 5.395 | 5.425 | 1.006 |

The counters on the plain row (base alpha.117, new alpha.118):

```
base ins/req 18459 cyc/req 10725 ipc 1.72 brmiss/req 16.19 icmiss/req 296.11
new ins/req 18460 cyc/req 11359 ipc 1.63 brmiss/req 16.42 icmiss/req 305.40
base ins/req 18369 cyc/req 10813 ipc 1.70 brmiss/req 17.05 icmiss/req 295.51
new ins/req 18407 cyc/req 10179 ipc 1.81 brmiss/req 16.10 icmiss/req 286.19
base ins/req 18396 cyc/req 10361 ipc 1.78 brmiss/req 17.50 icmiss/req 285.60
new ins/req 18439 cyc/req 10462 ipc 1.76 brmiss/req 16.73 icmiss/req 286.89
```

Instructions per request equal (18,370 to 18,460 on both), instruction-cache misses in one range (286 to
305 against 286 to 296), CPU time 1.004 to 1.016: no cost to answer for.

## The fix that was tried and taken out

On the reading above, `StaticHandler::serve_location`'s miss path was moved into a function of its own
(`[[gnu::noinline]]`), since GCC had stopped inlining the hit path's `shared_ptr` copy once compression
grew the fill path (alpha.117 calls the out-of-line copy constructor from 2 sites of that function,
alpha.118 from 6; on the plain row it took 1.1 % of the cycles in the arena build). The split did inline
it again (serve_location 8 KB to 3.6 KB, no out-of-line copy), and measured built alike it changes
nothing, so it was not kept:

| row | alpha.118 µs/req (rounds) | with the split (rounds) | mean base | mean new | new/base |
|---|---|---|---|---|---|
| http://127.0.0.1:8080/ | 1.94 1.95 1.95 1.93 1.97 1.96 | 1.93 1.94 1.93 1.94 2.06 1.96 | 1.950 | 1.960 | 1.005 |
| http://127.0.0.1:8092/sub/index.html | 1.97 1.96 1.95 1.97 1.97 1.96 | 1.97 1.96 1.99 1.95 1.96 1.95 | 1.963 | 1.963 | 1.000 |

```
base ins/req 18419 cyc/req 10335 ipc 1.78 brmiss/req 16.52 icmiss/req 285.73
new ins/req 18405 cyc/req 10327 ipc 1.78 brmiss/req 16.29 icmiss/req 290.44
base ins/req 18423 cyc/req 10517 ipc 1.75 brmiss/req 16.47 icmiss/req 297.53
new ins/req 18406 cyc/req 10286 ipc 1.79 brmiss/req 15.88 icmiss/req 302.25
base ins/req 18403 cyc/req 10483 ipc 1.76 brmiss/req 16.35 icmiss/req 280.89
new ins/req 18381 cyc/req 10514 ipc 1.75 brmiss/req 16.48 icmiss/req 285.66
```

`ab-20261031-231944.md` (`bench/ab.sh HEAD -P -A -C -2 -r 3`, the split in `build/` with the arena handler
against HEAD built alike) is the same comparison skewed the other way: flat but plain `/` at 1.027.

Raw output, one line per side and round:

```
http://127.0.0.1:8080/ base 1.92
http://127.0.0.1:8080/ new 1.95
http://127.0.0.1:8080/ base 1.95
http://127.0.0.1:8080/ new 1.95
http://127.0.0.1:8080/ base 1.93
http://127.0.0.1:8080/ new 1.94
http://127.0.0.1:8080/ base 1.94
http://127.0.0.1:8080/ new 1.95
http://127.0.0.1:8080/ base 1.92
http://127.0.0.1:8080/ new 1.94
http://127.0.0.1:8080/ base 1.93
http://127.0.0.1:8080/ new 1.91
http://127.0.0.1:8092/sub/index.html base 1.97
http://127.0.0.1:8092/sub/index.html new 2.00
http://127.0.0.1:8092/sub/index.html base 2.02
http://127.0.0.1:8092/sub/index.html new 1.99
http://127.0.0.1:8092/sub/index.html base 1.96
http://127.0.0.1:8092/sub/index.html new 1.97
http://127.0.0.1:8092/sub/index.html base 1.97
http://127.0.0.1:8092/sub/index.html new 1.97
http://127.0.0.1:8092/sub/index.html base 1.94
http://127.0.0.1:8092/sub/index.html new 1.95
http://127.0.0.1:8092/sub/index.html base 1.94
http://127.0.0.1:8092/sub/index.html new 1.97
http://127.0.0.1:8088/sub/index.html base 1.92
http://127.0.0.1:8088/sub/index.html new 1.97
http://127.0.0.1:8088/sub/index.html base 1.92
http://127.0.0.1:8088/sub/index.html new 2.05
http://127.0.0.1:8088/sub/index.html base 1.95
http://127.0.0.1:8088/sub/index.html new 1.94
http://127.0.0.1:8088/sub/index.html base 1.96
http://127.0.0.1:8088/sub/index.html new 1.96
http://127.0.0.1:8088/sub/index.html base 1.93
http://127.0.0.1:8088/sub/index.html new 1.93
http://127.0.0.1:8088/sub/index.html base 1.92
http://127.0.0.1:8088/sub/index.html new 1.93
http://127.0.0.1:8080/style.css base 5.42
http://127.0.0.1:8080/style.css new 5.40
http://127.0.0.1:8080/style.css base 5.37
http://127.0.0.1:8080/style.css new 5.43
http://127.0.0.1:8080/style.css base 5.43
http://127.0.0.1:8080/style.css new 5.41
http://127.0.0.1:8080/style.css base 5.40
http://127.0.0.1:8080/style.css new 5.36
http://127.0.0.1:8080/style.css base 5.36
http://127.0.0.1:8080/style.css new 5.41
http://127.0.0.1:8080/style.css base 5.39
http://127.0.0.1:8080/style.css new 5.54
http://127.0.0.1:8080/ base 1.94
http://127.0.0.1:8080/ new 1.93
http://127.0.0.1:8080/ base 1.95
http://127.0.0.1:8080/ new 1.94
http://127.0.0.1:8080/ base 1.95
http://127.0.0.1:8080/ new 1.93
http://127.0.0.1:8080/ base 1.93
http://127.0.0.1:8080/ new 1.94
http://127.0.0.1:8080/ base 1.97
http://127.0.0.1:8080/ new 2.06
http://127.0.0.1:8080/ base 1.96
http://127.0.0.1:8080/ new 1.96
http://127.0.0.1:8092/sub/index.html base 1.97
http://127.0.0.1:8092/sub/index.html new 1.97
http://127.0.0.1:8092/sub/index.html base 1.96
http://127.0.0.1:8092/sub/index.html new 1.96
http://127.0.0.1:8092/sub/index.html base 1.95
http://127.0.0.1:8092/sub/index.html new 1.99
http://127.0.0.1:8092/sub/index.html base 1.97
http://127.0.0.1:8092/sub/index.html new 1.95
http://127.0.0.1:8092/sub/index.html base 1.97
http://127.0.0.1:8092/sub/index.html new 1.96
http://127.0.0.1:8092/sub/index.html base 1.96
http://127.0.0.1:8092/sub/index.html new 1.95
```
