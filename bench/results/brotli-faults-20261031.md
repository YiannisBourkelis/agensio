# The brotli row's page faults, 2026-10-31 (design-compression.md 6, 7; `tune_heap` in server.cpp)

- machine: AMD Ryzen 9 9900X (12 cores), Debian 13, Linux 6.12.113+deb13-amd64, glibc 2.41,
  libbrotli 1.1.0-2+deb13u1, inside `agensio-devbox` with `--network none`
- base: 674de9ef (`bench/tmp/ab/674de9ef/build/agensio`); new: the working tree of step 5
  (the guard and the padding on every answer), then with `tune_heap()` added
- one worker, `bench/agensio_upstream -p 9100 -w 1`, wrk 4 threads, 64 connections, 5 s after 2 s
  of warm-up; CPU us/req and minor page faults per request from `/proc/<pid>/stat`
- commands: `bench/compression/brotli-row.sh BASE NEW` (HDR=br, URL=/page: the upstream's 32 KB
  page for a client taking brotli alone, the A/B's `proxy-comp-br:/page:64` row), the same with
  `HDR="gzip, deflate, br, zstd"` (zstd) and `HDR=gzip`; the micro-benchmarks `padcost.cpp`
  (compress_buffered with and without padding, and the brotli stream driven by hand) and
  `bralloc.cpp` (brotli's allocations through a counting allocator) were run from the scratchpad
  and are quoted below

## What the A/B showed

`bench/ab.sh 674de9ef -P -C -r 3` (`ab-20261031-102243.md`): every row within noise but
`proxy-comp-br /page c=64`, 113.98 / 113.46 / 113.94 base against 151.66 / 150.79 / 150.58 new
(1.327), 8,780 against 6,600 req/s at the same 10.9 KB per answer. zstd (`proxy-comp /page`,
1.006) and gzip (`proxy-comp-gzip /page`, 0.998) paid nothing for their padding.

## The padding is not it

Hot loop, 300 answers of the same 33 KB page (`padcost`, devbox):

| coding | padding 0 | padding 32 |
|---|---|---|
| zstd 3 | 54.0 us | 52.2 us |
| brotli 3 | 144.0 us | 139.9 us |
| gzip 5 | 356.6 us | 350.1 us |
| brotli by hand, FINISH alone | 141.4 us | |
| brotli by hand, EMIT_METADATA 32 bytes then FINISH | | 144.6 us |
| brotli by hand, EMIT_METADATA 0 bytes then FINISH | | 144.8 us |

## The row by hand: both binaries pay the same, and it is page faults

`brotli-row.sh`, default malloc:

| binary | us/req | faults/req | req/s |
|---|---|---|---|
| base 674de9ef, round 1 | 150.1 | 84.2 | 6,663 |
| new (step 5), round 1 | 148.8 | 82.9 | 6,736 |
| base, round 2 | 150.9 | 84.8 | 6,636 |
| new, round 2 | 149.5 | 84.5 | 6,704 |

The same with `MALLOC_TRIM_THRESHOLD_=536870912 MALLOC_MMAP_THRESHOLD_=1073741824
MALLOC_TOP_PAD_=67108864` in the environment:

| binary | us/req | faults/req | req/s |
|---|---|---|---|
| base, round 1 | 114.1 | 0.0 | 8,763 |
| new, round 1 | 115.2 | 0.0 | 8,684 |
| base, round 2 | 114.0 | 0.0 | 8,771 |
| new, round 2 | 113.0 | 0.0 | 8,865 |

So the A/B's base side at 114 was a heap layout the process's earlier rows had left it, and the
padding's extra bytes in the answer buffer moved the new side to the other layout. The cause:
the brotli encoder is created and destroyed per answer (zstd's and gzip's contexts live per
thread), and glibc maps a block above its mmap threshold from the kernel and unmaps it at free,
so each answer faults the pages in again, zeroed; the dynamic threshold rises to the size of each
mapped block freed, and a block that recurs at exactly that size is mapped every time (the test
is `>=`). Brotli's blocks per answer at quality 3 with the capped window (`bralloc`):

| input | lgwin | blocks | in all |
|---|---|---|---|
| 8 KB | 14 | 6976, 8201, 98576, 262144, 16887, 20640 | 403 KB |
| 33 KB (the row) | 16 | 6976, 147465, 196880, 262144, 66925, 20640 | 684 KB |
| 70 KB (WordPress's page) | 17 | 6976, 278537, 196880, 262144, 141075, 20640 | 885 KB |
| 256 KB (the whole-answer limit) | 18 | 6976, 540681, 196880, 262144, 524791, 20640 | 1,515 KB |

84 faults are 336 KB: the hasher's 256 KB (written whole by its memset) and the 67 KB output
storage, both above the default 128 KB threshold.

## With `tune_heap()` (M_MMAP_THRESHOLD 2 MB, M_TRIM_THRESHOLD 8 MB at start)

| row | base us/req (faults) | new us/req (faults) |
|---|---|---|
| brotli alone, round 1 | 151.2 (84.3) | 113.5 (0.0) |
| brotli alone, round 2 | 148.7 (84.2) | 113.5 (0.0) |
| the browser's header (zstd 3), round 2 | 61.7 (0.0) | 61.5 (0.0) |
| gzip alone, round 2 | 369.4 (0.0) | 371.3 (0.0) |

The worker's `trim_heap()` (`malloc_trim(0)` after sheds and closes) still returns everything
when connections go idle, so idle memory is unchanged; what changes is that memory freed and
re-allocated between two answers stays mapped. The A/Bs after it: `ab-20261031-113544.md`
(`bench/ab.sh 674de9ef -P -C -r 3`: the brotli row 0.998, every compression row within 2 %) and
`ab-20261031-114708.md` (`bench/ab.sh 674de9ef -A -C -r 3`: the access rows flat). The second run
of the morning (`ab-20261031-104901`) was cut off by a reboot of the machine and has no result.

## The static rows, the thresholds alone

Both A/Bs read `comp-plain /style.css` (the 100 KB file without Accept-Encoding on a site with
compression on, sent with sendfile) at 1.049 and 1.052 and `http /style.css` at 1.025 and 1.022,
paths step 5's code does not run. glibc takes the same thresholds from the environment, so
`bench/compression/static-row.sh 674de9ef-binary new-binary` alternates the base, the base with
`MALLOC_MMAP_THRESHOLD_=2097152 MALLOC_TRIM_THRESHOLD_=8388608` (what `tune_heap` sets) and the new
binary on that row, four rounds of 5 s, in the devbox:

| side | us/req per round | mean | faults/req |
|---|---|---|---|
| base 674de9ef | 6.03 / 5.46 / 5.47 / 5.68 | 5.66 | 0.000 |
| base with the thresholds | 5.64 / 5.57 / 5.65 / 5.45 | 5.58 | 0.000 |
| new | 5.77 / 5.65 / 5.81 / 5.57 | 5.70 | 0.000 |

Within noise: the thresholds cost the static path nothing, and the A/Bs' 5 % was the spread of
a busy box (baloo was indexing 330,000 files that day).
