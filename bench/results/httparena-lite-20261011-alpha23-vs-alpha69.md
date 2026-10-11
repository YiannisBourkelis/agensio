# HttpArena lite, alpha.23 (the arena entry) against alpha.69 (2026-10-11)

- machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13, kernel 6.12.111+deb13-amd64,
  the arena's harness inside Docker-in-Docker (`bench/httparena/local.sh`, engine 29.8.1), the
  HttpArena clone of 2026-09-23 (05bff12)
- base: e60c61c (v0.1.0-alpha.23, the version HttpArena PR #1511 pins), built from the worktree
  `bench/tmp/ab/e60c61c` with its own entry files; new: b10462c (v0.1.0-alpha.69) with today's
  entry files; both with `Dockerfile.local` (`-DAGENSIO_NATIVE=ON -DAGENSIO_HTTPARENA=ON`)
- server pinned to cores 0-5,12-17, load generators to 6-11,18-23; 5 s per run, best of 3; the
  four runs back to back: alpha.23, alpha.69, alpha.69, alpha.23 (order 1 is runs 1-2, order 2
  runs 3-4)
- raw output: `bench/results/raw/httparena-20261011-alpha23/`

Commands:

```
LOCAL=1 bench/httparena/local.sh validate agensio                        # alpha.69: 72 passed, 0 failed
export LOCAL=1 SERVER_CPUS=0-5,12-17 LOAD_CPUS=6-11,18-23 ARENA=$PWD/bench/tmp/httparena
bench/tmp/ab/e60c61c/bench/httparena/local.sh bench agensio              # run 1, alpha.23
bench/httparena/local.sh bench agensio                                   # run 2, alpha.69
bench/httparena/local.sh bench agensio                                   # run 3, alpha.69
bench/tmp/ab/e60c61c/bench/httparena/local.sh bench agensio              # run 4, alpha.23
```

| profile | alpha.23 req/s (run 1 / 4) | alpha.69 req/s (run 2 / 3) | alpha.69/alpha.23 (order 1 / 2) | CPU alpha.23 / alpha.69 | Mem alpha.23 / alpha.69 |
|---|---|---|---|---|---|
| baseline 512c | 2,317,160 / 2,369,457 | 2,357,324 / 2,359,628 | 1.017 / 0.996 | 1217, 1135% / 1110, 1144% | 56 MiB / 59 MiB |
| pipelined 512c | 3,316,245 / 3,302,711 | 3,311,843 / 3,296,800 | 0.999 / 0.998 | 1121, 1225% / 1234, 1147% | 46 MiB / 46 MiB |
| limited-conn 512c | 1,818,748 / 1,852,001 | 1,848,543 / 1,854,673 | 1.016 / 1.001 | 1068, 1183% / 1089, 1098% | 52 MiB / 52 MiB |
| baseline-h2 512c | 11,261,937 / 11,384,660 | 11,298,657 / 11,415,339 | 1.003 / 1.003 | 478, 488% / 459, 432% | 83 MiB / 84 MiB |
| static-h2 512c | 685,180 / 681,423 | 685,197 / 713,765 | 1.000 / 1.047 | 1229, 1109% / 1103, 1224% | 271 MiB / 275 MiB |
| static-tls 512c | 589,924 / 594,937 | 589,717 / 590,769 | 1.000 / 0.993 | 1046, 1151% / 1136, 1083% | 91 MiB / 89 MiB |
| json-tls 512c | 1,115,653 / 1,115,798 | 1,112,594 / 1,117,638 | 0.997 / 1.002 | 902, 1008% / 1016, 1015% | 85 MiB / 85 MiB |
| baseline-h2c 512c | 12,324,437 / 12,425,214 | 12,342,166 / 12,469,187 | 1.001 / 1.004 | 484, 420% / 446, 427% | 54 MiB / 54 MiB |
| json-h2c 512c | 2,687,126 / 2,665,814 | 2,634,893 / 2,672,304 | 0.981 / 1.002 | 1105, 1208% / 1209, 1116% | 291 MiB / 283 MiB |
| baseline-h3 64c | 4,007,662 / 4,005,206 | 3,950,835 / 3,972,765 | 0.986 / 0.992 | 208, 218% / 254, 234% | 79 MiB / 81 MiB |
| static-h3 64c | 607,154 / 609,259 | 603,794 / 607,338 | 0.994 / 0.997 | 909, 882% / 905, 919% | 76 MiB / 78 MiB |

Every throughput row is within the harness's run-to-run spread (2-3 %), in both orders: 46
releases of features since alpha.23 (site operations, access rules, refused paths, passwords, the
connection ceiling, site isolation, the certificate work) left the arena's rows where they were,
as each step's own A/B said. The CPU column is a sample per run, about 10 % apart on one binary
(json-tls alpha.23: 8.1 and 9.0 us per request); on baseline-h3, bound by its load generator,
alpha.69 reads 0.59-0.64 us per request against alpha.23's 0.52-0.54 in both orders, with 1 to
1.4 % less throughput: a possible small HTTP/3 cost, which `bench/ab.sh v0.1.0-alpha.23 -3 -r 3`
(CPU per request measured, not sampled) would settle.

These are this machine's numbers: the arena's run on PR #1511 (2026-09-25, alpha.23) used its
own 64-core host, so its absolute figures differ.

Followed with the A/B (`bench/results/ab-20261011-145717.md`: `bench/ab.sh v0.1.0-alpha.23 -3 -r 3`
in the devbox, one worker, CPU per request measured; its "base 22f3f81" is the annotated tag's own
object, the build is alpha.23's commit e60c61c): the HTTP/1 rows flat or lower (0.955 to 1.022), h3
at one stream 0.991, ten streams 1.026, the 100 KB file 1.002, and 64 streams 1.072 (base 0.69 /
0.69 / 0.71 us, new 0.72 / 0.72 / 0.80), the row that matches the arena's baseline-h3. Looked for
across the releases (`bench/results/h3-releases-20261011.md`): no step anywhere from alpha.23 to
alpha.69, every release's median within 3 % of alpha.23's, and alpha.69 1.007 of alpha.23 head to
head over ten rounds; the 1.072 was one high round (0.80), which alpha.23 also produces (0.795).
No regression.
