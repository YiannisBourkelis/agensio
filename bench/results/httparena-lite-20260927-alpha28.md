# HttpArena lite, alpha.27 against the alpha.28 working tree (2026-09-27)

- machine: AMD Ryzen 9 9900X (12 cores, 24 threads), Debian 13, kernel 6.12.107+deb13-amd64,
  the arena's harness inside Docker-in-Docker (`bench/httparena/local.sh`)
- base: b5fde5e (v0.1.0-alpha.27) from the A/B worktree `bench/tmp/ab/b5fde5e`; new: b5fde5e
  plus the uncommitted alpha.28 changes (HTTP/1 access-log site per request, 413 logging and
  the chunked 413, the site environment's reveal and checks); both `LOCAL=1`
- server pinned to cores 0-5,12-17, load generators to 6-11,18-23; 5 s per run, best of 3;
  two full runs in opposite order
- validator on the new tree: 72 passed, 0 failed
- raw output: `bench/results/raw/httparena-20260927-alpha28/`

```
export LOCAL=1 SERVER_CPUS=0-5,12-17 LOAD_CPUS=6-11,18-23 ARENA=$PWD/bench/tmp/httparena
bench/httparena/local.sh validate agensio
bench/tmp/ab/b5fde5e/bench/httparena/local.sh bench agensio && bench/httparena/local.sh bench agensio   # run 1
bench/httparena/local.sh bench agensio && bench/tmp/ab/b5fde5e/bench/httparena/local.sh bench agensio   # run 2
```

| profile | run 1 (base first) new/base | run 2 (new first) new/base | mean |
|---|---|---|---|
| baseline 512c | 0.983 | 0.997 | 0.990 |
| pipelined 512c | 1.010 | 0.994 | 1.002 |
| limited-conn 512c | 0.982 | 1.010 | 0.996 |
| baseline-h2 512c | 1.010 | 1.008 | 1.009 |
| static-h2 512c | 0.981 | 1.017 | 0.999 |
| static-tls 512c | 0.958 | 1.002 | 0.980 |
| json-tls 512c | 0.993 | 0.998 | 0.995 |
| baseline-h2c 512c | 0.997 | 0.989 | 0.993 |
| json-h2c 512c | 1.019 | 0.980 | 0.999 |
| baseline-h3 64c | 0.991 | 0.989 | 0.990 |
| static-h3 64c | 1.000 | 0.968 | 0.984 |

static-tls moves with the order (0.958 base first, 1.002 new first; the same on the alpha.27
comparison), so its single runs are not a verdict; the CPU-per-request gate is the A/B:
`ab-20260927-160319.md` (static, proxy, h2: 0.943 to 1.025) and `ab-20260927-160958.md`
(h3: 0.964 to 1.031).
