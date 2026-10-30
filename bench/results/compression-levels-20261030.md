# Encoder levels on real pages, whole and flushed per 16 KB, 2026-10-30 (design-compression.md 6, the `levels` defaults)

- machine: x86_64, AMD Ryzen 9 9900X 12-Core Processor, Linux 6.12.113+deb13-amd64, Debian 13; one thread
- commit: ded536d4 (step 4 of the design); the program `bench/compression/flush-levels.cpp` in the devbox
  (GCC 14.2, zlib 1.3.1, libzstd 1.5.7, libbrotli 1.1.0), `g++ -O2 -std=c++23 flush-levels.cpp -lbrotlienc -lz -lzstd`
- command: `./flush-levels page.html laravel.html wordpress.html html_hn.html html_debian.html html_mdn_fetch.html json_gh_commits.json json_gh_issues.json`;
  raw CSV in `raw/compression-levels-20261030/flush-levels.csv`
- inputs: the benchmark upstream's `/page` (33,211 bytes, synthetic prose, sha256 2b1f04ab…), the Laravel bed's
  welcome page over ddev's router (80,650 bytes, 9e6ede78…), the WordPress bed's home page from its web container
  (70,286 bytes, c459bd3d…), and five files of the research corpus (`research_notes/Web server response
  compression/cdn_browsers_cost_bench/corpus.sha256`): Hacker News's front page, Debian's, MDN's fetch page,
  GitHub's commits and issues JSON
- each encoder called as `compress.cpp` calls it (step 4) and as the step-6 `CompressedBody` would: whole = one
  call with the size known (brotli's window the smallest of 2^10 to 2^18 holding the input, zstd's pledged size);
  flushed = 16 KB pieces, the encoder flushed after each (`BROTLI_OPERATION_FLUSH`, `Z_SYNC_FLUSH`,
  `ZSTD_e_flush`), brotli's window 2^18; gzip window 2^15 and memLevel 8 on one reset context, zstd window 2^19
  on one context, a brotli encoder made per call; 60 calls per row (20 above 200 KB), a warm-up call first

## Whole answers: bytes / µs per answer

| input | zstd 3 | brotli 3 | brotli 4 | brotli 5 | gzip 1 | gzip 5 | gzip 6 |
|---|---|---|---|---|---|---|---|
| Laravel welcome page, 80,650 | 16,411 / 68 | 16,212 / 262 | 15,242 / 450 | 14,558 / 734 | 18,425 / 249 | 16,121 / 576 | 16,019 / 657 |
| WordPress home page, 70,286 | 13,353 / 54 | 13,088 / 191 | 12,480 / 337 | 11,506 / 492 | 14,663 / 198 | 12,312 / 399 | 12,111 / 537 |
| Hacker News front page, 34,597 | 5,573 / 23 | 5,877 / 64 | 5,521 / 105 | 4,974 / 166 | 6,112 / 39 | 5,664 / 91 | 5,655 / 126 |
| Debian's front page, 15,864 | 4,456 / 18 | 4,426 / 42 | 4,129 / 70 | 3,843 / 95 | 4,814 / 32 | 4,304 / 57 | 4,282 / 61 |
| MDN fetch page, 184,066 | 26,903 / 159 | 26,410 / 468 | 24,970 / 731 | 23,086 / 1,093 | 34,204 / 593 | 28,492 / 1,151 | 27,661 / 1,473 |
| GitHub commits JSON, 41,433 | 7,299 / 28 | 7,499 / 76 | 7,266 / 114 | 7,111 / 157 | 8,318 / 56 | 7,641 / 128 | 7,484 / 139 |
| GitHub issues JSON, 238,682 | 50,090 / 344 | 50,040 / 933 | 48,827 / 1,395 | 46,009 / 2,171 | 60,902 / 1,023 | 51,740 / 2,084 | 51,034 / 2,695 |
| the upstream's synthetic page, 33,211 | 10,752 / 51 | 10,676 / 115 | 10,637 / 245 | 10,247 / 390 | 11,616 / 86 | 10,789 / 367 | 10,643 / 548 |

Read:

- **brotli 4 against 3 on real HTML**: 5 to 7 % fewer bytes (Laravel 6.4, WordPress 4.9, Hacker News 6.4, MDN
  5.8, Debian 7.2; JSON 2.5 to 3.2) for 1.5 to 1.8 times the CPU (WordPress 191 to 337 µs). The synthetic page
  (0.4 % for 2.1 times) is repetitive prose and misleads on level comparisons; `beds-compression-20261030.md`'s
  "2.7 times for 0.4 %" came from it.
- **gzip 5 against 1 on real HTML**: 7 to 17 % fewer bytes (Laravel 12.5, WordPress 16, MDN 17, issues JSON 15,
  Hacker News 7) for 1.9 to 2.3 times the CPU (WordPress 198 to 399 µs). The synthetic page's "4.3 times for 7 %"
  misleads the same way.
- **zstd 3** is within 2 % of brotli 3's bytes on every page (ahead on Hacker News and the commits JSON) at a
  quarter to a third of its CPU and a sixth to a quarter of gzip 5's; 1 to 8 % behind brotli 4 on HTML.
- brotli 3 is within 1 to 6 % of gzip 5's bytes at half its CPU on the CMS pages; brotli 4 is 1 % above to 5 %
  below gzip 5's bytes at 0.8 of its CPU.

## Flushed per 16 KB against whole: bytes

| encoder | Laravel | WordPress | Hacker News | MDN | commits JSON | issues JSON | synthetic page |
|---|---|---|---|---|---|---|---|
| brotli 1 | +31.7 % | +13.4 % | +19.2 % | +42.3 % | +22.2 % | +39.4 % | +7.3 % |
| brotli 2 | −2.6 % | +2.3 % | +3.7 % | +2.3 % | +2.9 % | +2.7 % | +1.1 % |
| brotli 3 | −3.2 % | +1.0 % | +2.0 % | +0.9 % | +1.4 % | +1.7 % | +0.2 % |
| brotli 4 | −0.4 % | +0.6 % | +1.8 % | +1.7 % | +1.2 % | +2.0 % | +0.4 % |
| brotli 5 | −0.3 % | +0.9 % | +1.9 % | +1.4 % | +0.6 % | +2.0 % | +0.4 % |
| gzip 5 | −2.5 % | +0.3 % | +1.3 % | +0.4 % | +0.7 % | +0.9 % | −0.5 % |
| zstd 3 | −3.0 % | +0.6 % | +2.3 % | +1.6 % | +1.9 % | +0.9 % | +0.4 % |

Debian's page (15,864 bytes) fits one piece and is unchanged by flushing. The Laravel page compresses smaller
when flushed with every encoder: its block boundaries then fall between the inline style sheet and the markup.

Read: **the flushed-stream loss is brotli 1's alone** (its one-pass mode, 7 to 42 %); from quality 2 up a flush
every 16 KB costs 0 to 4 %, the same as gzip 5 and zstd 3 pay. The research note measured brotli 1, 4, 5 and 6
flushed (`cdn_browsers_cost_bench/`, `bq[] = {1, 4, 5, 6}`), never 2 or 3, and the design generalised "brotli below
quality 4 loses up to 24 % when flushed" from quality 1; at quality 3 that reason does not hold. The time per
answer of a flushed stream is up to about a quarter above the whole answer's at every level (the flushes, the
fixed window).

## Cost of the whole-answer limit (`compress_answer::kWholeMax`), from the table

The time one answer holds the worker when compressed whole between two reads: at 64 KB about 0.05 ms (zstd 3),
0.3 ms (brotli 4), 0.4 ms (gzip 5); at 256 KB (the issues JSON) 0.34, 1.4 and 2.1 ms. A page a browser asks for
gets zstd (Chrome and Firefox, 83 % of browsers), so the common case at 256 KB is 0.3 ms and the worst 2.1 ms for
a gzip-only client.

## The beds with the new defaults (the limit 256 KB, brotli 3), the same day

- commit: ded536d4+dirty (the tree of this change); Laravel `bench/laravel/bench.sh -p unix -u / -e <coding>` on the
  host (`laravel-20261030-151420.md` zstd, `laravel-20261030-151530.md` br, raw wrk output beside each; the script
  runs nginx and reads the pool's cgroup through docker, so it runs on the host, not in the devbox); WordPress
  `bench/wordpress/.ddev/bench.sh build/agensio <coding> 10s 64` (raw in `raw/wordpress-compression-20261030-1515/`;
  the script's `ROOT` was one directory short until this change); one worker, wrk 4 threads, 64 connections, 10 s
- encoder µs = web µs/req minus the identity row's (Laravel's 49.3 from `beds-compression-20261030.md`)

| bed | coding | req/s | p50 | p99 | web µs/req | encoder µs | php µs/req | bytes/ans | ratio |
|---|---|---|---|---|---|---|---|---|---|
| Laravel / (82,458 bytes) | zstd 3 | 3509 | 17.8 ms | 22.8 ms | 147.0 | 98 | 2214 | 18397 | 4.5:1 |
| Laravel / | brotli 3 | 2542 | 24.5 ms | 31.3 ms | 384.5 | 335 | 2496 | 18196 | 4.5:1 |
| WordPress / (70,286 bytes) | identity | 355 | 178 ms | 206 ms | 163.3 | | 20635 | 70549 | |
| WordPress / | zstd 3 | 354 | 180 ms | 199 ms | 336.2 | 173 | 20700 | 13664 | 5.2:1 |
| WordPress / | brotli 3 | 344 | 182 ms | 219 ms | 534.4 | 371 | 21275 | 13397 | 5.3:1 |

Read: both pages are compressed now (identity with Vary in the morning's run). Through the server each encoder
costs more than the program measures on the page alone in a hot loop: zstd 3 98 µs against 68 on Laravel's page
and 173 against 54 on WordPress's, brotli 3 335 against 262 and 371 against 191. The program's loop keeps the
page and the encoder's tables in cache; the worker meets them cold after the socket read and whatever it did
between two answers. The relative picture holds (zstd 3 at a third to a half of brotli 3, brotli 3 at 0.6 of the
morning's brotli 4 on WordPress: 371 against 643), and the gap between the loop and the server is the next thing
to profile on the compression path (`perf` in the `agensio-devbox-perf` image under the WordPress bed).
