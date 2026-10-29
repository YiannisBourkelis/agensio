// Compression cost benchmark: gzip (zlib, zlib-ng, libdeflate), brotli, zstd.
// Usage: cbench speed FILE...   -> CSV: file,size,codec,level,mode,out,us_per_resp,mbps
//        cbench mem             -> CSV of peak heap per encoder (100 KB known size, 1 MB stream)
#define _GNU_SOURCE
#include <brotli/encode.h>
#include <libdeflate.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <zlib.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

static double now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

// ---- counting allocator (size header) ----
static size_t cur_bytes, peak_bytes;
static void *cnt_alloc(size_t n) {
    size_t *p = malloc(n + 16);
    if (!p) return NULL;
    p[0] = n;
    cur_bytes += n;
    if (cur_bytes > peak_bytes) peak_bytes = cur_bytes;
    return (char *)p + 16;
}
static void cnt_free(void *q) {
    if (!q) return;
    size_t *p = (size_t *)((char *)q - 16);
    cur_bytes -= p[0];
    free(p);
}
static void *z_alloc(void *o, unsigned items, unsigned size) { (void)o; return cnt_alloc((size_t)items * size); }
static void z_free(void *o, void *p) { (void)o; cnt_free(p); }
void *cnt_alloc_pub(size_t n) { return cnt_alloc(n); }
void cnt_free_pub(void *p) { cnt_free(p); }
void *zng_new(int level, int count);
size_t zng_oneshot(void *p, const unsigned char *in, size_t n, unsigned char *out, size_t cap);
void zng_del(void *p);
static void *b_alloc(void *o, size_t n) { (void)o; return cnt_alloc(n); }
static void b_free(void *o, void *p) { (void)o; cnt_free(p); }
static void *zs_alloc(void *o, size_t n) { (void)o; return cnt_alloc(n); }
static void zs_free(void *o, void *p) { (void)o; cnt_free(p); }
static void reset_count(void) { cur_bytes = peak_bytes = 0; }

static unsigned char *obuf;
static size_t ocap;

// ---- one-shot compressors (whole response in memory, size known) ----
static size_t c_zlib(const unsigned char *in, size_t n, z_stream *zs) {
    deflateReset(zs);
    zs->next_in = (unsigned char *)in; zs->avail_in = n;
    zs->next_out = obuf; zs->avail_out = ocap;
    deflate(zs, Z_FINISH);
    return ocap - zs->avail_out;
}
static size_t c_brotli(const unsigned char *in, size_t n, int q) {
    size_t out = ocap;
    BrotliEncoderCompress(q, BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, n, in, &out, obuf);
    return out;
}
static size_t c_zstd(const unsigned char *in, size_t n, ZSTD_CCtx *cc) {
    return ZSTD_compress2(cc, obuf, ocap, in, n);
}

// ---- streaming: 16 KB chunks, flush after each, size unknown ----
#define CHUNK 16384
static size_t s_zlib(const unsigned char *in, size_t n, z_stream *zs) {
    deflateReset(zs);
    size_t total = 0;
    for (size_t off = 0; off < n; off += CHUNK) {
        size_t len = n - off < CHUNK ? n - off : CHUNK;
        int last = off + len >= n;
        zs->next_in = (unsigned char *)in + off; zs->avail_in = len;
        zs->next_out = obuf + total; zs->avail_out = ocap - total;
        deflate(zs, last ? Z_FINISH : Z_SYNC_FLUSH);
        total = ocap - zs->avail_out;
    }
    return total;
}
static size_t s_brotli(const unsigned char *in, size_t n, int q, int count) {
    BrotliEncoderState *s = count ? BrotliEncoderCreateInstance(b_alloc, b_free, NULL)
                                  : BrotliEncoderCreateInstance(NULL, NULL, NULL);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, q);
    BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, BROTLI_DEFAULT_WINDOW);
    size_t total = 0;
    for (size_t off = 0; off < n; off += CHUNK) {
        size_t len = n - off < CHUNK ? n - off : CHUNK;
        int last = off + len >= n;
        const uint8_t *nin = in + off;
        size_t ain = len;
        uint8_t *nout = obuf + total;
        size_t aout = ocap - total;
        BrotliEncoderOperation op = last ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
        do {
            BrotliEncoderCompressStream(s, op, &ain, &nin, &aout, &nout, NULL);
        } while (ain > 0 || BrotliEncoderHasMoreOutput(s) ||
                 (last && !BrotliEncoderIsFinished(s)));
        total = ocap - aout;
    }
    BrotliEncoderDestroyInstance(s);
    return total;
}
static size_t s_zstd(const unsigned char *in, size_t n, ZSTD_CCtx *cc) {
    ZSTD_CCtx_reset(cc, ZSTD_reset_session_only);
    size_t total = 0;
    for (size_t off = 0; off < n; off += CHUNK) {
        size_t len = n - off < CHUNK ? n - off : CHUNK;
        int last = off + len >= n;
        ZSTD_inBuffer ib = {in + off, len, 0};
        ZSTD_outBuffer ob = {obuf, ocap, total};
        size_t r;
        do {
            r = ZSTD_compressStream2(cc, &ob, &ib, last ? ZSTD_e_end : ZSTD_e_flush);
        } while (r != 0 && !ZSTD_isError(r));
        total = ob.pos;
    }
    return total;
}

static unsigned char *load(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END); *n = ftell(f); fseek(f, 0, SEEK_SET);
    unsigned char *b = malloc(*n);
    if (fread(b, 1, *n, f) != *n) exit(1);
    fclose(f);
    return b;
}

#define MINT 0.12
#define TIMEIT(expr)                                                     \
    do {                                                                 \
        int runs = 0; double t0 = now(), t;                              \
        do { out = (expr); runs++; t = now() - t0; } while (t < MINT || runs < 3); \
        us = t / runs * 1e6;                                             \
    } while (0)

static void row(const char *file, size_t n, const char *codec, int level, const char *mode, size_t out, double us) {
    printf("%s,%zu,%s,%d,%s,%zu,%.2f,%.1f\n", file, n, codec, level, mode, out, us, n / us);
    fflush(stdout);
}

static void speed(const char *path) {
    size_t n; unsigned char *in = load(path, &n);
    const char *file = strrchr(path, '/') ? strrchr(path, '/') + 1 : path;
    size_t out; double us;
    for (int l = 1; l <= 9; l++) {
        z_stream zs = {0};
        deflateInit2(&zs, l, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        TIMEIT(c_zlib(in, n, &zs));
        row(file, n, "zlib", l, "oneshot", out, us);
        deflateEnd(&zs);
    }
    for (int l = 1; l <= 9; l++) {
        void *zs = zng_new(l, 0);
        TIMEIT(zng_oneshot(zs, in, n, obuf, ocap));
        row(file, n, "zlib-ng", l, "oneshot", out, us);
        zng_del(zs);
    }
    for (int l = 1; l <= 12; l++) {
        struct libdeflate_compressor *c = libdeflate_alloc_compressor(l);
        TIMEIT(libdeflate_gzip_compress(c, in, n, obuf, ocap));
        row(file, n, "libdeflate", l, "oneshot", out, us);
        libdeflate_free_compressor(c);
    }
    for (int q = 0; q <= 11; q++) {
        TIMEIT(c_brotli(in, n, q));
        row(file, n, "brotli", q, "oneshot", out, us);
    }
    for (int l = -5; l <= 19; l++) {
        if (l == 0) continue;
        ZSTD_CCtx *cc = ZSTD_createCCtx();
        ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, l);
        TIMEIT(c_zstd(in, n, cc));
        row(file, n, "zstd", l, "oneshot", out, us);
        ZSTD_freeCCtx(cc);
    }
    // Streaming with a flush every 16 KB and unknown total size (a proxied/dynamic response).
    int zl[] = {1, 4, 6};
    for (int i = 0; i < 3; i++) {
        z_stream zs = {0};
        deflateInit2(&zs, zl[i], Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
        TIMEIT(s_zlib(in, n, &zs));
        row(file, n, "zlib", zl[i], "stream16k", out, us);
        deflateEnd(&zs);
    }
    int bq[] = {1, 4, 5, 6};
    for (int i = 0; i < 4; i++) {
        TIMEIT(s_brotli(in, n, bq[i], 0));
        row(file, n, "brotli", bq[i], "stream16k", out, us);
    }
    int sl[] = {1, 3, 6};
    for (int i = 0; i < 3; i++) {
        ZSTD_CCtx *cc = ZSTD_createCCtx();
        ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, sl[i]);
        TIMEIT(s_zstd(in, n, cc));
        row(file, n, "zstd", sl[i], "stream16k", out, us);
        ZSTD_freeCCtx(cc);
    }
    // Per-response setup cost: fresh encoder each time (zlib init vs reset; zstd new cctx).
    {
        TIMEIT(({ z_stream zs = {0}; deflateInit2(&zs, 6, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
                  zs.next_in = in; zs.avail_in = n; zs.next_out = obuf; zs.avail_out = ocap;
                  deflate(&zs, Z_FINISH); size_t o = ocap - zs.avail_out; deflateEnd(&zs); o; }));
        row(file, n, "zlib", 6, "fresh-init", out, us);
        TIMEIT(({ ZSTD_CCtx *cc = ZSTD_createCCtx(); size_t o = ZSTD_compress(cc ? obuf : obuf, ocap, in, n, 3); ZSTD_freeCCtx(cc); o; }));
        row(file, n, "zstd", 3, "fresh-cctx", out, us);
    }
    free(in);
}

// Peak heap of one encoder, compressing (a) a 100 KB response whose size is known,
// (b) 1 MB streamed in 16 KB chunks with a flush each, size unknown.
static void mem(const char *path) {
    size_t n; unsigned char *big = load(path, &n);
    size_t sizes[2] = {100 * 1024, n};
    for (int k = 0; k < 2; k++) {
        size_t len = sizes[k] < n ? sizes[k] : n;
        const char *mode = k == 0 ? "known-100KB" : "stream-unknown";
        for (int l = 1; l <= 9; l += 1) {
            reset_count();
            z_stream zs = {0}; zs.zalloc = z_alloc; zs.zfree = z_free;
            deflateInit2(&zs, l, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
            k == 0 ? c_zlib(big, len, &zs) : s_zlib(big, len, &zs);
            deflateEnd(&zs);
            printf("mem,zlib,%d,%s,%zu,%zu\n", l, mode, len, peak_bytes);
        }
        for (int l = 1; l <= 9; l += 4) {
            reset_count();
            void *zs = zng_new(l, 1);
            zng_oneshot(zs, big, len, obuf, ocap);
            zng_del(zs);
            printf("mem,zlib-ng,%d,%s,%zu,%zu\n", l, mode, len, peak_bytes);
        }
        if (k == 0) {
            int ll[] = {1, 6, 9, 12};
            for (int i = 0; i < 4; i++) {
                reset_count();
                struct libdeflate_options o = {.sizeof_options = sizeof o, .malloc_func = cnt_alloc, .free_func = cnt_free};
                struct libdeflate_compressor *c = libdeflate_alloc_compressor_ex(ll[i], &o);
                libdeflate_gzip_compress(c, big, len, obuf, ocap);
                libdeflate_free_compressor(c);
                printf("mem,libdeflate,%d,%s,%zu,%zu\n", ll[i], mode, len, peak_bytes);
            }
        }
        for (int q = 0; q <= 11; q++) {
            reset_count();
            if (k == 0) {
                BrotliEncoderState *s = BrotliEncoderCreateInstance(b_alloc, b_free, NULL);
                BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, q);
                BrotliEncoderSetParameter(s, BROTLI_PARAM_SIZE_HINT, len);
                size_t ain = len, aout = ocap; const uint8_t *ni = big; uint8_t *no = obuf;
                while (!BrotliEncoderIsFinished(s))
                    BrotliEncoderCompressStream(s, BROTLI_OPERATION_FINISH, &ain, &ni, &aout, &no, NULL);
                BrotliEncoderDestroyInstance(s);
            } else {
                s_brotli(big, len, q, 1);
            }
            printf("mem,brotli,%d,%s,%zu,%zu\n", q, mode, len, peak_bytes);
        }
        int zl[] = {-5, -1, 1, 2, 3, 4, 5, 6, 7, 9, 12, 15, 19};
        for (int i = 0; i < 13; i++) {
            reset_count();
            ZSTD_customMem cm = {zs_alloc, zs_free, NULL};
            ZSTD_CCtx *cc = ZSTD_createCCtx_advanced(cm);
            ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, zl[i]);
            k == 0 ? c_zstd(big, len, cc) : s_zstd(big, len, cc);
            ZSTD_freeCCtx(cc);
            printf("mem,zstd,%d,%s,%zu,%zu,est_cstream=%zu\n", zl[i], mode, len, peak_bytes,
                   ZSTD_estimateCStreamSize(zl[i]));
        }
    }
}

// Peak heap and output size with a limited window, streamed with unknown size.
static void memwin(const char *path) {
    size_t n; unsigned char *in = load(path, &n);
    int bq[] = {4, 5, 6}, lg[] = {16, 18, 19, 20, 22};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 5; j++) {
            reset_count();
            BrotliEncoderState *s = BrotliEncoderCreateInstance(b_alloc, b_free, NULL);
            BrotliEncoderSetParameter(s, BROTLI_PARAM_QUALITY, bq[i]);
            BrotliEncoderSetParameter(s, BROTLI_PARAM_LGWIN, lg[j]);
            size_t total = 0;
            for (size_t off = 0; off < n; off += CHUNK) {
                size_t len = n - off < CHUNK ? n - off : CHUNK; int last = off + len >= n;
                const uint8_t *ni = in + off; size_t ain = len; uint8_t *no = obuf + total; size_t aout = ocap - total;
                BrotliEncoderOperation op = last ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
                do BrotliEncoderCompressStream(s, op, &ain, &ni, &aout, &no, NULL);
                while (ain > 0 || BrotliEncoderHasMoreOutput(s) || (last && !BrotliEncoderIsFinished(s)));
                total = ocap - aout;
            }
            BrotliEncoderDestroyInstance(s);
            printf("memwin,brotli,q%d,lgwin%d,%zu,peak=%zu,out=%zu\n", bq[i], lg[j], n, peak_bytes, total);
        }
    int zl[] = {1, 3, 6}, wl[] = {17, 19, 20, 21, 23};
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 5; j++) {
            reset_count();
            ZSTD_customMem cm = {zs_alloc, zs_free, NULL};
            ZSTD_CCtx *cc = ZSTD_createCCtx_advanced(cm);
            ZSTD_CCtx_setParameter(cc, ZSTD_c_compressionLevel, zl[i]);
            ZSTD_CCtx_setParameter(cc, ZSTD_c_windowLog, wl[j]);
            size_t out = s_zstd(in, n, cc);
            ZSTD_freeCCtx(cc);
            printf("memwin,zstd,l%d,wlog%d,%zu,peak=%zu,out=%zu\n", zl[i], wl[j], n, peak_bytes, out);
        }
    // zstd default parameters per level for unknown size (windowLog, chainLog, hashLog, strategy)
    for (int l = 1; l <= 19; l++) {
        ZSTD_compressionParameters p = ZSTD_getCParams(l, ZSTD_CONTENTSIZE_UNKNOWN, 0);
        ZSTD_compressionParameters q = ZSTD_getCParams(l, 100 * 1024, 0);
        printf("zstdparams,%d,unknown:wlog=%u,clog=%u,hlog=%u,strat=%d,known100KB:wlog=%u,clog=%u,hlog=%u\n", l,
               p.windowLog, p.chainLog, p.hashLog, p.strategy, q.windowLog, q.chainLog, q.hashLog);
    }
}

int main(int argc, char **argv) {
    ocap = 64 << 20;
    obuf = malloc(ocap);
    if (argc >= 3 && !strcmp(argv[1], "memwin")) { memwin(argv[2]); return 0; }
    if (argc >= 3 && !strcmp(argv[1], "mem")) { mem(argv[2]); return 0; }
    printf("file,size,codec,level,mode,out,us_per_resp,mbps\n");
    for (int i = 2; i < argc; i++) speed(argv[i]);
    return 0;
}
