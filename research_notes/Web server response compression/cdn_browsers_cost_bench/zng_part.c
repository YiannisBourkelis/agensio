#include <stdlib.h>
#include <zlib-ng.h>
void *cnt_alloc_pub(size_t n);
void cnt_free_pub(void *p);
static void *a(void *o, unsigned i, unsigned s) { (void)o; return cnt_alloc_pub((size_t)i * s); }
static void f(void *o, void *p) { (void)o; cnt_free_pub(p); }
void *zng_new(int level, int count) {
    zng_stream *zs = calloc(1, sizeof *zs);
    if (count) { zs->zalloc = a; zs->zfree = f; }
    zng_deflateInit2(zs, level, Z_DEFLATED, 31, 8, Z_DEFAULT_STRATEGY);
    return zs;
}
size_t zng_oneshot(void *p, const unsigned char *in, size_t n, unsigned char *out, size_t cap) {
    zng_stream *zs = p;
    zng_deflateReset(zs);
    zs->next_in = in; zs->avail_in = n; zs->next_out = out; zs->avail_out = cap;
    zng_deflate(zs, Z_FINISH);
    return cap - zs->avail_out;
}
void zng_del(void *p) { zng_deflateEnd(p); free(p); }
