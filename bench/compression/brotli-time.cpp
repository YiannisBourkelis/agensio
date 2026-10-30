// Build and run in the devbox (g++ -O2 -std=c++23 brotli-time.cpp -lbrotlienc -o brotli-time; ./brotli-time page.html,
// the page being the benchmark upstream's /page: build/agensio_upstream -p 9177 -w 1, then curl). Numbers of
// 2026-10-30 in bench/results/beds-compression-20261030.md.
// Where brotli 4's per-answer cost goes on the upstream's 32 KB page: the one-shot call at the
// library's window and at a window sized to the input, the stream API as compress.cpp uses it
// (an encoder made and freed per answer), and the same with a reused arena behind the encoder's
// allocator (no mmap, no page faults per answer).
#include <brotli/encode.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::string page;
static std::vector<std::uint8_t> out;

struct Arena {
    std::vector<char> buf;
    std::size_t used = 0;
    void reset() { used = 0; }
    void* alloc(std::size_t n) {
        n = (n + 63) & ~std::size_t(63);
        if (used + n > buf.size()) { std::fprintf(stderr, "arena too small\n"); std::abort(); }
        void* p = buf.data() + used;
        used += n;
        return p;
    }
};
static Arena arena;
static void* arena_alloc(void*, std::size_t n) { return arena.alloc(n); }
static void arena_free(void*, void*) {}

static std::size_t stream_compress(int quality, int lgwin, bool use_arena) {
    BrotliEncoderState* enc = use_arena ? BrotliEncoderCreateInstance(arena_alloc, arena_free, nullptr) : BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_QUALITY, quality);
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_LGWIN, lgwin);
    BrotliEncoderSetParameter(enc, BROTLI_PARAM_SIZE_HINT, page.size());
    std::size_t avail_in = page.size(), avail_out = out.size();
    const auto* next_in = reinterpret_cast<const std::uint8_t*>(page.data());
    std::uint8_t* next_out = out.data();
    while (!BrotliEncoderIsFinished(enc)) {
        if (!BrotliEncoderCompressStream(enc, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, nullptr)) std::abort();
    }
    BrotliEncoderDestroyInstance(enc);
    if (use_arena) arena.reset();
    return out.size() - avail_out;
}

static std::size_t oneshot(int quality, int lgwin) {
    std::size_t n = out.size();
    if (!BrotliEncoderCompress(quality, lgwin, BROTLI_MODE_GENERIC, page.size(), reinterpret_cast<const std::uint8_t*>(page.data()), &n, out.data())) std::abort();
    return n;
}

template <class F>
static void time_it(const char* name, F f) {
    for (int i = 0; i < 20; ++i) f();  // warm
    const int n = 300;
    const auto t0 = std::chrono::steady_clock::now();
    std::size_t size = 0;
    for (int i = 0; i < n; ++i) size = f();
    const auto t1 = std::chrono::steady_clock::now();
    std::printf("%-44s %7.1f us  %6zu bytes\n", name, std::chrono::duration<double, std::micro>(t1 - t0).count() / n, size);
}

int main(int argc, char** argv) {
    if (argc < 2) return 2;
    std::ifstream f(argv[1], std::ios::binary);
    page.assign(std::istreambuf_iterator<char>(f), {});
    out.resize(BrotliEncoderMaxCompressedSize(page.size()) + 64);
    arena.buf.resize(16u << 20);
    std::printf("page %zu bytes, brotli %x\n", page.size(), BrotliEncoderVersion());
    for (int q : {4, 3, 2, 1}) {
        char n1[64], n2[64], n3[64], n4[64];
        std::snprintf(n1, sizeof n1, "one-shot q%d lgwin 22 (library default)", q);
        std::snprintf(n2, sizeof n2, "one-shot q%d lgwin 16 (sized to the page)", q);
        std::snprintf(n3, sizeof n3, "stream q%d lgwin 16, encoder per answer", q);
        std::snprintf(n4, sizeof n4, "stream q%d lgwin 16, reused arena", q);
        time_it(n1, [&] { return oneshot(q, 22); });
        time_it(n2, [&] { return oneshot(q, 16); });
        time_it(n3, [&] { return stream_compress(q, 16, false); });
        time_it(n4, [&] { return stream_compress(q, 16, true); });
    }
    return 0;
}
