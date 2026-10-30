// Whole against flushed-per-16 KB output and cost per level, the way compress.cpp (step 4) and
// the step-6 CompressedBody would call the encoders: brotli 1-5 (window sized to the input for a
// whole answer, 2^18 for a stream), zlib 1/5/6 (window 2^15, memLevel 8, one reset context),
// zstd 3 (window 2^19, one context). One thread, 60 calls per row (20 above 200 KB), CSV on stdout.
// Build and run in the devbox: g++ -O2 -std=c++23 flush-levels.cpp -lbrotlienc -lz -lzstd -o flush-levels;
// ./flush-levels FILE...   Numbers of 2026-10-30 in bench/results/compression-levels-20261030.md.
#include <brotli/encode.h>
#include <zlib.h>
#include <zstd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static std::vector<std::uint8_t> out;
static const std::size_t kChunk = 16 * 1024;

static int lgwin_for(std::size_t n) {
    int lg = 10;
    while (lg < 18 && (std::size_t(1) << lg) - 16 < n) ++lg;
    return lg;
}

static std::size_t brotli_run(int q, const std::string& in, bool stream) {
    BrotliEncoderState* st = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    BrotliEncoderSetParameter(st, BROTLI_PARAM_QUALITY, q);
    BrotliEncoderSetParameter(st, BROTLI_PARAM_LGWIN, stream ? 18 : lgwin_for(in.size()));
    if (!stream) BrotliEncoderSetParameter(st, BROTLI_PARAM_SIZE_HINT, in.size());
    std::size_t avail_in = in.size();
    const std::uint8_t* next_in = reinterpret_cast<const std::uint8_t*>(in.data());
    std::size_t total = 0;
    while (true) {
        const std::size_t piece = stream ? std::min(kChunk, avail_in) : avail_in;
        const bool last = piece == avail_in;
        const BrotliEncoderOperation op = last ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_FLUSH;
        std::size_t ai = piece;
        do {
            std::size_t avail_out = out.size() - total;
            std::uint8_t* next_out = out.data() + total;
            BrotliEncoderCompressStream(st, op, &ai, &next_in, &avail_out, &next_out, nullptr);
            total = out.size() - avail_out;
        } while (ai > 0 || BrotliEncoderHasMoreOutput(st) || (last && !BrotliEncoderIsFinished(st)));
        avail_in -= piece;
        if (last) break;
    }
    BrotliEncoderDestroyInstance(st);
    return total;
}

static std::size_t zlib_run(z_stream& z, const std::string& in, bool stream) {
    deflateReset(&z);
    std::size_t done = 0, total = 0;
    while (true) {
        const std::size_t piece = stream ? std::min(kChunk, in.size() - done) : in.size();
        const bool last = done + piece == in.size();
        z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data() + done));
        z.avail_in = static_cast<uInt>(piece);
        z.next_out = out.data() + total;
        z.avail_out = static_cast<uInt>(out.size() - total);
        deflate(&z, last ? Z_FINISH : Z_SYNC_FLUSH);
        total = out.size() - z.avail_out;
        done += piece;
        if (last) break;
    }
    return total;
}

static std::size_t zstd_run(ZSTD_CCtx* c, const std::string& in, bool stream) {
    ZSTD_CCtx_reset(c, ZSTD_reset_session_only);
    if (!stream) {
        ZSTD_CCtx_setPledgedSrcSize(c, in.size());
        return ZSTD_compress2(c, out.data(), out.size(), in.data(), in.size());
    }
    std::size_t done = 0;
    ZSTD_outBuffer ob{out.data(), out.size(), 0};
    while (true) {
        const std::size_t piece = std::min(kChunk, in.size() - done);
        const bool last = done + piece == in.size();
        ZSTD_inBuffer ib{in.data() + done, piece, 0};
        std::size_t r;
        do {  // e_flush and e_end both answer 0 once everything is out
            r = ZSTD_compressStream2(c, &ob, &ib, last ? ZSTD_e_end : ZSTD_e_flush);
        } while (r != 0 || ib.pos < ib.size);
        done += piece;
        if (last) break;
    }
    return ob.pos;
}

template <class F>
static void row(const char* file, const char* codec, int level, const char* mode, std::size_t size, F f) {
    const int iters = size > 200000 ? 20 : 60;
    std::size_t bytes = 0;
    f();  // warm
    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < iters; ++i) bytes = f();
    const auto us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / iters;
    std::printf("%s,%zu,%s,%d,%s,%zu,%.1f\n", file, size, codec, level, mode, bytes, us);
}

int main(int argc, char** argv) {
    std::printf("file,size,codec,level,mode,bytes,us\n");
    for (int a = 1; a < argc; ++a) {
        std::ifstream f(argv[a], std::ios::binary);
        std::string in((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (in.empty()) continue;
        out.assign(in.size() + in.size() / 8 + 4096, 0);
        const char* name = std::strrchr(argv[a], '/') ? std::strrchr(argv[a], '/') + 1 : argv[a];
        for (int q : {1, 2, 3, 4, 5}) {
            row(name, "brotli", q, "whole", in.size(), [&] { return brotli_run(q, in, false); });
            row(name, "brotli", q, "flush16k", in.size(), [&] { return brotli_run(q, in, true); });
        }
        for (int l : {1, 5, 6}) {
            z_stream z{};
            deflateInit2(&z, l, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY);
            row(name, "gzip", l, "whole", in.size(), [&] { return zlib_run(z, in, false); });
            row(name, "gzip", l, "flush16k", in.size(), [&] { return zlib_run(z, in, true); });
            deflateEnd(&z);
        }
        ZSTD_CCtx* c = ZSTD_createCCtx();
        ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, 3);
        ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, 19);
        ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 0);
        row(name, "zstd", 3, "whole", in.size(), [&] { return zstd_run(c, in, false); });
        row(name, "zstd", 3, "flush16k", in.size(), [&] { return zstd_run(c, in, true); });
        ZSTD_freeCCtx(c);
    }
}
