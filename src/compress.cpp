#include "compress.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <random>

#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef AGENSIO_HAS_ZSTD
#include <zstd.h>
#endif
#ifdef AGENSIO_HAS_BROTLI
#include <brotli/encode.h>
#endif

namespace agensio {

bool coding_built(Encoding e) noexcept {
    switch (e) {
        case Encoding::gzip:
#ifdef AGENSIO_HAS_ZLIB
            return true;
#else
            return false;
#endif
        case Encoding::zstd:
#ifdef AGENSIO_HAS_ZSTD
            return true;
#else
            return false;
#endif
        case Encoding::br:
#ifdef AGENSIO_HAS_BROTLI
            return true;
#else
            return false;
#endif
        case Encoding::identity: break;
    }
    return true;
}

std::string_view coding_package(Encoding e) noexcept {
    switch (e) {
        case Encoding::gzip: return "zlib1g-dev";
        case Encoding::zstd: return "libzstd-dev";
        case Encoding::br: return "libbrotli-dev";
        case Encoding::identity: break;
    }
    return "";
}

bool compress_whole(Encoding e, int level, std::string_view in, std::vector<char>& out) {
    out.clear();
    switch (e) {
        case Encoding::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            // gzip framing (RFC 1952) through deflateInit2's windowBits + 16; window 2^15, memLevel 8:
            // zlib's own, the output every browser decodes.
            z_stream z{};
            if (deflateInit2(&z, std::clamp(level, 1, 9), Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) return false;
            const uLong bound = deflateBound(&z, static_cast<uLong>(in.size()));
            out.resize(static_cast<std::size_t>(bound));
            z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT: zlib's API, not written to
            z.avail_in = static_cast<uInt>(in.size());
            z.next_out = reinterpret_cast<Bytef*>(out.data());
            z.avail_out = static_cast<uInt>(out.size());
            const int rc = deflate(&z, Z_FINISH);
            const std::size_t produced = static_cast<std::size_t>(z.total_out);
            deflateEnd(&z);
            if (rc != Z_STREAM_END) {
                out.clear();
                return false;
            }
            out.resize(produced);
            return true;
#else
            return false;
#endif
        }
        case Encoding::zstd: {
#ifdef AGENSIO_HAS_ZSTD
            out.resize(ZSTD_compressBound(in.size()));
            const std::size_t n = ZSTD_compress(out.data(), out.size(), in.data(), in.size(), std::clamp(level, 1, 19));
            if (ZSTD_isError(n)) {
                out.clear();
                return false;
            }
            out.resize(n);
            return true;
#else
            return false;
#endif
        }
        case Encoding::br: {
#ifdef AGENSIO_HAS_BROTLI
            // The window from the input's size (BrotliEncoderCompress picks lgwin for a one-shot input,
            // at most BROTLI_MAX_WINDOW_BITS); the whole input is in memory, so no per-stream cost.
            std::size_t n = BrotliEncoderMaxCompressedSize(in.size());
            if (n == 0) return false;
            out.resize(n);
            if (!BrotliEncoderCompress(std::clamp(level, 0, 11), BROTLI_DEFAULT_WINDOW, BROTLI_MODE_GENERIC, in.size(),
                                       reinterpret_cast<const std::uint8_t*>(in.data()), &n, reinterpret_cast<std::uint8_t*>(out.data()))) {
                out.clear();
                return false;
            }
            out.resize(n);
            return true;
#else
            return false;
#endif
        }
        case Encoding::identity: break;
    }
    return false;
}

unsigned padding_length() noexcept {
    // xorshift64* per thread, seeded once from the system; the length only has to be unguessable
    // enough that an attacker averaging an answer's length pays for every sample (design 7).
    thread_local std::uint64_t state = [] {
        std::random_device rd;
        std::uint64_t s = (static_cast<std::uint64_t>(rd()) << 32) ^ rd();
        return s ? s : 0x9E3779B97F4A7C15ULL;
    }();
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return static_cast<unsigned>((state * 0x2545F4914F6CDD1DULL >> 32) % (kPaddingMax + 1));
}

#ifdef AGENSIO_HAS_ZLIB
namespace {
// The zlib stream with the header it writes: FEXTRA carries the padding as one subfield (RFC 1952
// 2.3.1.1: SI1, SI2, a little-endian length, the bytes), zero bytes of a length drawn per answer.
struct GzipState {
    z_stream z{};
    gz_header header{};
    unsigned char extra[4 + kPaddingMax] = {'a', 'g', 0, 0};
};
}  // namespace
#endif

GzipContext::GzipContext() = default;

GzipContext::~GzipContext() {
#ifdef AGENSIO_HAS_ZLIB
    if (z_) {
        auto* st = static_cast<GzipState*>(z_);
        deflateEnd(&st->z);
        delete st;
    }
#endif
}

bool GzipContext::compress(int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;  // one deflate call: zlib's counts are 32-bit
#ifdef AGENSIO_HAS_ZLIB
    level = std::clamp(level, 1, 9);
    auto* st = static_cast<GzipState*>(z_);
    if (!st) {
        st = new GzipState;
        // gzip framing (RFC 1952): windowBits 15 + 16, the 32 KB window deflate has at most; memLevel 8, zlib's own.
        if (deflateInit2(&st->z, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            delete st;
            return false;
        }
        st->header.os = 3;  // unix, what zlib writes on its own
        z_ = st;
        level_ = level;
    } else {
        if (deflateReset(&st->z) != Z_OK) return false;  // the stream fresh for this answer
        if (level != level_) {
            if (deflateParams(&st->z, level, Z_DEFAULT_STRATEGY) != Z_OK) return false;
            level_ = level;
        }
    }
    // The header set for every answer (a reset keeps the pointer, the fields are read at the first
    // deflate): the padding's subfield or no extra field at all, the other fields zlib's defaults.
    padding = std::min(padding, kPaddingMax);
    st->extra[2] = static_cast<unsigned char>(padding);
    st->header.extra = padding ? st->extra : nullptr;
    st->header.extra_len = padding ? 4 + padding : 0;
    if (deflateSetHeader(&st->z, &st->header) != Z_OK) return false;
    z_stream* z = &st->z;
    out.resize(static_cast<std::size_t>(deflateBound(z, static_cast<uLong>(in.size()))) + 2 + st->header.extra_len);
    z->next_in = reinterpret_cast<Bytef*>(const_cast<char*>(in.data()));  // NOLINT: zlib's API, not written to
    z->avail_in = static_cast<uInt>(in.size());
    z->next_out = reinterpret_cast<Bytef*>(out.data());
    z->avail_out = static_cast<uInt>(out.size());
    const int rc = deflate(z, Z_FINISH);
    if (rc != Z_STREAM_END) {
        out.clear();
        deflateReset(z);
        return false;
    }
    out.resize(static_cast<std::size_t>(z->total_out));
    return true;
#else
    (void)level;
    (void)padding;
    (void)in;
    return false;
#endif
}

GzipContext& gzip_context() {
    thread_local GzipContext ctx;
    return ctx;
}

ZstdContext::ZstdContext() = default;

ZstdContext::~ZstdContext() {
#ifdef AGENSIO_HAS_ZSTD
    if (cctx_) ZSTD_freeCCtx(static_cast<ZSTD_CCtx*>(cctx_));
#endif
}

bool ZstdContext::compress(int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;
#ifdef AGENSIO_HAS_ZSTD
    level = std::clamp(level, 1, 19);
    auto* cctx = static_cast<ZSTD_CCtx*>(cctx_);
    if (!cctx) {
        cctx = ZSTD_createCCtx();
        if (!cctx) return false;
        // The window capped (design 3; zstd takes the input's own size when that is smaller, as it
        // is for every whole answer); the frame carries the content size, no checksum: the transport
        // has its own, and the browsers do not check it.
        if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_windowLog, kZstdWindowLog)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_contentSizeFlag, 1)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 0)) ||
            ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) {
            ZSTD_freeCCtx(cctx);
            return false;
        }
        cctx_ = cctx;
        level_ = level;
    } else if (level != level_) {
        if (ZSTD_isError(ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, level))) return false;
        level_ = level;
    }
    // A skippable frame first (RFC 8878 3.1.2: magic 0x184D2A50, a little-endian length, the bytes;
    // every decoder of the content coding skips it), then the data frame; ZSTD_compress2 resets the
    // session and keeps the parameters.
    padding = std::min(padding, kPaddingMax);
    const std::size_t prefix = padding ? 8 + padding : 0;
    out.resize(prefix + ZSTD_compressBound(in.size()));
    if (padding) {
        static constexpr unsigned char kMagic[4] = {0x50, 0x2A, 0x4D, 0x18};
        std::memcpy(out.data(), kMagic, 4);
        const unsigned char len[4] = {static_cast<unsigned char>(padding), 0, 0, 0};
        std::memcpy(out.data() + 4, len, 4);
        std::memset(out.data() + 8, 0, padding);
    }
    const std::size_t n = ZSTD_compress2(cctx, out.data() + prefix, out.size() - prefix, in.data(), in.size());
    if (ZSTD_isError(n)) {
        out.clear();
        return false;
    }
    out.resize(prefix + n);
    return true;
#else
    (void)level;
    (void)padding;
    (void)in;
    return false;
#endif
}

ZstdContext& zstd_context() {
    thread_local ZstdContext ctx;
    return ctx;
}

#ifdef AGENSIO_HAS_BROTLI
namespace {
// brotli for one answer: an encoder made and freed here (its state is sized by the window), the
// window the smallest that holds the answer up to the cap (design 3; a window is 2^bits - 16 bytes),
// the padding as a metadata meta-block the decoder skips (RFC 7932 9.2), then the data, finished.
bool brotli_buffered(int quality, unsigned padding, std::string_view in, std::string& out) {
    int lgwin = BROTLI_MIN_WINDOW_BITS;
    while (lgwin < kBrotliWindowBits && (static_cast<std::size_t>(1) << lgwin) - 16 < in.size()) ++lgwin;
    BrotliEncoderState* enc = BrotliEncoderCreateInstance(nullptr, nullptr, nullptr);
    if (!enc) return false;
    bool ok = BrotliEncoderSetParameter(enc, BROTLI_PARAM_QUALITY, static_cast<std::uint32_t>(std::clamp(quality, 0, 11))) &&
              BrotliEncoderSetParameter(enc, BROTLI_PARAM_LGWIN, static_cast<std::uint32_t>(lgwin)) &&
              BrotliEncoderSetParameter(enc, BROTLI_PARAM_SIZE_HINT, static_cast<std::uint32_t>(std::min<std::size_t>(in.size(), 1u << 30)));
    std::size_t bound = BrotliEncoderMaxCompressedSize(in.size());
    if (bound == 0) ok = false;
    if (ok) out.resize(bound + 16 + padding);
    std::size_t avail_out = out.size();
    auto* next_out = reinterpret_cast<std::uint8_t*>(out.data());
    const auto more_room = [&] {  // the bound is for one shot of quality 2 and up; a stream may want more
        const std::size_t used = out.size() - avail_out;
        out.resize(out.size() * 2);
        next_out = reinterpret_cast<std::uint8_t*>(out.data()) + used;
        avail_out = out.size() - used;
    };
    if (ok && padding) {
        static constexpr std::uint8_t kZeros[kPaddingMax] = {};
        std::size_t avail_in = std::min(padding, kPaddingMax);
        const std::uint8_t* next_in = kZeros;
        while (ok && (avail_in > 0 || BrotliEncoderHasMoreOutput(enc))) {
            if (avail_out == 0) more_room();
            ok = BrotliEncoderCompressStream(enc, BROTLI_OPERATION_EMIT_METADATA, &avail_in, &next_in, &avail_out, &next_out, nullptr) == BROTLI_TRUE;
        }
    }
    std::size_t avail_in = in.size();
    const auto* next_in = reinterpret_cast<const std::uint8_t*>(in.data());
    while (ok && !BrotliEncoderIsFinished(enc)) {
        if (avail_out == 0) more_room();
        ok = BrotliEncoderCompressStream(enc, BROTLI_OPERATION_FINISH, &avail_in, &next_in, &avail_out, &next_out, nullptr) == BROTLI_TRUE;
    }
    BrotliEncoderDestroyInstance(enc);
    if (!ok) {
        out.clear();
        return false;
    }
    out.resize(out.size() - avail_out);
    return true;
}
}  // namespace
#endif

bool compress_buffered(Encoding e, int level, unsigned padding, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;
    switch (e) {
        case Encoding::gzip: return gzip_context().compress(level, padding, in, out);
        case Encoding::zstd: return zstd_context().compress(level, padding, in, out);
        case Encoding::br:
#ifdef AGENSIO_HAS_BROTLI
            return brotli_buffered(level, padding, in, out);
#else
            return false;
#endif
        case Encoding::identity: break;
    }
    return false;
}

}  // namespace agensio
