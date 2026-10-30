#include "compress.hpp"

#include <algorithm>
#include <cstring>

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

GzipContext::GzipContext() = default;

GzipContext::~GzipContext() {
#ifdef AGENSIO_HAS_ZLIB
    if (z_) {
        deflateEnd(static_cast<z_stream*>(z_));
        delete static_cast<z_stream*>(z_);
    }
#endif
}

bool GzipContext::compress(int level, std::string_view in, std::string& out) {
    out.clear();
    if (in.size() > kCompressWholeMax) return false;  // one deflate call: zlib's counts are 32-bit
#ifdef AGENSIO_HAS_ZLIB
    level = std::clamp(level, 1, 9);
    auto* z = static_cast<z_stream*>(z_);
    if (!z) {
        z = new z_stream{};
        // gzip framing (RFC 1952): windowBits 15 + 16; memLevel 8, zlib's own.
        if (deflateInit2(z, level, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            delete z;
            return false;
        }
        z_ = z;
        level_ = level;
    } else {
        if (deflateReset(z) != Z_OK) return false;  // the stream fresh for this answer
        if (level != level_) {
            if (deflateParams(z, level, Z_DEFAULT_STRATEGY) != Z_OK) return false;
            level_ = level;
        }
    }
    out.resize(static_cast<std::size_t>(deflateBound(z, static_cast<uLong>(in.size()))));
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
    (void)in;
    return false;
#endif
}

GzipContext& gzip_context() {
    thread_local GzipContext ctx;
    return ctx;
}

}  // namespace agensio
