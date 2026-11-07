// The tests' and fuzzers' decoder for answers compressed in pieces: the bytes sent so far decoded as
// a client's decoder takes them, so a test can hold every flush to "all the input so far is out".
// Test code only: the server never decodes (docs/design-compression.md 6).
#pragma once

#include <string>
#include <string_view>

#include "handlers/encoding.hpp"

#ifdef AGENSIO_HAS_ZLIB
#include <zlib.h>
#endif
#ifdef AGENSIO_HAS_ZSTD
#include <zstd.h>
#endif
#ifdef AGENSIO_TEST_BROTLIDEC
#include <brotli/decode.h>
#endif

namespace agensio::test {

struct Decoded {
    bool available = true;  // a decoder for the coding is built in here
    bool ok = true;         // the bytes are a valid prefix of the coding
    bool ended = false;     // the coding's end was reached
    std::string out;        // what the decoder gives for them
};

inline Decoded decode_stream(Encoding e, std::string_view bytes) {
    Decoded d;
    char buf[65536];
    switch (e) {
        case Encoding::gzip: {
#ifdef AGENSIO_HAS_ZLIB
            z_stream z{};
            if (inflateInit2(&z, 15 + 16) != Z_OK) return {true, false, false, {}};
            z.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(bytes.data()));  // NOLINT: zlib's API
            z.avail_in = static_cast<uInt>(bytes.size());
            for (;;) {
                z.next_out = reinterpret_cast<Bytef*>(buf);
                z.avail_out = sizeof buf;
                const int rc = inflate(&z, Z_SYNC_FLUSH);
                d.out.append(buf, sizeof buf - z.avail_out);
                if (rc == Z_STREAM_END) {
                    d.ended = true;
                    d.ok = z.avail_in == 0;  // nothing after the end
                    break;
                }
                if (rc == Z_BUF_ERROR || (rc == Z_OK && z.avail_in == 0 && z.avail_out != 0)) break;  // all given is out
                if (rc != Z_OK) {
                    d.ok = false;
                    break;
                }
            }
            inflateEnd(&z);
            return d;
#else
            d.available = false;
            return d;
#endif
        }
        case Encoding::zstd: {
#ifdef AGENSIO_HAS_ZSTD
            ZSTD_DCtx* dc = ZSTD_createDCtx();
            ZSTD_inBuffer ib{bytes.data(), bytes.size(), 0};
            std::size_t rc = 1;
            for (;;) {
                ZSTD_outBuffer ob{buf, sizeof buf, 0};
                rc = ZSTD_decompressStream(dc, &ob, &ib);
                if (ZSTD_isError(rc)) {
                    d.ok = false;
                    break;
                }
                d.out.append(buf, ob.pos);
                // All given and nothing held back; 0 is a frame decoded and flushed whole, after which a
                // further call would wait for the next frame's header.
                if (ib.pos == ib.size && (ob.pos < ob.size || rc == 0)) break;
            }
            // A frame decoded to its end with nothing pending, and that frame the data's (its magic is in
            // the bytes): the skippable frame of the padding alone is not the answer's end.
            d.ended = d.ok && rc == 0 && bytes.find(std::string_view("\x28\xb5\x2f\xfd", 4)) != std::string_view::npos;
            ZSTD_freeDCtx(dc);
            return d;
#else
            d.available = false;
            return d;
#endif
        }
        case Encoding::br: {
#ifdef AGENSIO_TEST_BROTLIDEC
            BrotliDecoderState* st = BrotliDecoderCreateInstance(nullptr, nullptr, nullptr);
            std::size_t avail_in = bytes.size();
            const auto* next_in = reinterpret_cast<const std::uint8_t*>(bytes.data());
            for (;;) {
                std::size_t avail_out = sizeof buf;
                auto* next_out = reinterpret_cast<std::uint8_t*>(buf);
                const BrotliDecoderResult r = BrotliDecoderDecompressStream(st, &avail_in, &next_in, &avail_out, &next_out, nullptr);
                d.out.append(buf, sizeof buf - avail_out);
                if (r == BROTLI_DECODER_RESULT_SUCCESS) {
                    d.ended = true;
                    d.ok = avail_in == 0;
                    break;
                }
                // Out of input, but what it decoded may still wait in its window for room here.
                if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && !BrotliDecoderHasMoreOutput(st)) break;
                if (r == BROTLI_DECODER_RESULT_ERROR) {
                    d.ok = false;
                    break;
                }
            }
            BrotliDecoderDestroyInstance(st);
            return d;
#else
            d.available = false;
            return d;
#endif
        }
        case Encoding::identity: break;
    }
    d.out.assign(bytes);
    d.ended = true;
    return d;
}

}  // namespace agensio::test
