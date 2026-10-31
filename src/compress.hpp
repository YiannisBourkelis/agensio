// Compression behind response_compression (docs/design-compression.md): one-shot encoders for
// the copies of cached files made once at fill (brotli 11, gzip 9), and `coding_built` for what
// this binary offers. Each library optional at build time (CMakeLists.txt: AGENSIO_HAS_ZLIB,
// AGENSIO_HAS_ZSTD, AGENSIO_HAS_BROTLI); a coding the build lacks is refused where it is named.
// The streaming encoders for answers compressed per request come with a later step. Levels and
// windows are set explicitly here, never left to a library's default, so a library upgrade never
// changes what agensio sends (the Traefik regression of 2026).
#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "handlers/encoding.hpp"

namespace agensio {

// The most one call compresses (the callers pass at most 64 KB, docs/design-compression.md 6).
inline constexpr std::size_t kCompressWholeMax = 256u * 1024 * 1024;

// Whether this binary can produce the coding.
bool coding_built(Encoding e) noexcept;
// The package that gives it, for a refusal ("libzstd-dev").
std::string_view coding_package(Encoding e) noexcept;

// `in` compressed whole with the coding at `level`, appended to `out` (cleared first). False
// when the build lacks the coding or the encoder fails; `out` is then empty. For the copies made
// once: brotli at `level` with the window the library picks for the input (at most 2^22 for a
// file of a few MB; the whole input is in memory, so the window costs nothing per stream), gzip
// at `level`. zstd is not made for files (every zstd browser takes br).
bool compress_whole(Encoding e, int level, std::string_view in, std::vector<char>& out);

// The windows of the encoders behind answers compressed per request, fixed (docs/design-compression.md
// 3): the memory a stream holds against under 1 % of output; a setting here is a way to run out of
// memory. zstd 2^19 (the content coding's decoders take up to 2^23, RFC 8878 7.1), brotli 2^18, gzip
// 2^15 (deflate's most). An answer smaller than the window gets a window of its own size.
inline constexpr int kZstdWindowLog = 19;
inline constexpr int kBrotliWindowBits = 18;

// The padding of every answer compressed per request (docs/design-compression.md 7): up to kPaddingMax
// bytes the coding carries where every decoder skips them (gzip's FEXTRA field, RFC 1952 2.3.1.1; a
// zstd skippable frame, RFC 8878 3.1.2; a brotli metadata meta-block, RFC 7932 9.2), so one answer's
// length differs from request to request and an attacker measuring it pays for every sample (the
// Heal the Breach mitigation; Rails' Thruster pads up to 32 bytes by default, Django up to 100).
// What protects is the spread of the random part, so the bound is the padding's own, 32, and the
// coding's framing (6 bytes for gzip, 8 for zstd, up to 4 for brotli) comes on top. A length of 0
// adds nothing. padding_length() draws one from the calling thread's generator.
inline constexpr unsigned kPaddingMax = 32;
unsigned padding_length() noexcept;

// A gzip encoder kept by a worker for the answers it compresses per request (docs/design-compression.md
// 6): the zlib stream is set up once and reset per answer, so a buffered answer costs its deflate
// and nothing else, no allocation. One per thread; gzip_context() hands out the calling thread's.
class GzipContext {
public:
    GzipContext();
    ~GzipContext();
    GzipContext(const GzipContext&) = delete;
    GzipContext& operator=(const GzipContext&) = delete;
    // `in` compressed whole at `level` (1..9) into `out` (cleared first), `padding` bytes (at most
    // kPaddingMax) in the header's extra field; false on a failure or a build without zlib, `out`
    // then empty.
    bool compress(int level, unsigned padding, std::string_view in, std::string& out);

private:
    void* z_ = nullptr;  // the zlib stream and its header, kept behind the pointer so this header needs no zlib.h
    int level_ = 0;
};
GzipContext& gzip_context();

// The zstd encoder kept the same way: one ZSTD_CCtx per thread, its parameters set once (the level
// when it changes), the session reset by each answer's call. A skippable frame of `padding` bytes
// goes before the data frame.
class ZstdContext {
public:
    ZstdContext();
    ~ZstdContext();
    ZstdContext(const ZstdContext&) = delete;
    ZstdContext& operator=(const ZstdContext&) = delete;
    bool compress(int level, unsigned padding, std::string_view in, std::string& out);

private:
    void* cctx_ = nullptr;
    int level_ = 0;
};
ZstdContext& zstd_context();

// An answer compressed whole with the coding at `level` (docs/design-compression.md 6): gzip and
// zstd through the calling thread's context, brotli through an encoder made for the answer (its
// state is sized by the window, so one per answer costs less than one kept per thread), the window
// capped as above, `padding` bytes carried as the coding skips them. False when the build lacks the
// coding or the encoder fails, `out` then empty.
bool compress_buffered(Encoding e, int level, unsigned padding, std::string_view in, std::string& out);

}  // namespace agensio
