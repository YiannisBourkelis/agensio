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

}  // namespace agensio
