// File extension to Content-Type mapping (compiled-in table, nginx mime.types equivalent).
#pragma once

#include <string_view>

namespace agensio {

// Returns the Content-Type for the given path, based on its extension.
// Unknown extensions yield "application/octet-stream".
std::string_view mime_for_path(std::string_view path) noexcept;

// The type and, for a file stored with a content coding, that coding (RFC 9110 8.4): "gzip" for
// .svgz, gzip-compressed SVG (SVG 1.1 1.2), which a viewer must not render without it (G.8);
// empty for every other ending.
struct MimeInfo {
    std::string_view type;
    std::string_view encoding;
    bool compressible = false;  // worth compressing on the wire (compressible_type)
};
MimeInfo mime_info(std::string_view path) noexcept;

// Whether a media type is worth compressing (docs/design-compression.md 4): text of every kind but
// event streams, JavaScript in every spelling, JSON and +json, XML and +xml, XHTML, SVG, ICO, wasm,
// TTF/OTF/EOT fonts, web manifests. Never images (but SVG and ICO), audio, video, archives, WOFF
// (already compressed) or application/octet-stream. Judged on the media type alone: parameters
// (";charset=utf-8") are cut off first, nginx's `gzip_types application/json` trap. The site's
// `types_add` extends this through Config::compressible_types.
bool compressible_type(std::string_view content_type) noexcept;

}  // namespace agensio
