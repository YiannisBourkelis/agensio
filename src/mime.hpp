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
};
MimeInfo mime_info(std::string_view path) noexcept;

}  // namespace agensio
