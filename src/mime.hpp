// File extension to Content-Type mapping (compiled-in table, nginx mime.types equivalent).
#pragma once

#include <string_view>

namespace agensio {

// Returns the Content-Type for the given path, based on its extension.
// Unknown extensions yield "application/octet-stream".
std::string_view mime_for_path(std::string_view path) noexcept;

}  // namespace agensio
