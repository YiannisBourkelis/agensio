// Request-target decoding and normalisation.
#pragma once

#include <string>
#include <string_view>

namespace agensio {

// Turns the request-target (e.g. "/a/%20b/../c?x=1") into a safe absolute path
// ("/a/c"): strips the query, percent-decodes, collapses "." and ".." and repeated
// slashes, preserves a trailing slash. Returns false if the target is invalid:
// does not start with '/', bad percent escape, contains control characters or NUL,
// or tries to climb above the root. `out` is reused; capacity is kept between calls.
bool normalize_target(std::string_view target, std::string& out);

// True if any path segment starts with '.', i.e. a dotfile or dot-directory (".env",
// "/.git/config", "/a/.hidden/b"). Input is a normalised path.
bool has_hidden_segment(std::string_view path) noexcept;

// Windows filesystem rules, applied to a normalised path when the server runs on
// Windows (exposed for tests on every platform): backslashes are separators and are
// rejected, ':' is rejected (drive letters, NTFS alternate data streams), segments
// ending in '.' or ' ' are rejected (the filesystem strips them), and reserved device
// names (CON, PRN, AUX, NUL, COM1-9, LPT1-9, with or without extension) are rejected.
// Returns false if the path violates any rule.
bool windows_path_ok(std::string_view path) noexcept;

}  // namespace agensio
