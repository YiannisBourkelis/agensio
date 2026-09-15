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

}  // namespace agensio
