// What the FastCGI and proxy handlers share: the canned error page for a failed
// exchange, collecting the request body before talking to the upstream (memory, then a
// temp file), and turning an UpstreamResult into the client's Response (head fields
// passed through, body in memory, in a spilled file, or streamed).
#pragma once

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "config.hpp"
#include "core/stream.hpp"
#include "upstream/client.hpp"

namespace agensio {

// Fills s.response with a canned error page (502, 503 with Retry-After, 504, 404).
void upstream_error(Stream& s, int status, std::string_view retry_after = {});

// Reads the whole request body of `s` into `body` (memory up to `memory_max`, then an
// unlinked temp file), then runs `then(true)`. A spill failure answers 502 spill_error
// itself and runs `then(false)`; a client that vanished runs nothing. `holder` keeps the
// handler's exchange alive across the reads. Runs `then` inline when the body was
// already buffered.
void collect_request_body(Stream& s, UpstreamBodyInput& body, std::size_t memory_max, std::vector<char>& chunk,
                          std::shared_ptr<void> holder, std::function<void(bool)> then);

// The client's response from a successful exchange: status, every head field except the
// framing and connection ones the writer owns (and, for a proxy location, the fields it
// hides; a Location naming the origin is rewritten to this site), the location's
// add_headers on 2xx/3xx, and the body as the result carries it. `source` is the
// streaming body when the result is streamed. `log_name` is the access log's upstream field.
void apply_upstream_result(Stream& s, UpstreamResult& res, std::unique_ptr<StreamBody> source, const char* log_name,
                           const LocationConfig& loc);

}  // namespace agensio
