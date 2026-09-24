// The HttpArena benchmark endpoints (https://github.com/MDA2AV/HttpArena), in-process as
// the arena's rules require of an infrastructure entry: `/baseline11` and `/baseline2`
// sum the integer values of the query arguments and, on a POST, the body; `/json/{count}`
// serializes the first `count` items of a dataset with `total = price * quantity * m`;
// `/pipeline` answers `ok`. Compiled only with AGENSIO_HTTPARENA=ON (bench/httparena/);
// without it the parser refuses `handler = "httparena"` and the stubs below are never
// reached. Nothing here touches the static path.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "config.hpp"
#include "core/stream.hpp"
#include "core/worker_state.hpp"

namespace agensio {

// The dataset as the handler serializes it: everything of an item except its total is
// rendered once at load, so a request appends a prefix and one number per item.
struct HttparenaDataset {
    struct Item {
        std::string prefix;    // `{"id":1,...,"total":` for this item
        std::int64_t pq = 0;   // price * quantity, multiplied per request
    };
    std::vector<Item> items;
    std::size_t max_body = 0;  // an upper bound on the body of /json/{items.size()}
};

// Reads the dataset (a JSON array of items with id, name, category, price, quantity,
// active, tags, rating.score, rating.count). Empty result with `error` set on failure.
std::shared_ptr<const HttparenaDataset> load_httparena_dataset(const std::string& path, std::string& error);

class HttparenaHandler {
public:
    // Fills s.response for `loc` (kind httparena) and runs `done` exactly once, before
    // start() returns for everything but a POST whose body is still arriving.
    void start(Stream& s, const LocationConfig& loc, WorkerState& ws, std::function<void()> done);
};

#ifndef AGENSIO_HTTPARENA
inline std::shared_ptr<const HttparenaDataset> load_httparena_dataset(const std::string&, std::string& error) {
    error = "agensio was built without AGENSIO_HTTPARENA";
    return nullptr;
}
inline void HttparenaHandler::start(Stream& s, const LocationConfig&, WorkerState&, std::function<void()> done) {
    s.response.status = 500;  // unreachable: the parser refuses the handler kind in this build
    done();
}
#endif

}  // namespace agensio
