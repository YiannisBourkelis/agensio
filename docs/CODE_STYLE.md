# agensio code style and patterns

Short, enforced, and measured. The full references are linked, not copied: the C++ Core
Guidelines license allows copying for personal or internal use only, so this public repo
cites rule IDs and links instead. Agent skills in `.claude/skills/` carry the same rules
in checklist form for the coding agent.

## References (in order of authority for this project)

1. **C++ Core Guidelines**, editors Bjarne Stroustrup and Herb Sutter:
   https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines (rule IDs below refer to it).
2. **SEI CERT C++ Coding Standard** (secure coding):
   https://wiki.sei.cmu.edu/confluence/x/Wnw-BQ
3. **Herb Sutter**, Sutter's Mill (safety profiles, hardening, C++26 trip reports):
   https://herbsutter.com
4. **Sean Parent, "C++ Seasoning"**: no raw loops, no raw synchronization primitives, no
   raw pointers (owning). The best short statement of the RAII rule this project follows.
5. **Google C++ Style Guide** (CC-BY 3.0), used only for formatting defaults:
   https://google.github.io/styleguide/cppguide.html
6. Performance: Agner Fog's optimization manuals (free), Ulrich Drepper "What Every
   Programmer Should Know About Memory" (free), Chandler Carruth's CppCon talks
   ("Efficiency with Algorithms, Performance with Data Structures"), Brendan Gregg
   "Systems Performance". Books: "C++ High Performance" (Andrist, Sehr), "Optimized C++"
   (Guntheroth), "Effective Modern C++" (Meyers).

## Rules

### Ownership and lifetime (Core Guidelines R.*, Sean Parent)
- **RAII for everything** that must be released: memory, file descriptors, sockets,
  OpenSSL objects, timers (R.1). No `new`/`delete` in application code (R.11); use
  `std::make_unique` / `std::make_shared` (R.22, R.23) and `std::unique_ptr` with a
  deleter for C handles (`SSL*`, `BIO*`, fds): see `TlsStream`, `File`.
- **A raw pointer or reference is never owning** (R.3). A `T*` member means "points at
  something that outlives me" and the comment says what guarantees it. `std::shared_ptr`
  only where ownership is genuinely shared (cache entries referenced by in-flight
  responses); never as a lazy "I don't know who owns this" (R.21).
- Prefer references and `std::string_view`/`std::span` parameters; pointers only when
  null is a valid value (F.16, F.60). Return values, not out-parameters (F.20).
- Move-only types for handles; deleted copy (C.21, C.67). Rule of zero where possible.
- Handlers capturing `self` (`shared_from_this`) are the one sanctioned way to keep a
  connection alive through an async operation; never `delete this`.

### Interfaces and functions (I.*, F.*)
- Small, single-purpose functions (F.2, F.3). `noexcept` where nothing can throw (F.6).
- **Exceptions stay enabled in the compiler** (decided 2026-09-16) but are permitted only
  in configuration loading and server construction, where `main` catches and reports.
  The request path is exception-free and its functions are `noexcept`; errors there are
  `std::error_code`s, return values, or (from phase A) an `expected`-style result type.
  Rationale: with the table-based ABI non-throwing code pays nothing at runtime; the
  flag would only cost friction with Asio and toml++. A `-fno-exceptions` build is a
  planned phase A measurement; if it wins more than ~2 % CPU per request, we switch
  (E.2, E.3; `bugprone-exception-escape` and `performance-noexcept-*` enforce this).
- `const` by default; `constexpr` for compile-time constants (Con.1-5).
- No global mutable state (I.2); per-worker state lives in `WorkerState`, shared state
  is read-mostly and documented.

### Types and expressions (ES.*, Pro.*)
- `static_cast`, never C-style casts (ES.48, ES.49). `reinterpret_cast` needs a comment.
- Prefer `std::size_t`/fixed-width integers; check narrowing explicitly (ES.46). Sizes
  from the network are untrusted: bounds-check before use (CERT INT30-C, ARR30-C).
- `std::array`, `std::vector`, `std::string_view` over raw arrays (SL.con.1); no pointer
  arithmetic outside parsers, and there only with an explicit remaining-length check.
- Initialise everything (ES.20). Enum classes (Enum.3).

### Concurrency (CP.*)
- One io_context per worker; a connection never leaves its worker. No mutex on any per-
  request path. Shared structures use the documented patterns (cache store mutex on
  miss/insert only, atomics with explicit memory orders and a comment on each).
- `std::jthread`; never detached threads (CP.25, CP.26).

### Performance (Per.*, and what we measured)
- Measure before and after; the numbers go in the commit message (Per.1-6). Server CPU
  microseconds per request is the metric; req/s alone can measure the load generator.
- No allocation per request on the hot path: reuse buffers with capacity retained,
  `string_view` into the request buffer, prebuilt header blocks.
- Zero copy where the kernel offers it (sendfile, writev); coalesce only where the
  transport needs it (TLS records).
- Speculative completions inline (`immediate(...)`), not posted. Do not add clock reads,
  `ERR_clear_error`, or refcount traffic to the request path.
- Data layout over cleverness: flat structs, contiguous vectors, cache-line awareness for
  anything shared between workers (`alignas(64)` and a comment).
- Templates over virtual dispatch on the hot path (`Connection<Stream>`); virtual
  dispatch is fine at configuration time.

### Security (CERT, and this project's threat model)
- Every byte from the network is hostile: length-prefixed reads, size limits, timeouts,
  and a fuzz target for every parser (HTTP/1, chunked, FastCGI, config JSON).
- Paths: decode, normalise, then check containment under the root after
  canonicalisation; deny-rules compare case-insensitively on Windows.
- No format strings from data, no `system()`/shell, no secrets in logs.
- Control interface: see `docs/ROADMAP.md` phase C0.

### Style (mechanical, enforced by `.clang-format`)
- 4 spaces, 120 columns, braces on the same line, `PointerAlignment: Left` (`char* p`).
- `snake_case` functions and variables, `PascalCase` types, trailing underscore for private
  members, `kConstant` for constants, `SCREAMING_CASE` only for macros (avoid macros).
- One class or concern per `.hpp`/`.cpp` pair; templates that must be header-only end in
  `.hpp` with an explanatory comment.
- Comments say *why*, in English, and are kept current; measured facts carry the number.

## Tooling
- `brew install llvm` (macOS) provides clang-format and clang-tidy in
  `/opt/homebrew/opt/llvm/bin`; the scripts find them there.
- `scripts/lint.sh`: clang-tidy with the checks in `.clang-tidy` (bugprone, cert,
  cppcoreguidelines, performance, concurrency, modernize, readability) over `src/`.
  Baseline 2026-09-16 after tuning: mostly `misc-const-correctness`,
  `cppcoreguidelines-pro-type-member-init`, `avoid-c-arrays`; fix when touching a file.
- `scripts/format.sh`: clang-format check (`--fix` rewrites). The whole tree was formatted
  once on 2026-09-16; keep it that way.
- Hardened builds are the default (`AGENSIO_HARDEN=ON`): stack protector, zero-initialised
  locals, fortify, hardened libc++ / `_GLIBCXX_ASSERTIONS` (bounds-checked `[]`), RELRO/PIE.
  Measured on the request path: no cost (CLAUDE.md "Security hardening"). This follows
  Herb Sutter's 2026 trip report on production hardening (Google: >1000 bugs, 0.3 % cost).
- Sanitizer builds: `cmake -B build-asan -DAGENSIO_SANITIZE=address,undefined`.
- Fuzzing: `cmake -B build-fuzz -DAGENSIO_FUZZ=ON ...` with brew clang; every parser gets a
  target in `tests/fuzz/`; run for at least a minute after touching a parser, an hour before
  a release; crashing inputs become unit tests.

## Known deviations (fix when touched)
- `CacheKey::site` is a `const void*` used as an identity; a site index would be cleaner.
- `Route::by_name` stores `const SiteConfig*` into `Config::sites`; documented as
  non-owning, valid for the life of the `Server`.
