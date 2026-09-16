---
name: cpp-guidelines
description: Apply agensio's C++ rules (Core Guidelines subset, RAII and ownership, no exceptions on the hot path, security of parsers) when writing, changing or reviewing any C++ in this repository.
---

# agensio C++ guidelines

Source of truth: `docs/CODE_STYLE.md`. Rule IDs refer to the C++ Core Guidelines
(Stroustrup, Sutter) at https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines.

## Before writing code
- Read the surrounding file's conventions; this codebase is small and consistent.
- Decide ownership first: who frees it, who keeps it alive during async operations.

## Checklist for every change
1. **Ownership**: no `new`/`delete` (R.11); `make_unique`/`make_shared` (R.22/23); C
   handles in `unique_ptr` with a deleter; raw pointers and references are non-owning
   and commented with what keeps them alive (R.3). `shared_ptr` only for genuinely
   shared lifetime (cache entries, connections in async handlers via `shared_from_this`).
2. **No exceptions on the request path**; `std::error_code` or return values. Exceptions
   only at configuration/startup (E.2/E.3). Mark `noexcept` where true (F.6).
3. **Untrusted input**: every length from the network is checked against the buffer
   before use; size limits and timeouts exist; parsers get a fuzz target.
4. **No per-request allocation on the hot path**: reuse buffers, `string_view` into the
   request buffer, prebuilt header blocks. If you must allocate, say why in a comment.
5. **Casts**: `static_cast` only; `reinterpret_cast` needs a comment; no C casts (ES.48/49).
6. **Concurrency**: nothing per-request touches a mutex; a connection stays on its
   worker; every atomic has an explicit memory order and a comment.
7. **Interfaces**: small functions, `const` by default, references/`string_view`/`span`
   parameters, return values not out-params (F.20), enum classes.
8. **Style**: 4 spaces, 120 cols, `snake_case` functions, `PascalCase` types, `member_`,
   `kConstant`; run `scripts/format.sh` and `scripts/lint.sh` before finishing.
9. **Comments say why**, and carry the measured number when a design choice was measured.

## When reviewing
Quote the rule ID with each finding (e.g. "R.3: owning raw pointer"). Distinguish
correctness, security, performance and style; fix the first two before the rest.
