# Security regression inputs

One directory per fuzz target (`tests/fuzz/fuzz_<name>.cpp`), named without the `fuzz_`
prefix. `scripts/fuzz-all.sh` seeds each target with its directory; new inputs go to a scratch
corpus, never here. `agensio_tests` replays `parser/`, `chunked/`, `fcgi/`, `path/` and `json/`
on every build with the invariants the fuzzers assert. Hand-written attack strings, the seeds
that show a target its input format (`refuse/`: patterns, an empty line, paths; `redirect/`: rules
as three lines, from, to and flags, an empty line, then request targets; `response_headers/`: rules
one per line, path, flags, verb, name, value and endings separated by tabs, an empty line, then
probes, path, a status byte, the served file, flags and the answer's own fields; the input's length
modulo 3 makes the site php, static or without app, the first two with the security baseline), and the
fuzzers' most interesting corpus entries live here.

Rule: any input that crashes, hangs, or violates an invariant in a fuzzer or in production
is saved here first, then fixed, with a replay in `test_security_regressions` when its target
has none yet. The test then fails until the fix lands and stays as a permanent regression check.
