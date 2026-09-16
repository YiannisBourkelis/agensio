# Security regression inputs

Every file here is replayed by `agensio_tests` on every build through the request parser
(`parser/`) or the path normaliser (`path/`) with the same invariants the fuzzers assert.
Hand-written attack strings and the fuzzers' most interesting corpus entries live here.

Rule: any input that crashes, hangs, or violates an invariant in a fuzzer or in production
is saved here first, then fixed. The test then fails until the fix lands and stays as a
permanent regression check.
