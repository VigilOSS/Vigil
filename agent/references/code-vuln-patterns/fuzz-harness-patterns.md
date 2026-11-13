---
description: libFuzzer/AFL++ harness templates, sanitizer flag reference, seed corpus construction, engine quick references
skill: code-fuzz-campaign, code-vulnerability-analysis, code-variant-analysis
languages: C/C++
---

# Fuzz Harness Patterns

Harness, sanitizer, and engine reference for `code-fuzz-engineer` (Phase 4). The commands below are
the argument shapes the audited runtime driver runs inside Kali (`agent/skills/code-fuzz-campaign/SKILL.md`
"Audited runtime driver"); none of them runs on the host. Harness rules and the six triage gates are
owned by that skill.

## Sanitizers

- **ASan:** `-fsanitize=address -g -O1 -fno-omit-frame-pointer`, runtime
  `ASAN_OPTIONS=detect_leaks=0:allocator_may_return_null=1:symbolize=1:abort_on_error=1`. `-O1` is
  for speed with usable stacks; leak detection is noisy for fuzzing; `allocator_may_return_null=1`
  keeps huge allocations from aborting. ASan and MSan cannot share a binary.
- **UBSan:** `-fsanitize=undefined -fno-sanitize-recover=all` so the first violation aborts; combine
  as `-fsanitize=address,undefined`. Its signed-overflow checks matter for CWE-190 targets; add
  `-fsanitize=integer` or `-fsanitize=bounds` for a second configuration.
- **MSan:** `-fsanitize=memory -fsanitize-memory-track-origins=2`. Every library the program uses
  must be MSan-instrumented or it reports false positives; much slower, so run it as a second pass.

Combined libFuzzer build: compile project objects with
`-fsanitize=fuzzer-no-link,address,undefined` and link only the fuzz target with
`-fsanitize=fuzzer,address,undefined`, so libFuzzer's `main()` does not land in every object (this
matters when the same objects also build normal executables or tests). AFL++ build:
`CC=afl-clang-lto` (or `afl-clang-fast`/`afl-cc`) with `AFL_USE_ASAN=1 AFL_USE_UBSAN=1`, no
`-fsanitize=fuzzer`; the CmpLog binary is a separate build with `AFL_LLVM_CMPLOG=1`.

## Harness Shapes

- **Byte buffer:** `LLVMFuzzerTestOneInput(data, size)` calls `init`, the real `feed`/`parse`, and
  `cleanup`. Prefer it; refactor a descriptor-only target to accept bytes when possible.
- **Minimum size gate:** return early below the real parser's mandatory header size, never smaller
  or larger than what the real parser rejects.
- **Several fields:** use C++ `FuzzedDataProvider` (`ConsumeIntegralInRange`,
  `ConsumeBytes`, `ConsumeRemainingBytes`) instead of casting `data` to wider integers, which is
  unaligned undefined behavior that UBSan reports against the harness.
- **File-descriptor targets:** `fmemopen()` for `FILE*` APIs, or a `mkstemp` file written and
  rewound; slower, so only when the API requires it.
- **Stateful multi-call:** feed the input in chunks whose sizes come from input bytes
  (`chunk = data[off] + 1`, clamped to what remains) so the fuzzer explores split points; a parser
  error ends the loop normally.
- **AFL++ persistent mode:**
  ```c
  __AFL_FUZZ_INIT();
  int main(void) {
      __AFL_INIT();
      unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
      while (__AFL_LOOP(10000)) {
          int len = __AFL_FUZZ_TESTCASE_LEN;
          struct parser_ctx ctx; parser_init(&ctx); parser_feed(&ctx, buf, len); parser_cleanup(&ctx);
      }
      return 0;
  }
  ```

## Seeds

Sources in order: project fixtures (`test/`, `t/`, `tests/`, `testdata/`, `fixtures/`; group find
alternatives, e.g. `find "$root" -path '*/test*' -type f \( -name '*.bin' -o -name '*.dat' \)`),
a generated smallest valid input (the most valuable seed), small public samples for public formats,
and mechanical edge cases: empty, single bytes 0x00/0xFF/0x41, header only, header plus one byte,
maximum header field values, all-zero payload after a valid header. Check that seeds run clean and
measure their coverage with `-runs=0 -print_coverage=1` before mutating.

## AFL++ Quick Reference

`afl-fuzz -i seeds/ -o out/ -- ./target @@`; add `-c ./target_cmplog` for CmpLog, `-x dict.txt`
for a dictionary, `-M main` / `-S sec1` for parallel instances; `afl-whatsup out/` for status;
`afl-tmin -i crash -o crash.min -- ./target @@` to minimize. CmpLog: `-l 1`/`2`/`3` set intensity
(higher is slower); suffix `A` adds arithmetic solving and `T` transformational solving (`-l 2AT`
for checksums and length fields), `X` extreme transforms, `R` random colorization.

## libFuzzer Quick Reference

`./fuzz_target corpus/ seeds/ -max_total_time=3600 -artifact_prefix=crashes/`;
`-minimize_crash=1 -exact_artifact_path=crash.min crash`; `-merge=1 merged/ corpus1/ corpus2/` to
dedupe; `-runs=0 -print_coverage=1` for coverage; useful flags `-max_len=65536`, `-detect_leaks=0`,
`-print_final_stats=1`, `-use_value_profile=1` (helps with magic comparisons), `-dict=dict.txt`.
