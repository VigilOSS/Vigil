---
name: code-fuzz-campaign
description: AI-driven fuzz campaign orchestration — target selection, harness construction, sanitizer compilation, and crash triage for memory-safety vulnerabilities in C/C++ codebases
origin: Vigil
vuln_class: buffer-overflow, integer-overflow, format-string, null-dereference, use-after-free, uninitialized-memory, type-confusion, algorithmic-dos
---

# Code Fuzz Campaign

Together with `agent/shared-constraints-code.md` §5, this skill owns fuzz hunting depth: target
selection accounts for every required target, campaign execution is generation-bound and audited,
an empty, crashed, or failed run is interpreted from evidence, every crash is triaged, and sibling
root causes are checked before findings close. The web hunting rules are not required.

## When to Activate

Phase 4, after Verify + Variant, for C/C++ code that has or can take coverage-guided fuzzing
(libFuzzer, AFL++, OSS-Fuzz), and whenever current findings include a native memory-safety family
fuzzing can extend (buffer overflow, format string, integer overflow, null dereference, type
confusion, uninitialized memory, use-after-free). It can start during Phase 3 when the architect
flagged existing fuzzer infrastructure.

AI does not replace the fuzzer: you choose targets, write harnesses, repair builds, and triage
crashes, and the mutation engine does the byte-level exploration.

## Tools and execution boundary

Host-side work is reading sealed source and authoring harnesses, build glue, corpora, campaign
JSON, and the runtime driver beneath `$ENGAGEMENT_DIR/tools/fuzz-state/`. Everything that executes
(compilers, build systems, libFuzzer and AFL++, `afl-tmin`, sanitizer reproducers, `nm`/`objdump`,
coverage tools, repository-built binaries) runs in Kali through `vigil assess kali ...`
(`agent/shared-constraints-code.md` §3).

Apply this path-mapping and containment contract before every build, launch, resume, minimization,
or repro:
- Each runtime input is an engagement-root-relative POSIX path mapped to
  `/engagements/$ENGAGEMENT_KEY/<relative-path>`; reject absolute paths, empty or `.` components,
  and any `..` before mapping.
- Inside Kali, resolve the engagement root and every build root, config, binary, corpus, seed,
  crash, and source path with symlinks followed; prove containment with
  `pathlib.Path.relative_to()`/`is_relative_to()` (or a file-descriptor walk), and require the
  executable beneath the validated generation build root. A string prefix, glob, or `startsWith`
  test is not a containment check.
- If `snapshot_path` or a required build input is host-only, outside the engagement mount, or
  escapes the validated boundary, return blocked so the operator can establish a runtime-visible
  sealed generation; never fall back to running it on the host.

## Methodology

### Stage 1: Target Selection

Read `vigil assess fetch findings --paginate` (native memory-safety families, with
`verification_status`) and `vigil assess fetch "code/files?repo_id=<id>" --paginate` (a hand-written
`limit` returns one page, so ranking would see only the files on it), the per-file structural
indexes, `tools/analysis-state/call-graph.json`, `code/threat-model/<repo-id>` when current, and the
existing fuzzer inventory: search for `fuzz_*.c`, `*_fuzzer.c`, `LLVMFuzzerTestOneInput`, and
`oss-fuzz/`. Favor critical/high C/C++ files with `NETWORK-INPUT`, `FILE-CONTENT`,
`PROTOCOL-FIELD`, or `SERIALIZED-DATA` slots.

Score each candidate 0-3 on product-reachable untrusted input (network bytes or a public parser of
an untrusted format 3; shipped CLI/env/file or host callback 2; public API with unresolved consumer
control 1; internal 0), size arithmetic from untrusted fields, narrowing casts, missing fuzz
coverage (none 3 down to over 70% branch coverage 0), nearby Phase 2 signal, and parser complexity.
Campaign 12+ first, 8-11 as budget allows, below 8 only when a Phase 2 finding implicates it. Write
`tools/fuzz-state/targets.json`.

### Stage 2: Pre-Fuzz Audit

A focused scan for what shapes the harness and seeds: unchecked length arithmetic (counts near
`SIZE_MAX / sizeof(entry)`), parsed offset/length pairs, decompression sized from a header,
`size_t`-to-`int` narrowing (sizes above `INT_MAX`), raw `memcpy` where the project has a growth
API, table indexes from input, magic bytes and checksums (CmpLog/laf-intel or valid magic in seeds),
and input-driven recursion depth. Record a bug that is reportable without fuzzing now, with
`vigil assess finding record`; the harness then extends it.

### Generation-Bound Build Workspace

The sealed `snapshot_path` is evidence, not a writable checkout: never change its permissions,
generate files beneath it, or build from the mutable origin. Build out of tree when the project
supports it — read source from the runtime-visible snapshot and generate into
`tools/fuzz-state/builds/<repo_key>/<repo_generation>-<source_manifest_digest-prefix>/<target_id>/`
(for example CMake `-S <runtime-snapshot-path> -B <runtime-build-root>` inside Kali), with harness
and glue under `tools/fuzz-state/harnesses/<target_id>/`.

Only a build system that must write beside source gets a disposable copy under
`tools/fuzz-state/build-workspaces/<same path>/source/`, filled only from the validated snapshot.
Compare every pre-existing product file in it with the sealed manifest
(`<snapshot_path>/../manifest.json`: path, size, SHA-256) before and after compiling; any change
invalidates the build, so discard and recreate. Generated outputs are build artifacts, not reviewed
source. A build that needs an input the manifest did not admit goes back to Phase 0 for a new sealed
generation rather than borrowing from the origin.

### Source-build and allocator preflight

Read the snapshot's own build instructions first: a repository snapshot can need generated configure
or parser files that release tarballs ship (PHP needs `buildconf` with autoconf, bison, and re2c;
the [PHP source installation guide](https://www.php.net/manual/en/install.unix.source.php) separates
repository builds from release archives). Use the toolchain versions the sealed branch requires,
record compiler, generator, sanitizer, and dependency versions with the build receipt, and cache
toolchains in the runtime image or a prepared writable volume, never in the sealed tree. Container
root does not override host mount permissions: a failed `chmod` on sealed source means use the
generation-bound copy, and a mount that cannot host the build means reporting the exact failure and
provisioning an approved writable volume through the audited runtime.

Inspect custom allocators before trusting a clean sanitizer run: one that suballocates large blocks
hides allocation boundaries from ASan. For PHP/ZendMM, compare the normal allocator with a
diagnostic `USE_ZEND_ALLOC=0` run (the
[Zend allocator](https://github.com/php/php-src/blob/master/Zend/zend_alloc.c) then uses the system
allocator) and record the setting in receipt and config. Switching allocators changes layout,
failure handling, and memory-limit enforcement, so a diagnostic crash proves behavior in that
configuration only; trace or reproduce production behavior separately. A clean run under an
unvalidated allocation mode does not establish the absence of memory defects.

### Audited runtime driver

Author `tools/fuzz-state/runtime_driver.py` on the host and execute it only through
`vigil assess kali`; it is the single seam for `check-toolchain`, `build`, `seed-check`,
`quick-run`, `campaign`, `minimize`, and `reproduce`. It implements the containment contract above
for every path and for the executable's place under the resolved generation build root, validates
the config's full source identity against the dispatch (build actions also the runtime-visible
manifest inputs; campaign and repro actions the engine, sanitizer set, corpus/seed/crash paths, and
a bounded budget), and runs every tool as an argument array with `shell=False`, keeping outputs
under the engagement mount. When an input cannot be expressed or resolved beneath the runtime root,
stop rather than weaken validation. Invocations per action:
`agent/references/runtime-guides/code-fuzz-campaign-artifacts.md`.

A crash or source claim from a derived workspace is reproduced or traced back to the current sealed
bytes and recorded against the current `repo_id`, `repo_generation`, and `source_manifest_digest`.

### Stage 3: Harness Construction

The harness is the highest-leverage artifact: a good one finds bugs in minutes, a bad one produces
false crashes for hours. Match existing fuzzers (`oss-fuzz/`, `fuzz_*.c`, `*_fuzzer.c`) and reuse
their build glue, mirror CMake or Makefile test targets in external glue, and write a standalone
harness only when nothing exists.

Harness rules:
1. **Real parser entrypoints** — the function real code calls, not a helper that skips validation,
   setup, or state initialization.
2. **No fake stubs** — a real handle or initialized struct, the project's fixtures, or a mock the
   project provides; never fabricated impossible state.
3. **Respect caller preconditions** — if every caller validates X, so does the harness, or its
   crashes are harness bugs.
4. **Build against the real build system** — link real objects; copied sources lose preprocessor
   definitions, link dependencies, and platform config.
5. **Keep it simple** — 20 lines calling one real function beat 200 lines of fake state.

Seed from the project's tests plus minimal valid inputs and edge cases. Before Stage 4, confirm the
rules hold, at least one seed completes cleanly, and it compiles without `-Wall -Wextra` warnings.
Templates, sanitizer flags, seeds, and engine quick references:
`agent/references/code-vuln-patterns/fuzz-harness-patterns.md`.

### Stage 4: Build + Validate

Through the driver: ASan+UBSan build, seed-corpus check, 60-second quick run, and an MSan build for
uninitialized-memory targets. Fix compile failures in the harness or glue, never in product code.
Seeds that crash immediately are a harness bug, unless the crash is in product code on valid input —
a pre-existing bug to record now. Quick-run crashes go to Stage 6 before any longer campaign.

### Stage 5: Campaign Configuration

Quick (libFuzzer, minutes) for exploration; standard (libFuzzer, 1-4 h) for moderate targets; deep
(AFL++ with CmpLog, overnight) for magic bytes, checksums, and nesting; directed (AFL++ with
targeted seeds, 4-8 h) for a specific Stage 2 path. Escalate to an overnight campaign only when
the Stage 4 quick run shows coverage growth but no crashes. Each config at
`tools/fuzz-state/campaigns/<campaign_id>.json` carries its `source_identity` tuple, build root,
binaries, seed/corpus/crash dirs, budget, and engine flags. Before launch or resume, reject a stale
or missing `source_identity`; the driver proves every binary's containment and never falls back to
a same-named binary in the current directory. Short and standard campaigns run synchronously
through `kali exec`; deep configs return to the operator for the audited `kali job start` lifecycle,
because a specialist does not detach `screen`/`tmux` or background a fuzzer beyond its dispatch.

### Stage 6: Crash Triage

Every crash goes Minimize → Reproduce → Trace → Validate → Classify before it can become a finding;
harness bugs and impossible-state crashes are the main false-positive source. `reproduce --count 3`
fails unless all three runs hit the same location and type. Trace from the sanitizer report to the
input bytes that controlled the bad size, offset, or pointer (`input[8:12] -> uint32 block_len ->
malloc(block_len) -> memcpy(..., block_len) -> heap-buffer-overflow`). Validate per `agent/shared-constraints-code.md` §5 that the
harness drives a real runtime entry, supported public API sequence, shipped CLI input, or registered
callback, and which product entries reach the function under which preconditions. Missing consumer
source caps impact; it does not turn a deterministic supported-API memory-safety crash into a
harness bug, whereas bypassing validation every applicable caller performs does.

| Classification | Criteria | Action |
|---------------|----------|--------|
| **TRUE FINDING** | Real code, target-kind entry, deterministic failure, attacker bytes or a valid API sequence reach the bad operation within preconditions | Record (CF-xxx); cap impact without consumer context |
| **HARNESS BUG** | Impossible state, fake buffers, bypassed preconditions | Fix the harness, re-run |
| **HARDENING-ONLY** | Writes go through a safe growth API the crash circumvented | Informational only if that API has a known bypass |
| **DUPLICATE** | Same root cause as an existing finding | Link it; note the fuzz confirmation |
| **UNREPRODUCIBLE** | Fails to reproduce after minimization | Discard |

Six false-positive gates, all passed by a TRUE FINDING: (1) real code and a target-kind entry; (2)
3/3 deterministic reproduction of the minimized input under ASan/UBSan; (3) caller preconditions
respected; (4) attacker bytes or the exact valid API sequence trace to the bad allocation, offset,
copy, or dereference; (5) no internal call with impossible sizes or fake backing buffers; (6) no safe
growth API (strbuf, vector) mediating the write on this path. Write
`tools/fuzz-state/reports/<target_id>-triage.json`.

## Output Format

Report `#### Target Selection` (with the gap against existing fuzzers), `#### Pre-Fuzz Audit`,
`#### Harness Construction`, `#### Build Validation`, `#### Campaign Configuration`, and
`#### Crash Triage`.

### Finding Recording

Record each Stage 6 true finding with `vigil assess finding record code-fuzz-engineer
<finding-json> --agent-id <your-agent_id>` under the conventions in
`agent/references/runtime-guides/code-finding-recording.md`. The record carries the minimized
input, the sanitizer summary, the byte-to-crash trace, caller feasibility, and the six gates with
pass/fail.

## Kill Signals

Stop or skip when the code is entirely memory-safe (Python, Go, Java, Rust without `unsafe`;
property-based logic fuzzing is another method); every candidate scores below 8; two repair
attempts cannot build a harness against the real build; every high-value target already has an
OSS-Fuzz harness above 70% branch coverage with an active corpus; or there are no memory-safety
findings and low structural risk together. Zero static findings alone is not a reason: unfuzzed
high-risk parsers are where fuzzing finds what static analysis missed.

## Escalate When

Widen the campaign when coverage plateaus below the reachable block count (add structure-aware
mutators, dictionaries, or a grammar harness); a sanitizer flags a near-miss without a crash
(loosen length caps, expose more entries); a new sanitizer surface appears (`-fsanitize=integer`,
`-fsanitize=bounds`, MSan on a dependency — stack at least two configurations); one root cause shows
several distinct stacks (hunt each caller as a variant); or the harness rejects input the real
caller accepts (match production's accept surface).

## Extended Resources

- `agent/references/runtime-guides/code-fuzz-campaign-artifacts.md` — before writing any
  `tools/fuzz-state/` artifact or invoking the runtime driver: targets, audit, build status,
  campaign config, and triage shapes, the driver invocation for each action, and the state layout.
- `agent/references/code-vuln-patterns/fuzz-harness-patterns.md` — at Stage 3: harness templates,
  sanitizer flags, seed construction, engine quick references.
- `agent/references/code-vuln-patterns/buffer-overflow.md`, `integer-overflow.md`,
  `use-after-free.md`, `uninitialized-memory.md` — when triaging a crash of that class or seeding
  for it.
