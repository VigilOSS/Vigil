---
name: code-fuzz-campaign
description: AI-driven fuzz campaign orchestration — target selection, harness construction, sanitizer compilation, and crash triage for memory-safety vulnerabilities in C/C++ codebases
origin: Vigil
vuln_class: buffer-overflow, integer-overflow, format-string, null-dereference, use-after-free, uninitialized-memory, type-confusion, algorithmic-dos
---

# Code Fuzz Campaign

Together with `agent/shared-constraints-code.md` §5, this skill owns fuzz hunting depth: target
selection accounts for every required target, campaign execution is generation-bound and audited,
an empty/crashed/failed run is interpreted from evidence rather than vibe, every crash is triaged,
and sibling root causes are checked before findings close. The web hunting rules are not required.

## When to Activate

- Phase 4 of the code analysis pipeline, after Phase 3 (Verify+Variant) confirms static findings.
- When the codebase is C/C++ and contains or can integrate coverage-guided fuzzer infrastructure (libFuzzer, AFL++, OSS-Fuzz).
- When current findings include any native memory-safety family that fuzzing can extend: buffer
  overflow, format string, integer overflow, null dereference, type confusion, uninitialized
  memory, or use-after-free.
- Can start earlier (during Phase 3) when the architect flags existing fuzzer infrastructure in Phase 1.

## Core Principle

AI does not replace the fuzzer. AI selects targets, writes harnesses, repairs builds, and triages crashes. Coverage-guided mutation engines (libFuzzer, AFL++) do the byte-level exploration. The value of AI is in the bookend stages — choosing where to fuzz and interpreting what the fuzzer found.

## Tools and execution boundary

Host-side work is read/author only:
- `grep` / `rg` / `Read` / `Glob` — navigate sealed source
- author harness source, build configuration, corpora, campaign JSON, and the component-safe
  runtime helper beneath `$ENGAGEMENT_DIR/tools/fuzz-state/`

Executable work is Kali-runtime-only and always audited through `vigil assess kali ...`:
- `clang` / `gcc`, `make` / `cmake`, and the project build system
- libFuzzer and AFL++ (`afl-fuzz`, compiler wrappers, CmpLog/laf-intel)
- `afl-tmin`, sanitizer reproducers, `nm` / `objdump`, `llvm-cov` / `gcov`, and every
  repository-built binary

Use container-visible `/engagements/$ENGAGEMENT_KEY/...` argv paths. Apply the component-safe
mapping and containment contract in `shared-constraints-code.md` §3 before every build, launch,
resume, minimization, or repro. Never use a host path, a shell/string-prefix containment test, or a
host execution fallback. If sealed source or a required build input is outside the engagement
mount, return blocked so the operator can establish a runtime-visible sealed generation.

## Methodology

### Stage 1: Target Selection

Consume Phase 1-3 artifacts and rank functions for fuzzing value.

**Inputs (backend — query via `vigil assess`):**
- Findings: `vigil assess fetch findings` — filter for `defect_family` in `buffer-overflow`,
  `format-string`, `integer-overflow`, `null-dereference`, `type-confusion`,
  `uninitialized-memory`, or `use-after-free`.
  Check `verification_status` for Phase 3 confirmation status.
- File classifications: `vigil assess fetch "code/files?repo_id=<id>&limit=5000"` —
  `classification`, `slot_types`, `role`, `language` per file. Target critical/high C/C++ files
  with `NETWORK-INPUT`, `FILE-CONTENT`, `PROTOCOL-FIELD`, or `SERIALIZED-DATA` slot types.

**Inputs (filesystem — read directly):**
- Structural indexes for candidate targets, resolved via
  `agent/shared-constraints-code.md` ("Structural-index resolution"; per-file function
  maps, sinks, entry points)
- Call graph: `tools/analysis-state/call-graph.json` (entry-point chains, untrusted data annotations)
- Source code: Read target files directly via Read/grep/ctags from the Code Source Identity
  `snapshot_path`
- Existing fuzzer inventory: scan repo for `fuzz_*.c`, `*_fuzzer.c`, `LLVMFuzzerTestOneInput`, `oss-fuzz/`

**Input (backend):** fetch `code/threat-model/<repo-id>` and use its trust boundaries/entry points
only when `current: true` and its generation/digest match Code Source Identity. The current identity,
its matching structural-index manifest, and this complete envelope are required dispatch inputs; a
clipped threat summary is supplemental and never replaces them.

**Ranking criteria** (score each 0-3, sum for priority):

| Factor | 3 (highest) | 2 | 1 | 0 |
|--------|------------|---|---|---|
| Product-reachable plausibly untrusted input | Network bytes or a supported public parser for an untrusted format | Shipped CLI argument/env/file or registered host callback | Public API whose consumer control is unresolved | Internal-only, trusted input |
| Size arithmetic | malloc/realloc with computed size from untrusted field | memcpy/memmove with length param | Array index from parsed value | Fixed-size operations only |
| Narrowing casts | size_t -> int on buffer size | uint64 -> uint32 on offset | Signed/unsigned mix in comparison | No narrowing in data path |
| Existing coverage | No fuzzer covers this function | Fuzzer exists but low branch coverage (<30%) | Fuzzer exists, moderate coverage | Fuzzer exists, high coverage (>70%) |
| Phase 2 signal | Confirmed BOF/integer overflow finding nearby | Suspicious finding in same module | Related CWE in call chain | No related findings |
| Complexity | Parser with state machine + binary format | Binary format decoder | Text format parser | Simple validation |

**Target score thresholds:**
- Score >= 12: Priority 1 — campaign immediately
- Score 8-11: Priority 2 — campaign if budget allows
- Score < 8: Skip unless Phase 2 finding directly implicates

**Output:** `tools/fuzz-state/targets.json` — ranked target list with scores and rationale.

```json
[
  {
    "target_id": "reftable-block-parse",
    "entry_function": "block_reader_init",
    "source_files": ["reftable/block.c", "reftable/record.c"],
    "score": 14,
    "score_breakdown": {
      "attacker_input": 3,
      "size_arithmetic": 3,
      "narrowing_casts": 2,
      "existing_coverage": 2,
      "phase2_signal": 2,
      "complexity": 2
    },
    "rationale": "Parses binary reftable blocks from pack files. Phase 2 found OOB read in adjacent record parsing. No existing fuzzer covers block parsing path.",
    "suspected_bug_classes": ["CWE-120", "CWE-190", "CWE-125"],
    "existing_fuzzer": null,
    "priority": 1
  }
]
```

### Stage 2: Pre-Fuzz Audit

Before writing harness code, inspect each target for specific patterns that fuzzing is likely to trigger. This is not a full vulnerability audit (that was Phase 2) — it is a focused scan for patterns that inform harness design and seed construction.

**Patterns to check:**

| Pattern | What to look for | Harness implication |
|---------|-----------------|---------------------|
| Unchecked length arithmetic | `size = header.count * sizeof(entry)` without overflow check | Seed corpus needs count values near SIZE_MAX / sizeof(entry) |
| Offset/count pairs | `data[offset..offset+length]` where both are parsed | Structure-aware input: offset and length fields must be in valid range initially, then mutated |
| Decompression output sizing | `output_size = decoded_length(input)` followed by malloc | Seeds should include compressed formats with manipulated size headers |
| size_t -> int narrowing | `int len = (int)total_size` before bounds check | Seeds with sizes > INT_MAX |
| Raw writes without safe API | Direct `memcpy(dst, src, len)` instead of `strbuf_add` | Confirms the target is genuinely vulnerable to BOF, not guarded by growth API |
| Restart/retry table indexing | `table[parsed_index]` with index from input | Seed corpus needs index values at and beyond table bounds |
| Magic bytes / checksums | `if (memcmp(header, MAGIC, 4) != 0) return` | Use CmpLog/laf-intel or provide valid magic in seeds |
| Nested structure depth | Recursive descent parsing with depth from input | Seeds with varying nesting depths, fuzz with `-max_len` set high enough |

**Output per target:**
```json
{
  "target_id": "reftable-block-parse",
  "audit_findings": [
    {
      "file": "reftable/block.c",
      "line": 142,
      "pattern": "unchecked_length_arithmetic",
      "description": "block_reader_init computes header_off + block_len without overflow check",
      "seed_implication": "Seed with header_off near SIZE_MAX - block_len"
    }
  ],
  "harness_constraints": [
    "Must initialize reftable_buf with valid header magic before mutation",
    "Use structure-aware fuzzing for offset/length fields in block header"
  ],
  "directly_reportable": false
}
```

If the audit finds a bug that is directly reportable without fuzzing (e.g., provably reachable integer overflow), record it immediately via `vigil assess finding record` and continue — the harness will validate and extend the finding.

### Generation-Bound Build Workspace

The sealed `snapshot_path` is evidence, not a writable checkout. Never change its permissions,
generate files beneath it, or build from the mutable origin. Derive every fuzz build from the
current Code Source Identity and keep its outputs generation-scoped:

```
tools/fuzz-state/builds/<repo_key>/<repo_generation>-<source_manifest_digest-prefix>/<target_id>/
```

Prefer an out-of-tree build whenever the project supports one: read product source from the sealed
`snapshot_path`, map it component-by-component to its runtime-visible path, and direct
configuration, objects, generated files, and binaries into the build root (for example, CMake
`-S <runtime-snapshot-path> -B <runtime-build-root>` inside Kali). Keep harness source and build
glue under `tools/fuzz-state/harnesses/<target_id>/`; do not add either to the sealed product tree.

Some build systems necessarily generate beside source. For those only, create a disposable writable
workspace at:

```
tools/fuzz-state/build-workspaces/<repo_key>/<repo_generation>-<source_manifest_digest-prefix>/<target_id>/source/
```

Populate it only from the already validated sealed `snapshot_path` — never from the mutable origin
and never by mixing in files from another checkout. Before compiling, compare every pre-existing
product-source file in the copy with the sealed snapshot manifest (`<snapshot_path>/../manifest.json`):
the relative-path inventory, size, and SHA-256 must match. After the build, repeat that comparison
for the same pre-existing files. If any product-source input changed, discard and recreate the
workspace; do not treat the build as valid. Newly generated outputs remain build artifacts, not
reviewed source evidence. Harness/build-glue files are separately owned artifacts and must not
silently replace product inputs.

If a valid build needs a product source/configuration input that the sealed manifest did not admit,
stop and return to Phase 0 to include and ingest it into a new sealed generation. Do not fill that
gap from the origin inside the derived workspace.

### Audited runtime driver

Author `tools/fuzz-state/runtime_driver.py` on the host, then execute it only through
`vigil assess kali`. It is the single execution seam for `check-toolchain`, `build`, `seed-check`,
`quick-run`, `campaign`, `minimize`, and `reproduce` actions. The driver must:

1. Accept only engagement-root-relative POSIX config/artifact paths. Reject absolute paths,
   empty/`.` components, and every `..` component before joining.
2. Set the runtime root to `/engagements/$ENGAGEMENT_KEY`, resolve it and every input with symlinks
   followed, and prove containment with `Path.relative_to()` or `Path.is_relative_to()`. Prove the
   resolved executable is beneath the resolved generation build root the same way. A text prefix,
   `startswith`, shell glob, or common-prefix string is not a path proof.
3. Validate the config's full source identity against the dispatch before executing. Build actions
   also validate the runtime-visible sealed manifest inputs; campaign/repro actions validate the
   engine, sanitizer set, corpus/seed/crash paths, and bounded time/execution budget.
4. Invoke compilers, build tools, fuzzers, and target binaries as argument arrays with
   `shell=False`; never interpolate config content into a shell program. Keep outputs under the
   engagement mount.

If the sealed snapshot cannot be expressed beneath the runtime root, or strict resolution finds a
host-only/missing/escaping input, stop. Do not weaken validation or run the step directly on the
host. A typical audited invocation is:

```bash
vigil assess kali exec \
  --technique FUZZ --intent "generation-bound fuzz target build and validation" \
  --probe-kind baseline --phase code-hunt --timeout 1800 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    build --config tools/fuzz-state/campaigns/<campaign_id>.json
```

Any crash or source-level claim produced from a derived workspace must be reproduced or traced back
to the current sealed bytes and recorded with the current `repo_id`, `repo_generation`, and
`source_manifest_digest`. The disposable copy is execution material, never source identity.

### Stage 3: Harness Construction

Write a real harness using the project's existing fuzzer infrastructure. The harness is the highest-leverage artifact — a good harness finds bugs in minutes, a bad harness produces false crashes for hours.

**Harness type selection:**

| Codebase signal | Harness approach |
|----------------|-----------------|
| Existing `oss-fuzz/` directory with `LLVMFuzzerTestOneInput` targets | Match the existing pattern. Reuse build glue. |
| Existing `fuzz_*.c` or `*_fuzzer.c` files | Use as templates for new targets |
| CMake with `add_executable` for tests | Mirror the target pattern in external harness/build glue or the disposable generation-bound copy |
| Makefile with explicit fuzz targets | Mirror the existing target in external harness/build glue or the disposable generation-bound copy |
| No existing fuzzer infrastructure | Create standalone harness with minimal build glue |

**Harness rules (non-negotiable):**

1. **Use real parser entrypoints.** Call the same function that real code calls. Do not call internal helpers that skip validation, setup, or state initialization.
2. **No fake stubs.** If the function needs a database handle, file descriptor, or initialized struct, either:
   - Provide a real one (preferred)
   - Use the project's existing test fixtures
   - Use a mock ONLY if the project provides one
   - Never fabricate impossible internal state
3. **Respect caller preconditions.** Read the actual callers of the target function. If every caller validates X before calling, the harness must also validate X (or the crashes are harness bugs, not real bugs).
4. **Build against the real build system.** Link against the actual project objects. Do not copy-paste source files into a standalone compilation unit that misses preprocessor definitions, link-time dependencies, or platform-specific configuration.
5. **Keep it simple.** A 20-line harness that calls one real function is better than a 200-line harness that constructs elaborate fake state. Complexity in the harness creates false positives.

**Harness patterns:**

Basic libFuzzer:
```c
#include "target-header.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    /* Minimum size check if format requires a header */
    if (size < MIN_HEADER_SIZE)
        return 0;

    /* Call the real parser entrypoint */
    struct parse_context ctx = {0};
    parse_init(&ctx);
    parse_input(&ctx, data, size);
    parse_cleanup(&ctx);
    return 0;
}
```

Split-input (when multiple fields are needed):
```c
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4)
        return 0;

    /* First 2 bytes: field_a_len, next 2 bytes: field_b_len */
    uint16_t a_len = *(uint16_t *)data;
    uint16_t b_len = *(uint16_t *)(data + 2);
    size_t needed = 4 + (size_t)a_len + (size_t)b_len;
    if (needed > size)
        return 0;

    process_fields(data + 4, a_len, data + 4 + a_len, b_len);
    return 0;
}
```

Structure-aware (via custom mutator or protobuf):
```c
/* For complex binary formats, define the structure and let
   libFuzzer/AFL++ mutate within structural constraints.
   Use libprotobuf-mutator for heavily structured formats. */
```

**Seed corpus construction:**
- Extract valid inputs from the project's test suite (`test/`, `t/`, `tests/`)
- Generate minimal valid inputs that exercise the parser's happy path
- Include edge-case inputs: empty, minimum valid, maximum field values, all-zeros, all-0xFF
- For binary formats: valid header + corrupted body, valid body + corrupted header

**Write harness and seeds to:**
```
tools/fuzz-state/harnesses/<target_id>/
├── harness.c          # The fuzz harness
├── Makefile           # Build integration (or CMakeLists.txt)
├── seeds/             # Seed corpus
│   ├── valid_minimal  # Smallest valid input
│   ├── valid_complex  # Realistic input from tests
│   ├── edge_empty     # Empty input
│   └── ...
└── README.md          # Target rationale, audit findings, expected bugs
```

**Harness validation checklist** (verify before proceeding to Stage 4):
- [ ] Calls a real parser entrypoint, not an internal helper
- [ ] Does not create impossible internal state
- [ ] Respects documented or observed caller preconditions
- [ ] Links against real project objects (no source copy-paste)
- [ ] Seed corpus includes at least one valid input that completes without error
- [ ] No compile warnings under `-Wall -Wextra`

### Stage 4: Build + Validate

Compile the harness under sanitizers in the generation-bound build root and verify it works before
committing to a campaign. The runtime driver resolves and validates the generation build root from
the campaign config; none of these steps execute directly on the host.

**Build sequence:**

```bash
# Step 1: ASAN + UBSAN build. The driver applies fuzzer-no-link to project
# objects and links the fuzzer engine only on the final target.
vigil assess kali exec --technique FUZZ --intent "ASAN+UBSAN fuzz target build" \
  --probe-kind baseline --phase code-hunt --timeout 1800 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    build --profile address-undefined \
    --config tools/fuzz-state/campaigns/<campaign_id>.json

# Step 2: Verify the seed corpus runs clean.
vigil assess kali exec --technique FUZZ --intent "fuzz seed-corpus validation" \
  --probe-kind baseline --phase code-hunt --timeout 300 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    seed-check --config tools/fuzz-state/campaigns/<campaign_id>.json

# Step 3: Quick validation run (the config binds a 60-second budget).
vigil assess kali exec --technique FUZZ --intent "60-second generation-bound fuzz validation" \
  --probe-kind payload --phase code-hunt --timeout 120 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    quick-run --config tools/fuzz-state/campaigns/<campaign_id>.json

# Step 4 (optional): MSAN build for uninitialized-memory targets.
vigil assess kali exec --technique FUZZ --intent "MSAN fuzz target build" \
  --probe-kind baseline --phase code-hunt --timeout 1800 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    build --profile memory \
    --config tools/fuzz-state/campaigns/<campaign_id>.json
```

**Build failures:**
- If the harness fails to compile: fix the harness or build glue. Never patch product code to make a harness compile.
- If seeds crash immediately: the harness has a bug. Fix it. If the crash is in product code on valid input, that is a pre-existing bug — record it as a finding immediately.
- If the quick validation run finds crashes in < 60 seconds: triage them immediately (Stage 6) before running a longer campaign.

**Record build status:**
```json
{
  "target_id": "reftable-block-parse",
  "build_status": "success",
  "sanitizers": ["address", "undefined"],
  "seed_corpus_size": 12,
  "seed_run_clean": true,
  "quick_run_crashes": 0,
  "quick_run_coverage": "47 functions, 312 edges"
}
```

### Stage 5: Campaign Configuration

Configure and launch the actual fuzzing campaigns. Short campaigns run immediately; deep campaigns are configured for overnight execution.

**Campaign types:**

| Type | Engine | Duration | When to use |
|------|--------|----------|-------------|
| Quick local | libFuzzer | 5-10 min | Initial target exploration, rapid iteration |
| Standard | libFuzzer | 1-4 hours | Targets with moderate complexity |
| Deep | AFL++ with CmpLog | 8-24 hours (overnight) | Complex parsers with magic bytes, checksums, nested structures |
| Directed | AFL++ (PBFuzz-style directed approach) | 4-8 hours | When Stage 2 audit found a specific suspicious path to confirm. Uses targeted seed construction and path-constraint-aware generation to reach a suspected bug site. |

**Campaign configuration:**

```json
{
  "campaign_id": "reftable-block-v1",
  "target_id": "reftable-block-parse",
  "engine": "libfuzzer",
  "campaign_type": "standard",
  "source_identity": {
    "repo_id": 7,
    "repo_key": "reftable",
    "repo_generation": 3,
    "source_manifest_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "source_files": ["reftable/block.c", "reftable/record.c"],
  "entry_function": "block_reader_init",
  "suspected_bug_classes": ["CWE-120", "CWE-190"],
  "sanitizers": ["address", "undefined"],
  "build_root": "tools/fuzz-state/builds/reftable/3-0123456789abcdef/reftable-block-parse/",
  "binary_path": "tools/fuzz-state/builds/reftable/3-0123456789abcdef/reftable-block-parse/fuzz_reftable-block-parse",
  "afl_binary_path": "tools/fuzz-state/builds/reftable/3-0123456789abcdef/reftable-block-parse/fuzz_reftable-block-parse_afl",
  "seed_dir": "tools/fuzz-state/harnesses/reftable-block-parse/seeds/",
  "corpus_dir": "tools/fuzz-state/harnesses/reftable-block-parse/corpus/",
  "crash_dir": "tools/fuzz-state/crashes/reftable-block-parse/",
  "run_budget": {
    "max_total_time": 14400,
    "max_len": 65536
  },
  "engine_flags": {
    "libfuzzer": "-print_final_stats=1 -detect_leaks=0",
    "aflpp": "-p explore -L 0"
  },
  "cmplog": false,
  "notes": "Focus on block header parsing. Phase 2 CH-014 found OOB in adjacent record.c"
}
```

Write campaign configs to `tools/fuzz-state/campaigns/<campaign_id>.json`.
Before launch or resume, compare `source_identity` with the current Code Source Identity and reject
a stale/missing tuple. The runtime driver proves the build root's generation components and every
recorded binary with path-component containment; never fall back to a same-named binary in the
current directory.

**AFL++ flags for common parser patterns:**

| Parser pattern | AFL++ flag | Reason |
|---------------|-----------|--------|
| Magic bytes in header | `-l 2 -c <build-root>/fuzz_<target>_cmplog` (CmpLog level 2) | Helps the mutator learn magic constants. Requires a separate CmpLog-instrumented binary (built with `AFL_LLVM_CMPLOG=1`). |
| Checksums / length gates | `-l 2AT -c <build-root>/fuzz_<target>_cmplog` (CmpLog + auto-transform) | Transforms checksum comparisons to enable bypass. Same CmpLog binary requirement. |
| Deeply nested structures | `AFL_CUSTOM_MUTATOR_ONLY=1` with grammar | Structure-aware mutation prevents invalid nesting |
| Simple binary format | Default (`-p explore`) | Standard exploration is sufficient |

**Starting campaigns:**

```bash
# Short/standard campaign: specialists run synchronously through the audit wrapper.
vigil assess kali exec --technique FUZZ --intent "bounded generation fuzz campaign" \
  --probe-kind payload --phase code-hunt --timeout 1800 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<campaign_id>.json
```

Deep/overnight configs return to the operator for the audited `kali job start` lifecycle; a
specialist does not detach `screen`/`tmux` or background a fuzzer beyond its dispatch. The Phase 4
operator procedure owns that long-running launch.

### Stage 6: Crash Triage

Every crash must pass through the triage pipeline before becoming a finding. Harness bugs and impossible-state crashes are the primary source of false positives in AI-driven fuzzing.

**Triage pipeline:**

```
Raw crash → Minimize → Reproduce → Trace → Validate → Classify
```

**Step 1: Minimize**
```bash
vigil assess kali exec --technique FUZZ --intent "minimize generation-bound fuzz crash" \
  --probe-kind replay --phase code-verify --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    minimize --config tools/fuzz-state/campaigns/<campaign_id>.json \
    --crash tools/fuzz-state/crashes/<target_id>/<crash-file>
```

**Step 2: Reproduce deterministically**
```bash
vigil assess kali exec --technique FUZZ --intent "three-run sanitizer crash reproduction" \
  --probe-kind replay --phase code-verify --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    reproduce --count 3 --config tools/fuzz-state/campaigns/<campaign_id>.json \
    --crash tools/fuzz-state/crashes/<target_id>/<minimized-crash-file>
# The driver fails unless all three runs produce the same crash location and type.
```

**Step 3: Trace attacker bytes to crash**
- Read the ASAN report: note the exact allocation, write, or read that faulted
- Trace backward: which input bytes controlled the bad size/offset/pointer?
- Document the chain: `input_field[offset:offset+4] -> parsed as uint32 block_len -> malloc(block_len) -> memcpy(buf, data, block_len) -> ASAN: heap-buffer-overflow`

**Step 4: Validate caller feasibility**
- Apply `agent/shared-constraints-code.md` §5: is the harness using a real runtime entry, supported
  public parser/API sequence, shipped CLI input, or registered plugin callback?
- Check the call graph plus package/export/registration evidence: which target-kind product entries
  reach this function, and what preconditions do they enforce?
- Record separately whether an attacker can deliver this input in the available consumer/host
  context. Missing consumer source caps impact; it does not turn a deterministic supported-API
  memory-safety crash into a harness bug.
- If the harness bypasses validation that all applicable target-kind product callers perform, the
  crash is a harness bug

**Step 5: Classify**

| Classification | Criteria | Action |
|---------------|----------|--------|
| **TRUE FINDING** | Real code, target-kind product entry, deterministic concrete security failure, and either plausibly attacker-controlled bytes or a valid supported API sequence reaches the bad operation without violating preconditions | Record as finding (CF-xxx); cap attacker impact/severity when consumer context is missing |
| **HARNESS BUG** | Crash depends on impossible internal state, fake buffers, or bypassed preconditions | Fix harness, re-run |
| **HARDENING-ONLY** | Real code, but writes are mediated by safe growth APIs; crash requires circumventing the safe API | Record as informational only if the safe API has a known bypass |
| **DUPLICATE** | Same root cause as an existing Phase 2 finding | Link to existing finding, note fuzzing confirmation |
| **UNREPRODUCIBLE** | Does not reproduce after minimization | Discard |

**False positive gates (must ALL pass for TRUE FINDING):**
- [ ] Uses real code and a target-kind product entry, not impossible internal state
- [ ] Minimized input reproduces deterministically under ASAN/UBSAN (3/3 runs)
- [ ] Harness respects documented or observed caller preconditions
- [ ] Can trace attacker-controlled bytes or an exact valid supported API sequence to the bad allocation, offset, copy, or dereference
- [ ] If crash depends on calling an internal function with impossible sizes or fake backing buffers → HARNESS BUG
- [ ] If writes are mediated by safe growth APIs (strbuf, vector, etc.) → check if the safe API is actually used on this path; if yes → HARDENING-ONLY

**Triage output:**
```json
{
  "crash_id": "reftable-block-parse-001",
  "campaign_id": "reftable-block-v1",
  "classification": "true_finding",
  "crash_file": "tools/fuzz-state/crashes/reftable-block-parse/crash-abc123.min",
  "asan_summary": "heap-buffer-overflow READ of size 4 at block.c:187",
  "trace": "input[8:12] parsed as uint32 block_count -> block_count * 24 overflows to small value -> malloc(small) -> memcpy(buf, records, block_count * 24) -> OOB read",
  "attacker_control": "block_count field in reftable block header (bytes 8-11)",
  "caller_feasibility": "block_reader_init called from reftable_reader_seek_ref with pack-file data (attacker-controlled via git clone/fetch)",
  "cwe": "CWE-190",
  "false_positive_gates": {
    "real_entrypoint": true,
    "deterministic": true,
    "caller_preconditions": true,
    "attacker_trace": true,
    "not_impossible_state": true,
    "not_safe_api_mediated": true
  }
}
```

## Campaign State Layout

All campaign state lives under `tools/fuzz-state/`:

```
tools/fuzz-state/
├── targets.json                    # Stage 1: ranked target list
├── builds/
│   └── <repo_key>/<generation>-<digest-prefix>/<target_id>/
│       └── ...                         # Out-of-tree objects, generated files, binaries
├── build-workspaces/
│   └── <repo_key>/<generation>-<digest-prefix>/<target_id>/source/
│       └── ...                         # Disposable only when builds must write beside source
├── campaigns/
│   ├── <campaign_id>.json          # Stage 5: per-campaign configuration
│   └── ...
├── harnesses/
│   ├── <target_id>/
│   │   ├── harness.c               # Stage 3: fuzz harness source
│   │   ├── Makefile                 # Build integration
│   │   ├── seeds/                   # Seed corpus
│   │   ├── corpus/                  # Evolved corpus (libFuzzer)
│   │   ├── afl-out/                 # AFL++ output directory
│   │   └── README.md               # Target rationale + audit findings
│   └── ...
├── crashes/
│   ├── <target_id>/
│   │   ├── crash-<hash>            # Raw crash input
│   │   ├── crash-<hash>.min        # Minimized input
│   │   └── ...
│   └── ...
└── reports/
    ├── <target_id>-triage.json     # Stage 6: crash triage results
    └── campaign-summary.json       # Aggregate campaign stats
```

## Output Format

### Per-Stage Outputs

- `#### Target Selection` — ranked target list with scores, rationale, and gap analysis against existing fuzzers
- `#### Pre-Fuzz Audit` — per-target pattern matches with harness and seed implications
- `#### Harness Construction` — harness code, seed corpus, validation checklist results
- `#### Build Validation` — build status, seed run results, quick-run crash count and coverage
- `#### Campaign Configuration` — campaign configs with engine selection, flags, and budget
- `#### Crash Triage` — per-crash classification with full triage evidence

### Finding Recording

True findings from Stage 6 are recorded via:
```bash
vigil assess contract finding record
vigil assess finding record code-fuzz-engineer <finding-json> --agent-id <your-agent_id>
```

Finding prefix: `CF` (code-fuzz). Location format: `file:<path>:<line>`.

Findings must include:
- `provenance.code_snapshot` copied from the current Code Source Identity (`repo_id`,
  `repo_generation`, and `source_manifest_digest`); recheck source claims against the sealed bytes
- Minimized crash input path
- ASAN/UBSAN report summary
- Complete attacker-byte-to-crash trace
- Caller feasibility analysis
- All six false-positive gates with pass/fail

## Kill Signals

Stop or skip fuzzing when:

- **Language mismatch**: Codebase is entirely memory-safe (Python, Go, Java, Rust without unsafe) — coverage-guided fuzzing for memory-safety bugs has no value. Logic bug fuzzing (property-based testing) is a different methodology not covered by this skill.
- **No suitable targets**: All Stage 1 targets score < 8 — the codebase lacks target-kind
  product-reachable C/C++ parsing code with plausibly untrusted input and size arithmetic.
- **Build system intractable**: Cannot compile a harness against the project's build system after two repair attempts — harness effort exceeds likely value.
- **Existing coverage sufficient**: All high-value targets already have OSS-Fuzz harnesses with >70% branch coverage and active corpus — marginal value from additional harnesses is low.
- **No memory-safety findings AND low structural risk**: If Phase 2 found zero memory-safety findings
  AND Stage 1 target selection scores all candidates below 8 (no target-kind product-reachable
  C/C++ parsers with plausibly untrusted input and size arithmetic or low fuzz coverage), fuzzing ROI
  is very low. The absence of static findings alone does not justify skipping — high-risk parsers
  with no fuzz coverage are exactly where fuzzing discovers bugs that static analysis missed.

## Escalate When

Keep fuzzing and expand the campaign when:

- **Coverage plateaus below the structural ceiling**: libFuzzer `cov:` / AFL++ `edges_found` stops growing but is well under the function's reachable basic-block count — the corpus is not exercising deeper paths, add structure-aware mutators, dictionary entries, or a grammar harness before declaring the target fuzzed.
- **ASan/UBSan/MSan flags a near-miss without a crash**: heap-buffer-underflow warning, unsigned integer overflow in a size path, uninitialized-read in a pointer-adjacent allocation — the bug is reachable, tighten the harness constraints (remove input length caps, expose additional entry points) and re-run to turn near-miss into crash.
- **A new sanitizer surface appears after enabling a build flag**: enabling `-fsanitize=integer`, `-fsanitize=bounds`, or MSan on a dependency exposes previously invisible bugs — do not stop at ASan-only results, stack sanitizers across at least two configurations before closing the campaign.
- **A crash bucket has multiple distinct stack traces sharing one root cause**: several reports point at the same size-arithmetic function from different callers — each caller is a potential finding variant, run variant-hunting per caller rather than collapsing to one report.
- **The harness rejects inputs the real caller accepts**: your LLVMFuzzerTestOneInput filters by magic bytes, CRC, or length that the production parser tolerates — rewrite the harness to match production's accept surface, filtered harnesses hide real bugs.

## Extended Resources

- `references/code-vuln-patterns/buffer-overflow.md` — cross-function size propagation patterns
- `references/code-vuln-patterns/integer-overflow.md` — combinatorial arithmetic, narrowing cast patterns
- `references/code-vuln-patterns/use-after-free.md` — lifetime reasoning patterns
- `references/code-vuln-patterns/uninitialized-memory.md` — conditional init patterns
- `references/code-vuln-patterns/fuzz-harness-patterns.md` — harness templates, sanitizer reference, antipatterns
