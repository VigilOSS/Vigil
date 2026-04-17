---
name: code-fuzz-campaign
description: AI-driven fuzz campaign orchestration — target selection, harness construction, sanitizer compilation, and crash triage for memory-safety vulnerabilities in C/C++ codebases
origin: AI Threat Hunting
---

# Code Fuzz Campaign

## When to Activate

- Phase 4 of the code analysis pipeline, after Phase 3 (Verify+Variant) confirms static findings.
- When the codebase is C/C++ and contains or can integrate coverage-guided fuzzer infrastructure (libFuzzer, AFL++, OSS-Fuzz).
- When Phase 2 findings include memory-safety issues (buffer overflow, integer overflow, use-after-free) that fuzzing can extend.
- Can start earlier (during Phase 3) when the architect flags existing fuzzer infrastructure in Phase 1.

## Core Principle

AI does not replace the fuzzer. AI selects targets, writes harnesses, repairs builds, and triages crashes. Coverage-guided mutation engines (libFuzzer, AFL++) do the byte-level exploration. The value of AI is in the bookend stages — choosing where to fuzz and interpreting what the fuzzer found.

## Tools

Host-side (source code work, not target-facing):
- `clang` / `gcc` — compilation with sanitizer flags
- `make` / `cmake` / project build system — harness integration
- `libFuzzer` (via `-fsanitize=fuzzer`) — quick local campaigns
- `AFL++` (`afl-fuzz`, plus `afl-clang-lto`, `afl-clang-fast`, or `afl-cc`) — deep campaigns with CmpLog/laf-intel
- `afl-tmin` / libFuzzer `-minimize_crash=1` — crash minimization
- `grep` / `rg` / `Read` / `Glob` — source code navigation
- `nm` / `objdump` — symbol verification for harness linking
- `llvm-cov` / `gcov` — coverage measurement

No Kali MCP needed — this is entirely host-side source code and build work.

## Methodology

### Stage 1: Target Selection

Consume Phase 1-3 artifacts and rank functions for fuzzing value.

**Inputs (backend — query via `assess.py`):**
- Findings: `./scripts/assess.py fetch findings` — filter for `defect_family` in
  `buffer-overflow`, `integer-overflow`, `use-after-free`, `uninitialized-memory`.
  Check `verification_state` for Phase 3 confirmation status.
- File classifications: `./scripts/assess.py fetch "code/files?repo_id=<id>&limit=5000"` —
  `classification`, `slot_types`, `role`, `language` per file. Target critical/high C/C++ files
  with `NETWORK-INPUT`, `FILE-CONTENT`, `PROTOCOL-FIELD`, or `SERIALIZED-DATA` slot types.

**Inputs (filesystem — read directly):**
- Structural index: `tools/analysis-state/structural-index-manifest.json` (manifest) and
  `tools/analysis-state/structural-index/<hash>.json` (per-file function maps, sinks, entry points)
- Threat model: `tools/analysis-state/threat-model.json` (trust boundaries, entry points)
- Call graph: `tools/analysis-state/call-graph.json` (entry-point chains, untrusted data annotations)
- Source code: Read target files directly via Read/grep/ctags from `source/<repo-name>/`
- Existing fuzzer inventory: scan repo for `fuzz_*.c`, `*_fuzzer.c`, `LLVMFuzzerTestOneInput`, `oss-fuzz/`

**Ranking criteria** (score each 0-3, sum for priority):

| Factor | 3 (highest) | 2 | 1 | 0 |
|--------|------------|---|---|---|
| Attacker-controlled input | Network bytes, file format parser | CLI argument, env var | Internal API with untrusted caller | Internal-only, trusted input |
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

If the audit finds a bug that is directly reportable without fuzzing (e.g., provably reachable integer overflow), record it immediately via `assess.py record-finding` and continue — the harness will validate and extend the finding.

### Stage 3: Harness Construction

Write a real harness using the project's existing fuzzer infrastructure. The harness is the highest-leverage artifact — a good harness finds bugs in minutes, a bad harness produces false crashes for hours.

**Harness type selection:**

| Codebase signal | Harness approach |
|----------------|-----------------|
| Existing `oss-fuzz/` directory with `LLVMFuzzerTestOneInput` targets | Match the existing pattern. Reuse build glue. |
| Existing `fuzz_*.c` or `*_fuzzer.c` files | Use as templates for new targets |
| CMake with `add_executable` for tests | Add fuzzer target alongside existing tests |
| Makefile with explicit fuzz targets | Add new fuzz target following existing pattern |
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

Compile the harness under sanitizers and verify it works before committing to a campaign.

**Build sequence:**

```bash
# Step 1: ASAN + UBSAN build (primary)
# Use fuzzer-no-link for project objects so -fsanitize=fuzzer's main() doesn't
# conflict with normal executables. Link the fuzzer engine only on the final binary.
CC=clang \
CFLAGS="-fsanitize=fuzzer-no-link,address,undefined -g -O1 -fno-omit-frame-pointer" \
    make -C tools/fuzz-state/harnesses/<target_id>/ project_objects
CC=clang \
CFLAGS="-fsanitize=fuzzer,address,undefined -g -O1 -fno-omit-frame-pointer" \
    make -C tools/fuzz-state/harnesses/<target_id>/ fuzz_binary
# If the project's build system produces a single fuzz target directly,
# -fsanitize=fuzzer,address,undefined in CFLAGS+LDFLAGS is fine for that target alone.

# Step 2: Verify seed corpus runs clean
./fuzz_<target_id> tools/fuzz-state/harnesses/<target_id>/seeds/ -runs=0
# Exit code 0 = seeds don't crash. Non-zero = harness bug or pre-existing crash.

# Step 3: Quick validation run (60 seconds)
./fuzz_<target_id> \
    -artifact_prefix=tools/fuzz-state/crashes/<target_id>/ \
    tools/fuzz-state/harnesses/<target_id>/corpus/ \
    tools/fuzz-state/harnesses/<target_id>/seeds/ \
    -max_total_time=60 -print_final_stats=1

# Step 4 (optional): MSAN build for uninitialized memory
CC=clang \
CFLAGS="-fsanitize=fuzzer-no-link,memory -g -O1 -fno-omit-frame-pointer -fsanitize-memory-track-origins=2" \
    make -C tools/fuzz-state/harnesses/<target_id>/ clean project_objects
CC=clang \
CFLAGS="-fsanitize=fuzzer,memory -g -O1 -fno-omit-frame-pointer -fsanitize-memory-track-origins=2" \
    make -C tools/fuzz-state/harnesses/<target_id>/ fuzz_binary
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
  "source_files": ["reftable/block.c", "reftable/record.c"],
  "entry_function": "block_reader_init",
  "suspected_bug_classes": ["CWE-120", "CWE-190"],
  "sanitizers": ["address", "undefined"],
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

**AFL++ flags for common parser patterns:**

| Parser pattern | AFL++ flag | Reason |
|---------------|-----------|--------|
| Magic bytes in header | `-l 2 -c ./fuzz_<target>_cmplog` (CmpLog level 2) | Helps the mutator learn magic constants. Requires a separate CmpLog-instrumented binary (built with `AFL_LLVM_CMPLOG=1`). |
| Checksums / length gates | `-l 2AT -c ./fuzz_<target>_cmplog` (CmpLog + auto-transform) | Transforms checksum comparisons to enable bypass. Same CmpLog binary requirement. |
| Deeply nested structures | `AFL_CUSTOM_MUTATOR_ONLY=1` with grammar | Structure-aware mutation prevents invalid nesting |
| Simple binary format | Default (`-p explore`) | Standard exploration is sufficient |

**Starting campaigns:**

```bash
# libFuzzer (foreground, quick)
./fuzz_<target_id> \
    -artifact_prefix=tools/fuzz-state/crashes/<target_id>/ \
    tools/fuzz-state/harnesses/<target_id>/corpus/ \
    tools/fuzz-state/harnesses/<target_id>/seeds/ \
    -max_total_time=600 -print_final_stats=1

# AFL++ (background, long)
screen -dmS fuzz-<target_id> \
    afl-fuzz -i tools/fuzz-state/harnesses/<target_id>/seeds/ \
             -o tools/fuzz-state/harnesses/<target_id>/afl-out/ \
             -t 1000 \
             -- ./fuzz_<target_id>_afl @@
```

### Stage 6: Crash Triage

Every crash must pass through the triage pipeline before becoming a finding. Harness bugs and impossible-state crashes are the primary source of false positives in AI-driven fuzzing.

**Triage pipeline:**

```
Raw crash → Minimize → Reproduce → Trace → Validate → Classify
```

**Step 1: Minimize**
```bash
# libFuzzer
./fuzz_<target_id> -minimize_crash=1 -exact_artifact_path=crash.min crash.raw

# AFL++
afl-tmin -i crash.raw -o crash.min -- ./fuzz_<target_id>_afl @@
```

**Step 2: Reproduce deterministically**
```bash
# Run minimized input 3x under ASAN
for i in 1 2 3; do
    ./fuzz_<target_id> crash.min 2>&1 | grep -E "ERROR|SUMMARY"
done
# All 3 must produce identical crash location and type
```

**Step 3: Trace attacker bytes to crash**
- Read the ASAN report: note the exact allocation, write, or read that faulted
- Trace backward: which input bytes controlled the bad size/offset/pointer?
- Document the chain: `input_field[offset:offset+4] -> parsed as uint32 block_len -> malloc(block_len) -> memcpy(buf, data, block_len) -> ASAN: heap-buffer-overflow`

**Step 4: Validate caller feasibility**
- Is the harness entry function called with this kind of input in real code?
- Check the call graph: which real entry points reach this function?
- Can an attacker actually deliver this input through a real code path?
- If the harness bypasses validation that all real callers perform, the crash is a harness bug

**Step 5: Classify**

| Classification | Criteria | Action |
|---------------|----------|--------|
| **TRUE FINDING** | Real code, real entrypoint, deterministic, attacker-controlled bytes reach the bad operation, callers don't prevent it | Record as finding (CF-xxx) |
| **HARNESS BUG** | Crash depends on impossible internal state, fake buffers, or bypassed preconditions | Fix harness, re-run |
| **HARDENING-ONLY** | Real code, but writes are mediated by safe growth APIs; crash requires circumventing the safe API | Record as informational only if the safe API has a known bypass |
| **DUPLICATE** | Same root cause as an existing Phase 2 finding | Link to existing finding, note fuzzing confirmation |
| **UNREPRODUCIBLE** | Does not reproduce after minimization | Discard |

**False positive gates (must ALL pass for TRUE FINDING):**
- [ ] Uses real code and real parser entrypoints, not impossible internal state
- [ ] Minimized input reproduces deterministically under ASAN/UBSAN (3/3 runs)
- [ ] Harness respects documented or observed caller preconditions
- [ ] Can trace attacker-controlled bytes to the exact bad allocation, offset, copy, or dereference
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
./scripts/assess.py record-finding code-fuzz-engineer <finding-json>
```

Finding prefix: `CF` (code-fuzz). Location format: `file:<path>:<line>`.

Findings must include:
- Minimized crash input path
- ASAN/UBSAN report summary
- Complete attacker-byte-to-crash trace
- Caller feasibility analysis
- All six false-positive gates with pass/fail

## Kill Signals

Stop or skip fuzzing when:

- **Language mismatch**: Codebase is entirely memory-safe (Python, Go, Java, Rust without unsafe) — coverage-guided fuzzing for memory-safety bugs has no value. Logic bug fuzzing (property-based testing) is a different methodology not covered by this skill.
- **No suitable targets**: All Stage 1 targets score < 8 — the codebase lacks attacker-reachable C/C++ parsing code with size arithmetic.
- **Build system intractable**: Cannot compile a harness against the project's build system after two repair attempts — harness effort exceeds likely value.
- **Existing coverage sufficient**: All high-value targets already have OSS-Fuzz harnesses with >70% branch coverage and active corpus — marginal value from additional harnesses is low.
- **No memory-safety findings AND low structural risk**: If Phase 2 found zero memory-safety findings AND Stage 1 target selection scores all candidates below 8 (no attacker-reachable C/C++ parsers with size arithmetic or low fuzz coverage), fuzzing ROI is very low. Note: the absence of static findings alone does NOT justify skipping — high-risk parsers with no fuzz coverage are exactly where fuzzing discovers bugs that static analysis missed.

## Extended Resources

- `references/code-vuln-patterns/buffer-overflow.md` — cross-function size propagation patterns
- `references/code-vuln-patterns/integer-overflow.md` — combinatorial arithmetic, narrowing cast patterns
- `references/code-vuln-patterns/use-after-free.md` — lifetime reasoning patterns
- `references/code-vuln-patterns/uninitialized-memory.md` — conditional init patterns
- `references/code-vuln-patterns/fuzz-harness-patterns.md` — harness templates, sanitizer reference, antipatterns
