---
description: Code-fuzz appendix — tools/fuzz-state artifact shapes (targets, pre-fuzz audit, build status, campaign config, triage), audited runtime-driver invocations per action, and the campaign state layout
skill: code-fuzz-campaign
---

# Code Fuzz Campaign Artifacts

Load this from `agent/skills/code-fuzz-campaign/SKILL.md` before writing a `tools/fuzz-state/`
artifact or invoking the runtime driver. The skill's stages, containment contract, and triage
gates stay authoritative. Every example uses one hypothetical target.

Every driver call keeps `--timeout` at 600 or less (`vigil assess kali exec --help` says why);
work that cannot fit returns to the operator as a `kali job` (skill Stage 5), named in
`next_steps`. `--phase` is the code audit tag of your `authorized_phase`
(`agent/shared-constraints-code.md` §3); the examples assume a `fuzz` dispatch.

## Stage 1: `tools/fuzz-state/targets.json`

```json
[
  {
    "target_id": "reftable-block-parse",
    "entry_function": "block_reader_init",
    "source_files": ["reftable/block.c", "reftable/record.c"],
    "score": 14,
    "score_breakdown": {
      "attacker_input": 3, "size_arithmetic": 3, "narrowing_casts": 2,
      "existing_coverage": 2, "phase2_signal": 2, "complexity": 2
    },
    "rationale": "Parses binary reftable blocks from pack files; Phase 2 found an OOB read in adjacent record parsing; no fuzzer covers the block path.",
    "suspected_bug_classes": ["CWE-120", "CWE-190", "CWE-125"],
    "existing_fuzzer": null,
    "priority": 1
  }
]
```

## Stage 2: pre-fuzz audit, per target

```json
{
  "target_id": "reftable-block-parse",
  "audit_findings": [
    {
      "file": "reftable/block.c", "line": 142,
      "pattern": "unchecked_length_arithmetic",
      "description": "block_reader_init computes header_off + block_len without an overflow check",
      "seed_implication": "Seed with header_off near SIZE_MAX - block_len"
    }
  ],
  "harness_constraints": [
    "Initialize reftable_buf with valid header magic before mutation",
    "Use structure-aware fuzzing for offset/length fields in the block header"
  ],
  "directly_reportable": false
}
```

## Stage 4: driver invocations and build status

The driver resolves and validates the generation build root from the campaign config.

```bash
# ASan+UBSan build (fuzzer-no-link on project objects; engine linked only on the final target)
vigil assess kali exec --technique FUZZ --intent "ASAN+UBSAN fuzz target build" \
  --probe-kind baseline --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    build --profile address-undefined --config tools/fuzz-state/campaigns/<campaign_id>.json

# Seed corpus runs clean
vigil assess kali exec --technique FUZZ --intent "fuzz seed-corpus validation" \
  --probe-kind baseline --phase code-fuzz --timeout 300 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    seed-check --config tools/fuzz-state/campaigns/<campaign_id>.json

# Quick validation run (the config binds a 60-second budget)
vigil assess kali exec --technique FUZZ --intent "60-second generation-bound fuzz validation" \
  --probe-kind payload --phase code-fuzz --timeout 120 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    quick-run --config tools/fuzz-state/campaigns/<campaign_id>.json

# MSan build for uninitialized-memory targets
vigil assess kali exec --technique FUZZ --intent "MSAN fuzz target build" \
  --probe-kind baseline --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    build --profile memory --config tools/fuzz-state/campaigns/<campaign_id>.json
```

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

## Stage 5: `tools/fuzz-state/campaigns/<campaign_id>.json`

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
  "run_budget": {"max_total_time": 14400, "max_len": 65536},
  "engine_flags": {
    "libfuzzer": "-print_final_stats=1 -detect_leaks=0",
    "aflpp": "-p explore -L 0"
  },
  "cmplog": false,
  "notes": "Focus on block header parsing; a Phase 2 finding shows an OOB read in record.c"
}
```

AFL++ flags by parser shape: magic bytes in the header → `-l 2 -c <build-root>/fuzz_<target>_cmplog`;
checksums or length gates → `-l 2AT -c ...` (both need the separate CmpLog binary built with
`AFL_LLVM_CMPLOG=1`); deeply nested structures → a grammar custom mutator with
`AFL_CUSTOM_MUTATOR_ONLY=1`; a simple binary format → the default `-p explore`.

```bash
# Short or standard campaign, synchronous through the audit wrapper
vigil assess kali exec --technique FUZZ --intent "bounded generation fuzz campaign" \
  --probe-kind payload --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    campaign --config tools/fuzz-state/campaigns/<campaign_id>.json
```

## Stage 6: minimize, reproduce, and triage output

```bash
vigil assess kali exec --technique FUZZ --intent "minimize generation-bound fuzz crash" \
  --probe-kind replay --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    minimize --config tools/fuzz-state/campaigns/<campaign_id>.json \
    --crash tools/fuzz-state/crashes/<target_id>/<crash-file>

# Fails unless all three runs produce the same crash location and type
vigil assess kali exec --technique FUZZ --intent "three-run sanitizer crash reproduction" \
  --probe-kind replay --phase code-fuzz --timeout 600 -- \
  python3 /engagements/$ENGAGEMENT_KEY/tools/fuzz-state/runtime_driver.py \
    reproduce --count 3 --config tools/fuzz-state/campaigns/<campaign_id>.json \
    --crash tools/fuzz-state/crashes/<target_id>/<minimized-crash-file>
```

```json
{
  "crash_id": "reftable-block-parse-001",
  "campaign_id": "reftable-block-v1",
  "classification": "true_finding",
  "crash_file": "tools/fuzz-state/crashes/reftable-block-parse/crash-abc123.min",
  "asan_summary": "heap-buffer-overflow READ of size 4 at block.c:187",
  "trace": "input[8:12] parsed as uint32 block_count -> block_count * 24 wraps small -> malloc(small) -> memcpy(buf, records, block_count * 24) -> OOB read",
  "attacker_control": "block_count field in the reftable block header (bytes 8-11)",
  "caller_feasibility": "block_reader_init reached from reftable_reader_seek_ref with pack-file data delivered by clone/fetch",
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

## Campaign state layout

```
tools/fuzz-state/
├── targets.json                          # Stage 1
├── runtime_driver.py                     # the single audited execution seam
├── builds/<repo_key>/<generation>-<digest-prefix>/<target_id>/            # out-of-tree outputs
├── build-workspaces/<repo_key>/<generation>-<digest-prefix>/<target_id>/source/  # only when a build writes beside source
├── campaigns/<campaign_id>.json          # Stage 5
├── harnesses/<target_id>/
│   ├── harness.c, Makefile or CMakeLists.txt
│   ├── seeds/  corpus/  afl-out/
│   └── README.md                         # target rationale and audit findings
├── crashes/<target_id>/crash-<hash>[.min]
└── reports/
    ├── <target_id>-triage.json           # Stage 6
    └── campaign-summary.json
```
