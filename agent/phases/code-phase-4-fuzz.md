# Code Phase 4 — Fuzz

**Read-on-phase-entry.** When you ENTER Code Phase 4 (Fuzz — conditional), Read this doc to
evaluate the entry gate (run vs. skip directly to report) before dispatching anything, and re-read
it on a method re-anchor. It carries the conditional run/skip criteria, the entry-gate commands, 4A
Target Selection + Harness Construction (`code-fuzz-engineer` dispatch fields), 4B Campaign Execution
(the traditional-tool libFuzzer/AFL++ bash), 4C Crash Triage, the Phase 4 exit gate, and the terminal
Report Dispatch step that applies whether Phase 3 skipped straight to report or Phase 4 ran first.
Cross-phase machinery — the Core Loop, the Agent Roster, and the Dispatch Context Template /
Pre-Dispatch Checklist — stays in `agent/operator-core-code.md`; this doc does not restate it.
`code-fuzz-engineer` carries no family mindset lens (see "Phased mindset flow (code)" in
`agent/operator-core-code.md` for why Phase 4 is scoped out of the lens doctrine).

### Phase 4: FUZZ

Phase 4 uses AI-driven fuzz campaign orchestration to find memory-safety vulnerabilities that
static analysis missed. AI selects targets, writes harnesses, compiles under sanitizers, and
triages crashes. Coverage-guided mutation engines (libFuzzer, AFL++) do the actual exploration.

**Phase 4 is conditional.** Run it when ANY of the following are true:
- Phase 2/3 produced confirmed memory-safety findings (buffer overflow, integer overflow, UAF)
- Critical/high C/C++ files have attacker-reachable parsers with size arithmetic but low or
  no existing fuzz coverage (high structural risk even without a confirmed static finding)

Skip it when ALL of the following are true:
- Codebase is entirely memory-safe (Python, Go, Java, Rust without unsafe), OR
- No critical/high C/C++ files with attacker-reachable parsing code exist, OR
- All high-value parsing targets already have OSS-Fuzz coverage with >70% branch coverage

**Phase 4 entry gate:**
```bash
# Verify Phase 3 complete
vigil assess code-coverage --require-gate-pass

# Check for memory-safety findings OR high structural risk in C/C++ code.
# Filter findings for defect_family in: buffer-overflow, integer-overflow,
# use-after-free, uninitialized-memory.
vigil assess fetch findings

# Check for critical/high C/C++ files — fuzzing for memory-safety needs C/C++ targets.
# Even without confirmed memory-safety findings, high-risk C/C++ parsers with low
# existing fuzz coverage warrant a campaign.
vigil assess fetch "code/files?repo_id=<id>&limit=5000"
# If no C/C++ files at critical/high classification, skip Phase 4.

# Verify build toolchain
which clang && clang --version
```

#### Phase 4A: Target Selection + Harness Construction

Dispatch `code-fuzz-engineer` with `agent/skills/code-fuzz-campaign/SKILL.md`.

Provide:

**Backend state (operator fetches and summarizes):**
- Memory-safety findings: `vigil assess fetch findings` — extract findings with
  `defect_family` in `buffer-overflow`, `integer-overflow`, `use-after-free`,
  `uninitialized-memory`. Include slugs, canonical locations, severity, and
  `verification_state` (confirmed/unreviewed). Pass as a concise summary, not raw JSON dump.
- File classifications: `vigil assess fetch "code/files?repo_id=<id>&limit=5000"` —
  identify critical/high C/C++ files with relevant slot types. The fuzz engineer uses these to
  cross-reference targets against structural index data.

**Filesystem artifact paths (the fuzz engineer reads these directly):**
- Structural index manifest: `tools/analysis-state/structural-index-manifest.json`
- Threat model: `tools/analysis-state/threat-model.json`
- Call graph: `tools/analysis-state/call-graph.json`
- Source repo root path for direct code reads

**Operator-provided context:**
- Build system type (Makefile/CMake/etc.) and compiler availability (`which clang`)
- Existing fuzzer inventory paths (from `rg 'LLVMFuzzerTestOneInput'` or `ls oss-fuzz/`)
- CWE pattern references: `buffer-overflow.md`, `integer-overflow.md`, `use-after-free.md`,
  `uninitialized-memory.md`, `fuzz-harness-patterns.md`

The fuzz engineer:
- Selects and ranks targets using structural index, threat model, and Phase 2 findings
- Audits selected targets for specific BOF/integer-overflow patterns
- Writes libFuzzer/AFL++ harnesses using real parser entrypoints
- Compiles under ASAN+UBSAN, validates seeds run clean
- Runs quick local campaigns (60-second validation runs)
- Configures longer campaigns for overnight execution

**On return from target selection + harness construction:**
```bash
# Campaign state written to tools/fuzz-state/
ls tools/fuzz-state/targets.json
ls tools/fuzz-state/harnesses/*/harness.c
ls tools/fuzz-state/campaigns/*.json

# Record any findings from quick validation runs or pre-fuzz audit
vigil assess record-finding code-fuzz-engineer <finding-json>
```

#### Phase 4B: Campaign Execution

Campaign execution is a traditional tool run, not an AI agent task. The operator starts
campaigns based on the configurations from Phase 4A.

```bash
# Short campaigns (libFuzzer, 5-10 min) -- run immediately
for config in tools/fuzz-state/campaigns/*.json; do
    target_id=$(jq -r .target_id "$config")
    timeout=$(jq -r .run_budget.max_total_time "$config")
    ./fuzz_${target_id} \
        -artifact_prefix=tools/fuzz-state/crashes/${target_id}/ \
        tools/fuzz-state/harnesses/${target_id}/corpus/ \
        tools/fuzz-state/harnesses/${target_id}/seeds/ \
        -max_total_time=${timeout} -print_final_stats=1
done

# Deep campaigns (AFL++, overnight) -- start in screen/tmux
screen -dmS fuzz-campaign bash -c '
    for config in tools/fuzz-state/campaigns/*-deep.json; do
        target_id=$(jq -r .target_id "$config")
        # If campaign config has cmplog=true, build a CmpLog binary first:
        #   AFL_LLVM_CMPLOG=1 make fuzz_${target_id}_cmplog
        # Then pass -c ./fuzz_${target_id}_cmplog -l 2 to afl-fuzz.
        afl-fuzz -i tools/fuzz-state/harnesses/${target_id}/seeds/ \
                 -o tools/fuzz-state/harnesses/${target_id}/afl-out/ \
                 -t 1000 -- ./fuzz_${target_id}_afl @@
    done
'
```

#### Phase 4C: Crash Triage

After campaigns complete (or produce crashes during quick runs), dispatch `code-fuzz-engineer`
for crash triage.

Provide:
- Crash artifacts from `tools/fuzz-state/crashes/`
- Campaign configs from `tools/fuzz-state/campaigns/`
- Harness source from `tools/fuzz-state/harnesses/`
- Source code paths for the target functions

The fuzz engineer triages each crash through the false-positive pipeline:
minimize -> reproduce -> trace -> validate -> classify

**On return from crash triage:**
```bash
# Record true findings
vigil assess record-finding code-fuzz-engineer <finding-json>

# Triage reports written to tools/fuzz-state/reports/
ls tools/fuzz-state/reports/*-triage.json
```

**Phase 4 exit gate:**
- [ ] All quick campaigns completed
- [ ] All crashes triaged (no untriaged crash artifacts)
- [ ] True findings recorded with full false-positive gate evidence
- [ ] Harness bugs fixed and campaigns re-run (if applicable)
- [ ] Campaign summary written to `tools/fuzz-state/reports/campaign-summary.json`

```bash
vigil assess transition-phase complete --track code
```

**Report dispatch:**
For a final report, run `vigil assess check-phase-readiness --phase report` before dispatching
`report-writer`. Report-writer runs `vigil assess list-report-findings --mode final --json` for final output and
`vigil assess list-report-findings --mode draft --json` for interim output; both include code and web findings from the
shared backend with root-cause grouping applied. Fuzz findings (CF-xxx) include crash inputs and ASAN reports as evidence.
Use the same draft → review-and-fix QA → publish gate as runtime engagements: draft generation
writes `report.md` and returns the 13-check checklist, a fresh `report-writer` reviews and fixes
the rendered report, and publication plus `reported` lifecycle transitions wait for `QA PASS`.

---

Phase index (path → purpose) lives in `agent/operator-core-code.md` under "Phase Index". Prior:
`agent/phases/code-phase-3-verify-variant.md`. This is the last code-track phase doc; report
generation is described above.
