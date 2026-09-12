# Eval Harness

Deterministic quality checks for two different evidence rungs. The simple eval
definitions replay captured JSON finding arrays without an assessment backend.
The Wave 0 code-workflow harness instead drives the real in-process FastAPI,
SQLite, sealed-source, structural-index, dispatch, queue, finding, verification,
variant, fuzz-decision, and readiness surfaces. Neither rung calls an LLM or an
external network.

## How to run

The eval tests live under `tests/eval/` (repo root), but the backend virtual
environment and dev extra provide their runtime and pytest dependencies. Run
them from any directory with a Jujutsu-rooted absolute path:

```bash
uv run --directory orchestrator/backend --extra dev pytest "$(jj root)/tests/eval"
```

**Do NOT use `cd orchestrator/backend && pytest tests/eval`** — `pytest
tests/eval` resolves relative to the current working directory, so it looks
for `orchestrator/backend/tests/eval` (which does not exist). Also avoid `uv run`
without `--extra dev`; a clean backend environment may not contain pytest.

## What the tests do

Each `definitions/*.yaml` file names a fixture (a JSON array of finding
payloads under `fixtures/`) and lists assertions.  Assertions run in two
modes:

- `strict` — the test **fails** if the assertion is not satisfied.
- `soft` — a `UserWarning` is emitted and the test **continues**.

Assertions supported: `min_findings`, `max_findings`, `expected_cwes`,
`expected_severities`, `severity_distribution`, `attacker_outcome_present`, and
`white_box_finding_contract`. The white-box contract requires an exact code-finding
identity set, the expected source snapshot, and per-finding provenance, location,
proof, and verifier metadata.

## Wave 0 production lifecycle reference

`fixtures/code/cwe22-path-traversal-seed-0/` contains vulnerable, clean, and
hostile-instruction near twins. `harnesses/code_workflow/fixture.py` validates
their byte identities and exact oracle, `runner.py` sends reference-solver
decisions through production HTTP contracts, `metrics.py` measures anti-choke
facts, and `schema.py` validates the strict result in
`schemas/code-workflow-result-v1.schema.json`.

The reference solver proves lifecycle solvability only. Its result declares
`measurement_kind=oracle_reference_solvability` and
`model_efficacy_claimed=false`; zero LLM invocations is not a claim about model
recall or precision. The runner also keeps publication and submission disabled.

Run the lifecycle and its calibration regression through the backend suite:

```bash
uv run --directory orchestrator/backend --extra dev pytest \
  tests/test_code_workflow_runner.py
```

`baselines/private-code-evaluation.json` is the committed runner-calibration
envelope. It binds the exact fixture and recipe identities to seven distinct
production-workflow observations, their observation/platform digests, and
recomputed medians. Each bounded observation receipt is recomputable from its
run index, platform fingerprint, retained metrics, and exact fixture, recipe,
and runtime identities. Ordinary runs load that envelope and require matching
fixture, recipe, and declared-runtime identity. Requests, mutations, exact
dispatch topology, and assigned-input counts remain blocking across platforms;
only wall-time and latency become informational when the platform fingerprint
differs. An absent or mismatched calibration is explicitly unavailable and
cannot produce a green overall gate; malformed or tampered evidence fails
validation. The backend acceptance test separately compares a validated current
seven-run median envelope with the committed seven-run medians at the unchanged
20% same-platform threshold. It still exercises an ordinary single-run load,
but does not treat sub-millisecond jitter in that one observation as stable
acceptance evidence.

To refresh the baseline intentionally, call
`harnesses.code_workflow.runner.calibrate_workflow(...)` with the backend test
client and isolated settings used by `test_code_workflow_runner.py`, review the
returned seven-or-more runner-calibration envelope, then replace the committed JSON.
The helper uses distinct engagement/workspace names for each repetition; it does
not pretend that repetitions sharing one test process are isolated runtimes.

## Adding a new definition

1. Drop a JSON array of finding payloads into `tests/eval/fixtures/`.
2. Add a `tests/eval/definitions/<name>.yaml` pointing at the fixture.
3. Run the harness with the command above to confirm green.

## Capturing a fixture from a real engagement

Hand-authoring fixtures is one path; the other is snapshotting the backend
findings of a real, human-blessed engagement with `eval_capture.py`. This is a
maintainer/CI tool, intentionally NOT registered on the operator `vigil assess`
surface — invoke the module directly (its import chain is stdlib-only, so no
extra venv is required). Replay stays zero-token.

Run a seeded engagement against a known-vulnerable app (e.g. DVWA, juice-shop)
via the normal `vigil engagement create` / `start` flow and let the agent record
findings as usual. Then, with the orchestrator backend running:

```bash
python agent/scripts/assess/commands/eval_capture.py \
  --engagement-dir <engagement-dir> \
  --out tests/eval/fixtures/golden_<name>.json \
  --definition tests/eval/definitions/<name>.yaml
```

This reads `GET /findings`, transforms each backend row into a schema-valid
finding-record (parsing the `details_json`/`provenance_json` columns into nested
objects, injecting `links: []`, and dropping DB-only columns such as `id` and
timestamps), **validates every record against `finding-record.schema.json` and
hard-fails on any error** (an unconditional guard against backend-model drift),
stable-sorts the findings for byte-reproducible output, and writes the fixture.
`--definition` additionally scaffolds a green-by-construction definition derived
from the captured data (count bounds, present CWEs, severity mins, strict
attacker-outcome). Commit the fixture + definition — replay is then offline.

Filters mirror `finding list` (`--severity`, `--workflow-status`, `--slug`,
`--search`, ...) to capture a subset. `--strict` turns the empty-`details.impact`
warning into a hard failure.

### Quality signal — `--check`

After re-running an engagement, diff the fresh capture against the committed
baseline without overwriting it:

```bash
python agent/scripts/assess/commands/eval_capture.py --engagement-dir <engagement-dir> \
  --out tests/eval/fixtures/golden_<name>.json --check
```

`--check` exits non-zero on a regression (fewer findings, a dropped CWE, a
shrunken severity bucket, or a newly-empty `details.impact`) and writes nothing.
Strictly-more coverage is not a regression.

