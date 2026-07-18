# Eval Harness

Offline, deterministic quality checks over captured engagement outputs (JSON
finding arrays). No LLM calls, no network access, no real assessment backend.

## How to run

The eval tests live under `tests/eval/` (repo root) but the backend virtual
environment is required because `assess.lib.*` is imported from
`agent/scripts/`.  Use one of the following forms — both are equivalent:

```bash
# From the repo root
uv run --directory orchestrator/backend pytest "$(git rev-parse --show-toplevel)/tests/eval"

# Or with an explicit relative path from orchestrator/backend
uv run --directory orchestrator/backend pytest ../../tests/eval
```

**Do NOT use `cd orchestrator/backend && pytest tests/eval`** — `pytest
tests/eval` resolves relative to the current working directory, so it looks
for `orchestrator/backend/tests/eval` (which does not exist) and silently
collects zero tests, producing a false-green result.

## What the tests do

Each `definitions/*.yaml` file names a fixture (a JSON array of finding
payloads under `fixtures/`) and lists assertions.  Assertions run in two
modes:

- `strict` — the test **fails** if the assertion is not satisfied.
- `soft` — a `UserWarning` is emitted and the test **continues**.

Assertions supported: `min_findings`, `max_findings`, `expected_cwes`,
`expected_severities`, `severity_distribution`, `attacker_outcome_present`.

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
