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
