"""eval-capture — snapshot backend findings into a golden eval fixture (maintainer/CI tool).

eval-capture is intentionally NOT registered on the operator ``vigil assess``
surface: it is a dev/CI fixture-capture tool run by maintainers, not part of an
engagement's operator workflow. Invoke it via the standalone entrypoint::

    python agent/scripts/assess/commands/eval_capture.py --engagement-dir <dir> --out <fixture>

Captures a real engagement's backend findings into a committed golden fixture
that is DROP-IN compatible with the offline eval harness (tests/eval): a flat
JSON array of finding-records validating against
``agent/schemas/finding-record.schema.json``. Replay stays zero-token.

``GET /findings`` returns parsed ``details``/``provenance`` objects alongside
backend metadata the fixture schema does not accept. Every API row is projected
via :func:`_to_fixture_record` and then VALIDATED with
``collect_validation_errors`` before writing. The validate-before-write guard is
UNCONDITIONAL (not behind a flag): a backend-model change surfaces here as a
capture failure because the schema is generated from ``FindingRecordRequest``.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

# When invoked as a standalone maintainer script
# (``python agent/scripts/assess/commands/eval_capture.py ...``) rather than
# imported as ``assess.commands.eval_capture``, the package root (agent/scripts)
# is not on sys.path. Add it so the ``assess.*`` imports below resolve. The whole
# import chain is stdlib-only, so no backend virtualenv is required.
_SCRIPTS_ROOT = str(Path(__file__).resolve().parents[2])
if _SCRIPTS_ROOT not in sys.path:
    sys.path.insert(0, _SCRIPTS_ROOT)

from assess.lib.client import AssessmentClient  # noqa: E402
from assess.lib.config import load_config  # noqa: E402
from assess.lib.schema_validation import collect_validation_errors, load_schema  # noqa: E402

# Allow-listed scalar columns the fixture schema accepts at the finding-record
# top level. Everything else on the DB row (id, engagement_id, *_json,
# merged_into_*, timestamps, evidence_artifact_id, slug) is DROPPED.
_SCHEMA_SCALARS = (
    "title",
    "severity",
    "defect_family",
    "canonical_location",
    "summary",
    "evidence_ref",
    "notes",
    "workflow_status",
    "verification_status",
    "root_cause_key",
    "auth_context",
    "source_name",
)

# Headroom added to max_findings in a scaffolded definition so a re-run that
# legitimately surfaces a couple more findings does not flip the gate red.
_MAX_FINDINGS_HEADROOM = 3

_SCHEMA_NAME = "finding-record.schema.json"


# Standalone invocation examples (see the module docstring for why).
_MAINTAINER_EXAMPLES = (
    "Examples (maintainer/CI tool — invoke the module directly, not `vigil assess`):\n"
    "  python agent/scripts/assess/commands/eval_capture.py --engagement-dir <dir> "
    "--out tests/eval/fixtures/golden_<name>.json\n"
    "  python agent/scripts/assess/commands/eval_capture.py --engagement-dir <dir> "
    "--out tests/eval/fixtures/golden_<name>.json "
    "--definition tests/eval/definitions/<name>.yaml\n"
    "  python agent/scripts/assess/commands/eval_capture.py --engagement-dir <dir> "
    "--out tests/eval/fixtures/golden_<name>.json --check"
)


def _add_capture_arguments(p) -> None:
    """Attach the eval-capture flags. Shared by the standalone :func:`main`
    entrypoint and the retained (currently unregistered) ``register`` hook."""
    p.add_argument("--out", required=True, help="Path to write (or, with --check, diff against) the fixture JSON")
    p.add_argument(
        "--definition",
        help="Also scaffold a green-by-construction definition YAML at this path (derived from captured data)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help=(
            "Validate a fresh capture and diff it against the committed --out fixture "
            "(count/CWE-set/severity/impact-presence). Exit non-zero on regression. Writes nothing."
        ),
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Hard-fail (instead of warn) if any captured finding has an empty details.impact (G5)",
    )
    # Reuse the list_findings CLI-side filters (list_findings.py:24-41).
    p.add_argument("--severity")
    p.add_argument("--workflow-status", "--status", dest="workflow_status")
    p.add_argument("--verification-status")
    p.add_argument("--source-name")
    p.add_argument("--slug")
    p.add_argument(
        "--search", help="Case-insensitive search over slug, title, summary, location, and source name"
    )


def register(subparsers) -> None:
    """Retained subparser hook, not wired into the operator ``vigil assess`` CLI
    (see the module docstring). Real invocation is the standalone :func:`main`
    entrypoint below."""
    p = subparsers.add_parser(
        "eval-capture",
        help="Snapshot backend findings into a golden eval fixture (zero-token replay)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_MAINTAINER_EXAMPLES,
    )
    _add_capture_arguments(p)
    p.set_defaults(func=run)


# ---------------------------------------------------------------------------
# Transform (blueprint G1) — the mandatory row → fixture-record conversion.
# ---------------------------------------------------------------------------


def _to_fixture_record(row: dict) -> dict:
    """Transform a serialized backend finding row into a fixture record.

    Allow-lists the schema scalars, preserves ``details``/``provenance``
    for unconditional schema validation, injects ``links: []`` (G2: links live in a separate
    table and are not on the row; goldens use ``[]``), includes
    ``evidence_type`` only when non-null, and DROPS everything else (id,
    engagement_id, *_json, merged_into_*, timestamps, evidence_artifact_id,
    slug, request_variant_id/service_id/surface_id).
    """
    out = {k: row[k] for k in _SCHEMA_SCALARS if k in row}
    out["details"] = row.get("details", {})
    out["provenance"] = row.get("provenance", {})
    if isinstance(out["provenance"], dict):
        # Server-issued receipts are not authorable or portable fixture input.
        out["provenance"] = {
            key: value
            for key, value in out["provenance"].items()
            if key != "code_snapshot_attestation"
        }
    out["links"] = []
    if row.get("evidence_type"):
        out["evidence_type"] = row["evidence_type"]
    return out


def _sort_key(record: dict) -> tuple[str, str]:
    """Stable, reproducible ordering.

    The backend ``list_findings`` query orders by ``updated_at DESC`` (a
    time-varying column), so capture re-sorts deterministically. ``slug`` is
    dropped from the fixture but is the natural key; fall back to ``title`` like
    findings.py:1075-1092 / export_findings.py.
    """
    return (str(record.get("slug", "")), str(record.get("title", "")))


def _matches_search(finding: dict, search: str) -> bool:
    haystack = " ".join(
        str(finding.get(key, ""))
        for key in ("slug", "title", "summary", "canonical_location", "source_name")
    ).lower()
    return search in haystack


def _filter_rows(rows: list[dict], args) -> list[dict]:
    """Apply the list_findings-style CLI filters (list_findings.py:73-105)."""
    filtered = rows
    if args.severity:
        filtered = [r for r in filtered if str(r.get("severity", "")).lower() == args.severity.lower()]
    if args.workflow_status:
        filtered = [
            r for r in filtered if str(r.get("workflow_status", "")).lower() == args.workflow_status.lower()
        ]
    if args.verification_status:
        filtered = [
            r
            for r in filtered
            if str(r.get("verification_status", "")).lower()
            == args.verification_status.lower()
        ]
    if args.source_name:
        filtered = [r for r in filtered if str(r.get("source_name", "")).lower() == args.source_name.lower()]
    if args.slug:
        filtered = [r for r in filtered if str(r.get("slug", "")).lower() == args.slug.lower()]
    if args.search:
        needle = args.search.lower()
        filtered = [r for r in filtered if _matches_search(r, needle)]
    return filtered


def _capture_records(rows: list[dict], args) -> list[dict]:
    """Filter + sort raw rows, then transform each into a fixture record."""
    selected = _filter_rows(rows, args)
    # Sort the RAW rows (slug is still present) before dropping it in the transform.
    selected.sort(key=_sort_key)
    return [_to_fixture_record(r) for r in selected]


def _validate_or_die(records: list[dict]) -> None:
    """Validate every record against the finding-record schema; hard-fail on any error.

    This is the UNCONDITIONAL coupling guard (blueprint G4). It runs on both the
    write path and the --check path so a backend serializer/model drift surfaces
    as a capture failure rather than a silently-broken fixture.
    """
    schema = load_schema(_SCHEMA_NAME)
    problems: list[str] = []
    for idx, record in enumerate(records):
        errors = collect_validation_errors(record, schema)
        if errors:
            label = record.get("title") or f"record[{idx}]"
            problems.append(f"  - {label}:")
            problems.extend(f"      {e}" for e in errors)
    if problems:
        raise SystemExit(
            "eval-capture: captured records do not satisfy "
            f"{_SCHEMA_NAME} (backend serializer drift?):\n" + "\n".join(problems)
        )


def _empty_impact_titles(records: list[dict]) -> list[str]:
    """Titles of records whose details.impact is empty/missing (G5).

    Mirrors test_quality ``attacker_outcome_present`` (strict per-finding).
    """
    titles: list[str] = []
    for idx, record in enumerate(records):
        details = record.get("details") or {}
        impact = details.get("impact", "")
        if not (isinstance(impact, str) and impact.strip()):
            titles.append(str(record.get("title") or f"finding[{idx}]"))
    return titles


def _enforce_impact(records: list[dict], strict: bool) -> None:
    """Warn (default) or hard-fail (--strict) when any details.impact is empty."""
    titles = _empty_impact_titles(records)
    if not titles:
        return
    joined = ", ".join(titles)
    message = (
        f"{len(titles)} finding(s) have an empty details.impact "
        f"(test_quality attacker_outcome_present is strict): {joined}"
    )
    if strict:
        raise SystemExit(f"eval-capture: {message}")
    print(f"WARN eval-capture: {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Serialization — match the goldens byte-for-byte-reproducibly.
# ---------------------------------------------------------------------------


def _dump_fixture(records: list[dict]) -> str:
    """Render the fixture JSON exactly like the committed goldens.

    ``indent=2`` + ``ensure_ascii=False`` + trailing newline matches
    ``tests/eval/fixtures/golden_engagement_0{1,2}.json``.
    """
    return json.dumps(records, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------------
# --definition scaffolding (blueprint §CLI) — green-by-construction.
# ---------------------------------------------------------------------------


def _present_cwes(records: list[dict]) -> list[str]:
    cwes = {
        str(r.get("details", {}).get("cwe_id", ""))
        for r in records
        if isinstance(r.get("details"), dict) and r.get("details", {}).get("cwe_id")
    }
    return sorted(cwes)


def _severity_distribution(records: list[dict]) -> dict[str, dict[str, int]]:
    counts: Counter[str] = Counter(str(r.get("severity", "")) for r in records if r.get("severity"))
    return {sev: {"min": count} for sev, count in sorted(counts.items())}


def _scaffold_definition(records: list[dict], fixture_basename: str) -> str:
    """Build a definition YAML derived from the captured data.

    The captured fixture is never born red: min_findings=count,
    max_findings=count+headroom, expected_cwes=sorted present cwe_id,
    severity_distribution mins from the actual counts, attacker_outcome_present
    strict. Emitted as hand-written YAML (no yaml.dump) so the formatting
    matches the existing definitions and stays diff-friendly.
    """
    count = len(records)
    # Quote the fixture value as a JSON string (a valid YAML double-quoted
    # scalar) so a basename containing YAML-significant characters (``#``, ``:``)
    # does not corrupt the emitted definition. YAML strips the quotes on load,
    # so ``defn["fixture"]`` round-trips to the bare basename.
    lines = [
        f"# Eval definition scaffolded by eval_capture.py from {fixture_basename}",
        "# Green-by-construction: thresholds derived from the captured snapshot.",
        f"fixture: {json.dumps(fixture_basename)}",
        "",
        "assertions:",
        "  - kind: min_findings",
        f"    value: {count}",
        "    mode: strict",
        "",
        "  - kind: max_findings",
        f"    value: {count + _MAX_FINDINGS_HEADROOM}",
        "    mode: strict",
    ]

    cwes = _present_cwes(records)
    if cwes:
        lines += ["", "  - kind: expected_cwes", "    value:"]
        lines += [f"      - {cwe}" for cwe in cwes]
        lines.append("    mode: strict")

    distribution = _severity_distribution(records)
    if distribution:
        lines += ["", "  - kind: severity_distribution", "    value:"]
        for sev, constraints in distribution.items():
            lines.append(f"      {sev}:")
            lines.append(f"        min: {constraints['min']}")
        lines.append("    mode: strict")

    lines += ["", "  - kind: attacker_outcome_present", "    mode: strict", ""]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# --check diff (blueprint §CLI) — regression detection against the golden.
# ---------------------------------------------------------------------------


def _diff_against_golden(fresh: list[dict], golden: list[dict]) -> list[str]:
    """Return regression messages comparing a fresh capture to the committed golden.

    Mirrors test_quality's assertion KINDS: count, CWE set, severity
    distribution, and impact presence. A fresh capture that surfaces strictly
    MORE coverage (extra findings/CWEs) is not a regression; losing coverage
    (fewer findings, a dropped CWE, a shrunken severity bucket, a newly-empty
    impact) is.
    """
    regressions: list[str] = []

    if len(fresh) < len(golden):
        regressions.append(
            f"finding count regressed: {len(fresh)} now vs {len(golden)} in golden"
        )

    golden_cwes = set(_present_cwes(golden))
    fresh_cwes = set(_present_cwes(fresh))
    missing_cwes = sorted(golden_cwes - fresh_cwes)
    if missing_cwes:
        regressions.append(
            f"CWE coverage regressed: {missing_cwes} present in golden but missing now"
        )

    golden_sev = Counter(str(r.get("severity", "")) for r in golden if r.get("severity"))
    fresh_sev = Counter(str(r.get("severity", "")) for r in fresh if r.get("severity"))
    for sev, golden_count in sorted(golden_sev.items()):
        fresh_count = fresh_sev.get(sev, 0)
        if fresh_count < golden_count:
            regressions.append(
                f"severity '{sev}' regressed: {fresh_count} now vs {golden_count} in golden"
            )

    empty_now = _empty_impact_titles(fresh)
    if empty_now:
        regressions.append(
            "attacker_outcome regressed: finding(s) now have empty details.impact: "
            + ", ".join(empty_now)
        )

    return regressions


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows = client.get("findings")

    if not isinstance(rows, list):
        print("eval-capture: unexpected response from backend (expected a findings list)", file=sys.stderr)
        sys.exit(1)

    records = _capture_records(rows, args)

    # G4: UNCONDITIONAL validate-before-write/compare guard.
    _validate_or_die(records)
    # G5: empty-impact discipline (warn, or hard-fail with --strict).
    _enforce_impact(records, getattr(args, "strict", False))

    out_path = Path(args.out)

    if args.check:
        if not out_path.is_file():
            print(
                f"eval-capture --check: golden fixture not found at {out_path}; "
                "run eval-capture without --check to create it first.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            golden = json.loads(out_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            print(f"eval-capture --check: golden fixture {out_path} is not valid JSON: {exc}", file=sys.stderr)
            sys.exit(1)
        if not isinstance(golden, list):
            print(f"eval-capture --check: golden fixture {out_path} must be a JSON array", file=sys.stderr)
            sys.exit(1)
        regressions = _diff_against_golden(records, golden)
        if regressions:
            print(
                f"eval-capture --check: {len(regressions)} regression(s) vs {out_path}:",
                file=sys.stderr,
            )
            for msg in regressions:
                print(f"  - {msg}", file=sys.stderr)
            sys.exit(1)
        print(f"eval-capture --check: no regressions vs {out_path} ({len(records)} findings)")
        return

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(_dump_fixture(records), encoding="utf-8")
    print(f"Captured {len(records)} findings to {out_path}")

    if args.definition:
        def_path = Path(args.definition)
        def_path.parent.mkdir(parents=True, exist_ok=True)
        def_path.write_text(_scaffold_definition(records, out_path.name), encoding="utf-8")
        print(f"Scaffolded definition at {def_path}")


def main(argv: list[str] | None = None) -> None:
    """Standalone maintainer/CI entrypoint.

    eval-capture is off the operator ``vigil assess`` surface; run it directly::

        python agent/scripts/assess/commands/eval_capture.py \\
          --engagement-dir <dir> --out tests/eval/fixtures/golden_<name>.json

    ``--engagement-dir`` mirrors the root ``vigil assess`` flag (default: the
    engagement tree containing CWD or the Vigil launcher session binding).
    """
    parser = argparse.ArgumentParser(
        prog="eval_capture.py",
        description="Snapshot backend findings into a golden eval fixture (zero-token replay).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=_MAINTAINER_EXAMPLES,
    )
    parser.add_argument(
        "--engagement-dir",
        dest="engagement_dir",
        default=None,
        help="Engagement directory (default: engagement CWD or launcher session binding).",
    )
    _add_capture_arguments(parser)
    run(parser.parse_args(argv))


if __name__ == "__main__":  # pragma: no cover - maintainer CLI shim
    main()
