"""assess.py code-record-analysis — POST per-function analysis results."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.code_audit import write_json_snapshot
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-record-analysis",
        help="Record per-function analysis results from code-vuln-hunter",
    )
    p.add_argument(
        "analysis_json",
        help="Path to JSON file with a single result object or array of result objects",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    json_path = Path(args.analysis_json)
    if not json_path.is_file():
        print(f"Analysis JSON file not found: {args.analysis_json}", file=sys.stderr)
        sys.exit(1)

    raw = json.loads(json_path.read_text(encoding="utf-8"))

    # Accept either a single object or an array
    if isinstance(raw, dict):
        results = [raw]
    elif isinstance(raw, list):
        results = raw
    else:
        print("Analysis file must contain a JSON object or array", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("No analysis results to submit.", file=sys.stderr)
        sys.exit(0)

    # Validate required fields
    required = {"file_id", "disposition"}
    for i, result in enumerate(results):
        if not isinstance(result, dict):
            print(f"Item {i} is not a JSON object", file=sys.stderr)
            sys.exit(1)
        missing = required - set(result.keys())
        if missing:
            print(
                f"Item {i} missing required fields: {', '.join(sorted(missing))}",
                file=sys.stderr,
            )
            sys.exit(1)

    cfg = load_config(args.engagement_dir)
    submit_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-analysis-submit",
        label=json_path.stem,
        payload=results,
        source_path=str(json_path),
        metadata={"command": "code-record-analysis", "count": len(results)},
    )
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    responses = []
    try:
        created = 0
        for result in results:
            resp = client.post("code/analysis-results", result)
            responses.append(resp)
            created += 1
            disp = result.get("disposition", "?")
            func = result.get("function_name", "unknown")
            print(f"  Recorded: {func} → {disp}")
    finally:
        client.close()

    response_snapshot = write_json_snapshot(
        cfg.engagement_dir,
        category="code-analysis-response",
        label=json_path.stem,
        payload=responses,
        source_path=str(submit_snapshot),
        metadata={"command": "code-record-analysis", "count": len(results)},
    )

    print(f"\n=== Analysis Results Summary ===")
    print(f"Results recorded: {created}")
    print(f"Audit snapshots: {submit_snapshot.name}, {response_snapshot.name}")

    # Count dispositions
    dispositions = {}
    for r in results:
        d = r.get("disposition", "unknown")
        dispositions[d] = dispositions.get(d, 0) + 1
    for d, count in sorted(dispositions.items()):
        print(f"  {d}: {count}")
