"""aith assess record-proposal — validate + append to proposals.jsonl."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.schema_validation import SchemaValidationError, load_schema, validate_payload


_PROPOSAL_SCHEMAS = {
    "finding_record": "finding-record.schema.json",
    "probe_run": "probe-run.schema.json",
    "attack_chain": "attack-chain.schema.json",
    "credential": "credential.schema.json",
    "access_record": "access-record.schema.json",
}


def register(subparsers) -> None:
    p = subparsers.add_parser("record-proposal", help="Record a session proposal")
    p.add_argument("session_dir", help="Path to session directory")
    p.add_argument("json_file", help="Path to proposal JSON file")
    p.set_defaults(func=run)


def run(args) -> None:
    session_dir = Path(args.session_dir)
    json_path = Path(args.json_file)

    if not session_dir.is_dir():
        print(f"session directory not found: {args.session_dir}", file=sys.stderr)
        sys.exit(1)
    if not json_path.is_file():
        print(f"proposal file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    proposal = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(proposal, dict):
        print("session proposal must be a JSON object", file=sys.stderr)
        sys.exit(1)

    # Validate required fields
    proposal_type = proposal.get("type")
    payload = proposal.get("payload")

    if not proposal_type:
        print("session proposal missing required field: type", file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("session proposal payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    schema_name = _PROPOSAL_SCHEMAS.get(proposal_type)
    if schema_name is None:
        print(f"unsupported proposal type: {proposal_type}", file=sys.stderr)
        sys.exit(1)
    try:
        validate_payload(payload, load_schema(schema_name))
    except SchemaValidationError as exc:
        print(f"session proposal payload invalid: {exc}", file=sys.stderr)
        sys.exit(1)

    # Append to proposals.jsonl
    proposals_dir = session_dir / "proposals"
    proposals_dir.mkdir(parents=True, exist_ok=True)
    proposals_file = proposals_dir / "proposals.jsonl"

    normalized = json.dumps(proposal, ensure_ascii=True, separators=(",", ":"))
    with open(proposals_file, "a", encoding="utf-8") as f:
        f.write(normalized + "\n")

    print(f"Recorded proposal in {proposals_file}")
