"""vigil assess code-record threat-model — POST a threat model for a code repository."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("threat-model", help="Record a threat model for a code repository")
    p.add_argument("repo_id", help="Repository ID")
    p.add_argument(
        "--repo-generation",
        required=True,
        type=int,
        help="Exact published repository generation the threat model describes",
    )
    p.add_argument(
        "--source-manifest-digest",
        required=True,
        help="Exact sealed source manifest digest the threat model describes",
    )
    p.add_argument("threat_model_json", help="Path to JSON file containing the threat model")
    p.set_defaults(func=run)


def run(args) -> None:
    repo_generation = getattr(args, "repo_generation", None)
    source_manifest_digest = str(getattr(args, "source_manifest_digest", "") or "")
    if not isinstance(repo_generation, int) or repo_generation < 1:
        print("--repo-generation must be a positive integer", file=sys.stderr)
        sys.exit(1)
    if len(source_manifest_digest) != 64 or any(
        character not in "0123456789abcdef" for character in source_manifest_digest
    ):
        print(
            "--source-manifest-digest must be a lowercase 64-character SHA-256 digest",
            file=sys.stderr,
        )
        sys.exit(1)

    json_path = Path(args.threat_model_json)
    if not json_path.is_file():
        print(f"Threat model JSON file not found: {args.threat_model_json}", file=sys.stderr)
        sys.exit(1)

    threat_model = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(threat_model, dict):
        print("Threat model file must contain a JSON object", file=sys.stderr)
        sys.exit(1)

    payload = {
        'repo_id': int(args.repo_id),
        'repo_generation': repo_generation,
        'source_manifest_digest': source_manifest_digest,
        'threat_model': threat_model,
    }

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/threat-model', payload)
    require_write_result(
        result,
        operation="record code threat model",
        expected={
            "id": int(args.repo_id),
            "active_generation": repo_generation,
            "threat_model_generation": repo_generation,
            "source_manifest_digest": source_manifest_digest,
            "threat_model": threat_model,
        },
        positive_ids=("id",),
    )

    print(f"Threat model recorded for repo {args.repo_id} (id: {result['id']})")
    print(json.dumps(result, indent=2, ensure_ascii=False))
