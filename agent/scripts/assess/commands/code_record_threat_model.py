"""vigil assess code-record-threat-model — POST a threat model for a code repository."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser("code-record-threat-model", help="Record a threat model for a code repository")
    p.add_argument("repo_id", help="Repository ID")
    p.add_argument("threat_model_json", help="Path to JSON file containing the threat model")
    p.set_defaults(func=run)


def run(args) -> None:
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
        'threat_model': threat_model,
    }

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = client.post('code/threat-model', payload)

    tm_id = result.get('id') or result.get('threat_model_id', '')
    print(f"Threat model recorded for repo {args.repo_id} (id: {tm_id})")
    print(json.dumps(result, indent=2, ensure_ascii=False))
