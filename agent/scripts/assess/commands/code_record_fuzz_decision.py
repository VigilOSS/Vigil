"""vigil assess code-record fuzz-decision — persist fuzz applicability."""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.code_record_input import (
    bounded_string,
    canonical_string_list,
    fail,
    positive_integer,
    read_strict_object,
    sha256,
)
from assess.lib.config import load_config


_LABEL = "fuzz-decision"
_FIELDS = frozenset(
    {
        "repo_id",
        "repo_generation",
        "source_manifest_digest",
        "decision",
        "target_ids",
        "evidence_ref",
        "rationale",
    }
)


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "fuzz-decision",
        help="Record a generation-bound fuzz applicability decision",
    )
    parser.add_argument("decision_json", help="Path to one decision JSON object, or '-'")
    parser.set_defaults(func=run)


def run(args) -> None:
    payload = read_strict_object(
        args.decision_json,
        label=_LABEL,
        required_fields=_FIELDS,
    )
    positive_integer(_LABEL, payload, "repo_id")
    positive_integer(_LABEL, payload, "repo_generation")
    sha256(_LABEL, payload, "source_manifest_digest")
    decision = payload["decision"]
    if decision not in {"required", "not_required"}:
        fail(_LABEL, "decision must be 'required' or 'not_required'")
    targets = canonical_string_list(
        _LABEL, payload, "target_ids", maximum=128
    )
    if decision == "not_required" and targets:
        fail(_LABEL, "not_required decisions cannot declare target_ids")
    if decision == "required" and not targets:
        fail(_LABEL, "required decisions must declare at least one target_id")
    bounded_string(_LABEL, payload, "evidence_ref", maximum=4096)
    bounded_string(_LABEL, payload, "rationale", maximum=20000)
    config = load_config(args.engagement_dir)
    with AssessmentClient(config.base_url, config.engagement_key) as client:
        result = client.post("code/fuzz/decision", payload)
    if not isinstance(result, dict):
        fail(_LABEL, "backend response must be a JSON object")
    require_write_result(
        result,
        operation="record code fuzz decision",
        expected={
            "repo_id": payload["repo_id"],
            "repo_generation": payload["repo_generation"],
            "source_manifest_digest": payload["source_manifest_digest"],
            "decision": payload["decision"],
            "target_ids": payload["target_ids"],
            "current": True,
        },
        positive_ids=("id",),
    )
    print(json.dumps(result, indent=2, sort_keys=True))
