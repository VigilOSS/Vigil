"""vigil assess code-record fuzz-campaign — persist one terminal campaign receipt."""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient
from assess.lib.code_record_input import (
    bounded_string,
    canonical_string_list,
    fail,
    nonnegative_integer,
    positive_integer,
    read_strict_object,
    sha256,
)
from assess.lib.config import load_config


_LABEL = "fuzz-campaign"
_FIELDS = frozenset(
    {
        "dispatch_id",
        "repo_id",
        "repo_generation",
        "source_manifest_digest",
        "target_id",
        "covered_finding_slugs",
        "engine",
        "sanitizers",
        "run_budget_seconds",
        "executions",
        "outcome",
        "crash_count",
        "triage_summary",
        "evidence_ref",
        "rationale",
    }
)
_OUTCOMES = {
    "completed_no_crash",
    "completed_crashes_triaged",
    "build_failed",
    "campaign_failed",
}


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "fuzz-campaign",
        help="Record one generation- and dispatch-bound terminal fuzz campaign receipt",
    )
    parser.add_argument("receipt_json", help="Path to one receipt JSON object, or '-'")
    parser.set_defaults(func=run)


def run(args) -> None:
    payload = read_strict_object(
        args.receipt_json,
        label=_LABEL,
        required_fields=_FIELDS,
    )
    for field in ("dispatch_id", "repo_id", "repo_generation", "run_budget_seconds"):
        positive_integer(_LABEL, payload, field)
    executions = nonnegative_integer(_LABEL, payload, "executions")
    crash_count = nonnegative_integer(_LABEL, payload, "crash_count")
    sha256(_LABEL, payload, "source_manifest_digest")
    for field, maximum in (
        ("target_id", 256),
        ("engine", 128),
        ("triage_summary", 20000),
        ("evidence_ref", 4096),
        ("rationale", 20000),
    ):
        bounded_string(_LABEL, payload, field, maximum=maximum)
    canonical_string_list(
        _LABEL, payload, "covered_finding_slugs", maximum=1000
    )
    canonical_string_list(
        _LABEL, payload, "sanitizers", maximum=32, require_nonempty=True
    )
    outcome = bounded_string(_LABEL, payload, "outcome", maximum=64)
    if outcome not in _OUTCOMES:
        fail(_LABEL, "unknown campaign outcome")
    if outcome == "completed_no_crash" and crash_count != 0:
        fail(_LABEL, "completed_no_crash requires crash_count=0")
    if outcome == "completed_crashes_triaged" and crash_count < 1:
        fail(_LABEL, "completed_crashes_triaged requires crash_count>=1")
    if outcome in {"completed_no_crash", "completed_crashes_triaged"} and executions < 1:
        fail(_LABEL, "completed fuzz campaigns require at least one execution")
    config = load_config(args.engagement_dir)
    with AssessmentClient(config.base_url, config.engagement_key) as client:
        result = client.post("code/fuzz/campaign-receipts", payload)
    if not isinstance(result, dict):
        fail(_LABEL, "backend response must be a JSON object")
    print(json.dumps(result, indent=2, sort_keys=True))
