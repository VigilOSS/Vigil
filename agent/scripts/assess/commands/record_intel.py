"""vigil assess intel record — multiplexed intel-type recorder.

Replaces the old ``intel.md`` append pattern. Validates payload against the
matching ``agent/schemas/intel-<type>.schema.json`` then POSTs to
``/engagements/{key}/intel/{type-plural}`` on the orchestrator backend.
Emits an ``intel.recorded`` event on success.

Usage::

    vigil assess intel record <type> <json-file>

``<type>`` is one of: tech-component, person, email, domain, cve,
dns-record, social-profile, breach-record, org-fact, note.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import get_contract
from assess.lib.intel_types import INTEL_TYPES
from assess.lib.schema_validation import collect_validation_errors, load_schema


_NATURAL_IDENTITY_FIELDS: dict[str, tuple[tuple[str, object], ...]] = {
    "tech-component": (("component", ""), ("version", "")),
    "person": (("name", ""),),
    "email": (("address", ""),),
    "domain": (("identity", ""), ("kind", "subdomain")),
    "cve": (("cve_id", ""), ("affected_component", "")),
    "dns-record": (("record_type", ""), ("name", ""), ("value", "")),
    "social-profile": (
        ("subject_kind", ""),
        ("subject_ref", ""),
        ("platform", ""),
        ("handle", ""),
    ),
    "breach-record": (("subject", ""), ("breach_name", "")),
    "org-fact": (("fact_key", ""),),
    "note": (("title", ""),),
}


def _unknown_long_options(parser: argparse.ArgumentParser, tokens: list[str]) -> list[str]:
    """Long options in ``tokens`` that this parser does not register.

    Only ``--``-prefixed names are policed: a single-dash token can be a bundled
    short option or a negative number, and argparse owns those. A bare ``--``
    ends option parsing, so nothing after it is a flag.
    """
    unknown: list[str] = []
    for token in tokens:
        if token == "--":
            break
        if not token.startswith("--") or len(token) < 3:
            continue
        name = token.split("=", 1)[0]
        # A unique-prefix abbreviation (`--dry` for `--dry-run`) is a spelling
        # argparse accepts, so it is not an unknown flag.
        if any(option.startswith(name) for option in parser._option_string_actions):
            continue
        if name not in unknown:
            unknown.append(name)
    return unknown


def _refuse_unknown_options(unknown: list[str], tokens: list[str]) -> None:
    """Answer an unknown flag with the JSON shape the verb actually wanted.

    Returns without refusing when nothing is left to explain, so argparse's own
    unrecognized-arguments path still owns the flags that are not this verb's to
    answer for.
    """
    # A root flag that lost its value (`... --engagement-dir` with nothing after
    # it) is not hoisted to the front of argv by `cli._hoist_root_flags` and so
    # lands here — but it is not a content flag, and this verb's schema is no
    # answer for it. Read the roster from the root rather than re-spelling it.
    from assess.cli import _ROOT_FLAGS_WITH_VALUE

    unknown = [name for name in unknown if name not in _ROOT_FLAGS_WITH_VALUE]
    if not unknown:
        return
    intel_type = next((token for token in tokens if token in INTEL_TYPES), "")
    label = intel_type or "<type>"
    contract = get_contract(f"intel record {intel_type}") if intel_type else None
    if contract is None:
        contract = get_contract("intel record")
    print(
        f"intel record: unrecognized option(s): {', '.join(unknown)}",
        file=sys.stderr,
    )
    schema_name = getattr(contract, "schema_name", "") or f"intel-{label}.schema.json"
    print(
        "intel record takes no content flags — the row is one JSON document "
        f"validated against {schema_name}:",
        file=sys.stderr,
    )
    invocations = getattr(contract, "preferred_invocations", ()) or ()
    example = invocations[0] if invocations else "vigil assess intel record <type> <file.json>"
    print(f"  {example}", file=sys.stderr)
    fields = getattr(contract, "author_supplied_fields", ()) or ()
    if fields:
        print(
            f"Author-supplied fields for {label}: {', '.join(fields)}",
            file=sys.stderr,
        )
    print(
        f"Run `vigil assess contract intel record {label}` for the full contract.",
        file=sys.stderr,
    )
    sys.exit(2)


class _IntelRecordParser(argparse.ArgumentParser):
    """Answer an unknown long option at ``intel record``'s own scope.

    This verb takes a JSON document, not content flags, so ``--summary "..."``
    is the natural first attempt — and argparse answers it from the ROOT parser,
    because ``_SubParsersAction.__call__`` hands whatever this parser did not
    recognize back up the chain. What the caller got was a usage block listing
    every top-level verb plus ``unrecognized arguments: --summary``, naming
    neither the file argument nor the schema behind it.

    The leftover is only attributable to this verb while argv is still scoped to
    it, so the check runs BEFORE delegating: argparse's own pass would otherwise
    answer ``--summary`` (whose value it swallows as ``json_file``) with a
    missing-positional error that says nothing about the flag.
    """

    def parse_known_args(self, args=None, namespace=None):  # noqa: D102 - argparse override
        tokens = list(args or [])
        unknown = _unknown_long_options(self, tokens)
        if unknown:
            _refuse_unknown_options(unknown, tokens)
        return super().parse_known_args(args, namespace)


def register(subparsers) -> None:
    types_list = ", ".join(sorted(INTEL_TYPES.keys()))
    # argparse binds the parser class at `add_subparsers(parser_class=...)`
    # time, so one leaf opts into a different class through a temporary factory
    # swap — the same mechanism `contracts.add_contract_subparser` uses, which
    # cannot be reused directly because it hardcodes `ContractErrorParser`.
    saved_parser_class = subparsers._parser_class
    subparsers._parser_class = _IntelRecordParser
    try:
        p = subparsers.add_parser(
            "record",
            help="Record a structured intel record (replaces intel.md appends)",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=(
                "Examples:\n"
                "  vigil assess intel record tech-component tech.json\n"
                "  vigil assess intel record cve cve-2024-1234.json\n"
                "  vigil assess intel record note catchall.json\n"
                "  vigil assess contract intel record tech-component   # allowed keys for a type\n"
                f"\nValid types: {types_list}"
            ),
        )
    finally:
        subparsers._parser_class = saved_parser_class
    p.add_argument("intel_type", help=f"One of: {types_list}")
    p.add_argument("json_file", help="Path to intel JSON file matching the intel-<type> schema")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the payload and print the resolved URL without POSTing",
    )
    p.set_defaults(func=run)


def _load_payload(path: Path) -> dict:
    if not path.is_file():
        print(f"intel json file not found: {path}", file=sys.stderr)
        sys.exit(1)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"intel json file is not valid JSON: {exc}", file=sys.stderr)
        sys.exit(1)
    if not isinstance(payload, dict):
        print("intel payload must be a JSON object", file=sys.stderr)
        sys.exit(1)
    return payload


def _report_validation_errors(intel_type: str, errors: list[str]) -> None:
    print(f"record-intel {intel_type}: payload failed schema validation:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)
    print(
        f"Run `vigil assess contract intel record {intel_type}` for the allowed keys.",
        file=sys.stderr,
    )
    sys.exit(1)


def run(args) -> None:
    intel_type = args.intel_type
    if intel_type not in INTEL_TYPES:
        print(
            f"unknown intel type '{intel_type}'. Valid: {', '.join(sorted(INTEL_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(1)

    schema_name, endpoint_segment = INTEL_TYPES[intel_type]

    payload = _load_payload(Path(args.json_file))

    schema = load_schema(schema_name)
    errors = collect_validation_errors(payload, schema)
    if errors:
        _report_validation_errors(intel_type, errors)

    cfg = load_config(args.engagement_dir)
    endpoint = f"intel/{endpoint_segment}"

    if args.dry_run:
        # Print the resolved URL and validated payload so the caller can
        # verify schema + URL construction without hitting the backend.
        url = f"{cfg.base_url}/engagements/{cfg.engagement_key}/{endpoint}"
        print(f"[dry-run] would POST {url}")
        print(f"[dry-run] payload: {json.dumps(payload, ensure_ascii=False)}")
        return

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        response = client.post_engagement(endpoint, payload)

    # An object alone is not this endpoint's success contract. The write may
    # already be durable, so an absent canonical id is an uncertain outcome:
    # stop before emitting the success event and tell the caller to inspect the
    # exact typed list rather than blindly replaying the write.
    record_id = response.get("id")
    if (
        not isinstance(record_id, int)
        or isinstance(record_id, bool)
        or record_id < 1
        or any(
            field not in response or response[field] != payload.get(field, default)
            for field, default in _NATURAL_IDENTITY_FIELDS[intel_type]
        )
    ):
        print(
            f"record-intel: backend did not return a canonical {intel_type} record "
            "with a positive id; the write may have committed, so inspect "
            f"`vigil assess intel list {intel_type}` and do not retry automatically",
            file=sys.stderr,
        )
        sys.exit(1)

    # Emit event — fire-and-forget, outside the main call.
    summary_title = ""
    for key in ("component", "name", "address", "identity", "cve_id", "handle", "fact_key", "title"):
        value = response.get(key)
        if value:
            summary_title = str(value)
            break

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as event_client:
        event_client.post_event(
            {
                "event_type": "intel.recorded",
                "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
                "task_name": intel_type,
                "agent_name": payload.get("source_name")
                or (payload.get("provenance") or {}).get("agent_name")
                or "unknown",
                "summary": summary_title or intel_type,
            }
        )

    if intel_type == "note" and response.get("write_outcome") in {"created", "updated"}:
        outcome = str(response["write_outcome"])
        qualifier = "new" if outcome == "created" else "existing"
        print(f"Recorded intel note id={record_id}: {outcome} {qualifier} note")
    else:
        print(f"Recorded intel {intel_type} id={record_id}")
