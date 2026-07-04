"""Shared argument + payload plumbing for the probe-recording verbs.

Both ``record-attempt`` (the NON-covering path: ``attempted|blocked|no-signal|
error``) and ``record-probe`` (the COVERING path: ``tested|signal`` with
required evidence) POST to the same backend ``probe-runs`` route with the same
``ProbeRunRecordRequest`` shape. Keeping the flag set, the payload assembly, and
the ``--finding`` resolver in one place is what stops the covering and
non-covering verbs from drifting apart as fields are added to the backend model.

Each verb owns only its own ``--result-status`` argument (different ``choices``
and help) and its own covering/non-covering guardrails; everything else comes
from here.
"""
from __future__ import annotations

import sys

from assess.lib import vuln_taxonomy
from assess.lib.client import AssessError, AssessmentClient


def add_common_probe_args(parser, *, include_links: bool) -> None:
    """Add every ``ProbeRunRecordRequest`` field except ``--result-status``.

    ``include_links=True`` also exposes the canonical FK links a specialist
    carries forward from a fetched work-item (``request_variant_id`` /
    ``service_id`` / ``coverage_item_id``). ``record-attempt`` omits them (a
    non-covering lead is target-anchored by host/path); ``record-probe`` exposes
    them so a covering probe attaches to the exact coverage item it satisfies.
    """
    parser.add_argument(
        "--attack-family",
        dest="attack_family",
        required=True,
        help=(
            "Vuln-class family the probe exercised (a vuln_taxonomy class, e.g. "
            "ssrf | idor | sqli | open-redirect). Unknown values WARN but are stored."
        ),
    )
    parser.add_argument(
        "--lens",
        default="",
        help=(
            "Free-text lens/mindset the probe ran under (e.g. 'tenant-boundary', "
            "'blind-oob'). Part of the probe key: the same target under a different "
            "lens is a distinct probe, not a dedup collision."
        ),
    )
    parser.add_argument("--tool", dest="tool_name", default="manual", help="Tool that produced the probe (default: manual).")
    parser.add_argument("--target-host", dest="target_host", default="", help="Target host the probe hit.")
    parser.add_argument("--target-path", dest="target_path", default="", help="Target path the probe hit.")
    parser.add_argument("--target-port", dest="target_port", type=int, default=None, help="Target port (int).")
    parser.add_argument(
        "--auth-context",
        dest="auth_context",
        default="anonymous",
        help="Identity the probe ran under (default: anonymous).",
    )
    parser.add_argument(
        "--input-slot",
        dest="input_slot",
        default="unknown",
        help=(
            "Where the payload entered. Prefer the specific named input as "
            "'slot:name' (e.g. 'header:X-Forwarded-Host', 'query:uid', "
            "'body:idProofUser') so 'which input was tested' stays queryable; a bare "
            "slot (query|body|header|path|cookie) is fine for whole-slot probes "
            "(default: unknown)."
        ),
    )
    parser.add_argument("--payload-family", dest="payload_family", default="", help="Optional payload family tag.")
    parser.add_argument("--payload-value", dest="payload_value", default="", help="Optional payload value that was sent.")
    parser.add_argument("--signal-type", dest="signal_type", default="", help="Optional signal-type tag when partial signal was seen.")
    parser.add_argument(
        "--observed-status",
        dest="observed_http_status",
        type=int,
        default=None,
        help="Observed HTTP status code (int), when the target answered.",
    )
    parser.add_argument("--evidence-ref", dest="evidence_ref", default="", help="Engagement-relative evidence path (e.g. scans/idor.txt). record-probe requires it; record-attempt does not.")
    parser.add_argument("--notes", default="", help="Short free-text note on what was tried and what the outcome shows.")
    parser.add_argument("--agent-name", dest="agent_name", default="", help="Recording agent name (audit attribution).")
    parser.add_argument(
        "--finding",
        dest="finding",
        default="",
        help="Optional finding slug (or numeric id) to backfill the probe→finding link.",
    )
    if include_links:
        parser.add_argument(
            "--request-variant-id",
            dest="request_variant_id",
            type=int,
            default=None,
            help="Canonical request_variant_id from the fetched work-item (links the probe to the exact request).",
        )
        parser.add_argument(
            "--service-id",
            dest="service_id",
            type=int,
            default=None,
            help="Canonical service_id from the fetched work-item.",
        )
        parser.add_argument(
            "--coverage-item-id",
            dest="coverage_item_id",
            type=int,
            default=None,
            help="Canonical coverage_item_id this probe covers (from the fetched work-item).",
        )


def normalize_attack_family(raw: str, verb: str) -> str:
    """Normalize ``--attack-family`` to a taxonomy class; WARN (not fail) if out-of-vocab.

    The backend stores plain TEXT for forward-compatibility, so an out-of-vocab
    class is advisory rather than a hard block — normalize and surface a hint.
    """
    family = vuln_taxonomy.normalize_class(raw)
    if not family:
        print(f"{verb}: --attack-family is required", file=sys.stderr)
        sys.exit(1)
    if not vuln_taxonomy.is_valid_class(family):
        print(
            f"WARN {verb}: --attack-family {family!r} is not a known "
            f"vuln_taxonomy class; recording it verbatim.",
            file=sys.stderr,
        )
    return family


def build_probe_payload(args, *, attack_family: str, result_status: str) -> dict:
    """Assemble the ``ProbeRunRecordRequest`` body from the shared args.

    ``attack_family`` and ``result_status`` are passed in already-resolved so
    each verb keeps ownership of its status vocabulary.
    """
    payload: dict = {
        "attack_family": attack_family,
        "result_status": result_status,
        "tool_name": (args.tool_name or "manual").strip() or "manual",
        "lens": (args.lens or "").strip(),
        "auth_context": (args.auth_context or "anonymous").strip() or "anonymous",
        "input_slot": (args.input_slot or "unknown").strip() or "unknown",
        "payload_family": args.payload_family or "",
        "payload_value": args.payload_value or "",
        "signal_type": args.signal_type or "",
        "target_host": (args.target_host or "").strip(),
        "target_path": (args.target_path or "").strip(),
        "evidence_ref": args.evidence_ref or "",
        "notes": args.notes or "",
        "agent_name": args.agent_name or "",
    }
    if args.target_port is not None:
        payload["target_port"] = int(args.target_port)
    if args.observed_http_status is not None:
        payload["observed_http_status"] = int(args.observed_http_status)
    for link in ("request_variant_id", "service_id", "coverage_item_id"):
        value = getattr(args, link, None)
        if value is not None:
            payload[link] = int(value)
    return payload


def resolve_finding_id(client: AssessmentClient, ref: str, verb: str) -> int:
    """Resolve a ``--finding`` reference (slug or numeric id) to a finding_id int.

    A bare integer is used directly (the backend re-validates it belongs to the
    engagement, 404 otherwise). Otherwise the ref is treated as a slug and looked
    up so the operator can pass the human slug (e.g. VA-047) they already hold.
    """
    ref = ref.strip()
    try:
        return int(ref)
    except ValueError:
        pass
    row = client.get(f"findings/{ref}")
    if not isinstance(row, dict) or not row.get("id"):
        raise AssessError(f"{verb}: finding {ref!r} not found")
    return int(row["id"])
