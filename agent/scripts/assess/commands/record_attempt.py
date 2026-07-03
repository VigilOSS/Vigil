"""vigil assess record-attempt — record a NON-covering probe attempt.

A specialist runs this to log a probe attempt whose ``result_status`` is
deliberately NON-covering — ``attempted`` (the probe fired but proved nothing),
``blocked`` (a wall stopped it: WAF, auth gate, egress firewall), ``no-signal``
(the target answered but nothing distinguished it), or ``error`` (the probe
itself failed). These four are the "a non-conclusive response is a lead, not a
verdict" statuses: they record that the target was TOUCHED under a given lens
without counting as coverage, so the resume brief surfaces them under Attempts
and the next dispatch does not silently re-run the same dead end.

Covering statuses (``tested`` / ``signal``) are recorded by the normal probe
pipeline, not here — this verb intentionally restricts ``--result-status`` to
the non-covering set so a covering verdict cannot be recorded without evidence.

POSTs to the same ``probe-runs`` route the covering path uses. The ``--lens`` is
part of the probe key server-side, so the same target under a different lens is
a distinct attempt (not a dedup hit). Pass ``--finding <slug>`` to backfill the
attempt→finding link (COALESCE-backfilled on a re-run of the same probe).
"""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib import vuln_taxonomy
from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


# The non-covering result_status vocabulary. The backend's ProbeRunRecordRequest
# accepts these plus the covering `tested`/`signal`; this verb exposes only the
# non-covering four so a hand-recorded attempt can never masquerade as coverage.
_NONCOVERING_STATUSES = ("attempted", "blocked", "no-signal", "error")


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record-attempt",
        help="Record a non-covering probe attempt (attempted|blocked|no-signal|error) under a lens.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("record-attempt"),
    )
    p.add_argument(
        "--result-status",
        dest="result_status",
        required=True,
        choices=list(_NONCOVERING_STATUSES),
        help="Non-covering outcome: attempted | blocked | no-signal | error.",
    )
    p.add_argument(
        "--attack-family",
        dest="attack_family",
        required=True,
        help=(
            "Vuln-class family the attempt exercised (a vuln_taxonomy class, e.g. "
            "ssrf | idor | sqli | open-redirect). Unknown values WARN but are stored."
        ),
    )
    p.add_argument(
        "--lens",
        default="",
        help=(
            "Free-text lens/mindset the probe ran under (e.g. 'tenant-boundary', "
            "'blind-oob'). Part of the probe key: the same target under a different "
            "lens is a distinct attempt, not a dedup collision."
        ),
    )
    p.add_argument("--tool", dest="tool_name", default="manual", help="Tool that produced the attempt (default: manual).")
    p.add_argument("--target-host", dest="target_host", default="", help="Target host the attempt hit.")
    p.add_argument("--target-path", dest="target_path", default="", help="Target path the attempt hit.")
    p.add_argument("--target-port", dest="target_port", type=int, default=None, help="Target port (int).")
    p.add_argument(
        "--auth-context",
        dest="auth_context",
        default="anonymous",
        help="Identity the attempt ran under (default: anonymous).",
    )
    p.add_argument(
        "--input-slot",
        dest="input_slot",
        default="unknown",
        help="Where the payload entered (query|body|header|path|cookie|...; default: unknown).",
    )
    p.add_argument("--payload-family", dest="payload_family", default="", help="Optional payload family tag.")
    p.add_argument("--payload-value", dest="payload_value", default="", help="Optional payload value that was sent.")
    p.add_argument("--signal-type", dest="signal_type", default="", help="Optional signal-type tag when partial signal was seen.")
    p.add_argument(
        "--observed-status",
        dest="observed_http_status",
        type=int,
        default=None,
        help="Observed HTTP status code (int), when the target answered.",
    )
    p.add_argument("--evidence-ref", dest="evidence_ref", default="", help="Optional engagement-relative evidence path.")
    p.add_argument("--notes", default="", help="Short free-text note on what was tried and why it did not conclude.")
    p.add_argument("--agent-name", dest="agent_name", default="", help="Recording agent name (audit attribution).")
    p.add_argument(
        "--finding",
        dest="finding",
        default="",
        help="Optional finding slug (or numeric id) to backfill the attempt→finding link.",
    )
    p.set_defaults(func=run)


def _resolve_finding_id(client: AssessmentClient, ref: str) -> int:
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
        raise AssessError(f"record-attempt: finding {ref!r} not found")
    return int(row["id"])


def run(args) -> None:
    attack_family = vuln_taxonomy.normalize_class(args.attack_family)
    if not attack_family:
        print("record-attempt: --attack-family is required", file=sys.stderr)
        sys.exit(1)
    # WARN-first: an out-of-vocab family is advisory, not a hard block — the
    # backend stores plain TEXT for forward compatibility, so we normalize and
    # surface a hint rather than fail closed on a class the taxonomy hasn't
    # caught up with yet.
    if not vuln_taxonomy.is_valid_class(attack_family):
        print(
            f"WARN record-attempt: --attack-family {attack_family!r} is not a known "
            f"vuln_taxonomy class; recording it verbatim.",
            file=sys.stderr,
        )

    payload: dict = {
        "attack_family": attack_family,
        "result_status": args.result_status,
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

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if (args.finding or "").strip():
            payload["finding_id"] = _resolve_finding_id(client, args.finding)
        result = client.post("probe-runs", payload)
    print(json.dumps(result, indent=2, ensure_ascii=False))
