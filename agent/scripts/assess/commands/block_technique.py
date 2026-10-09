"""vigil assess block-technique / list-blocked-techniques — do-today attempt ledger.

Records a technique that is walled off on a specific target (an account/line/
device/credential/access wall, a WAF, a policy stop) so the operator and the
next engagement see "this was tried and blocked here" instead of rediscovering
the wall per-dispatch. Wires the previously CLI-less
``assessment_blocked_techniques`` backend table (POST/GET /blocked-techniques).

This is a POINTER, not a finding: a blocked technique stays out of the report,
and — unlike a finding — it has NO slug, so it can never be the SUBJECT of a
``finding link`` call (that resolver is findings-only and hard-404s a non-slug).
Record the unblock relationship on the FINDING side instead: when a finding/chain
later satisfies the wall, link it with
``vigil assess finding link <unblocking-finding-slug> --link-kind unblocks
--target-kind blocked_technique --target-ref <technique_key>`` so the unblock
path is first-class (the finding points AT the blocked-technique key this verb
emits/derives).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from urllib.parse import urlencode

from assess.lib.audit_enums import TECHNIQUE_ENUM, normalize_technique
from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_optional_inline_json


RETRY_STATES: tuple[str, ...] = (
    "pending",
    "no_retry",
    "retryable",
    "blocked",
    "blocked_on_dependency",
    "needs_authorization",
)


def register(subparsers) -> None:
    block = subparsers.add_parser(
        "block-technique",
        help="Record a technique blocked on a target (account/device/credential/policy wall, WAF).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("block-technique"),
    )
    block.add_argument(
        "--technique",
        required=True,
        help="Vuln-class technique tag; one of TECHNIQUE_ENUM: " + ", ".join(TECHNIQUE_ENUM),
    )
    block.add_argument(
        "--target-kind",
        dest="target_kind",
        required=True,
        help="What the block is scoped to, e.g. finding | surface | host | request_variant | endpoint.",
    )
    block.add_argument(
        "--target-ref",
        dest="target_ref",
        required=True,
        help="Reference to the blocked target (finding slug, host, URL, surface id, …).",
    )
    block.add_argument(
        "--reason",
        required=True,
        help="Why the technique is blocked here (the wall: needs an account in group X, WAF, device binding, …).",
    )
    block.add_argument(
        "--technique-key",
        dest="technique_key",
        default="",
        help=(
            "Stable upsert key (UNIQUE per engagement). Omit to derive "
            "'<technique>:<target_kind>:<target_ref>' so re-recording the same "
            "block updates the row instead of duplicating it."
        ),
    )
    block.add_argument(
        "--retry-state",
        dest="retry_state",
        default="pending",
        choices=RETRY_STATES,
        help=(
            "Reviewed state: pending | no_retry | retryable | blocked | "
            "blocked_on_dependency | needs_authorization. Default: pending."
        ),
    )
    block.add_argument("--evidence-ref", dest="evidence_ref", default="", help="Optional engagement-relative evidence path.")
    block.add_argument(
        "--notes",
        default="",
        help=(
            "Short free-text cue (also surfaced in the resume brief). The DURABLE "
            "home for unblock requirements is the RELATED finding's "
            "details.unblock_requirements {kind, description, requested_from}, not "
            "this note — keep --notes to a one-line pointer."
        ),
    )
    block.add_argument("--source-name", dest="source_name", default="operator", help="Recording actor (stored in provenance).")
    block.add_argument("--provenance-inline", dest="provenance_inline", help="Inline JSON object merged into provenance.")
    block.add_argument(
        "--revalidation-context-inline",
        dest="revalidation_context_inline",
        help=(
            "JSON object describing this review (for example actor, basis, and "
            "dependencies checked); appended to retry-state history."
        ),
    )
    block.set_defaults(func=run_block)

    listing = subparsers.add_parser(
        "list-blocked-techniques",
        help="List recorded blocked techniques for this engagement.",
    )
    listing.add_argument("--json", dest="as_json", action="store_true", help="Emit raw JSON rows.")
    listing.add_argument(
        "--history",
        action="store_true",
        help="List append-only retry-state and revalidation history.",
    )
    listing.add_argument(
        "--technique-key",
        default="",
        help="With --history, limit audit rows to one stable technique key.",
    )
    listing.add_argument(
        "--limit",
        type=int,
        choices=range(1, 501),
        default=100,
        metavar="1..500",
        help="Maximum history rows (default: 100).",
    )
    listing.set_defaults(func=run_list)


_KEY_SANITIZE_RE = re.compile(r"[^a-z0-9]+")

# The backend caps ``BlockedTechniqueRecordRequest.technique_key`` at 256 chars
# while ``target_ref`` accepts up to 1024, so a full endpoint URL as target_ref
# would otherwise derive an over-long key and 422 the POST.
_MAX_TECHNIQUE_KEY_LEN = 256


def _derive_technique_key(technique: str, target_kind: str, target_ref: str) -> str:
    """Stable, deterministic upsert key from the three identity fields.

    Lower-cased and non-alphanumeric-collapsed so re-recording the same block
    (same technique on the same target) upserts instead of duplicating. Kept
    human-legible (``ssrf:host:api-example-com``) for `list-blocked-techniques`.

    A ``target_ref`` up to 1024 chars (e.g. a full endpoint URL) can push the
    key past the backend's 256-char ``technique_key`` limit and 422 the POST;
    see the bounding below.
    """
    parts = [technique, target_kind, target_ref]
    slugged = [
        _KEY_SANITIZE_RE.sub("-", str(part).strip().lower()).strip("-")
        for part in parts
    ]
    key = ":".join(part for part in slugged if part)
    if len(key) <= _MAX_TECHNIQUE_KEY_LEN:
        return key
    # Bound it: a 12-hex-char digest of the FULL key keeps distinct long refs
    # distinct (identical refs still collide → still upsert), appended to a
    # truncated readable prefix so the total never exceeds the 256-char cap.
    digest = hashlib.sha1(key.encode("utf-8"), usedforsecurity=False).hexdigest()[:12]
    suffix = f"-{digest}"
    prefix = key[: _MAX_TECHNIQUE_KEY_LEN - len(suffix)].rstrip("-")
    return f"{prefix}{suffix}"


def run_block(args) -> None:
    technique = normalize_technique(args.technique)
    if TECHNIQUE_ENUM and technique not in TECHNIQUE_ENUM:
        print(
            f"block-technique: --technique {args.technique!r} is not a valid technique. "
            f"Use one of: {', '.join(TECHNIQUE_ENUM)}",
            file=sys.stderr,
        )
        sys.exit(1)

    target_kind = str(args.target_kind).strip()
    target_ref = str(args.target_ref).strip()
    reason = str(args.reason).strip()
    if not target_kind or not target_ref or not reason:
        print(
            "block-technique requires non-empty --target-kind, --target-ref, and --reason",
            file=sys.stderr,
        )
        sys.exit(1)

    technique_key = str(args.technique_key).strip() or _derive_technique_key(
        technique, target_kind, target_ref
    )

    try:
        provenance = parse_optional_inline_json(
            getattr(args, "provenance_inline", None),
            default={},
            description="provenance JSON",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(provenance, dict):
        print("provenance JSON must be an object", file=sys.stderr)
        sys.exit(1)
    provenance.setdefault("source_name", args.source_name)
    try:
        revalidation_context = parse_optional_inline_json(
            getattr(args, "revalidation_context_inline", None),
            default={},
            description="revalidation context JSON",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(revalidation_context, dict):
        print("revalidation context JSON must be an object", file=sys.stderr)
        sys.exit(1)

    payload = {
        "technique_key": technique_key,
        "technique": technique,
        "target_kind": target_kind,
        "target_ref": target_ref,
        "reason": reason,
        "retry_state": str(args.retry_state).strip() or "pending",
        "evidence_ref": args.evidence_ref or "",
        "notes": args.notes or "",
        "provenance": provenance,
        "revalidation_context": revalidation_context,
    }

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        result = require_write_result(
            client.post("blocked-techniques", payload),
            operation="block technique",
            expected={
                "technique_key": technique_key,
                "technique": technique,
                "target_kind": target_kind,
                "target_ref": target_ref,
                "retry_state": payload["retry_state"],
            },
            positive_ids=("id",),
        )
    print(json.dumps(result, indent=2, ensure_ascii=False))


def run_list(args) -> None:
    cfg = load_config(args.engagement_dir)
    history = bool(getattr(args, "history", False))
    endpoint = "blocked-techniques"
    if history:
        params = {"limit": int(getattr(args, "limit", 100))}
        technique_key = str(getattr(args, "technique_key", "") or "").strip()
        if technique_key:
            params["technique_key"] = technique_key
        endpoint += "/history?" + urlencode(params)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        rows = client.get(endpoint)
    if not isinstance(rows, list):
        rows = []
    if getattr(args, "as_json", False):
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    if not rows:
        print("# Blocked Techniques\n\n- none")
        return
    lines = ["# Blocked Technique History" if history else "# Blocked Techniques", ""]
    for row in rows:
        if history:
            lines.append(
                f"- #{row.get('id')} {row.get('technique_key') or '-'} "
                f"[{row.get('event_kind') or '-'}] "
                f"{row.get('from_retry_state') or '-'} -> "
                f"{row.get('to_retry_state') or '-'}"
            )
            reason = str(row.get("reason") or "").replace("\n", " ").strip()
            if reason:
                lines.append(f"  - reason: {reason[:200]}")
            continue
        target = f"{row.get('target_kind') or '-'}:{row.get('target_ref') or '-'}"
        lines.append(
            f"- #{row.get('id')} {row.get('technique') or '-'} "
            f"[{row.get('retry_state') or '-'}] {target} "
            f"(key={row.get('technique_key') or '-'})"
        )
        reason = str(row.get("reason") or "").replace("\n", " ").strip()
        if reason:
            lines.append(f"  - reason: {reason[:200]}")
    print("\n".join(lines))
