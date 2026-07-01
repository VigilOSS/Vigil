"""vigil assess link-finding — root-cause/sibling finding grouping helper."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_optional_inline_json


# The backend rejects link_kind=root_cause on the generic /links route (it must
# go through PUT /root-cause). Mirror that guard client-side so the operator gets
# a pointed message instead of an opaque 400.
_ROOT_CAUSE_LINK_KIND = "root_cause"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "link-finding",
        help="Group findings by root cause, attach intel rows, record a generic typed link (incl. the unblock path), or clear the root-cause link",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("link-finding"),
    )
    p.add_argument("finding_slug", help="Finding slug the link is recorded on")
    p.add_argument("--root-cause", dest="root_cause_slug", help="Root-cause finding slug")
    p.add_argument("--order", dest="sibling_order", type=int, help="Display order within the root-cause group")
    p.add_argument(
        "--effect",
        dest="root_cause_effect",
        choices=["eliminates_finding", "eliminates_attack_path"],
        default="eliminates_finding",
        help="Whether fixing the root fully resolves the finding or only this attack path",
    )
    p.add_argument("--note", default="", help="One-sentence relationship note (root-cause and generic modes)")
    p.add_argument("--source-name", default="operator")
    p.add_argument("--provenance-inline", help="Inline JSON object merged into link provenance")
    p.add_argument("--clear-root-cause", action="store_true", help="Remove the root-cause link from this finding")
    p.add_argument(
        "--intel",
        dest="intel_ids",
        action="append",
        default=None,
        help=(
            "Intel row id to attach to this finding "
            "(`details.related_intel_ids[]`). May be specified multiple times. "
            "Merges with any existing related_intel_ids on the finding — "
            "duplicates are dropped, order is preserved."
        ),
    )
    # Generic typed-link mode (POST /findings/{slug}/links). The backend accepts
    # an arbitrary link_kind/target_kind; the key first-class use is the unblock
    # path — a blocked finding stays out of the report, but when a finding/chain
    # that satisfies the wall lands it is linked (e.g. --link-kind unblocked_by).
    p.add_argument(
        "--link-kind",
        dest="link_kind",
        default=None,
        help=(
            "Generic link kind, e.g. unblocked_by | related | depends_on | attempt. "
            "Selects generic mode (requires --target-kind). "
            f"'{_ROOT_CAUSE_LINK_KIND}' is refused here — use --root-cause."
        ),
    )
    p.add_argument(
        "--target-kind",
        dest="target_kind",
        default=None,
        help="Generic link target kind, e.g. finding | chain | surface | command_run | probe_run.",
    )
    p.add_argument("--target-id", dest="target_id", type=int, default=None, help="Generic link target id (int).")
    p.add_argument("--target-ref", dest="target_ref", default=None, help="Generic link target reference (e.g. a finding slug).")
    p.set_defaults(func=run)


def _link_intel(client, finding_slug: str, raw_intel_ids: list[str], note: str) -> dict:
    """Merge ``--intel`` values into ``details.related_intel_ids[]`` on the finding.

    Reads the existing finding to preserve any prior intel ids; PATCHes back
    with the union (dedupe-preserve-order). Intel ids are coerced to ints
    when they parse cleanly; otherwise kept as-is so callers can pass either
    int rows (the common case) or string keys (legacy intel sources).
    """
    cleaned: list[object] = []
    for raw in raw_intel_ids:
        if raw is None:
            continue
        text = str(raw).strip()
        if not text:
            continue
        try:
            cleaned.append(int(text))
        except ValueError:
            cleaned.append(text)
    if not cleaned:
        raise ValueError("link-finding --intel requires at least one non-empty id")

    existing = client.get(f"findings/{finding_slug}")
    if not isinstance(existing, dict):
        raise ValueError(f"link-finding --intel: finding {finding_slug} not found")
    details = existing.get("details") if isinstance(existing.get("details"), dict) else None
    if details is None:
        details = existing.get("details_json")
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except json.JSONDecodeError:
                details = {}
    if not isinstance(details, dict):
        details = {}
    prior_raw = details.get("related_intel_ids") if isinstance(details, dict) else None
    prior_list = list(prior_raw) if isinstance(prior_raw, list) else []

    merged: list[object] = []
    seen: set[str] = set()
    for value in [*prior_list, *cleaned]:
        key = json.dumps(value, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        merged.append(value)

    payload = {"details": {"related_intel_ids": merged}}
    if note:
        payload["reason_text"] = note
    return client.patch(f"findings/{finding_slug}", payload)


def run(args) -> None:
    intel_ids = list(args.intel_ids or [])
    # Generic typed-link mode is selected by --link-kind or --target-kind (or a
    # target id/ref). The four modes — root-cause / clear / intel / generic — are
    # mutually exclusive; each collision gets a pointed message.
    generic_selected = bool(
        getattr(args, "link_kind", None)
        or getattr(args, "target_kind", None)
        or getattr(args, "target_id", None) is not None
        or getattr(args, "target_ref", None) is not None
    )

    if args.clear_root_cause and args.root_cause_slug:
        print("link-finding: --clear-root-cause cannot be combined with --root-cause", file=sys.stderr)
        sys.exit(1)
    if args.clear_root_cause and intel_ids:
        print("link-finding: --clear-root-cause cannot be combined with --intel", file=sys.stderr)
        sys.exit(1)
    if args.root_cause_slug and intel_ids:
        print(
            "link-finding: --root-cause and --intel cannot be combined in a single call; "
            "run them as two separate invocations",
            file=sys.stderr,
        )
        sys.exit(1)
    if generic_selected and (args.root_cause_slug or args.clear_root_cause or intel_ids):
        print(
            "link-finding: generic link flags (--link-kind / --target-kind / --target-id / "
            "--target-ref) cannot be combined with --root-cause, --clear-root-cause, or --intel; "
            "run them as separate invocations",
            file=sys.stderr,
        )
        sys.exit(1)
    if (
        not args.clear_root_cause
        and not args.root_cause_slug
        and not intel_ids
        and not generic_selected
    ):
        print(
            "link-finding requires --root-cause <slug>, --intel <id> (one or more), "
            "--clear-root-cause, or a generic link (--link-kind + --target-kind + "
            "--target-id/--target-ref)",
            file=sys.stderr,
        )
        sys.exit(1)

    if generic_selected:
        target_kind = (getattr(args, "target_kind", None) or "").strip()
        target_id = getattr(args, "target_id", None)
        target_ref = (getattr(args, "target_ref", None) or "").strip()
        link_kind = (getattr(args, "link_kind", None) or "related").strip()
        if not target_kind:
            print(
                "link-finding: a generic link requires --target-kind (e.g. finding | chain | "
                "surface | command_run | probe_run)",
                file=sys.stderr,
            )
            sys.exit(1)
        if target_id is None and not target_ref:
            print(
                "link-finding: a generic link requires --target-id <int> or --target-ref <ref>",
                file=sys.stderr,
            )
            sys.exit(1)
        if link_kind == _ROOT_CAUSE_LINK_KIND:
            print(
                "link-finding: --link-kind root_cause is not allowed on the generic route; "
                "use --root-cause <root-slug>",
                file=sys.stderr,
            )
            sys.exit(1)

    try:
        provenance = parse_optional_inline_json(
            args.provenance_inline,
            default={},
            description="provenance JSON",
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
    if not isinstance(provenance, dict):
        print("provenance JSON must be an object", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        if intel_ids:
            try:
                result = _link_intel(client, args.finding_slug, intel_ids, args.note)
            except ValueError as exc:
                print(str(exc), file=sys.stderr)
                sys.exit(1)
        elif generic_selected:
            payload = {
                "link_kind": link_kind,
                "target_kind": target_kind,
                "target_id": target_id,
                "target_ref": target_ref,
                "notes": args.note,
                "provenance": provenance,
            }
            result = client.post(f"findings/{args.finding_slug}/links", payload)
        elif args.clear_root_cause:
            result = client.delete(f"findings/{args.finding_slug}/root-cause")
        else:
            payload = {
                "root_cause_slug": args.root_cause_slug,
                "sibling_order": args.sibling_order,
                "root_cause_effect": args.root_cause_effect,
                "note": args.note,
                "source_name": args.source_name,
                "provenance": provenance,
            }
            result = client.put(f"findings/{args.finding_slug}/root-cause", payload)

    print(json.dumps(result, indent=2, ensure_ascii=False))
