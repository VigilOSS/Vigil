"""vigil assess finding link — root-cause/sibling finding grouping helper."""
from __future__ import annotations

import argparse
import json
import sys

from assess.lib.client import (
    AssessmentClient,
    require_finding_write_response,
    require_write_result,
)
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog
from assess.lib.json_inputs import parse_optional_inline_json


# The backend rejects link_kind=root_cause on the generic /links route (it must
# go through PUT /root-cause). Mirror that guard client-side so the operator gets
# a pointed message instead of an opaque 400.
_ROOT_CAUSE_LINK_KIND = "root_cause"


class _RemovedNoteAction(argparse.Action):
    """Point old callers at the one canonical explanation flag."""

    def __call__(self, parser, namespace, values, option_string=None) -> None:
        parser.error(
            "finding link: --note was removed; use --reason "
            "\"<one-sentence relationship rationale>\""
        )


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "link",
        help="Group findings by root cause, attach intel rows, record a generic typed link (incl. the unblock path), or clear the root-cause link",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("finding link"),
    )
    p.add_argument(
        "finding_slug",
        nargs="+",
        help="One or more finding slugs the link is recorded on. Batch: attach many siblings to "
             "one --root-cause (or apply the same --intel / generic / --clear-root-cause op to "
             "each) in a resilient loop with a per-slug failure tally.",
    )
    p.add_argument("--root-cause", dest="root_cause_slug", help="Root-cause finding slug")
    p.add_argument("--order", dest="sibling_order", type=int, help="Display order within the root-cause group")
    p.add_argument(
        "--effect",
        dest="root_cause_effect",
        choices=["eliminates_finding", "eliminates_attack_path"],
        default="eliminates_finding",
        help="Whether fixing the root fully resolves the finding or only this attack path",
    )
    p.add_argument(
        "--reason",
        dest="reason_text",
        default=None,
        help="One-sentence relationship rationale (root-cause, intel, and generic modes)",
    )
    p.add_argument(
        "--note",
        action=_RemovedNoteAction,
        help=argparse.SUPPRESS,
    )
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
            "Generic link kind, e.g. unblocks | unblocked_by | related | depends_on | attempt. "
            "Selects generic mode (requires --target-kind). "
            f"'{_ROOT_CAUSE_LINK_KIND}' is refused here — use --root-cause."
        ),
    )
    p.add_argument(
        "--target-kind",
        dest="target_kind",
        default=None,
        help=(
            "Generic link target kind, e.g. finding | blocked_technique | chain | surface | "
            "command_run | probe_run. Use blocked_technique (with --target-ref <technique_key>) "
            "to record that this finding unblocks a walled-off technique."
        ),
    )
    p.add_argument("--target-id", dest="target_id", type=int, default=None, help="Generic link target id (int).")
    p.add_argument("--target-ref", dest="target_ref", default=None, help="Generic link target reference (e.g. a finding slug).")
    p.add_argument(
        "--link-id",
        dest="link_id",
        type=int,
        default=None,
        help="Update or retire this existing generic link in place.",
    )
    retirement = p.add_mutually_exclusive_group()
    retirement.add_argument(
        "--retire",
        action="store_true",
        help="Retire --link-id without deleting its evidence row.",
    )
    retirement.add_argument(
        "--reactivate",
        action="store_true",
        help="Reactivate a retired --link-id.",
    )
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
        raise ValueError("finding link --intel requires at least one non-empty id")

    existing = client.get(f"findings/{finding_slug}")
    if not isinstance(existing, dict):
        raise ValueError(f"finding link --intel: finding {finding_slug} not found")
    details = existing.get("details") if isinstance(existing.get("details"), dict) else None
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
    return require_finding_write_response(
        client.patch(f"findings/{finding_slug}", payload),
        finding_slug=finding_slug,
        operation="link finding intel",
    )


def _require_generic_link_result(
    response: dict,
    *,
    finding_slug: str,
    payload: dict,
) -> dict:
    expected = {
        "link_kind": payload["link_kind"],
        "target_kind": payload["target_kind"],
    }
    if payload.get("target_ref"):
        expected["target_ref"] = payload["target_ref"]
    elif payload.get("target_id") is not None:
        expected["target_id"] = payload["target_id"]
    return require_write_result(
        response,
        operation=f"link finding {finding_slug}",
        expected=expected,
        positive_ids=("id",),
    )


def run(args) -> None:
    intel_ids = list(args.intel_ids or [])
    link_update_selected = getattr(args, "link_id", None) is not None
    # Generic typed-link mode is selected by --link-kind or --target-kind (or a
    # target id/ref). The four modes — root-cause / clear / intel / generic — are
    # mutually exclusive; each collision gets a pointed message.
    generic_selected = not link_update_selected and bool(
        getattr(args, "link_kind", None)
        or getattr(args, "target_kind", None)
        or getattr(args, "target_id", None) is not None
        or getattr(args, "target_ref", None) is not None
    )

    if args.clear_root_cause and args.root_cause_slug:
        print("finding link: --clear-root-cause cannot be combined with --root-cause", file=sys.stderr)
        sys.exit(1)
    if args.clear_root_cause and intel_ids:
        print("finding link: --clear-root-cause cannot be combined with --intel", file=sys.stderr)
        sys.exit(1)
    if args.root_cause_slug and intel_ids:
        print(
            "finding link: --root-cause and --intel cannot be combined in a single call; "
            "run them as two separate invocations",
            file=sys.stderr,
        )
        sys.exit(1)
    if (generic_selected or link_update_selected) and (
        args.root_cause_slug or args.clear_root_cause or intel_ids
    ):
        print(
            "finding link: generic link flags (--link-kind / --target-kind / --target-id / "
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
        and not link_update_selected
    ):
        print(
            "finding link requires --root-cause <slug>, --intel <id> (one or more), "
            "--clear-root-cause, or a generic link (--link-kind + --target-kind + "
            "--target-id/--target-ref)",
            file=sys.stderr,
        )
        sys.exit(1)

    if link_update_selected and len(args.finding_slug) != 1:
        print(
            "finding link: --link-id updates exactly one finding at a time",
            file=sys.stderr,
        )
        sys.exit(1)
    if (
        getattr(args, "retire", False) or getattr(args, "reactivate", False)
    ) and not link_update_selected:
        print(
            "finding link: --retire/--reactivate requires --link-id",
            file=sys.stderr,
        )
        sys.exit(1)
    if (
        getattr(args, "target_id", None) is not None
        and getattr(args, "target_ref", None) is not None
    ):
        print(
            "finding link: provide only one of --target-id or --target-ref",
            file=sys.stderr,
        )
        sys.exit(1)
    if (
        link_update_selected
        and getattr(args, "target_kind", None) is not None
        and getattr(args, "target_id", None) is None
        and getattr(args, "target_ref", None) is None
    ):
        print(
            "finding link: changing --target-kind requires --target-id or --target-ref",
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
                "finding link: a generic link requires --target-kind (e.g. finding | chain | "
                "surface | command_run | probe_run)",
                file=sys.stderr,
            )
            sys.exit(1)
        if target_id is None and not target_ref:
            print(
                "finding link: a generic link requires --target-id <int> or --target-ref <ref>",
                file=sys.stderr,
            )
            sys.exit(1)
        if link_kind == _ROOT_CAUSE_LINK_KIND:
            print(
                "finding link: --link-kind root_cause is not allowed on the generic route; "
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

    # The selected mode's payload does not depend on the slug, so build it once and
    # apply it to every listed slug. Batch = link many siblings to one --root-cause
    # (or the same --intel / generic / --clear-root-cause op across siblings).
    generic_payload = {
        "link_kind": link_kind,
        "target_kind": target_kind,
        "target_id": target_id,
        "target_ref": target_ref,
        "notes": args.reason_text or "",
        "provenance": provenance,
    } if generic_selected else None
    root_cause_payload = {
        "root_cause_slug": args.root_cause_slug,
        "sibling_order": args.sibling_order,
        "root_cause_effect": args.root_cause_effect,
        "note": args.reason_text or "",
        "source_name": args.source_name,
        "provenance": provenance,
    }
    link_update_payload: dict[str, object] = {}
    if link_update_selected:
        if args.target_kind is not None:
            link_update_payload["target_kind"] = args.target_kind
        if args.target_id is not None:
            link_update_payload["target_id"] = args.target_id
        if args.target_ref is not None:
            link_update_payload["target_ref"] = args.target_ref
        if args.reason_text is not None:
            link_update_payload["notes"] = args.reason_text
        if args.provenance_inline is not None:
            link_update_payload["provenance"] = provenance
        if getattr(args, "retire", False):
            link_update_payload["retired"] = True
        elif getattr(args, "reactivate", False):
            link_update_payload["retired"] = False
        if not link_update_payload:
            print(
                "finding link: --link-id requires a field correction, --retire, "
                "or --reactivate",
                file=sys.stderr,
            )
            sys.exit(1)

    slugs = args.finding_slug if isinstance(args.finding_slug, list) else [args.finding_slug]
    cfg = load_config(args.engagement_dir)
    results: list = []
    failed = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        for slug in slugs:
            try:
                if intel_ids:
                    result = _link_intel(
                        client,
                        slug,
                        intel_ids,
                        args.reason_text or "",
                    )
                elif link_update_selected:
                    result = require_write_result(
                        client.patch(
                            f"findings/{slug}/links/{args.link_id}",
                            link_update_payload,
                        ),
                        operation=f"update finding link {args.link_id}",
                        expected={"id": args.link_id, "finding_slug": slug},
                    )
                elif generic_selected:
                    result = _require_generic_link_result(
                        client.post(f"findings/{slug}/links", generic_payload),
                        finding_slug=slug,
                        payload=generic_payload,
                    )
                elif args.clear_root_cause:
                    result = require_write_result(
                        client.delete(f"findings/{slug}/root-cause"),
                        operation=f"clear root cause for {slug}",
                        expected={"finding_slug": slug},
                        nonnegative_counts=("cleared",),
                    )
                else:
                    result = require_write_result(
                        client.put(f"findings/{slug}/root-cause", root_cause_payload),
                        operation=f"set root cause for {slug}",
                        expected={
                            "finding_slug": slug,
                            "root_cause_slug": root_cause_payload["root_cause_slug"],
                        },
                        positive_ids=("id",),
                    )
            except Exception as exc:  # noqa: BLE001 - one bad sibling must not drop the rest
                failed += 1
                print(f"finding link: {slug} failed: {exc}", file=sys.stderr)
                continue
            results.append(result)

    if len(slugs) == 1 and results:
        print(json.dumps(results[0], indent=2, ensure_ascii=False))
    else:
        for result in results:
            print(json.dumps(result, ensure_ascii=False))
        print(
            f"[finding link] linked {len(results)} finding(s); {failed} failed.",
            file=sys.stderr,
        )
    if failed:
        sys.exit(1)
