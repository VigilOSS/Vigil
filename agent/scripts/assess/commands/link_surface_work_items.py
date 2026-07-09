"""vigil assess link-surface-work-items — link backend surfaces to the request
variants behind local work_items.

Selects work items from the backend work buffer (by cluster or explicit
queue_key) and, for each, links the durable backend ``request_variant_id`` to
one or more surfaces. A work_item that was never successfully posted to the
backend has a NULL ``request_variant_id`` (the backend has no record of it) and
is skipped with a warning rather than failing the whole command.
"""
from __future__ import annotations

import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.surface_links import create_surface_request_variant_link


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "link-surface-work-items",
        help="Link backend surfaces to the request variants behind local work_items",
    )
    p.add_argument(
        "--cluster",
        action="append",
        default=[],
        metavar="CLUSTER_KEY",
        help="Select work_items by cluster_key (repeatable)",
    )
    p.add_argument(
        "--queue-key",
        action="append",
        default=[],
        metavar="QUEUE_KEY",
        help="Select work_items by exact queue_key (repeatable)",
    )
    p.add_argument(
        "--surface-id",
        action="append",
        default=[],
        metavar="SURFACE_ID",
        help="Backend surface id to link (repeatable or comma-separated)",
    )
    p.add_argument("--relation", default="", help="Free-text relation label, e.g. primary-endpoint")
    p.add_argument("--evidence-ref", default="", help="Evidence reference for the link")
    p.set_defaults(func=run)


def _parse_surface_ids(raw_values: list[str]) -> list[int]:
    surface_ids: list[int] = []
    for raw in raw_values:
        for token in str(raw).split(","):
            token = token.strip()
            if not token:
                continue
            try:
                surface_id = int(token)
            except ValueError:
                print(f"ERROR: invalid --surface-id '{token}' (must be an integer)", file=sys.stderr)
                sys.exit(1)
            if surface_id not in surface_ids:
                surface_ids.append(surface_id)
    return surface_ids


def run(args) -> None:
    surface_ids = _parse_surface_ids(args.surface_id)
    if not surface_ids:
        print("ERROR: at least one --surface-id is required", file=sys.stderr)
        sys.exit(1)
    if not args.cluster and not args.queue_key:
        print("ERROR: select work_items with --cluster and/or --queue-key", file=sys.stderr)
        sys.exit(1)

    # Select the target rows by cluster_key / queue_key in Python, mirroring the
    # former SQL `WHERE cluster_key IN (...) OR queue_key IN (...)`.
    cluster_filter = set(args.cluster)
    queue_key_filter = set(args.queue_key)

    cfg = load_config(args.engagement_dir)
    created = 0
    skipped_no_variant = 0
    failed = 0
    linked_variants: set[int] = set()

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        # Read the whole buffer (all statuses; get_all_pages preserves the
        # backend's ORDER BY id) and filter to the requested selectors.
        rows = [
            row for row in client.get_all_pages("work-items")
            if row.get("cluster_key") in cluster_filter
            or row.get("queue_key") in queue_key_filter
        ]

        if not rows:
            print("link-surface-work-items: no matching work_items found", file=sys.stderr)
            return

        for row in rows:
            request_variant_id = row.get("request_variant_id")
            if not request_variant_id:
                skipped_no_variant += 1
                print(
                    f"link-surface-work-items: work_item {row.get('queue_key')!r} "
                    f"({row.get('url')}) has no request_variant_id (never posted to the "
                    "backend); skipping",
                    file=sys.stderr,
                )
                continue
            request_variant_id = int(request_variant_id)
            if request_variant_id in linked_variants:
                continue
            linked_variants.add(request_variant_id)
            for surface_id in surface_ids:
                try:
                    create_surface_request_variant_link(
                        client,
                        surface_id=surface_id,
                        request_variant_id=request_variant_id,
                        relation=args.relation,
                        evidence_ref=args.evidence_ref,
                    )
                    created += 1
                except Exception as exc:  # noqa: BLE001 - one bad link must not drop the rest
                    failed += 1
                    print(
                        f"link-surface-work-items: failed to link surface {surface_id} to "
                        f"request_variant {request_variant_id}: {exc}; skipping this link",
                        file=sys.stderr,
                    )

    print(
        f"[link] Created {created} surface link(s) across {len(linked_variants)} "
        f"request variant(s); skipped {skipped_no_variant} work_item(s) with no "
        f"request_variant_id; {failed} link(s) failed."
    )
