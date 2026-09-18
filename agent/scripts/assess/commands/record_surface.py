"""vigil assess record-surface — POST surface + emit event."""
from __future__ import annotations

import os

from assess.lib.client import AssessmentClient, require_write_result
from assess.lib.config import load_config
from assess.lib.contracts import FRAMEWORK_REGISTRATION_KINDS
from assess.lib.surfaces import CREATABLE_STATUSES, VALID_SURFACE_TYPES


def register(subparsers) -> None:
    p = subparsers.add_parser("record-surface", help="Record a surface candidate")
    valid_types = ", ".join(sorted(VALID_SURFACE_TYPES))
    valid_statuses = ", ".join(sorted(CREATABLE_STATUSES))
    p.add_argument("type", help=f"Surface type ({valid_types})")
    p.add_argument("target", help="Target descriptor (URL or identifier)")
    p.add_argument("source", help="Source agent or process name")
    p.add_argument("--rationale", default="", help="Rationale for the surface")
    p.add_argument("--evidence-ref", default="", help="Evidence reference")
    p.add_argument("--status", default="discovered", help=f"Surface status ({valid_statuses})")
    p.add_argument(
        "--framework-registration",
        choices=tuple(FRAMEWORK_REGISTRATION_KINDS),
        default="",
        metavar="KIND",
        help=(
            "How the host framework registers this code, when it is a plugin or "
            "extension. Orthogonal to the positional surface type, which keeps "
            "carrying the security meaning. Run `vigil assess contract "
            "record-surface` for the worked per-framework mappings."
        ),
    )
    p.set_defaults(func=run)


def run(args) -> None:
    from assess.lib.surfaces import validate_surface_create_status, validate_surface_type
    validate_surface_type(args.type)
    validate_surface_create_status(args.status)

    cfg = load_config(args.engagement_dir)

    payload = {
        "surface_type": args.type,
        "target_descriptor": args.target,
        "source_name": args.source,
        "rationale": args.rationale,
        "evidence_ref": args.evidence_ref,
        "status": args.status,
    }
    # Omitted means "not a framework registration", and the backend upsert reads
    # an absent key as "leave whatever is recorded alone". Sending an empty value
    # would be indistinguishable but noisier on the wire, so only a real kind
    # travels.
    framework_registration = getattr(args, "framework_registration", "") or ""
    if framework_registration:
        payload["framework_registration"] = framework_registration

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        require_write_result(
            client.post("surfaces", payload),
            operation="record surface",
            expected={
                "surface_type": args.type,
                "target_descriptor": args.target,
                "status": args.status,
            },
            positive_ids=("id",),
        )

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": "surface.updated",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": args.type,
            "agent_name": args.source,
            "summary": f"{args.type} {args.status}: {args.target}",
        })

    print(f"Recorded surface: {args.type} {args.target}")
