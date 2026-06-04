"""vigil assess check-intel-readiness — advisory view of un-dispositioned intel.

NON-gating by design: it surfaces open PoC-backed high CVEs, open leads,
exploited CVEs with no linked finding, and dangling linked_finding_slug
references so they are not silently abandoned. Red engagements only — blue/IR
engagements do not pursue CVE exploitation and are reported as not applicable.

Default exit is 0 (advisory). Pass --strict to exit 1 when any open item is
present (opt-in, for operators who want a CI-style gate).
"""
from __future__ import annotations

import sys

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "check-intel-readiness",
        help="Advisory (non-gating): open CVEs/leads + dangling finding links (red engagements).",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any open item is present (default: advisory, exit 0).",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        data = client.get_engagement("intel/readiness")

    if not isinstance(data, dict):
        print("check-intel-readiness: unexpected response from backend", file=sys.stderr)
        sys.exit(1)

    if not data.get("applicable", True):
        print(
            f"intel readiness: not applicable for engagement_type="
            f"{data.get('engagement_type', 'unknown')!r} (red engagements only)."
        )
        return

    open_high = data.get("open_high_cves") or []
    open_leads = data.get("open_leads") or []
    exploited_unlinked = data.get("exploited_unlinked_cves") or []
    dangling = data.get("dangling_links") or []
    total = len(open_high) + len(open_leads) + len(exploited_unlinked) + len(dangling)

    if total == 0:
        print("intel readiness: ok — no open CVEs, leads, or dangling links")
        return

    print(f"Open intel needing a disposition ({total}):")
    if open_high:
        print(f"- open PoC-backed high CVEs ({len(open_high)}):")
        for row in open_high:
            print(
                f"  - id={row.get('id')} {row.get('cve_id')} cvss {row.get('cvss_score')} "
                f"[{row.get('validation_status')}] {row.get('affected_component') or ''}".rstrip()
            )
    if exploited_unlinked:
        print(f"- exploited CVEs with no linked finding ({len(exploited_unlinked)}):")
        for row in exploited_unlinked:
            print(f"  - id={row.get('id')} {row.get('cve_id')} {row.get('affected_component') or ''}".rstrip())
    if dangling:
        print(f"- dangling linked_finding_slug references ({len(dangling)}):")
        for row in dangling:
            print(
                f"  - id={row.get('id')} {row.get('cve_id')} → {row.get('linked_finding_slug')} "
                f"({row.get('reason')}: {row.get('workflow_status') or 'no such finding'})"
            )
    if open_leads:
        print(f"- open leads ({len(open_leads)}):")
        for row in open_leads:
            print(f"  - id={row.get('id')} [{row.get('lead_status')}] {row.get('title')}")
    print(
        "\nDisposition by id: "
        "`vigil assess update-intel cve <id> --inline '{\"validation_status\": \"ruled_out\"}'` "
        "or `update-intel note <id> --inline '{\"lead_status\": \"resolved\"}'`."
    )

    if args.strict:
        sys.exit(1)
