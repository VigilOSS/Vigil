"""vigil assess chain list — recorded attack chains with their finding steps."""
from __future__ import annotations

import json

from assess.lib.client import AssessmentClient, AssessError
from assess.lib.config import load_config
from assess.lib.contracts import FINDING_SEVERITIES
from assess.lib.finding_render import warn_untrusted_data

# The verdicts that make a finding a verified step: the backend's
# CLAIM_REVIEW_VERIFICATION_STATUSES, the same pair every report gate admits.
_VERIFIED_STATUSES = frozenset({"confirmed", "downgraded"})
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(FINDING_SEVERITIES)}
# The finding ledger's list projection: the step fields below, without each
# finding's details, notes or evidence.
_FINDING_LIST_ROUTE = "findings?view=list"
_CHAIN_FIELDS = (
    "id", "chain_key", "title", "status", "severity", "narrative",
    "evidence_ref", "created_at", "updated_at",
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "list",
        help="List recorded attack chains, their finding steps, and how many steps are verified",
    )
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON.")
    p.set_defaults(func=run)


def _require_rows(result: object, route: str) -> list[dict]:
    if not isinstance(result, list) or any(not isinstance(row, dict) for row in result):
        raise AssessError(f"chain list: {route} did not return a JSON array of objects")
    return result


def _step(link: dict, findings_by_slug: dict, findings_by_id: dict) -> dict:
    finding = None
    ref = str(link.get("entity_ref") or "")
    if ref:
        finding = findings_by_slug.get(ref)
    elif link.get("entity_id") is not None:
        finding = findings_by_id.get(link.get("entity_id"))
    step = {
        "link_id": link.get("id"),
        "relation": str(link.get("relation") or ""),
        "slug": str(finding.get("slug")) if finding else ref,
        "entity_id": link.get("entity_id"),
        "found": finding is not None,
        "severity": finding.get("severity") if finding else None,
        "verification_status": finding.get("verification_status") if finding else None,
        "workflow_status": finding.get("workflow_status") if finding else None,
        "title": finding.get("title") if finding else None,
        "notes": str(link.get("notes") or ""),
    }
    step["verified"] = step["verification_status"] in _VERIFIED_STATUSES
    return step


def build_chain_rows(
    chains: list[dict], links: list[dict], findings: list[dict]
) -> list[dict]:
    """Compose each chain with its links in recorded (step) order.

    The schema has no step-order column, so a chain's link ids, ascending, are
    the order its steps were recorded in. Finding steps resolve by slug, or by
    id when the link carries only an id.
    """
    findings_by_slug = {str(row.get("slug")): row for row in findings}
    findings_by_id = {row.get("id"): row for row in findings}
    links_by_chain: dict[object, list[dict]] = {}
    for link in sorted(links, key=lambda row: int(row.get("id") or 0)):
        links_by_chain.setdefault(link.get("chain_id"), []).append(link)
    rows: list[dict] = []
    for chain in chains:
        chain_links = links_by_chain.get(chain.get("id"), [])
        steps = [
            _step(link, findings_by_slug, findings_by_id)
            for link in chain_links
            if link.get("entity_kind") == "finding"
        ]
        verified = sum(1 for step in steps if step["verified"])
        rows.append({
            **{key: chain.get(key) for key in _CHAIN_FIELDS},
            "steps": steps,
            "other_links": [
                {
                    "link_id": link.get("id"),
                    "relation": str(link.get("relation") or ""),
                    "entity_kind": str(link.get("entity_kind") or ""),
                    "entity_id": link.get("entity_id"),
                    "entity_ref": str(link.get("entity_ref") or ""),
                    "notes": str(link.get("notes") or ""),
                }
                for link in chain_links
                if link.get("entity_kind") != "finding"
            ],
            "finding_step_count": len(steps),
            "verified_finding_step_count": verified,
            "all_finding_steps_verified": bool(steps) and verified == len(steps),
        })
    rows.sort(
        key=lambda row: (
            -_SEVERITY_RANK.get(str(row.get("severity") or ""), -1),
            str(row.get("chain_key") or ""),
        )
    )
    return rows


def _print_table(rows: list[dict]) -> None:
    if not rows:
        print("No attack chains recorded.")
        return
    for row in rows:
        print(
            f"{row['chain_key']} | {row['severity']} | {row['status']} | "
            f"{row['verified_finding_step_count']}/{row['finding_step_count']} "
            f"finding steps verified | {row['title']}"
        )
        for index, step in enumerate(row["steps"], start=1):
            label = step["slug"] or f"finding #{step['entity_id']}"
            state = step["verification_status"] if step["found"] else "not found"
            severity = step["severity"] if step["found"] else "?"
            print(f"  {index}. {label} [{severity}] {state} ({step['relation']})")
        for link in row["other_links"]:
            target = link["entity_ref"] or f"#{link['entity_id']}"
            print(f"  - {link['entity_kind']} {target} ({link['relation']})")
    print(
        "This table leaves out each chain's narrative, evidence_ref and timestamps and "
        "each step's title and link notes; `vigil assess chain list --json` prints them."
    )


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        chains = _require_rows(client.get("attack-chains"), "attack-chains")
        links = (
            _require_rows(client.get("attack-chain-links"), "attack-chain-links")
            if chains
            else []
        )
        findings = (
            _require_rows(client.get_all_pages(_FINDING_LIST_ROUTE), "findings")
            if any(link.get("entity_kind") == "finding" for link in links)
            else []
        )
    rows = build_chain_rows(chains, links, findings)
    if rows:
        warn_untrusted_data()
    if args.as_json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return
    _print_table(rows)
