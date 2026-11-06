"""The RAW dispatch route's ``finding_slugs`` write semantics, pinned.

The contract's helper-default line read "appended additively to the row, not
replaced" while ``PATCH /dispatches/{agent_id}`` overwrote ``finding_slugs_json``
wholesale and ``agent done`` passed its CSV straight through. So an operator
following the contract to ADD one slug silently deleted every other slug the
dispatch had produced — and the dispatch row is what links a dispatch to the
findings it generated.

The fix is not a corrected sentence (one can drift again) but a named semantic:
``contract_registry.DISPATCH_FINDING_SLUGS_WRITE`` records what the ROUTE does,
and this file pins that value against the live API by PATCHing the route
directly — no CLI in the path. Flip the constant if the backend ever starts
merging.

The merge an operator sees is client-side: ``agent done`` and ``agent close``
read the dispatch row and PATCH the union, so the verb adds while the route
still replaces. Both halves are rendered into one helper-default line, and the
second test pins that the line states each of them — a caller who bypasses the
verbs inherits the raw semantics and has to send the complete set.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_SCRIPTS_ROOT = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from assess.lib import contract_registry, contracts  # noqa: E402


ENGAGEMENT_KEY = "2026-07-20-120000-dispatch-slug-writes"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"
AGENT_ID = "acme-done-1"


def _seed(client, engagements_dir: Path) -> None:
    engagement_dir = engagements_dir / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "engagement.json").write_text(
        json.dumps(
            {
                "key": ENGAGEMENT_KEY,
                "target": "https://app.acme.example",
                "hostname": "app.acme.example",
                "created_at": "2026-07-20T12:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "app.acme.example",
                "hosts": ["app.acme.example"],
                "status": "in_progress",
                "current_phase": "consume-test",
            }
        ),
        encoding="utf-8",
    )
    (engagement_dir / "sessions" / "index.json").write_text("[]", encoding="utf-8")
    assert client.get("/engagements").status_code == 200


def _create_finding(client, slug: str) -> None:
    response = client.post(
        f"{BASE}/findings",
        json={
            "slug": slug,
            "title": f"Finding {slug}",
            "severity": "low",
            "workflow_status": "active",
            "verification_status": "unreviewed",
            "defect_family": "idor",
            "auth_context": "anonymous",
            "canonical_location": f"https://app.acme.example/{slug.lower()}",
            "summary": f"Summary for {slug}",
            "evidence_ref": f"evidence/{slug.lower()}.json",
            "source_name": AGENT_ID,
            "details": {"evidence": "proof", "impact": "impact"},
            "provenance": {"agent_name": AGENT_ID, "agent_id": AGENT_ID},
            "links": [],
        },
    )
    assert response.status_code == 201, response.text


def test_the_raw_dispatch_patch_route_writes_as_the_constant_says(
    client, isolate_settings
) -> None:
    _seed(client, isolate_settings["engagements_dir"])
    created = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": AGENT_ID,
            "agent_role": "vulnerability-analyst",
            "task": "Exercise the Acme billing surface.",
        },
    )
    assert created.status_code == 201, created.text
    _create_finding(client, "VA-001")
    _create_finding(client, "VA-002")

    first = client.patch(f"{BASE}/dispatches/{AGENT_ID}", json={"finding_slugs": ["VA-001"]})
    assert first.status_code == 200, first.text
    assert first.json()["finding_slugs"] == ["VA-001"]

    # A caller bypassing `agent done` "adds" one slug by PATCHing the route.
    second = client.patch(f"{BASE}/dispatches/{AGENT_ID}", json={"finding_slugs": ["VA-002"]})
    assert second.status_code == 200, second.text
    stored = set(client.get(f"{BASE}/dispatches/{AGENT_ID}").json()["finding_slugs"])

    observed = "union" if stored == {"VA-001", "VA-002"} else "replace"
    assert stored in ({"VA-001", "VA-002"}, {"VA-002"}), stored
    assert contract_registry.DISPATCH_FINDING_SLUGS_WRITE == observed, (
        "PATCH /dispatches/{agent_id} now "
        f"{'merges' if observed == 'union' else 'overwrites'} finding_slugs; set "
        "contract_registry.DISPATCH_FINDING_SLUGS_WRITE to "
        f"{observed!r} so the --finding-slugs contract line stops describing the "
        "other raw behaviour"
    )


def test_the_agent_done_contract_renders_the_pinned_semantics() -> None:
    helper = dict(contracts.get_contract("agent done").helper_defaults)

    assert helper["--finding-slugs"] == contract_registry.dispatch_finding_slugs_help()
    assert "--finding-slugs = " in contracts.render_contract("agent done")


def test_the_contract_line_states_the_cli_union_and_the_raw_replace() -> None:
    """The verb merges, the route does not. An operator reading only half of
    that either re-sends a whole list the CLI would have built, or bypasses the
    verb and drops the slugs the dispatch already had."""
    line = contract_registry.dispatch_finding_slugs_help()

    assert "unioned" in line, line
    assert "reads the dispatch row" in line, (
        "the line must say the CLI does the merge, so the operator passes only "
        f"the new slugs: {line}"
    )
    if contract_registry.DISPATCH_FINDING_SLUGS_WRITE == "replace":
        assert "PATCH /dispatches/{agent_id}" in line, (
            f"the raw-route caveat has to name the route it applies to: {line}"
        )
        assert "complete set" in line, line


def test_the_contract_line_names_the_role_whose_scope_cannot_be_patched() -> None:
    """One role's dispatch slug list is immutable, and the CLI's union does not
    exempt it: `agent done --finding-slugs` on a code-variant-hunter 409s even
    when the union equals the stored set, because the route refuses ANY
    finding_slugs on that role. A line promising "passing one slug adds it" has
    to name the dispatch where that is not true.
    """
    from app.services.state_manager.dispatches import VARIANT_DISPATCH_ROLE

    line = contract_registry.dispatch_finding_slugs_help()

    assert VARIANT_DISPATCH_ROLE in line, (
        f"{VARIANT_DISPATCH_ROLE} is the role the backend refuses the write for: {line}"
    )
    assert "409" in line, line
    assert "handoff" in line, (
        "the operator needs the alternative, not only the refusal"
    )
