from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.services import credentials
from app.services import state_manager
from tests.test_app_units import _seed


def _variant(
    engagement_id: int,
    *,
    auth: str,
    method: str = "POST",
    url: str = "https://app.example/api/transfer",
    header_schema: dict[str, str] | None = None,
) -> dict:
    result = state_manager.ingest_request_observation(
        engagement_id,
        url=url,
        method=method,
        auth_context=auth,
        content_type_family="json",
        query_schema={},
        body_schema={"amount": "number"},
        path_schema={},
        cookie_schema={},
        header_schema=header_schema or {
            "X-Tenant-Id": "secret-value-must-not-persist",
            "X-Trace-Id": "volatile-trace",
        },
        path_template="",
        discovery_source="proxy",
        notes="",
        response_status=200,
        evidence_ref="scans/flow.json",
        observation_payload={},
        target_identity=None,
        target_kind="host",
        target_notes="",
        target_ip_address=None,
        target_hostname=None,
        banner="",
        coverage_candidates=None,
        auto_generate_coverage=True,
        work_item=None,
    )
    return result["request_variant"]


def test_observed_trust_header_materializes_name_only_obligation(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100000-headers")
    variant = _variant(engagement_id, auth="alice")
    rows = [
        row
        for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == variant["id"]
    ]
    slots = {row["input_slot"] for row in rows}
    assert "header:x-tenant-id" in slots
    assert "header:x-trace-id" not in slots
    obligation = next(row for row in rows if row["input_slot"] == "header:x-tenant-id")
    assert obligation["attack_family"] == "identity-header-review"
    assert "secret-value" not in obligation["notes"]
    assert "volatile-trace" not in obligation["notes"]


def test_identity_header_covered_requires_two_principals_on_write_leg(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100001-header-gate")
    alice = _variant(engagement_id, auth="alice")
    bob = _variant(engagement_id, auth="bob")
    for identity_name in ("alice", "bob"):
        credentials.upsert_material(
            engagement_id,
            identity_name,
            {
                "principal_id": f"principal-{identity_name}",
                "cookies": {"sid": identity_name},
            },
        )
    items = state_manager.list_coverage_items(engagement_id)
    alice_item = next(
        row for row in items
        if row["request_variant_id"] == alice["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )

    def probe(variant, auth):
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=variant["id"],
            service_id=None,
            coverage_item_id=None,
            auth_context=auth,
            input_slot="header:x-tenant-id",
            attack_family="identity-header-review",
            payload_family="cross-principal",
            payload_value=auth,
            tool_name="browser",
            agent_name="vulnerability-analyst",
            result_status="tested",
            observed_http_status=403,
            signal_type="",
            evidence_ref=f"scans/{auth}.json",
            notes="write request tested",
        )

    probe(alice, "alice")
    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=alice_item["id"],
            status_value="covered",
            notes="alice write leg complete",
        )
    assert exc.value.status_code == 409
    assert "two distinct principals" in str(exc.value.detail)

    probe(bob, "bob")
    covered = state_manager.update_coverage_item_status(
        engagement_id,
        coverage_item_id=alice_item["id"],
        status_value="covered",
        notes="two-principal write-leg evidence complete",
    )
    assert covered["status"] == "covered"


def test_identity_aliases_for_one_principal_do_not_satisfy_two_principal_gate(
    client, isolate_settings
):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100001-header-alias-gate")
    alice_web = _variant(engagement_id, auth="alice-web")
    alice_mobile = _variant(engagement_id, auth="alice-mobile")
    for identity_name in ("alice-web", "alice-mobile"):
        credentials.upsert_material(
            engagement_id,
            identity_name,
            {
                "principal_id": "principal-alice",
                "cookies": {"sid": identity_name},
            },
        )
    item = next(
        row
        for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == alice_web["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )
    for variant, auth in ((alice_web, "alice-web"), (alice_mobile, "alice-mobile")):
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=variant["id"],
            service_id=None,
            coverage_item_id=None,
            auth_context=auth,
            input_slot="header:x-tenant-id",
            attack_family="identity-header-review",
            payload_family="cross-principal",
            payload_value=auth,
            tool_name="browser",
            agent_name="vulnerability-analyst",
            result_status="tested",
            observed_http_status=403,
            signal_type="",
            evidence_ref=f"scans/{auth}.json",
            notes="write request tested",
        )

    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=item["id"],
            status_value="covered",
            notes="two aliases are not two principals",
        )
    assert exc.value.status_code == 409
    assert "two distinct principals" in str(exc.value.detail)


def test_unanchored_auth_context_labels_do_not_satisfy_two_principal_gate(
    client, isolate_settings
):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100001-header-label-gate")
    first = _variant(engagement_id, auth="fake-one")
    second = _variant(engagement_id, auth="fake-two")
    item = next(
        row
        for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == first["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )
    for variant, auth in ((first, "fake-one"), (second, "fake-two")):
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=variant["id"],
            service_id=None,
            coverage_item_id=None,
            auth_context=auth,
            input_slot="header:x-tenant-id",
            attack_family="identity-header-review",
            payload_family="cross-principal",
            payload_value=auth,
            tool_name="browser",
            agent_name="vulnerability-analyst",
            result_status="tested",
            observed_http_status=403,
            signal_type="",
            evidence_ref=f"scans/{auth}.json",
            notes="free-form label is not a durable principal",
        )

    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=item["id"],
            status_value="covered",
            notes="unanchored auth labels are not principals",
        )
    assert exc.value.status_code == 409
    assert "two distinct principals" in str(exc.value.detail)


def test_cookie_only_identities_without_principal_ids_do_not_satisfy_gate(
    client, isolate_settings
):
    # Two DISTINCT cookie-only identities: credential rows EXIST (the LEFT JOIN
    # matches) but principal_id is empty, as legacy/manual/cookie-only sessions
    # commonly are. Falling back to identity_name would count them as two durable
    # principals and falsely close the cross-principal WRITE gate; an unanchored
    # identity must contribute no principal.
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100001-header-cookieonly-gate")
    first = _variant(engagement_id, auth="cap-aaaa")
    second = _variant(engagement_id, auth="cap-bbbb")
    for identity_name in ("cap-aaaa", "cap-bbbb"):
        credentials.upsert_material(
            engagement_id,
            identity_name,
            {"principal_id": "", "cookies": {"sid": identity_name}},
        )
    item = next(
        row
        for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == first["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )
    for variant, auth in ((first, "cap-aaaa"), (second, "cap-bbbb")):
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=variant["id"],
            service_id=None,
            coverage_item_id=None,
            auth_context=auth,
            input_slot="header:x-tenant-id",
            attack_family="identity-header-review",
            payload_family="cross-principal",
            payload_value=auth,
            tool_name="browser",
            agent_name="vulnerability-analyst",
            result_status="tested",
            observed_http_status=403,
            signal_type="",
            evidence_ref=f"scans/{auth}.json",
            notes="cookie-only session, no durable principal",
        )

    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=item["id"],
            status_value="covered",
            notes="two cookie-only sessions are not two principals",
        )
    assert exc.value.status_code == 409
    assert "two distinct principals" in str(exc.value.detail)


def test_identity_header_read_only_variant_cannot_be_marked_covered(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100002-header-read")
    variant = _variant(engagement_id, auth="alice", method="GET")
    item = next(
        row for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == variant["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )
    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=item["id"],
            status_value="covered",
            notes="read only",
        )
    assert exc.value.status_code == 409
    assert "WRITE" in str(exc.value.detail)


def test_direct_coverage_upsert_cannot_bypass_identity_header_gate(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100003-header-upsert")
    variant = _variant(engagement_id, auth="alice")
    with pytest.raises(HTTPException) as exc:
        state_manager.record_coverage_item(
            engagement_id,
            request_variant_id=variant["id"],
            service_id=None,
            auth_context="alice",
            input_slot="header:x-tenant-id",
            attack_family="identity-header-review",
            status_value="covered",
            notes="attempted bypass",
            preserve_existing_status=False,
        )
    assert exc.value.status_code == 409


def test_security_routing_headers_become_obligations_without_forwarding_noise(
    client, isolate_settings
):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100004-header-commodity")
    variant = _variant(
        engagement_id,
        auth="alice",
        header_schema={
            "X-Forwarded-For": "",
            "X-Forwarded-Host": "",
            "X-Original-URL": "",
            "X-Rewrite-URL": "",
            "X-HTTP-Method-Override": "",
            "X-Tenant-Id": "",
        },
    )
    slots = {
        row["input_slot"]
        for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == variant["id"]
    }
    assert "header:x-tenant-id" in slots
    assert "header:x-forwarded-for" not in slots
    assert "header:x-forwarded-host" in slots
    assert "header:x-original-url" in slots
    assert "header:x-rewrite-url" in slots
    assert "header:x-http-method-override" in slots


def test_identity_header_evidence_cannot_cross_port_or_scheme(
    client, isolate_settings
):
    engagement_id = _seed(client, isolate_settings, "2026-07-15-100005-header-port")
    target = _variant(
        engagement_id, auth="alice", url="https://app.example:8443/api/transfer"
    )
    wrong_alice = _variant(
        engagement_id, auth="wrong-a", url="http://app.example:8080/api/transfer"
    )
    wrong_bob = _variant(
        engagement_id, auth="wrong-b", url="http://app.example:8080/api/transfer"
    )
    item = next(
        row for row in state_manager.list_coverage_items(engagement_id)
        if row["request_variant_id"] == target["id"]
        and row["input_slot"] == "header:x-tenant-id"
    )
    for variant, auth in ((wrong_alice, "wrong-a"), (wrong_bob, "wrong-b")):
        state_manager.record_probe_run(
            engagement_id,
            request_variant_id=variant["id"], service_id=None, coverage_item_id=None,
            auth_context=auth, input_slot="header:x-tenant-id",
            attack_family="identity-header-review", payload_family="cross-principal",
            payload_value=auth, tool_name="browser", agent_name="vulnerability-analyst",
            result_status="tested", observed_http_status=403, signal_type="",
            evidence_ref=f"scans/{auth}.json", notes="wrong service write request",
        )
    with pytest.raises(HTTPException) as exc:
        state_manager.update_coverage_item_status(
            engagement_id,
            coverage_item_id=item["id"],
            status_value="covered",
            notes="must not borrow evidence from another listener",
        )
    assert exc.value.status_code == 409
