"""Golden payloads for the depth ledger and the by-family coverage grid.

The fixture mixes every way a row reaches an application unit: probes and
coverage items attributed by ``application_unit_id``, by ``request_variant_id``,
by both, and probes attributed only by ``target_host``/``target_port``/
``target_path`` containment, plus rows that reach no unit. Units nest
(``/``, ``/api``, ``/api/v2``), sit on sibling paths (``/apix`` is not under
``/api``), use a non-normalised prefix (``/api/``), and span port classes, an
out-of-scope host, credentials, completed and in-progress dispatches, and
engagement-wide, host-scoped and resolved depth deferrals.

``tests/depth_ledger_golden.json`` holds the serialised output of
``by_family_coverage`` and ``depth_ledger`` for this fixture. Any change to how
rows are attributed to units, or to the order they are reported in, changes the
bytes. Regenerate it only for an intended behaviour change:
``VIGIL_REGENERATE_DEPTH_LEDGER_GOLDEN=1`` with this file selected.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from app.services import state_manager
from app.services.state_manager.depth_ledger import by_family_coverage
from tests.test_engagements_api import write_engagement

ENGAGEMENT_KEY = "2026-11-12-090000-ledger-golden"
GOLDEN_PATH = Path(__file__).with_name("depth_ledger_golden.json")

IN_SCOPE_HOSTS = ("example.com", "app.example.com", "shop.example.com")
OUT_OF_SCOPE_HOST = "cdn.example.net"
HOSTS = (*IN_SCOPE_HOSTS, OUT_OF_SCOPE_HOST)

UNIT_PREFIXES = ("/", "/api", "/api/v2", "/login", "/files")

VARIANT_PATHS = (
    "/",
    "/api",
    "/api/items",
    "/api/items/{id}",
    "/api/v2/users",
    "/api/v2/webhook",
    "/apix/status",
    "/login",
    "/login/reset",
    "/files/upload",
    "/checkout/pay",
    "/ws",
)

# (scheme, port): 443/80 are the "web" port class; 8443 is "port-8443".
ENDPOINTS = (("https", 443), ("http", 80), ("https", 8443), ("wss", 443))

QUERY_SCHEMAS = (
    {},
    {"id": "int"},
    {"url": "str"},
    {"file": "str"},
    {"q": "str", "user_id": "int"},
)

HEADER_SCHEMAS = (
    {},
    {"access-control-allow-origin": "*"},
    {"server": "cloudflare"},
)

ATTACK_FAMILIES = (
    "sqli", "idor", "ssti", "xss", "ssrf", "lfi", "csrf", "open-redirect",
    "endpoint-review", "auth-bypass", "file-upload", "race-condition",
)
RESULT_STATUSES = ("tested", "signal", "attempted", "blocked", "no-signal", "error")
TOOLS = ("sqlmap", "ffuf", "gau-secrets", "curl", "trufflehog", "nuclei-lite")
AUTH_CONTEXTS = ("anonymous", "alice", "bob", "")
COVERAGE_STATUSES = ("covered", "pending", "not_applicable", "not-applicable", "blocked")


def _seed_engagement(client, isolate_settings) -> int:
    eng_dir = write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    scope = json.loads((eng_dir / "scope.json").read_text(encoding="utf-8"))
    scope["engagement_type"] = "web"
    scope["scope_hosts"] = list(IN_SCOPE_HOSTS)
    scope["scope"] = list(IN_SCOPE_HOSTS)
    (eng_dir / "scope.json").write_text(json.dumps(scope), encoding="utf-8")
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def seed_mixed_attribution_fixture(eng_id: int) -> None:
    """Insert the mixed-attribution fixture with explicit, stable row ids."""
    with state_manager.get_connection() as connection:
        unit_rows: list[tuple[int, str, str, str]] = []
        unit_id = 100
        for host_index, host in enumerate(HOSTS):
            for prefix_index, prefix in enumerate(UNIT_PREFIXES):
                unit_id += 1
                unit_rows.append((unit_id, host, "web", prefix))
            unit_id += 1
            unit_rows.append((unit_id, host, "port-8443", "/"))
            if host_index == 2:
                unit_id += 1
                unit_rows.append((unit_id, host, "web", "/api/"))
        for index, (uid, host, port_class, prefix) in enumerate(unit_rows):
            connection.execute(
                "INSERT INTO assessment_application_units "
                "(id, engagement_id, host, port_class, path_prefix, deep_required, "
                "depth_tier, structure_score, risk_score, total_score, confidence) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    uid, eng_id, host, port_class, prefix,
                    0 if index % 4 == 3 else 1,
                    ("thin", "endpoint-cluster", "app-unit", "application")[index % 4],
                    index % 5, (index * 7) % 11, (index * 3) % 13,
                    ("high", "medium", "low")[index % 3],
                ),
            )
        unit_ids = [row[0] for row in unit_rows]

        variant_ids: list[int] = []
        variant_id = 1000
        for host_index, host in enumerate(HOSTS):
            for path_index, path in enumerate(VARIANT_PATHS):
                for endpoint_index, (scheme, port) in enumerate(ENDPOINTS):
                    if (host_index + path_index + endpoint_index) % 3 == 2:
                        continue
                    variant_id += 1
                    seq = len(variant_ids)
                    query = QUERY_SCHEMAS[seq % len(QUERY_SCHEMAS)]
                    header = HEADER_SCHEMAS[seq % len(HEADER_SCHEMAS)]
                    connection.execute(
                        "INSERT INTO assessment_request_variants "
                        "(id, engagement_id, auth_context, scheme, host, port, method, "
                        "normalized_path, content_type_family, query_schema_json, "
                        "body_schema_json, path_schema_json, header_schema_json, "
                        "params_schema_hash, body_schema_hash) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (
                            variant_id, eng_id, AUTH_CONTEXTS[seq % 3], scheme, host,
                            port, ("GET", "POST", "PUT", "DELETE")[seq % 4], path,
                            ("json", "form", "html")[seq % 3], json.dumps(query),
                            json.dumps({"comment": "str"} if seq % 5 == 0 else {}),
                            json.dumps({"id": "int"} if "{id}" in path else {}),
                            json.dumps(header), f"p{seq}", f"b{seq}",
                        ),
                    )
                    variant_ids.append(variant_id)
                    for obs in range(seq % 3):
                        connection.execute(
                            "INSERT INTO assessment_request_observations "
                            "(engagement_id, request_variant_id, observed_url, response_status) "
                            "VALUES (?, ?, ?, ?)",
                            (
                                eng_id, variant_id, f"{scheme}://{host}:{port}{path}",
                                (200, 401, 403, None)[(seq + obs) % 4],
                            ),
                        )

        surfaces = (
            ("object_reference", "https://app.example.com/api/items/1"),
            ("auth_entry", "https://example.com/login"),
            ("account_recovery", "app.example.com /login/reset"),
            ("file_handling", "https://shop.example.com/files/upload"),
            ("workflow_token", "https://shop.example.com/checkout/pay"),
            ("object_reference", "https://cdn.example.net/api/v2/users"),
            ("auth_entry", "us-east-1"),
        )
        for surface_type, descriptor in surfaces:
            connection.execute(
                "INSERT INTO assessment_surfaces (engagement_id, surface_type, target_descriptor) "
                "VALUES (?, ?, ?)",
                (eng_id, surface_type, descriptor),
            )

        findings = (
            (501, "VA-001", "https://app.example.com/api/items/7", "injection"),
            (502, "VA-002", "https://shop.example.com/files/upload", "file"),
            (503, "VA-003", "example.com/login", "auth"),
            (504, "VA-004", "", "disclosure"),
            (505, "VA-005", "https://cdn.example.net/api", "access-control"),
        )
        for fid, slug, location, family in findings:
            connection.execute(
                "INSERT INTO assessment_findings "
                "(id, engagement_id, slug, title, canonical_location, defect_family, "
                "root_cause_key) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (fid, eng_id, slug, f"Golden {slug}", location, family, f"rc-{slug}"),
            )
        finding_ids = [row[0] for row in findings]

        for index in range(160):
            unit_ref = unit_ids[index % len(unit_ids)] if index % 4 in (0, 3) else None
            variant_ref = variant_ids[(index * 7) % len(variant_ids)] if index % 4 in (1, 3) else None
            notes = "" if index % 6 == 5 else f"reviewed input {index}"
            connection.execute(
                "INSERT INTO assessment_coverage_items "
                "(id, engagement_id, request_variant_id, application_unit_id, auth_context, "
                "input_slot, attack_family, status, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    3000 + index, eng_id, variant_ref, unit_ref,
                    AUTH_CONTEXTS[index % 3] or "anonymous", f"slot-{index}",
                    ATTACK_FAMILIES[index % len(ATTACK_FAMILIES)],
                    COVERAGE_STATUSES[index % len(COVERAGE_STATUSES)], notes,
                ),
            )

        target_paths = (*VARIANT_PATHS, "", "/api/items/9", "/files/upload/x", "/apix")
        for index in range(420):
            mode = index % 5
            unit_ref = unit_ids[(index * 3) % len(unit_ids)] if mode in (0, 4) else None
            variant_ref = variant_ids[(index * 11) % len(variant_ids)] if mode in (1, 4) else None
            # mode 2: host/port/path containment only; mode 3: no attribution
            # unless the target matches (empty host never counts).
            target_host = HOSTS[index % len(HOSTS)] if mode != 3 or index % 2 else ""
            if index % 9 == 0:
                target_host = target_host.upper()
            connection.execute(
                "INSERT INTO assessment_probe_runs "
                "(id, engagement_id, request_variant_id, application_unit_id, auth_context, "
                "attack_family, probe_key, tool_name, result_status, observed_http_status, "
                "outcome_assertion, evidence_ref, target_host, target_path, target_port, "
                "finding_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    5000 + index, eng_id, variant_ref, unit_ref,
                    AUTH_CONTEXTS[(index // 2) % len(AUTH_CONTEXTS)],
                    ATTACK_FAMILIES[(index * 5) % len(ATTACK_FAMILIES)],
                    f"golden-{index}", TOOLS[index % len(TOOLS)],
                    RESULT_STATUSES[index % len(RESULT_STATUSES)],
                    (200, 403, None, 401, 404)[(index // 3) % 5],
                    "owner-only data returned" if index % 37 == 0 else "",
                    f"evidence/probe-{index % 13}.txt" if index % 4 else "",
                    target_host, target_paths[index % len(target_paths)],
                    (None, 443, 8443, 80, 0)[index % 5],
                    finding_ids[index % len(finding_ids)] if index % 17 == 0 else None,
                ),
            )

        # Cross-identity probes on shared variants: the per-identity HTTP status
        # differences and the access-control cross-identity verdict.
        app_variant_ids = [
            row[0]
            for row in connection.execute(
                "SELECT id FROM assessment_request_variants "
                "WHERE engagement_id = ? AND host = 'app.example.com' ORDER BY id",
                (eng_id,),
            ).fetchall()
        ]
        for index, shared_variant in enumerate(app_variant_ids[::3]):
            for identity, http_status in (("alice", 200), ("bob", 403 if index % 2 else 200), ("anonymous", 401)):
                connection.execute(
                    "INSERT INTO assessment_probe_runs "
                    "(engagement_id, request_variant_id, auth_context, attack_family, "
                    "probe_key, tool_name, result_status, observed_http_status, "
                    "outcome_assertion, evidence_ref) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        eng_id, shared_variant, identity, "idor",
                        f"golden-identity-{index}-{identity}", "curl",
                        "tested" if index % 3 else "signal", http_status,
                        "bob read alice's order" if identity == "bob" and index % 4 == 1 else "",
                        f"evidence/identity-{index}-{identity}.txt",
                    ),
                )

        for index in range(18):
            connection.execute(
                "INSERT INTO assessment_dispatches "
                "(engagement_id, agent_id, agent_role, application_unit_id, dispatched_at, "
                "status, vuln_classes, skills, finding_slugs_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    eng_id, f"va-golden-{index:02d}", "vulnerability-analyst",
                    unit_ids[(index * 5) % len(unit_ids)] if index % 6 else None,
                    f"2026-11-12T09:{index:02d}:00Z",
                    ("completed", "in-progress", "completed", "failed")[index % 4],
                    "sqli", "", "[]",
                ),
            )

        connection.execute(
            "INSERT INTO assessment_credentials (engagement_id, credential_key, principal) "
            "VALUES (?, ?, ?)",
            (eng_id, "admin@shop.example.com", "app.example.com:web"),
        )

        deferrals = (
            (9001, {"engagement_wide": True, "vuln_classes": ["csrf"], "reason": "out of ROE"}, 0),
            (9002, {"host": "app.example.com", "path_prefix": "/api",
                    "vuln_classes": ["sqli", "ssrf"], "reason": "vendor API"}, 0),
            (9003, {"host": "https://shop.example.com", "path_prefix": "/",
                    "vuln_classes": ["idor"], "reason": "single identity"}, 0),
            (9004, {"host": "example.com", "vuln_classes": ["lfi"], "reason": "resolved"}, 1),
        )
        for decision_id, payload, resolved in deferrals:
            connection.execute(
                "INSERT INTO assessment_dispatch_decisions "
                "(id, engagement_id, kind, payload_json, resolved, created_at) "
                "VALUES (?, ?, 'depth_deferral', ?, ?, ?)",
                (
                    decision_id, eng_id, json.dumps(payload), resolved,
                    f"2026-11-12T10:00:{decision_id % 60:02d}Z",
                ),
            )


def _serialise(payload) -> str:
    return json.dumps(payload, indent=1, ensure_ascii=False) + "\n"


def test_by_family_and_depth_ledger_payloads_match_the_golden(client, isolate_settings):
    eng_id = _seed_engagement(client, isolate_settings)
    seed_mixed_attribution_fixture(eng_id)

    with state_manager.get_connection() as connection:
        by_family = by_family_coverage(connection, eng_id)
    ledger = state_manager.depth_ledger(eng_id)
    actual = _serialise({"by_family": by_family, "depth_ledger": ledger})

    if os.environ.get("VIGIL_REGENERATE_DEPTH_LEDGER_GOLDEN") == "1":
        GOLDEN_PATH.write_text(actual, encoding="utf-8")

    # The fixture must exercise every attribution path, or the golden proves little.
    assert by_family["totals"]["units"] == len(HOSTS) * (len(UNIT_PREFIXES) + 1) + 1
    assert by_family["totals"]["with_finding"] > 0
    assert ledger["skipped"] is False
    assert ledger["deferral_count"] == 3
    assert any(u["identity_outcome_difference_count"] for u in ledger["units"])
    assert any(u["dedicated_dispatch_satisfied"] for u in ledger["units"])
    assert {u["unit"]["host"] for u in ledger["units"]} <= set(IN_SCOPE_HOSTS)

    assert actual == GOLDEN_PATH.read_text(encoding="utf-8")
