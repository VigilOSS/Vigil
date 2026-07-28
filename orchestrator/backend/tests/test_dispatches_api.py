"""Contract tests for the ``assessment_dispatches`` API.

POST + GET + LIST + PATCH coverage. The sibling tables
(``assessment_dispatch_handoffs`` and ``assessment_dispatch_decisions``) have
their own files. UNIQUE(engagement_id, agent_id) enforcement → 409 on dup.
404 on missing agent_id. List filters: role, status, since, task_q, limit, offset.
"""
from __future__ import annotations

import json
from pathlib import Path

from app import db as db_module


ENGAGEMENT_KEY = "2026-04-28-120000-dispatches"
BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _write_engagement(engagements_dir: Path, key: str = ENGAGEMENT_KEY) -> Path:
    eng = engagements_dir / key
    (eng / "sessions").mkdir(parents=True, exist_ok=True)
    (eng / "engagement.json").write_text(
        json.dumps({"key": key, "target": "https://example.com", "hostname": "example.com",
                    "created_at": "2026-04-28T12:00:00Z"}),
        encoding="utf-8",
    )
    (eng / "scope.json").write_text(
        json.dumps({
            "hostname": "example.com",
            "hosts": ["example.com"],
            "status": "in_progress",
            "current_phase": "recon",
        }),
        encoding="utf-8",
    )
    return eng


def _seed(client, isolate_settings) -> int:
    eng = _write_engagement(isolate_settings["engagements_dir"])
    (eng / "findings.md").write_text("# Findings\n", encoding="utf-8")
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    engagement_id = int(response.json()["id"])
    for slug in ("VA-001", "VA-002"):
        finding = client.post(
            f"{BASE}/findings",
            json={
                "slug": slug,
                "title": f"Seed finding {slug}",
                "severity": "medium",
                "workflow_status": "active",
                "verification_state": "unreviewed",
                "verification_disposition": "none",
                "canonical_location": f"https://example.com/seed/{slug}",
                "summary": "Seed finding for dispatch references",
                "evidence_ref": "findings.md",
                "source_name": "vulnerability-analyst",
            },
        )
        assert finding.status_code == 201, finding.text
    return engagement_id


def _application_unit(engagement_id: int) -> int:
    with db_module.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_application_units (
                engagement_id, host, port_class, path_prefix
            ) VALUES (?, ?, ?, ?)
            """,
            (engagement_id, "rock.example.com", "web", "/giving"),
        )
        return int(cursor.lastrowid)


def test_dispatch_post_get_list_patch(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    payload = {
        "agent_id": "AG-001",
        "agent_role": "vulnerability-analyst",
        "task": "Validate IDOR on /api/users/{id}",
        "model": "gpt-5.4",
        "reasoning": "high",
        "dispatch_mode": "item-iterating",
        "finding_slugs": [],
        "skills": "auth-bypass,business-logic-testing",
    }
    resp = client.post(f"{BASE}/dispatches", json=payload)
    assert resp.status_code == 201, resp.text
    row = resp.json()

    titles = {
        row["title"]
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/activity-entries",
            params={"q": "agent"},
        ).json()["items"]
    }
    assert "agent start" in titles

    assert row["agent_id"] == "AG-001"
    assert row["agent_role"] == "vulnerability-analyst"
    assert row["status"] == "in-progress"
    assert row["finding_slugs"] == []
    assert row["skills"] == "auth-bypass,business-logic-testing"
    assert row["dispatched_at"]  # server-stamped when not supplied

    # GET one
    resp = client.get(f"{BASE}/dispatches/AG-001")
    assert resp.status_code == 200, resp.text
    assert resp.json()["task"].startswith("Validate IDOR")

    # GET list
    resp = client.get(f"{BASE}/dispatches")
    assert resp.status_code == 200
    rows = resp.json()
    assert len(rows) == 1
    assert rows[0]["agent_id"] == "AG-001"

    # Filter by role
    resp = client.get(f"{BASE}/dispatches", params={"role": "vulnerability-analyst"})
    assert resp.status_code == 200
    assert len(resp.json()) == 1
    resp = client.get(f"{BASE}/dispatches", params={"role": "recon-specialist"})
    assert resp.status_code == 200
    assert resp.json() == []

    # PATCH status -> completed
    resp = client.patch(
        f"{BASE}/dispatches/AG-001",
        json={
            "status": "completed",
            "completed_at": "2026-04-28T13:00:00Z",
            "finding_slugs": ["VA-001", "VA-002"],
        },
    )
    assert resp.status_code == 200, resp.text
    updated = resp.json()
    titles_done = {
        row["title"]
        for row in client.get(
            f"/engagements/{ENGAGEMENT_KEY}/activity-entries",
            params={"q": "agent done"},
        ).json()["items"]
    }
    assert "agent done" in titles_done

    assert updated["status"] == "completed"
    assert updated["completed_at"] == "2026-04-28T13:00:00Z"
    assert updated["finding_slugs"] == ["VA-001", "VA-002"]


def test_dispatch_duplicate_agent_id_returns_409(client, isolate_settings) -> None:
    _seed(client, isolate_settings)

    payload = {
        "agent_id": "AG-DUP",
        "agent_role": "recon-specialist",
        "skills": "subdomain-enumeration",
    }
    resp = client.post(f"{BASE}/dispatches", json=payload)
    assert resp.status_code == 201
    resp2 = client.post(f"{BASE}/dispatches", json=payload)
    assert resp2.status_code == 409, resp2.text


def test_dispatch_404_on_missing(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    resp = client.get(f"{BASE}/dispatches/never-existed")
    assert resp.status_code == 404
    resp = client.patch(f"{BASE}/dispatches/never-existed", json={"status": "completed"})
    assert resp.status_code == 404


def test_dispatch_list_filters(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    rows = [
        {"agent_id": "F1", "agent_role": "recon-specialist", "task": "phase 1 enum",
         "status": "completed", "dispatched_at": "2026-04-27T09:00:00Z",
         "skills": "subdomain-enumeration"},
        {"agent_id": "F2", "agent_role": "vulnerability-analyst", "task": "IDOR sweep",
         "status": "in-progress", "dispatched_at": "2026-04-28T10:00:00Z",
         "skills": "auth-bypass"},
        {"agent_id": "F3", "agent_role": "vulnerability-analyst", "task": "SQLi probe",
         "status": "failed", "dispatched_at": "2026-04-28T11:00:00Z",
         "skills": "sql-injection"},
    ]
    for r in rows:
        assert client.post(f"{BASE}/dispatches", json=r).status_code == 201

    # status filter
    resp = client.get(f"{BASE}/dispatches", params={"status": "completed"})
    assert {r["agent_id"] for r in resp.json()} == {"F1"}

    # since filter
    resp = client.get(f"{BASE}/dispatches", params={"since": "2026-04-28T00:00:00Z"})
    assert {r["agent_id"] for r in resp.json()} == {"F2", "F3"}

    # task_q filter (substring)
    resp = client.get(f"{BASE}/dispatches", params={"task_q": "IDOR"})
    assert {r["agent_id"] for r in resp.json()} == {"F2"}

    # limit
    resp = client.get(f"{BASE}/dispatches", params={"limit": 2})
    assert len(resp.json()) == 2

    # offset
    resp = client.get(f"{BASE}/dispatches", params={"limit": 1, "offset": 1})
    assert [r["agent_id"] for r in resp.json()] == ["F2"]


def test_dispatch_validation_rejects_bad_status_and_unknown_fields(client, isolate_settings) -> None:
    _seed(client, isolate_settings)
    # Bad status enum
    bad = client.post(f"{BASE}/dispatches", json={
        "agent_id": "BAD-1",
        "agent_role": "recon-specialist",
        "status": "in_progress",  # underscore instead of hyphen
        "skills": "subdomain-enumeration",
    })
    assert bad.status_code == 422

    # Unknown field (extra="forbid")
    bad = client.post(f"{BASE}/dispatches", json={
        "agent_id": "BAD-2",
        "agent_role": "recon-specialist",
        "garbage_key": "nope",
        "skills": "subdomain-enumeration",
    })
    assert bad.status_code == 422


def test_dispatch_without_skills_is_accepted(client, isolate_settings) -> None:
    """A specialist dispatch may omit skills: the specialist selects them from
    what it observes on the surface, so the honest list is only known after the
    dispatch runs. Requiring it up front would force the operator to name a
    vulnerability class before the hunt."""
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/dispatches", json={
        "agent_id": "ADHOC-1",
        "agent_role": "vulnerability-analyst",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["agent_id"] == "ADHOC-1"


def test_dispatch_unknown_dispatch_mode_stored_as_text(client, isolate_settings) -> None:
    """L2-4: a newly-coined dispatch_mode is stored as free text rather than
    422'd by a closed enum."""
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/dispatches", json={
        "agent_id": "NEWMODE-1",
        "agent_role": "vulnerability-analyst",
        "skills": "idor-testing",
        "dispatch_mode": "freshly-coined-mode",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["dispatch_mode"] == "freshly-coined-mode"
    fetched = client.get(f"{BASE}/dispatches/NEWMODE-1")
    assert fetched.status_code == 200
    assert fetched.json()["dispatch_mode"] == "freshly-coined-mode"


def test_dispatch_operator_role_skills_optional(client, isolate_settings) -> None:
    """Operator coordinates phases and is exempt from the skills requirement."""
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/dispatches", json={
        "agent_id": "OP-1",
        "agent_role": "operator",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["skills"] is None


def test_dispatch_operator_role_skills_optional_case_insensitive(client, isolate_settings) -> None:
    """Operator role casing should not accidentally turn operators into specialists."""
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/dispatches", json={
        "agent_id": "OP-CASE",
        "agent_role": "Operator",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["agent_role"] == "Operator"
    assert resp.json()["skills"] is None


def test_dispatch_skills_round_trip(client, isolate_settings) -> None:
    """skills value is persisted through POST and surfaces unchanged on GET."""
    _seed(client, isolate_settings)
    resp = client.post(f"{BASE}/dispatches", json={
        "agent_id": "SK-1",
        "agent_role": "surface-collector",
        "skills": "surface-collection,gau-triage",
    })
    assert resp.status_code == 201, resp.text
    assert resp.json()["skills"] == "surface-collection,gau-triage"
    fetched = client.get(f"{BASE}/dispatches/SK-1")
    assert fetched.status_code == 200
    assert fetched.json()["skills"] == "surface-collection,gau-triage"


def test_dispatch_requested_actual_fields_post_get_list(client, isolate_settings) -> None:
    """requested_* / actual_* model and reasoning fields round-trip via POST / GET / LIST."""
    _seed(client, isolate_settings)
    resp = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "RQ-ACT-1",
            "agent_role": "vulnerability-analyst",
            "skills": "auth-bypass",
            "requested_model": "gpt-test-a",
            "actual_model": "gpt-test-b",
            "requested_reasoning": "high",
            "actual_reasoning": "medium",
            "dispatch_mode": "hypothesis-driven",
        },
    )
    assert resp.status_code == 201, resp.text
    posted = resp.json()
    assert posted["requested_model"] == "gpt-test-a"
    assert posted["actual_model"] == "gpt-test-b"
    assert posted["requested_reasoning"] == "high"
    assert posted["actual_reasoning"] == "medium"
    assert posted["model"] == "gpt-test-a"
    assert posted["reasoning"] == "high"

    fetched = client.get(f"{BASE}/dispatches/RQ-ACT-1").json()
    for key in (
        "requested_model",
        "actual_model",
        "requested_reasoning",
        "actual_reasoning",
    ):
        assert fetched[key] == posted[key]

    listed = client.get(f"{BASE}/dispatches").json()
    assert len(listed) == 1
    for key in (
        "requested_model",
        "actual_model",
        "requested_reasoning",
        "actual_reasoning",
    ):
        assert listed[0][key] == posted[key]


def test_dispatch_structured_depth_metadata_round_trips(client, isolate_settings) -> None:
    """Application-unit identity and descriptive metadata round-trip."""
    engagement_id = _seed(client, isolate_settings)
    unit_id = _application_unit(engagement_id)
    payload = {
        "agent_id": "AG-DEPTH-1",
        "agent_role": "vulnerability-analyst",
        "task": "Deep IDOR pass on the giving app",
        "application_unit_id": unit_id,
        "vuln_classes": "idor,bola,sqli",
        "identity": "user_a",
        "skills": "idor-testing",
    }
    resp = client.post(f"{BASE}/dispatches", json=payload)
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["application_unit_id"] == unit_id
    assert row["vuln_classes"] == "idor,bola,sqli"
    assert row["identity"] == "user_a"

    fetched = client.get(f"{BASE}/dispatches/AG-DEPTH-1").json()
    assert fetched["application_unit_id"] == unit_id
    assert fetched["vuln_classes"] == "idor,bola,sqli"
    assert fetched["identity"] == "user_a"

    listed = client.get(f"{BASE}/dispatches").json()
    assert listed[0]["application_unit_id"] == unit_id
    assert listed[0]["vuln_classes"] == "idor,bola,sqli"
    assert listed[0]["identity"] == "user_a"


def test_dispatch_application_unit_identity_round_trips(client, isolate_settings) -> None:
    """Dispatch depth attribution uses a concrete engagement-owned unit id."""
    engagement_id = _seed(client, isolate_settings)
    unit_id = _application_unit(engagement_id)
    payload = {
        "agent_id": "AG-UNIT-1",
        "agent_role": "vulnerability-analyst",
        "task": "Deep pass over the measured application unit",
        "application_unit_id": unit_id,
        "identity": "user_a",
        "skills": "idor-testing",
    }
    response = client.post(f"{BASE}/dispatches", json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["application_unit_id"] == unit_id
    assert client.get(f"{BASE}/dispatches/AG-UNIT-1").json()["application_unit_id"] == unit_id
    assert client.get(f"{BASE}/dispatches").json()[0]["application_unit_id"] == unit_id


def test_dispatch_rejects_application_unit_from_another_engagement(
    client,
    isolate_settings,
) -> None:
    _seed(client, isolate_settings)
    other_key = "2026-04-28-120001-dispatches-other"
    _write_engagement(isolate_settings["engagements_dir"], key=other_key)
    other = client.get(f"/engagements/{other_key}")
    assert other.status_code == 200, other.text
    foreign_unit_id = _application_unit(int(other.json()["id"]))

    response = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "AG-FOREIGN-UNIT",
            "agent_role": "vulnerability-analyst",
            "application_unit_id": foreign_unit_id,
        },
    )
    assert response.status_code == 400, response.text
    assert "this engagement" in response.json()["detail"]


def test_dispatch_structured_depth_metadata_optional(client, isolate_settings) -> None:
    """The new fields are optional — a dispatch without them stores NULL."""
    _seed(client, isolate_settings)
    resp = client.post(
        f"{BASE}/dispatches",
        json={
            "agent_id": "AG-DEPTH-2",
            "agent_role": "vulnerability-analyst",
            "skills": "sql-injection",
        },
    )
    assert resp.status_code == 201, resp.text
    row = resp.json()
    assert row["application_unit_id"] is None
    assert row["vuln_classes"] is None
    assert row["identity"] is None
