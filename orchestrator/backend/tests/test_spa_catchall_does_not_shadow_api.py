"""The SPA catch-all must not answer for API paths.

``@app.get("/{full_path:path}")`` served ``index.html`` with **200** for every
unmatched path, so a misspelt endpoint (``code-files`` for ``code/files``) came
back as a successful HTML body: exit 0, no error, no route. UI deep links live in
the same namespace and MUST keep resolving to the SPA, so the split is by the API
families the routers actually claim.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from app.main import _engagement_api_segments, _is_unmatched_api_path

ENGAGEMENT_KEY = "2026-08-21-spa-catchall"


@pytest.fixture
def seeded(client, isolate_settings):
    engagement_dir: Path = isolate_settings["engagements_dir"] / ENGAGEMENT_KEY
    (engagement_dir / "sessions").mkdir(parents=True, exist_ok=True)
    (engagement_dir / "scope.json").write_text(
        json.dumps({"engagement_name": "SPA", "targets": ["https://app.example"]}),
        encoding="utf-8",
    )
    (engagement_dir / "findings.md").write_text("# Findings\n", encoding="utf-8")
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200
    return client


def test_the_api_segment_set_is_derived_from_the_registered_routers() -> None:
    """Hand-listing the segments would drift the moment a router is added."""
    segments = _engagement_api_segments()
    assert {"assessment", "intel", "artifacts", "credentials", "events"} <= segments


@pytest.mark.parametrize(
    "path",
    [
        f"engagements/{ENGAGEMENT_KEY}/assessment/code-files",
        f"engagements/{ENGAGEMENT_KEY}/assessment/totally-made-up",
        "api/anything",
    ],
)
def test_unmatched_api_paths_are_json_404s(seeded, path) -> None:
    response = seeded.get(f"/{path}")

    assert response.status_code == 404, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert "no API route matches" in response.json()["detail"]


def test_an_unknown_intel_type_is_the_routers_own_json_404(seeded) -> None:
    """The parameterised intel GET matches, so its OWN 404 answers — the point is
    that no path under an API family can come back as HTML."""
    response = seeded.get(f"/engagements/{ENGAGEMENT_KEY}/intel/frobs/1")

    assert response.status_code == 404, response.text
    assert response.headers["content-type"].startswith("application/json")
    assert "unknown intel type segment" in response.json()["detail"]


@pytest.mark.parametrize(
    "path",
    [
        "",
        f"engagements/{ENGAGEMENT_KEY}/findings",
        f"engagements/{ENGAGEMENT_KEY}/coverage",
        "some/ui/deep/link",
    ],
)
def test_ui_deep_links_still_serve_the_spa(seeded, path) -> None:
    """A client-side router owns these paths; 404ing them would break the UI."""
    response = seeded.get(f"/{path}")

    assert response.status_code in (200, 503), response.text
    if response.status_code == 200:
        assert not response.headers["content-type"].startswith("application/json")


def test_the_predicate_never_claims_a_two_segment_engagement_path() -> None:
    assert not _is_unmatched_api_path(f"engagements/{ENGAGEMENT_KEY}")
    assert not _is_unmatched_api_path("")


def test_intel_by_id_reads_a_row_and_404s_json_for_unknown_ids(seeded) -> None:
    base = f"/engagements/{ENGAGEMENT_KEY}/intel"
    created = seeded.post(
        f"{base}/notes",
        json={
            "title": "Vendor uses a shared JWT signing key",
            "body_markdown": "Observed across two tenants.",
            "source_name": "recon",
        },
    )
    assert created.status_code == 201, created.text
    intel_id = created.json()["id"]

    fetched = seeded.get(f"{base}/notes/{intel_id}")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["title"] == "Vendor uses a shared JWT signing key"

    missing = seeded.get(f"{base}/notes/999999")
    assert missing.status_code == 404, missing.text
    assert missing.headers["content-type"].startswith("application/json")

    # DECLARATION ORDER: the parameterised GET must not shadow the literal ones.
    assert seeded.get(f"{base}/summary").status_code == 200
    assert seeded.get(f"{base}/notes").status_code == 200
    assert seeded.get(f"{base}/credentials").status_code == 200


def test_dispatch_decision_by_id_reads_a_row_and_404s_json(seeded) -> None:
    base = f"/engagements/{ENGAGEMENT_KEY}/assessment"
    created = seeded.post(
        f"{base}/dispatch-decisions",
        json={
            "kind": "scope_decision",
            "payload": {"host": "staging.app.example", "reason": "Named in the ROE."},
        },
    )
    assert created.status_code == 201, created.text
    decision_id = created.json()["id"]

    fetched = seeded.get(f"{base}/dispatch-decisions/{decision_id}")
    assert fetched.status_code == 200, fetched.text
    assert fetched.json()["id"] == decision_id

    missing = seeded.get(f"{base}/dispatch-decisions/999999")
    assert missing.status_code == 404, missing.text

    # The literal list route still resolves.
    assert seeded.get(f"{base}/dispatch-decisions").status_code == 200
