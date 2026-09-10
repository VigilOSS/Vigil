"""Omitted note fields must survive same-title upserts and remain searchable."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest

from app.services import intel
from tests.test_engagements_api import write_engagement


@pytest.fixture
def note_api(client, isolate_settings):
    key = "2026-09-08-120000-notes"
    write_engagement(isolate_settings["engagements_dir"], key=key)
    response = client.get(f"/engagements/{key}")
    assert response.status_code == 200, response.text
    return f"/engagements/{key}/intel"


def _record(client, base, **payload):
    response = client.post(f"{base}/notes", json={"title": "Work log", **payload})
    assert response.status_code == 201, response.text
    return response.json()


def _rerecord(writer, client, base, engagement_id, **payload):
    if writer == "api":
        return _record(client, base, **payload)
    return intel.record_note(engagement_id, title="Work log", **payload)


@pytest.mark.parametrize("writer", ["api", "service"])
def test_omitted_body_preserves_saved_note(client, note_api, writer):
    created = _record(client, note_api, body_markdown="Authored archivisttoken content.")

    if writer == "api":
        updated = _record(client, note_api, source_agent="editor")
    else:
        updated = intel.record_note(
            created["engagement_id"], title="Work log", source_agent="editor"
        )

    assert updated["id"] == created["id"]
    assert updated["body_markdown"] == created["body_markdown"]
    listing = client.get(f"{note_api}/notes")
    assert listing.status_code == 200, listing.text
    assert len(listing.json()) == 1
    assert listing.json()[0]["body_markdown"] == created["body_markdown"]


@pytest.mark.parametrize("writer", ["api", "service"])
def test_omitted_metadata_preserves_saved_note_and_search_index(client, note_api, writer):
    created = _record(
        client,
        note_api,
        body_markdown="Authored bodytoken content.",
        source_agent="archivistagenttoken",
        tags=["archivisttagtoken"],
        source_name="archivistsourcetoken",
        provenance={"origin": "archivistprovenancetoken"},
    )

    updated = _rerecord(
        writer,
        client,
        note_api,
        created["engagement_id"],
        body_markdown="Revised bodytoken content.",
    )

    assert updated["id"] == created["id"]
    assert updated["source_agent"] == created["source_agent"]
    assert updated["tags"] == created["tags"]
    assert updated["source_name"] == created["source_name"]
    assert updated["provenance"] == created["provenance"]
    for token in ("archivistagenttoken", "archivisttagtoken", "archivistsourcetoken"):
        response = client.get(f"{note_api}/search", params={"q": token})
        assert response.status_code == 200, response.text
        assert any(hit["source_id"] == created["id"] for hit in response.json())


@pytest.mark.parametrize("writer", ["api", "service"])
def test_explicit_empty_metadata_clears_saved_note_and_search_index(client, note_api, writer):
    created = _record(
        client,
        note_api,
        body_markdown="Keep bodytoken content.",
        source_agent="clearagenttoken",
        tags=["cleartagtoken"],
        source_name="clearsourcetoken",
        provenance={"origin": "clearprovenancetoken"},
    )

    updated = _rerecord(
        writer,
        client,
        note_api,
        created["engagement_id"],
        source_agent="",
        tags=[],
        source_name="",
        provenance={},
    )

    assert updated["id"] == created["id"]
    assert updated["body_markdown"] == created["body_markdown"]
    assert updated["source_agent"] == ""
    assert updated["tags"] == []
    assert updated["source_name"] == ""
    assert updated["provenance"] == {}
    for token in ("clearagenttoken", "cleartagtoken", "clearsourcetoken"):
        response = client.get(f"{note_api}/search", params={"q": token})
        assert response.status_code == 200, response.text
        assert response.json() == []
    response = client.get(f"{note_api}/search", params={"q": "bodytoken"})
    assert response.status_code == 200, response.text
    assert any(hit["source_id"] == created["id"] for hit in response.json())


def test_omitted_body_remains_in_search_index(client, note_api):
    created = _record(client, note_api, body_markdown="Authored archivisttoken content.")
    _record(client, note_api, source_agent="editor")

    response = client.get(f"{note_api}/search", params={"q": "archivisttoken"})
    assert response.status_code == 200, response.text
    assert any(hit["source_id"] == created["id"] for hit in response.json())


@pytest.mark.parametrize("body", ["Replacement replacementtoken content.", ""])
def test_explicit_body_replaces_or_clears_saved_note(client, note_api, body):
    created = _record(client, note_api, body_markdown="Original archivisttoken content.")
    updated = _record(client, note_api, body_markdown=body)

    assert updated["id"] == created["id"]
    assert updated["body_markdown"] == body
    response = client.get(f"{note_api}/search", params={"q": "archivisttoken"})
    assert response.status_code == 200, response.text
    assert response.json() == []
    if body:
        response = client.get(f"{note_api}/search", params={"q": "replacementtoken"})
        assert response.status_code == 200, response.text
        assert any(hit["source_id"] == created["id"] for hit in response.json())


def test_new_note_without_optional_fields_uses_storage_defaults(client, note_api):
    created = _record(client, note_api)

    assert created["body_markdown"] == ""
    assert created["source_agent"] == ""
    assert created["tags"] == []
    assert created["source_name"] == ""
    assert created["provenance"] == {}


def test_explicit_null_body_is_rejected_without_mutating_note(client, note_api):
    created = _record(client, note_api, body_markdown="Keep this text.")
    response = client.post(
        f"{note_api}/notes", json={"title": "Work log", "body_markdown": None}
    )
    assert response.status_code == 422, response.text
    listing = client.get(f"{note_api}/notes")
    assert listing.status_code == 200, listing.text
    assert listing.json()[0]["body_markdown"] == created["body_markdown"]


def test_same_title_note_body_is_isolated_by_engagement(client, isolate_settings, note_api):
    created = _record(client, note_api, body_markdown="Private archivisttoken content.")
    other_key = "2026-09-08-130000-other-notes"
    write_engagement(isolate_settings["engagements_dir"], key=other_key)
    response = client.get(f"/engagements/{other_key}")
    assert response.status_code == 200, response.text
    other_base = f"/engagements/{other_key}/intel"

    assert _record(client, other_base)["body_markdown"] == ""
    assert _record(client, note_api)["body_markdown"] == created["body_markdown"]
    response = client.get(f"{other_base}/search", params={"q": "archivisttoken"})
    assert response.status_code == 200, response.text
    assert response.json() == []


def test_concurrent_disjoint_note_edits_preserve_both_writers(client, note_api):
    """Omitted columns must not become stale defaults under concurrent upserts."""
    created = _record(
        client,
        note_api,
        body_markdown="Original body.",
        source_agent="original-agent",
        tags=["original"],
    )
    barrier = threading.Barrier(3)

    def replace_body():
        barrier.wait()
        return intel.record_note(
            created["engagement_id"],
            title="Work log",
            body_markdown="Concurrent bodytoken replacement.",
        )

    def replace_metadata():
        barrier.wait()
        return intel.record_note(
            created["engagement_id"],
            title="Work log",
            source_agent="concurrent-agenttoken",
            tags=["concurrent-tagtoken"],
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        body_result = pool.submit(replace_body)
        metadata_result = pool.submit(replace_metadata)
        barrier.wait()
        body_result.result(timeout=5)
        metadata_result.result(timeout=5)

    listing = client.get(f"{note_api}/notes")
    assert listing.status_code == 200, listing.text
    [row] = listing.json()
    assert row["body_markdown"] == "Concurrent bodytoken replacement."
    assert row["source_agent"] == "concurrent-agenttoken"
    assert row["tags"] == ["concurrent-tagtoken"]
    for token in ("bodytoken", "concurrent-agenttoken", "concurrent-tagtoken"):
        search = client.get(f"{note_api}/search", params={"q": token})
        assert search.status_code == 200, search.text
        assert any(hit["source_id"] == created["id"] for hit in search.json())
