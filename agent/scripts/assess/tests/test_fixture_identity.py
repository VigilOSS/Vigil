"""Tests for dynamic fixture/session identity manifests."""
from __future__ import annotations

import json

import pytest
from assess.lib.fixture_identity import (
    FixtureIdentityError,
    FixtureManifest,
    extract_fixture_ids,
    resolve_fixture_id,
)


def test_extracts_json_api_person_and_parent_organization() -> None:
    payload = {
        "data": {"type": "Person", "id": "person-new"},
        "meta": {"parent": {"type": "Organization", "id": "org-new"}},
    }
    assert extract_fixture_ids(payload) == {
        "organization_id": "org-new",
        "person_id": "person-new",
    }


def test_untyped_parent_id_is_not_assumed_to_be_an_organization() -> None:
    assert extract_fixture_ids({"meta": {"parent": {"id": "ambiguous-1"}}}) == {}


def test_extracts_subscription_and_direct_aliases() -> None:
    payload = {
        "data": [{"type": "Subscription", "id": 12345}],
        "organization_id": "org-rotated",
    }
    assert extract_fixture_ids(payload) == {
        "organization_id": "org-rotated",
        "subscription_id": "12345",
    }


def test_conflicting_response_ids_fail_closed() -> None:
    with pytest.raises(FixtureIdentityError, match="conflicting person_id"):
        extract_fixture_ids(
            {"person_id": "new", "data": {"type": "Person", "id": "old"}}
        )


@pytest.mark.parametrize("container", [[], (), set(), frozenset(), {}])
def test_container_ids_are_rejected(container) -> None:
    with pytest.raises(FixtureIdentityError, match="non-empty scalar"):
        extract_fixture_ids({"organization_id": container})


def test_manifest_observe_resolve_and_atomic_round_trip(tmp_path) -> None:
    path = tmp_path / "fixtures.json"
    manifest = FixtureManifest()
    observed = manifest.observe(
        "org3_admin",
        {
            "data": {"type": "Person", "id": "person-3"},
            "meta": {"parent": {"type": "Organization", "id": "org-3"}},
        },
        source="GET /people/v2/me",
    )
    assert observed["organization_id"] == "org-3"
    assert resolve_fixture_id(manifest, "org3_admin.organization_id") == "org-3"
    manifest.save(path)

    loaded = FixtureManifest.load(path)
    assert loaded.require("org3_admin", "person_id") == "person-3"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema"] == "vigil-fixture-manifest/v1"
    assert list(tmp_path.glob("*.tmp")) == []


def test_observe_is_atomic_when_a_later_field_conflicts() -> None:
    manifest = FixtureManifest({"org3_admin": {"organization_id": "org-old"}})

    with pytest.raises(FixtureIdentityError, match="already binds"):
        manifest.observe(
            "org3_admin",
            {
                "data": {"type": "Person", "id": "person-new"},
                "organization_id": "org-new",
            },
        )

    assert manifest.records == {"org3_admin": {"organization_id": "org-old"}}


def test_fixture_names_may_contain_dots() -> None:
    manifest = FixtureManifest()
    manifest.record("org3.admin", "organization_id", "org-3")
    assert resolve_fixture_id(manifest, "org3.admin.organization_id") == "org-3"


def test_rotation_requires_new_alias_or_explicit_replace() -> None:
    manifest = FixtureManifest({"owned": {"organization_id": "org-old"}})
    with pytest.raises(FixtureIdentityError, match="already binds"):
        manifest.record("owned", "organization_id", "org-new")
    manifest.record("owned", "organization_id", "org-new", replace=True)
    assert manifest.require("owned", "organization_id") == "org-new"


@pytest.mark.parametrize("reference", ["", "owned", "owned.", "<name>.id"])
def test_invalid_references_and_placeholders_fail_closed(reference: str) -> None:
    manifest = FixtureManifest({"owned": {"organization_id": "org-1"}})
    with pytest.raises(FixtureIdentityError):
        resolve_fixture_id(manifest, reference)
