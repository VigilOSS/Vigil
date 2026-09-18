"""B5: framework/registration kind is a second axis, not a surface type.

The shared semantic surface types describe security *meaning* and are
deliberately cross-engagement. A Keycloak authenticator, a realm REST
provider, a user-storage SPI and a theme override are *architecture* labels:
they say how the host framework discovers and runs plugin code, not what the
code means for an attacker. Folding one into the other would corrupt the
taxonomy, so ``framework_registration`` is a separate optional column that no
surface-type-keyed behaviour reads.
"""
from __future__ import annotations

import sqlite3

import pytest

from app import db as db_module
from app.api.assessment import SurfaceRecordRequest
from app.services.state_manager.app_units import (
    _AUTH_SURFACE_TYPES,
    _DECISIVE_SURFACE_TYPES,
)
from app.services.state_manager.coverage import HIGH_RISK_DEFERRED_SURFACE_TYPES
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-09-16-surface-framework-registration"
ASSESSMENT_BASE = f"/engagements/{ENGAGEMENT_KEY}/assessment"


def _literal_values(model, field_name: str) -> set[str]:
    annotation = model.model_fields[field_name].annotation
    return {str(value) for value in getattr(annotation, "__args__", ())}


def _seed(client, isolate_settings) -> None:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    assert client.get(f"/engagements/{ENGAGEMENT_KEY}").status_code == 200


def test_recorded_surface_persists_a_framework_registration_kind(
    client, isolate_settings
):
    _seed(client, isolate_settings)

    created = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "auth_entry",
            "target_descriptor": "keycloak:authenticator/OtpFormAuthenticator",
            "source_name": "code-architecture-mapper",
            "rationale": "Realm browser-flow authenticator registered through the SPI factory.",
            "framework_registration": "service_provider",
        },
    )
    assert created.status_code == 201, created.text
    assert created.json()["framework_registration"] == "service_provider"
    # The semantic axis is untouched by the architecture axis.
    assert created.json()["surface_type"] == "auth_entry"

    listed = client.get(f"{ASSESSMENT_BASE}/surfaces")
    assert listed.status_code == 200, listed.text
    assert listed.json()[0]["framework_registration"] == "service_provider"


def test_framework_registration_defaults_to_unset_and_survives_re_record(
    client, isolate_settings
):
    _seed(client, isolate_settings)

    plain = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "dynamic_render",
            "target_descriptor": "https://target.example/search",
            "source_name": "surface-collector",
        },
    )
    assert plain.status_code == 201, plain.text
    assert plain.json()["framework_registration"] == ""

    labelled = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "dynamic_render",
            "target_descriptor": "https://target.example/search",
            "source_name": "surface-collector",
            "framework_registration": "template_override",
        },
    )
    assert labelled.status_code == 201, labelled.text
    assert labelled.json()["framework_registration"] == "template_override"

    # An omitted kind on a later observation must never erase a recorded one —
    # the same COALESCE/NULLIF rule the upsert already applies to source_name.
    silent = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "dynamic_render",
            "target_descriptor": "https://target.example/search",
            "source_name": "surface-collector",
        },
    )
    assert silent.status_code == 201, silent.text
    assert silent.json()["framework_registration"] == "template_override"


def test_unregistered_framework_registration_kind_is_rejected(
    client, isolate_settings
):
    _seed(client, isolate_settings)

    response = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "auth_entry",
            "target_descriptor": "https://target.example/login",
            "source_name": "surface-collector",
            "framework_registration": "keycloak_authenticator",
        },
    )
    assert response.status_code == 422, response.text


def test_framework_registration_does_not_change_surface_type_keyed_behaviour():
    """The three behaviours B5 must not disturb key on surface_type alone."""
    registration_kinds = _literal_values(
        SurfaceRecordRequest, "framework_registration"
    )

    assert not registration_kinds & _DECISIVE_SURFACE_TYPES
    assert not registration_kinds & _AUTH_SURFACE_TYPES
    assert not registration_kinds & HIGH_RISK_DEFERRED_SURFACE_TYPES
    assert not registration_kinds & _literal_values(
        SurfaceRecordRequest, "surface_type"
    )


def test_framework_registration_vocabulary_mirrors_the_cli():
    from assess.lib.contracts import FRAMEWORK_REGISTRATION_KINDS

    assert _literal_values(SurfaceRecordRequest, "framework_registration") == (
        set(FRAMEWORK_REGISTRATION_KINDS) | {""}
    )


def test_semantic_surface_types_still_mirror_the_cli_vocabulary():
    """B5 adds an axis; it must not add, drop, or rename a semantic type."""
    from assess.lib.surfaces import VALID_SURFACE_TYPES

    assert _literal_values(SurfaceRecordRequest, "surface_type") == set(
        VALID_SURFACE_TYPES
    )


def test_migration_adds_framework_registration_to_a_legacy_surfaces_table(
    client, isolate_settings
):
    """A surfaces table written before B5 must open, migrate, and read back.

    Driven through the real ``init_db`` upgrade path with the column removed
    again, because that is the sequence an operator's existing database takes
    on the next backend start.
    """
    _seed(client, isolate_settings)
    created = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": "auth_entry",
            "target_descriptor": "https://legacy.example/login",
            "source_name": "surface-collector",
        },
    )
    assert created.status_code == 201, created.text

    db_path = isolate_settings["data_dir"] / "orchestrator.sqlite3"
    with sqlite3.connect(str(db_path)) as legacy:
        legacy.execute(
            "ALTER TABLE assessment_surfaces DROP COLUMN framework_registration"
        )
        assert "framework_registration" not in {
            row[1] for row in legacy.execute("PRAGMA table_info(assessment_surfaces)")
        }

    db_module.init_db()
    # Idempotent: a second open of the already-migrated file changes nothing.
    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        rows = [
            row[0]
            for row in connection.execute(
                "SELECT framework_registration FROM assessment_surfaces"
            )
        ]

    assert rows == [""]


@pytest.mark.parametrize(
    ("registration_kind", "surface_type"),
    (
        ("service_provider", "auth_entry"),
        ("http_endpoint", "privileged_write"),
        ("template_override", "dynamic_render"),
        ("event_listener", "workflow_token"),
    ),
)
def test_every_registration_kind_composes_with_any_semantic_type(
    client, isolate_settings, registration_kind, surface_type
):
    """The two axes are free: any kind may carry any security meaning."""
    _seed(client, isolate_settings)

    response = client.post(
        f"{ASSESSMENT_BASE}/surfaces",
        json={
            "surface_type": surface_type,
            "target_descriptor": f"keycloak:{registration_kind}/{surface_type}",
            "source_name": "code-architecture-mapper",
            "framework_registration": registration_kind,
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    assert payload["surface_type"] == surface_type
    assert payload["framework_registration"] == registration_kind
