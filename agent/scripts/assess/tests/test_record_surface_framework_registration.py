"""B5 CLI side: ``record-surface --framework-registration``.

The flag carries the architecture axis (how the host framework discovers and
runs the code) and must stay independent of the positional semantic surface
type. Omitting it has to leave the wire payload byte-identical to today so an
existing web engagement records exactly what it always did.
"""
from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from assess.commands import record_surface
from assess.lib.contracts import FRAMEWORK_REGISTRATION_KINDS


class _RecordingClient:
    def __init__(self) -> None:
        self.payloads: list[dict] = []
        self.events: list[dict] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def post(self, _endpoint, payload):
        self.payloads.append(payload)
        return {
            "id": 1,
            "surface_type": payload["surface_type"],
            "target_descriptor": payload["target_descriptor"],
            "status": payload["status"],
        }

    def post_event(self, payload):
        self.events.append(payload)
        return {"id": 1}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    record_surface.register(parser.add_subparsers(dest="command"))
    return parser


def _args(tmp_path, **overrides) -> SimpleNamespace:
    base = {
        "type": "auth_entry",
        "target": "keycloak:authenticator/OtpFormAuthenticator",
        "source": "code-architecture-mapper",
        "rationale": "",
        "evidence_ref": "",
        "status": "discovered",
        "framework_registration": "",
        "engagement_dir": str(tmp_path),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


@pytest.fixture
def client(monkeypatch, tmp_path):
    recorder = _RecordingClient()
    monkeypatch.setattr(record_surface, "AssessmentClient", lambda *_a: recorder)
    monkeypatch.setattr(
        record_surface,
        "load_config",
        lambda _dir: SimpleNamespace(
            base_url="http://localhost:9999", engagement_key="k", engagement_dir=str(tmp_path)
        ),
    )
    return recorder


def test_framework_registration_is_sent_as_its_own_payload_key(client, tmp_path):
    record_surface.run(_args(tmp_path, framework_registration="service_provider"))

    payload = client.payloads[0]
    assert payload["framework_registration"] == "service_provider"
    # The semantic axis is unchanged by the architecture axis.
    assert payload["surface_type"] == "auth_entry"


def test_omitting_the_flag_leaves_the_payload_shape_unchanged(client, tmp_path):
    record_surface.run(_args(tmp_path))

    assert set(client.payloads[0]) == {
        "surface_type",
        "target_descriptor",
        "source_name",
        "rationale",
        "evidence_ref",
        "status",
    }


def test_parser_accepts_every_registered_kind_and_rejects_others(tmp_path):
    parser = _parser()

    for kind in FRAMEWORK_REGISTRATION_KINDS:
        parsed = parser.parse_args(
            [
                "record-surface",
                "auth_entry",
                "target",
                "source",
                "--framework-registration",
                kind,
            ]
        )
        assert parsed.framework_registration == kind

    with pytest.raises(SystemExit):
        parser.parse_args(
            [
                "record-surface",
                "auth_entry",
                "target",
                "source",
                "--framework-registration",
                "keycloak_authenticator",
            ]
        )


def test_registration_kinds_do_not_collide_with_semantic_surface_types():
    from assess.lib.surfaces import VALID_SURFACE_TYPES

    assert not set(FRAMEWORK_REGISTRATION_KINDS) & VALID_SURFACE_TYPES


def test_contract_documents_the_worked_framework_mappings():
    from assess.lib.contracts import render_contract

    rendered = render_contract("record-surface")

    for kind, worked_mapping in FRAMEWORK_REGISTRATION_KINDS.items():
        assert kind in rendered
        assert worked_mapping in rendered


def test_record_surface_is_discoverable_in_the_code_phases_that_use_it():
    """The architecture axis is a code-engagement primitive, so the verb has to
    appear in the code-phase catalog an operator lists. `operator-core-code.md`
    already routes surface recording through this verb; without the phase tags
    `vigil assess list-commands --phase code-classify` never names it."""
    from assess.lib.contracts import get_contract

    contract = get_contract("record-surface")
    assert contract is not None
    phases = set(contract.phase)

    assert {"code-classify", "code-hunt"} <= phases
    # The web phases it already served must stay.
    assert {"recon", "collect", "consume-test", "exploit"} <= phases
