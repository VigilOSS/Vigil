"""``vigil blue tier|verify|contain`` must reach a real finding write.

Every one of those three verbs annotates a finding by shelling out to
``vigil assess finding update`` / ``finding verify`` with ``--details-inline``,
and ``details`` is a CLOSED allow-list enforced on both the CLI and the server.
An unregistered annotation key is therefore not a cosmetic gap: the assess-side
validator refuses the payload before any write, so the blue verb exits non-zero
having recorded nothing.

The existing blue coverage could not see that. It monkeypatches ``_run_assess``
away and inspects the argv the wrapper *intended* to send, which stays correct
while the write at the other end is rejected. These cases keep the wrapper and
replace only the HTTP boundary: ``_run_assess`` dispatches into the REAL
``update_finding.run()`` / ``verify_finding.run()`` through the real argument
parsers, so the details contract is exercised exactly as it is in production.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pytest

from vigil_cli import blue

# ``agent/scripts`` holds the assess CLI the blue wrapper shells into. It is not
# an installed distribution, so put it on the path the way the assess suite's
# own conftest does (and ``vigil_cli.paths.add_assess_import_path`` does at
# runtime) before importing the commands under test.
_SCRIPTS_ROOT = Path(__file__).resolve().parents[1] / "agent" / "scripts"
if str(_SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_ROOT))

from assess.commands import update_finding, verify_finding  # noqa: E402


class _Cfg:
    def __init__(self, engagement_dir: Path) -> None:
        self.engagement_dir = str(engagement_dir)
        self.base_url = "http://backend.invalid"
        self.engagement_key = "acme-ir"


class _FakeClient:
    """The HTTP boundary, and nothing above it.

    Serves the one read the write paths make (the finding, for its
    ``row_version`` and canonical location) and records every write.
    """

    def __init__(self, finding: dict) -> None:
        self.finding = finding
        self.patches: list[tuple[str, dict]] = []
        self.posts: list[tuple[str, dict]] = []

    def get(self, path: str) -> dict:
        return dict(self.finding)

    def patch(self, path: str, payload: dict) -> dict:
        self.patches.append((path, payload))
        return {"finding": {**self.finding, "row_version": self.finding["row_version"] + 1}}

    def post(self, path: str, payload: dict) -> dict:
        self.posts.append((path, payload))
        return {"finding": dict(self.finding)}

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _assess_parser() -> argparse.ArgumentParser:
    """The real ``vigil assess finding <verb>`` parsers the wrapper targets."""
    parser = argparse.ArgumentParser(prog="vigil assess")
    parser.add_argument("--engagement-dir", dest="engagement_dir", default=None)
    sub = parser.add_subparsers(dest="command")
    finding = sub.add_parser("finding")
    finding_sub = finding.add_subparsers(dest="finding_action")
    update_finding.register(finding_sub)
    verify_finding.register(finding_sub)
    return parser


def _install(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, finding: dict) -> _FakeClient:
    fake = _FakeClient(finding)
    for module in (update_finding, verify_finding):
        monkeypatch.setattr(module, "load_config", lambda *a, **k: _Cfg(tmp_path))
        monkeypatch.setattr(module, "AssessmentClient", lambda *a, **k: fake)

    def run_assess(_root, eng_dir, assess_args, *, check: bool = True) -> int:
        if not assess_args or assess_args[0] != "finding":
            # The wrapper composes several assess verbs per blue verb (activity
            # log rows, artifact registration). Only the finding writes are
            # under test; the rest succeed as they do in production.
            return 0
        args = _assess_parser().parse_args(
            ["--engagement-dir", str(eng_dir), *assess_args]
        )
        try:
            args.func(args)
        except SystemExit as exc:
            code = exc.code
            return int(code) if isinstance(code, int) else 1
        return 0

    monkeypatch.setattr(blue, "_run_assess", run_assess)
    monkeypatch.setattr(blue, "_resolve_blue_engagement", lambda *_a: tmp_path)
    monkeypatch.setattr(blue, "_read_scope", lambda *_a, **_k: {"engagement_type": "blue"})
    return fake


def _finding(**over) -> dict:
    row = {
        "slug": "FIND-001",
        "id": 11,
        "title": "Suspicious OAuth grant on acme.example",
        "row_version": 3,
        "canonical_location": "https://admin.acme.example/oauth/grants",
        "provenance": {"agent_id": "TRIAGE-1"},
        "details": {},
    }
    row.update(over)
    return row


def _counter_check(tmp_path: Path) -> str:
    path = tmp_path / "counter-check.json"
    path.write_text(
        json.dumps(
            {
                "method": "Replayed the grant with the tenant allowlist applied",
                "expected_result": "Grant refused",
                "observed_result": "Grant refused; the alert fired on a documented pattern",
                "falsified_claim": "The OAuth grant was adversarial",
                "completed": True,
                "proof_receipt_ids": [7],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def _confirm_check(tmp_path: Path) -> str:
    path = tmp_path / "confirm-check.json"
    path.write_text(
        json.dumps(
            {
                "method": "Replayed the grant from an unprivileged session",
                "attempted_falsification": "Tried to attribute the grant to the tenant allowlist",
                "expected_result": "Allowlist explains the grant",
                "observed_result": "Allowlist does not cover the client_id; the grant stands",
                "completed": True,
                "proof_receipt_ids": [7],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def test_blue_tier_lands_its_annotation_on_the_finding(tmp_path, monkeypatch, capsys):
    fake = _install(monkeypatch, tmp_path, _finding())
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        tier="L3",
        notes="L2 corroborated the grant; handing to independent verification.",
    )

    blue._cmd_tier(args, tmp_path)
    capsys.readouterr()

    assert len(fake.patches) == 1, "blue tier recorded nothing"
    path, payload = fake.patches[0]
    assert path == "findings/FIND-001"
    assert payload["details"]["tier"] == "L3"
    assert payload["details"]["tier_notes"].startswith("L2 corroborated")


@pytest.mark.parametrize("disposition", ["verified", "downgraded", "escalated"])
def test_blue_verify_lands_its_annotation_on_the_finding(
    tmp_path, monkeypatch, capsys, disposition
):
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(blue, "_has_verifier_dispatch_for", lambda *_a: True)
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        disposition=disposition,
        reason="Independent verification reproduced the grant from a clean session.",
        evidence_refs="ir/oauth-grant.json,ir/login-events.csv",
        proof_receipt_ids=[7],
        counter_check_file=None,
        confirm_check_file=(
            _confirm_check(tmp_path) if disposition in {"verified", "downgraded"} else None
        ),
        kill_reason=None,
        kill_check=None,
        new_severity="low" if disposition == "downgraded" else None,
        force=False,
    )

    blue._cmd_verify(args, tmp_path)
    capsys.readouterr()

    assert len(fake.posts) == 1, f"blue verify --disposition {disposition} recorded nothing"
    path, payload = fake.posts[0]
    assert path == "findings/FIND-001/verify"
    assert payload["details"]["disposition"] == disposition
    assert payload["details"]["evidence_refs"] == [
        "ir/oauth-grant.json",
        "ir/login-events.csv",
    ]


def test_blue_verify_false_positive_carries_the_kill_the_backend_demands(
    tmp_path, monkeypatch, capsys
):
    """A kill needs ``details.kill_reason`` + ``details.kill_check`` server-side.

    Without flags for them the wrapper could only ever send a counter-check,
    which the backend rejects for a false-positive verdict.
    """
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(blue, "_has_verifier_dispatch_for", lambda *_a: True)
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        disposition="false_positive",
        reason="Documented tenant pattern; the allowlist covers this client_id.",
        evidence_refs=None,
        proof_receipt_ids=None,
        counter_check_file=_counter_check(tmp_path),
        kill_reason="Check 3 showed the client_id on the tenant allowlist.",
        kill_check=3,
        new_severity=None,
        force=False,
    )

    blue._cmd_verify(args, tmp_path)
    capsys.readouterr()

    assert len(fake.posts) == 1, "blue verify --disposition false_positive recorded nothing"
    _path, payload = fake.posts[0]
    assert payload["details"]["kill_reason"].startswith("Check 3")
    assert payload["details"]["kill_check"] == 3
    assert payload["counter_check"]["completed"] is True


@pytest.mark.parametrize("disposition", ["verified", "downgraded"])
def test_blue_verify_without_a_falsification_check_stops_at_the_real_refusal(
    tmp_path, monkeypatch, capsys, disposition
):
    """``finding verify`` refuses confirmed/downgraded with no completed check.

    The wrapper had no ``--confirm-check-file`` flag at all, so there was no
    invocation of ``vigil blue verify --disposition verified`` that could reach a
    write. The refusal stays with the verb that owns the gate; what this pins is
    that the wrapper reaches it and records nothing.
    """
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(blue, "_has_verifier_dispatch_for", lambda *_a: True)
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        disposition=disposition,
        reason="Reproduced from a clean session.",
        evidence_refs=None,
        proof_receipt_ids=[7],
        counter_check_file=None,
        confirm_check_file=None,
        kill_reason=None,
        kill_check=None,
        new_severity="low" if disposition == "downgraded" else None,
        force=False,
    )

    with pytest.raises(SystemExit) as exit_info:
        blue._cmd_verify(args, tmp_path)

    assert exit_info.value.code == 1
    assert "--confirm-check-file" in capsys.readouterr().err
    assert fake.posts == []


def test_blue_verify_refuses_a_kill_reason_on_a_surviving_finding(tmp_path, monkeypatch):
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(blue, "_has_verifier_dispatch_for", lambda *_a: True)
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        disposition="verified",
        reason="Reproduced from a clean session.",
        evidence_refs=None,
        proof_receipt_ids=[7],
        counter_check_file=None,
        confirm_check_file=_confirm_check(tmp_path),
        kill_reason="Check 3 cleared it.",
        kill_check=3,
        new_severity=None,
        force=False,
    )

    with pytest.raises(SystemExit, match="false_positive"):
        blue._cmd_verify(args, tmp_path)
    assert fake.posts == []


def test_blue_verify_refuses_a_confirm_check_on_a_false_positive(tmp_path, monkeypatch):
    """The exact inverse of the kill-reason guard, and the same contradiction.

    ``--confirm-check-file`` carries the falsification a SURVIVING finding
    withstood, so pairing it with a kill is operator confusion about which check
    the verdict rests on. The false-positive branch must say so rather than
    accept a flag it never forwards: the counter-check it does send would make
    the write look like the operator's invocation succeeded as written.
    """
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(blue, "_has_verifier_dispatch_for", lambda *_a: True)
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        disposition="false_positive",
        reason="Documented tenant pattern; the allowlist covers this client_id.",
        evidence_refs=None,
        proof_receipt_ids=None,
        counter_check_file=_counter_check(tmp_path),
        confirm_check_file=_confirm_check(tmp_path),
        kill_reason="Check 3 showed the client_id on the tenant allowlist.",
        kill_check=3,
        new_severity=None,
        force=False,
    )

    with pytest.raises(SystemExit, match="--confirm-check-file"):
        blue._cmd_verify(args, tmp_path)
    assert fake.posts == []


def test_blue_contain_lands_its_annotation_on_the_finding(tmp_path, monkeypatch, capsys):
    fake = _install(monkeypatch, tmp_path, _finding())
    monkeypatch.setattr(
        blue,
        "_fetch_containment_decision",
        lambda *_a: {
            "resolved": True,
            "payload": {
                "finding_slug": "FIND-001",
                "action": "revoke_session",
                "target": "jsmith@acme.example",
                "platform": "gws",
            },
        },
    )
    monkeypatch.setattr(
        blue,
        "_fetch_command_run",
        lambda *_a: {
            "route": "host_exec",
            "phase": "respond",
            "technique": "CONTAINMENT",
            "success": True,
            "finding_id": 11,
            "intent": "containment proposal=42 action=revoke_session",
            "argv": ["gam", "user", "jsmith@acme.example", "signout"],
        },
    )
    monkeypatch.setattr(
        blue, "_fetch_containment_finding", lambda *_a: {"id": 11, "slug": "FIND-001"}
    )
    args = argparse.Namespace(
        engagement_key="acme-ir",
        select=False,
        finding_slug="FIND-001",
        proposal="42",
        action=None,
        target=None,
        proof_artifact=None,
        command_run_id=73,
    )

    blue._cmd_contain(args, tmp_path)
    capsys.readouterr()

    assert len(fake.patches) == 1, "blue contain recorded nothing"
    _path, payload = fake.patches[0]
    assert payload["workflow_status"] == "contained"
    assert payload["details"]["containment_status"] == "contained"
    assert payload["details"]["containment_action"] == "revoke_session"
    assert payload["details"]["containment_command_run_id"] == 73


def test_the_incident_verifier_copy_paste_details_are_writable(tmp_path, monkeypatch, capsys):
    """``agent/agents/incident-verifier.md`` hands out these two keys verbatim.

    They are offered as a copy-paste ``finding verify --details-inline``, so a
    verifier that follows the role file must be able to record them.
    """
    fake = _install(monkeypatch, tmp_path, _finding())
    details = {
        "checks": [
            {
                "check": 1,
                "result": "PASS",
                "evidence_ref": "ir/oauth-grant.json",
                "rationale": "Grant is outside the allowlist.",
            }
        ],
        "devils_advocate": [
            {
                "hypothesis": "A tenant admin granted it deliberately.",
                "counter_evidence_ref": "ir/admin-audit.csv",
                "discharged": True,
            }
        ],
    }
    args = _assess_parser().parse_args(
        [
            "--engagement-dir",
            str(tmp_path),
            "finding",
            "verify",
            "FIND-001",
            "--status",
            "confirmed",
            "--reason",
            "Independent verification reproduced the grant.",
            "--proof-receipt-id",
            "7",
            "--confirm-check-file",
            _confirm_check(tmp_path),
            "--details-inline",
            json.dumps(details),
        ]
    )

    args.func(args)
    capsys.readouterr()

    assert len(fake.posts) == 1
    _path, payload = fake.posts[0]
    assert payload["details"]["checks"][0]["result"] == "PASS"
    assert payload["details"]["devils_advocate"][0]["discharged"] is True


@pytest.mark.parametrize(
    "key",
    [
        "network_window_utc",
        "coverage",
        "cross_skill_correlation_ids",
        "disposition_recommendation",
        "respond_review",
    ],
)
def test_the_blue_skill_instructed_details_are_writable(tmp_path, monkeypatch, capsys, key):
    """Five more keys a blue skill or role file tells a specialist to record."""
    fake = _install(monkeypatch, tmp_path, _finding())
    values = {
        "network_window_utc": ["2026-09-08T00:00:00Z", "2026-10-08T00:00:00Z"],
        "coverage": {"flows": 182_340, "bytes_out": 9_912_311, "retention_days": 30},
        "cross_skill_correlation_ids": ["EDR-004"],
        "disposition_recommendation": "confirmed",
        "respond_review": "No containment warranted: the grant was revoked by the tenant.",
    }
    args = _assess_parser().parse_args(
        [
            "--engagement-dir",
            str(tmp_path),
            "finding",
            "update",
            "FIND-001",
            "--details-inline",
            json.dumps({key: values[key]}),
            "--reason",
            "blue annotation",
        ]
    )

    args.func(args)
    capsys.readouterr()

    assert len(fake.patches) == 1
    _path, payload = fake.patches[0]
    assert payload["details"][key] == values[key]
