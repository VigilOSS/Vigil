"""Derivable provenance is derived, and a code finding parks in one call.

Three round trips the finding lifecycle charged the caller for nothing:

1. Recording a code finding and then parking it at ``pending_runtime_proof``
   was always two invocations, because ``finding record`` pins the axis to
   ``unreviewed`` and only ``finding verify`` may move it.
2. ``provenance.code_snapshot`` is three mechanical values the caller could only
   transcribe from Code Source Identity. The backend already holds them.
3. ``provenance.agent_id`` is what the backend resolves into the stored
   ``code_snapshot_attestation``. The documented verify invocation omitted it,
   so every documented verification stored an attestation reading ``unattested``
   — a binding with nothing behind it.
"""
from __future__ import annotations

import json

import pytest

from assess import cli
from assess.lib import config
from assess.lib.client import AssessmentClient


_DIGEST = "ab" * 32
_NEXT_DIGEST = "cd" * 32


_PLAN = {
    "hypothesis": "The parser copies an attacker-controlled length.",
    "confirm_if": "An oversized length crashes the harness.",
    "falsify_if": "The length is clamped before the copy.",
    "route_hint": "local",
    "prerequisites": "",
}


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    (tmp_path / "next-test.json").write_text(json.dumps(_PLAN), encoding="utf-8")
    return tmp_path


def _file_finding_payload() -> dict:
    return {
        "title": "Unchecked parser length",
        "severity": "high",
        "defect_family": "buffer-overflow",
        "root_cause_key": "parse_packet-length",
        "canonical_location": "file:src/parser.c:41",
        "summary": "An attacker-controlled length reaches a fixed-size copy.",
        "details": {
            "evidence": "The copy length is attacker controlled.",
            "impact": "Memory corruption",
        },
    }


class _Backend:
    """Minimal stand-in for the assessment routes these two verbs touch."""

    def __init__(self, *, finding: dict | None = None, repos: list[dict] | None = None):
        self.posts: list[tuple[str, dict]] = []
        self.finding = finding or {}
        self.repos = repos if repos is not None else [
            {
                "id": 7,
                "repo_key": "bound-repo",
                "active_generation": 3,
                "source_manifest_digest": _DIGEST,
                "source_snapshot_quality": "verified",
            }
        ]

    def get(self, endpoint: str):
        if endpoint == "findings":
            return []
        if endpoint == "code/repos":
            return list(self.repos)
        if endpoint.startswith("code/repos/"):
            repo_id = int(endpoint.rsplit("/", 1)[1])
            for repo in self.repos:
                if int(repo["id"]) == repo_id:
                    return dict(repo)
            raise AssertionError(f"unexpected repo id {repo_id}")
        if endpoint.startswith("dispatches/"):
            return {"agent_id": endpoint.split("/", 1)[1]}
        if endpoint.startswith("findings/"):
            return dict(self.finding)
        raise AssertionError(f"unexpected GET {endpoint}")

    def post(self, endpoint: str, payload: dict):
        self.posts.append((endpoint, payload))
        if endpoint == "findings":
            return {
                "finding": {
                    "slug": payload["slug"],
                    "title": payload["title"],
                    "verification_status": payload["verification_status"],
                },
                "transition": {"action": "recorded"},
            }
        return {
            "finding": {
                "slug": endpoint.split("/")[1],
                "title": "Unchecked parser length",
                "verification_status": payload.get("verification_status", ""),
            },
            "transition": {"action": "verified"},
        }

    def install(self, monkeypatch) -> None:
        monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
        monkeypatch.setattr(AssessmentClient, "get", self.get)
        monkeypatch.setattr(AssessmentClient, "post", self.post)
        monkeypatch.setattr(
            AssessmentClient, "post_event", lambda *_args, **_kwargs: None
        )

    def payload_for(self, endpoint: str) -> dict:
        for posted_endpoint, payload in self.posts:
            if posted_endpoint == endpoint:
                return payload
        raise AssertionError(f"no POST to {endpoint} in {[e for e, _ in self.posts]}")


# ── 1. record + park in one call ─────────────────────────────────────────────


def test_record_can_park_a_code_finding_at_pending_runtime_proof(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend()
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "record",
            "code-vuln-hunter",
            str(json_file),
            "--agent-id",
            "CH-1",
            "--pending-runtime-proof",
            "Static dataflow only; no runtime trigger yet.",
            "--next-test-file",
            str(engagement / "next-test.json"),
            "--allow-unindexed-evidence",
        ]
    )

    out = capsys.readouterr().out
    assert out.strip() == "CH-001"
    park = backend.payload_for("findings/CH-001/verify")
    assert park["verification_status"] == "pending_runtime_proof"
    assert park["reason_text"] == "Static dataflow only; no runtime trigger yet."
    assert park["next_test"] == _PLAN
    # The park is a write against a file: finding, so it carries the same
    # derived binding and the same author identity the record did.
    assert park["provenance"]["agent_id"] == "CH-1"
    assert park["provenance"]["code_snapshot"] == {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": _DIGEST,
    }


def test_a_record_without_the_park_flag_still_makes_exactly_one_write(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend()
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "record",
            "code-vuln-hunter",
            str(json_file),
            "--agent-id",
            "CH-1",
            "--allow-unindexed-evidence",
        ]
    )

    capsys.readouterr()
    assert [endpoint for endpoint, _ in backend.posts] == ["findings"]


# ── 2. derivable provenance is derived ───────────────────────────────────────


def test_record_derives_the_code_snapshot_binding_for_a_file_finding(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend()
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "record",
            "code-vuln-hunter",
            str(json_file),
            "--agent-id",
            "CH-1",
            "--allow-unindexed-evidence",
        ]
    )

    capsys.readouterr()
    recorded = backend.payload_for("findings")
    assert recorded["provenance"]["code_snapshot"] == {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": _DIGEST,
    }
    assert recorded["provenance"]["agent_id"] == "CH-1"


def test_record_never_overwrites_an_authored_binding(
    tmp_path, monkeypatch, capsys
) -> None:
    """An explicitly authored binding wins — including a stale one, which the
    backend must still be free to refuse."""
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    authored = _file_finding_payload()
    authored["provenance"] = {
        "code_snapshot": {
            "repo_id": 7,
            "repo_generation": 2,
            "source_manifest_digest": _NEXT_DIGEST,
        }
    }
    json_file.write_text(json.dumps(authored), encoding="utf-8")
    backend = _Backend()
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "record",
            "code-vuln-hunter",
            str(json_file),
            "--agent-id",
            "CH-1",
            "--allow-unindexed-evidence",
        ]
    )

    capsys.readouterr()
    assert backend.payload_for("findings")["provenance"]["code_snapshot"] == {
        "repo_id": 7,
        "repo_generation": 2,
        "source_manifest_digest": _NEXT_DIGEST,
    }


def test_record_leaves_a_url_finding_unbound(tmp_path, monkeypatch, capsys) -> None:
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    web = _file_finding_payload()
    web["canonical_location"] = "https://target.example/search?q"
    json_file.write_text(json.dumps(web), encoding="utf-8")
    backend = _Backend()
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "record",
            "vulnerability-analyst",
            str(json_file),
            "--agent-id",
            "VA-RUN-1",
            "--allow-unindexed-evidence",
        ]
    )

    capsys.readouterr()
    assert "code_snapshot" not in backend.payload_for("findings")["provenance"]


def test_record_refuses_to_guess_between_several_active_repositories(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    json_file = engagement / "finding.json"
    json_file.write_text(json.dumps(_file_finding_payload()), encoding="utf-8")
    backend = _Backend(
        repos=[
            {
                "id": 7,
                "repo_key": "bound-repo",
                "active_generation": 3,
                "source_manifest_digest": _DIGEST,
                "source_snapshot_quality": "verified",
            },
            {
                "id": 8,
                "repo_key": "other-repo",
                "active_generation": 1,
                "source_manifest_digest": _NEXT_DIGEST,
                "source_snapshot_quality": "verified",
            },
        ]
    )
    backend.install(monkeypatch)

    with pytest.raises(SystemExit) as exit_info:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "finding",
                "record",
                "code-vuln-hunter",
                str(json_file),
                "--agent-id",
                "CH-1",
                "--allow-unindexed-evidence",
            ]
        )

    assert exit_info.value.code == 1
    err = capsys.readouterr().err
    assert "bound-repo" in err and "other-repo" in err
    assert "provenance.code_snapshot" in err
    assert backend.posts == []


def test_verify_stamps_the_verifier_dispatch_as_the_attesting_identity(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1", "code_snapshot": {"repo_id": 7}},
        }
    )
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "verify",
            "CH-001",
            "--status",
            "pending_runtime_proof",
            "--next-test-file",
            str(engagement / "next-test.json"),
            "--reason",
            "Re-read the current sealed source; runtime trigger still owed.",
            "--agent-id",
            "VF-1",
        ]
    )

    capsys.readouterr()
    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["agent_id"] == "VF-1"
    assert provenance["code_snapshot"] == {
        "repo_id": 7,
        "repo_generation": 3,
        "source_manifest_digest": _DIGEST,
    }


def test_verify_lets_an_explicit_provenance_inline_win(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "CH-001",
            "canonical_location": "file:src/parser.c:41",
            "provenance": {"agent_id": "CH-1", "code_snapshot": {"repo_id": 7}},
        }
    )
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "verify",
            "CH-001",
            "--status",
            "pending_runtime_proof",
            "--next-test-file",
            str(engagement / "next-test.json"),
            "--reason",
            "Rebinding by hand.",
            "--agent-id",
            "VF-1",
            "--provenance-inline",
            json.dumps(
                {
                    "agent_id": "VF-2",
                    "code_snapshot": {
                        "repo_id": 7,
                        "repo_generation": 2,
                        "source_manifest_digest": _NEXT_DIGEST,
                    },
                }
            ),
        ]
    )

    capsys.readouterr()
    provenance = backend.payload_for("findings/CH-001/verify")["provenance"]
    assert provenance["agent_id"] == "VF-2"
    assert provenance["code_snapshot"]["repo_generation"] == 2


def test_verify_leaves_a_url_finding_unbound(tmp_path, monkeypatch, capsys) -> None:
    engagement = _engagement(tmp_path)
    backend = _Backend(
        finding={
            "slug": "VA-001",
            "canonical_location": "https://target.example/search?q",
            "provenance": {"agent_id": "VA-RUN-1"},
        }
    )
    backend.install(monkeypatch)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "finding",
            "verify",
            "VA-001",
            "--status",
            "pending_runtime_proof",
            "--next-test-file",
            str(engagement / "next-test.json"),
            "--reason",
            "Runtime proof still owed.",
            "--agent-id",
            "VF-1",
        ]
    )

    capsys.readouterr()
    provenance = backend.payload_for("findings/VA-001/verify")["provenance"]
    assert provenance == {"agent_id": "VF-1"}


def test_a_stale_binding_is_never_derived_for_the_verifier(
    tmp_path, monkeypatch, capsys
) -> None:
    """Rebinding a superseded snapshot stays a deliberate act.

    `disputed` and `blocked` need no proof receipt, so if the CLI derived the
    current binding here, an administrative status change would clear the
    report-readiness stale blocker with nobody having re-read the new bytes.
    Record-time and legacy-unbound derivation stay automatic; a rebind does not.
    """

    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    posted: list[dict] = []

    def get(_client, endpoint: str):
        if endpoint == "findings/VA-001":
            return {
                "slug": "VA-001",
                "canonical_location": "file:src/app.py:42",
                "code_snapshot_status": "stale",
                "provenance": {
                    "code_snapshot": {
                        "repo_id": 7,
                        "repo_generation": 2,
                        "source_manifest_digest": "a" * 64,
                    }
                },
            }
        raise AssertionError(endpoint)

    monkeypatch.setattr(AssessmentClient, "get", get)
    monkeypatch.setattr(
        AssessmentClient,
        "post",
        lambda _c, _e, payload: posted.append(payload),
    )

    with pytest.raises(SystemExit):
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "finding",
                "verify",
                "VA-001",
                "--status",
                "disputed",
                "--agent-id",
                "VF-1",
                "--reason",
                "An administrative status change must not silently rebind.",
            ]
        )
    stderr = capsys.readouterr().err
    assert "superseded source snapshot" in stderr
    assert "--provenance-inline" in stderr
    assert posted == []
