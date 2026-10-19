"""CLI-boundary guards for `vigil assess finding update`.

Two defects live here, both of the same family — a write that reports success
while the thing it claimed to write is not what landed:

  * `--details-inline {"impact": ""}` returned HTTP 200 and bumped row_version
    while the content stayed put, because the backend details merge discards
    null/""/[]/{} values. A rendered submission kept a dead `**Run:** bash poc.sh`
    line long after an update had reported clearing it. The rejection lives at the
    CLI, not in the merge: `merge_findings` deliberately relies on the empty-drop,
    and a naive-merge experiment passed the whole backend suite, so a change there
    would not be caught by CI.
  * `--evidence-ref` accepted a URL / composite / prose ref with no complaint,
    while `finding record` had warned about exactly those shapes for a while. The
    check WARNs and lets the write land — blocking an update mid-hunt risks losing
    work, and report-readiness is the terminal backstop.
"""
from __future__ import annotations

import argparse

import pytest

from assess.commands import update_finding


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient:
    def __init__(self) -> None:
        self.patches: list[tuple[str, dict]] = []

    def get(self, path: str) -> dict:
        return {"slug": path.split("/", 1)[-1], "row_version": 3}

    def patch(self, path: str, payload: dict) -> dict:
        self.patches.append((path, payload))
        return {
            "finding": {
                "slug": path.split("/", 1)[-1],
                "row_version": 4,
            }
        }

    def __enter__(self) -> "_FakeClient":
        return self

    def __exit__(self, *exc) -> bool:
        return False

    def close(self) -> None:  # pragma: no cover - trivial
        pass


def _parse(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    update_finding.register(sub)
    args = parser.parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _install(monkeypatch, tmp_path, fake: _FakeClient) -> None:
    monkeypatch.setattr(update_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *a, **k: fake)


# -- Defect: --details-inline empty values silently no-op ----------------------


@pytest.mark.parametrize(
    "inline",
    [
        '{"impact": ""}',
        '{"run": null}',
        '{"references": []}',
        '{"poc_request": {}}',
        '{"evidence": "real", "impact": ""}',  # partial silent failure
    ],
)
def test_details_inline_empty_value_is_rejected_not_silently_dropped(
    tmp_path, monkeypatch, capsys, inline
):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["update", "VA-001", "--details-inline", inline], str(tmp_path))

    with pytest.raises(SystemExit) as exc:
        update_finding.run(args)

    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "silently discarded" in err
    assert "--details-replace" in err  # names the mechanism that DOES clear a key
    # Nothing was written: no PATCH, so no phantom row_version bump.
    assert fake.patches == []


def test_details_inline_with_content_still_patches(tmp_path, monkeypatch, capsys):
    """The guard is a no-op detector, not a tax on every details update."""
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["update", "VA-001", "--details-inline", '{"impact": "PII disclosure."}'],
        str(tmp_path),
    )

    update_finding.run(args)
    capsys.readouterr()

    assert len(fake.patches) == 1
    assert fake.patches[0][1]["details"] == {"impact": "PII disclosure."}


def test_details_replace_may_still_clear_a_key_with_an_empty_value(
    tmp_path, monkeypatch, capsys
):
    """--details-replace overwrites the object wholesale — an empty value is real there.

    This is the documented, verified way to clear a details key, so the guard must
    not take it away.
    """
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        [
            "update", "VA-001",
            "--details-inline", '{"evidence": "kept", "run": ""}',
            "--details-replace",
            "--expected-row-version", "3",
        ],
        str(tmp_path),
    )

    update_finding.run(args)
    capsys.readouterr()

    assert len(fake.patches) == 1
    payload = fake.patches[0][1]
    assert payload["details_mode"] == "replace"
    assert payload["details"] == {"evidence": "kept", "run": ""}


def test_payload_file_details_merge_is_guarded_too(tmp_path, monkeypatch, capsys):
    """The payload-file door reaches the same merge, so it gets the same guard."""
    payload_file = tmp_path / "patch.json"
    payload_file.write_text(
        '{"details": {"impact": ""}, "expected_row_version": 3}', encoding="utf-8"
    )
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["update", "VA-001", "--payload-file", str(payload_file)], str(tmp_path)
    )

    with pytest.raises(SystemExit):
        update_finding.run(args)

    assert "silently discarded" in capsys.readouterr().err
    assert fake.patches == []


# -- Defect: evidence_ref shape unchecked on the update path -------------------


@pytest.mark.parametrize(
    ("ref", "marker"),
    [
        ("scans/a.txt;scans/b.txt", "is not a single engagement-local path"),
        ("command-runs 56052/56054/56060", "is not a single engagement-local path"),
        ("https://example.test/proof", "is a URL, not a registered artifact path"),
        ("see the notes", "is not a single engagement-local path"),
        ("scans/does-not-exist.txt", "looks like a path but nothing exists there"),
    ],
)
def test_malformed_evidence_ref_warns_and_still_writes(
    tmp_path, monkeypatch, capsys, ref, marker
):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["update", "VA-001", "--evidence-ref", ref], str(tmp_path))

    update_finding.run(args)

    err = capsys.readouterr().err
    assert "finding update: warning" in err
    assert marker in err
    # HARNESS, NOT GATE: the update still lands.
    assert len(fake.patches) == 1
    assert fake.patches[0][1]["evidence_ref"] == ref


def test_existing_engagement_file_evidence_ref_is_silent(tmp_path, monkeypatch, capsys):
    (tmp_path / "scans").mkdir()
    (tmp_path / "scans" / "idor.txt").write_text("proof", encoding="utf-8")
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["update", "VA-001", "--evidence-ref", "scans/idor.txt"], str(tmp_path))

    update_finding.run(args)

    assert "warning" not in capsys.readouterr().err
    assert len(fake.patches) == 1


def test_directory_evidence_ref_is_accepted_not_warned(tmp_path, monkeypatch, capsys):
    """A directory of captured evidence is a valid ref — existence, not file-ness.

    Keeps this path in lock-step with `finding record` and the backend indexer,
    which both accept a directory (`vigil assess artifact register <dir>`).
    """
    (tmp_path / "scans" / "burp-capture").mkdir(parents=True)
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(
        ["update", "VA-001", "--evidence-ref", "scans/burp-capture"], str(tmp_path)
    )

    update_finding.run(args)

    assert "warning" not in capsys.readouterr().err
    assert len(fake.patches) == 1


def test_update_carries_editor_without_changing_author(tmp_path, monkeypatch):
    fake = _FakeClient()
    _install(monkeypatch, tmp_path, fake)
    args = _parse(["update", "VA-001", "--agent-id", "VERIFY-1",
                   "--details-inline", '{"steps_to_reproduce": "Replay the supported Acme API"}'], str(tmp_path))
    update_finding.run(args)
    assert fake.patches[0][1]["dispatch_agent_id"] == "VERIFY-1"
    assert "provenance" not in fake.patches[0][1]
