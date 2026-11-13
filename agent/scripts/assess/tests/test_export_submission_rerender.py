"""Re-rendering a submission reuses what the last render captured.

A re-render after a finding edit reuses the inputs the workspace context
captured (and names them on stderr), so the caller does not repeat --body and
--guidance. An output that still matches the last render recorded in
submission-context.json is replaced without --overwrite. Only bytes edited by
hand since that render are refused, because replacing them would silently
discard someone's work.
"""
from __future__ import annotations

import pytest

from assess.commands import export_submission
from assess.lib.client import AssessError
from test_export_submission import (
    _FakeClient,
    _complete_details,
    _finding,
    _install,
    _parse,
    _submission_path,
)


def _render(monkeypatch, tmp_path, *argv: str) -> _FakeClient:
    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    export_submission.run(_parse(["submission", "VA-047", *argv], str(tmp_path)))
    return fake


def test_an_unedited_render_is_replaced_without_overwrite(tmp_path, monkeypatch, capsys):
    _render(monkeypatch, tmp_path, "--platform", "bugcrowd")
    capsys.readouterr()

    fake = _render(monkeypatch, tmp_path, "--platform", "bugcrowd")

    assert any(endpoint == "artifacts" for endpoint, _ in fake.posts)
    err = capsys.readouterr().err
    assert "match the last render" in err


@pytest.mark.parametrize("name", ["submission.md", "submission-body.md"])
def test_hand_edited_output_is_refused_without_overwrite(name, tmp_path, monkeypatch, capsys):
    _render(monkeypatch, tmp_path, "--platform", "bugcrowd")
    edited = _submission_path(tmp_path).parent / name
    edited.write_text(edited.read_text(encoding="utf-8") + "\nHand-edited line.\n", encoding="utf-8")
    capsys.readouterr()

    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(AssessError) as exc:
        export_submission.run(_parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path)))

    message = str(exc.value)
    assert name in message and "--overwrite" in message and "by hand" in message
    assert fake.posts == []
    assert edited.read_text(encoding="utf-8").endswith("Hand-edited line.\n")

    _render(monkeypatch, tmp_path, "--platform", "bugcrowd", "--overwrite")
    assert "Hand-edited line." not in edited.read_text(encoding="utf-8")


def test_a_workspace_without_a_render_record_is_refused(tmp_path, monkeypatch):
    output = _submission_path(tmp_path)
    output.parent.mkdir(parents=True)
    output.write_text("Operator draft.\n", encoding="utf-8")

    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(AssessError, match="--overwrite"):
        export_submission.run(_parse(["submission", "VA-047", "--platform", "bugcrowd"], str(tmp_path)))
    assert output.read_text(encoding="utf-8") == "Operator draft.\n"


def test_captured_body_and_guidance_are_reused(tmp_path, monkeypatch, capsys):
    outgoing = b"## Reproducer\r\nRequires an authenticated member.\r\n"
    (tmp_path / "advisory.md").write_bytes(outgoing)
    (tmp_path / "SECURITY.md").write_text("Send a short reproducer.\n", encoding="utf-8")
    _render(
        monkeypatch, tmp_path, "--platform", "direct",
        "--body", "advisory.md", "--guidance", "SECURITY.md", "--prepare",
    )
    capsys.readouterr()

    _render(monkeypatch, tmp_path, "--platform", "direct", "--prepare")

    directory = _submission_path(tmp_path).parent
    assert (directory / "submission-body.md").read_bytes() == outgoing
    err = capsys.readouterr().err
    assert "reusing the captured --body advisory.md" in err
    assert "reusing the captured --guidance SECURITY.md" in err


def test_a_changed_captured_body_is_named(tmp_path, monkeypatch, capsys):
    (tmp_path / "advisory.md").write_text("First body.\n", encoding="utf-8")
    _render(monkeypatch, tmp_path, "--platform", "direct", "--body", "advisory.md", "--prepare")
    (tmp_path / "advisory.md").write_text("Second body.\n", encoding="utf-8")
    capsys.readouterr()

    _render(monkeypatch, tmp_path, "--platform", "direct", "--prepare")

    directory = _submission_path(tmp_path).parent
    assert (directory / "submission-body.md").read_text(encoding="utf-8") == "Second body.\n"
    assert "changed since that render" in capsys.readouterr().err


def test_a_missing_captured_body_is_refused(tmp_path, monkeypatch):
    (tmp_path / "advisory.md").write_text("First body.\n", encoding="utf-8")
    _render(monkeypatch, tmp_path, "--platform", "direct", "--body", "advisory.md", "--prepare")
    (tmp_path / "advisory.md").unlink()

    fake = _FakeClient(_finding(details=_complete_details()))
    _install(monkeypatch, tmp_path, fake)
    with pytest.raises(AssessError, match="advisory.md"):
        export_submission.run(_parse(["submission", "VA-047", "--platform", "direct", "--prepare"], str(tmp_path)))
    assert fake.posts == []
