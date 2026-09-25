from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
from pathlib import Path

import pytest

from assess import cli

export_triage_packet = importlib.import_module(
    "assess.commands.export_triage_packet"
)


def _write_submission(submission_dir: Path, body: bytes) -> None:
    (submission_dir / "submission.md").write_bytes(body)
    (submission_dir / "submission-body.md").write_bytes(body)
    (submission_dir / "submission-context.json").write_text(
        json.dumps({
            "submission_sha256": hashlib.sha256(body).hexdigest(),
            "external_body_sha256": hashlib.sha256(body).hexdigest(),
            "platform": "direct",
        }), encoding="utf-8",
    )


def _run_cli(argv: list[str]) -> None:
    try:
        cli.main(argv)
    except SystemExit as exc:
        pytest.fail(f"command unexpectedly exited with {exc.code}")


def _seed_packet_inputs(tmp_path: Path) -> tuple[Path, list[str]]:
    engagement = tmp_path / "engagement"
    submission_dir = engagement / "submissions" / "VA-001"
    submission_dir.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}\n", encoding="utf-8")
    (engagement / "ENGAGEMENT.md").write_text("# Program facts\n", encoding="utf-8")
    _write_submission(submission_dir, b"# Finding\nProof.\n")
    return engagement, [
        "--engagement-dir",
        str(engagement),
        "export",
        "triage-packet",
        "VA-001",
        "--json",
    ]


def test_prompt_census_reports_structure_cost_and_partial_read_without_blocking(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    prompt_root = tmp_path / "agent"
    roles = prompt_root / "agents"
    shared = prompt_root / "shared.md"
    roles.mkdir(parents=True)
    shared.write_text("shared context\n", encoding="utf-8")
    complete = roles / "complete.md"
    complete.write_text(
        "# Complete role\n\n"
        "## Load First\n\n"
        "**MANDATORY (before work):**\n\n"
        "- `agent/shared.md`\n\n"
        "**LOAD-ON-FIRST-USE (lazy):**\n\n"
        "- `agent/lazy.md` when needed\n\n"
        "## Work\nBody\n",
        encoding="utf-8",
    )
    (roles / "advisory.md").write_text(
        "# Advisory role\n\n## Load First\n\n**MANDATORY:**\n\n- dynamic tenant ref\n",
        encoding="utf-8",
    )
    read_bytes = complete.read_bytes().index(b"agent/shared.md") + 3

    _run_cli(
        [
            "prompt-census",
            "--prompt-root",
            str(prompt_root),
            "--read-bytes",
            str(read_bytes),
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["blocking"] is False
    by_role = {row["role"]: row for row in payload["roles"]}
    complete_row = by_role["complete"]
    assert complete_row["expected_sections"] == {
        "load_first": True,
        "mandatory": True,
        "load_on_first_use": True,
    }
    assert complete_row["role_bytes"] == len(complete.read_bytes())
    assert complete_row["mandatory_references"][0]["bytes"] == len(shared.read_bytes())
    assert complete_row["approximate_standing_bytes"] == (
        len(complete.read_bytes()) + len(shared.read_bytes())
    )
    assert complete_row["read_visibility"] == "partial"
    assert by_role["advisory"]["expected_sections"]["load_on_first_use"] is False
    assert by_role["advisory"]["advisories"]


def test_blind_triage_packet_uses_exact_canonical_inputs_and_truthful_manifest(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    engagement = tmp_path / "engagement"
    submission_dir = engagement / "submissions" / "VA-001"
    submission_dir.mkdir(parents=True)
    (engagement / "scope.json").write_text("{}\n", encoding="utf-8")
    brief_bytes = b"# Program facts\nIn scope: app.example\n"
    submission_bytes = b"# Finding\nExact canonical submission bytes.\n"
    (engagement / "ENGAGEMENT.md").write_bytes(brief_bytes)
    _write_submission(submission_dir, submission_bytes)

    _run_cli(
        [
            "--engagement-dir",
            str(engagement),
            "export",
            "triage-packet",
            "VA-001",
            "--json",
        ]
    )

    result = json.loads(capsys.readouterr().out)
    packet_dir = Path(result["packet_dir"])
    manifest = json.loads((packet_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema"] == "vigil-blind-triage-packet/v2"
    assert manifest["process_isolation_enforced"] is False
    assert (packet_dir / "submission.md").read_bytes() == submission_bytes
    assert (packet_dir / "program-brief.md").read_bytes() == brief_bytes
    assert manifest["inputs"]["submission"]["sha256"] == hashlib.sha256(
        submission_bytes
    ).hexdigest()
    rubric = packet_dir / "verdict-rubric.md"
    assert rubric.read_bytes()
    assert manifest["inputs"]["verdict_rubric"]["sha256"] == hashlib.sha256(
        rubric.read_bytes()
    ).hexdigest()
    assert submission_bytes.decode() in (packet_dir / "packet.md").read_text(
        encoding="utf-8"
    )

    _run_cli(
        [
            "--engagement-dir",
            str(engagement),
            "export",
            "triage-packet",
            "VA-001",
            "--json",
        ]
    )
    repeated = json.loads(capsys.readouterr().out)
    assert repeated["packet_id"] == result["packet_id"]

    revised_bytes = submission_bytes + b"Additional canonical evidence.\n"
    _write_submission(submission_dir, revised_bytes)
    _run_cli(
        [
            "--engagement-dir",
            str(engagement),
            "export",
            "triage-packet",
            "VA-001",
            "--json",
        ]
    )
    revised = json.loads(capsys.readouterr().out)
    assert revised["packet_id"] != result["packet_id"]
    assert (Path(revised["packet_dir"]) / "submission.md").read_bytes() == revised_bytes


def test_blind_triage_packet_excludes_operator_only_reference_from_reviewer_input(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    engagement, argv = _seed_packet_inputs(tmp_path)
    submission_dir = engagement / "submissions" / "VA-001"
    external_body = b"**Title:** Finding\n\n---\n\n### Evidence\n\nPublic proof.\n"
    full_workspace = (
        external_body
        + b"\n---\n\n## OPERATOR DETAILS \xe2\x80\x94 NOT FOR SUBMISSION\n\n"
        + b"Internal proof that a recipient will not see.\n"
    )
    (submission_dir / "submission.md").write_bytes(full_workspace)
    (submission_dir / "submission-body.md").write_bytes(external_body)
    (submission_dir / "submission-context.json").write_text(
        json.dumps({
            "submission_sha256": hashlib.sha256(full_workspace).hexdigest(),
            "external_body_sha256": hashlib.sha256(external_body).hexdigest(),
            "platform": "direct",
        }), encoding="utf-8",
    )

    _run_cli(argv)

    result = json.loads(capsys.readouterr().out)
    packet_dir = Path(result["packet_dir"])
    reviewer_input = (packet_dir / "packet.md").read_bytes()
    assert external_body in reviewer_input
    assert b"Internal proof that a recipient will not see" not in reviewer_input
    assert (packet_dir / "submission.md").read_bytes() == external_body


def test_blind_triage_packet_binds_selected_attachment_bytes(tmp_path: Path) -> None:
    engagement, _ = _seed_packet_inputs(tmp_path)
    proof = engagement / "proof" / "crash.txt"
    proof.parent.mkdir()
    proof.write_bytes(b"ASAN crash at vulnerable sink\n")
    artifact = {
        "id": 7,
        "relative_path": "proof/crash.txt",
        "sha256": hashlib.sha256(proof.read_bytes()).hexdigest(),
        "size_bytes": proof.stat().st_size,
        "present": True,
        "media_type": "text/plain",
    }

    result = export_triage_packet.build_packet(
        engagement, "VA-001", attachment_rows=[artifact]
    )

    packet_dir = Path(result["packet_dir"])
    manifest = json.loads((packet_dir / "manifest.json").read_text())
    assert manifest["inputs"]["attachments"][0]["sha256"] == artifact["sha256"]
    assert (packet_dir / "attachments" / "7-crash.txt").read_bytes() == proof.read_bytes()
    assert export_triage_packet.build_packet(engagement, "VA-001")["packet_id"] != result["packet_id"]


def test_blind_triage_packet_refuses_symlinked_packet_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _engagement, argv = _seed_packet_inputs(tmp_path)
    _run_cli(argv)
    packet_dir = Path(json.loads(capsys.readouterr().out)["packet_dir"])
    shutil.rmtree(packet_dir)
    outside = tmp_path / "outside"
    outside.mkdir()
    packet_dir.symlink_to(outside, target_is_directory=True)

    with pytest.raises(SystemExit, match="symlink"):
        cli.main(argv)

    assert list(outside.iterdir()) == []


def test_blind_triage_packet_refuses_symlinked_output_file_even_when_bytes_match(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _engagement, argv = _seed_packet_inputs(tmp_path)
    _run_cli(argv)
    packet_dir = Path(json.loads(capsys.readouterr().out)["packet_dir"])
    submission_output = packet_dir / "submission.md"
    outside = tmp_path / "outside-submission.md"
    outside.write_bytes(submission_output.read_bytes())
    submission_output.unlink()
    submission_output.symlink_to(outside)

    with pytest.raises(SystemExit, match="symlink"):
        cli.main(argv)


@pytest.mark.parametrize(
    "source",
    ["submission", "program_brief", "verdict_rubric"],
)
def test_blind_triage_packet_refuses_symlinked_canonical_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    engagement, argv = _seed_packet_inputs(tmp_path)
    outside = tmp_path / f"outside-{source}.md"
    outside.write_text("attacker-selected bytes\n", encoding="utf-8")
    if source == "submission":
        target = engagement / "submissions" / "VA-001" / "submission.md"
    elif source == "program_brief":
        target = engagement / "ENGAGEMENT.md"
    else:
        rubric_root = tmp_path / "rubric-root"
        target = rubric_root / "skills" / "blind-triage" / "SKILL.md"
        target.parent.mkdir(parents=True)
        monkeypatch.setattr(export_triage_packet, "_RUBRIC_ROOT", rubric_root)
    if target.exists():
        target.unlink()
    target.symlink_to(outside)

    with pytest.raises(SystemExit, match="symlink|regular file"):
        cli.main(argv)


@pytest.mark.parametrize(
    "source",
    ["submission", "program_brief", "verdict_rubric"],
)
def test_blind_triage_packet_refuses_input_replaced_between_validation_and_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, source: str
) -> None:
    engagement, argv = _seed_packet_inputs(tmp_path)
    outside = tmp_path / f"outside-race-{source}.md"
    outside.write_text("replacement bytes\n", encoding="utf-8")
    if source == "submission":
        target = engagement / "submissions" / "VA-001" / "submission.md"
    elif source == "program_brief":
        target = engagement / "ENGAGEMENT.md"
    else:
        rubric_root = tmp_path / "rubric-root"
        target = rubric_root / "skills" / "blind-triage" / "SKILL.md"
        target.parent.mkdir(parents=True)
        target.write_text("canonical rubric\n", encoding="utf-8")
        monkeypatch.setattr(export_triage_packet, "_RUBRIC_ROOT", rubric_root)

    original_open = os.open
    replaced = False

    def replace_before_open(path, flags, mode=0o777, *, dir_fd=None):
        nonlocal replaced
        if not replaced and path == target.name and dir_fd is not None:
            replaced = True
            target.unlink()
            target.symlink_to(outside)
        return original_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(export_triage_packet.os, "open", replace_before_open)

    with pytest.raises(SystemExit, match="changed|symlink|safely open"):
        cli.main(argv)
    assert replaced is True
