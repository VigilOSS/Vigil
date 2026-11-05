"""`code-history check-shapes` admits only shapes that cite their history artifacts."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from test_code_history import (
    _REPO_ID,
    _bind,
    _commit,
    _engagement,
    _history_repo,
    _main,
    _run_json,
    _write,
    git_bin,  # noqa: F401 - pytest fixture
)


@pytest.fixture
def cited(tmp_path, monkeypatch, capsys, git_bin):  # noqa: F811 - pytest fixture
    repo, commits = _history_repo(tmp_path)
    engagement = _engagement(tmp_path)
    _bind(monkeypatch, engagement, repo, git_bin)
    diff = _run_json(capsys, "diff", "--repo-id", str(_REPO_ID), "--commit", commits["cve_fix"])
    return engagement, commits, diff


def _shape(commits: dict, diff: dict, **overrides) -> dict:
    shape = {
        "shape_id": "upload-name-traversal",
        "cwe": "CWE-22",
        "affected_paths": ["src/upload.py"],
        "vulnerable_revision": commits["initial"],
        "fixed_revision": commits["cve_fix"],
        "bug_pattern": "upload() opens a caller-supplied name without rejecting parent-directory segments",
        "guard_delta": "the fix rejects any name containing '..' before the open() call",
        "evidence_refs": [diff["receipt_path"], diff["output"]["path"]],
    }
    shape.update(overrides)
    return shape


def _check(capsys, engagement: Path, shapes: list[dict] | str, *extra: str) -> tuple[int, str, str]:
    path = engagement / "tools" / "analysis-state" / "cve-bug-shapes.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(shapes, str):
        path.write_text(shapes, encoding="utf-8")
    else:
        path.write_text("".join(json.dumps(shape) + "\n" for shape in shapes), encoding="utf-8")
    try:
        _main(["--engagement-dir", str(engagement), "code-history", "check-shapes", str(path), *extra])
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _errors(capsys, engagement: Path, shapes) -> list[str]:
    code, out, _err = _check(capsys, engagement, shapes, "--json")
    report = json.loads(out)
    assert code != 0
    assert report["valid"] is False
    return report["errors"] + [error for line in report["lines"] for error in line["errors"]]


def test_a_shape_citing_its_receipt_and_patch_is_accepted(cited, capsys):
    engagement, commits, diff = cited

    code, out, err = _check(capsys, engagement, [_shape(commits, diff)], "--json")

    assert code == 0, err
    report = json.loads(out)
    assert report["valid"] is True
    assert report["lines"][0]["errors"] == []
    assert report["lines"][0]["evidence_truncated"] is False
    text_code, text, _ = _check(capsys, engagement, [_shape(commits, diff)])
    assert text_code == 0
    assert "1 shape(s) valid" in text


@pytest.mark.parametrize(
    "overrides",
    [
        {"bug_pattern": "CVE-2026-0001", "guard_delta": "fixed in GHSA-2c4f-8x9q-m5h7"},
        {"bug_pattern": "CWE-22 / CVE-2026-0001", "guard_delta": "see commit"},
        {"bug_pattern": "", "guard_delta": ""},
    ],
    ids=["ids", "ids-and-a-word", "empty"],
)
def test_an_identifier_only_shape_is_rejected(cited, capsys, overrides):
    engagement, commits, diff = cited

    errors = _errors(capsys, engagement, [_shape(commits, diff, **overrides)])

    assert any("identifier" in error or "required" in error for error in errors), errors


def _tamper_patch(engagement: Path, diff: dict) -> dict:
    patch = engagement / diff["output"]["path"]
    patch.chmod(0o644)
    patch.write_bytes(patch.read_bytes() + b"+forged\n")
    return {}


def _copied_receipt(engagement: Path, diff: dict) -> dict:
    elsewhere = engagement / "tools" / "analysis-state" / "notes" / "receipt.json"
    elsewhere.parent.mkdir(parents=True)
    shutil.copyfile(engagement / diff["receipt_path"], elsewhere)
    return {"evidence_refs": ["tools/analysis-state/notes/receipt.json", diff["output"]["path"]]}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda engagement, diff: {"evidence_refs": []},
        lambda engagement, diff: {"evidence_refs": [diff["output"]["path"]]},
        lambda engagement, diff: {"evidence_refs": [diff["receipt_path"]]},
        lambda engagement, diff: {
            "evidence_refs": ["tools/analysis-state/code-history/7/3/missing.receipt.json"]
        },
        lambda engagement, diff: {"vulnerable_revision": "f" * 40},
        lambda engagement, diff: {"fixed_revision": "f" * 40},
        lambda engagement, diff: {"affected_paths": ["src/auth.py"]},
        _tamper_patch,
        _copied_receipt,
    ],
    ids=[
        "no-refs", "patch-only", "receipt-only", "missing-receipt", "vulnerable-mismatch",
        "fixed-mismatch", "path-not-in-fix", "patch-digest", "receipt-outside-history",
    ],
)
def test_a_shape_whose_citations_do_not_hold_is_rejected(cited, capsys, mutate):
    engagement, commits, diff = cited

    errors = _errors(capsys, engagement, [_shape(commits, diff, **mutate(engagement, diff))])

    assert errors


def test_a_shape_citing_a_truncated_diff_is_flagged(tmp_path, monkeypatch, capsys, git_bin):  # noqa: F811
    repo, commits = _history_repo(tmp_path)
    engagement = _engagement(tmp_path)
    _bind(monkeypatch, engagement, repo, git_bin)
    diff = _run_json(
        capsys, "diff", "--repo-id", str(_REPO_ID), "--commit", commits["cve_fix"], "--max-bytes", "16",
    )

    code, out, _err = _check(capsys, engagement, [_shape(commits, diff)], "--json")
    text_code, text, _ = _check(capsys, engagement, [_shape(commits, diff)])

    assert code == 0
    assert json.loads(out)["lines"][0]["evidence_truncated"] is True
    assert text_code == 0
    assert "TRUNCATED" in text


def test_layout_errors_are_rejected(cited, capsys):
    engagement, commits, diff = cited
    good = json.dumps(_shape(commits, diff))

    assert _errors(capsys, engagement, "")
    assert _errors(capsys, engagement, good + "\n\n")
    assert _errors(capsys, engagement, good + "\n" + good + "\n")
    assert _errors(capsys, engagement, "[1, 2]\n")
    separated = _shape(commits, diff, guard_delta="the fix rejects '..'\u2028before the open() call")
    assert _errors(capsys, engagement, json.dumps(separated, ensure_ascii=False) + "\n")


def test_root_commit_diffs_cannot_seed_a_shape(tmp_path, monkeypatch, capsys, git_bin):  # noqa: F811
    repo, commits = _history_repo(tmp_path)
    _write(repo, "src/extra.py", "X = 1\n")
    _commit(repo, "Add extra module", "2026-05-05T09:00:00Z")
    engagement = _engagement(tmp_path)
    _bind(monkeypatch, engagement, repo, git_bin)
    root = _run_json(capsys, "diff", "--repo-id", str(_REPO_ID), "--commit", commits["initial"])

    assert root["diff_status"] == "root_commit"
    errors = _errors(
        capsys,
        engagement,
        [_shape(commits, root, vulnerable_revision=commits["initial"], fixed_revision=commits["initial"])],
    )
    assert errors
