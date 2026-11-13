"""`code-snapshot-repair` rewrites a legacy absolute source binding in place, audited.

A sealed manifest's ``source_path`` is outside its content address, so rewriting an
absolute binding to the relative ``"source"`` changes no digest. The repair validates
each snapshot in full first, refuses one whose binding names another snapshot or whose
bytes drifted, restores the sealed modes, and records what it rewrote.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
from pathlib import Path

import pytest

from assess.commands import code_snapshot_repair
from assess.lib.code_snapshot import SnapshotBuilder, capture_regular_file, validate_snapshot

_REPO_KEY = "acme-app"
_RAW = b"def handler(request):\n    return request.args\n"


def _rewrite_sealed_json(path: Path, update) -> None:
    path.parent.chmod(0o755)
    path.chmod(0o644)
    value = json.loads(path.read_text(encoding="utf-8"))
    update(value)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o444)
    path.parent.chmod(0o555)


def _writable(root: Path) -> None:
    for path in root.rglob("*"):
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


def _engagement(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "scope.json").write_text("{}\n", encoding="utf-8")
    return root


def _seal(engagement: Path, repo_key: str = _REPO_KEY, raw: bytes = _RAW) -> Path:
    origin = engagement.parent / f"{repo_key}-origin"
    origin.mkdir(exist_ok=True)
    (origin / "app.py").write_bytes(raw)
    builder = SnapshotBuilder(engagement / "tools" / "analysis-state" / "code-snapshots", repo_key)
    builder.add("app.py", capture_regular_file(origin / "app.py"), language="python")
    sealed = builder.finish(
        repo_key=repo_key, repo_name=repo_key, source_origin_path=str(origin),
        git={"head": "", "branch": "", "dirty": None},
    )
    return sealed.manifest_path.parent


def _bind_absolute(snapshot_root: Path, prefix: Path) -> str:
    """Give a seal the absolute binding manifests recorded before the relative one."""
    legacy = str(
        prefix / "tools" / "analysis-state" / "code-snapshots"
        / snapshot_root.parent.name / snapshot_root.name / "source"
    )
    _rewrite_sealed_json(
        snapshot_root / "manifest.json", lambda value: value.update(source_path=legacy)
    )
    return legacy


def _run(capsys, engagement: Path, *argv: str) -> tuple[int, str, str]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--engagement-dir", default=None)
    code_snapshot_repair.register(parser.add_subparsers(dest="command"))
    args = parser.parse_args(["--engagement-dir", str(engagement), "code-snapshot-repair", *argv])
    try:
        args.func(args)
        code = 0
    except SystemExit as exc:
        code = int(exc.code or 0)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _audits(engagement: Path) -> list[Path]:
    return sorted((engagement / "tools" / "analysis-state").glob("*-code-snapshot-repair-*.json"))


@pytest.fixture
def moved_install(tmp_path: Path):
    """A seal made under a prior install layout, then moved to the current one."""
    before = tmp_path / "old-install" / "agent" / "engagements" / "acme-eng"
    snapshot = _seal(_engagement(before))
    legacy = _bind_absolute(snapshot, before)
    after = tmp_path / "install" / "engagements" / "acme-eng"
    after.parent.mkdir(parents=True)
    os.rename(before, after)
    yield after, after / snapshot.relative_to(before), legacy
    _writable(tmp_path)


def test_repair_rebinds_a_moved_seal_in_place_and_records_it(moved_install, capsys) -> None:
    engagement, snapshot, legacy = moved_install
    manifest_path = snapshot / "manifest.json"
    before_bytes = manifest_path.read_bytes()

    code, out, err = _run(capsys, engagement)

    assert code == 0, err
    after_bytes = manifest_path.read_bytes()
    manifest = validate_snapshot(snapshot, expected_digest=snapshot.name)
    assert manifest["source_path"] == "source"
    assert {key: value for key, value in json.loads(before_bytes).items() if key != "source_path"} == {
        key: value for key, value in manifest.items() if key != "source_path"
    }
    assert stat.S_IMODE(manifest_path.stat().st_mode) == 0o444
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o555
    assert sorted(entry.name for entry in snapshot.iterdir()) == ["manifest.json", "source"]
    assert f"{_REPO_KEY}/{snapshot.name}" in out and legacy in out
    [audit_path] = _audits(engagement)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert audit["actor"] == "operator"
    assert audit["refused"] == []
    assert audit["rebound"] == [{
        "repo_key": _REPO_KEY,
        "snapshot_digest": snapshot.name,
        "manifest_path": str(manifest_path.relative_to(engagement)),
        "previous_source_path": legacy,
        "source_path": "source",
        "manifest_sha256_before": hashlib.sha256(before_bytes).hexdigest(),
        "manifest_sha256_after": hashlib.sha256(after_bytes).hexdigest(),
    }]
    listed = json.loads(
        (engagement / "tools" / "analysis-state" / "artifact-manifest.json").read_text(encoding="utf-8")
    )
    assert audit_path.name in {entry["name"] for entry in listed["entries"]}
    assert str(audit_path.relative_to(engagement)) in out


def test_repair_is_a_no_op_on_a_relative_seal(tmp_path: Path, capsys) -> None:
    engagement = _engagement(tmp_path / "acme-eng")
    snapshot = _seal(engagement)
    before_bytes = (snapshot / "manifest.json").read_bytes()

    code, out, err = _run(capsys, engagement)

    assert code == 0, err
    assert (snapshot / "manifest.json").read_bytes() == before_bytes
    assert _audits(engagement) == []
    assert "0 repaired, 1 already relative, 0 refused" in out
    _writable(tmp_path)


def test_a_repeated_repair_changes_nothing(moved_install, capsys) -> None:
    engagement, snapshot, _legacy = moved_install
    _run(capsys, engagement)
    repaired = (snapshot / "manifest.json").read_bytes()

    code, out, _err = _run(capsys, engagement)

    assert code == 0
    assert (snapshot / "manifest.json").read_bytes() == repaired
    assert len(_audits(engagement)) == 1
    assert "0 repaired, 1 already relative" in out


def test_dry_run_reports_without_rewriting(moved_install, capsys) -> None:
    engagement, snapshot, legacy = moved_install
    before_bytes = (snapshot / "manifest.json").read_bytes()

    code, out, err = _run(capsys, engagement, "--dry-run")

    assert code == 0, err
    assert (snapshot / "manifest.json").read_bytes() == before_bytes
    assert _audits(engagement) == []
    assert legacy in out
    assert "1 would be repaired" in out


@pytest.mark.parametrize(
    "corrupt",
    ["foreign-binding", "drifted-bytes"],
)
def test_repair_refuses_a_seal_that_does_not_validate_and_still_repairs_the_rest(
    tmp_path: Path, capsys, corrupt: str,
) -> None:
    engagement = _engagement(tmp_path / "acme-eng")
    good = _seal(engagement)
    _bind_absolute(good, tmp_path / "elsewhere")
    bad = _seal(engagement, repo_key="acme-other", raw=b"x = 1\n")
    if corrupt == "foreign-binding":
        _rewrite_sealed_json(
            bad / "manifest.json",
            lambda value: value.update(
                source_path=f"/srv/acme/code-snapshots/acme-other/{'e' * 64}/source"
            ),
        )
    else:
        _bind_absolute(bad, tmp_path / "elsewhere")
        sealed = bad / "source" / "app.py"
        sealed.parent.chmod(0o755)
        sealed.chmod(0o644)
        sealed.write_bytes(b"x = 2\n")
        sealed.chmod(0o444)
        sealed.parent.chmod(0o555)
    bad_bytes = (bad / "manifest.json").read_bytes()

    code, out, err = _run(capsys, engagement)

    assert code == 1
    assert (bad / "manifest.json").read_bytes() == bad_bytes
    assert validate_snapshot(good, expected_digest=good.name)["source_path"] == "source"
    assert f"acme-other/{bad.name}" in err
    assert "1 repaired, 0 already relative, 1 refused" in out
    [audit_path] = _audits(engagement)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    assert [row["repo_key"] for row in audit["rebound"]] == [_REPO_KEY]
    assert [row["snapshot"] for row in audit["refused"]] == [f"acme-other/{bad.name}"]
    _writable(tmp_path)


def test_repo_key_limits_the_repair_to_one_repository(tmp_path: Path, capsys) -> None:
    engagement = _engagement(tmp_path / "acme-eng")
    chosen = _seal(engagement)
    _bind_absolute(chosen, tmp_path / "elsewhere")
    other = _seal(engagement, repo_key="acme-other", raw=b"x = 1\n")
    _bind_absolute(other, tmp_path / "elsewhere")
    other_bytes = (other / "manifest.json").read_bytes()

    code, out, err = _run(capsys, engagement, "--repo-key", _REPO_KEY)

    assert code == 0, err
    assert validate_snapshot(chosen, expected_digest=chosen.name)["source_path"] == "source"
    assert (other / "manifest.json").read_bytes() == other_bytes
    assert "1 repaired, 0 already relative, 0 refused" in out
    _writable(tmp_path)


def test_an_engagement_with_no_seals_reports_that(tmp_path: Path, capsys) -> None:
    engagement = _engagement(tmp_path / "acme-eng")

    code, out, err = _run(capsys, engagement)

    assert code == 0, err
    assert "0 repaired, 0 already relative, 0 refused" in out
    assert _audits(engagement) == []


_STAGED = ".manifest.json.rebind"


def test_repair_recovers_a_seal_a_killed_repair_left_writable(moved_install, capsys) -> None:
    """A kill between the two chmods leaves the root 0700 with a staged manifest."""
    engagement, snapshot, _legacy = moved_install
    snapshot.chmod(0o700)
    (snapshot / _STAGED).write_bytes(b"{}")
    with pytest.raises(ValueError, match="code-snapshot-repair"):
        validate_snapshot(snapshot, expected_digest=snapshot.name)

    code, _out, err = _run(capsys, engagement)

    assert code == 0, err
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o555
    assert sorted(entry.name for entry in snapshot.iterdir()) == ["manifest.json", "source"]
    assert validate_snapshot(snapshot, expected_digest=snapshot.name)["source_path"] == "source"


def test_repair_recovers_a_seal_killed_after_its_manifest_was_replaced(
    tmp_path: Path, capsys
) -> None:
    engagement = _engagement(tmp_path / "acme-eng")
    snapshot = _seal(engagement)
    snapshot.chmod(0o700)

    code, out, err = _run(capsys, engagement)

    assert code == 0, err
    assert "1 already relative" in out
    assert stat.S_IMODE(snapshot.stat().st_mode) == 0o555
    validate_snapshot(snapshot, expected_digest=snapshot.name)
    _writable(tmp_path)


def test_a_concurrent_repair_neither_rewrites_nor_deletes_the_others_staged_file(
    moved_install, capsys
) -> None:
    import fcntl

    engagement, snapshot, _legacy = moved_install
    manifest_before = (snapshot / "manifest.json").read_bytes()
    holder = os.open(snapshot, os.O_RDONLY)
    try:
        fcntl.flock(holder, fcntl.LOCK_EX | fcntl.LOCK_NB)
        snapshot.chmod(0o700)
        (snapshot / _STAGED).write_bytes(b"in flight")

        code, _out, err = _run(capsys, engagement)

        assert code == 1
        assert "another code-snapshot-repair" in err
        assert (snapshot / _STAGED).read_bytes() == b"in flight"
        assert (snapshot / "manifest.json").read_bytes() == manifest_before
    finally:
        os.close(holder)
        (snapshot / _STAGED).unlink()
        snapshot.chmod(0o555)


def test_a_rewrite_whose_final_check_fails_is_still_audited(
    moved_install, capsys, monkeypatch
) -> None:
    from assess.lib import code_snapshot

    engagement, snapshot, legacy = moved_install
    real = code_snapshot.validate_snapshot

    def failing_shallow(root, *, expected_digest=None, deep=True):
        if not deep:
            raise ValueError("Acme post-rewrite drift")
        return real(root, expected_digest=expected_digest, deep=deep)

    monkeypatch.setattr(code_snapshot, "validate_snapshot", failing_shallow)

    code, _out, err = _run(capsys, engagement)

    assert code == 1
    assert "Acme post-rewrite drift" in err and "rewritten" in err
    [audit_path] = _audits(engagement)
    audit = json.loads(audit_path.read_text(encoding="utf-8"))
    (row,) = audit["rebound"]
    assert row["previous_source_path"] == legacy
    assert "Acme post-rewrite drift" in row["post_rewrite_validation"]
    (refused,) = audit["refused"]
    assert refused["rewritten"] is True
