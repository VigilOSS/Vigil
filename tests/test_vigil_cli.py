"""Root-level smoke tests for `vigil` runtime helpers.

These tests exercise the `vigil runtime resources` helper against a stub Docker
runner and skip cleanly when the host has no docker CLI on PATH. The deeper
CLI test surface lives in `orchestrator/backend/tests/test_aith_cli.py`; this
file is a contract guard so the runtime helper stays callable from the
installable package surface even without backend test infrastructure.
"""
from __future__ import annotations

import io
import re
import shutil
import subprocess
import sys
import urllib.error
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
RENDER_SCRIPT = REPO_ROOT / "agent" / "scripts" / "render-operator-prompts.sh"
STAMP_MARKER = "vigil-prompt-stamp"


def test_vigil_runtime_resources_helper_renders_against_stub_container(monkeypatch, capsys):
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import vigil_runtime_resources

    monkeypatch.setenv("VIGIL_RUNTIME_MEMORY_GB", "8")
    monkeypatch.setenv("VIGIL_RUNTIME_CPUS", "4")

    def runner(argv, **_):
        if argv[:3] == ["docker", "ps", "--format"]:
            return DockerResult(0, "vigil\n", "")
        if argv[:3] == ["docker", "exec", "vigil"]:
            return DockerResult(
                0,
                "/sys/fs/cgroup/memory.max=max\n"
                "/sys/fs/cgroup/cpu.max=max\n"
                "/sys/fs/cgroup/pids.max=max\n",
                "",
            )
        return DockerResult(0, "", "")

    vigil_runtime_resources(runner=runner)
    output = capsys.readouterr().out
    assert "configured\tmemory=8g" in output
    assert "memory.max=max" in output


@pytest.mark.skipif(shutil.which("docker") is None, reason="docker CLI not installed on host")
def test_vigil_runtime_resources_helper_handles_real_docker_cli_gracefully(capsys):
    """When docker is on PATH but no `vigil` container is running, the helper
    reports `running=False` and prints `live\tcontainer not running` rather than crashing."""
    from vigil_cli.runtime import vigil_runtime_resources

    vigil_runtime_resources(container_name="vigil-stub-nonexistent")
    output = capsys.readouterr().out
    assert "running=False" in output
    assert "container not running" in output


# --------------------------------------------------------------------------- #
# I-02: Docker lifecycle must not hang when the daemon/VM is unresponsive.
# run_command bounds every metadata query with a timeout and turns a
# TimeoutExpired into a typed failed result; callers surface a clear message.
# --------------------------------------------------------------------------- #


def test_run_command_times_out_returns_failed_result_not_hang(monkeypatch):
    """A wedged daemon makes subprocess.run raise TimeoutExpired; run_command
    must convert that into a non-zero, timeout-tagged DockerResult (never hang,
    never propagate the exception)."""
    from vigil_cli import docker as docker_module

    def fake_run(argv, **kwargs):
        # The call is bounded — a timeout is always passed to subprocess.run.
        assert kwargs.get("timeout"), "run_command must pass a timeout"
        raise docker_module.subprocess.TimeoutExpired(cmd=argv, timeout=kwargs.get("timeout"))

    monkeypatch.delenv("VIGIL_DOCKER_TIMEOUT", raising=False)
    monkeypatch.setattr(docker_module.subprocess, "run", fake_run)

    result = docker_module.run_command(["docker", "info"])
    assert result.returncode == docker_module.TIMEOUT_RETURNCODE
    assert result.returncode != 0
    assert "timed out" in result.stderr


def test_run_command_timeout_overridable_and_disablable_via_env(monkeypatch):
    from types import SimpleNamespace

    from vigil_cli import docker as docker_module

    captured: dict[str, object] = {}

    def fake_run(argv, **kwargs):
        captured["timeout"] = kwargs.get("timeout")
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(docker_module.subprocess, "run", fake_run)

    monkeypatch.setenv("VIGIL_DOCKER_TIMEOUT", "5")
    assert docker_module.run_command(["docker", "info"]).returncode == 0
    assert captured["timeout"] == 5.0

    # 0 (or negative/garbage) disables the bound for a slow-but-healthy daemon.
    monkeypatch.setenv("VIGIL_DOCKER_TIMEOUT", "0")
    docker_module.run_command(["docker", "info"])
    assert captured["timeout"] is None


def test_daemon_status_flags_timeout_vs_absent_vs_healthy():
    from vigil_cli import docker as docker_module

    timed = docker_module.daemon_status(
        runner=lambda argv, **_: docker_module.DockerResult(docker_module.TIMEOUT_RETURNCODE, "", "timed out")
    )
    assert timed.responsive is False and timed.timed_out is True

    absent = docker_module.daemon_status(
        runner=lambda argv, **_: docker_module.DockerResult(1, "", "Cannot connect to the Docker daemon")
    )
    assert absent.responsive is False and absent.timed_out is False
    assert "Cannot connect" in absent.detail

    healthy = docker_module.daemon_status(
        runner=lambda argv, **_: docker_module.DockerResult(0, "Server Version: 27\n", "")
    )
    assert healthy.responsive is True and healthy.timed_out is False


def test_start_runtime_surfaces_unresponsive_docker_not_missing_image(tmp_path):
    """When the first metadata probe times out, start_runtime must name the real
    problem (Docker unresponsive + recovery hint), NOT the misleading
    'Missing runtime image'."""
    from vigil_cli.docker import DockerResult, TIMEOUT_RETURNCODE
    from vigil_cli.runtime import RuntimeOptions, start_runtime

    install_root = tmp_path / "install"
    (install_root / "agent" / "engagements").mkdir(parents=True)

    def runner(argv, **_):
        if argv[:2] == ["docker", "info"]:
            return DockerResult(TIMEOUT_RETURNCODE, "", "docker command timed out after 20s (daemon unresponsive?): docker info")
        return DockerResult(0, "", "")

    with pytest.raises(SystemExit) as exc_info:
        start_runtime(RuntimeOptions(install_root=install_root), runner=runner, validate_tools=False)

    message = str(exc_info.value)
    assert "not responding" in message.lower() or "wedged" in message.lower()
    assert "Missing runtime image" not in message
    assert "docker info" in message.lower()


def test_runtime_status_reports_docker_unavailable_on_unresponsive_daemon():
    from vigil_cli.docker import DockerResult, TIMEOUT_RETURNCODE
    from vigil_cli.runtime import runtime_status

    def runner(argv, **_):
        # Both the liveness (`docker ps`) and health (`docker info`) probes time out.
        return DockerResult(TIMEOUT_RETURNCODE, "", "timed out")

    assert runtime_status(container_name="vigil", runner=runner) == "docker-unavailable"


def test_runtime_status_reports_stopped_when_daemon_healthy_but_container_absent():
    from vigil_cli.docker import DockerResult
    from vigil_cli.runtime import runtime_status

    def runner(argv, **_):
        return DockerResult(0, "", "")  # `docker ps` empty, `docker info` ok

    assert runtime_status(container_name="vigil", runner=runner) == "stopped"


def _seed_engagement(eng_dir: Path) -> None:
    """Create a minimal engagement skeleton — scope.json is the discovery marker."""
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text("{}", encoding="utf-8")


def test_doctor_failed_audit(tmp_path, monkeypatch):
    """`vigil doctor` must surface orphaned `<run_uuid>.failed-audit` markers.

    Without this signal, a long engagement can accumulate dozens of markers
    silently — each one is an `vigil assess kali` invocation whose audit row
    never reached the orchestrator backend, so coverage drifts behind the
    runtime evidence.
    """
    from vigil_cli.status import (
        _failed_audit_marker_check,
        list_failed_audit_markers,
    )

    install_root = tmp_path
    eng_root = install_root / "agent" / "engagements"
    eng_dir = eng_root / "2026-04-28-000000-target"
    _seed_engagement(eng_dir)

    # Quiet env so unrelated checks (frp token) don't leak state into the test.
    monkeypatch.delenv("VIGIL_FRP_TOKEN", raising=False)

    # Empty case: no scans/kali dir → check returns OK with quiet message.
    assert list_failed_audit_markers(eng_dir) == []
    quiet = _failed_audit_marker_check(install_root)
    assert quiet.name == "failed-audit-markers"
    assert quiet.status == "OK"

    # Populated case: write a marker and assert WARN with engagement key + count.
    kali_dir = eng_dir / "scans" / "kali"
    kali_dir.mkdir(parents=True)
    marker_path = kali_dir / "abc.failed-audit"
    marker_path.write_text("2026-04-28T00:00:00Z audit POST failed: connection refused\n", encoding="utf-8")

    markers = list_failed_audit_markers(eng_dir)
    assert markers == [marker_path]

    warn = _failed_audit_marker_check(install_root)
    assert warn.name == "failed-audit-markers"
    assert warn.status == "WARN"
    assert "1 orphaned marker(s) across 1 engagement(s)" in warn.detail
    assert eng_dir.name in warn.detail
    assert str(marker_path) in warn.detail


def test_doctor_failed_audit_no_engagements_dir(tmp_path):
    """When the install root has no engagements directory yet, the check returns OK."""
    from vigil_cli.status import _failed_audit_marker_check

    result = _failed_audit_marker_check(tmp_path)
    assert result.name == "failed-audit-markers"
    assert result.status == "OK"


def test_readyz_http_error_preserves_readiness_payload(tmp_path, monkeypatch):
    """HTTP 503 from /readyz is a reachable not-ready state, not a transport failure."""
    from vigil_cli import status as status_module

    body = (
        b'{"status":"not_ready","database_connected":true,'
        b'"assessment_schema_ready":false,"code_analysis_schema_ready":true}'
    )

    def fail_readyz(url, *, timeout):
        assert url.endswith("/readyz")
        assert timeout == 1
        raise urllib.error.HTTPError(
            url,
            503,
            "Service Unavailable",
            hdrs=None,
            fp=io.BytesIO(body),
        )

    monkeypatch.setattr(status_module.urllib.request, "urlopen", fail_readyz)

    healthy, readiness = status_module._orchestrator_readyz_snapshot(tmp_path)

    assert healthy is False
    assert readiness["reachable"] is True
    assert readiness["http_status"] == 503
    assert readiness["status"] == "not_ready"
    assert readiness["database_connected"] is True
    assert readiness["assessment_schema_ready"] is False
    assert readiness["code_analysis_schema_ready"] is True


# --------------------------------------------------------------------------- #
# I-104: `vigil auth` and `vigil assess auth` are a deliberate split (operator-
# side vs agent-side, different engagement resolution). A verb that lives on
# only one side must name the other rather than dead-ending on argparse's
# "invalid choice" — a POINTER, never a second listing that would resolve the
# engagement differently.
# --------------------------------------------------------------------------- #


def test_vigil_auth_unknown_verb_points_at_the_assess_sibling(capsys):
    from vigil_cli.main import main

    with pytest.raises(SystemExit) as exc:
        main(["auth", "list"])

    # argparse's usage-error exit code is unchanged: this adds a route, not a verb.
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice" in err
    assert "vigil assess auth list" in err


def test_vigil_auth_valid_verb_is_not_given_the_sibling_hint(capsys, tmp_path):
    """The hint fires only on an unknown subcommand, never on a real error."""
    from vigil_cli.main import main

    with pytest.raises(SystemExit):
        # `--identity` is required for quarantine; this is a normal usage error.
        main(["--root", str(tmp_path), "auth", "quarantine"])

    err = capsys.readouterr().err
    assert "vigil assess auth list" not in err


# --------------------------------------------------------------------------- #
# I-149(a): a rendered operator prompt materialised into an engagement or an
# install root is a copy nothing ever re-renders. Every out-of-tree mirror
# carries a `vigil-prompt-stamp` so a consumer can compare it against
# `render-operator-prompts.sh source-sha` and warn on a stale prompt.
# --------------------------------------------------------------------------- #

requires_bash = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash not available on host"
)


def _render(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(RENDER_SCRIPT), *args],
        capture_output=True,
        text=True,
        check=False,
    )


@requires_bash
def test_render_stamps_every_out_of_tree_mirror_with_the_source_digest(tmp_path):
    sha_proc = _render("source-sha")
    assert sha_proc.returncode == 0, sha_proc.stderr
    source_sha = sha_proc.stdout.strip()
    assert len(source_sha) == 64

    out = tmp_path / "engagement"
    out.mkdir()
    rendered = _render("repo", str(out))
    assert rendered.returncode == 0, rendered.stderr

    mirrors = [
        out / "AGENTS.md",
        out / "CLAUDE.md",
        out / ".claude" / "agents" / "operator.md",
        out / ".claude" / "agents" / "fuzzer.md",
        out / ".codex" / "agents" / "operator.toml",
        out / ".codex" / "agents" / "fuzzer.toml",
        out / ".opencode" / "agent" / "fuzzer.md",
        out / ".goose" / "recipes" / "fuzzer.yaml",
    ]
    # `<!-- vigil-prompt-stamp: <sha> <iso8601> -->` in markdown mirrors,
    # `# vigil-prompt-stamp: <sha> <iso8601>` in the toml/yaml ones.
    stamp_pattern = re.compile(
        rf"^(?:<!--|#) {STAMP_MARKER}: (?P<sha>[0-9a-f]{{64}}) "
        r"(?P<rendered_at>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)(?: -->)?$"
    )
    for mirror in mirrors:
        stamps = [
            line
            for line in mirror.read_text(encoding="utf-8").splitlines()
            if STAMP_MARKER in line
        ]
        assert len(stamps) == 1, f"{mirror} carries {len(stamps)} stamps"
        match = stamp_pattern.match(stamps[0])
        assert match is not None, f"{mirror} stamp is malformed: {stamps[0]!r}"
        assert match.group("sha") == source_sha


@requires_bash
def test_repo_tree_artifacts_stay_unstamped_and_render_check_stays_clean():
    """In-tree artifacts are committed and byte-guarded by render-check already.

    Stamping them would churn every tracked wrapper on every render for no
    staleness signal, so the stamp is out-of-tree only — and render-check
    compares modulo the stamp, so a stamped copy never reads as prompt drift.
    """
    for tracked in (
        REPO_ROOT / "agent" / "AGENTS.md",
        REPO_ROOT / "agent" / "CLAUDE.md",
        REPO_ROOT / "agent" / ".codex" / "agents" / "fuzzer.toml",
    ):
        assert STAMP_MARKER not in tracked.read_text(encoding="utf-8")

    check = _render("check")
    assert check.returncode == 0, check.stdout + check.stderr


def _git_init(path: Path) -> None:
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    subprocess.run(
        ["git", "-C", str(path), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-q", "--allow-empty", "-m", "init"],
        check=True,
    )


def test_source_revision_prefers_the_jj_working_copy_over_git_head(tmp_path):
    """A jj-managed source must stamp the tree it actually installs.

    In a colocated repo the jj working copy is a commit git HEAD does not track,
    so a git-only stamp names its PARENT: the install records the wrong revision
    and `vigil status` then reports `current` while the working root is a commit
    behind. AGENTS.md mandates jj, so that is the normal path, not an edge case.
    """
    from vigil_cli.status import source_revision_sha

    repo = tmp_path / "colocated"
    repo.mkdir()
    _git_init(repo)
    (repo / ".jj").mkdir()

    jj_sha = "b" * 40
    git_sha = "a" * 40
    calls: list[str] = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd[0])
        sha = jj_sha if cmd[0] == "jj" else git_sha
        return subprocess.CompletedProcess(cmd, 0, stdout=sha + "\n", stderr="")

    with mock.patch("vigil_cli.status.subprocess.run", side_effect=fake_run):
        assert source_revision_sha(repo) == jj_sha
    assert "git" not in calls, "git must not be consulted when jj resolves"


def test_source_revision_falls_back_to_git_without_jj(tmp_path):
    """Contributors who never touch jj keep the original behavior."""
    from vigil_cli.status import source_revision_sha

    repo = tmp_path / "gitonly"
    repo.mkdir()
    _git_init(repo)
    assert not (repo / ".jj").exists()

    sha = source_revision_sha(repo)
    assert sha is not None and len(sha) == 40


def test_source_revision_is_none_outside_any_vcs(tmp_path):
    """No git, no jj, no crash — staleness degrades to `unknown`."""
    from vigil_cli.status import source_revision_sha

    plain = tmp_path / "plain"
    plain.mkdir()
    assert source_revision_sha(plain) is None
    assert source_revision_sha(None) is None


def test_jj_revision_read_never_snapshots_the_working_copy(tmp_path):
    """Reading a revision must not mutate the user's repo.

    Every ordinary jj command snapshots the working copy first, which would make
    `vigil status` and `vigil install` write to the source as a side effect.
    """
    from vigil_cli.status import _jj_working_copy_sha

    repo = tmp_path / "colocated"
    (repo / ".jj").mkdir(parents=True)
    seen: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        seen.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, stdout="c" * 40 + "\n", stderr="")

    with mock.patch("vigil_cli.status.subprocess.run", side_effect=fake_run):
        _jj_working_copy_sha(repo)

    assert seen and "--ignore-working-copy" in seen[0]


def test_install_staleness_tracks_unsnapshotted_source_bytes_not_stale_jj_commit(
    tmp_path, capsys
):
    """The copied bytes, not jj's possibly stale ``@``, decide freshness.

    ``--ignore-working-copy`` deliberately avoids snapshotting, so an install can
    copy edits that its revision stamp cannot see. A later snapshot also changes
    the commit id without changing those installed bytes. Neither case may make
    the freshness verdict lie.
    """
    from vigil_cli.status import (
        _print_install_staleness_warning,
        install_staleness,
        write_install_meta,
    )

    source = tmp_path / "source"
    installed = tmp_path / "installed"
    source_file = source / "src" / "vigil_cli" / "feature.py"
    installed_file = installed / "src" / "vigil_cli" / "feature.py"
    source_file.parent.mkdir(parents=True)
    installed_file.parent.mkdir(parents=True)
    source_file.write_text("current = 'unsnapshotted'\n", encoding="utf-8")
    installed_file.write_bytes(source_file.read_bytes())
    revision = {"sha": "a" * 40}

    with mock.patch(
        "vigil_cli.status.source_revision_sha",
        side_effect=lambda _repo: revision["sha"],
    ):
        meta = write_install_meta(installed, source)
        assert isinstance(meta["source_content_sha256"], str)

        source_file.write_text("current = 'newer edit'\n", encoding="utf-8")
        stale = install_staleness(installed, source_root=source)
        assert stale["state"] == "stale"
        assert stale["reason"] == "source_content_changed_without_revision"
        assert stale["installed_sha"] == stale["current_source_sha"]
        _print_install_staleness_warning(stale)
        assert "application files changed without a new revision" in capsys.readouterr().out

        source_file.write_bytes(installed_file.read_bytes())
        revision["sha"] = "b" * 40
        current = install_staleness(installed, source_root=source)
        assert current["state"] == "current"
        assert current["installed_sha"] != current["current_source_sha"]


@pytest.mark.parametrize(
    ("has_stamp", "planned_action"),
    [(False, "planned install"), (True, "planned update")],
)
def test_install_cli_dry_run_names_plan_and_preserves_destination(
    tmp_path, monkeypatch, capsys, has_stamp: bool, planned_action: str
) -> None:
    from vigil_cli import main as main_module

    source = tmp_path / "source"
    (source / "agent").mkdir(parents=True)
    (source / "orchestrator").mkdir()
    (source / "README.md").write_text("new\n", encoding="utf-8")
    install = tmp_path / "install"
    install.mkdir()
    sentinel = install / "README.md"
    sentinel.write_text("old\n", encoding="utf-8")
    if has_stamp:
        (install / ".vigil-install-meta.json").write_text("{}\n", encoding="utf-8")
    config = tmp_path / "config.json"
    monkeypatch.setenv("VIGIL_CONFIG", str(config))

    main_module.main(
        [
            "--source",
            str(source),
            "install",
            str(install),
            "--dry-run",
            "--force-image",
        ]
    )

    captured = capsys.readouterr()
    assert captured.out.strip() == str(install)
    assert "dry-run" in captured.err
    assert planned_action in captured.err
    assert str(install) in captured.err
    assert sentinel.read_text(encoding="utf-8") == "old\n"
    assert not config.exists()


def test_install_manifest_framing_distinguishes_file_directory_and_absence(
    tmp_path,
) -> None:
    from vigil_cli.install_manifest import install_source_content_sha256

    file_tree = tmp_path / "file-tree"
    directory_tree = tmp_path / "directory-tree"
    absent_tree = tmp_path / "absent-tree"
    absent_marker_tree = tmp_path / "absent-marker-tree"
    for root in (file_tree, directory_tree, absent_tree, absent_marker_tree):
        root.mkdir()
    (file_tree / "src").write_bytes(b"<directory>")
    (directory_tree / "src").mkdir()
    (absent_marker_tree / "README.md").write_bytes(b"<absent>")

    assert install_source_content_sha256(file_tree) != install_source_content_sha256(
        directory_tree
    )
    assert install_source_content_sha256(absent_tree) != install_source_content_sha256(
        absent_marker_tree
    )


def test_install_manifest_length_frames_arbitrary_binary_payloads(tmp_path) -> None:
    from vigil_cli.install_manifest import install_source_content_sha256

    one_file = tmp_path / "one-file"
    two_files = tmp_path / "two-files"
    (one_file / "src").mkdir(parents=True)
    (two_files / "src").mkdir(parents=True)
    (one_file / "src" / "a").write_bytes(b"X\0src/b\0Y")
    (two_files / "src" / "a").write_bytes(b"X")
    (two_files / "src" / "b").write_bytes(b"Y")

    assert install_source_content_sha256(one_file) != install_source_content_sha256(
        two_files
    )


def test_install_manifest_ignores_finder_metadata_at_every_depth(tmp_path) -> None:
    from vigil_cli.install_manifest import install_source_content_sha256

    source = tmp_path / "source"
    (source / "agent" / "scripts").mkdir(parents=True)
    (source / "agent" / "scripts" / "assess.py").write_text(
        "#!/usr/bin/env python3\n", encoding="utf-8"
    )
    expected = install_source_content_sha256(source)

    (source / ".DS_Store").write_bytes(b"root finder metadata")
    (source / "agent" / ".DS_Store").write_bytes(b"agent finder metadata")
    (source / "agent" / "scripts" / ".DS_Store").write_bytes(
        b"nested finder metadata"
    )

    assert install_source_content_sha256(source) == expected


def test_install_staleness_is_no_stamp_for_readable_non_vcs_source(tmp_path) -> None:
    from vigil_cli.status import install_staleness

    source = tmp_path / "source"
    (source / "src").mkdir(parents=True)
    (source / "src" / "feature.py").write_text("enabled = True\n", encoding="utf-8")
    installed = tmp_path / "installed"
    installed.mkdir()

    result = install_staleness(installed, source_root=source)

    assert result["state"] == "no-stamp"


@pytest.mark.parametrize("link_target", ["outside", "loop"])
def test_install_staleness_degrades_safely_for_symlinked_source_tree(
    tmp_path, link_target: str
) -> None:
    from vigil_cli.status import INSTALL_META_FILENAME, install_staleness

    source = tmp_path / "source"
    installed = tmp_path / "installed"
    outside = tmp_path / "outside"
    (source / "src").mkdir(parents=True)
    installed.mkdir()
    outside.mkdir()
    target = outside if link_target == "outside" else source / "src" / "link"
    try:
        (source / "src" / "link").symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlinks unavailable: {exc}")
    (installed / INSTALL_META_FILENAME).write_text(
        '{"source_content_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
        encoding="utf-8",
    )

    result = install_staleness(installed, source_root=source)

    assert result["state"] == "unknown"


def test_legacy_revision_only_install_stamp_keeps_commit_distance(
    tmp_path,
) -> None:
    from vigil_cli.status import INSTALL_META_FILENAME, install_staleness

    source = tmp_path / "source"
    installed = tmp_path / "installed"
    source.mkdir()
    installed.mkdir()
    (installed / INSTALL_META_FILENAME).write_text(
        '{"source_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}\n',
        encoding="utf-8",
    )

    with (
        mock.patch("vigil_cli.status.source_revision_sha", return_value="b" * 40),
        mock.patch("vigil_cli.status._commits_behind", return_value=3),
    ):
        result = install_staleness(installed, source_root=source)

    assert result["state"] == "stale"
    assert result["behind_count"] == 3


def test_assess_stale_warning_explains_unsnapshotted_source_content(
    tmp_path, monkeypatch, capsys
) -> None:
    from vigil_cli import preflight as preflight_module

    monkeypatch.setattr(
        preflight_module,
        "install_staleness",
        lambda _root: {
            "state": "stale",
            "reason": "source_content_changed_without_revision",
            "installed_sha": "a" * 40,
            "current_source_sha": "a" * 40,
        },
    )

    preflight_module._warn_if_install_stale(tmp_path)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "source files changed without a new revision" in captured.err
    assert "run `vigil install`" in captured.err


def test_status_stale_warning_is_neutral_without_positive_commit_distance(
    capsys,
) -> None:
    from vigil_cli.status import _print_install_staleness_warning

    _print_install_staleness_warning(
        {
            "state": "stale",
            "reason": "source_content_changed",
            "installed_sha": "a" * 40,
            "current_source_sha": "b" * 40,
        }
    )

    output = capsys.readouterr().out
    assert "workspace provenance differs from application" in output
    assert "behind" not in output


def test_doctor_fails_on_a_corrupt_orchestrator_database(tmp_path):
    """`PRAGMA quick_check` reports corruption in its ROW, not by raising.

    Discarding the row made `vigil doctor` report OK on a corrupt database — the
    one condition it exists to rule out.
    """
    import sqlite3 as _sqlite3

    from vigil_cli.status import _database_check

    healthy = tmp_path / "healthy.sqlite3"
    with _sqlite3.connect(str(healthy)) as connection:
        connection.execute("CREATE TABLE t (a INTEGER PRIMARY KEY, b TEXT)")
        # Enough rows to span many pages, so damaging one leaves a valid header
        # and an intact file that still opens — the shape a real corruption takes.
        connection.executemany(
            "INSERT INTO t (b) VALUES (?)", [(f"row-{i}" * 40,) for i in range(4000)]
        )
        connection.execute("CREATE INDEX t_b ON t (b)")
    assert _database_check(healthy).status == "OK"

    corrupt = tmp_path / "corrupt.sqlite3"
    raw = bytearray(healthy.read_bytes())
    assert len(raw) > 200_000, f"fixture too small to corrupt meaningfully: {len(raw)}"
    # Scribble deep inside the b-tree, well past the header page.
    for offset in range(len(raw) // 2, len(raw) // 2 + 40_000, 4):
        raw[offset : offset + 4] = b"\xde\xad\xbe\xef"
    corrupt.write_bytes(bytes(raw))

    result = _database_check(corrupt)
    assert result.status == "FAIL", f"corrupt database reported {result.status}"
    assert result.detail, "a failing integrity check must say what was wrong"


def test_doctor_reports_missing_database_without_touching_sqlite(tmp_path):
    from vigil_cli.status import _database_check

    assert _database_check(tmp_path / "absent.sqlite3").status == "MISSING"


def test_doctor_bounds_database_integrity_scan(tmp_path):
    import sqlite3 as _sqlite3

    from vigil_cli.status import _database_check

    database = tmp_path / "large.sqlite3"
    with _sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE rows (value TEXT NOT NULL)")
        connection.executemany(
            "INSERT INTO rows (value) VALUES (?)",
            [(f"row-{index}" * 20,) for index in range(20_000)],
        )

    result = _database_check(database, timeout_seconds=0.0)

    assert result.status == "WARN"
    assert "timed out" in result.detail


@pytest.mark.parametrize(("cpus", "expected"), [(2, "2"), (2.0, "2"), (0.5, "0.5")])
def test_runtime_cpu_argument_accepts_integer_and_fractional_limits(cpus, expected):
    from vigil_cli.runtime import _format_cpus

    assert _format_cpus(cpus) == expected
