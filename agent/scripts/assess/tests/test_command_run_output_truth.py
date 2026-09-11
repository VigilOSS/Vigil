"""The finalize PATCH carries the wrapper's own measurement of its output.

Only the ``host_exec`` lane spills through the backend's retention machinery.
Every other route — ``vigil assess kali/<tool>`` above all — streams its output
to a file this CLI opened, so the wrapper is the only party that can see how
many bytes were WRITTEN: the finalize payload's previews are head+tail
truncations and would undercount. Without these fields the audit row keeps the
pre-exec placeholders (0 bytes, no hash, retention ``empty``) for the life of
the engagement, so evidence sitting on disk reads as evidence destroyed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.lib import kali_audit
from assess.lib.client import AssessError


class _RecordingClient:
    def __init__(self) -> None:
        self.patches: list[tuple[str, dict]] = []

    def patch(self, endpoint: str, payload: dict, accept_409: bool = False) -> dict:
        self.patches.append((endpoint, payload))
        return {"id": 7, "run_uuid": "run-expected", **payload}


class _MalformedFinalizeClient(_RecordingClient):
    def patch(self, endpoint: str, payload: dict, accept_409: bool = False) -> dict:
        self.patches.append((endpoint, payload))
        return {"message": "accepted"}


def _finalize(client, **overrides) -> dict:
    kwargs: dict = {
        "run_id": 7,
        "run_uuid": "run-expected",
        "status": "completed",
        "return_code": 0,
        "ended_at_iso": "2026-08-25T09:00:05Z",
        "duration_ms": 5000,
        "stdout_preview": "truncated preview",
        "stderr_preview": "",
        "timed_out": False,
        "partial_results": False,
        "peak_rss_bytes": None,
        "cpu_user_seconds": None,
        "cpu_system_seconds": None,
    }
    kwargs.update(overrides)
    kali_audit._patch_finalize(client, **kwargs)
    return client.patches[0][1]


def test_finalize_sends_bytes_written_not_preview_length(tmp_path) -> None:
    body = b"A" * 100_000
    out = tmp_path / "run.out"
    out.write_bytes(body)
    err = tmp_path / "run.err"
    err.write_bytes(b"warning\n")

    payload = _finalize(_RecordingClient(), stdout_path=out, stderr_path=err)

    assert payload["stdout_bytes"] == len(body)
    assert payload["stdout_sha256"] == hashlib.sha256(body).hexdigest()
    assert payload["stderr_bytes"] == len(b"warning\n")
    assert payload["stderr_sha256"] == hashlib.sha256(b"warning\n").hexdigest()
    # The preview stays what it always was: a truncation, not the byte truth.
    assert payload["stdout_preview"] == "truncated preview"


def test_finalize_reports_an_empty_stream_without_a_digest(tmp_path) -> None:
    out = tmp_path / "run.out"
    out.write_bytes(b"")

    payload = _finalize(_RecordingClient(), stdout_path=out)

    assert payload["stdout_bytes"] == 0
    assert payload["stdout_sha256"] == ""
    assert "stderr_bytes" not in payload


def test_finalize_omits_byte_truth_when_the_spill_is_unreadable(tmp_path) -> None:
    """A missing spill must record NO byte truth rather than a wrong one."""
    payload = _finalize(_RecordingClient(), stdout_path=tmp_path / "never-written.out")

    assert "stdout_bytes" not in payload
    assert "stdout_sha256" not in payload


def test_finalize_without_paths_is_unchanged(tmp_path) -> None:
    payload = _finalize(_RecordingClient())

    assert "stdout_bytes" not in payload
    assert "stderr_bytes" not in payload


def test_finalize_rejects_arbitrary_success_object() -> None:
    with pytest.raises(AssessError, match="finalize command run") as exc:
        _finalize(_MalformedFinalizeClient())

    assert "do not retry automatically" in str(exc.value)


@pytest.mark.parametrize(
    ("row_id", "run_uuid"),
    [(8, "run-expected"), (7, "run-other")],
    ids=["wrong-id", "wrong-uuid"],
)
def test_host_finalize_validation_binds_id_and_run_uuid(row_id, run_uuid) -> None:
    from assess.commands import host_exec

    attempted = {
        "id": 7,
        "run_uuid": "run-expected",
        "status": "completed",
        "return_code": 0,
        "timed_out": False,
        "duration_ms": 5000,
        "partial_results": False,
        "ended_at": "2026-08-25T09:00:05Z",
    }
    finalized = {
        **attempted,
        "id": row_id,
        "run_uuid": run_uuid,
        "completed_at": attempted["ended_at"],
    }

    with pytest.raises(AssessError, match="finalize command run"):
        host_exec._validate_terminal_finalize_response(finalized, attempted)


# --------------------------------------------------------------------------- #
# End-to-end: a real kali run records byte truth for the file its row names
# --------------------------------------------------------------------------- #
#
# The unit tests above prove `_patch_finalize` measures a file when handed one.
# These prove the production callers actually hand it one — and that the file
# they hand it is the file the pre-exec audit row named, including across the
# CR-36 http=000 retry, which is the only path where the run has two attempts.


class _RunClient:
    """Backend-less AssessmentClient double that keeps the whole exchange."""

    def __init__(self, *_args, **_kwargs) -> None:
        self.posts: list[tuple[str, dict]] = []
        self.patches: list[tuple[str, dict]] = []

    def post(self, endpoint: str, payload: dict) -> dict:
        self.posts.append((endpoint, payload))
        return {"id": 7, "superseded_by_id": None}

    def patch(self, endpoint: str, payload: dict, *, accept_409: bool = False) -> dict:
        self.patches.append((endpoint, payload))
        return {"id": 7, "status": payload.get("status")}

    def close(self) -> None:
        return None


class _Proc:
    def __init__(self, returncode: int) -> None:
        self.pid = 4242
        self._rc = returncode

    def wait(self, timeout=None):
        return self._rc


@pytest.fixture
def engagement(tmp_path, monkeypatch):
    eng_dir = tmp_path / "engagements" / "2026-08-25-truth"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (eng_dir / "scope.json").write_text(
        json.dumps({"hostname": "example.com", "hosts": ["example.com"]})
    )
    monkeypatch.setenv("ENGAGEMENT_DIR", str(eng_dir))
    monkeypatch.setenv("AGENT_NAME", "vulnerability-analyst")
    monkeypatch.delenv("VIGIL_NO_RESOLVE_PIN", raising=False)
    return eng_dir


def _wire_kali(monkeypatch, eng_dir, *, docker_desktop: bool):
    """Wire ``kali_exec`` for a container-free, backend-free run."""
    from assess.lib import kali, kali_resolve, runtime_route

    runtime = runtime_route.RuntimeInfo(
        platform="darwin" if docker_desktop else "linux",
        is_docker_desktop=docker_desktop,
        recommended="host" if docker_desktop else "container",
    )
    monkeypatch.setattr(
        kali,
        "load_config",
        lambda _flag: SimpleNamespace(
            base_url="http://127.0.0.1:18000",
            engagement_dir=str(eng_dir),
            engagement_key=eng_dir.name,
            agent_root=str(eng_dir.parent.parent),
        ),
    )
    client = _RunClient()
    monkeypatch.setattr(kali, "AssessmentClient", lambda *a, **k: client)
    monkeypatch.setattr(kali, "_check_container_running", lambda _name: None)
    monkeypatch.setattr(kali, "_read_container_pid", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_kill_in_container", lambda *a, **k: None)
    monkeypatch.setattr(kali, "_cleanup_container_pid_file", lambda *a, **k: None)
    runtime_route.reset_runtime_cache()
    monkeypatch.setattr(runtime_route, "detect_runtime", lambda *a, **k: runtime)
    return kali, kali_resolve, client


def _row_paths(client: _RunClient) -> tuple[Path, Path]:
    """The stdout/stderr files the pre-exec audit row committed to."""
    _endpoint, payload = client.posts[0]
    return Path(payload["stdout_path"]), Path(payload["stderr_path"])


def _assert_row_hashes_what_it_names(client: _RunClient) -> dict:
    """The finalize PATCH must describe the exact file the row points at."""
    out_path, err_path = _row_paths(client)
    payload = client.patches[-1][1]
    out_bytes = out_path.read_bytes()
    err_bytes = err_path.read_bytes()
    assert payload["stdout_bytes"] == len(out_bytes)
    assert payload["stdout_sha256"] == (
        hashlib.sha256(out_bytes).hexdigest() if out_bytes else ""
    )
    assert payload["stderr_bytes"] == len(err_bytes)
    assert payload["stderr_sha256"] == (
        hashlib.sha256(err_bytes).hexdigest() if err_bytes else ""
    )
    return payload


def test_kali_run_records_the_bytes_written_not_the_preview(monkeypatch, engagement):
    """A live kali route must stop leaving the pre-exec placeholders behind.

    The body is deliberately far longer than the preview truncation, so a row
    that merely echoed the preview length would fail here.
    """
    kali, _kr, client = _wire_kali(monkeypatch, engagement, docker_desktop=False)
    body = b"finding-bearing scan output\n" * 5_000

    def fake_popen(argv, **kwargs):
        kwargs["stdout"].write(body)
        kwargs["stderr"].write(b"1 warning\n")
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["curl", "-sS", "https://api.example.com/v1/users"],
        technique="RECON",
        intent="enumerate users",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=engagement,
        tool_name="curl",
    )

    assert result.status == "completed"
    payload = _assert_row_hashes_what_it_names(client)
    assert payload["stdout_bytes"] == len(body)
    assert payload["stdout_sha256"] == hashlib.sha256(body).hexdigest()
    # The preview is a truncation; the byte count must not be derived from it.
    assert len(payload["stdout_preview"]) < len(body)


def test_kali_retry_row_hashes_the_attempt_that_produced_the_verdict(
    monkeypatch, engagement
):
    """CR-36 retry — the row's bytes, preview and verdict all describe attempt 2.

    The audit row's ``stdout_path`` is written once, pre-exec. If the retry
    streamed into a second file, the row would name attempt 1 while hashing
    attempt 2 (or vice versa) — internally incoherent evidence a later reader
    could not detect. The retry therefore re-runs into the same file and the
    losing attempt is preserved beside it.
    """
    kali, kali_resolve, client = _wire_kali(monkeypatch, engagement, docker_desktop=True)

    # Pre-flight resolution fails (no pin), so attempt 1 hits the flapping
    # container resolver; the guard re-resolves and retries with a pin.
    calls = {"n": 0}

    def flaky_resolve(host):
        calls["n"] += 1
        return [] if calls["n"] == 1 else ["203.0.113.7"]

    monkeypatch.setattr(kali_resolve, "resolve_host_ips", flaky_resolve)

    first = b"curl: (6) Could not resolve host: api.example.com\n"
    retry_body = b'{"users":[{"id":1},{"id":2}]}\n'
    attempts = {"n": 0}

    def fake_popen(argv, **kwargs):
        attempts["n"] += 1
        if attempts["n"] == 1:
            kwargs["stderr"].write(first)
            return _Proc(6)
        assert "--resolve" in argv, "retry must carry the host-resolved pin"
        kwargs["stdout"].write(retry_body)
        return _Proc(0)

    monkeypatch.setattr(kali.subprocess, "Popen", fake_popen)

    result = kali.kali_exec(
        ["curl", "-sS", "https://api.example.com/v1/users"],
        technique="RECON",
        intent="enumerate users",
        probe_kind="baseline",
        phase="recon",
        timeout=30,
        engagement_dir=engagement,
        tool_name="curl",
    )

    assert attempts["n"] == 2, "the guard must have retried"
    assert result.status == "completed"

    out_path, err_path = _row_paths(client)
    # The row still names the canonical file, and that file now holds attempt 2.
    assert out_path.name.endswith(".out") and ".retry" not in out_path.name
    assert out_path.read_bytes() == retry_body
    assert result.stdout_path == str(out_path)

    payload = _assert_row_hashes_what_it_names(client)
    assert payload["stdout_bytes"] == len(retry_body)
    assert payload["stdout_sha256"] == hashlib.sha256(retry_body).hexdigest()
    # Attempt 1 said nothing on stdout and its stderr must not leak into the
    # recorded truth for attempt 2.
    assert payload["stderr_bytes"] == 0
    assert payload["stderr_sha256"] == ""

    # The abandoned attempt survives on disk for forensics, under a name no
    # audit row references.
    kept_err = err_path.with_name(f"{err_path.stem}.attempt1{err_path.suffix}")
    assert kept_err.read_bytes() == first
    assert out_path.with_name(
        f"{out_path.stem}.attempt1{out_path.suffix}"
    ).read_bytes() == b""


def test_async_job_finalize_records_byte_truth(tmp_path) -> None:
    """The dtach lane finalizes its parent command-run from the job's spill.

    ``start_job`` opens ONE pair of files and writes it to both the job row and
    the paired command-run row, so hashing the job's paths is hashing the file
    the command-run row names.
    """
    from assess.lib import kali_jobs

    spill_dir = tmp_path / "scans" / "kali" / "jobs"
    spill_dir.mkdir(parents=True)
    out = spill_dir / "job.out"
    err = spill_dir / "job.err"
    body = b"nuclei: 3 findings\n" * 2_000
    out.write_bytes(body)
    err.write_bytes(b"")

    client = _RecordingClient()
    kali_jobs.finalize_parent_command_run(
        client,
        {
            "parent_command_run_id": 11,
            "started_at": "2026-08-25T09:00:00Z",
            "ended_at": "2026-08-25T09:04:00Z",
            "stdout_path": str(out),
            "stderr_path": str(err),
        },
        status_value="completed",
        return_code=0,
    )

    payload = client.patches[-1][1]
    assert payload["stdout_bytes"] == len(body)
    assert payload["stdout_sha256"] == hashlib.sha256(body).hexdigest()
    assert payload["stderr_bytes"] == 0
    assert payload["stderr_sha256"] == ""


def test_async_job_finalize_warns_when_run_uuid_cannot_be_resolved(capsys) -> None:
    from assess.lib import kali_jobs

    client = _RecordingClient()
    kali_jobs.finalize_parent_command_run(
        client,
        {"parent_command_run_id": 11},
        status_value="failed",
        return_code=1,
    )

    assert client.patches == []
    assert capsys.readouterr().err == (
        "warning: could not finalize parent command run id=11: "
        "job record has neither run_uuid nor stdout_path\n"
    )
