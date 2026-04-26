"""Host-side `aith assess kali` execution helper.

Owns the docker-exec subprocess, the audit pipeline (pre-exec POST + finalize
PATCH), output spilling under `${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}`,
process-group cleanup on timeout, scope/auth context capture, and dedup
warnings. Typed kali_* commands and the raw `kali exec` fallback all delegate
here.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import resource
import shlex
import signal
import subprocess
import sys
import time
import uuid
from importlib import util as _import_util
from pathlib import Path
from typing import Any, Optional

from .client import AssessError, AssessmentClient
from .config import Config, load_config


_DEFAULT_CONTAINER_NAME = "security-research"

_SHELL_BINARIES = frozenset({"sh", "bash", "dash", "zsh", "/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/sh", "/usr/bin/bash", "/usr/bin/env"})


_SHELL_KEYWORDS = frozenset({
    "for", "while", "until", "if", "elif", "case", "do", "done", "then", "else",
    "fi", "esac", "in", "select", "function", "time", "{", "}", "(", ")",
    "&&", "||", ";", ";;", "!", "exec",
})


def _is_plausible_executable(token: str) -> bool:
    if not token:
        return False
    # `VAR=value` env prefix.
    if "=" in token and token.split("=", 1)[0].isidentifier():
        return False
    # Shell keyword or operator.
    if token in _SHELL_KEYWORDS:
        return False
    # Trailing semicolons/operators (e.g. `true;`).
    if any(ch in token for ch in (";", "&", "|", "(", ")", "{", "}", "<", ">")):
        return False
    # Pure path argument (starts with `/` but no slashes after `bin`/`sbin`/`opt` etc — heuristic: an executable path is fine).
    return True


def _derive_tool_name(cmd: list[str]) -> str:
    """Pick the human-meaningful tool name from a command argv.

    Default: first argv token. Override: when the first token is a shell
    binary and a `-c` argument is present, parse the inner command and pick
    the first plausibly-executable token, skipping shell keywords
    (`for`/`while`/`if`/...), env-var prefixes (`FOO=bar`), redirection
    operators, and bare loop-iteration variables. Falls back to the shell
    binary itself if no plausible executable is found inside `-c`.
    """
    if not cmd:
        return "command"
    first = cmd[0]
    if first not in _SHELL_BINARIES:
        return first
    for idx, token in enumerate(cmd[1:-1], start=1):
        if token == "-c":
            try:
                inner = shlex.split(cmd[idx + 1])
            except ValueError:
                return first
            skip_until_after = None
            skip_next = False
            iterations_left = 64
            i = 0
            while i < len(inner) and iterations_left > 0:
                iterations_left -= 1
                part = inner[i]
                if skip_next:
                    skip_next = False
                    i += 1
                    continue
                if part in {">", "<", ">>", "<<", "2>", "2>>", "&>", "&>>", "<&", ">&"}:
                    skip_next = True
                    i += 1
                    continue
                if part in {"for", "while", "until"}:
                    skip_until_after = "do"
                    i += 1
                    continue
                if part == "if":
                    skip_until_after = "then"
                    i += 1
                    continue
                if skip_until_after is not None:
                    if part == skip_until_after:
                        skip_until_after = None
                    i += 1
                    continue
                if _is_plausible_executable(part):
                    return part
                i += 1
            return first
    return first


# Test-mode override: when set, skips both audit POST and `docker exec` so
# argparse round-trip tests don't require a live backend or container. The
# `run` callable on every kali_* command should still be reachable for `--help`
# without going through the helper.
_KALI_NOOP_ENV = "AITH_KALI_NOOP"


# Drift guard: import TECHNIQUE_ENUM / PROBE_KIND_ENUM from the runtime
# module so adding a new value lands in one place. The runtime sits at
# `docker/kali-mcp-runtime/audit_enums.py` (hyphen in path → not a package),
# so we load it via spec_from_file_location and tolerate its absence in
# install layouts that ship only the agent.


def _load_audit_enums() -> tuple[tuple[str, ...], tuple[str, ...]]:
    runtime_path = (
        Path(__file__).resolve().parents[4]
        / "docker"
        / "kali-mcp-runtime"
        / "audit_enums.py"
    )
    if not runtime_path.is_file():
        return (), ()
    spec = _import_util.spec_from_file_location("_kali_audit_enums_runtime", runtime_path)
    if spec is None or spec.loader is None:
        return (), ()
    module = _import_util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return (
        tuple(getattr(module, "TECHNIQUE_ENUM", ())),
        tuple(getattr(module, "PROBE_KIND_ENUM", ())),
    )


TECHNIQUE_ENUM, PROBE_KIND_ENUM = _load_audit_enums()


# Allowed phase enum mirrors orchestrator/backend/app/api/assessment.py
# `_ALLOWED_PHASES`. Fail closed if the agent passes anything else so the
# operator gets a clear error before the backend rejects with 422.
ALLOWED_PHASES: tuple[str, ...] = (
    "recon",
    "collect",
    "consume-test",
    "verify",
    "exploit",
    "report",
    "code-ingest",
    "code-classify",
    "code-hunt",
    "code-verify",
    "recon-pivot",
    "exploit-recon",
)


_INTENT_MAX_LEN = 200


@dataclasses.dataclass
class KaliResult:
    run_id: int | None
    status: str
    return_code: int | None
    stdout_path: str
    stderr_path: str
    duration_ms: int
    peak_rss_bytes: int | None
    stdout_preview: str
    stderr_preview: str
    timed_out: bool
    partial_results: bool


def _utcnow_iso() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _scope_version(engagement_dir: Path) -> str:
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return ""
    try:
        digest = hashlib.sha256(scope.read_bytes()).hexdigest()
    except OSError:
        return ""
    return digest[:16]


def _auth_context(engagement_dir: Path) -> str:
    auth = engagement_dir / "auth.json"
    if not auth.is_file():
        return "none"
    try:
        data = json.loads(auth.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "none"
    if not isinstance(data, dict):
        return "none"
    kind = data.get("kind") or data.get("mode") or "none"
    return str(kind) or "none"


def _validate_inputs(
    *,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    timeout: int,
    agent_name: str,
) -> None:
    if not technique:
        raise AssessError("--technique is required")
    if TECHNIQUE_ENUM and technique not in TECHNIQUE_ENUM:
        raise AssessError(
            f"--technique '{technique}' is not in TECHNIQUE_ENUM. "
            f"Allowed values: {', '.join(TECHNIQUE_ENUM)}"
        )
    if not intent:
        raise AssessError("--intent is required")
    if len(intent) > _INTENT_MAX_LEN:
        raise AssessError(f"--intent exceeds {_INTENT_MAX_LEN} characters")
    if not probe_kind:
        raise AssessError("--probe-kind is required")
    if PROBE_KIND_ENUM and probe_kind not in PROBE_KIND_ENUM:
        raise AssessError(
            f"--probe-kind '{probe_kind}' is not in PROBE_KIND_ENUM. "
            f"Allowed values: {', '.join(PROBE_KIND_ENUM)}"
        )
    if not phase:
        raise AssessError("--phase is required (no env-var fallback)")
    if phase not in ALLOWED_PHASES:
        raise AssessError(
            f"--phase '{phase}' is not allowed. Allowed values: {', '.join(ALLOWED_PHASES)}"
        )
    if timeout is None or timeout <= 0:
        raise AssessError("--timeout (seconds) is required and must be > 0")
    if not agent_name:
        raise AssessError("--agent-name is required (or set AGENT_NAME)")


def _peak_rss_kilobytes_to_bytes(peak_kb: int) -> int:
    # Linux exposes ru_maxrss in KB; macOS exposes it in bytes. Rather than
    # branch on platform, treat the number as KB on Linux (engagement runtime)
    # and fall back to "as reported" elsewhere. The audit field name uses
    # bytes so legacy MCP-era data stays consistent.
    if sys.platform == "linux":
        return peak_kb * 1024
    return peak_kb


def _read_proc_peak_rss(pid: int) -> Optional[int]:
    try:
        text = Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except OSError:
        return None
    for line in text.splitlines():
        if line.startswith("VmHWM:"):
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                return int(parts[1]) * 1024
    return None


def _container_pid_file(run_uuid: str) -> str:
    """Path inside the container where the wrapper shell records the user
    command's PID. Sharing the engagement-wide ``run_uuid`` here means the
    audit row, the strace artifact (when enabled), and this pid file all key
    on the same identifier — the operator can grep one ID across all three."""
    return f"/tmp/aith-pid-{run_uuid}.pid"


def _container_strace_file(run_uuid: str) -> str:
    return f"/tmp/aith-strace-{run_uuid}.log"


def _build_docker_exec(
    cmd: list[str],
    *,
    container_name: str,
    strace: bool,
    run_uuid: str,
) -> list[str]:
    """Wrap the user command in a tiny shell that records the in-container
    PID before ``exec``-ing the real command.

    The captured PID is the user command's PID because ``exec`` in POSIX
    shells reuses the calling shell's PID when replacing the process image.
    On wall-clock timeout the host helper reads this file via ``docker exec
    cat`` and issues ``docker exec kill -TERM/-KILL`` against the captured
    PID — that crosses the PID namespace boundary that ``os.killpg`` cannot.
    Without this, tools that trap SIGTERM (sqlmap, nuclei) survive the
    host-side process-group kill because they never see a signal."""
    pid_file = _container_pid_file(run_uuid)
    if strace:
        strace_log = _container_strace_file(run_uuid)
        wrapper = (
            f'echo $$ > {pid_file}; '
            f'exec strace -f -e trace=network,write,unlink '
            f'-o {strace_log} "$@"'
        )
    else:
        wrapper = f'echo $$ > {pid_file}; exec "$@"'
    return [
        "docker",
        "exec",
        container_name,
        "sh",
        "-c",
        wrapper,
        "sh",
        *cmd,
    ]


def _read_container_pid(container_name: str, run_uuid: str) -> int | None:
    """Best-effort fetch of the wrapper-recorded PID from inside the container.
    Returns ``None`` for any failure mode — empty file, container gone, race
    where the wrapper exec'd but hadn't yet written the file. Callers should
    fall back to host-side ``os.killpg`` when this returns ``None``."""
    pid_file = _container_pid_file(run_uuid)
    try:
        result = subprocess.run(
            ["docker", "exec", container_name, "cat", pid_file],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    raw = (result.stdout or "").strip().splitlines()
    if not raw:
        return None
    try:
        return int(raw[0])
    except ValueError:
        return None


def _kill_in_container(container_name: str, pid: int, signal_name: str) -> None:
    """Issue ``docker exec kill`` against the captured in-container PID. All
    failure modes are swallowed: the process may have already exited, the
    container may be gone, docker may not be reachable. Caller still has the
    host-side process-group kill as belt-and-braces."""
    try:
        subprocess.run(
            ["docker", "exec", container_name, "kill", f"-{signal_name}", str(pid)],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _cleanup_container_pid_file(container_name: str, run_uuid: str) -> None:
    pid_file = _container_pid_file(run_uuid)
    try:
        subprocess.run(
            ["docker", "exec", container_name, "rm", "-f", pid_file],
            check=False,
            capture_output=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return


def _check_container_running(container_name: str) -> None:
    try:
        result = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}", "--filter", f"name=^{container_name}$"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise AssessError(f"docker not reachable: {exc}") from exc
    if result.returncode != 0:
        raise AssessError(f"docker ps failed: {result.stderr.strip() or result.stdout.strip()}")
    if container_name not in (result.stdout or "").splitlines():
        raise AssessError(
            f"runtime container '{container_name}' is not running. "
            "Run `aith runtime start` first."
        )


def _post_pre_exec_row(
    client: AssessmentClient,
    *,
    cmd: list[str],
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool,
    agent_name: str,
    engagement_dir: Path,
    container_name: str,
    timeout: int,
    force: bool,
    started_at_iso: str,
    stdout_path: str,
    stderr_path: str,
    working_dir: str,
    scope_version: str,
    auth_context: str,
    tool_name: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command": " ".join(cmd),
        "argv": list(cmd),
        "tool_name": tool_name,
        "route": f"aith assess kali/{tool_name}",
        "agent_name": agent_name,
        "phase": phase,
        "started_at": started_at_iso,
        "completed_at": started_at_iso,
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "audit_source": "header",
        "technique": technique,
        "intent": intent[:_INTENT_MAX_LEN],
        "probe_kind": probe_kind,
        "destructive": destructive,
        "status": "running",
        "stdout_path": stdout_path,
        "stderr_path": stderr_path,
        "working_dir": working_dir,
        "scope_version": scope_version,
        "auth_context": auth_context,
        "timeout_seconds_requested": int(timeout),
        "force": bool(force),
    }
    return client.post("command-runs", payload)


def _patch_finalize(
    client: AssessmentClient,
    *,
    run_id: int,
    status: str,
    return_code: int | None,
    ended_at_iso: str,
    duration_ms: int,
    stdout_preview: str,
    stderr_preview: str,
    timed_out: bool,
    partial_results: bool,
    peak_rss_bytes: int | None,
    cpu_user_seconds: float | None,
    cpu_system_seconds: float | None,
    strace_path: str | None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "return_code": return_code,
        "ended_at": ended_at_iso,
        "duration_ms": int(duration_ms),
        "stdout_preview": stdout_preview,
        "stderr_preview": stderr_preview,
        "timed_out": bool(timed_out),
        "partial_results": bool(partial_results),
    }
    if peak_rss_bytes is not None:
        payload["peak_rss_bytes"] = int(peak_rss_bytes)
    if cpu_user_seconds is not None:
        payload["cpu_user_seconds"] = float(cpu_user_seconds)
    if cpu_system_seconds is not None:
        payload["cpu_system_seconds"] = float(cpu_system_seconds)
    if strace_path:
        payload["strace_path"] = strace_path
    return client.patch(f"command-runs/{int(run_id)}", payload)


def _build_preview(text: str, *, head_bytes: int = 4096, tail_bytes: int = 4096) -> str:
    raw = text.encode("utf-8", errors="replace") if isinstance(text, str) else bytes(text)
    if len(raw) <= head_bytes + tail_bytes:
        return raw.decode("utf-8", errors="replace")
    head = raw[:head_bytes].decode("utf-8", errors="replace")
    tail = raw[-tail_bytes:].decode("utf-8", errors="replace")
    return f"{head}\n...\n[truncated {len(raw) - head_bytes - tail_bytes} bytes]\n...\n{tail}"


def _read_safely(path: Path, *, max_bytes: int = 32_768) -> str:
    if not path.is_file():
        return ""
    try:
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
    except OSError:
        return ""
    if not data:
        return ""
    return _build_preview(data.decode("utf-8", errors="replace"), head_bytes=max_bytes // 2, tail_bytes=max_bytes // 2)


def _write_failed_audit_marker(engagement_dir: Path, *, run_uuid: str, error: str) -> None:
    marker_dir = engagement_dir / "scans" / "kali"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{run_uuid}.failed-audit"
    try:
        marker.write_text(f"{_utcnow_iso()} {error}\n", encoding="utf-8")
    except OSError:
        pass


def _resolve_agent_name(explicit: str | None) -> str:
    if explicit:
        return explicit
    env_value = os.environ.get("AGENT_NAME") or os.environ.get("AITH_AGENT_NAME") or ""
    return env_value


def _resolve_engagement_dir(explicit: Path | None, cfg: Config) -> Path:
    if explicit is not None:
        return Path(explicit).resolve()
    return Path(cfg.engagement_dir).resolve()


def kali_exec(
    cmd: list[str],
    *,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool = False,
    timeout: int,
    agent_name: str | None = None,
    engagement_dir: Path | None = None,
    engagement_key: str | None = None,
    force: bool = False,
    strace: bool = False,
    container_name: str = _DEFAULT_CONTAINER_NAME,
    config: Config | None = None,
    tool_name: str | None = None,
) -> KaliResult:
    """Run `cmd` inside the runtime container with full audit recording.

    The pre-exec audit row is written before docker-exec starts so a crash
    leaves a `running` row that can be reaped by orphan-sweep tooling.
    Stdout/stderr stream to disk from line 1 — never buffered in memory.
    """
    # When the caller passes engagement_dir explicitly (typically via
    # --engagement-dir hoisted by assess.cli), forward it to load_config so
    # config resolution doesn't fall back to env/cwd and erroneously
    # SystemExit with "Cannot resolve engagement directory."
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = _resolve_engagement_dir(engagement_dir, cfg)
    eng_key = engagement_key or eng_dir.name or cfg.engagement_key
    resolved_agent = _resolve_agent_name(agent_name)
    _validate_inputs(
        technique=technique,
        intent=intent,
        probe_kind=probe_kind,
        phase=phase,
        timeout=timeout,
        agent_name=resolved_agent,
    )

    run_uuid = uuid.uuid4().hex
    out_dir = eng_dir / "scans" / "kali"
    out_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = out_dir / f"{run_uuid}.out"
    stderr_path = out_dir / f"{run_uuid}.err"
    strace_path = out_dir / f"{run_uuid}.strace" if strace else None

    started_at_iso = _utcnow_iso()
    started_monotonic = time.monotonic()
    scope_version = _scope_version(eng_dir)
    auth_context = _auth_context(eng_dir)

    if os.environ.get(_KALI_NOOP_ENV):
        # Test-only short-circuit. Returns a synthetic result so argparse
        # smoke tests work without a real container or backend.
        return KaliResult(
            run_id=None,
            status="completed",
            return_code=0,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            duration_ms=0,
            peak_rss_bytes=None,
            stdout_preview="",
            stderr_preview="",
            timed_out=False,
            partial_results=False,
        )

    _check_container_running(container_name)

    derived_tool_name = tool_name or _derive_tool_name(cmd)
    docker_argv = _build_docker_exec(
        cmd,
        container_name=container_name,
        strace=strace,
        run_uuid=run_uuid,
    )

    client = AssessmentClient(cfg.base_url, eng_key)
    run_id: int | None = None
    superseded_by_id: int | None = None
    audit_failed = False
    try:
        try:
            row = _post_pre_exec_row(
                client,
                cmd=cmd,
                technique=technique,
                intent=intent,
                probe_kind=probe_kind,
                phase=phase,
                destructive=destructive,
                agent_name=resolved_agent,
                engagement_dir=eng_dir,
                container_name=container_name,
                timeout=timeout,
                force=force,
                started_at_iso=started_at_iso,
                stdout_path=str(stdout_path),
                stderr_path=str(stderr_path),
                working_dir=os.getcwd(),
                scope_version=scope_version,
                auth_context=auth_context,
                tool_name=derived_tool_name,
            )
            run_id = int(row.get("id")) if row.get("id") is not None else None
            superseded_by_id = row.get("superseded_by_id")
            if superseded_by_id and not force:
                print(
                    f"warning: dedup hit — equivalent command-run id={superseded_by_id} "
                    f"is still in flight; pass --force to bypass.",
                    file=sys.stderr,
                )
                return KaliResult(
                    run_id=run_id,
                    status="superseded",
                    return_code=None,
                    stdout_path=str(stdout_path),
                    stderr_path=str(stderr_path),
                    duration_ms=0,
                    peak_rss_bytes=None,
                    stdout_preview="",
                    stderr_preview="",
                    timed_out=False,
                    partial_results=False,
                )
        except AssessError as exc:
            print(
                f"warning: pre-exec audit POST failed: {exc}; continuing without audit row.",
                file=sys.stderr,
            )
            _write_failed_audit_marker(eng_dir, run_uuid=run_uuid, error=str(exc))
            audit_failed = True

        # Open output files BEFORE Popen so streaming starts at line 1.
        with stdout_path.open("wb") as out_fh, stderr_path.open("wb") as err_fh:
            try:
                process = subprocess.Popen(  # noqa: S603 — controlled argv
                    docker_argv,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    stdout=out_fh,
                    stderr=err_fh,
                    start_new_session=True,
                )
            except FileNotFoundError as exc:
                raise AssessError(f"docker not found: {exc}") from exc
            timed_out = False
            partial_results = False
            return_code: int | None = None
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                # Two-namespace kill cascade. ``os.killpg`` only signals the
                # host-side ``docker exec`` client and any siblings in our
                # process group — it cannot reach the user command running
                # inside the container's PID namespace under ``dockerd+tini``,
                # and dockerd's signal forwarding is best-effort. SIGTERM-
                # trapping tools (sqlmap, nuclei) survive that path. The
                # wrapper shell records the in-container PID to a pid file so
                # we can also send ``docker exec kill`` directly at the user
                # command across the namespace boundary.
                container_pid = _read_container_pid(container_name, run_uuid)
                if container_pid is not None:
                    _kill_in_container(container_name, container_pid, "TERM")
                else:
                    print(
                        f"warning: in-container pid file missing for run {run_uuid}; "
                        "relying on host-side process-group kill only.",
                        file=sys.stderr,
                    )
                try:
                    pgid = os.getpgid(process.pid)
                    os.killpg(pgid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass
                try:
                    return_code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if container_pid is not None:
                        _kill_in_container(container_name, container_pid, "KILL")
                    try:
                        pgid = os.getpgid(process.pid)
                        os.killpg(pgid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        return_code = process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        return_code = None
                _cleanup_container_pid_file(container_name, run_uuid)

        # Clean up the pid file on the happy path too so /tmp doesn't grow
        # unboundedly. The wrapper writes the file then ``exec``s the user
        # command, so by the time we get here the user command has exited
        # but the file remains.
        if not timed_out:
            _cleanup_container_pid_file(container_name, run_uuid)

        ended_at_iso = _utcnow_iso()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)

        # Resource snapshot. getrusage(RUSAGE_CHILDREN) is rolled-up across all
        # waited-for children of the calling process; for a single-shot CLI
        # call the caller is the lone child so the values are accurate.
        try:
            usage = resource.getrusage(resource.RUSAGE_CHILDREN)
            cpu_user_seconds = float(usage.ru_utime)
            cpu_system_seconds = float(usage.ru_stime)
            peak_rss_bytes: int | None = _peak_rss_kilobytes_to_bytes(int(usage.ru_maxrss))
        except OSError:
            cpu_user_seconds = None
            cpu_system_seconds = None
            peak_rss_bytes = None

        proc_peak = _read_proc_peak_rss(process.pid)
        if proc_peak is not None:
            peak_rss_bytes = proc_peak

        stdout_preview = _read_safely(stdout_path)
        stderr_preview = _read_safely(stderr_path)

        if timed_out and (stdout_preview or stderr_preview):
            partial_results = True

        if return_code is None:
            terminal_status = "killed"
        elif timed_out:
            terminal_status = "timed_out"
        elif return_code != 0:
            terminal_status = "failed"
        else:
            terminal_status = "completed"

        if run_id is not None and not audit_failed:
            try:
                _patch_finalize(
                    client,
                    run_id=run_id,
                    status=terminal_status,
                    return_code=return_code,
                    ended_at_iso=ended_at_iso,
                    duration_ms=duration_ms,
                    stdout_preview=stdout_preview,
                    stderr_preview=stderr_preview,
                    timed_out=timed_out,
                    partial_results=partial_results,
                    peak_rss_bytes=peak_rss_bytes,
                    cpu_user_seconds=cpu_user_seconds,
                    cpu_system_seconds=cpu_system_seconds,
                    strace_path=str(strace_path) if strace_path else None,
                )
            except AssessError as exc:
                print(
                    f"warning: finalize PATCH failed: {exc}; row stays running and may need orphan sweep.",
                    file=sys.stderr,
                )

        return KaliResult(
            run_id=run_id,
            status=terminal_status,
            return_code=return_code,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            duration_ms=duration_ms,
            peak_rss_bytes=peak_rss_bytes,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            timed_out=timed_out,
            partial_results=partial_results,
        )
    finally:
        client.close()


def add_required_kali_flags(parser) -> None:
    """Register the audit/lifecycle flags every kali_* subcommand needs.

    Author note: every flag here is intentionally `required=True` so the LLM
    cannot accidentally skip the audit context. Per-tool flags layer on top
    via the calling subcommand's argparse spec.
    """
    parser.add_argument(
        "--technique",
        required=True,
        help=(
            "Vulnerability-class technique tag (e.g. RECON, SSRF, SQLI). "
            f"Allowed: {', '.join(TECHNIQUE_ENUM) if TECHNIQUE_ENUM else 'see audit_enums.py'}"
        ),
    )
    parser.add_argument(
        "--intent",
        required=True,
        help=f"One-line purpose of this command (max {_INTENT_MAX_LEN} chars).",
    )
    parser.add_argument(
        "--probe-kind",
        required=True,
        dest="probe_kind",
        choices=list(PROBE_KIND_ENUM) if PROBE_KIND_ENUM else None,
        help="fingerprint | baseline | payload | exploit | replay | cleanup",
    )
    parser.add_argument(
        "--phase",
        required=True,
        choices=list(ALLOWED_PHASES),
        help=(
            "Phase the dispatching agent was authorized for. No env-var "
            "fallback — pass explicitly."
        ),
    )
    parser.add_argument(
        "--destructive",
        action="store_true",
        help="Mark this command as destructive (writes/edits/deletes on the target).",
    )
    parser.add_argument(
        "--timeout",
        required=True,
        type=int,
        help="Wall-clock budget in seconds. Suggested baseline: 1800.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass the dedup window check.",
    )
    parser.add_argument(
        "--strace",
        action="store_true",
        help="Wrap in `strace -e trace=network,write,unlink` and spill the artifact.",
    )
    parser.add_argument(
        "--agent-name",
        dest="kali_agent_name",
        default=None,
        help="Dispatching agent name (defaults to $AGENT_NAME / $AITH_AGENT_NAME).",
    )
    parser.add_argument(
        "--container-name",
        dest="container_name",
        default=_DEFAULT_CONTAINER_NAME,
        help=f"Docker container to exec into (default: {_DEFAULT_CONTAINER_NAME}).",
    )


def add_passthrough_args_flag(parser) -> None:
    """Adds the optional --extra-args raw-passthrough flag.

    The string is shlex-split and appended to the command argv after the
    typed-flag-derived arguments. Use for flags the typed verb does not
    yet model — the audit row still records the full argv, and --destructive
    still applies if the extra args toggle a destructive mode.
    """
    parser.add_argument(
        "--extra-args",
        default="",
        help="Raw additional CLI args appended to the underlying tool. shlex-split. Use sparingly; prefer typed flags.",
    )


def extend_cmd_with_extra_args(cmd: list[str], args) -> list[str]:
    """Append shlex-split extra args to cmd if the namespace has any."""
    extra = getattr(args, "extra_args", "") or ""
    if extra:
        cmd.extend(shlex.split(extra))
    return cmd


def kali_args_to_kwargs(args) -> dict[str, Any]:
    """Pull the audit/lifecycle flag values off an argparse Namespace.

    Returned dict can be splatted into kali_exec(**kwargs) directly. Includes
    `engagement_dir` so a per-call `--engagement-dir <path>` (root-parser
    flag, hoisted by `assess.cli._hoist_root_flags`) reaches kali_exec.
    Without this thread-through, --engagement-dir on a kali verb silently
    falls back to `$ENGAGEMENT_DIR` / cwd scope.json and the operator hits
    "Cannot resolve engagement directory" even when they passed it.
    """
    explicit_dir = getattr(args, "engagement_dir", None)
    kwargs: dict[str, Any] = {
        "technique": args.technique,
        "intent": args.intent,
        "probe_kind": args.probe_kind,
        "phase": args.phase,
        "destructive": bool(getattr(args, "destructive", False)),
        "timeout": int(args.timeout),
        "agent_name": getattr(args, "kali_agent_name", None),
        "force": bool(getattr(args, "force", False)),
        "strace": bool(getattr(args, "strace", False)),
        "container_name": getattr(args, "container_name", _DEFAULT_CONTAINER_NAME),
    }
    if explicit_dir:
        from pathlib import Path as _Path
        kwargs["engagement_dir"] = _Path(explicit_dir).expanduser().resolve()
    return kwargs


def emit_result(result: KaliResult) -> None:
    """Print a compact result summary suitable for both humans and `jq -R`.

    Stdout is one JSON object. Stderr already carries any warnings emitted
    during the run (dedup hit, audit failure, finalize failure).
    """
    print(
        json.dumps(
            {
                "run_id": result.run_id,
                "status": result.status,
                "return_code": result.return_code,
                "duration_ms": result.duration_ms,
                "stdout_path": result.stdout_path,
                "stderr_path": result.stderr_path,
                "peak_rss_bytes": result.peak_rss_bytes,
                "timed_out": result.timed_out,
                "partial_results": result.partial_results,
                "stdout_preview": result.stdout_preview,
                "stderr_preview": result.stderr_preview,
            },
            ensure_ascii=False,
        )
    )
