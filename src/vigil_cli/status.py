from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path

from . import docker
from .backup import latest_backup, live_database
from .config import get_config_value
from .engagements import list_engagements
from .image_freshness import proxy_image_drift
from .install_fs import atomic_write_bytes, open_pinned_directory
from .install_manifest import (
    INSTALL_META_FILENAME,
)
from .oob import oob_options, oob_status
from .oob_relay import has_pre_routing_oob_state, load_relay_route
from .orchestrator import orchestrator_status
from .paths import agent_root, default_runtime_container, engagements_root, resolve_orchestrator_base_url, resolve_orchestrator_data_dir
from .runtime import runtime_mounts_ok, runtime_resource_state, runtime_status


@dataclass(frozen=True, slots=True)
class Check:
    name: str
    status: str
    detail: str = ""
    # A prerequisite whose absence means this host cannot run Vigil at all, as
    # opposed to one whose absence is a legitimate steady state. `MISSING` is
    # used for both — an unset `oob.frp_token` and a missing Docker CLI produce
    # the same status string — so the distinction has to live here rather than
    # in the caller's status filter, which would otherwise have to hard-code
    # row names to tell "not configured" from "cannot run".
    required: bool = False


def git_head_sha(repo: Path | None) -> str | None:
    """Resolved HEAD commit sha of a git checkout, or None.

    Never raises: a missing ``git`` binary, a non-repo path, or an empty/unborn
    repo all yield None so the caller degrades to ``unknown`` instead of failing.
    """
    if repo is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    sha = (result.stdout or "").strip()
    return sha if result.returncode == 0 and sha else None


def _jj_working_copy_sha(repo: Path | None) -> str | None:
    """Commit sha of a Jujutsu working copy, or None when this is not one.

    ``--ignore-working-copy`` keeps this a pure read: every ordinary jj command
    snapshots the working copy first, and stamping an install or printing status
    must not mutate the user's repository as a side effect.
    """
    if repo is None or not (repo / ".jj").is_dir():
        return None
    try:
        result = subprocess.run(
            [
                "jj", "--repository", str(repo), "--ignore-working-copy",
                "log", "--revisions", "@", "--no-graph", "--template", "commit_id",
            ],
            text=True,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    sha = (result.stdout or "").strip()
    return sha if result.returncode == 0 and sha else None


def source_revision_sha(repo: Path | None) -> str | None:
    """Best-effort provenance revision for the source tree, or None.

    Jujutsu first, because this repository is jj-managed and in a colocated repo
    the jj working copy is a commit git HEAD does not track. ``--ignore-working-copy``
    intentionally avoids mutating the checkout, so this revision can lag live
    filesystem edits; the content digest, not this value, decides freshness.
    Plain git checkouts (and contributors who never touch jj) fall through to
    git unchanged. jj working-copy commits are real git objects in a colocated
    repo, so the result remains useful for provenance and commit-distance output.
    """
    # Release provenance is its validated content manifest, never a checkout.
    if repo is not None and (repo / "bundle.json").is_file():
        return None
    return _jj_working_copy_sha(repo) or git_head_sha(repo)


def source_content_sha256(repo: Path | None) -> str | None:
    """Digest current install-managed source bytes without consulting VCS state."""

    if repo is None:
        return None
    try:
        from .application import application_provenance

        return application_provenance(repo)["content_sha256"]
    except OSError:
        return None


def read_install_meta(install_root: Path) -> dict[str, object] | None:
    """Read ``.vigil-install-meta.json`` from the working root, or None.

    The stamp records the source revision and install-managed content digest that
    ``vigil install`` last synced. Missing, unreadable, or malformed files return
    None.
    """
    path = install_root.expanduser() / INSTALL_META_FILENAME
    try:
        parsed = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def write_install_meta(
    install_root: Path,
    source_root: Path,
    *,
    install_fd: int | None = None,
) -> dict[str, object]:
    """Record legacy-compatible application provenance, not copied workspace code.

    Canonical initialization truth lives in ``workspace.json``. This stamp
    retains revision/distance information for older workspace readers.
    """
    meta: dict[str, object] = {
        "source_sha": source_revision_sha(source_root),
        # Keep the legacy field name; the bytes now belong to the application.
        "source_content_sha256": source_content_sha256(source_root),
        "source_root": str(source_root),
        "installed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        payload = (json.dumps(meta, indent=2, sort_keys=True) + "\n").encode()
        if install_fd is None:
            pinned = open_pinned_directory(install_root)
            assert pinned is not None
            with pinned:
                atomic_write_bytes(
                    pinned.fd,
                    INSTALL_META_FILENAME,
                    payload,
                    mode=0o644,
                    display=pinned.path / INSTALL_META_FILENAME,
                )
        else:
            atomic_write_bytes(
                install_fd,
                INSTALL_META_FILENAME,
                payload,
                mode=0o644,
                display=install_root / INSTALL_META_FILENAME,
            )
    except OSError:
        pass
    return meta


def _resolve_source_root_offline(install_root: Path) -> Path | None:
    """Resolve the imported/pinned application without network or CWD discovery."""
    from .application import application_root_for_workspace

    try:
        return application_root_for_workspace(install_root)
    except (SystemExit, OSError, ValueError):
        return None


def _commits_behind(source_root: Path | None, installed_sha: str, current_sha: str) -> int | None:
    """How many commits the working root's stamped sha is behind the live source.

    Best-effort: returns None when the two shas are not comparable in this
    checkout (e.g. the installed sha is on a branch the local repo lacks).
    """
    if source_root is None:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(source_root), "rev-list", "--count", f"{installed_sha}..{current_sha}"],
            text=True,
            capture_output=True,
            check=False,
        )
    except (FileNotFoundError, OSError):
        return None
    if result.returncode != 0:
        return None
    text = (result.stdout or "").strip()
    return int(text) if text.isdigit() else None


def install_staleness(
    install_root: Path, *, source_root: Path | None = None
) -> dict[str, object]:
    """Compare workspace initialization provenance with the matched application.

    CLI, backend, prompts, docs and UI are one application release. This
    comparison describes workspace adoption; process restart requirements are
    derived separately by ``restart_manifest.consumer_states``.

    ``state`` is one of:
      - ``current``  workspace provenance matches application content
      - ``stale``    workspace provenance differs from application content
      - ``no-stamp`` install predates stamping (or the meta is unreadable) but a
                     application is resolvable — recommend initialize/adopt
      - ``unknown``  no live source content is readable to compare against

    Legacy revision-only stamps retain their original SHA comparison and commit
    distance behavior until the next install writes a content digest.
    """
    meta = read_install_meta(install_root)
    from .workspace import read_workspace
    workspace = read_workspace(install_root)
    installed_sha: str | None = None
    installed_content_sha256: str | None = None
    if isinstance(meta, dict):
        raw = meta.get("source_sha")
        installed_sha = raw if isinstance(raw, str) and raw else None
        raw_content = meta.get("source_content_sha256")
        installed_content_sha256 = (
            raw_content if isinstance(raw_content, str) and raw_content else None
        )
    if workspace is not None:
        application = workspace.get("application")
        if isinstance(application, dict):
            digest = application.get("content_sha256")
            if isinstance(digest, str) and digest:
                installed_content_sha256 = digest
    if source_root is None:
        source_root = _resolve_source_root_offline(install_root)
    current_sha = source_revision_sha(source_root)
    current_content_sha256 = source_content_sha256(source_root)

    result: dict[str, object] = {
        "installed_sha": installed_sha,
        "current_source_sha": current_sha,
        "installed_content_sha256": installed_content_sha256,
        "current_source_content_sha256": current_content_sha256,
        "source_root": str(source_root) if source_root is not None else None,
        "meta_present": workspace is not None or meta is not None,
    }
    if installed_content_sha256 is not None:
        result["comparison_basis"] = "content"
        if current_content_sha256 is None:
            result["state"] = "unknown"
            return result
        if installed_content_sha256 == current_content_sha256:
            result["state"] = "current"
            return result
        result["state"] = "stale"
        result["reason"] = (
            "source_content_changed_without_revision"
            if installed_sha is not None and installed_sha == current_sha
            else "source_content_changed"
        )
        if installed_sha is not None and current_sha is not None:
            behind = _commits_behind(source_root, installed_sha, current_sha)
            if behind is not None:
                result["behind_count"] = behind
        return result
    if installed_sha is None:
        result["comparison_basis"] = "none"
        result["state"] = (
            "no-stamp"
            if current_content_sha256 is not None or current_sha is not None
            else "unknown"
        )
        return result
    result["comparison_basis"] = "revision"
    if current_sha is None:
        result["state"] = "unknown"
        return result
    if installed_sha == current_sha:
        result["state"] = "current"
        return result
    result["state"] = "stale"
    behind = _commits_behind(source_root, installed_sha, current_sha)
    if behind is not None:
        result["behind_count"] = behind
    return result


def collect_status(
    install_root: Path,
    *,
    runner: docker.Runner = docker.run_command,
    write_check: bool = False,
) -> dict[str, object]:
    install_root = install_root.expanduser().resolve()
    rows = list_engagements(install_root)
    # C36: surface legacy engagement_type=both engagements that predate
    # dual-track phase tracking. The explicit repair command records the
    # initialization instead of asking an operator to edit durable state by hand.
    from .engagements import _both_engagements_missing_code_phase
    legacy_both_missing_code_phase = [
        eng_dir.name for eng_dir in _both_engagements_missing_code_phase(install_root)
    ]
    runtime_state = runtime_status(runner=runner)
    mitm_running = docker.container_running("vigil-proxy", runner=runner)
    # Drift is only meaningful for a running container; skip the two docker
    # inspects otherwise to keep `vigil status` cheap.
    mitm_image_drift = mitm_running and proxy_image_drift(runner=runner)
    backup = latest_backup(install_root)
    oob_token_configured = bool(os.environ.get("VIGIL_FRP_TOKEN") or get_config_value("oob.frp_token"))
    resolved_oob = oob_options(install_root)
    from .application import application_provenance, application_root_for_workspace
    from .restart_manifest import client_sessions_state
    from dataclasses import asdict
    try:
        application: dict[str, object] = dict(application_provenance(application_root_for_workspace(install_root)))
    except (OSError, SystemExit, ValueError) as exc:
        application = {"state": "unavailable", "detail": str(exc)}
    return {
        "install_root": str(install_root),
        "application": application,
        "client_sessions": asdict(client_sessions_state(install_root)),
        "install_exists": install_root.exists(),
        "engagement_count": len(rows),
        "orchestrator": {
            "state": orchestrator_status(install_root),
            "base_url": resolve_orchestrator_base_url(install_root),
            **(_orchestrator_readyz_bundle(install_root)),
        },
        "runtime": {
            "state": runtime_state,
            "image_exists": docker.image_exists("vigil:latest", runner=runner),
            "mounts_ok": runtime_mounts_ok(install_root, runner=runner) if runtime_state == "running" else None,
            "resources": runtime_resource_state(runner=runner),
        },
        "mitmproxy": {
            "state": "running" if mitm_running else "stopped",
            "image_exists": docker.image_exists("vigil-proxy:latest", runner=runner),
            "image_drift": bool(mitm_image_drift),
            "ca_volume": docker.volume_exists("mitmproxy-ca", runner=runner),
        },
        # deep=False keeps `vigil status` cheap (no per-client log reads / DNS probe);
        # `vigil oob status` runs the full health check.
        "oob": oob_status(
            oob_domain=resolved_oob.oob_domain,
            slot_prefix=resolved_oob.slot_prefix,
            dns_remote_port=resolved_oob.dns_remote_port,
            reverse_remote_port=resolved_oob.reverse_remote_port,
            runner=runner,
            deep=False,
        ) | {"frp_token_configured": oob_token_configured},
        "backup": {
            "latest": str(backup.path) if backup else None,
            "modified_at": backup.modified_at if backup else None,
        },
        "legacy_both_missing_code_phase": legacy_both_missing_code_phase,
        # Install-staleness guard (I-5): warn when the working root has fallen
        # behind the source it was installed from. Resolution is offline/cheap.
        "install_staleness": install_staleness(install_root),
        "database_write_check": (
            database_write_check(install_root)
            if write_check
            else {"status": "not_requested", "database": None, "detail": ""}
        ),
    }


def print_status(status: dict[str, object], *, json_output: bool = False) -> None:
    if json_output:
        print(json.dumps(status, indent=2))
        return
    print(f"install\t{status['install_root']}")
    application = status.get("application")
    if isinstance(application, dict):
        if application.get("state") == "unavailable":
            print(f"application\tunavailable\t{application.get('detail', '-')}")
        else:
            print(f"application\t{application.get('root', '-')}\tversion={application.get('version', 'unknown')}")
    client_sessions = status.get("client_sessions")
    if isinstance(client_sessions, dict) and client_sessions.get("state") == "stale":
        print(f"warn\tclient sessions require restart: {client_sessions.get('detail')}; {client_sessions.get('remedy')}")
    orchestrator_blk = status["orchestrator"]  # type: ignore[index]
    runtime = status["runtime"]  # type: ignore[index]
    mitmproxy = status["mitmproxy"]  # type: ignore[index]
    oob_block = status["oob"]
    oob = oob_block if isinstance(oob_block, dict) else {}
    backup = status["backup"]  # type: ignore[index]
    readiness = orchestrator_blk.get("readiness") if isinstance(orchestrator_blk, dict) else None
    ready_bits = ""
    if isinstance(readiness, dict):
        if readiness.get("reachable"):
            ready_bits = f"\treadyz_status={readiness.get('status')}\thttp={readiness.get('http_status')}"
        else:
            ready_bits = "\treadyz=unreachable"
    print(
        f"orchestrator\t{orchestrator_blk['state']}\thealthy={orchestrator_blk['healthy']}{ready_bits}"  # type: ignore[index]
    )
    backend_state = orchestrator_blk.get("backend_runtime_state") if isinstance(orchestrator_blk, dict) else None
    if isinstance(backend_state, dict) and backend_state.get("state") == "stale":
        print(
            f"warn\tbackend restart required: {backend_state.get('detail')}; "
            f"run `{backend_state.get('remedy')}`"
        )
    elif isinstance(readiness, dict):
        backend_runtime = readiness.get("backend_runtime")
        if isinstance(backend_runtime, dict) and backend_runtime.get("restart_required"):
            changed = backend_runtime.get("changed_inputs")
            preview = ", ".join(str(path) for path in changed[:3]) if isinstance(changed, list) else ""
            suffix = f" ({preview})" if preview else ""
            print(
                "warn\tbackend restart required: build inputs changed since the process "
                f"started{suffix}; run `vigil orchestrator restart`"
            )
    print(f"runtime\t{runtime['state']}\tmounts_ok={runtime['mounts_ok']}")  # type: ignore[index]
    resources = runtime.get("resources") if isinstance(runtime, dict) else None  # type: ignore[union-attr]
    if isinstance(resources, dict):
        configured = resources.get("configured") or {}
        live = resources.get("live") or {}
        configured_str = (
            f"memory={configured.get('memory_gb', '?')}g cpus={configured.get('cpus', '?')} "
            f"pids={configured.get('pids_limit', '?')} shm={configured.get('shm_size', '?')}"
        )
        live_str = ""
        if isinstance(live, dict) and live:
            live_str = (
                f"\tlive=memory.max={live.get('memory_max', '?')} "
                f"cpu.max={live.get('cpu_max', '?')} pids.max={live.get('pids_max', '?')}"
            )
        print(f"runtime-tier\t{configured_str}{live_str}")
    mitm_dict = mitmproxy if isinstance(mitmproxy, dict) else {}
    drift_note = "\trestart-needed" if mitm_dict.get("image_drift") else ""
    print(f"mitmproxy\t{mitm_dict.get('state', '-')}\tca_volume={mitm_dict.get('ca_volume')}{drift_note}")
    print(
        f"oob\t{oob.get('state', '-')}\tclients={len(oob.get('clients') or [])}"
        f"\tslot={oob.get('slot_prefix') or '-'}\tports={oob.get('port_range') or '-'}"
        f"\tdomain={oob.get('domain') or '-'}"
    )
    print(f"backup\t{backup['latest'] or '-'}")  # type: ignore[index]
    write_check = status.get("database_write_check")
    if isinstance(write_check, dict) and write_check.get("status") != "not_requested":
        detail = str(write_check.get("detail") or "")
        suffix = f"\t{detail}" if detail else ""
        print(f"database-write\t{write_check.get('status', 'storage_error')}{suffix}")
    legacy_keys = status.get("legacy_both_missing_code_phase") or []
    if isinstance(legacy_keys, list) and legacy_keys:
        preview = ", ".join(legacy_keys[:3]) + (" ..." if len(legacy_keys) > 3 else "")
        first_key = str(legacy_keys[0])
        print(
            f"warn\t{len(legacy_keys)} legacy `engagement_type=both` engagement(s) "
            f"missing `code_phase` ({preview}); run `vigil engagement repair-tracks "
            f"{first_key}` (once for each listed key)"
        )
    _print_install_staleness_warning(status.get("install_staleness"))


def _print_install_staleness_warning(staleness: object) -> None:
    """Non-fatal workspace-adoption notice; process restart truth is separate."""
    if not isinstance(staleness, dict):
        return
    state = staleness.get("state")
    if state == "stale":
        installed = _short_sha(staleness.get("installed_sha"))
        current = _short_sha(staleness.get("current_source_sha"))
        behind = staleness.get("behind_count")
        positively_behind = isinstance(behind, int) and behind > 0
        behind_str = f" ({behind} commit(s) behind)" if positively_behind else ""
        if staleness.get("reason") == "source_content_changed_without_revision":
            installed_content = _short_sha(staleness.get("installed_content_sha256"))
            current_content = _short_sha(staleness.get("current_source_content_sha256"))
            print(
                "warn\tworkspace provenance is stale: application files changed without a new "
                f"revision (revision {current}; recorded content {installed_content}, "
                f"application content {current_content}); run `vigil install` to adopt "
                "the matched application without copying source; check restart requirements above"
            )
            return
        relationship = (
            f"is behind source{behind_str}" if positively_behind else "differs from application"
        )
        print(
            f"warn\tworkspace provenance {relationship}: recorded {installed} "
            f"vs application {current}; run `vigil install` to adopt the matched application "
            "without copying source; check restart requirements above"
        )
    elif state == "no-stamp":
        print(
            "warn\tworkspace has no application provenance; run `vigil install` to adopt "
            "the matched application and preserve existing private data in place"
        )


def _short_sha(value: object) -> str:
    return value[:12] if isinstance(value, str) and value else "?"


def _install_staleness_check(install_root: Path) -> Check:
    """Workspace adoption provenance, as a doctor check."""
    staleness = install_staleness(install_root)
    state = str(staleness.get("state") or "unknown")
    if state == "current":
        return Check("install-staleness", "OK")
    if state == "unknown":
        return Check("install-staleness", "SKIPPED", "no matched application available")
    installed = _short_sha(staleness.get("installed_sha"))
    current = _short_sha(staleness.get("current_source_sha"))
    if staleness.get("reason") == "source_content_changed_without_revision":
        return Check(
            "install-staleness",
            "STALE",
            f"source files changed without a new revision at {current}; run `vigil install`",
        )
    return Check(
        "install-staleness",
        "STALE",
        f"{state}: workspace provenance at {installed}, application at {current}; run `vigil install`",
    )


# What an operator loses without ripgrep, said on the row rather than left to a
# bare MISSING. `agent/shared-constraints-code.md` ranks `rg` second only to the
# ctags index for code specialists and uses the ripgrep-only `--type` flag.
# Claude and OpenCode bundle their own Grep tool; the Codex and Goose hunters
# have shell only, so every search on a host without ripgrep is exit 127 — which
# a specialist reads as "no results", not "tool missing". That is the failure
# shape that makes a coverage tool report clean coverage of code it never read.
# Nothing else checks for it: ripgrep is in no dependency manifest and ships
# only in the runtime image, which code analysis does not use.
_RIPGREP_DEGRADATION = (
    "code-track search tool; Codex and Goose specialists have shell only, so "
    "their searches exit 127 and read as \"no results\" rather than \"tool "
    "missing\" — install ripgrep before running code analysis here"
)


def collect_doctor_checks(install_root: Path, *, runner: docker.Runner = docker.run_command) -> list[Check]:
    checks: list[Check] = []
    binary_status: dict[str, str] = {}
    for command in ("uv", "docker", "codex", "claude", "fzf", "rg"):
        check = _binary_check(command)
        # Docker alone is required: every runtime, orchestrator, and proxy path
        # goes through it. The client binaries are not — Vigil supports five and
        # an operator needs one — and `uv`/`npm` are build-time tools an install
        # can already have run. `rg` is advisory for the same reason `fzf` is:
        # useful, not universally installed, and not needed by a web engagement.
        if command in {"uv", "docker"} and check.status != "OK":
            check = replace(check, required=True)
        elif command == "rg" and check.status != "OK":
            check = replace(check, detail=_RIPGREP_DEGRADATION)
        checks.append(check)
        binary_status[command] = check.status
    install_root = install_root.expanduser().resolve()
    from .install import has_prior_install_state
    workspace_ready = has_prior_install_state(install_root)
    # Required: `vigil doctor` is the post-install health check AGENTS.md points
    # at after `vigil up`. With no install root or no agent tree there is nothing
    # to be healthy, and reporting that as advisory made the command exit 0.
    checks.append(
        Check(
            "install-root",
            "OK" if workspace_ready else "MISSING",
            str(install_root),
            required=not workspace_ready,
        )
    )
    application_error = "matched application unavailable"
    try:
        application_agent = agent_root(install_root)
        agent_dir_present = application_agent.is_dir()
    except (OSError, SystemExit, ValueError) as exc:
        application_agent = None
        agent_dir_present = False
        application_error = f"{application_error}: {exc}"
    if application_agent is not None:
        from .application import application_provenance
        provenance = application_provenance(application_agent.parent)
        checks.append(Check("application", "OK", f"version={provenance['version']} root={provenance['root']}"))
    else:
        checks.append(Check("application", "MISSING", application_error, required=True))
    from .restart_manifest import client_sessions_state
    sessions = client_sessions_state(install_root)
    session_status = "STALE" if sessions.state == "stale" else "WARN" if sessions.state == "unknown" else "OK"
    checks.append(Check("client-sessions", session_status,
                        f"{sessions.detail}; {sessions.remedy}" if sessions.remedy else sessions.detail))
    checks.append(
        Check(
            "agent-dir",
            "OK" if agent_dir_present else "MISSING",
            str(application_agent) if application_agent is not None else "matched application assets unavailable",
            required=not agent_dir_present,
        )
    )
    data_dir = resolve_orchestrator_data_dir(install_root)
    checks.append(Check("backend-data", "OK" if data_dir.is_dir() else "MISSING"))
    checks.append(_database_check(data_dir / "orchestrator.sqlite3"))
    if binary_status.get("docker") == "OK":
        checks.append(Check("docker-daemon", "OK" if docker.daemon_available(runner=runner) else "FAIL"))
        checks.append(Check("runtime-image", "OK" if docker.image_exists("vigil:latest", runner=runner) else "MISSING"))
        checks.append(Check("mitmproxy-image", "OK" if docker.image_exists("vigil-proxy:latest", runner=runner) else "MISSING"))
        # Drift only exists for a running container; a stopped/absent proxy is
        # OK because the next `vigil mitmproxy start` picks up the current image.
        mitm_drift = docker.container_running("vigil-proxy", runner=runner) and proxy_image_drift(runner=runner)
        checks.append(
            Check("mitmproxy-container-drift", "STALE", "container older than image; run `vigil mitmproxy start`")
            if mitm_drift
            else Check("mitmproxy-container-drift", "OK")
        )
        if runtime_status(runner=runner) == "running":
            checks.append(Check("runtime-mounts", "OK" if runtime_mounts_ok(install_root, runner=runner) else "FAIL"))
            for tool in ("dtach", "tmux", "frpc", "interactsh-server", "interactsh-client"):
                result = runner(["docker", "exec", default_runtime_container(), "sh", "-lc", f"command -v {tool} >/dev/null"])
                checks.append(Check(f"runtime-tool:{tool}", "OK" if result.returncode == 0 else "MISSING"))
    else:
        detail = "docker CLI not found" if binary_status.get("docker") == "MISSING" else "docker --version failed"
        checks.append(Check("docker-daemon", "SKIPPED", detail))
        checks.append(Check("runtime-image", "SKIPPED", detail))
        checks.append(Check("mitmproxy-image", "SKIPPED", detail))
    if orchestrator_status(install_root) == "running":
        healthy, readiness = _orchestrator_readyz_snapshot(install_root)
        detail = ""
        if not healthy:
            if not readiness.get("reachable"):
                detail = "/readyz unreachable"
            elif readiness.get("status") == "not_ready":
                detail = "/readyz reports not_ready (schema/database)"
            elif readiness.get("http_status") is not None:
                detail = f"/readyz HTTP {readiness['http_status']}"
        checks.append(Check("orchestrator-health", "OK" if healthy else "FAIL", detail))
        checks.append(_backend_runtime_check(install_root, readiness))
    backup = latest_backup(install_root)
    checks.append(Check("backup-latest", "OK" if backup else "MISSING", str(backup.path) if backup else ""))
    checks.append(_install_staleness_check(install_root))
    checks.append(_failed_audit_marker_check(install_root))
    checks.append(_host_recon_tools_check())
    checks.append(_oob_relay_check(install_root))
    checks.append(_oob_token_check())
    return checks


def print_doctor(checks: list[Check]) -> None:
    for check in checks:
        suffix = f"\t{check.detail}" if check.detail else ""
        print(f"{check.status}\t{check.name}{suffix}")



def _oob_token_check() -> Check:
    """The FRP shared secret, with the command that sets it.

    A bare MISSING row leaves the operator to guess; `vigil oob start` refuses
    without this, so the remedy belongs next to the finding.
    """
    if os.environ.get("VIGIL_FRP_TOKEN") or get_config_value("oob.frp_token"):
        return Check("oob.frp_token", "OK")
    return Check(
        "oob.frp_token",
        "MISSING",
        "required by `vigil oob start`; set `vigil config set oob.frp_token <token>` "
        "(or export VIGIL_FRP_TOKEN) — it must match your frps `auth.token`",
    )

def _oob_relay_check(install_root: Path) -> Check:
    try:
        route = load_relay_route(install_root)
    except SystemExit as exc:
        return Check("oob.relay-route", "FAIL", str(exc))
    if route is None:
        # `vigil install` allocates a route only when oob.domain is already set,
        # so the remedy depends on whether it is. Naming `vigil install` while
        # the domain is unset sends the operator round a loop that cannot clear
        # this warning.
        configured_domain = (
            os.environ.get("VIGIL_OOB_DOMAIN")
            or get_config_value("oob.domain")
            or ""
        )
        if not configured_domain:
            # The parenthetical answers "will allocating a slot move my live
            # callbacks?", which only a root already running OOB on the shared
            # route can ask. Asserting it unconditionally told every fresh root
            # about state it does not have — the same defect `install.py` carries
            # the conditional for, and the reason
            # `oob_relay.has_pre_routing_oob_state` is a public name.
            kept = (
                " (a root already running OOB on the shared 53/8443 route keeps that "
                "route instead)"
                if has_pre_routing_oob_state(install_root)
                else ""
            )
            return Check(
                "oob.relay-route",
                "WARN",
                "no OOB route allocated; set `vigil config set oob.domain <domain>` "
                f"then `vigil install`, which reserves this install its own relay slot{kept}",
            )
        if has_pre_routing_oob_state(install_root):
            return Check(
                "oob.relay-route",
                "WARN",
                "no relay-slot metadata; run `vigil install` to pin the shared 53/8443 "
                "route this root is already running OOB on",
            )
        return Check(
            "oob.relay-route",
            "WARN",
            "no relay-slot metadata; run `vigil install` to allocate this install's slot",
        )
    mode = "legacy-pinned" if route.legacy else "slot"
    return Check(
        "oob.relay-route",
        "OK",
        f"{mode}={route.slot_prefix} domain={route.oob_domain} ports={route.dns_remote_port}-{route.reverse_remote_port}",
    )


def _host_recon_tools_check() -> Check:
    """Host-side recon binaries the `--runtime host` / `vigil assess recon` path
    needs on macOS Docker Desktop (DNS-heavy + bulk-liveness; I-001). WARN-only —
    they are unneeded on native Linux / remote Docker, and the recon job's
    enforce-preflight is the hard gate at run time."""
    from .runtime import host_recon_tool_status, missing_essential_host_tools

    statuses = host_recon_tool_status()
    missing_essential = missing_essential_host_tools()
    if missing_essential:
        return Check(
            "host-recon-tools", "WARN",
            "missing " + ", ".join(missing_essential)
            + " — see docs/installation.md 'Recon runtime: host vs container' for install commands "
            "(needed for --runtime host on Docker Desktop)",
        )
    present = [t.binary for t, present in statuses if present]
    return Check("host-recon-tools", "OK", "present: " + ", ".join(present))


def _binary_check(command: str) -> Check:
    if shutil.which(command) is None:
        return Check(command, "MISSING")
    try:
        result = subprocess.run([command, "--version"], text=True, capture_output=True, check=False)
    except FileNotFoundError:
        return Check(command, "MISSING")
    return Check(command, "OK" if result.returncode == 0 else "FAIL")


def _database_check(path: Path, *, timeout_seconds: float = 2.0) -> Check:
    """Report the orchestrator database's integrity.

    ``PRAGMA quick_check`` reports corruption in its RESULT ROW — it returns the
    first errors it finds and does not raise — so reading the row is the whole
    check. Discarding it makes this report OK on a corrupt database, which is the
    one condition an operator runs ``vigil doctor`` to rule out. Mirrors the
    verification ``backup.py`` already performs on every snapshot it writes.
    """
    if not path.exists():
        return Check("orchestrator-db", "MISSING", str(path))
    timed_out = False
    deadline = time.monotonic() + max(timeout_seconds, 0.0)

    def _cancel_when_expired() -> int:
        nonlocal timed_out
        timed_out = time.monotonic() >= deadline
        return int(timed_out)

    try:
        with sqlite3.connect(str(path)) as connection:
            connection.set_progress_handler(_cancel_when_expired, 1_000)
            try:
                row = connection.execute("PRAGMA quick_check").fetchone()
            finally:
                connection.set_progress_handler(None, 0)
    except sqlite3.Error as exc:
        if timed_out and "interrupted" in str(exc).lower():
            return Check(
                "orchestrator-db",
                "WARN",
                f"{path}: integrity scan timed out after {timeout_seconds:g}s",
            )
        return Check("orchestrator-db", "FAIL", str(exc))
    if not row or row[0] != "ok":
        detail = str(row[0]) if row else "quick_check returned no result"
        return Check("orchestrator-db", "FAIL", f"{path}: {detail}")
    return Check("orchestrator-db", "OK", str(path))


def database_write_check(
    install_root: Path,
    *,
    timeout_seconds: float = 0.25,
) -> dict[str, object]:
    """Prove the existing main SQLite database is writable, then roll back.

    ``mode=rw`` prevents a typo or missing installation from creating a new,
    empty database. The schema write is deliberately stronger than a temporary
    table or ``SELECT`` probe: it exercises the same main database that durable
    assessment state uses. SQLite transactional DDL lets the table and its row
    disappear in the same rollback.
    """
    path = live_database(install_root).expanduser().resolve()
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            f"{path.as_uri()}?mode=rw",
            uri=True,
            timeout=timeout_seconds,
            isolation_level=None,
        )
        connection.execute("BEGIN IMMEDIATE")
        collision = connection.execute(
            "SELECT 1 FROM main.sqlite_master WHERE type = 'table' "
            "AND name = '_vigil_status_write_probe'"
        ).fetchone()
        if collision is not None:
            connection.rollback()
            return {
                "status": "storage_error",
                "database": str(path),
                "detail": "reserved probe table already exists",
            }
        connection.execute(
            "CREATE TABLE main._vigil_status_write_probe "
            "(marker INTEGER NOT NULL)"
        )
        connection.execute(
            "INSERT INTO main._vigil_status_write_probe (marker) VALUES (1)"
        )
        connection.rollback()
        leftover = connection.execute(
            "SELECT 1 FROM main.sqlite_master WHERE type = 'table' "
            "AND name = '_vigil_status_write_probe'"
        ).fetchone()
        if leftover is not None:
            return {
                "status": "storage_error",
                "database": str(path),
                "detail": "probe rollback left schema residue",
            }
        return {"status": "ok", "database": str(path), "detail": "write rolled back"}
    except sqlite3.Error as exc:
        if connection is not None and connection.in_transaction:
            connection.rollback()
        return {
            "status": _database_write_error_status(exc),
            "database": str(path),
            "detail": str(exc),
        }
    finally:
        if connection is not None:
            connection.close()


def _database_write_error_status(exc: sqlite3.Error) -> str:
    raw_code = getattr(exc, "sqlite_errorcode", None)
    primary_code = raw_code & 0xFF if isinstance(raw_code, int) else None
    if primary_code in {sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED}:
        return "busy"
    if primary_code == sqlite3.SQLITE_READONLY:
        return "read_only"
    if primary_code == sqlite3.SQLITE_CANTOPEN:
        return "missing_or_unopenable"
    return "storage_error"


def _orchestrator_readyz_snapshot(install_root: Path) -> tuple[bool, dict[str, object]]:
    """Fetch ``/readyz`` and return ``(healthy, readiness)``.

    ``healthy`` is True when the endpoint returns HTTP 200 (orchestrator ready for work).
    ``readiness`` surfaces connection reachability, HTTP status, and parsed JSON fields
    when the response body is JSON (mirrors the backend ``/readyz`` payload shape).
    """
    url = f"{resolve_orchestrator_base_url(install_root)}/readyz"
    readiness: dict[str, object] = {
        "reachable": False,
        # Why there was no answer, when there was none. Collapsing every OSError
        # into `reachable: False` made a refused connection and a backend that
        # simply did not answer within the timeout indistinguishable, and
        # `restart_manifest` read the pair as "the process is stopped".
        "unreachable_reason": None,
        "unreachable_detail": None,
        "http_status": None,
        "status": None,
        "database_connected": None,
        "assessment_schema_ready": None,
        "code_analysis_schema_ready": None,
        "backend_runtime": None,
    }
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            readiness["reachable"] = True
            readiness["http_status"] = response.status
            _merge_readyz_payload(readiness, response.read())
            healthy = response.status == 200
            return healthy, readiness
    except urllib.error.HTTPError as exc:
        readiness["reachable"] = True
        readiness["http_status"] = exc.code
        _merge_readyz_payload(readiness, exc.read())
        return False, readiness
    except OSError as exc:
        readiness["unreachable_reason"] = _unreachable_reason(exc)
        readiness["unreachable_detail"] = str(exc) or exc.__class__.__name__
        return False, readiness


def _unreachable_reason(exc: OSError) -> str:
    """Classify a failed `/readyz` probe: `refused`, `timeout`, or `error`.

    `urlopen` wraps connection-level failures in `URLError`, so the OSError that
    actually describes what happened is one level down in ``reason``. The
    distinction matters to `restart_manifest`: a refusal means nothing accepted
    the connection, while a timeout means something did and then went quiet —
    a live process whose loaded code an install can invalidate.
    """
    reason = getattr(exc, "reason", None)
    inner = reason if isinstance(reason, OSError) else exc
    if isinstance(inner, TimeoutError):
        return "timeout"
    if isinstance(inner, ConnectionRefusedError):
        return "refused"
    return "error"


def _merge_readyz_payload(readiness: dict[str, object], raw: bytes) -> None:
    try:
        parsed = json.loads(raw.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(parsed, dict):
        return
    for key in (
        "status",
        "database_connected",
        "assessment_schema_ready",
        "code_analysis_schema_ready",
        "backend_runtime",
    ):
        if key in parsed:
            readiness[key] = parsed[key]


def _orchestrator_readyz_bundle(install_root: Path) -> dict[str, object]:
    healthy, readiness = _orchestrator_readyz_snapshot(install_root)
    return {
        "healthy": healthy, "readiness": readiness,
        "backend_runtime_state": _backend_runtime_state(install_root, readiness),
    }


def _backend_runtime_state(install_root: Path, readiness: dict[str, object]) -> dict[str, object]:
    from dataclasses import asdict
    from .restart_manifest import backend_state_from_readiness

    try:
        return asdict(backend_state_from_readiness(install_root, readiness))
    except (OSError, SystemExit, ValueError) as exc:
        return {"key": "backend", "state": "unknown", "remedy": "", "detail": str(exc)}


def _backend_runtime_check(install_root: Path, readiness: dict[str, object]) -> Check:
    state = _backend_runtime_state(install_root, readiness)
    detail = str(state.get("detail") or "")
    if state["state"] == "stale":
        return Check("backend-runtime", "STALE", f"{detail}; run `{state['remedy']}`")
    if state["state"] == "current":
        return Check("backend-runtime", "OK")
    return Check("backend-runtime", "WARN", detail)


def list_failed_audit_markers(engagement_dir: Path) -> list[Path]:
    """Return ``<run_uuid>.failed-audit`` markers under ``scans/kali/`` for one engagement.

    Each marker is written by ``agent/scripts/assess/lib/kali.py`` when the
    pre-exec audit POST to the orchestrator backend fails. The assess CLI
    refuses execution; the marker retains the failed attempt and backend error
    for diagnosis without manufacturing an unaudited target request.

    Returns the markers sorted newest-first by mtime so callers can show the
    most recent ones without re-sorting. Missing directories return ``[]``.
    """
    marker_dir = engagement_dir / "scans" / "kali"
    if not marker_dir.is_dir():
        return []
    markers = [path for path in marker_dir.glob("*.failed-audit") if path.is_file()]
    markers.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return markers


def _failed_audit_marker_check(install_root: Path) -> Check:
    """Surface orphaned ``<run_uuid>.failed-audit`` markers across engagements.

    The marker is the on-disk signal that an ``vigil assess kali`` run was
    refused because its backend audit row could not be created. Surface a WARN
    with per-engagement counts plus the most recent marker paths (capped at 5
    per engagement) so the operator can diagnose the write path.
    """
    root = engagements_root(install_root)
    if not root.is_dir():
        return Check("failed-audit-markers", "OK", "no engagements directory")
    per_engagement: list[tuple[Path, list[Path]]] = []
    total = 0
    for eng_dir in sorted(root.glob("*")):
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        markers = list_failed_audit_markers(eng_dir)
        if markers:
            per_engagement.append((eng_dir, markers))
            total += len(markers)
    if total == 0:
        return Check("failed-audit-markers", "OK", "no orphaned markers")
    parts: list[str] = [f"{total} orphaned marker(s) across {len(per_engagement)} engagement(s)"]
    for eng_dir, markers in per_engagement:
        recent = markers[:5]
        recent_paths = ", ".join(str(path) for path in recent)
        suffix = f" (+{len(markers) - len(recent)} more)" if len(markers) > len(recent) else ""
        parts.append(f"{eng_dir.name}: {len(markers)} — {recent_paths}{suffix}")
    return Check("failed-audit-markers", "WARN", "; ".join(parts))
