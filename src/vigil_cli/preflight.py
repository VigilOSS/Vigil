"""Launch-time preflight shared by every path that execs an operator client.

Two entrypoints exec the generated launcher — ``vigil engagement start``
(`main`) and ``vigil blue engage --start`` (`blue`) — and both must run the
same checks. ``main`` imports ``blue``, so this cannot live in either of them;
it lives here so both can import it without a cycle.

The stale-install warning fires HERE ONLY. It used to also ride the ``vigil
assess`` exec passthrough, which an operator and every specialist call for each
finding, fetch, and queue closeout — so one lagging root emitted hundreds of
identical stderr lines per engagement, on the channel real failures use. A
warning that repeats that often stops being read, which costs exactly the run
that needed it. Engagement start is where it is both actionable (nothing is
in flight yet) and read.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .engagements import CLIENT_PROVIDER_KEY, _read_json
from .orchestrator import orchestrator_status
from .runtime import runtime_status
from .status import install_staleness
from .paths import resolve_orchestrator_base_url

def _resolve_provider_key(install_root: Path, engagement_dir: Path, key: str) -> str | None:
    """Resolve one provider key exactly as the generated launcher does.

    Environment first, then the engagement's `.orchestrator.env`, then the install
    root's `.orchestrator.env` and `.env` — first hit wins (see
    `engagements._write_launcher`'s provider block).
    """
    # Normalize the inherited value too, not just file assignments: an ambient
    # `KEY=""` or whitespace would otherwise shadow a usable key in the env files
    # and reach the provider as junk.
    value = _dotenv_value(os.environ.get(key) or "")
    if value:
        return value
    for env_file in (
        engagement_dir / ".orchestrator.env",
        install_root / ".orchestrator.env",
        install_root / ".env",
    ):
        try:
            lines = env_file.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise SystemExit(
                f"provider-key preflight cannot read {env_file} as UTF-8; "
                "repair or replace that env file before launching. "
                "Pass --skip-preflight to launch anyway."
            ) from exc
        except OSError:
            continue
        assignments = [
            _dotenv_value(line.split("=", 1)[1])
            for line in lines
            if line.startswith(f"{key}=")
        ]
        if assignments and assignments[-1]:
            return assignments[-1]
    return None


def _dotenv_value(raw: str) -> str:
    """Normalize one dotenv assignment the way a shell would read it.

    `KEY=""` is a conventional placeholder for "not set yet". Taking the two
    quote characters literally makes the preflight pass and the launcher export
    quotes instead of a credential, so the operator learns at the first provider
    request rather than before the session starts. A genuinely quoted value is
    unwrapped for the same reason.
    """
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value.strip()


def _preflight_engagement_start(
    install_root: Path, engagement_dir: Path, client: str, *, mode: str | None = None
) -> None:
    """Validate the client and durable backend before launching a session.

    A stopped managed backend starts here. An explicit endpoint is checked
    without starting a different service. Static code review never queries
    Docker; audited execution starts its managed runtime on first use.

    Every line goes to stderr: `vigil blue engage --start` prints the bare
    engagement path on stdout for `eng=$(…)` capture.
    """
    from .engagements import resolve_engagement_mode
    mode = resolve_engagement_mode(engagement_dir, mode, client=client, install_root=install_root)
    if client == "zcode":
        if mode not in {"web", "code"}:
            raise SystemExit("ZCode assessment start supports web/code only")
        from .remediation_clients import _zcode_application
        _zcode_application()
    elif shutil.which(client) is None:
        raise SystemExit(
            f"{client} CLI not found on PATH; install it, or start a different client "
            f"with `vigil engagement start {engagement_dir.name} --client <name>`. "
            "Pass --skip-preflight to launch anyway."
        )
    provider_key = None if client == "opencode" and mode in {"web", "code"} else CLIENT_PROVIDER_KEY.get(client)
    if provider_key and not _resolve_provider_key(
        install_root, engagement_dir, provider_key
    ):
        raise SystemExit(
            f"{client} needs {provider_key}; set it in the environment, in "
            f"{engagement_dir / '.orchestrator.env'}, or in {install_root / '.env'}. "
            "Pass --skip-preflight to launch anyway."
        )

    if client == "pi" and mode != "remediation":
        raise SystemExit("Pi supports remediation engagements only; select codex or claude for this engagement.")
    _ensure_engagement_backend(install_root, engagement_dir)
    scope = _read_json(engagement_dir / "scope.json")
    tracks = scope.get("tracks")
    static_code = mode == "code" or (mode is None and (
        scope.get("engagement_type") == "code" or (isinstance(tracks, dict) and set(tracks) == {"code"})
    ))
    if not static_code:
        try:
            runtime_state = runtime_status()
        except Exception:  # noqa: BLE001 — a diagnostic must never block the launch
            runtime_state = "unknown"
        if runtime_state != "running":
            print(
                f"[vigil] WARN: Kali runtime container is {runtime_state}; "
                "audited execution starts the managed runtime on demand.",
                file=sys.stderr,
            )
    _warn_if_ripgrep_missing()
    _warn_if_install_stale(install_root)


def managed_backend_host(base_url: str) -> str | None:
    """Only literal HTTP loopback endpoints at the managed port convey start authority."""
    import ipaddress
    from urllib.parse import urlsplit
    try:
        parsed = urlsplit(base_url)
        if (parsed.scheme != "http" or parsed.port != 18000 or parsed.path not in {"", "/"}
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            return None
        host = parsed.hostname or ""
        if host == "localhost":
            return "127.0.0.1"
        return host if ipaddress.ip_address(host).is_loopback else None
    except ValueError:
        return None


def _ensure_backend_freshness(install_root: Path, base_url: str) -> None:
    import json
    import shlex
    from .engagements import _backend_request
    from .restart_manifest import backend_state_from_readiness

    status, body, _detail, _protocol = _backend_request(base_url, "GET", "/readyz")
    try:
        readiness = json.loads(body) if status is not None else {}
        if not isinstance(readiness, dict):
            readiness = {}
    except (ValueError, UnicodeError):
        readiness = {}
    readiness.update(reachable=status is not None, http_status=status)
    consumer = backend_state_from_readiness(install_root, readiness)
    runtime = readiness.get("backend_runtime")
    stale = consumer.state == "stale" or (isinstance(runtime, dict) and runtime.get("restart_required") is True)
    if stale:
        remedy = ("run `" + shlex.join(["vigil", "--root", str(install_root), "orchestrator", "restart"]) + "`"
                  if managed_backend_host(base_url) is not None
                  else f"restart or upgrade the configured backend at {base_url} on its owning host")
        raise SystemExit(f"Engagement backend requires restart: {consumer.detail}; {remedy}. Pass --skip-preflight to launch anyway.")
    if consumer.state == "unknown":
        print(f"[vigil] WARN: backend freshness at {base_url} is unknown: {consumer.detail}; upgrade/restart that backend to verify its release.", file=sys.stderr)


def _ensure_engagement_backend(install_root: Path, engagement_dir: Path) -> None:
    """Recover managed local state without retargeting an explicit endpoint."""
    from contextlib import redirect_stdout
    from . import engagements, orchestrator

    base_url = resolve_orchestrator_base_url(install_root, engagement_dir)
    managed_host = managed_backend_host(base_url)
    ownership = engagements.inspect_backend_ownership(install_root, engagement_dir)
    verified_ownership: engagements.BackendOwnership | None = ownership
    engagements.require_backend_ownership(ownership, install_root)
    if ownership.state == engagements.BackendInstallRootStatus.PROTOCOL_ERROR:
        raise SystemExit(f"engagement backend is not ready at {base_url}: protocol error: {ownership.detail}. Pass --skip-preflight to launch anyway.")
    if (managed_host is not None and ownership.state == engagements.BackendInstallRootStatus.UNREACHABLE
            and orchestrator_status(install_root) != "running"):
        print("[vigil] Starting the engagement backend...", file=sys.stderr)
        with redirect_stdout(sys.stderr):
            orchestrator.start_orchestrator(orchestrator.OrchestratorOptions(install_root=install_root, host=managed_host, allow_existing=True))
        verified_ownership = None
    backend_state = engagements._verify_backend_install_root(install_root, engagement_dir, verified_ownership)
    if backend_state in {engagements.BackendInstallRootStatus.SYNC_PENDING,
                         engagements.BackendInstallRootStatus.SYNC_PENDING_OWNERSHIP_UNVERIFIED}:
        verified = ("backend install root matched" if backend_state == engagements.BackendInstallRootStatus.SYNC_PENDING
                    else "backend workspace ownership is unverified (older orchestrator build)")
        print(f"[vigil] WARN: {verified} and engagement sync is pending at {base_url}; the next backend request will retry synchronization.", file=sys.stderr)
        _ensure_backend_freshness(install_root, base_url)
        return
    if backend_state == engagements.BackendInstallRootStatus.UNREACHABLE and managed_host is None:
        print(f"[vigil] WARN: configured remote engagement backend is unreachable at {base_url}; launching with local engagement state only.", file=sys.stderr)
        return
    if backend_state != engagements.BackendInstallRootStatus.VERIFIED:
        raise SystemExit(f"engagement backend is not ready at {base_url}; check that configured endpoint before starting. Pass --skip-preflight to launch anyway.")
    _ensure_backend_freshness(install_root, base_url)


def _warn_if_ripgrep_missing() -> None:
    """Name the one missing tool whose failure mode is silence.

    `agent/shared-constraints-code.md` ranks `rg` second only to the ctags index
    for code specialists, and uses the ripgrep-only `--type` flag. Codex and
    Goose specialists have shell only, so a missing `rg` turns every search
    into exit 127, read as "no results" rather than "tool missing" — the worst
    shape a coverage gap can take, and nothing else in Vigil checks for it:
    ripgrep is in no dependency manifest and ships only in the runtime image,
    which code analysis does not use.

    Advisory, never a refusal: a web engagement reaches no code search at all,
    and a Claude or OpenCode hunter has its own Grep tool.
    """
    if shutil.which("rg") is not None:
        return
    print(
        "[vigil] WARN: ripgrep (`rg`) not found on PATH; it is the code track's "
        "primary search tool after the ctags index. Codex and Goose specialists "
        "have shell only, so their searches would exit 127 and read as "
        "\"no results\" instead of \"tool missing\" — install ripgrep before "
        "running code analysis on this host.",
        file=sys.stderr,
    )


def _warn_if_install_stale(install_root: Path) -> None:
    """Emit one non-fatal STDERR line before launching a client into a lagging root.

    ``vigil assess ...`` execs the INSTALL ROOT's ``assess.py``, so a working root
    behind its source silently exposes an older verb set — the failure surfaces as
    "no such verb" rather than "your install lags". Saying so once, at engagement
    start, covers every assess call the session goes on to make. Never writes to
    stdout (callers parse assess JSON there), never raises, and never blocks the
    launch: the operator stays free to proceed and decide.
    """
    try:
        staleness = install_staleness(install_root)
    except Exception:  # noqa: BLE001 — a diagnostic must never break the exec
        return
    state = str(staleness.get("state") or "")
    if state not in {"stale", "no-stamp"}:
        return
    installed = str(staleness.get("installed_sha") or "unstamped")[:12]
    current = str(staleness.get("current_source_sha") or "unknown")[:12]
    if staleness.get("reason") == "source_content_changed_without_revision":
        detail = f"source files changed without a new revision at {current}"
    else:
        detail = f"installed {installed}, source {current}"
    print(
        f"[vigil] WARN: install root {install_root} is {state} "
        f"({detail}); "
        "run `vigil install` to sync it.",
        file=sys.stderr,
        flush=True,  # execvpe replaces this process without flushing Python buffers
    )
