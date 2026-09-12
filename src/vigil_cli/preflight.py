"""Launch-time preflight shared by every path that execs an operator client.

Two entrypoints exec the generated launcher — ``vigil engagement start``
(`main`) and ``vigil blue engage --start`` (`blue`) — and both must run the
same checks. ``main`` imports ``blue``, so this cannot live in either of them;
it lives here so both can import it without a cycle.

The stale-install warning also fires on the ``vigil assess`` exec passthrough,
which is the other place a lagging install root silently changes behaviour.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from .engagements import CLIENT_PROVIDER_KEY
from .orchestrator import orchestrator_status
from .runtime import runtime_status
from .status import install_staleness

def _resolve_provider_key(install_root: Path, engagement_dir: Path, key: str) -> str | None:
    """Resolve one provider key exactly as the generated launcher does.

    Environment first, then the engagement's `.orchestrator.env`, then the install
    root's `.orchestrator.env` and `.env` — first hit wins (see
    `engagements._write_launcher`'s provider block).
    """
    value = os.environ.get(key)
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
            line.split("=", 1)[1]
            for line in lines
            if line.startswith(f"{key}=")
        ]
        if assignments and assignments[-1]:
            return assignments[-1]
    return None


def _preflight_engagement_start(
    install_root: Path, engagement_dir: Path, client: str
) -> None:
    """Refuse a session that cannot work; warn about one that can recover.

    Both halves matter. Without the hard checks the operator gets a bash
    `command not found` (exit 127) or a first-API-call auth error minutes in, with no
    Vigil-level explanation. Without the soft ones they start a real session against a
    stopped orchestrator or runtime and only learn on their first `vigil assess` call.
    Nothing here blocks a session that a mid-session `vigil up` would repair.

    Every line goes to stderr: `vigil blue engage --start` prints the bare
    engagement path on stdout for `eng=$(…)` capture.
    """
    if shutil.which(client) is None:
        raise SystemExit(
            f"{client} CLI not found on PATH; install it, or start a different client "
            f"with `vigil engagement start {engagement_dir.name} --client <name>`. "
            "Pass --skip-preflight to launch anyway."
        )
    provider_key = CLIENT_PROVIDER_KEY.get(client)
    if provider_key and not _resolve_provider_key(
        install_root, engagement_dir, provider_key
    ):
        raise SystemExit(
            f"{client} needs {provider_key}; set it in the environment, in "
            f"{engagement_dir / '.orchestrator.env'}, or in {install_root / '.env'}. "
            "Pass --skip-preflight to launch anyway."
        )

    if orchestrator_status(install_root) != "running":
        print(
            "[vigil] WARN: orchestrator is not running; `vigil assess` calls will fail "
            "until you run `vigil up`.",
            file=sys.stderr,
        )
    try:
        runtime_state = runtime_status()
    except Exception:  # noqa: BLE001 — a diagnostic must never block the launch
        runtime_state = "unknown"
    if runtime_state != "running":
        print(
            f"[vigil] WARN: Kali runtime container is {runtime_state}; "
            "`vigil assess kali` calls will fail until you run `vigil up`.",
            file=sys.stderr,
        )
    _warn_if_install_stale(install_root)


def _warn_if_install_stale(install_root: Path) -> None:
    """Emit one non-fatal STDERR line before execing into a lagging install root.

    ``vigil assess ...`` execs the INSTALL ROOT's ``assess.py``, so a working root
    behind its source silently exposes an older verb set — the failure surfaces as
    "no such verb" rather than "your install lags". Never writes to stdout (callers
    parse assess JSON there), never raises, and never blocks the exec: the agent
    stays free to proceed and decide.
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
