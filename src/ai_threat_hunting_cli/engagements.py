from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from .paths import (
    DEFAULT_ORCHESTRATOR_BASE_URL,
    engagements_root,
    resolve_orchestrator_base_url,
    resolve_orchestrator_data_dir,
)

AUTH_MODES = {"none", "manual", "auth_json", "proxy_capture"}
ENGAGEMENT_TYPES = {"web", "code", "both"}
EXPLOIT_POLICIES = {"pause", "full_send", "selected"}


@dataclass(frozen=True, slots=True)
class CreateEngagementOptions:
    install_root: Path
    engagement_type: str = "web"
    target: str | None = None
    name: str | None = None
    hosts: list[str] = field(default_factory=list)
    auth_mode: str = "none"
    exploit_policy: str = "pause"
    repos: list[str] = field(default_factory=list)
    skip_permissions: bool = False


@dataclass(frozen=True, slots=True)
class CreatedEngagement:
    key: str
    path: Path


@dataclass(frozen=True, slots=True)
class EngagementRow:
    key: str
    path: Path
    target: str
    status: str
    current_phase: str
    created_at: str


def normalize_target(raw: str) -> str:
    if "://" in raw:
        return raw
    return f"https://{raw}"


def hostname_for(target: str) -> str:
    parsed = urlparse(target)
    return parsed.hostname or target


def slug(value: str) -> str:
    cleaned = "".join(char if char.isalnum() or char == "-" else "-" for char in value.replace(".", "-").replace(":", "-").replace("/", "-"))
    cleaned = "-".join(part for part in cleaned.split("-") if part)
    return cleaned or "engagement"


def repo_name(raw: str) -> str:
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https", "ssh", "git"}:
        name = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    else:
        name = Path(raw).expanduser().name
    return name.removesuffix(".git") or "repo"


def create_engagement(options: CreateEngagementOptions) -> CreatedEngagement:
    install_root = options.install_root.expanduser().resolve()
    agent_root = install_root / "agent"
    root = engagements_root(install_root)
    root.mkdir(parents=True, exist_ok=True)

    if options.engagement_type not in ENGAGEMENT_TYPES:
        raise SystemExit("--type must be one of: web, code, both")
    if options.auth_mode not in AUTH_MODES:
        raise SystemExit("--auth-mode must be one of: none, manual, auth_json, proxy_capture")
    if options.exploit_policy not in EXPLOIT_POLICIES:
        raise SystemExit("--exploit-policy must be one of: pause, full_send, selected")

    _snapshot_orchestrator_database(install_root)

    now = datetime.now(timezone.utc)
    date_label = now.strftime("%Y-%m-%d")
    time_label = now.strftime("%H%M%S")
    created_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    target_normalized = ""
    hostname = ""
    hosts = list(options.hosts)
    if options.engagement_type in {"web", "both"}:
        if not options.target and not hosts:
            raise SystemExit("web and both engagements require --target or --hosts")
        target_normalized = normalize_target(options.target or hosts[0].removeprefix("*."))
        hostname = hostname_for(target_normalized)
        if not hosts:
            hosts = [hostname]

    name = options.name or (options.target if options.engagement_type == "code" else None)
    if options.engagement_type in {"code", "both"} and not name:
        raise SystemExit("code and both engagements require --name")

    if options.engagement_type == "web":
        label = slug(hostname)
    else:
        label = slug(name or "engagement")
    eng_dir = root / f"{date_label}-{time_label}-{label}"
    counter = 2
    while eng_dir.exists():
        eng_dir = root / f"{date_label}-{time_label}-{label}-{counter}"
        counter += 1
    eng_dir.mkdir(parents=True)
    key = eng_dir.name

    subdirs = ["tools", "downloads", "scans", "pids", "sessions"]
    if options.engagement_type in {"code", "both"}:
        subdirs.append("source")
    for subdir in subdirs:
        (eng_dir / subdir).mkdir()

    repos = [{"path": raw, "name": repo_name(raw)} for raw in options.repos]
    scope: dict[str, object]
    manifest: dict[str, object]
    if options.engagement_type == "code":
        scope = {
            "engagement_type": "code",
            "name": name,
            "repos": repos,
            "hosts": [],
            "exploit_policy": options.exploit_policy,
            "exploit_review_state": "pending",
            "approved_targets": [],
            "source_repos": [],
            "status": "in_progress",
            "current_phase": "ingest",
        }
        manifest = {"key": key, "name": name, "target": name, "repos": repos, "created_at": created_at}
    elif options.engagement_type == "web":
        scope = {
            "engagement_type": "web",
            "hostname": hostname,
            "hosts": hosts,
            "exploit_policy": options.exploit_policy,
            "exploit_review_state": "pending",
            "approved_targets": [],
            "status": "in_progress",
            "current_phase": "recon",
        }
        manifest = {"key": key, "target": target_normalized, "hostname": hostname, "created_at": created_at}
    else:
        scope = {
            "engagement_type": "both",
            "name": name,
            "hostname": hostname,
            "hosts": hosts,
            "repos": repos,
            "exploit_policy": options.exploit_policy,
            "exploit_review_state": "pending",
            "approved_targets": [],
            "source_repos": [],
            "status": "in_progress",
            "current_phase": "recon",
        }
        manifest = {
            "key": key,
            "name": name,
            "target": target_normalized,
            "hostname": hostname,
            "repos": repos,
            "created_at": created_at,
        }

    _write_json(eng_dir / "scope.json", scope)
    _write_json(eng_dir / "engagement.json", manifest)
    _write_report(eng_dir, options.engagement_type, name=name, target=target_normalized, repos=repos, date_label=date_label)
    _write_auth_scaffold(eng_dir, "none" if options.engagement_type == "code" else options.auth_mode, created_at)
    _write_json(eng_dir / "sessions" / "index.json", [])
    # Round 9: dispatch tracking + handoff content moved into the orchestrator
    # backend (assessment_dispatches / assessment_dispatch_handoffs /
    # assessment_dispatch_decisions). The legacy `agent-registry.json` file is
    # no longer initialized at engagement create — operators write via
    # `aith assess dispatch register|record-handoff|record-decision` instead.
    #
    # AGENT_NAME defaulting to "operator" is now handled in
    # agent/scripts/assess/lib/kali.py (`_resolve_agent_name`) so the env file
    # only carries `ORCHESTRATOR_BASE_URL`; specialists still override
    # AGENT_NAME=<role> in their dispatch wrapper.
    #
    # Only seed `.orchestrator.env` when an explicit override is in effect.
    # The default base URL falls through `resolve_orchestrator_base_url`
    # (env var → engagement env file → `aith config get orchestrator_base_url`
    # → hardcoded default), so writing the default into the file would just
    # confuse operators reading it ("do I edit this to change the port?").
    # When an override IS configured (via env var or `aith config`), we
    # snapshot it into the engagement file so the launcher re-exports it.
    resolved_base_url = resolve_orchestrator_base_url(install_root, eng_dir)
    if resolved_base_url and resolved_base_url != DEFAULT_ORCHESTRATOR_BASE_URL:
        (eng_dir / ".orchestrator.env").write_text(
            f"ORCHESTRATOR_BASE_URL={resolved_base_url}\n",
            encoding="utf-8",
        )
    else:
        # Touch an empty file so launcher loops that test ``-f`` don't trip
        # on a missing path. The launcher's grep falls through to the
        # default when the file has no ORCHESTRATOR_BASE_URL line.
        (eng_dir / ".orchestrator.env").write_text("", encoding="utf-8")
    _init_cases_db(agent_root, eng_dir)

    client_kind = _install_client_kind(agent_root)
    _write_prompt_wrappers(agent_root, eng_dir, client_kind)
    if client_kind in {"codex", "both"}:
        _write_codex_config(agent_root, eng_dir)
    _write_launchers(agent_root, eng_dir, client_kind, skip_permissions=options.skip_permissions)
    _emit_bootstrap_scope_summary(scope)
    _verify_backend_install_root(install_root, eng_dir)
    return CreatedEngagement(key=key, path=eng_dir)


def _verify_backend_install_root(install_root: Path, eng_dir: Path) -> None:
    """Detect install-root mismatch between this CLI and the running orchestrator.

    The orchestrator picks ``settings.install_dir`` at startup time from
    ``$AI_THREAT_HUNTING_INSTALL_DIR`` and cannot retarget at runtime. When
    the operator runs ``aith --root /custom/path engagement create ...`` against
    a backend that was started with a *different* install root, the new
    engagement directory is invisible to ``sync_engagements()`` — every
    subsequent ``aith assess`` call will write audit data to a backend that
    cannot see the engagement, silently dropping recon evidence.

    Strategy:
      - If the backend is unreachable (offline / not started yet), do nothing.
        Local-only workflows are valid and ``aith engagement create`` should
        succeed when the orchestrator is intentionally down.
      - If the backend is reachable AND its install_root matches ours, force a
        re-sync so the new engagement is registered immediately.
      - If the backend is reachable AND its install_root differs, abort with
        the recovery message — the operator must restart the orchestrator
        against the matching install root before the engagement is usable.
    """
    import http.client
    import json as _json
    from urllib.parse import urlparse

    base_url = resolve_orchestrator_base_url(install_root, eng_dir)
    parsed = urlparse(base_url)
    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    prefix = (parsed.path or "").rstrip("/")
    connection_cls = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection

    backend_install_root: str | None = None
    try:
        conn = connection_cls(host, port, timeout=2)
        conn.request("GET", f"{prefix}/admin/install-root")
        resp = conn.getresponse()
        body = resp.read().decode("utf-8", errors="replace")
        conn.close()
        if resp.status == 200:
            payload = _json.loads(body)
            backend_install_root = str(payload.get("install_root") or "")
        elif resp.status == 404:
            # Older orchestrator without /admin/install-root — fall back to a
            # plain force-sync attempt; if that also 404s, treat as unreachable.
            print(
                f"[aith] orchestrator at {base_url} does not expose /admin/install-root "
                "(older build). Skipping install-root drift check; "
                "restart the orchestrator after upgrading to validate.",
                file=sys.stderr,
            )
            return
        else:
            print(
                f"[aith] orchestrator at {base_url} returned HTTP {resp.status} "
                "for /admin/install-root; skipping install-root drift check.",
                file=sys.stderr,
            )
            return
    except (OSError, _json.JSONDecodeError):
        # Backend unreachable or unparseable — local-only workflows are valid,
        # so engagement creation should still succeed.
        return

    expected = str(install_root.expanduser().resolve())
    if backend_install_root and Path(backend_install_root).resolve() != Path(expected).resolve():
        raise SystemExit(
            "\n".join(
                [
                    f"Engagement created at {eng_dir}, but the running orchestrator does not know about it.",
                    f"  The orchestrator was started against install_root={backend_install_root}",
                    f"  This engagement is at install_root={expected}",
                    "",
                    "Recover by:",
                    f"  aith --root {expected} orchestrator restart",
                    f"  aith --root {expected} assess fetch summary --engagement-dir {eng_dir}",
                ]
            )
        )

    # Install roots match — force a re-sync so the new engagement is visible
    # to the backend immediately, without waiting for the next implicit trigger.
    try:
        conn = connection_cls(host, port, timeout=2)
        conn.request("POST", f"{prefix}/admin/sync-engagements")
        resp = conn.getresponse()
        resp.read()
        conn.close()
    except OSError:
        # Sync race conditions are non-fatal — the next implicit sync covers it.
        pass


def _emit_bootstrap_scope_summary(scope: dict[str, object]) -> None:
    """Print a one-line scope summary at bootstrap."""
    raw_hosts = scope.get("hosts") if isinstance(scope, dict) else None
    if not isinstance(raw_hosts, list) or not raw_hosts:
        return
    print(f"[aith] scope: {len(raw_hosts)} entries", file=sys.stderr)


def list_engagements(install_root: Path) -> list[EngagementRow]:
    rows: list[EngagementRow] = []
    for eng_dir in sorted(engagements_root(install_root).glob("*")):
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        scope = _read_json(eng_dir / "scope.json")
        manifest = _read_json(eng_dir / "engagement.json")
        target = str(manifest.get("target") or manifest.get("hostname") or scope.get("hostname") or manifest.get("name") or eng_dir.name)
        rows.append(
            EngagementRow(
                key=eng_dir.name,
                path=eng_dir.resolve(),
                target=target,
                status=str(scope.get("status") or "unknown"),
                current_phase=str(scope.get("current_phase") or "unknown"),
                created_at=str(manifest.get("created_at") or ""),
            )
        )
    return sorted(rows, key=lambda row: (row.created_at or "", row.key))


def resolve_engagement_path(install_root: Path, key: str | None = None, *, select: bool = False) -> Path:
    rows = list_engagements(install_root)
    if key:
        for row in rows:
            if row.key == key:
                return row.path
        raise SystemExit(f"Engagement not found: {key}")
    if select:
        return _select_engagement(rows).path
    raise SystemExit("Specify an engagement key or --select")


def current_engagement_path() -> Path | None:
    candidates: list[Path] = []
    env_dir = os.environ.get("ENGAGEMENT_DIR")
    if env_dir:
        candidates.append(Path(env_dir).expanduser())
    cwd = Path.cwd()
    candidates.extend([cwd, *cwd.parents])
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "scope.json").is_file():
            return resolved
    return None


def _select_engagement(rows: list[EngagementRow]) -> EngagementRow:
    if not rows:
        raise SystemExit("No engagements found")
    if shutil.which("fzf"):
        lines = [f"{row.key}\t{row.status}\t{row.current_phase}\t{row.target}\t{row.path}" for row in rows]
        result = subprocess.run(["fzf", "--with-nth", "1,2,3,4"], input="\n".join(lines), text=True, capture_output=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            selected = result.stdout.split("\t", 1)[0]
            return next(row for row in rows if row.key == selected)
    if not sys.stdin.isatty():
        raise SystemExit("Interactive selection requires fzf or a TTY")
    for idx, row in enumerate(rows, start=1):
        print(f"{idx}. {row.key} [{row.status}/{row.current_phase}] {row.target}", file=sys.stderr)
    choice = input("> ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
        raise SystemExit("Invalid selection")
    return rows[int(choice) - 1]


def print_shell_cd_init(shell: str = "zsh") -> str:
    if shell not in {"zsh", "bash"}:
        raise SystemExit("Only zsh and bash shell snippets are supported")
    return 'athcd() { cd "$(aith engagement path --select)"; }\n'


def start_engagement(install_root: Path, engagement_dir: Path, client: str, extra_args: list[str]) -> None:
    launcher = engagement_dir / f"start_{client}.sh"
    if not launcher.exists():
        raise SystemExit(f"Launcher not found for {client}: {launcher}")
    os.chdir(engagement_dir)
    os.execv(str(launcher), [str(launcher), *extra_args])


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _write_auth_scaffold(eng_dir: Path, mode: str, timestamp: str) -> None:
    if mode == "none":
        payload = {
            "mode": "none",
            "state": "none",
            "use_for_requests": False,
            "auth_context": "anonymous",
            "expires_at": None,
            "updated_at": timestamp,
            "cookies": {},
            "headers": {},
            "notes": "No authenticated context configured for this engagement.",
        }
    else:
        payload = {
            "mode": mode,
            "state": "missing",
            "use_for_requests": True,
            "auth_context": "authenticated",
            "expires_at": None,
            "updated_at": timestamp,
            "cookies": {},
            "headers": {},
            "notes": "Populate cookies and/or headers here, or refresh them through mitmproxy.",
        }
    _write_json(eng_dir / "auth.json", payload)


def _write_report(eng_dir: Path, engagement_type: str, *, name: str | None, target: str, repos: list[dict[str, str]], date_label: str) -> None:
    lines = ["# Engagement Report", ""]
    if engagement_type == "code":
        lines.append(f"- **Name**: {name}")
        display = ", ".join(repo["path"] for repo in repos) if repos else "(none - add source to ./source/)"
        lines.append(f"- **Repositories**: {display}")
    elif engagement_type == "web":
        lines.append(f"- **Target**: {target}")
    else:
        lines.append(f"- **Name**: {name}")
        lines.append(f"- **Target**: {target}")
    lines.extend([f"- **Engagement Date**: {date_label}", "- **Status**: Pending - report not yet generated", "", "---", ""])
    (eng_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def _init_cases_db(agent_root: Path, eng_dir: Path) -> None:
    db_path = eng_dir / "cases.db"
    schema_path = agent_root / "scripts" / "schema.sql"
    db_path.touch()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(schema_path.read_text(encoding="utf-8"))


def _snapshot_orchestrator_database(install_root: Path) -> None:
    data_dir = resolve_orchestrator_data_dir(install_root)
    db_path = data_dir / "orchestrator.sqlite3"
    if not db_path.exists():
        return
    backup = db_path.with_name(f"{db_path.name}.bak.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.{os.getpid()}")
    try:
        with sqlite3.connect(str(db_path)) as source, sqlite3.connect(str(backup)) as dest:
            source.backup(dest)
    except sqlite3.Error as exc:
        print(f"[aith] warning: orchestrator DB snapshot failed for {db_path}: {exc}", file=sys.stderr)


def _install_client_kind(agent_root: Path) -> str:
    has_codex = (agent_root / "AGENTS.md").exists() and (agent_root / ".codex").is_dir()
    has_claude = (agent_root / "CLAUDE.md").exists() and (agent_root / ".claude").is_dir()
    env_client = os.environ.get("AI_THREAT_HUNTING_CLIENT")
    if env_client in {"codex", "claude"}:
        return env_client
    if has_codex and not has_claude:
        return "codex"
    if has_claude and not has_codex:
        return "claude"
    return "both"


def _write_prompt_wrappers(agent_root: Path, eng_dir: Path, client_kind: str) -> None:
    install_root = agent_root.parent
    # Specialist context isolation invariant:
    # The per-engagement AGENTS.md/CLAUDE.md written here are operator-only bootstrap pointers.
    # Specialists never land at this cwd directly — they are dispatched FROM the operator via
    # the registered wrappers in agent/.codex/agents/*.toml or agent/.claude/agents/*.md, which
    # tell specialists to NOT read agent/AGENTS.md or agent/CLAUDE.md (those are operator
    # bootstrap prompts and carry the runtime/startup banner that must not bleed into
    # specialist responses). Cross-cutting context (audit-flag tables, listener URL
    # conventions, runtime tier table, half-phase tag definitions) lives in
    # agent/shared-constraints.md, which every role file's Load First section already
    # includes (see agent/scripts/render-operator-prompts.sh). If you change how engagement
    # bootstrap files are seeded — e.g. start landing specialist clients in their own cwd —
    # make sure the new cwd's local AGENTS.md/CLAUDE.md does not pull operator startup
    # banner prose into a specialist context.
    common = f"""This engagement directory is only the run-artifact root. Resolve shared prompts, skills, references, and scripts through:
- Install root: {install_root}
- Agent workspace root: {agent_root}
- Scripts: {agent_root / "scripts"}

Artifact sync:
- Use `aith assess ...` for assessment operations from any directory
- Start clients through this engagement directory's launcher so ENGAGEMENT_DIR is exported automatically
- The local .orchestrator.env provides the default orchestrator base URL; install-root .env can override it
"""
    if client_kind in {"codex", "both"}:
        (eng_dir / "AGENTS.md").write_text(f"# Engagement Workspace\n\nLoad workspace operator instructions from:\n- {agent_root / 'AGENTS.md'}\n\n{common}", encoding="utf-8")
    if client_kind in {"claude", "both"}:
        (eng_dir / "CLAUDE.md").write_text(f"# Engagement Workspace\n\nLoad workspace operator instructions from:\n- {agent_root / 'CLAUDE.md'}\n\n{common}", encoding="utf-8")


def _write_codex_config(agent_root: Path, eng_dir: Path) -> None:
    src = agent_root / ".codex" / "config.toml"
    if src.exists():
        (eng_dir / ".codex").mkdir()
        shutil.copy2(src, eng_dir / ".codex" / "config.toml")


def _write_launchers(agent_root: Path, eng_dir: Path, client_kind: str, *, skip_permissions: bool) -> None:
    if client_kind in {"codex", "both"}:
        _write_launcher(agent_root, eng_dir, "codex", "--full-auto" if skip_permissions else "")
    if client_kind in {"claude", "both"}:
        _write_launcher(agent_root, eng_dir, "claude", "--dangerously-skip-permissions" if skip_permissions else "")


def _write_launcher(agent_root: Path, eng_dir: Path, client: str, permission_arg: str) -> None:
    extra = f" {permission_arg}" if permission_arg else ""
    # The launcher exports operator-side env from the per-engagement
    # .orchestrator.env (and the install-root .env / .orchestrator.env
    # fallbacks). The legacy contract for ORCHESTRATOR_BASE_URL is preserved
    # verbatim: parent-shell export wins over file values; among file values
    # the LAST file wins (install-root .env overrides per-eng).
    #
    # AGENT_NAME is no longer exported here. The kali.py helper now defaults
    # to "operator" when neither --agent-name nor $AGENT_NAME / $AITH_AGENT_NAME
    # is set, so operator-executed mechanical pipeline work (tier-pick smoke,
    # runtime health, credential validation) still records the right
    # agent_name without the launcher poking the env. Specialist dispatch
    # wrappers continue to export AGENT_NAME=<role> before launching.
    script = f"""#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
export ENGAGEMENT_DIR
ENGAGEMENT_KEY="$(basename "$ENGAGEMENT_DIR")"
export ENGAGEMENT_KEY
AI_THREAT_HUNTING_AGENT_ROOT="{agent_root}"
export AI_THREAT_HUNTING_AGENT_ROOT
AI_THREAT_HUNTING_INSTALL_DIR="{agent_root.parent}"
export AI_THREAT_HUNTING_INSTALL_DIR

if [[ -z "${{ORCHESTRATOR_BASE_URL:-}}" ]]; then
  for env_file in "$ENGAGEMENT_DIR/.orchestrator.env" "$AI_THREAT_HUNTING_INSTALL_DIR/.orchestrator.env" "$AI_THREAT_HUNTING_INSTALL_DIR/.env"; do
    if [[ -f "$env_file" ]]; then
      candidate="$(grep -E '^ORCHESTRATOR_BASE_URL=' "$env_file" | tail -n1 | cut -d= -f2- || true)"
      if [[ -n "$candidate" ]]; then
        export ORCHESTRATOR_BASE_URL="${{candidate%/}}"
      fi
    fi
  done
fi

exec {client}{extra} "$@"
"""
    path = eng_dir / f"start_{client}.sh"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
