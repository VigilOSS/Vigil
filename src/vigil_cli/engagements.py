from __future__ import annotations

import fcntl
import json
import os
import re
import shlex
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol, Sequence
from urllib.parse import urlparse

from . import docker
from .client_rosters import (
    ensure_claude_agents_link,
    ensure_claude_commands_link,
    ensure_claude_settings,
    ensure_codex_agents_link,
    ensure_codex_config,
    ensure_codex_skills_link,
    ensure_goose_recipes_link,
    ensure_goose_standard_hooks,
    ensure_opencode_agents_link,
    unsafe_symlink_destination,
)
from .paths import (
    DEFAULT_ORCHESTRATOR_BASE_URL,
    engagements_root,
    resolve_orchestrator_base_url,
    resolve_orchestrator_data_dir,
)
from .scope_entries import ScopeEntryError, canonicalize_scope_entry

# Persisted active-engagement pointer key in ~/.config/vigil/config.json. This
# serves top-level `vigil` verbs and shared services; `vigil assess` deliberately
# ignores it so concurrent assessment sessions cannot retarget each other.
ACTIVE_ENGAGEMENT_CONFIG_KEY = "active_engagement_dir"

ENGAGEMENT_TYPES = {"web", "code", "both", "android", "blue"}
ANDROID_DYNAMIC_MODES = {"static_only", "device", "emulator"}
ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES_ENV = "VIGIL_ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES"
DEFAULT_ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES = 2
CODE_TARGET_CONTACT_POLICY = "warn-do-not-contact-declared-hosts"

# Engagement types that probe a live HTTP target and so can carry required
# attribution headers / out-of-scope carve-outs. code/blue have no HTTP target.
_HTTP_TARGET_TYPES = {"web", "both", "android"}

# Bug-bounty program → the attribution header name that program mandates on all
# traffic. `--program <name> --researcher <handle>` is sugar over `--header`.
PROGRAM_HEADER_PRESETS = {
    "bugcrowd": "X-Bug-Bounty",
    "hackerone": "X-HackerOne",
    "intigriti": "X-Intigriti",
}


def resolve_required_headers(
    program: str | None,
    researcher: str | None,
    headers: list[str] | None,
) -> dict[str, str]:
    """Resolve `--program/--researcher` + repeatable `--header "Name: Value"`
    into the `required_headers` map written to scope.json.

    Returns `{}` when nothing is requested (the unchanged default). Later
    `--header` entries win over an earlier preset of the same name so a custom
    override is always possible. Raises SystemExit on malformed input.
    """
    resolved: dict[str, str] = {}
    if program:
        key = program.strip().lower()
        header_name = PROGRAM_HEADER_PRESETS.get(key)
        if header_name is None:
            known = ", ".join(sorted(PROGRAM_HEADER_PRESETS))
            raise SystemExit(
                f"unknown --program '{program}'. Known presets: {known}. "
                "Use --header \"Name: Value\" for an arbitrary header."
            )
        researcher_handle = (researcher or "").strip()
        if not researcher_handle:
            raise SystemExit(
                f"--program {key} requires --researcher <handle> (the value sent "
                f"as '{header_name}: <handle>')."
            )
        resolved[header_name] = researcher_handle
    elif researcher:
        raise SystemExit("--researcher is only meaningful together with --program.")

    for raw in headers or []:
        if ":" not in raw:
            raise SystemExit(
                f"--header '{raw}' is malformed; expected \"Name: Value\"."
            )
        name, value = raw.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise SystemExit(f"--header '{raw}' has an empty header name.")
        resolved[name] = value
    return resolved


def resolve_out_of_scope(values: list[str] | None) -> list[str]:
    """Normalize repeatable `--out-of-scope` entries into the `out_of_scope`
    denylist written to scope.json (deduped, order-preserving).

    Entry syntax mirrors `hosts` (bare host, `*.wildcard`, CIDR, URL); strict
    classification happens at match time in `scope.out_of_scope_entries`, so
    here we only strip/lowercase, reject whitespace-bearing tokens, and dedup.
    """
    result: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        entry = raw.strip().lower()
        if not entry:
            continue
        if any(ch.isspace() for ch in entry):
            raise SystemExit(
                f"--out-of-scope '{raw}' contains whitespace; pass one host/pattern per flag."
            )
        if entry not in seen:
            seen.add(entry)
            result.append(entry)
    return result


def resolve_rate_limit(value: float | str | None) -> float | None:
    """Normalize a ``--rate-limit`` flag into the ``rate_limit`` (req/s) value
    written to scope.json, or ``None`` when unset.

    ``None``/empty preserves today's behavior (per-tool defaults; agent
    discretion — no hard gate). A supplied value must be a number of at least
    1 req/s; anything else raises SystemExit so a malformed cap can never be
    persisted.

    The value is a PER-INVOCATION / GLOBAL request-rate ceiling (req/s): httpx
    ``-rate-limit`` and katana ``-rl`` are single global token buckets, so the
    cap bounds the AGGREGATE rate of the bulk web stage it is applied to over the
    whole in-scope host set probed in one invocation, and bounds per-host only as
    a side effect. It must be at least 1 because httpx ``-rate-limit`` /
    katana ``-rl`` take an INTEGER req/s and cannot express a fractional rate — a
    sub-1 cap (e.g. 0.5) would otherwise floor UP to 1 (2x the intended ceiling),
    so it is rejected here rather than silently doubled. Only the recon
    pipeline's bulk web stages (httpx liveness, katana crawl, js-mining
    body-fetch) consume this cap today; it does NOT cover the recon-specialist's
    nuclei/ffuf/nmap/whatweb/nikto probes or gau body-fetches.
    """
    if value is None:
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            value = float(text)
        except ValueError as exc:
            raise SystemExit(
                f"--rate-limit '{text}' is not a number (req/s)."
            ) from exc
    rate = float(value)
    if rate < 1:
        raise SystemExit(
            f"--rate-limit must be at least 1 req/s, got {rate:g}. httpx "
            "-rate-limit and katana -rl take an integer req/s and cannot express "
            "a fractional rate; a sub-1 cap would floor up to 1 (2x the intended "
            "ceiling)."
        )
    return rate


@dataclass(frozen=True, slots=True)
class CreateEngagementOptions:
    install_root: Path
    engagement_type: str = "web"
    target: str | None = None
    name: str | None = None
    hosts: list[str] = field(default_factory=list)
    repos: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    android_package: str | None = None
    dynamic_mode: str = "static_only"
    skip_permissions: bool = False
    # Program-mandated attribution headers (e.g. {"X-Bug-Bounty": "<handle>"}) and
    # out-of-scope carve-outs, written into scope.json for HTTP-target engagements.
    required_headers: dict[str, str] = field(default_factory=dict)
    out_of_scope: list[str] = field(default_factory=list)
    # Optional PER-INVOCATION / GLOBAL request-rate ceiling (req/s) for the recon
    # pipeline's bulk web stages (httpx liveness, katana crawl, js-mining body-
    # fetch). httpx -rate-limit / katana -rl are single global token buckets, so
    # the cap bounds the aggregate stage rate over the whole in-scope host set and
    # bounds per-host only as a side effect; it does NOT cover the recon-
    # specialist's nuclei/ffuf/nmap/whatweb/nikto probes or gau body-fetches. None
    # preserves today's behavior (per-tool defaults; agent discretion — no hard
    # gate). Written into scope.json's ``rate_limit`` only when set, for
    # HTTP-target engagements.
    rate_limit: float | None = None
    # Blue-only fields (ignored unless engagement_type == "blue"):
    customer: str | None = None
    platforms: list[str] = field(default_factory=list)
    tenant_reference_paths: list[str] = field(default_factory=list)
    alert_source: str | None = None
    severity_hint: str | None = None


@dataclass(frozen=True, slots=True)
class CreatedEngagement:
    key: str
    path: Path


@dataclass(frozen=True, slots=True)
class EngagementPlan:
    """Pure, side-effect-free derivation of everything `create_engagement`
    would write for a given set of options.

    `plan_engagement` performs all option validation and scope/manifest
    construction without touching the filesystem, database, or network, so
    `vigil engagement create --dry-run` can show exactly what would be created
    and fail on exactly the inputs the real create would reject. The manifest
    carries an empty `key` placeholder — the final key depends on the
    collision-suffixed directory name chosen at materialization time.
    """

    engagement_type: str
    label: str
    scope: dict[str, object]
    manifest: dict[str, object]
    subdirs: tuple[str, ...]
    report_name: str | None
    report_target: str
    repos: tuple[dict[str, str], ...]
    date_label: str
    time_label: str
    created_at: str


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


def plan_engagement(options: CreateEngagementOptions, *, now: datetime | None = None) -> EngagementPlan:
    """Validate options and derive the scope/manifest/report inputs.

    Pure with respect to the environment: no directories are created, no
    database snapshot is taken, and the orchestrator is not contacted. Raises
    SystemExit on the same invalid inputs `create_engagement` rejects.
    """
    if options.engagement_type not in ENGAGEMENT_TYPES:
        raise SystemExit("--type must be one of: web, code, both, android, blue")
    if options.dynamic_mode not in ANDROID_DYNAMIC_MODES:
        raise SystemExit("--dynamic-mode must be one of: static_only, device, emulator")
    if options.engagement_type == "blue":
        if not options.customer:
            raise SystemExit("blue engagements require --customer")
        if not options.platforms:
            raise SystemExit("blue engagements require at least one --platform")

    if now is None:
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

    artifacts = [str(Path(raw).expanduser()) for raw in options.artifacts]
    name = options.name or (options.target if options.engagement_type == "code" else None)
    if options.engagement_type == "android" and not name:
        if options.android_package:
            name = options.android_package
        elif artifacts:
            name = Path(artifacts[0]).name
    if options.engagement_type in {"code", "both"} and not name:
        raise SystemExit("code and both engagements require --name")
    if options.engagement_type == "android" and not name:
        raise SystemExit("android engagements require --name, --package-name, or --apk")

    if options.engagement_type == "web":
        label = slug(hostname)
    elif options.engagement_type == "blue":
        # Blue engagements aren't host- or repo-shaped; the natural label is
        # `<customer>-<first-platform>` so engagement dirs sort meaningfully
        # under engagements/.
        first_platform = options.platforms[0] if options.platforms else "alert"
        label = slug(f"{options.customer}-{first_platform}")
    else:
        label = slug(name or "engagement")

    subdirs = ["tools", "downloads", "scans", "pids", "sessions"]
    if options.engagement_type in {"code", "both", "android"}:
        subdirs.append("source")

    # The final key is the collision-suffixed directory name, chosen when the
    # plan is materialized; the manifest carries a placeholder until then.
    key = ""

    repos = [{"path": raw, "name": repo_name(raw)} for raw in options.repos]
    scope: dict[str, object]
    manifest: dict[str, object]
    if options.engagement_type == "code":
        scope = {
            "engagement_type": "code",
            "name": name,
            "hosts": [],
            "code_target_contact_policy": CODE_TARGET_CONTACT_POLICY,
            "exploit_policy": "pause",
            "exploit_review_state": "pending",
            "approved_targets": [],
            "status": "in_progress",
            "current_phase": "ingest",
        }
        manifest = {"key": key, "name": name, "target": name, "repos": repos, "created_at": created_at}
    elif options.engagement_type == "android":
        scope = {
            "engagement_type": "android",
            "mobile_platform": "android",
            "scope_mode": "artifact-only",
            "name": name,
            "android_package": options.android_package or "",
            "artifacts": artifacts,
            "hosts": [],
            "backend_hosts": hosts,
            "dynamic_mode": options.dynamic_mode,
            "exploit_policy": "pause",
            "exploit_review_state": "pending",
            "approved_targets": [],
            "status": "in_progress",
            "current_phase": "ingest",
        }
        manifest = {
            "key": key,
            "name": name,
            "target": name,
            "mobile_platform": "android",
            "android_package": options.android_package or "",
            "artifacts": artifacts,
            "dynamic_mode": options.dynamic_mode,
            "created_at": created_at,
        }
    elif options.engagement_type == "web":
        scope = {
            "engagement_type": "web",
            "hostname": hostname,
            "hosts": hosts,
            "exploit_policy": "pause",
            "exploit_review_state": "pending",
            "approved_targets": [],
            "status": "in_progress",
            "current_phase": "recon",
        }
        manifest = {"key": key, "target": target_normalized, "hostname": hostname, "created_at": created_at}
    elif options.engagement_type == "blue":
        # Per Blue Team Engagement.plan.md §8.4. hosts stays empty so existing
        # scope-readers don't crash; exploit_policy is explicitly null because
        # blue has no exploit phase; response_policy is the blue-mode analog
        # (operator-approved containment).
        blue_customer = str(options.customer or "")
        blue_target = f"{blue_customer}:{','.join(options.platforms)}"
        scope = {
            "engagement_type": "blue",
            "customer": blue_customer,
            "platforms": list(options.platforms),
            "tenant_reference_paths": list(options.tenant_reference_paths),
            "alert_metadata": {
                "source": options.alert_source or "operator_chat",
                "external_id": None,
                "received_at": None,
                "severity_hint": options.severity_hint,
                "raw_body": None,
                "parsed": None,
            },
            "response_policy": "contain-with-approval",
            "exploit_policy": None,
            "status": "in_progress",
            "current_phase": "intake",
            "hosts": [],
        }
        manifest = {
            "key": key,
            "name": blue_customer,
            "target": blue_target,
            "customer": blue_customer,
            "platforms": list(options.platforms),
            "created_at": created_at,
        }
    else:
        scope = {
            "engagement_type": "both",
            "name": name,
            "hostname": hostname,
            "hosts": hosts,
            "code_target_contact_policy": CODE_TARGET_CONTACT_POLICY,
            "exploit_policy": "pause",
            "exploit_review_state": "pending",
            "approved_targets": [],
            "status": "in_progress",
            "current_phase": "recon",
            "code_phase": "ingest",
        }
        manifest = {
            "key": key,
            "name": name,
            "target": target_normalized,
            "hostname": hostname,
            "repos": repos,
            "created_at": created_at,
        }

    # Program attribution headers + OOS carve-outs apply only to engagements
    # that probe a live HTTP target. Written only when non-empty so existing
    # scope.json shapes stay byte-identical when the feature is unused.
    if options.engagement_type in _HTTP_TARGET_TYPES:
        if options.required_headers:
            scope["required_headers"] = dict(options.required_headers)
        if options.out_of_scope:
            scope["out_of_scope"] = list(options.out_of_scope)
        # Written only when set so an unconfigured cap leaves scope.json
        # byte-identical and recon stages fall through to their tool defaults.
        if options.rate_limit is not None:
            scope["rate_limit"] = options.rate_limit
    elif (
        options.required_headers
        or options.out_of_scope
        or options.rate_limit is not None
    ):
        raise SystemExit(
            "--program/--header, --out-of-scope, and --rate-limit apply only to "
            f"HTTP-target engagements (web/both/android), not '{options.engagement_type}'."
        )

    report_name = name
    report_target = target_normalized
    if options.engagement_type == "blue":
        report_name = str(manifest.get("customer") or options.customer or "")
        report_target = str(manifest.get("target") or "")

    return EngagementPlan(
        engagement_type=options.engagement_type,
        label=label,
        scope=scope,
        manifest=manifest,
        subdirs=tuple(subdirs),
        report_name=report_name,
        report_target=report_target,
        repos=tuple(repos),
        date_label=date_label,
        time_label=time_label,
        created_at=created_at,
    )


def create_engagement(
    options: CreateEngagementOptions,
    *,
    engagement_root: Path | None = None,
    contact_backend: bool = True,
) -> CreatedEngagement:
    """Materialize an engagement, optionally as an offline isolated staging tree.

    Ordinary callers use the default installed registry and backend checks. The
    benchmark Lima path supplies a judge-side staging root and disables all host
    database/network interaction; the copied guest tree is registered only by
    the attempt-local backend.
    """

    install_root = options.install_root.expanduser().resolve()
    agent_root = install_root / "agent"
    # Validate and derive everything before taking any side effect: an invalid
    # option set, or an install root that cannot back an engagement, must not
    # leave behind a DB snapshot or a half-made directory.
    plan = plan_engagement(options)
    _require_install_prerequisites(agent_root, options.engagement_type)

    root = (
        engagement_root.expanduser().resolve()
        if engagement_root is not None
        else engagements_root(install_root)
    )
    root.mkdir(parents=True, exist_ok=True)
    if contact_backend:
        _snapshot_orchestrator_database(install_root)

    eng_dir = root / f"{plan.date_label}-{plan.time_label}-{plan.label}"
    counter = 2
    while eng_dir.exists():
        eng_dir = root / f"{plan.date_label}-{plan.time_label}-{plan.label}-{counter}"
        counter += 1
    eng_dir.mkdir(parents=True)
    key = eng_dir.name
    # Everything below writes into the new directory. A writer that fails part
    # way through must not leave a scoped-but-unlaunchable engagement behind:
    # roll the directory back and let the error surface. Steps AFTER this block
    # (backend sync verification, footers) report on a durable engagement and
    # must not delete it -- their own messages tell the operator how to recover.
    try:
        for subdir in plan.subdirs:
            (eng_dir / subdir).mkdir()

        scope = dict(plan.scope)
        manifest = dict(plan.manifest)
        manifest["key"] = key

        _write_json(eng_dir / "scope.json", scope)
        _write_json(eng_dir / "engagement.json", manifest)
        _write_report(
            eng_dir,
            options.engagement_type,
            name=plan.report_name,
            target=plan.report_target,
            repos=list(plan.repos),
            date_label=plan.date_label,
        )
        _write_issues_doc(eng_dir)
        _write_engagement_brief_stub(agent_root, eng_dir)
        # No auth.json scaffold: credentials live in the centralized store and an
        # engagement with no credentials reads as anonymous (vigil auth import /
        # mitmproxy capture populate it). See orchestrator credentials API.
        _write_json(eng_dir / "sessions" / "index.json", [])
        # Dispatch tracking + handoff content live in the orchestrator backend
        # (assessment_dispatches / assessment_dispatch_handoffs /
        # assessment_dispatch_decisions). Write via
        # `vigil assess agent start|handoff|decision`.
        #
        # AGENT_NAME defaulting to "operator" is handled in
        # agent/scripts/assess/lib/kali_audit.py (`_resolve_agent_name`) so the env
        # file only carries `ORCHESTRATOR_BASE_URL`; specialist dispatch wrappers
        # must export AGENT_NAME=<role> or pass --agent-name explicitly.
        #
        # Only seed `.orchestrator.env` when an explicit override is in effect.
        # The default base URL falls through `resolve_orchestrator_base_url`
        # (env var → engagement env file → `vigil config get orchestrator_base_url`
        # → legacy install env files → hardcoded default), so writing the default
        # into the file would just confuse operators reading it ("do I edit this
        # to change the port?").
        # When an override IS configured (via env var, `vigil config`, or a legacy
        # install-root env file), we snapshot it into the engagement file so the
        # launcher re-exports it.
        resolved_base_url = (
            resolve_orchestrator_base_url(install_root, eng_dir)
            if contact_backend
            else DEFAULT_ORCHESTRATOR_BASE_URL
        )
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
        # No local work-buffer DB is created: the work buffer lives in the
        # orchestrator backend (assessment_work_items) and is populated on first
        # ingest (ADR 0013). Fresh engagements start with an empty backend buffer.

        client_kind = _install_client_kind(agent_root)
        _write_prompt_wrappers(agent_root, eng_dir, client_kind, engagement_type=options.engagement_type)
        if client_kind in {"codex", "both"}:
            _write_codex_config(agent_root, eng_dir)
        if client_kind in {"claude", "both"}:
            _write_claude_config(agent_root, eng_dir)
        # OpenCode parity: the standard plugin (scope-check + activity-log) and the
        # specialist roster install for every kind that also gets start_opencode.sh
        # (codex/claude/both), so an `--client opencode` run — including `vigil bench`,
        # whose engagement creation routes through here — has the standard logging
        # plugin in place. The bench then layers its guard-only plugin beside it.
        if client_kind in {"codex", "claude", "both"}:
            _write_opencode_config(agent_root, eng_dir)
        # Goose parity: the operator prompt (`.goosehints`), the specialist recipe roster
        # (`.goose/recipes` link), and the standard hooks plugin (scope-check + activity-log)
        # install for every kind that also gets start_goose.sh, so an `--client goose` run —
        # including `vigil bench` — has them in place. The bench layers its guard-only hook
        # beside the standard one (anticheat._patch_goose_hooks). Written AFTER
        # _write_prompt_wrappers so AGENTS.md exists to seed .goosehints.
        if client_kind in {"codex", "claude", "both"}:
            _write_goose_config(agent_root, eng_dir)
        _write_launchers(agent_root, eng_dir, client_kind, skip_permissions=options.skip_permissions)
    except BaseException:
        shutil.rmtree(eng_dir, ignore_errors=True)
        raise
    _emit_bootstrap_scope_summary(scope)
    if contact_backend:
        _verify_backend_install_root(install_root, eng_dir)
    # Blue engagements own their own footer (blue.py:_cmd_engage) and must not
    # emit the red-infra footer (mitmproxy/oob are irrelevant to incident
    # response). Skip entirely for blue so blue.py has sole footer ownership.
    if contact_backend and options.engagement_type != "blue":
        _emit_post_create_footer(key)
    return CreatedEngagement(key=key, path=eng_dir)


def _emit_post_create_footer(key: str, *, runner: docker.Runner = docker.run_command) -> None:
    """Print a status-aware next-steps footer after creating an engagement.

    Reuses the existing helpers from ``docker`` and ``oob`` so we don't
    re-implement liveness probes. stdout still carries just the path so
    ``eng=$(vigil engagement create ...)`` keeps working — this writes to
    stderr only. Blue engagements skip this entirely — blue.py owns its own
    footer (no mitmproxy/oob lines).
    """
    try:
        mitm_running = docker.container_running("vigil-proxy", runner=runner)
    except Exception:
        mitm_running = False
    try:
        from .oob import oob_status

        oob_state = str(oob_status(runner=runner, deep=False).get("state", "unknown"))
    except Exception:
        oob_state = "unknown"

    mitm_label = "running" if mitm_running else "stopped"
    mitm_hint = "" if mitm_running else "   (auth capture: vigil mitmproxy start)"
    oob_hint = "" if oob_state == "running" else "   (callbacks: vigil oob start)"

    print(f"[vigil] engagement: {key}", file=sys.stderr)
    print(f"[vigil] mitmproxy: {mitm_label}{mitm_hint}", file=sys.stderr)
    print(f"[vigil] oob:       {oob_state}{oob_hint}", file=sys.stderr)
    print(
        f"[vigil] start:     vigil engagement start {key} --client codex   (or --client claude)",
        file=sys.stderr,
    )


def _verify_backend_install_root(install_root: Path, eng_dir: Path) -> bool:
    """Detect install-root mismatch between this CLI and the running orchestrator.

    The orchestrator picks ``settings.install_dir`` at startup time from
    ``$VIGIL_INSTALL_DIR`` and cannot retarget at runtime. When
    the operator runs ``vigil --root /custom/path engagement create ...`` against
    a backend that was started with a *different* install root, the new
    engagement directory is invisible to ``sync_engagements()`` — every
    subsequent ``vigil assess`` call will write audit data to a backend that
    cannot see the engagement, silently dropping recon evidence.

    Strategy:
      - If the backend is unreachable (offline / not started yet), return false.
        Local-only workflows are valid and ``vigil engagement create`` should
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
                f"[vigil] orchestrator at {base_url} does not expose /admin/install-root "
                "(older build). Skipping install-root drift check; "
                "restart the orchestrator after upgrading to validate.",
                file=sys.stderr,
            )
        else:
            print(
                f"[vigil] orchestrator at {base_url} returned HTTP {resp.status} "
                "for /admin/install-root; skipping install-root drift check.",
                file=sys.stderr,
            )
            return False
    except (OSError, _json.JSONDecodeError):
        # Backend unreachable or unparseable — local-only workflows are valid,
        # so engagement creation should still succeed.
        return False

    expected = str(install_root.expanduser().resolve())
    if backend_install_root and Path(backend_install_root).resolve() != Path(expected).resolve():
        raise SystemExit(
            "\n".join(
                [
                    f"Engagement state at {eng_dir} exists, but the running orchestrator does not know about it.",
                    f"  The orchestrator was started against install_root={backend_install_root}",
                    f"  This engagement is at install_root={expected}",
                    "",
                    "Recover by:",
                    f"  vigil --root {expected} orchestrator restart",
                    f"  vigil --root {expected} assess fetch summary --engagement-dir {eng_dir}",
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
        return 200 <= resp.status < 300
    except OSError:
        # Sync race conditions are non-fatal — the next implicit sync covers it.
        return False


def _emit_bootstrap_scope_summary(scope: dict[str, object]) -> None:
    """Print a one-line scope summary at bootstrap."""
    raw_hosts = scope.get("hosts") if isinstance(scope, dict) else None
    if not isinstance(raw_hosts, list) or not raw_hosts:
        return
    print(f"[vigil] scope: {len(raw_hosts)} entries", file=sys.stderr)


def _engagement_scope_path(install_root: Path, key: str) -> Path:
    """Resolve an engagement's scope.json by key."""
    eng_dir = engagements_root(install_root) / key
    scope_path = eng_dir / "scope.json"
    if not scope_path.is_file():
        raise SystemExit(f"engagement '{key}' not found (no scope.json at {scope_path}).")
    return scope_path


@contextmanager
def _scope_file_lock(scope_path: Path) -> Iterator[None]:
    """Use the same lock path as assess-side scope.json writers."""
    lock_path = scope_path.parent / ".locks" / "scope-json.lock"
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def mutate_scope_file(
    scope_path: Path,
    mutator: Callable[[dict[str, Any]], object],
) -> dict[str, Any]:
    """Apply an in-place scope.json mutation under the shared writer lock."""
    with _scope_file_lock(scope_path):
        try:
            scope = json.loads(scope_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise SystemExit(f"could not read scope.json at {scope_path}: {exc}") from exc
        if not isinstance(scope, dict):
            raise SystemExit(f"scope.json at {scope_path} is not a JSON object.")
        mutator(scope)
        _write_json_atomic(scope_path, scope)
    return scope


def _mutate_http_scope(
    install_root: Path,
    key: str,
    mutator: Callable[[dict[str, Any]], object],
) -> dict[str, Any]:
    scope_path = _engagement_scope_path(install_root, key)

    def checked_mutation(scope: dict[str, Any]) -> None:
        if str(scope.get("engagement_type") or "") not in _HTTP_TARGET_TYPES:
            raise SystemExit(
                f"engagement '{key}' is type '{scope.get('engagement_type')}'; required "
                "headers / out-of-scope apply only to HTTP-target engagements."
            )
        mutator(scope)

    return mutate_scope_file(scope_path, checked_mutation)


def set_engagement_header(install_root: Path, key: str, header: str) -> dict[str, str]:
    """Add/replace a `required_headers` entry on an existing engagement."""
    if ":" not in header:
        raise SystemExit(f"header '{header}' is malformed; expected \"Name: Value\".")
    name, value = header.split(":", 1)
    name, value = name.strip(), value.strip()
    if not name:
        raise SystemExit(f"header '{header}' has an empty header name.")
    def update(scope: dict[str, Any]) -> None:
        headers = scope.get("required_headers")
        if not isinstance(headers, dict):
            headers = {}
        headers[name] = value
        scope["required_headers"] = headers

    scope = _mutate_http_scope(install_root, key, update)
    return dict(scope["required_headers"])


def unset_engagement_header(install_root: Path, key: str, name: str) -> dict[str, str]:
    """Remove a `required_headers` entry from an existing engagement."""
    def update(scope: dict[str, Any]) -> None:
        headers = scope.get("required_headers")
        if not isinstance(headers, dict) or name not in headers:
            raise SystemExit(f"engagement '{key}' has no required header '{name}'.")
        del headers[name]
        if headers:
            scope["required_headers"] = headers
        else:
            scope.pop("required_headers", None)

    scope = _mutate_http_scope(install_root, key, update)
    headers = scope.get("required_headers")
    return dict(headers) if isinstance(headers, dict) else {}


def add_out_of_scope(install_root: Path, key: str, entries: list[str]) -> list[str]:
    """Add out-of-scope carve-out entries to an existing engagement (deduped)."""
    new_entries = resolve_out_of_scope(entries)
    if not new_entries:
        raise SystemExit("no valid --out-of-scope entries given.")
    def update(scope: dict[str, Any]) -> None:
        current = scope.get("out_of_scope")
        merged = list(current) if isinstance(current, list) else []
        for entry in new_entries:
            if entry not in merged:
                merged.append(entry)
        scope["out_of_scope"] = merged

    scope = _mutate_http_scope(install_root, key, update)
    return list(scope["out_of_scope"])


def remove_out_of_scope(install_root: Path, key: str, entry: str) -> list[str]:
    """Remove an out-of-scope carve-out from an existing engagement."""
    target = entry.strip().lower()
    def update(scope: dict[str, Any]) -> None:
        current = scope.get("out_of_scope")
        if not isinstance(current, list) or target not in current:
            raise SystemExit(f"engagement '{key}' has no out-of-scope entry '{entry}'.")
        remaining = [item for item in current if item != target]
        if remaining:
            scope["out_of_scope"] = remaining
        else:
            scope.pop("out_of_scope", None)

    scope = _mutate_http_scope(install_root, key, update)
    remaining = scope.get("out_of_scope")
    return list(remaining) if isinstance(remaining, list) else []


def _track_state(scope: dict[str, Any]) -> dict[str, str]:
    return {
        "engagement_type": str(scope.get("engagement_type") or ""),
        "current_phase": str(scope.get("current_phase") or ""),
        "code_phase": str(scope.get("code_phase") or ""),
    }


def _append_track_transition(
    scope: dict[str, Any],
    *,
    operation: str,
    actor: str,
    before: dict[str, str],
) -> None:
    history = scope.get("track_transitions")
    if not isinstance(history, list):
        history = []
    history.append(
        {
            "operation": operation,
            "actor": actor or "operator",
            "before": before,
            "after": _track_state(scope),
            "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
    )
    scope["track_transitions"] = history


def add_engagement_track(
    install_root: Path,
    key: str,
    track: str,
    *,
    actor: str = "operator",
) -> dict[str, str]:
    """Explicitly upgrade a single-track web/code engagement to ``both``.

    The existing track phase is preserved. Only the newly enabled track is
    initialized, and the transition is retained in scope.json so an implicit
    ingest/probe side effect can never masquerade as operator authorization.
    """
    requested = track.strip().lower()
    if requested not in {"web", "code"}:
        raise SystemExit(f"cannot add track '{track}'; choose web or code.")
    scope_path = _engagement_scope_path(install_root, key)

    def update(scope: dict[str, Any]) -> None:
        current_type = str(scope.get("engagement_type") or "")
        if current_type == "both":
            if not scope.get("current_phase") or not scope.get("code_phase"):
                raise SystemExit(
                    f"engagement '{key}' is both but has incomplete track state; "
                    f"run `vigil engagement repair-tracks {key}` first."
                )
            return
        expected = "code" if requested == "web" else "web"
        if current_type != expected:
            raise SystemExit(
                f"cannot add {requested} track to engagement '{key}' of type "
                f"'{current_type or 'unknown'}'; expected {expected}."
            )
        before = _track_state(scope)
        previous_phase = str(scope.get("current_phase") or "")
        if current_type == "code":
            scope["code_phase"] = previous_phase or "ingest"
            scope["current_phase"] = "recon"
        else:
            scope["current_phase"] = previous_phase or "recon"
            scope["code_phase"] = "ingest"
        scope["engagement_type"] = "both"
        scope["code_target_contact_policy"] = CODE_TARGET_CONTACT_POLICY
        scope["status"] = "in_progress"
        _append_track_transition(
            scope,
            operation=f"add-{requested}",
            actor=actor,
            before=before,
        )

    scope = mutate_scope_file(scope_path, update)
    return _track_state(scope)


def repair_engagement_tracks(
    install_root: Path,
    key: str,
    *,
    actor: str = "operator",
) -> dict[str, str]:
    """Repair the one supported legacy shape: ``both`` without code_phase."""
    scope_path = _engagement_scope_path(install_root, key)

    def update(scope: dict[str, Any]) -> None:
        if str(scope.get("engagement_type") or "") != "both":
            raise SystemExit(f"engagement '{key}' is not a both-track engagement.")
        if scope.get("code_phase"):
            raise SystemExit(f"engagement '{key}' already has code_phase.")
        before = _track_state(scope)
        scope["current_phase"] = str(scope.get("current_phase") or "recon")
        scope["code_phase"] = "ingest"
        scope["status"] = "in_progress"
        _append_track_transition(
            scope,
            operation="repair-missing-code-phase",
            actor=actor,
            before=before,
        )

    scope = mutate_scope_file(scope_path, update)
    return _track_state(scope)


def add_engagement_hosts(
    install_root: Path,
    key: str,
    entries: list[str],
) -> list[str]:
    """Append normalized authorization roots to canonical ``scope.json``."""
    added: list[str] = []
    for raw in entries:
        try:
            canonical = canonicalize_scope_entry(raw)
        except ScopeEntryError as exc:
            raise SystemExit(f"invalid host entry {raw!r}: {exc}") from exc
        if canonical not in added:
            added.append(canonical)
    if not added:
        raise SystemExit("no valid host entries given.")

    def update(scope: dict[str, Any]) -> None:
        current = scope.get("hosts")
        merged = [str(item).strip().lower() for item in current] if isinstance(current, list) else []
        for entry in added:
            if entry not in merged:
                merged.append(entry)
        scope["hosts"] = merged

    scope = _mutate_http_scope(install_root, key, update)
    return list(scope["hosts"])


def set_engagement_rate_limit(
    install_root: Path,
    key: str,
    value: float | str,
) -> float:
    """Set the canonical per-invocation HTTP rate ceiling."""
    rate = resolve_rate_limit(value)
    if rate is None:
        raise SystemExit("rate limit value is required.")

    scope = _mutate_http_scope(
        install_root,
        key,
        lambda current: current.__setitem__("rate_limit", rate),
    )
    return float(scope["rate_limit"])


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


def _both_engagements_missing_code_phase(install_root: Path) -> list[Path]:
    """Return engagement directories where engagement_type='both' but
    scope.json has no `code_phase` field.

    Dual-track phase tracking landed mid-flight: engagements created before
    that change only carry `current_phase` and confuse `transition-phase
    --track code`. Setting code_phase='ingest' in scope.json clears this;
    this helper is the read-only detector used by `vigil status` and the CLI
    summary. (The one-shot `vigil engagement migrate-scope` command that used
    to perform the write was retired in the 2026-07 CLI consolidation.)
    """
    affected: list[Path] = []
    root = engagements_root(install_root)
    if not root.is_dir():
        return affected
    for eng_dir in sorted(root.glob("*")):
        scope_path = eng_dir / "scope.json"
        if not eng_dir.is_dir() or not scope_path.is_file():
            continue
        try:
            scope = _read_json(scope_path)
        except Exception:
            continue
        if scope.get("engagement_type") != "both":
            continue
        if not scope.get("code_phase"):
            affected.append(eng_dir)
    return affected


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


def _read_active_pointer() -> Path | None:
    """Return the persisted active-engagement dir if it is a valid engagement
    root, else None. A pointer at a deleted/renamed engagement (no scope.json)
    is skipped with a one-line stderr warning — never used silently.
    """
    from . import config as config_module

    raw = config_module.get_config_value(ACTIVE_ENGAGEMENT_CONFIG_KEY)
    if not raw:
        return None
    pointer = Path(raw).expanduser()
    if (pointer / "scope.json").is_file():
        return pointer.resolve()
    print(
        f"WARNING: active engagement pointer '{raw}' is not an engagement root "
        "(no scope.json); ignoring it. Run `vigil use <key>` to re-point it.",
        file=sys.stderr,
    )
    return None


def _warn_env_mismatch(resolved_dir: Path, tier: str) -> None:
    """One-line stderr warning when ``$ENGAGEMENT_DIR`` disagrees with the tier
    that actually won — the guard against a stale shell-profile leak.
    """
    env_dir = os.environ.get("ENGAGEMENT_DIR", "")
    if not env_dir:
        return
    try:
        env_resolved = Path(env_dir).expanduser().resolve()
    except OSError:
        return
    if env_resolved == resolved_dir:
        return
    print(
        f"WARNING: $ENGAGEMENT_DIR points at {env_dir} but resolved {resolved_dir} "
        f"from {tier}; check your shell profile (e.g. a stale "
        "`export ENGAGEMENT_DIR=` line).",
        file=sys.stderr,
    )


def resolve_current_engagement() -> tuple[Path, str] | None:
    """Resolve context for top-level, non-assessment ``vigil`` verbs.

    The ``--engagement-dir`` flag tier is handled by callers via
    :func:`resolve_engagement_path`:

        CWD walk-up  ->  active pointer  ->  ``$ENGAGEMENT_DIR``

    Returns ``(path, tier)`` with tier in ``{"cwd", "pointer", "env"}`` or None.
    Assessment commands use their independent fail-closed session binding.
    """
    cwd = Path.cwd()
    for candidate in (cwd, *cwd.parents):
        resolved = candidate.resolve()
        if (resolved / "scope.json").is_file():
            _warn_env_mismatch(resolved, "cwd")
            return resolved, "cwd"
    pointer = _read_active_pointer()
    if pointer is not None:
        _warn_env_mismatch(pointer, "pointer")
        return pointer, "pointer"
    env_dir = os.environ.get("ENGAGEMENT_DIR")
    if env_dir:
        resolved = Path(env_dir).expanduser().resolve()
        if (resolved / "scope.json").is_file():
            return resolved, "env"
    return None


def current_engagement_path() -> Path | None:
    result = resolve_current_engagement()
    return result[0] if result is not None else None


def set_active_engagement(install_root: Path, path: Path) -> Path:
    """Persist *path* as the active-engagement pointer.

    Writes BOTH ``~/.config/vigil/config.json:active_engagement_dir`` (canonical,
    consumed by the resolver) and the ``<engagements_root>/.active`` mirror (a
    human-readable breadcrumb). Validates the engagement root first so the
    pointer can never point at a non-engagement. Returns the resolved path.
    """
    from . import config as config_module

    resolved = path.expanduser().resolve()
    if not (resolved / "scope.json").is_file():
        raise SystemExit(f"{resolved} is not an engagement root (no scope.json).")
    config_module.set_config_value(ACTIVE_ENGAGEMENT_CONFIG_KEY, str(resolved))
    _write_active_mirror(install_root, resolved.name)
    return resolved


def clear_active_engagement(install_root: Path) -> None:
    """Unset both the config pointer and the ``.active`` mirror."""
    from . import config as config_module

    config_module.unset_config_value(ACTIVE_ENGAGEMENT_CONFIG_KEY)
    mirror = engagements_root(install_root) / ".active"
    try:
        mirror.unlink()
    except FileNotFoundError:
        pass


def _write_active_mirror(install_root: Path, key: str) -> None:
    """Best-effort ``<engagements_root>/.active`` breadcrumb; config.json is
    canonical, so a mirror-write failure is non-fatal.
    """
    root = engagements_root(install_root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        (root / ".active").write_text(key + "\n", encoding="utf-8")
    except OSError:
        pass


def _select_engagement(rows: list[EngagementRow]) -> EngagementRow:
    if not rows:
        raise SystemExit("No engagements found")
    if not sys.stdin.isatty():
        raise SystemExit(
            "Interactive --select is unavailable in a non-interactive process; "
            "pass the optional engagement key explicitly"
        )
    if shutil.which("fzf"):
        lines = [f"{row.key}\t{row.status}\t{row.current_phase}\t{row.target}\t{row.path}" for row in rows]
        result = subprocess.run(["fzf", "--with-nth", "1,2,3,4"], input="\n".join(lines), text=True, capture_output=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            selected = result.stdout.split("\t", 1)[0]
            return next(row for row in rows if row.key == selected)
    for idx, row in enumerate(rows, start=1):
        print(f"{idx}. {row.key} [{row.status}/{row.current_phase}] {row.target}", file=sys.stderr)
    choice = input("> ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(rows)):
        raise SystemExit("Invalid selection")
    return rows[int(choice) - 1]


def print_shell_cd_init(shell: str = "zsh") -> str:
    if shell not in {"zsh", "bash"}:
        raise SystemExit("Only zsh and bash shell snippets are supported")
    return 'athcd() { cd "$(vigil engagement path --select)"; }\n'


def start_engagement(install_root: Path, engagement_dir: Path, client: str, extra_args: list[str]) -> None:
    launcher = engagement_dir / f"start_{client}.sh"
    if not launcher.exists():
        raise SystemExit(f"Launcher not found for {client}: {launcher}")
    # Refresh the persisted active-engagement pointer to the engagement being
    # launched so the durable default tracks reality and can never freeze on a
    # foreign engagement (the ~/.zshrc-leak class). Best-effort: a pointer-write
    # failure must not block the launch. The launcher still exports
    # ENGAGEMENT_DIR for back-compat.
    try:
        set_active_engagement(install_root, engagement_dir)
    except (SystemExit, OSError):
        pass
    # Keep operator intent distinct from the launcher's effective identity.
    # The generated wrapper exports VIGIL_CLIENT_NAME; neither fact is a
    # provider-owned observation.
    os.environ["VIGIL_REQUESTED_CLIENT"] = client
    os.chdir(engagement_dir)
    os.execv(str(launcher), [str(launcher), *client_launch_argv(client, extra_args)])


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_json_atomic(path: Path, payload: object) -> None:
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o600
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as tmp_file:
            tmp_file.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        tmp_path.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


_CHROME_PATHS = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
]


_OPERATOR_DETAILS_RE = re.compile(r"^##\s+OPERATOR DETAILS\b", re.MULTILINE)


def _strip_operator_details(markdown: str) -> str:
    """Drop the ``## OPERATOR DETAILS — NOT FOR SUBMISSION`` reference section.

    ``vigil assess export submission`` appends an internal-only section (finding
    metadata, hygiene warnings, structured proof, linked command runs) below a
    second ``---`` divider. It must never reach a rendered submission PDF, so
    truncate the document at that heading and drop the divider that introduces it.
    A document without the heading (e.g. a blue-incident ``report.md``) is
    returned unchanged.
    """
    match = _OPERATOR_DETAILS_RE.search(markdown)
    if match is None:
        return markdown
    head = markdown[: match.start()]
    # Also drop the trailing horizontal-rule divider that introduces the section.
    head = re.sub(r"\n-{3,}[ \t]*\n?\s*$", "\n", head)
    return head.rstrip() + "\n"


def export_pdf(eng_dir: Path, output: Path | None = None) -> Path:
    # Blue incident engagements still scaffold a report.md; render it as before.
    # Red/code/android engagements no longer seed one — their closeout is the
    # per-finding submissions tree (`vigil assess export submission` writes
    # submissions/<slug>/submission.md), so fall back to rendering that tree.
    report_md = eng_dir / "report.md"
    if report_md.exists():
        sources: list[Path] = [report_md]
    else:
        sources = sorted(
            p for p in eng_dir.glob("submissions/*/submission.md") if p.is_file()
        )
        if not sources:
            raise SystemExit(
                f"nothing to export in {eng_dir}: no report.md and no "
                "submissions/<slug>/submission.md. Generate per-finding submissions "
                "first with `vigil assess export submission <finding-slug> "
                "--platform <bugcrowd|hackerone|direct>`."
            )

    pandoc = shutil.which("pandoc")
    if not pandoc:
        raise SystemExit("pandoc not found on PATH — install via: brew install pandoc")

    chrome = next((p for p in _CHROME_PATHS if Path(p).exists()), None)
    if not chrome:
        raise SystemExit("No Chrome/Chromium found — install Google Chrome")

    if output is None:
        output = eng_dir / "report.pdf"

    html_path = eng_dir / ".report_tmp.html"
    # Render from stripped copies so the internal-only OPERATOR DETAILS reference
    # section in each submission.md never lands in the pasteable report.pdf.
    stripped_dir = eng_dir / ".submission_tmp"
    try:
        stripped_dir.mkdir(exist_ok=True)
        render_sources: list[Path] = []
        for idx, src in enumerate(sources):
            stripped = _strip_operator_details(src.read_text(encoding="utf-8"))
            tmp = stripped_dir / f"{idx:03d}-{src.parent.name}.md"
            tmp.write_text(stripped, encoding="utf-8")
            render_sources.append(tmp)
        subprocess.run(
            [pandoc, *[str(src) for src in render_sources], "-o", str(html_path),
             "--standalone", "--embed-resources",
             "--metadata", "title=Engagement Report"],
            check=True,
        )
        subprocess.run(
            [chrome, "--headless", "--disable-gpu", "--no-sandbox",
             f"--print-to-pdf={output}", "--print-to-pdf-no-header",
             html_path.resolve().as_uri()],
            check=True,
            capture_output=True,
        )
    finally:
        html_path.unlink(missing_ok=True)
        shutil.rmtree(stripped_dir, ignore_errors=True)

    return output


# ── Engagement export: git-diff-able per-finding markdown tree ────────────
#
# `vigil engagement export --format markdown-tree` materializes one directory
# per finding under an output root, each holding three files:
#
#   draft.md   — the raw finding as the backend stores it (every persisted
#                field, including details_json contents flattened out).
#   debate.md  — the verification-narrative artifact (Phase 3:
#                kind="verification-narrative") linked to the finding, if one
#                was registered; otherwise a short placeholder.
#   report.md  — the report-ready rendering (the report-findings projection
#                with report_id numbering and root-cause grouping context).
#
# The point is review-without-a-running-backend: once exported, an engagement's
# findings become a stable directory tree that diffs cleanly in git across
# re-runs, so reviewers can see exactly what changed in draft/debate/report
# prose between two passes without standing the orchestrator back up.
#
# Findings are sourced over the same read API the rest of the CLI uses. The
# `client` parameter is duck-typed to ``AssessmentClient.get`` (see
# agent/scripts/assess/lib/client.py) so tests can inject a FastAPI TestClient
# adapter and exercise the whole renderer deterministically without a live LLM
# or a real socket.

EXPORT_FORMATS = {"markdown-tree"}

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class FindingReader(Protocol):
    """Minimal read surface this exporter needs from an assessment client.

    ``AssessmentClient.get(endpoint)`` returns the parsed JSON body for
    ``/engagements/{key}/assessment/{endpoint}``; that single method is all the
    markdown-tree export consumes, which keeps the production path and the
    test adapter trivially interchangeable.
    """

    def get(self, endpoint: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class ExportedEngagement:
    output_root: Path
    finding_count: int
    finding_dirs: list[Path]


def _finding_render():
    """Import the shared ``assess.lib.finding_render`` module.

    The finding->markdown block is rendered by a single shared module that
    physically lives under ``agent/scripts/assess/lib`` so the assess
    ``export findings`` command can import it directly. This installable ``src``
    package reaches it through the same import bridge it already uses for
    ``assess.lib.client`` (see ``paths.add_assess_import_path`` and
    ``_build_assessment_client``): the production ``vigil engagement export`` path puts
    ``agent/scripts`` on ``sys.path`` before this runs (via
    ``_build_assessment_client``), but tests and any direct caller may not — so
    fall back to discovering the repo root from this module's own location and
    bridging the path ourselves before retrying.
    """
    try:
        from assess.lib import finding_render  # type: ignore[import-not-found]

        return finding_render
    except ImportError:
        from .paths import agent_root, find_repo_root

        repo_root = find_repo_root(Path(__file__))
        if repo_root is not None:
            scripts_dir = agent_root(repo_root) / "scripts"
            if str(scripts_dir) not in sys.path:
                sys.path.insert(0, str(scripts_dir))
        from assess.lib import finding_render  # type: ignore[import-not-found]

        return finding_render


def _string_list(values: object) -> list[str]:
    return _finding_render().string_list(values)


def _finding_dir_name(finding: dict) -> str:
    """Stable, filesystem-safe directory name for one finding.

    Slug-first so the tree sorts by the canonical finding id (VA-001, …) and
    so two exports of the same engagement produce identical paths — that
    stability is the whole reason this is git-diff-able. Falls back to the
    title, then a generic label, when a slug is somehow absent.
    """
    raw = str(finding.get("slug") or finding.get("title") or "finding").strip()
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", raw).strip("-._")
    # Cap below the 255-byte filename limit, leaving room for a `-NN` collision
    # suffix; re-strip so we never end on a separator after truncation.
    cleaned = cleaned[:240].strip("-._")
    return cleaned or "finding"


def _render_finding_draft(finding: dict) -> str:
    """Render the raw finding (draft.md) — every persisted field, flattened.

    Uses the shared ``assess.lib.finding_render.render_finding`` so a single
    finding's draft block is identical to its section in the engagement-wide
    ``findings.md`` (export findings), but scoped to one finding per file. The
    root-cause grouping bullets that export findings includes inline are omitted
    here because each finding's grouping context is rendered separately into its
    own ``report.md`` (see ``_render_finding_report``). The shared renderer
    returns the newline-stripped block; draft.md is newline-terminated so the
    tree diffs cleanly.
    """
    return _finding_render().render_finding(finding, include_root_cause_group=False) + "\n"


def _render_finding_report(record: dict, *, group: dict | None = None) -> str:
    """Render the report-ready view (report.md) for a single finding.

    ``record`` is one entry from the report-findings projection (it carries a
    ``report_id`` and details already flattened to the top level). ``group``,
    when present, is the root-cause group this record roots, so the report
    rendering can note sibling findings the way the report-writer consumes
    them.
    """
    # An unset field renders as ``(unset)``, matching ``render_finding`` in
    # ``assess.lib.finding_render``: printing ``INFO`` for a finding whose severity
    # nobody set states a triage decision the record does not contain, and the
    # reader cannot tell it apart from a real one.
    report_id = str(record.get("report_id") or "---")
    slug = str(record.get("slug") or "")
    title = str(record.get("title") or "(unset)")
    severity = str(record.get("severity") or "(unset)").upper()
    header = f"# {report_id} — {title}"
    lines = [header, ""]
    meta = f"- **ID**: {report_id}"
    if slug:
        meta += f" (`{slug}`)"
    lines.append(meta)
    lines.append(f"- **Severity**: {severity}")
    location = record.get("canonical_location") or ""
    if location:
        lines.append(f"- **Location**: {location}")
    cwe_id = record.get("cwe_id") or ""
    if cwe_id:
        lines.append(f"- **CWE**: {cwe_id}")
    owasp_category = record.get("owasp_category") or ""
    if owasp_category:
        lines.append(f"- **OWASP**: {owasp_category}")
    cvss_vector = record.get("cvss_vector") or ""
    if cvss_vector:
        cvss_score = record.get("cvss_score")
        score_str = f" ({cvss_score})" if cvss_score is not None else ""
        lines.append(f"- **CVSS**: {cvss_vector}{score_str}")

    # No ``impact ← summary`` fallback: Summary prose under an Impact heading makes
    # an unauthored impact statement look authored, and the reader cannot tell which
    # field they are reading. ``render_finding`` and ``export submission`` refuse the
    # same substitution, so all three renderings of one finding agree.
    impact = record.get("impact") or ""
    if impact:
        lines.extend(["", "## Impact", "", str(impact)])
    evidence = record.get("evidence_detail") or record.get("evidence_ref") or ""
    if evidence:
        lines.extend(["", "## Evidence", "", str(evidence)])
    steps = _string_list(record.get("steps_to_reproduce"))
    if steps:
        lines.extend(["", "## Steps to Reproduce", ""])
        # The shared ``step_lines`` helper, so report.md and draft.md render one
        # finding's steps identically: each authored item verbatim, numbering left
        # to the author.
        lines.extend(_finding_render().step_lines(steps))
        # The audit rows behind those steps, named right under them — same reason
        # as ``render_finding``: without them a reader cannot tell a transcript
        # from a reconstruction.
        repro_runs = _string_list(record.get("repro_runs"))
        if repro_runs:
            lines.extend(["", f"Repro runs: {', '.join(repro_runs)}"])
    remediation = record.get("remediation") or ""
    if remediation:
        lines.extend(["", "## Remediation", "", str(remediation)])

    if group and group.get("siblings"):
        lines.extend(["", "## Root-Cause Group", ""])
        sibling_count = group.get("sibling_count", len(group.get("siblings", [])))
        lines.append(f"Root of a root-cause group with {sibling_count} sibling finding(s):")
        for sibling in group.get("siblings", []):
            effect = sibling.get("root_cause_effect", "eliminates_finding")
            marker = "residual attack path" if effect == "eliminates_attack_path" else "resolved by fixing this root"
            lines.append(
                f"- `{sibling.get('slug', '')}` [{str(sibling.get('severity', 'info')).upper()}] "
                f"{sibling.get('title', '')} — {marker}"
            )

    return "\n".join(lines).rstrip() + "\n"


def _placeholder_debate(finding: dict) -> str:
    slug = str(finding.get("slug") or finding.get("title") or "this finding")
    return (
        f"# Verification Debate — {slug}\n\n"
        "No verification-narrative artifact (kind=\"verification-narrative\") is "
        "linked to this finding yet.\n\n"
        "Register one during verification with:\n"
        "    vigil assess finding verify "
        f"{finding.get('slug', '<slug>')} --status <status> "
        "--reason \"...\" --narrative <path-to-debate.md>\n"
    )


def _fetch_debate_narrative(client: FindingReader, slug: str, finding: dict) -> str:
    """Resolve debate.md content for one finding.

    Searches the artifact index for a ``verification-narrative`` artifact
    linked to ``slug`` (Phase 3 registers these via `vigil assess
    finding verify --narrative`). When found, the top hit's full content is
    read back via the per-artifact GET (which inlines ``content`` for textual
    files). Any miss — no artifact, an unreadable id, or a transport hiccup —
    degrades to the placeholder so a single broken narrative never aborts the
    whole export.
    """
    if not slug:
        return _placeholder_debate(finding)
    try:
        hits = client.get(f"artifacts/search?finding={slug}&kind=verification-narrative")
    except Exception:
        return _placeholder_debate(finding)
    if not isinstance(hits, list) or not hits:
        return _placeholder_debate(finding)
    top = hits[0]
    if not isinstance(top, dict):
        return _placeholder_debate(finding)
    artifact_id = top.get("id")
    rel_path = str(top.get("relative_path") or "")
    content = ""
    if artifact_id is not None:
        try:
            full = client.get(f"artifacts/{artifact_id}")
        except Exception:
            full = None
        if isinstance(full, dict):
            content = str(full.get("content") or "")
    if not content:
        # The file exceeded the inline-content cap, or the search row already
        # carried an indexed/preview excerpt — fall back to whichever excerpt
        # we have so debate.md is never silently empty.
        content = str(top.get("indexed_text") or top.get("preview_text") or "")
    if not content.strip():
        return _placeholder_debate(finding)
    suffix = "" if content.endswith("\n") else "\n"
    return f"<!-- source artifact: {rel_path} -->\n{content}{suffix}"


def export_engagement_tree(
    client: FindingReader,
    output_root: Path,
    *,
    fmt: str = "markdown-tree",
) -> ExportedEngagement:
    """Write a git-diff-able per-finding markdown tree under ``output_root``.

    Returns the output root, the finding count, and the per-finding directories
    written (sorted by directory name). ``client`` is any object exposing the
    ``AssessmentClient.get`` read surface.
    """
    if fmt not in EXPORT_FORMATS:
        raise SystemExit(f"--format must be one of: {', '.join(sorted(EXPORT_FORMATS))}")

    findings = client.get("findings")
    if not isinstance(findings, list):
        raise SystemExit("export: unexpected response from backend for findings")

    # report-findings (draft mode) is the report-ready projection: report_id
    # numbering + flattened details + root-cause grouping. Index both the
    # grouped roots and standalone records by slug so each finding's report.md
    # can be rendered from its own projection record.
    report = client.get("report-findings?mode=draft")
    report_by_slug: dict[str, dict] = {}
    group_by_root_slug: dict[str, dict] = {}
    if isinstance(report, dict):
        for group in report.get("groups", []) or []:
            if not isinstance(group, dict):
                continue
            root = group.get("root")
            if isinstance(root, dict) and root.get("slug"):
                root_slug = str(root["slug"])
                report_by_slug[root_slug] = root
                group_by_root_slug[root_slug] = group
            for sibling in group.get("siblings", []) or []:
                if isinstance(sibling, dict) and sibling.get("slug"):
                    report_by_slug[str(sibling["slug"])] = sibling
        for record in report.get("standalone", []) or []:
            if isinstance(record, dict) and record.get("slug"):
                report_by_slug[str(record["slug"])] = record

    output_root = output_root.expanduser()
    output_root.mkdir(parents=True, exist_ok=True)

    ordered = sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity") or "medium").lower(), 99),
            str(f.get("slug") or ""),
        ),
    )

    written: list[Path] = []
    used_names: dict[str, int] = {}
    for finding in ordered:
        if not isinstance(finding, dict):
            continue
        slug = str(finding.get("slug") or "")
        base_name = _finding_dir_name(finding)
        # Guard against two findings collapsing to the same on-disk name
        # (e.g. slugless findings with identical titles): suffix collisions so
        # the tree never silently drops a finding.
        count = used_names.get(base_name, 0)
        used_names[base_name] = count + 1
        dir_name = base_name if count == 0 else f"{base_name}-{count + 1}"

        finding_dir = output_root / dir_name
        finding_dir.mkdir(parents=True, exist_ok=True)

        (finding_dir / "draft.md").write_text(_render_finding_draft(finding), encoding="utf-8")
        (finding_dir / "debate.md").write_text(
            _fetch_debate_narrative(client, slug, finding), encoding="utf-8"
        )
        report_record = report_by_slug.get(slug)
        if report_record is None:
            # Finding excluded from the report projection (merged /
            # false-positive / disputed / pending_runtime_proof holding): fall
            # back to the raw finding so report.md still exists and stays
            # diff-able, with a one-line note.
            report_md = (
                f"# {finding.get('slug') or '---'} — {finding.get('title') or '(untitled)'}\n\n"
                "_Not included in the current report projection "
                "(merged, false-positive, disputed, or pending_runtime_proof)._\n\n"
                + _render_finding_draft(finding)
            )
        else:
            report_md = _render_finding_report(
                report_record, group=group_by_root_slug.get(slug)
            )
        (finding_dir / "report.md").write_text(report_md, encoding="utf-8")
        written.append(finding_dir)

    # Prune stale finding directories from a prior export: re-exporting into a
    # stable output_root must not retain dirs for findings that were since
    # merged, renamed, or removed. Only remove dirs THIS exporter created —
    # identified by the draft.md + report.md marker files — never unrelated
    # content that happens to share output_root.
    current_names = {p.name for p in written}
    for child in sorted(output_root.iterdir()):
        if not child.is_dir() or child.name in current_names:
            continue
        if (child / "draft.md").is_file() and (child / "report.md").is_file():
            shutil.rmtree(child)

    return ExportedEngagement(
        output_root=output_root.resolve(),
        finding_count=len(written),
        finding_dirs=sorted(written),
    )


def _write_report(eng_dir: Path, engagement_type: str, *, name: str | None, target: str, repos: list[dict[str, str]], date_label: str) -> None:
    # Red-family engagements (web/code/both/android, and any default/fallback
    # type) no longer seed a `report.md`: their closeout artifact is the
    # per-finding submissions tree written by `vigil assess export submission`
    # and rendered to PDF by `export_pdf`. Only blue incident engagements keep a
    # scaffolded `report.md` for the report-writer to render into.
    if engagement_type != "blue":
        return
    # Blue incident engagements retain a minimal scaffold so report-writer
    # dispatch always has a report.md to render into.
    lines = ["# Engagement Report", ""]
    lines.append(f"- **Customer**: {name or '-'}")
    lines.append(f"- **Scope**: {target}")
    lines.append("- **Report Kind**: Incident (blue)")
    lines.extend([f"- **Engagement Date**: {date_label}", "- **Status**: Pending - report not yet generated", "", "---", ""])
    (eng_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")


def _write_issues_doc(eng_dir: Path) -> None:
    """Seed ISSUES-AND-ENHANCEMENTS.md — the operator's log of REUSABLE lessons.

    This file is for product / prompt / tooling improvements noticed DURING the
    engagement that outlive it (a confusing CLI flag, a missing skill step, a
    tool that needs a wrapper). It is deliberately NOT a findings log: findings,
    evidence, reproducing commands, and specialist handoffs stay backend-owned
    (recorded via `vigil assess`) and are never duplicated here.
    """
    lines = [
        "# Issues & Enhancements",
        "",
        "> Operator-owned log of REUSABLE product / prompt / tooling lessons from",
        "> this engagement — things worth fixing in Vigil itself (a confusing flag,",
        "> a missing skill step, a tool that needs a wrapper), not per-target notes.",
        ">",
        "> NOT a findings log. Findings, evidence, reproducing commands, and",
        "> specialist handoffs stay backend-owned — record them via `vigil assess`,",
        "> do not duplicate them here.",
        "",
    ]
    (eng_dir / "ISSUES-AND-ENHANCEMENTS.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


# Canonical program-brief section headings. The stub mirrors the
# `agent/references/_template-engagement.md`
# template's shape so an engagement starts with a structured, fill-in-the-blanks
# program brief even before an operator authors one.
_ENGAGEMENT_BRIEF_SECTIONS: tuple[tuple[str, str], ...] = (
    (
        "In-Scope / Out-of-Scope",
        "In-scope assets / targets (note Core vs Supplemental tiers when their "
        "rules differ) and the explicit out-of-scope carve-outs.",
    ),
    (
        "Required Request Headers / Deconfliction Marker",
        "Mandatory attribution headers (e.g. `X-Bug-Bounty: <handle>`) and how the "
        "program wants traffic marked for deconfliction (header vs User-Agent).",
    ),
    (
        "Rate Cap",
        "Program-mandated request-rate ceiling, if any (req/s); leave blank to use "
        "per-tool defaults.",
    ),
    (
        "No-Fire Endpoints",
        "Endpoints that must never be triggered (signup, password-reset, "
        "support/report/ticket, contact-form, ...). Characterize statically instead.",
    ),
    (
        "Irreversible / Notifying Flows",
        "Actions that create persistent state or reach a human inbox/queue/audit "
        "trail — surface a `scope_decision` rather than firing them.",
    ),
    (
        "Exfiltration Limits",
        "How far a proof-of-concept may go when reading data (record counts, "
        "redaction, stop conditions).",
    ),
    (
        "Parked / Non-Submittable Findings",
        "Classes the program will not reward or that are explicitly out of bounds.",
    ),
    (
        "Ban-Risk Rules",
        'Hard rules whose violation risks a platform ban (e.g. "do not modify '
        'customer account data → instant ban").',
    ),
)


def _write_engagement_brief_stub(agent_root: Path, eng_dir: Path) -> None:
    """Seed a STUB `ENGAGEMENT.md` program brief into the engagement run dir.

    `ENGAGEMENT.md` is referenced by ``agent/operator-core.md`` as a MANDATORY
    read whose hard requirements override default tool behavior and the
    AUTHORIZATION note, but nothing scaffolded it before — so a real program's
    ROE had no structured home in a fresh engagement. This drops an
    ENGAGEMENT-NEUTRAL scaffold (no host/program specifics — operators fill it
    in per engagement, or delete it when an engagement has no program brief)
    mirroring the section shape of the ``agent/references/_template-engagement.md``
    template (P3-C). The template is referenced by path rather than copied so the
    stub stays self-contained and deterministic whether or not the template has
    landed yet; when present, the template carries the fuller guidance/examples.
    """
    template_path = agent_root / "references" / "_template-engagement.md"
    lines = [
        "# Engagement Program Brief",
        "",
        "> **STUB — fill this in per engagement, or delete it if this engagement has",
        "> no program brief.** When present, this file is a MANDATORY read for the",
        "> operator (see `agent/operator-core.md` → \"Engagement Program Brief —",
        "> ENGAGEMENT.md\"); its hard requirements override default tool behavior and",
        "> the AUTHORIZATION note. It is the home for per-engagement ROE so those",
        "> rules stay OUT of the global operator prompt.",
        ">",
        f"> Structured template (full guidance + examples): `{template_path}`",
        "> Kept ENGAGEMENT-NEUTRAL on purpose — no host/program specifics are seeded",
        "> here. Populate each section from the program brief before recon/testing.",
        "",
    ]
    for heading, guidance in _ENGAGEMENT_BRIEF_SECTIONS:
        lines.extend([f"## {heading}", "", f"<!-- {guidance} -->", ""])
    (eng_dir / "ENGAGEMENT.md").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def _snapshot_orchestrator_database(install_root: Path) -> None:
    data_dir = resolve_orchestrator_data_dir(install_root)
    db_path = data_dir / "orchestrator.sqlite3"
    if not db_path.exists():
        return
    backup = db_path.with_name(f"{db_path.name}.bak.{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.{os.getpid()}")
    try:
        with sqlite3.connect(str(db_path)) as source, sqlite3.connect(str(backup)) as dest:
            source.backup(dest)
        _prune_orchestrator_database_snapshots(
            data_dir,
            max_copies=_engagement_db_snapshot_max_copies(),
        )
    except sqlite3.Error as exc:
        print(f"[vigil] warning: orchestrator DB snapshot failed for {db_path}: {exc}", file=sys.stderr)
    except OSError as exc:
        print(f"[vigil] warning: orchestrator DB snapshot pruning failed for {data_dir}: {exc}", file=sys.stderr)


def _engagement_db_snapshot_max_copies() -> int:
    raw = os.environ.get(ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES_ENV, "").strip()
    if not raw:
        return DEFAULT_ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES
    try:
        value = int(raw)
    except ValueError as exc:
        raise SystemExit(f"{ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES_ENV} must be an integer >= 1") from exc
    if value < 1:
        raise SystemExit(f"{ENGAGEMENT_DB_SNAPSHOT_MAX_COPIES_ENV} must be an integer >= 1")
    return value


def _prune_orchestrator_database_snapshots(data_dir: Path, *, max_copies: int) -> list[Path]:
    if max_copies < 1:
        raise ValueError("max_copies must be >= 1")
    snapshots = sorted(data_dir.glob("orchestrator.sqlite3.bak.*"), key=lambda path: path.name)
    if len(snapshots) <= max_copies:
        return []
    removed: list[Path] = []
    for path in snapshots[: len(snapshots) - max_copies]:
        try:
            path.unlink()
        except FileNotFoundError:
            # Another engagement creator may have pruned the same snapshot after
            # this process enumerated it. The retention postcondition already holds.
            continue
        removed.append(path)
    return removed


def _install_client_kind(agent_root: Path) -> str:
    has_codex = (agent_root / "AGENTS.md").exists() and (agent_root / ".codex").is_dir()
    has_claude = (agent_root / "CLAUDE.md").exists() and (agent_root / ".claude").is_dir()
    env_client = os.environ.get("VIGIL_CLIENT")
    if env_client in {"codex", "claude"}:
        return env_client
    if has_codex and not has_claude:
        return "codex"
    if has_claude and not has_codex:
        return "claude"
    return "both"


# Specialist auto-load stop-sign. Claude Code (and other harnesses) auto-load
# CLAUDE.md/AGENTS.md walking up the dir tree, so a DISPATCHED SPECIALIST subagent
# inherits these per-engagement operator pointers before it reaches its own
# Specialist-Context-Isolation rule. Authored ONCE and prepended to every per-engagement
# pointer this writer emits (DRY). Kept in lock-step with the render-pipeline banner in
# agent/scripts/render-operator-prompts.sh:render_specialist_stop_sign.
_SPECIALIST_STOP_SIGN = (
    "<!-- STOP — DISPATCHED SPECIALIST: if you are a specialist subagent (recon, source,\n"
    "     surface, vuln, exploit, fuzzer, osint, report, or any code-* role), do NOT load\n"
    "     this file. It is an OPERATOR pointer and its startup/runtime banner must not bleed\n"
    "     into your context. Load ONLY your own role file and every entry in its `Load First`.\n"
    "     Auto-loaded CLAUDE.md/AGENTS.md pointers up the directory tree do not apply to you.\n"
    '     See agent/shared-specialist-core.md ("Specialist Context Isolation") for why. -->\n'
)

# Operator-only ROE pointer added to per-engagement wrappers. ENGAGEMENT.md carries this
# engagement's ban-risk ROE (scope, required headers, rate cap, no-fire endpoints).
_ENGAGEMENT_ROE_POINTER = (
    "Read `ENGAGEMENT.md` in this directory if present (it carries ban-risk ROE for this engagement).\n"
)


def _canonical_operator_prompt(agent_root: Path, engagement_type: str) -> Path:
    """The installed operator prompt this engagement's wrappers must point at."""
    return agent_root / ("AGENTS-blue.md" if engagement_type == "blue" else "AGENTS.md")


def _require_install_prerequisites(agent_root: Path, engagement_type: str) -> None:
    """Fail before any side effect when the install root cannot back an engagement.

    ``create_engagement`` writes the directory, scope, manifest and launchers in one
    pass, so a missing installed prompt discovered mid-pass used to leave a scoped
    engagement with no launchers and no operator prompt — `engagement list` showed it
    as live, `engagement start` could not launch it, and `vigil install` could not
    repair it (a launcher-less directory is a `clientless` repair skip). Checking the
    precondition first turns that unrecoverable state into an actionable refusal.
    """
    operator_prompt = _canonical_operator_prompt(agent_root, engagement_type)
    if not operator_prompt.is_file():
        raise SystemExit(
            f"canonical operator prompt not found at {operator_prompt}; "
            f"run `vigil install {agent_root.parent}` first"
        )


def _write_prompt_wrappers(agent_root: Path, eng_dir: Path, client_kind: str, *, engagement_type: str) -> None:
    install_root = agent_root.parent
    _require_install_prerequisites(agent_root, engagement_type)
    operator_prompt = _canonical_operator_prompt(agent_root, engagement_type)

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

Artifacts:
- Use `vigil assess artifact register <path>` to index engagement files explicitly
- Use `vigil assess ...` for assessment operations from any directory
- Treat backend records and indexed engagement artifacts as shared durable memory; client-local memory is not visible to other clients or the audit trail
- Start clients through this engagement directory's launcher so ENGAGEMENT_DIR is exported for artifact paths and VIGIL_SESSION_ENGAGEMENT_DIR binds assessment state
- The local .orchestrator.env provides this engagement's orchestrator base URL; install-root env files are only fallbacks
"""
    # The engagement-local AGENTS.md points at the applicable canonical installed
    # prompt for both Codex and Claude. When the client kind requires a CLAUDE.md
    # entrypoint, we write it as a thin local pointer to the engagement
    # AGENTS.md rather than a second pointer to agent/CLAUDE.md — that prevents
    # Cursor / Claude Code from loading the same ~16.5k-token prompt twice per
    # turn (once via CLAUDE.md, once via AGENTS.md).
    if client_kind in {"codex", "claude", "both"}:
        (eng_dir / "AGENTS.md").write_text(
            f"{_SPECIALIST_STOP_SIGN}\n"
            f"# Engagement Workspace\n\nLoad workspace operator instructions from:\n- {operator_prompt}\n\n"
            "Read that file in bounded parts, following its Map of This File, and continue "
            "until you have reached the end of the file. Do not treat a tool's partial-read "
            "notice as completion.\n\n"
            f"{_ENGAGEMENT_ROE_POINTER}\n{common}",
            encoding="utf-8",
        )
    if client_kind in {"claude", "both"}:
        (eng_dir / "CLAUDE.md").write_text(
            f"{_SPECIALIST_STOP_SIGN}\n"
            "# Engagement Workspace\n\n"
            "Read `AGENTS.md` (in this same directory) for operator instructions.\n"
            "Do not also load this file — it is a pointer to AGENTS.md to avoid\n"
            "double-loading the operator prompt.\n\n"
            f"{_ENGAGEMENT_ROE_POINTER}",
            encoding="utf-8",
        )


def _write_codex_config(
    agent_root: Path,
    eng_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    codex_dir = eng_dir / ".codex"
    ensure_codex_config(
        agent_root,
        codex_dir,
        rendered_agent_root=rendered_agent_root,
    )
    ensure_codex_agents_link(agent_root, codex_dir)
    ensure_codex_skills_link(agent_root, codex_dir)


def _write_claude_config(
    agent_root: Path,
    eng_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    claude_dir = eng_dir / ".claude"
    ensure_claude_settings(
        agent_root,
        claude_dir,
        rendered_agent_root=rendered_agent_root,
    )
    ensure_claude_agents_link(agent_root, claude_dir)
    ensure_claude_commands_link(agent_root, claude_dir)


# OpenCode's --dangerously-skip-permissions is honored ONLY for the PRIMARY session.
# A task-dispatched sub-agent runs in a child session whose permission prompts the CLI
# loop never answers, so any child tool call that resolves to "ask" — most often
# external_directory (a specialist reading a file outside the engagement cwd, e.g. a
# skill/reference under the agent root) — freezes the child forever, hanging the parent
# task for the whole budget (opencode#12566/#7474/#16367, unfixed in 1.17.5). Resolving
# every tool to "allow" at the PROJECT-config level means no prompt is ever raised, so
# specialist (task) dispatch works. Per-agent roster frontmatter permission is NOT honored
# for task children — it must be this project opencode.json. Engagements run isolated with
# full authorization, so blanket-allow is the intended posture.
_OPENCODE_PERMISSION: dict = {"*": "allow", "external_directory": "allow", "doom_loop": "allow"}


def _load_opencode_config(eng_dir: Path) -> dict:
    """The engagement's opencode.json as a dict, guaranteeing the permission block."""
    path = eng_dir / "opencode.json"
    config: dict = {}
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                config = loaded
        except (OSError, json.JSONDecodeError):
            config = {}
    config.setdefault("$schema", "https://opencode.ai/config.json")
    config.setdefault("permission", dict(_OPENCODE_PERMISSION))
    return config


def _write_opencode_json(eng_dir: Path, config: dict) -> None:
    (eng_dir / "opencode.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")


def _write_opencode_config(agent_root: Path, eng_dir: Path) -> None:
    """Install the standard OpenCode plugin + specialist roster into an engagement.

    Mirrors ``_write_codex_config`` / ``_write_claude_config``: OpenCode reads
    neither Claude's ``settings.json`` nor Codex's ``config.toml``, so the standard
    scope-check + activity-log hooks ship as an OpenCode *plugin* copied from the
    agent-root template ``agent/.opencode/plugin/standard-hooks.js``. The plugin is
    written to BOTH ``.opencode/plugin/`` and ``.opencode/plugins/`` so it loads
    regardless of which directory name the installed OpenCode honours (the binary
    documents both; the singular ``plugin/`` is predominant). The specialist roster
    is exposed via symlink, exactly like Codex/Claude.

    This is the source of the standard PostToolUse logging for OpenCode — on the
    bench the guard-only ``bench-guard.js`` plugin is layered beside this file, so
    blocking (bench) and logging (standard) are both present, exactly like the
    Claude/Codex layering.
    """
    src = agent_root / ".opencode" / "plugin" / "standard-hooks.js"
    if src.exists():
        body = src.read_text(encoding="utf-8")
        for dirname in ("plugin", "plugins"):
            plugin_dir = eng_dir / ".opencode" / dirname
            plugin_dir.mkdir(parents=True, exist_ok=True)
            (plugin_dir / "standard-hooks.js").write_text(body, encoding="utf-8")
    ensure_opencode_agents_link(agent_root, eng_dir / ".opencode")
    # Seed opencode.json with the project-level permission block REQUIRED for task
    # sub-agent dispatch to work headlessly (see _OPENCODE_PERMISSION); thinking options
    # are merged on top later by write_opencode_reasoning_config.
    _write_opencode_json(eng_dir, _load_opencode_config(eng_dir))


# Appended to the engagement's `.goosehints` (Goose ONLY — never touches the shared
# operator prompt or the other clients). The live SSRF/BOLA runs showed deepseek-chat
# (non-thinking) solving INLINE with 0 `delegate` calls and writing no backend state —
# behaving like a lone CTF solver, not the Vigil orchestrator (a benchmark-validity issue:
# we want to measure the ORCHESTRATED agent, the way claude/codex run it). `delegate` IS
# available on Goose (verified), so this is a prompting gap: the shared prompt's concrete
# "Sanctioned inline form" example out-pulls the delegate bullet for a non-thinking model.
# This goose-scoped, imperative reinforcement counters that without re-steering any other
# client. See docs/goose-bench.md.
GOOSE_DISPATCH_DIRECTIVE = (
    "\n\n---\n"
    "## Goose runtime — dispatch, do not solo (read this first)\n\n"
    "You are running on **Goose**, where custom specialists ARE dispatchable headless. Operate as the\n"
    "Vigil **orchestrator**, not a lone solver:\n\n"
    "- **Dispatch** the find/test/exploit work to specialists with the `delegate` tool:\n"
    "  `delegate source <role>` (roster under `./.goose/recipes/`: recon-specialist, source-analyzer,\n"
    "  surface-collector, vulnerability-analyst, exploit-developer, fuzzer, osint-analyst,\n"
    "  report-writer; the code-* roles for code engagements). Pass the target URL + the specific\n"
    "  objective. Your FIRST action in a phase is a `delegate`, not a probe.\n"
    "- Run `vigil assess kali` YOURSELF only for the Operator-executed exceptions (one login test, a\n"
    "  fingerprint/health smoke, backend-write helpers). The 'Sanctioned inline form' in AGENTS.md is\n"
    "  for OpenCode and those exceptions — on Goose, delegate the probing rather than doing it inline.\n"
    "- **Record** findings and surfaces to the backend (`vigil assess finding record` /\n"
    "  `record-surface`) as you confirm them, even on a fast solve — backend state is the deliverable.\n"
)


def _write_goose_config(
    agent_root: Path,
    eng_dir: Path,
    *,
    rendered_agent_root: Path | None = None,
) -> None:
    """Install Goose's operator prompt, specialist roster, and standard hooks.

    Mirrors ``_write_opencode_config`` but Goose-native (see docs/goose-bench.md):

    - ``.goosehints`` — Goose auto-loads this from the cwd. We copy the engagement
      ``AGENTS.md`` (written by ``_write_prompt_wrappers`` just before this call) into it, so
      Goose gets the SAME engagement-local entrypoint Codex/OpenCode read natively. For a
      red engagement that ``AGENTS.md`` is a thin POINTER to the workspace-root operator
      prompt (a blue engagement's is the full rendered prompt); the operator resolves the
      pointer by reading the referenced file — the bench CTF message and the human start
      prompt both say "Read AGENTS.md", which drives that. There is no ``--agent operator``
      step — the default ``goose run`` agent already holds the ``delegate`` tool.
    - ``.goose/recipes`` — symlink to the generated specialist roster; the operator
      dispatches by name (``delegate source <role>``), resolved via ``GOOSE_RECIPE_PATH``.
    - ``.agents/plugins/vigil-standard`` — the standard hooks plugin (scope-check +
      activity-log), running the SHARED shell scripts via the payload adapter. The bench
      layers its guard-only hook beside it (anticheat._patch_goose_hooks).
    """
    agents_md = eng_dir / "AGENTS.md"
    base = agents_md.read_text(encoding="utf-8") if agents_md.is_file() else ""
    # Append the Goose-only dispatch directive so the (non-thinking) open-model operator
    # actually orchestrates instead of soloing inline; Goose auto-loads .goosehints.
    (eng_dir / ".goosehints").write_text(base + GOOSE_DISPATCH_DIRECTIVE, encoding="utf-8")
    ensure_goose_recipes_link(agent_root, eng_dir / ".goose")
    ensure_goose_standard_hooks(
        agent_root,
        eng_dir,
        rendered_agent_root=rendered_agent_root,
    )


# DeepSeek thinking levels → opencode per-model options. OpenCode deep-merges this
# project config over the global provider definition (baseURL/apiKey), so only the
# per-model options are written. The operator model deepseek-v4-pro takes the
# requested level; deepseek-v4-flash is always pinned thinking-off (bounded
# recon/parsing — reasoning adds latency without a quality gain).
_DEEPSEEK_THINKING_OPTIONS: dict[str, dict] = {
    "off":  {"thinking": {"type": "disabled"}},
    "high": {"thinking": {"type": "enabled"}, "reasoningEffort": "high"},
    "max":  {"thinking": {"type": "enabled"}, "reasoningEffort": "max"},
}


def write_opencode_reasoning_config(eng_dir: Path, thinking: str) -> None:
    """Merge the DeepSeek thinking options into ``<engagement>/opencode.json``.

    Preserves the permission block (and any other keys) seeded by ``_write_opencode_config``.
    ``thinking`` is ``off`` | ``high`` | ``max``; a blank/unknown level leaves the provider
    options untouched but still ensures the permission block is present. deepseek-v4-pro
    takes the level; deepseek-v4-flash is pinned thinking-off.
    """
    config = _load_opencode_config(eng_dir)
    pro_options = _DEEPSEEK_THINKING_OPTIONS.get((thinking or "").strip().lower())
    if pro_options is not None:
        models = config.setdefault("provider", {}).setdefault("deepseek", {}).setdefault("models", {})
        models["deepseek-v4-pro"] = {"options": pro_options}
        models["deepseek-v4-flash"] = {"options": dict(_DEEPSEEK_THINKING_OPTIONS["off"])}
    _write_opencode_json(eng_dir, config)


# Goose provider env + the #9397 reasoning-content repair proxy bootstrap, injected
# into start_goose.sh. Goose drives direct DeepSeek through its OpenAI-compatible
# provider; the sourced DeepSeek credential becomes Goose's OPENAI_API_KEY.
#
# THINKING-MODE STOPGAP (aaif-goose#9397): goose v1.38.0 drops DeepSeek's
# `reasoning_content` from the 2nd..Nth assistant messages it emits when it splits a
# multi-tool-call turn, and DeepSeek 400s ("reasoning_content ... must be passed
# back"). DeepSeek ignores `parallel_tool_calls:false`, so we cannot stop the model
# emitting parallel calls; instead a tiny local proxy
# (vigil_cli/bench/goose_reasoning_proxy.py, stdlib-only) re-attaches the dropped
# reasoning_content on the way to the API. The launcher starts it on an ephemeral
# port, repoints OPENAI_HOST at it (real DeepSeek host becomes the proxy's UPSTREAM),
# and trap-kills it on exit so it is auto-cleaned per attempt. The proxy is a no-op
# for non-thinking models (no reasoning_content to repair), so it is always safe to
# run. Disable with VIGIL_GOOSE_REASONING_PROXY=0 (then thinking-mode V4 regresses to
# the #9397 400). See docs/goose-bench.md.
_GOOSE_EXTRA_ENV = (
    "# Goose: direct DeepSeek via the OpenAI-compatible provider. OPENAI_API_KEY\n"
    "# is derived from DEEPSEEK_API_KEY; recipe roster + headless hygiene.\n"
    "# See docs/goose-bench.md.\n"
    'export GOOSE_PROVIDER="openai"\n'
    '_VIGIL_DEEPSEEK_HOST="https://api.deepseek.com"\n'
    'export OPENAI_API_KEY="${{DEEPSEEK_API_KEY:-}}"\n'
    "# Pin the model to a thinking V4 id so a bare `vigil engagement start\n"
    "# --client goose` (no --model) works; the bench passes --model on the CLI,\n"
    "# which OVERRIDES GOOSE_MODEL. Thinking mode is supported via the repair proxy below.\n"
    'export GOOSE_MODEL="deepseek-v4-pro"\n'
    'export GOOSE_RECIPE_PATH="$ENGAGEMENT_DIR/.goose/recipes"\n'
    'export GOOSE_DISABLE_KEYRING="1"\n'
    'export GOOSE_MODE="auto"\n'
    'export GOOSE_DISABLE_SESSION_NAMING="true"\n'
    "\n"
    "# --- #9397 reasoning-content repair proxy ---------------------------------\n"
    "# Start the stdlib-only repair proxy in front of DeepSeek, repoint OPENAI_HOST\n"
    "# at it, and kill it when this launcher exits (auto-cleaned per attempt).\n"
    'if [[ "${{VIGIL_GOOSE_REASONING_PROXY:-1}}" != "0" ]]; then\n'
    '  _vigil_proxy_script="{install_dir}/src/vigil_cli/bench/goose_reasoning_proxy.py"\n'
    '  if [[ -f "$_vigil_proxy_script" ]]; then\n'
    "    # Prefer the install venv python (always present); any python3 works (stdlib only).\n"
    '    _vigil_py="{install_dir}/.venv/bin/python"\n'
    '    [[ -x "$_vigil_py" ]] || _vigil_py="$(command -v python3 || true)"\n'
    '    if [[ -n "$_vigil_py" ]]; then\n'
    '      _vigil_proxy_out="$(mktemp -t vigil-goose-proxy.XXXXXX)"\n'
    "      # The launcher execs goose (its EXIT trap is then lost), so the proxy\n"
    "      # reaps its own announce file via PROXY_ANNOUNCE_FILE on shutdown.\n"
    '      UPSTREAM_HOST="$_VIGIL_DEEPSEEK_HOST" PROXY_PORT=0 PROXY_ANNOUNCE_FILE="$_vigil_proxy_out" \\\n'
    '        "$_vigil_py" "$_vigil_proxy_script" >"$_vigil_proxy_out" 2>&1 &\n'
    "      _vigil_proxy_pid=$!\n"
    '      trap \'kill "$_vigil_proxy_pid" 2>/dev/null; rm -f "$_vigil_proxy_out" 2>/dev/null\' EXIT INT TERM\n'
    "      # Wait (<=10s) for the proxy to announce its chosen port, then repoint.\n"
    '      _vigil_proxy_url=""\n'
    "      for _ in $(seq 1 50); do\n"
    '        _vigil_proxy_url="$(sed -n \'s#^LISTENING \\(http://127.0.0.1:[0-9]*\\)$#\\1#p\' "$_vigil_proxy_out" 2>/dev/null | head -n1)"\n'
    '        [[ -n "$_vigil_proxy_url" ]] && break\n'
    '        kill -0 "$_vigil_proxy_pid" 2>/dev/null || break\n'
    "        sleep 0.2\n"
    "      done\n"
    '      if [[ -n "$_vigil_proxy_url" ]]; then\n'
    '        export OPENAI_HOST="$_vigil_proxy_url"\n'
    "      else\n"
    '        echo "vigil: goose reasoning-content proxy failed to start; falling back to direct DeepSeek (thinking-mode V4 may 400 — #9397)" >&2\n'
    '        export OPENAI_HOST="$_VIGIL_DEEPSEEK_HOST"\n'
    "      fi\n"
    "    else\n"
    '      export OPENAI_HOST="$_VIGIL_DEEPSEEK_HOST"\n'
    "    fi\n"
    "  else\n"
    '    export OPENAI_HOST="$_VIGIL_DEEPSEEK_HOST"\n'
    "  fi\n"
    "else\n"
    '  export OPENAI_HOST="$_VIGIL_DEEPSEEK_HOST"\n'
    "fi\n"
)


_CLAUDE_EXTRA_ENV = (
    '# Keep Vigil memory in its shared backend/artifact stores. This launcher-only setting '
    'does not affect Claude sessions in other projects.\n'
    'export CLAUDE_CODE_DISABLE_AUTO_MEMORY="1"'
)


_SKIP_PERMISSION_ARGS = {
    "codex": "--dangerously-bypass-approvals-and-sandbox",
    "claude": "--dangerously-skip-permissions",
    "opencode": "--dangerously-skip-permissions",
    "kimi": "--auto",
}
_LEGACY_SKIP_PERMISSION_ARGS = {
    "codex": ("--full-auto",),
}

# Provider key the generated open-model launchers source from engagement/install
# env files. Both supported paths are direct DeepSeek. Claude/Codex/Kimi carry
# their own vendor authentication and need no env export.
CLIENT_PROVIDER_KEY = {
    "opencode": "DEEPSEEK_API_KEY",
    "goose": "DEEPSEEK_API_KEY",
}

# Clients whose CLI takes the operator message as a FLAG VALUE instead of a trailing
# positional. Vigil inserts the flag itself (client_launch_argv) so no launcher has to
# guess which argv element is the prompt.
CLIENT_MESSAGE_FLAGS = {
    "opencode": "--prompt",
    "goose": "-t",
}


def split_operator_message(client_args: Sequence[str]) -> tuple[list[str], str | None]:
    """Split a client passthrough tail into ``(flags, operator_message)``.

    The message is the trailing token when it is not option-shaped and is not the
    VALUE of the option-shaped token before it — the rule that stops ``--model opus``
    from being handed to the model as its operator prompt. An inline assignment such
    as ``--model=opus`` is already complete, so a following token can be the message.
    Everything else stays a flag, in order. An operator whose message would be misread
    (a boolean client flag directly before it) passes it through the client's own flag instead
    (``-- --prompt "…"`` / ``-- -t "…"``), which this returns untouched.
    """
    if not client_args:
        return [], None
    last = client_args[-1]
    if last.startswith("-"):
        return list(client_args), None
    previous = client_args[-2] if len(client_args) >= 2 else ""
    if previous.startswith("-") and "=" not in previous:
        return list(client_args), None
    return list(client_args[:-1]), last


def client_launch_argv(client: str, client_args: Sequence[str]) -> list[str]:
    """Place the operator message where ``client`` expects it, flags untouched."""
    flags, message = split_operator_message(client_args)
    if message is None:
        return flags
    message_flag = CLIENT_MESSAGE_FLAGS.get(client)
    return [*flags, message_flag, message] if message_flag else [*flags, message]


@dataclass(frozen=True, slots=True)
class ClientEntrypointRepairSkip:
    engagement_key: str
    reason: str
    evidence: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class ClientEntrypointRepairResult:
    scanned_count: int
    reconciled: tuple[str, ...]
    skipped: tuple[ClientEntrypointRepairSkip, ...]
    permission_overrides: tuple[str, ...] = ()

    @property
    def reconciled_count(self) -> int:
        return len(self.reconciled)

    @property
    def skipped_count(self) -> int:
        return len(self.skipped)


_ENTRYPOINT_REPAIR_DESTINATIONS = (
    ".codex/config.toml",
    ".codex/skills",
    ".claude/settings.json",
    ".claude/commands",
    ".opencode/plugin/standard-hooks.js",
    ".opencode/plugins/standard-hooks.js",
    "opencode.json",
    ".goose",
    ".goosehints",
    ".agents/plugins/vigil-standard/hooks/hooks.json",
    "start_codex.sh",
    "start_claude.sh",
    "start_opencode.sh",
    "start_goose.sh",
    "start_kimi.sh",
)


def _write_launchers(agent_root: Path, eng_dir: Path, client_kind: str, *, skip_permissions: bool) -> None:
    if client_kind in {"codex", "both"}:
        _write_launcher(
            agent_root,
            eng_dir,
            "codex",
            _SKIP_PERMISSION_ARGS["codex"] if skip_permissions else "",
        )
    if client_kind in {"claude", "both"}:
        _write_launcher(
            agent_root,
            eng_dir,
            "claude",
            _SKIP_PERMISSION_ARGS["claude"] if skip_permissions else "",
            extra_env=_CLAUDE_EXTRA_ENV,
        )
    # OpenCode reads the same engagement-local AGENTS.md as Codex (written for every
    # real client kind), so the operator prompt drives it unchanged. We always emit
    # start_opencode.sh so `--client opencode` (engagement start and `vigil bench`)
    # works regardless of install kind. It execs OpenCode's DEFAULT command (the TUI),
    # not `opencode run`: `run` is a one-shot headless invocation that exits after a
    # single reply, so a launcher built on it can never hold the operator loop that
    # `vigil engagement start` exists to open. The operator message rides OpenCode's
    # own `--prompt` (see CLIENT_MESSAGE_FLAGS), which seeds the session exactly like
    # a trailing prompt seeds claude/codex. Provider keys come from the same env files
    # the launcher already sources for ORCHESTRATOR_BASE_URL.
    #
    # `--agent operator` is REQUIRED for specialist dispatch to happen at all. With
    # no `--agent`, OpenCode uses its built-in default primary "build" agent,
    # which reads AGENTS.md as mere context and does every probe/analysis inline
    # (the observed "0 specialist dispatches" bug — empty sessions/index.json).
    # Our `operator` wrapper (.opencode/agent/operator.md) is rendered `mode: primary`
    # precisely so this `--agent operator` launch is accepted; a `mode: subagent`
    # entrypoint is silently rejected by OpenCode 1.17.5 (it falls back to "build").
    # The operator-as-primary has the `task` tool and dispatches the subagent roster
    # via `subagent_type: <role>` / `@<role>`, each loading its mandatory skill.
    if client_kind in {"codex", "claude", "both"}:
        _write_launcher(
            agent_root, eng_dir, "opencode",
            _SKIP_PERMISSION_ARGS["opencode"] if skip_permissions else "",
            exec_cmd="opencode --agent operator",
            provider_key=CLIENT_PROVIDER_KEY["opencode"],
        )
    # Goose: the PRIMARY open-model bench client. Like OpenCode it reads the engagement
    # prompt natively (Goose auto-loads `.goosehints`, written by _write_goose_config),
    # so we always emit start_goose.sh for every real client kind. Both exec forms load
    # the `developer` builtin (shell+editor) and — crucially — omit `--no-profile`, so
    # the default `summon` extension loads and the operator can `delegate source <role>`
    # to the specialist recipes (verified: --no-profile strips the delegate tool).
    #
    # Goose splits the session across two subcommands and the launcher must route on
    # that: `goose run` REFUSES to start without an instruction ("Must provide either
    # --instructions (-i), --text (-t), or --recipe") and, without `--interactive`,
    # exits as soon as that instruction is answered; `goose session` is the
    # instruction-less interactive entrypoint. `--no-session` is deliberately gone —
    # it suppresses the session file that both `--interactive` continuation and
    # `goose session --resume` depend on. Provider env is the OpenAI-compatible
    # direct-DeepSeek path.
    if client_kind in {"codex", "claude", "both"}:
        _write_launcher(
            agent_root, eng_dir, "goose",
            "",  # Goose has no skip-permissions flag; GOOSE_MODE=auto (in extra_env) handles approvals
            exec_cmd="goose run --interactive --with-builtin developer",
            uninstructed_cmd="goose session --with-builtin developer",
            provider_key=CLIENT_PROVIDER_KEY["goose"],
            extra_env=_GOOSE_EXTRA_ENV.format(install_dir="$VIGIL_INSTALL_DIR"),
        )
    # Kimi Code reads the same engagement-local AGENTS.md natively and needs no
    # generated roster, so — like opencode/goose — always emit start_kimi.sh.
    # `--auto` (fully autonomous, no questions) mirrors Codex's approval/sandbox
    # bypass and Claude's --dangerously-skip-permissions. The model is deliberately NOT pinned: the CLI's
    # own default_model is Moonshot's current flagship, so the best model is the
    # default and upgrades land without a repo change.
    if client_kind in {"codex", "claude", "both"}:
        _write_launcher(
            agent_root,
            eng_dir,
            "kimi",
            _SKIP_PERMISSION_ARGS["kimi"] if skip_permissions else "",
        )


def _existing_engagement_client_kind(eng_dir: Path) -> str | None:
    codex = (eng_dir / ".codex").exists() or (eng_dir / "start_codex.sh").exists()
    claude = (eng_dir / ".claude").exists() or (eng_dir / "start_claude.sh").exists()
    if codex and claude:
        return "both"
    if codex:
        return "codex"
    if claude:
        return "claude"
    return None


_GENERATED_LAUNCHER_PREAMBLE = (
    "#!/usr/bin/env bash\n"
    "set -euo pipefail\n\n"
    'ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"\n'
    "export ENGAGEMENT_DIR\n"
)


def _generated_primary_launcher_permission_mode(
    launcher: Path, client: str
) -> tuple[bool | None, str | None]:
    if launcher.is_symlink() or not launcher.is_file():
        return None, "not_regular_generated_file"
    try:
        body = launcher.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None, "unreadable_generated_file"
    if not body.startswith(_GENERATED_LAUNCHER_PREAMBLE):
        return None, "unrecognized_generated_preamble"
    permission_args = (
        _SKIP_PERMISSION_ARGS[client],
        *_LEGACY_SKIP_PERMISSION_ARGS.get(client, ()),
    )
    permission_arg = "|".join(re.escape(value) for value in permission_args)
    exec_pattern = re.compile(
        rf'^exec {client}[ \t]+(?:(?P<permission>(?:{permission_arg}))[ \t]+)?"\$@"$'
    )
    exec_lines = [line for line in body.splitlines() if line.startswith("exec ")]
    if len(exec_lines) != 1:
        return None, "unrecognized_generated_exec"
    match = exec_pattern.fullmatch(exec_lines[0])
    if match is None:
        return None, "unrecognized_generated_exec"
    return match.group("permission") is not None, None


def _existing_engagement_skip_permissions(
    eng_dir: Path, client_kind: str
) -> tuple[bool | None, ClientEntrypointRepairSkip | None]:
    observed: dict[str, bool] = {}
    for client in ("codex", "claude"):
        launcher = eng_dir / f"start_{client}.sh"
        if not launcher.exists() and not launcher.is_symlink():
            continue
        mode, error = _generated_primary_launcher_permission_mode(launcher, client)
        if error is not None:
            return None, ClientEntrypointRepairSkip(
                engagement_key=eng_dir.name,
                reason="unrecognized_primary_launcher",
                evidence=(f"{client}={error}",),
            )
        assert mode is not None
        observed[client] = mode

    if not observed:
        return None, ClientEntrypointRepairSkip(
            engagement_key=eng_dir.name,
            reason="permission_mode_unavailable",
            evidence=(f"client_kind={client_kind}",),
        )
    modes = set(observed.values())
    if len(modes) != 1:
        evidence = tuple(
            f"{client}={'skip' if enabled else 'prompt'}"
            for client, enabled in sorted(observed.items())
        )
        return None, ClientEntrypointRepairSkip(
            engagement_key=eng_dir.name,
            reason="permission_mode_conflict",
            evidence=evidence,
        )
    return modes.pop(), None


def repair_engagement_client_entrypoints(
    install_root: Path,
    *,
    ambiguous_permissions_as_skip: bool = False,
    rendered_install_root: Path | None = None,
) -> ClientEntrypointRepairResult:
    """Refresh installer-owned client entrypoints in existing engagements.

    Historical manifests do not record the creation-time ``--skip-permissions``
    choice. Exact current or historical generated primary launchers are therefore
    the durable source for that choice. Plan every engagement before writing any
    entrypoint. By default, ambiguous directories are preserved and returned as
    structured skips while every independently provable directory is reconciled.
    The explicit ``ambiguous_permissions_as_skip`` maintenance override applies
    only when primary-client intent is known and the sole ambiguity is absent or
    conflicting permission evidence from recognized generated launchers. It never
    overwrites an unrecognized/custom launcher or invents a client for a clientless
    engagement.
    """
    agent_root = install_root / "agent"
    rendered_agent_root = (rendered_install_root or install_root) / "agent"
    root = agent_root / "engagements"
    if not root.is_dir():
        return ClientEntrypointRepairResult(scanned_count=0, reconciled=(), skipped=())

    plans: list[tuple[Path, str, bool, bool]] = []
    skipped: list[ClientEntrypointRepairSkip] = []
    scanned_count = 0
    for eng_dir in sorted(root.iterdir(), key=lambda path: path.name):
        if eng_dir.is_symlink():
            if eng_dir.is_dir() and (eng_dir / "scope.json").is_file():
                scanned_count += 1
                skipped.append(
                    ClientEntrypointRepairSkip(
                        engagement_key=eng_dir.name,
                        reason="unsafe_engagement_path",
                    )
                )
            continue
        if not eng_dir.is_dir() or not (eng_dir / "scope.json").is_file():
            continue
        scanned_count += 1
        unsafe_destination = unsafe_symlink_destination(
            eng_dir, _ENTRYPOINT_REPAIR_DESTINATIONS
        )
        if unsafe_destination is not None:
            skipped.append(
                ClientEntrypointRepairSkip(
                    engagement_key=eng_dir.name,
                    reason="unsafe_repair_destination",
                    evidence=(unsafe_destination,),
                )
            )
            continue
        client_kind = _existing_engagement_client_kind(eng_dir)
        if client_kind is None:
            skipped.append(
                ClientEntrypointRepairSkip(
                    engagement_key=eng_dir.name,
                    reason="clientless",
                )
            )
            continue
        skip_permissions, skip = _existing_engagement_skip_permissions(eng_dir, client_kind)
        if skip is not None:
            if ambiguous_permissions_as_skip and skip.reason in {
                "permission_mode_conflict",
                "permission_mode_unavailable",
            }:
                plans.append((eng_dir, client_kind, True, True))
                continue
            skipped.append(skip)
            continue
        assert skip_permissions is not None
        plans.append((eng_dir, client_kind, skip_permissions, False))

    reconciled: list[str] = []
    permission_overrides: list[str] = []
    for eng_dir, client_kind, skip_permissions, permission_overridden in plans:
        if client_kind in {"codex", "both"}:
            _write_codex_config(
                agent_root,
                eng_dir,
                rendered_agent_root=rendered_agent_root,
            )
        if client_kind in {"claude", "both"}:
            _write_claude_config(
                agent_root,
                eng_dir,
                rendered_agent_root=rendered_agent_root,
            )
        _write_opencode_config(agent_root, eng_dir)
        _write_goose_config(
            agent_root,
            eng_dir,
            rendered_agent_root=rendered_agent_root,
        )
        _write_launchers(
            rendered_agent_root,
            eng_dir,
            client_kind,
            skip_permissions=skip_permissions,
        )
        reconciled.append(eng_dir.name)
        if permission_overridden:
            permission_overrides.append(eng_dir.name)

    return ClientEntrypointRepairResult(
        scanned_count=scanned_count,
        reconciled=tuple(reconciled),
        skipped=tuple(skipped),
        permission_overrides=tuple(permission_overrides),
    )


def _write_launcher(
    agent_root: Path,
    eng_dir: Path,
    client: str,
    permission_arg: str,
    *,
    exec_cmd: str | None = None,
    uninstructed_cmd: str | None = None,
    provider_key: str | None = None,
    extra_env: str = "",
) -> None:
    extra = f" {permission_arg}" if permission_arg else ""
    # The command the launcher execs. Defaults to the bare client binary (claude,
    # codex, kimi); a client whose session entrypoint is a subcommand or needs a
    # pinned agent (opencode, goose) passes it explicitly. The launcher FILE is
    # still start_<client>.sh.
    exec_cmd = exec_cmd or client
    # The launcher never parses "$@": it forwards argv verbatim, and Vigil places the
    # operator message where the client wants it (a trailing positional, or the
    # client's own message flag — see CLIENT_MESSAGE_FLAGS / client_launch_argv).
    # An earlier launcher split "${@: -1}" off as the message, which silently handed
    # a flag VALUE (`--model x` → "x") to the model as its operator prompt.
    if uninstructed_cmd:
        # Goose alone needs two entrypoints: `goose run` refuses to start without an
        # instruction flag, `goose session` takes none. Route on the exact flag set
        # goose itself demands, so a bare launch opens a session instead of exiting 1.
        instruction_flags = " | ".join(
            (
                "-t | --text | --text=*",
                "-i | --instructions | --instructions=*",
                "--recipe | --recipe=*",
            )
        )
        exec_line = (
            "instructed=0\n"
            'for arg in "$@"; do\n'
            f'  case "$arg" in {instruction_flags}) instructed=1; break ;; esac\n'
            "done\n"
            "if (( instructed )); then\n"
            f'  exec {exec_cmd}{extra} "$@"\n'
            "else\n"
            f'  exec {uninstructed_cmd}{extra} "$@"\n'
            "fi"
        )
    else:
        exec_line = f'exec {exec_cmd}{extra} "$@"'
    # Optional extra environment exports (e.g. Goose's GOOSE_*/OPENAI_* wiring),
    # inserted after the provider-key sourcing block so it can reference the sourced
    # keys (Goose derives OPENAI_API_KEY from DEEPSEEK_API_KEY for its direct path).
    extra_env_block = f"\n{extra_env.rstrip()}\n" if extra_env else ""
    # Optional provider-key export block (runner clients only). Built as a plain
    # string so its bash ${...} expansions are inserted literally into the f-string
    # template below; empty for claude/codex so their launchers stay byte-for-byte
    # identical to before.
    provider_block = ""
    if provider_key:
        provider_block = (
            "\n# Export the provider API key for the runner client from the same env files\n"
            "# the launcher already sources for ORCHESTRATOR_BASE_URL (first hit wins;\n"
            "# a value already in the environment is never overwritten).\n"
            'for env_file in "$ENGAGEMENT_DIR/.orchestrator.env" "$VIGIL_INSTALL_DIR/.orchestrator.env" "$VIGIL_INSTALL_DIR/.env"; do\n'
            '  [[ -f "$env_file" ]] || continue\n'
            f'  if [[ -z "${{{provider_key}:-}}" ]]; then\n'
            f'    candidate="$(grep -E "^{provider_key}=" "$env_file" | tail -n1 | cut -d= -f2- || true)"\n'
            f'    [[ -n "$candidate" ]] && export {provider_key}="$candidate"\n'
            "  fi\n"
            "done\n"
        )
    # The launcher exports operator-side env from the per-engagement
    # .orchestrator.env, with install-root .orchestrator.env / .env kept as
    # legacy fallbacks. Parent-shell ORCHESTRATOR_BASE_URL remains the
    # explicit override; among files the first hit wins so an install-root
    # default cannot retarget an engagement-local snapshot.
    #
    # AGENT_NAME is no longer exported here. The kali helper now defaults
    # to "operator" when neither --agent-name nor $AGENT_NAME / $VIGIL_AGENT_NAME
    # is set, so operator-executed mechanical pipeline work (tier-pick smoke,
    # runtime health, credential validation) still records the right
    # agent_name without the launcher poking the env. Specialist dispatch
    # wrappers must export AGENT_NAME=<role> before launching or pass
    # --agent-name explicitly in their commands.
    script = f"""#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"
export ENGAGEMENT_DIR
export VIGIL_SESSION_ENGAGEMENT_DIR="$ENGAGEMENT_DIR"
ENGAGEMENT_KEY="$(basename "$ENGAGEMENT_DIR")"
export ENGAGEMENT_KEY
VIGIL_AGENT_ROOT={shlex.quote(str(agent_root))}
export VIGIL_AGENT_ROOT
VIGIL_INSTALL_DIR={shlex.quote(str(agent_root.parent))}
export VIGIL_INSTALL_DIR
export VIGIL_CLIENT_NAME="{client}"

if [[ -z "${{ORCHESTRATOR_BASE_URL:-}}" ]]; then
  for env_file in "$ENGAGEMENT_DIR/.orchestrator.env" "$VIGIL_INSTALL_DIR/.orchestrator.env" "$VIGIL_INSTALL_DIR/.env"; do
    if [[ -f "$env_file" ]]; then
      candidate="$(grep -E '^ORCHESTRATOR_BASE_URL=' "$env_file" | tail -n1 | cut -d= -f2- || true)"
      if [[ -n "$candidate" ]]; then
        export ORCHESTRATOR_BASE_URL="${{candidate%/}}"
        break
      fi
    fi
  done
fi
{provider_block}{extra_env_block}
{exec_line}
"""
    path = eng_dir / f"start_{client}.sh"
    path.write_text(script, encoding="utf-8")
    path.chmod(0o755)
