"""Audit POST/PATCH plumbing and input validation for kali runs.

Owns the orchestrator-backend interactions tied to the audit pipeline:
the pre-exec ``command-runs`` POST that registers a ``running`` row before
docker-exec starts, the finalize PATCH that writes the terminal status,
and the ``failed-audit`` marker file written when the POST itself fails.
Also hosts the input-validation helpers (``--phase`` enum, agent-name
resolution, engagement-dir resolution) because they gate whether a row
makes it onto the wire at all.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any

from .audit_enums import (
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
    normalize_probe_kind,
    normalize_technique,
)
from .client import AssessError, AssessmentClient
from .scope import execution_policy_notes
from .config import Config
from .kali_output import _utcnow_iso


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


_INTENT_MAX_LEN = 400


def _enum_reject_message(
    flag: str, bad_value: str, allowed: tuple[str, ...], *, hint: str = ""
) -> str:
    """One-line, scoped enum-rejection text: closest matches first, then the full list.

    Leads with up to 3 edit-distance suggestions + the offending flag, so the
    caller does not have to scan a 46-value table to find the value they meant.
    The full allowed list is ALWAYS appended after the suggestion — the
    suggestion is additive, never a replacement — so validation behavior is
    unchanged and only the error TEXT becomes scoped.

    Matching is case-insensitive: both the offending value and the allowed
    values are upper-cased before ``difflib.get_close_matches`` so a lowercase
    ``--probe-kind`` typo or an upper-cased ``--technique`` both surface a
    suggestion, while the echoed suggestion and allowed list keep each enum's
    own canonical casing.
    """
    from .schema_validation import suggest_close_match

    bad_upper = (bad_value or "").upper()
    canonical_by_upper = {value.upper(): value for value in allowed}
    raw_suggestion = suggest_close_match(bad_upper, list(canonical_by_upper.keys()))
    upper_matches: list[str]
    if raw_suggestion:
        upper_matches = [token.strip() for token in raw_suggestion.split(",")]
    else:
        # Difflib's 0.55 edit-distance cutoff misses the "spelled-out
        # abbreviation" shape — e.g. a user typing the full word ``SQLINJECTION``
        # for the abbreviated enum ``SQLI`` (ratio 0.50) — because the long
        # operator word dilutes the ratio. Fall back to a conservative
        # substring/prefix check: an allowed token of length >= 3 that is wholly
        # contained in the bad value (or vice-versa) is a strong "you wrote the
        # long form of what we abbreviate" signal. Still additive (the full list
        # is always appended) and tight enough that unrelated tokens do not hit.
        upper_matches = [
            key
            for key in canonical_by_upper
            if len(key) >= 3 and bad_upper and (key in bad_upper or bad_upper in key)
        ][:3]
    head = f"{flag} '{bad_value}' is not valid."
    if upper_matches:
        # Map the upper-cased matches back to each enum's canonical spelling.
        canonical_matches = ", ".join(
            canonical_by_upper.get(token, token) for token in upper_matches
        )
        head += f" Did you mean: {canonical_matches}?"
    if hint:
        head += f" {hint}"
    return head + f" (allowed: {', '.join(allowed)})"


# Phases where a kali run resolving to the "operator" default is almost
# certainly a misattributed specialist call. Operators legitimately run
# mechanical probes in `recon`/`consume-test` (tier-pick smoke, runtime
# health, credential validation), so those are deliberately EXCLUDED — the
# WARN must stay non-noisy. `exploit`/`verify` are specialist-owned phases
# operators essentially never run mechanical kali in, so a fall-through to
# "operator" there is the misattribution signal CR-35 targets.
_SPECIALIST_ONLY_PHASES: frozenset[str] = frozenset({"exploit", "verify"})


def _extract_target_host(tool_name: str, cmd: list[str]) -> str:
    """C30: extract a parsed target host from argv for high-traffic verbs.

    Operators query coverage with ``vigil assess command-run list
    --target-host <host>``; the backend stores this in the
    ``target_host`` column. Per-verb extraction keeps the logic simple
    and deterministic — each kali wrapper knows its argv shape, so the
    parser is a switch on tool_name rather than a generic URL/host
    regex over the whole command string.

    Unhandled tools return ''. The existing FTS ``--q`` search still
    matches those rows, so no row is hidden from coverage queries —
    only the exact-match filter is empty.
    """
    if not cmd:
        return ""
    tool = (tool_name or "").lower()

    def _host_from_url(value: str) -> str:
        # Strip scheme, port, path. Tolerate '@user:pass' shapes.
        # Returns the canonical bare host so `--target-host <host>` queries
        # match — for bracketed IPv6 URLs that means the address inside the
        # brackets (e.g. `https://[2001:db8::1]:8443` → `2001:db8::1`), not
        # the `[addr]:port` literal.
        v = value.strip()
        if not v:
            return ""
        if "://" in v:
            v = v.split("://", 1)[1]
        # Drop everything after the first '/'
        v = v.split("/", 1)[0]
        # Drop credentials
        if "@" in v:
            v = v.split("@", 1)[1]
        # Bracketed IPv6 with optional :port suffix — extract the address
        # inside the brackets. URLs MUST bracket IPv6 literals per RFC 3986,
        # so unbracketed-IPv6 input is out of scope.
        if v.startswith("["):
            end = v.find("]")
            if end > 0:
                return v[1:end].lower()
            # Malformed input — fall through and emit the lowercased literal.
        elif ":" in v:
            # plain host:port
            v = v.split(":", 1)[0]
        return v.lower()

    def _next_value(flag_names: tuple[str, ...]) -> str:
        for idx, token in enumerate(cmd):
            if token in flag_names and idx + 1 < len(cmd):
                return cmd[idx + 1]
        return ""

    if tool == "httpx":
        # httpx supports -u <url> (single) or -l <file> (list); for list mode
        # we cannot pin a single target, leave empty.
        return _host_from_url(_next_value(("-u", "--url", "-target")))
    if tool == "nuclei":
        # nuclei -u <target> or -l <list>; list mode leaves target_host empty.
        return _host_from_url(_next_value(("-u", "--target", "-target")))
    if tool == "ffuf":
        # ffuf -u <url-with-fuzz-marker>; strip the FUZZ marker before host parse.
        raw = _next_value(("-u", "--url"))
        return _host_from_url(raw.split("FUZZ", 1)[0] if raw else "")
    if tool == "sqlmap":
        # sqlmap -u <url>; the URL is the canonical target.
        return _host_from_url(_next_value(("-u", "--url")))
    return ""


def _extract_target_anchor(tool_name: str, cmd: list[str]) -> tuple[str, str, int | None]:
    """Extract ``(host, path, port)`` of a probe's target URL from a kali argv.

    The depth ledger maps a null-FK probe_run to an app unit by host + PATH
    containment, so a probe against ``/api/...`` MUST carry its path or it can
    never cover that unit and the terminal backstop keeps blocking despite real
    tests. Unlike ``_extract_target_host`` (host only), this returns
    the path and port too, and also handles the raw ``kali exec curl <url>``
    fallback (a positional URL token), which the host-only switch missed.

    Returns ``("", "", None)`` for list-mode / unrecognized argv shapes.
    """
    from urllib.parse import urlsplit

    if not cmd:
        return "", "", None
    tool = (tool_name or "").lower()

    def _flag_value(flags: tuple[str, ...]) -> str:
        for idx, token in enumerate(cmd):
            if token in flags and idx + 1 < len(cmd):
                return cmd[idx + 1]
        return ""

    url = ""
    if tool in ("httpx", "nuclei", "sqlmap", "katana"):
        url = _flag_value(("-u", "--url", "--target", "-target"))
    elif tool == "ffuf":
        raw = _flag_value(("-u", "--url"))
        url = raw.split("FUZZ", 1)[0] if raw else ""
    else:
        words = [w for token in cmd[1:] for w in str(token).split()]
        url = next((w for w in words if w.startswith(("http://", "https://"))), "")
        if not url:
            url = next((w for w in words if "://" in w), "")
        if not url:
            for word in words:
                if word.startswith("-"):
                    continue
                head = word.split("/", 1)[0]
                if word.startswith("[") or "." in head:
                    url = word
                    break
    if not url:
        return "", "", None
    url = url.split("FUZZ", 1)[0]
    parse = url if "://" in url else "http://" + url
    try:
        split = urlsplit(parse)
        host = (split.hostname or "").lower()
        path = split.path or ""
        port = split.port
    except ValueError:
        return "", "", None
    return host, path, port


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
    canonical_technique = normalize_technique(technique)
    if TECHNIQUE_ENUM and canonical_technique not in TECHNIQUE_ENUM:
        raise AssessError(_enum_reject_message(
            "--technique", technique, TECHNIQUE_ENUM,
            hint="--technique is the vuln-class tag for the AUDIT row, not the probe step; "
                 "the per-step kind is --probe-kind. For initial mapping use RECON.",
        ))
    if not intent:
        raise AssessError("--intent is required")
    if len(intent) > _INTENT_MAX_LEN:
        raise AssessError(f"--intent exceeds {_INTENT_MAX_LEN} characters")
    if not probe_kind:
        raise AssessError("--probe-kind is required")
    canonical_probe_kind = normalize_probe_kind(probe_kind)
    if PROBE_KIND_ENUM and canonical_probe_kind not in PROBE_KIND_ENUM:
        raise AssessError(_enum_reject_message(
            "--probe-kind", probe_kind, PROBE_KIND_ENUM,
            hint="--probe-kind is the step type (recon vs. crafted payload vs. proof); "
                 "the vuln-class tag is --technique.",
        ))
    if not phase:
        raise AssessError("--phase is required (no env-var fallback)")
    if phase not in ALLOWED_PHASES:
        raise AssessError(_enum_reject_message("--phase", phase, ALLOWED_PHASES))
    if timeout is None or timeout <= 0:
        raise AssessError("--timeout (seconds) is required and must be > 0")
    if not agent_name:
        # `_resolve_agent_name` always returns a non-empty string thanks to the
        # default-to-"operator" fallback, so reaching this branch means an
        # internal regression (e.g. someone bypassed the resolver). Defense in
        # depth — keep the guard with a different message so the failure mode
        # is clear if it ever fires.
        raise AssessError("internal error: agent_name unexpectedly empty")


def _resolve_agent_name(
    explicit: str | None,
    *,
    agent_id: str | None = None,
    phase: str | None = None,
    warn: bool = False,
) -> str:
    """Resolve the kali audit attribution with a deterministic carrier.

    Precedence (CR-35):
        explicit ``--agent-name`` > ``--agent-id`` > $AGENT_NAME >
        $VIGIL_AGENT_NAME > "operator".

    The ``--agent-id`` companion is a deterministic carrier for the common
    case where a specialist knows its dispatch id (from its Runtime Identity
    block) but not its role string: the dispatch id (e.g. ``va-7f3``) is
    itself a non-"operator" attribution that ties the row to a specific
    dispatch, so it is used verbatim WITHOUT a backend lookup (no hot-path
    GET, no auto-inference of the in-progress dispatch — parallel lanes make
    that ambiguous). Env is an unreliable carrier because subagent shells do
    not inherit AGENT_NAME and Bash env does not persist across calls, so the
    explicit flags are the real fix.

    The "operator" default lets the operator run mechanical pipeline checks
    (tier-pick smoke, runtime health, credential validation) without
    remembering to set an attribution.

    WARN (only when ``warn=True``): a single concise stderr line nudging
    ``--agent-name <role>`` fires ONLY when the run falls through to the
    "operator" default while ``phase`` is a specialist-only phase
    (``exploit``/``verify``). It deliberately does NOT fire in
    ``recon``/``consume-test`` where operators legitimately run mechanical
    probes, so routine operator calls stay silent.
    """
    if explicit:
        return explicit
    if agent_id:
        return agent_id
    env_value = os.environ.get("AGENT_NAME") or os.environ.get("VIGIL_AGENT_NAME") or ""
    if env_value:
        return env_value
    if warn and (phase or "").strip().lower() in _SPECIALIST_ONLY_PHASES:
        print(
            f"warning: kali run in --phase '{phase}' resolved to agent_name='operator' "
            "(no --agent-name/--agent-id and no AGENT_NAME env). If you are a specialist, "
            "pass --agent-name <role> so coverage is attributed to you, not the operator.",
            file=sys.stderr,
        )
    return "operator"


def _resolve_engagement_dir(explicit: Path | None, cfg: Config) -> Path:
    if explicit is not None:
        return Path(explicit).resolve()
    return Path(cfg.engagement_dir).resolve()


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
    run_uuid: str,
    execution_policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command": " ".join(cmd),
        "argv": list(cmd),
        "tool_name": tool_name,
        "route": f"vigil assess kali/{tool_name}",
        "agent_name": agent_name,
        "phase": phase,
        "target_host": _extract_target_host(tool_name, cmd),
        "started_at": started_at_iso,
        # Empty until the post-exec PATCH-finalize writes the real terminal
        # timestamp. Previously we wrote started_at here to satisfy the
        # backend NOT NULL constraint, which made orphan rows look "completed
        # at the same instant they started." Backend now accepts empty for
        # status="running" rows and rejects empty on terminal status.
        "completed_at": "",
        "duration_ms": 0,
        "stdout": "",
        "stderr": "",
        "audit_source": "header",
        "technique": technique,
        "intent": intent,
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
        # Pin the backend's `run_uuid` column to the engagement-wide id the
        # CLI generated for the wrapper pid file and stdout path. Without
        # this, the backend would generate its OWN uuid and the column would
        # not match the pid file key — orphan-sweep would have no DB-side way
        # to recover the in-container PID and would fall back to regex-parsing
        # stdout_path, which breaks the moment the artifact dir is reconfigured.
        "run_uuid": run_uuid,
    }
    if execution_policy is not None:
        payload["notes"] = execution_policy_notes(execution_policy)
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
    # 409 from the finalize endpoint means a concurrent finalize already
    # wrote the canonical row — accept it and return that row, do not raise.
    return client.patch(f"command-runs/{int(run_id)}", payload, accept_409=True)


def _write_failed_audit_marker(engagement_dir: Path, *, run_uuid: str, error: str) -> None:
    marker_dir = engagement_dir / "scans" / "kali"
    marker_dir.mkdir(parents=True, exist_ok=True)
    marker = marker_dir / f"{run_uuid}.failed-audit"
    try:
        marker.write_text(f"{_utcnow_iso()} {error}\n", encoding="utf-8")
    except OSError:
        pass
