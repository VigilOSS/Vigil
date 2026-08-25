"""Host-side `vigil assess kali` orchestration.

Owns ``kali_exec`` — the high-level loop that ties the docker-exec
subprocess, the audit pipeline (pre-exec POST + finalize PATCH), output
spilling under ``${ENGAGEMENT_DIR}/scans/kali/<run-id>.{out,err}``, the
two-namespace process-group cleanup on timeout, scope/auth context
capture, and dedup warnings together. Typed kali_* commands and the raw
``kali exec`` fallback all delegate here.

Implementation responsibilities are split across sibling modules so the
blast radius of future changes stays scoped:

- ``kali_tool_naming``  — tool-name derivation + shell-pipeline parsing
- ``kali_runtime_exec`` — docker-exec wrapping + two-namespace kill cascade
- ``kali_audit``        — pre-exec POST, finalize PATCH, failed-audit marker,
                          input validation, agent-name + engagement-dir resolution
- ``kali_output``       — head+tail preview, RSS rollup, scope/auth context,
                          ``KaliResult`` dataclass
- ``kali_cli``          — argparse scaffolding (flags, kwargs builder,
                          ``emit_result``) used by every ``kali_<verb>`` file

This module re-exports the public surface (``kali_exec``, ``KaliResult``,
``ALLOWED_PHASES``, ``add_required_kali_flags``, etc.) plus the private
helpers that ``orchestrator/backend/tests/test_kali_cli.py`` patches via
``monkeypatch.setattr(kali, "<name>", ...)`` so test mocks keep resolving
without touching the rest of the suite.
"""
from __future__ import annotations

import os
import re
import resource
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from . import kali_resolve, vuln_taxonomy
from . import scope as scope_lib

# Re-exports — keep this block ordered by source module so the public surface
# is grep-friendly. Tests patch a number of these via the legacy
# ``kali.<name>`` attribute path; the orchestrator below also calls them via
# bare name lookup, which resolves to these globals (so patches take effect).
from .audit_enums import (
    PROBE_KIND_ENUM,
    TECHNIQUE_ENUM,
    normalize_probe_kind,
    normalize_technique,
)
from .client import AssessError, AssessmentClient, default_runtime_container
from .config import Config, load_config
from .identity import (
    browser_cookies_for,
    host_cookie_hosts,
    host_cookies_for,
    resolve_identity,
)
from .kali_audit import (
    _INTENT_MAX_LEN,
    ALLOWED_PHASES,
    _extract_target_anchor,
    _extract_target_host,
    _patch_finalize,
    _post_pre_exec_row,
    _resolve_agent_name,
    _resolve_engagement_dir,
    _validate_inputs,
    _write_failed_audit_marker,
)
from .kali_cli import (
    CRAWL_RATE_DEFAULT,
    CRAWL_RATE_HARD_CAP,
    ScopedErrorParser,
    add_passthrough_args_flag,
    add_required_kali_flags,
    count_list_targets,
    emit_result,
    extend_cmd_with_extra_args,
    incomplete_list_run_warning,
    kali_args_to_kwargs,
    parse_list_progress,
    resolve_crawl_rate_limit,
    safe_engagement_dir,
)
from .kali_output import (
    _REQUIRED_HEADER_INJECTABLE,
    _REQUIRED_HEADER_SKIP,
    KaliResult,
    _apply_identity_headers,
    _apply_required_headers,
    _auth_context,
    _engagement_type,
    _existing_header_names,
    _peak_rss_kilobytes_to_bytes,
    _read_proc_peak_rss,
    _read_safely,
    _required_headers,
    _scope_version,
    _utcnow_iso,
    detect_transport_error,
    detect_waf_challenge,
    extract_probe_response_headers,
    is_http_prober,
)
from .kali_runtime_exec import (
    _build_docker_exec,
    _check_container_running,
    _cleanup_container_pid_file,
    _container_pid_file,
    _kill_in_container,
    _read_container_pid,
)
from .kali_tool_naming import (
    _SHELL_BINARIES,
    _SHELL_KEYWORDS,
    _analyze_tool_name,
    _derive_tool_name,
    _is_plausible_executable,
    _scan_inner_for_first_exec,
    _split_inner_pipeline_stages,
)
from .rate_leases import aggregate_rate_reservation, target_rate_lease

# Test-mode override: when set, skips both audit POST and `docker exec` so
# argparse round-trip tests don't require a live backend or container. The
# `run` callable on every kali_* command should still be reachable for `--help`
# without going through the helper.
_KALI_NOOP_ENV = "VIGIL_KALI_NOOP"


_PROBE_EMITTING_KINDS = frozenset({"payload", "exploit", "baseline", "replay"})

_NON_WEB_ENGAGEMENT_TYPES = frozenset({"code", "blue"})


def _emit_probe_run(
    client: AssessmentClient,
    *,
    engagement_type: str,
    technique: str,
    probe_kind: str,
    auth_context: str,
    tool_name: str,
    agent_name: str,
    return_code: int | None,
    timed_out: bool,
    cmd: list[str],
    evidence_ref: str,
) -> None:
    """Best-effort auto-emit one probe_run from a finished Kali run.

    This is the linchpin that makes depth observable: every typed kali call
    already carries a vuln-class ``--technique`` and a ``--probe-kind``, so a
    completed real-attack probe honestly records "this vuln class was tested
    against this host" WITHOUT any new specialist behavior.

    Emission rules (each derived from durable run state, never a blind default):
      * WEB-ONLY GUARD: skip unless engagement_type ∈ {web, both} — no
        cross-track bleed onto code/blue (R-H2 doctrine).
      * Only for a REAL test (probe_kind ∈ payload/exploit/baseline/replay);
        fingerprint/cleanup never emit.
      * attack_family = TECHNIQUE_TO_CLASS[technique]; if None (operational
        technique like RECON/FUZZ/HEALTH) there is no vuln class to attribute,
        so SKIP — never invent a class.
      * result_status: timed_out OR return_code not in (0, None) → "error"
        (which is NOT in PROBE_RESULT_STATUSES_COVERING, so a failed probe never
        counts as covered, S4); otherwise "tested". Operational/fingerprint
        probes are already excluded, so a completed real-attack probe = the
        class was honestly tested.

    BEST-EFFORT: any failure warns to stderr and returns; it must NEVER block or
    fail the tool run, and must not raise.
    """
    try:
        if str(engagement_type or "").lower() in _NON_WEB_ENGAGEMENT_TYPES:
            return
        if probe_kind not in _PROBE_EMITTING_KINDS:
            return
        attack_family = vuln_taxonomy.TECHNIQUE_TO_CLASS.get(technique)
        if attack_family is None:
            return
        if timed_out or (return_code not in (0, None)):
            result_status = "error"
        else:
            result_status = "tested"
        target_host, target_path, target_port = _extract_target_anchor(tool_name, cmd)
        if not target_host:
            target_host = _extract_target_host(tool_name, cmd)
        payload = {
            "target_host": target_host,
            "target_path": target_path,
            "target_port": target_port,
            "auth_context": auth_context,
            "input_slot": "unknown",
            "attack_family": attack_family,
            "payload_family": "",
            "payload_value": "",
            "tool_name": tool_name,
            "agent_name": agent_name,
            "result_status": result_status,
            "observed_http_status": None,
            "evidence_ref": evidence_ref,
        }
        client.post("probe-runs", payload)
    except Exception as exc:  # noqa: BLE001 — best-effort, must never break a run
        print(
            f"warning: probe-run auto-emit failed: {exc}; depth harness skipped this run.",
            file=sys.stderr,
        )


# HTTP verbs that mutate server state. A CSRF double-submit token is only
# meaningful on these — a GET/HEAD is read-only and never needs it (and a
# framework that rejects an unexpected header on a safe request would be
# needlessly tripped).
_STATE_CHANGING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _request_is_state_changing(cmd: list[str]) -> bool:
    """True when the argv describes a state-changing HTTP request (curl-style).

    Derived from the argv the same way the target host is (see
    ``kali_resolve.target_host_port``). Precedence — and the reason we scan the
    WHOLE argv before deciding rather than returning on the first hit:

      1. An explicit ``-X/--request <verb>`` (attached ``-XPOST`` / ``--request=POST``
         or a separate value) is AUTHORITATIVE — it sets the method. If that verb
         is GET/HEAD the request is read-only even with a ``-d`` body attached, so
         we must not let an earlier ``-d`` short-circuit us into "state-changing".
      2. ``-G``/``--get`` forces curl to send a GET and move any ``-d`` data into the
         query string, so ``-G -d k=v`` is a GET — the CSRF header must NOT inject
         (a ``-d`` body no longer implies POST once ``-G`` is present).
      3. Otherwise a request-body flag (``-d`` / ``--data`` / ``--data-*`` / ``--json``)
         is curl's implicit POST → state-changing.

    GET/HEAD — and anything we cannot positively classify (including bundled short
    clusters like ``-sd`` we do not attempt to split) — are read-only, so the CSRF
    header stays off by default (fail-safe: never stamp a header we are not sure
    the request needs; a missed injection is harmless, a false one is not).
    """
    tokens = [str(t) for t in (cmd or [])]
    n = len(tokens)
    explicit_method: str | None = None
    force_get = False
    has_body_flag = False
    for idx, tok in enumerate(tokens):
        # -X POST / --request POST (verb as a separate token).
        if tok in ("-X", "--request"):
            if idx + 1 < n:
                explicit_method = tokens[idx + 1].strip().upper()
            continue
        # -XPOST (attached short form) / --request=POST.
        if tok.startswith("-X") and len(tok) > 2:
            explicit_method = tok[2:].strip().upper()
            continue
        if tok.startswith("--request="):
            explicit_method = tok.split("=", 1)[1].strip().upper()
            continue
        # -G / --get: curl sends a GET and appends -d data to the query string.
        if tok in ("-G", "--get"):
            force_get = True
            continue
        # Request-body flags imply a body → curl's implicit POST (unless -G/-X overrides).
        if tok in ("-d", "--json"):
            has_body_flag = True
            continue
        if tok.startswith("--data"):  # --data / --data-raw / --data-binary / --data-urlencode / --data=...
            has_body_flag = True
            continue
        if tok.startswith("-d") and len(tok) > 2:  # -d@file / -dvalue (attached short form)
            has_body_flag = True
            continue
    # Explicit method is authoritative; -G forces GET; else a body implies POST.
    if explicit_method is not None:
        return explicit_method in _STATE_CHANGING_METHODS
    if force_get:
        return False
    return has_body_flag


def _csrf_double_submit_pair(
    material: dict, cookie_map: dict[str, str]
) -> tuple[str, str] | None:
    """Resolve an opt-in CSRF double-submit ``(header, value)`` from identity material.

    The mapping is APP-SPECIFIC and OPT-IN — the header name and its source cookie
    vary per target, so nothing is hardcoded::

        material["csrf"] = {"cookie": "<cookie-name>", "header": "<header-name>"}

    The value is mirrored from the named cookie in the ALREADY-BUILT ``cookie_map``
    (the same host-scoped view that becomes the ``Cookie`` header), so the header
    carries exactly the token the request also sends as a cookie — the double-submit
    invariant. Returns ``None`` when the mapping is absent/malformed or the named
    cookie is not present in this request's cookie view (no crash, no header).
    """
    csrf = material.get("csrf")
    if not isinstance(csrf, dict):
        return None
    cookie_name = str(csrf.get("cookie") or "").strip()
    header_name = str(csrf.get("header") or "").strip()
    if not cookie_name or not header_name:
        return None
    value = cookie_map.get(cookie_name)
    if not isinstance(value, str) or not value.strip():
        return None
    return (header_name, value)


def _identity_header_pairs(
    material: dict, *, request_host: str = "", state_changing: bool = False
) -> list[tuple[str, str]]:
    """Flatten an identity's auth material into ``(header, value)`` pairs.

    Supports a ``headers`` map, a ``cookies`` map plus the request-host-scoped
    ``host_cookies`` jar (joined into one ``Cookie`` header the way a browser
    sends it), an optional bearer ``token``, and an opt-in CSRF double-submit
    header derived from a named cookie. Order is deterministic.

    ``request_host`` selects the matching ``host_cookies`` bucket(s) (I-22): a
    cookie-session app on a host other than the capture-time primary scope host
    would otherwise be sent the flat (mismatched/empty) cookie view and read the
    request as "session stale". When a per-host bucket matches, it is used ALONE:
    the flat ``cookies`` view is a UNION across every captured host, so blending it
    in would leak another host's uniquely-named session cookies into this request
    (cross-host session bleed). We fall back to the flat view ONLY for identities
    that carry no per-host buckets at all (manual/legacy identities with no
    ``host_cookies``); when buckets exist but none match this request host, we omit
    cookies entirely rather than route the display-only union onto an unrelated
    target.

    ``state_changing`` gates the CSRF double-submit header: on a POST/PUT/PATCH/
    DELETE the ``material["csrf"]`` mapping (if present) mirrors the named cookie's
    value into the configured header so writes aren't CSRF-rejected and misread as
    an auth gate (a false-negative BFLA risk). GET/HEAD never inject it.
    """
    pairs: list[tuple[str, str]] = []
    headers = material.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip():
                pairs.append((str(key), str(value)))
    cookie_map: dict[str, str] = {}
    host_scoped = host_cookies_for(material, request_host)
    if host_scoped:
        # Authoritative per-host bucket: use it alone (no flat-union blend), so a
        # cookie captured for a DIFFERENT host never rides this request.
        cookie_map.update(host_scoped)
    elif not host_cookie_hosts(material):
        # This identity has NO captured per-host buckets at all (a manual/legacy
        # identity whose only cookies live in the flat ``cookies`` view): fall
        # back to that flat view. When per-host buckets DO exist but none match
        # this request host (or a list-mode run left ``request_host`` empty) we
        # deliberately OMIT cookies rather than fall back — ``material["cookies"]``
        # is a DISPLAY-ONLY union across every captured host, so injecting it here
        # would bleed another host's uniquely-named session cookies into this
        # unrelated target (cross-host session bleed).
        cookies = material.get("cookies")
        if isinstance(cookies, dict):
            cookie_map.update({str(k): str(v) for k, v in cookies.items()})
    if cookie_map:
        cookie = "; ".join(f"{k}={v}" for k, v in cookie_map.items())
        pairs.append(("Cookie", cookie))
        # CSRF double-submit (opt-in, method-gated). Only on a state-changing
        # request, only when the app-specific mapping resolves against a cookie
        # this request actually carries, and never clobbering an operator-set
        # header (mirrors the Authorization guard below).
        if state_changing:
            csrf_pair = _csrf_double_submit_pair(material, cookie_map)
            if csrf_pair is not None:
                header_name, header_value = csrf_pair
                if not any(name.lower() == header_name.lower() for name, _ in pairs):
                    pairs.append((header_name, header_value))
    token = _identity_bearer_token(material)
    if token and not any(name.lower() == "authorization" for name, _ in pairs):
        pairs.append(("Authorization", f"Bearer {token}"))
    return pairs


def _identity_bearer_token(material: dict) -> str:
    """Return a bearer token from either legacy top-level fields or backend
    credential ``tokens`` material.
    """
    for value in (material.get("token"), material.get("bearer")):
        if isinstance(value, str) and value.strip():
            return value.strip()
    tokens = material.get("tokens")
    if isinstance(tokens, dict):
        for key in ("access_token", "accessToken", "bearer", "token", "id_token", "idToken"):
            value = tokens.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return ""


# Identity lifecycle states, from the credential store (backend db.py):
#   ""/"available" — replay normally.
#   "stale"        — ADVISORY age flag only. `_sweep_credential_age` sets it
#                    purely because `now - last_seen_at > 8h`; NOTHING has
#                    observed the session failing. Replay it and WARN.
#   "missing"      — no material was stored; nothing to inject.
#   "dead"         — a liveness PROBE proved the session dead. Refuse.
#   anything else  — an operator-set marker (the upsert API takes free text).
#                    Refuse: an explicit marker is a deliberate signal.
# `stale` is the ONE state that widened. Treating that advisory flag as a hard
# refusal deadlocked the store: an identity aged out at exactly 8h no matter how
# actively it was used, and the documented recovery (`auth status --probe`) runs
# THROUGH this same injector, so the recovery could not run against the state it
# recovers from. Operators worked around it by pasting the cookie as a plain
# `-H "Cookie: ..."` header, which records the audit row as
# auth_context=anonymous and silently destroys the cross-identity evidence the
# depth ledger measures access-control coverage from.
_IDENTITY_STATES_CLEAN = frozenset({"", "available"})
_IDENTITY_STATES_ADVISORY = frozenset({"stale"})
_IDENTITY_STATE_DEAD = "dead"


def _identity_material_replayable(material: dict, *, probe: bool = False) -> bool:
    """Honor the credential store's explicit replay and lifecycle controls.

    ``probe=True`` is the AUTH liveness-probe path (``auth status --probe``). It
    allows ANY flagged state, including ``dead``: probing is precisely how a
    flag gets re-tested, and ``db.set_liveness`` documents that a ``live``
    verdict "revives a session probed with --include-dead" — unreachable if the
    probe itself is refused. No other caller sets it, so a proven-dead or
    operator-flagged session is still never replayed by ordinary tooling.
    """
    if material.get("use_for_requests") is False:
        return False
    state = str(material.get("state") or "").strip().lower()
    if state in _IDENTITY_STATES_CLEAN or state in _IDENTITY_STATES_ADVISORY:
        return True
    return bool(probe)


def _identity_age_text(material: dict) -> str:
    """Human-readable ``last_seen_at`` + age, or ``"never recorded"``."""
    raw = str(material.get("last_seen_at") or "").strip()
    if not raw:
        return "last_seen_at never recorded"
    parsed: datetime | None = None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
            break
        except ValueError:
            continue
    if parsed is None:
        try:
            parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError:
            return f"last seen {raw}"
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
    age = (datetime.now(timezone.utc) - parsed).total_seconds()
    if age < 0:
        return f"last seen {raw}"
    hours, minutes = divmod(int(age) // 60, 60)
    return f"last seen {raw} ({hours}h{minutes:02d}m ago)"


def _identity_probe_recovery_command(identity_name: str) -> str:
    return (
        "vigil assess auth status --probe --identity "
        f"{identity_name or '<identity>'} --probe-url <an-authenticated-url>"
    )


def _warn_degraded_identity(material: dict) -> None:
    """Warn — but do not refuse — when replaying an advisory identity state."""
    state = str(material.get("state") or "").strip().lower()
    if state not in _IDENTITY_STATES_ADVISORY:
        return
    name = str(material.get("identity_name") or "").strip()
    detail = (
        "an age backstop, NOT a failed probe — nothing has observed this "
        "session failing"
    )
    print(
        f"warning: identity '{name or '(unnamed)'}' is in state '{state}' "
        f"({_identity_age_text(material)}); {detail}. Replaying it anyway — "
        "do NOT fall back to a hand-written `-H \"Cookie: ...\"` header, which "
        "records the run as auth_context=anonymous and destroys the "
        "cross-identity evidence the depth ledger credits. Confirm or refresh "
        f"it with: {_identity_probe_recovery_command(name)}",
        file=sys.stderr,
    )


def identity_refusal_detail(identity: str, material: dict) -> str:
    """Explain WHY a requested identity cannot be replayed, and how to recover.

    The old message named neither the state nor the age nor a recovery command,
    so an operator hitting it had no path forward except the anonymous-header
    workaround that corrupts the audit trail.
    """
    name = str(material.get("identity_name") or identity or "").strip()
    if material.get("use_for_requests") is False:
        return (
            "it is quarantined (use_for_requests=0), so the store forbids "
            "replaying it. Re-enable it by re-importing the session "
            "(`vigil auth import`), or pick another identity with "
            "`vigil assess auth list`"
        )
    state = str(material.get("state") or "").strip().lower()
    if state == _IDENTITY_STATE_DEAD:
        return (
            f"its stored state is 'dead' ({_identity_age_text(material)}) — a "
            "liveness probe PROVED this session dead, so it is never replayed. "
            "Re-authenticate and re-capture the session (proxy login, or "
            "`vigil auth import`), then verify with: "
            f"{_identity_probe_recovery_command(name)}"
        )
    if state not in _IDENTITY_STATES_CLEAN and state not in _IDENTITY_STATES_ADVISORY:
        return (
            f"the credential store holds it in state '{state}' "
            f"({_identity_age_text(material)}), which the injector will not "
            "replay — only the age-advisory 'stale' state is replayed with a "
            "warning. Re-test it (this clears the flag when the session is "
            f"still live) with: {_identity_probe_recovery_command(name)}"
        )
    return (
        f"the stored material carries nothing this tool can take (state="
        f"{state or 'unset'}, {_identity_age_text(material)}): no headers, no "
        "cookies for this request host, and no bearer token — or the tool "
        "accepts no injected headers. Check what the store actually holds with "
        "`vigil assess auth list`, then refresh it with "
        f"{_identity_probe_recovery_command(name)}"
    )


def prepare_browser_identity_material(
    engagement_dir: str | Path,
    identity_name: str | None,
    target_url: str,
    *,
    scope_key: str = "",
    external_state_applied: bool = False,
) -> tuple[str, dict[str, object]]:
    """Resolve one identity into Playwright-ready browser material.

    The returned auth context stays ``anonymous`` unless at least one header,
    cookie, or explicitly loaded storage-state artifact can actually be handed
    to the browser. Credential records never supply Playwright storage state.
    """
    empty: dict[str, object] = {
        "headers": {},
        "cookies": [],
        "storage_state": None,
    }
    if not identity_name:
        return "anonymous", empty
    resolved_name, material = (
        resolve_identity(engagement_dir, identity_name, scope_key=scope_key)
        if scope_key
        else resolve_identity(engagement_dir, identity_name)
    )
    if not isinstance(material, dict) or not material:
        empty["refusal_detail"] = (
            f"identity '{identity_name}' was not found in the credential store "
            "(check `vigil assess auth list`; `--include-dead` also shows "
            "probe-proven-dead sessions)"
        )
        return "anonymous", empty
    if not _identity_material_replayable(material):
        empty["refusal_detail"] = identity_refusal_detail(
            str(identity_name), material
        )
        return "anonymous", empty
    _warn_degraded_identity(material)
    try:
        host = (urlsplit(target_url).hostname or "").lower()
    except ValueError:
        host = ""
    headers = {
        str(name): str(value)
        for name, value in (material.get("headers") or {}).items()
        if str(name).strip()
    } if isinstance(material.get("headers"), dict) else {}
    token = _identity_bearer_token(material)
    if token and not any(name.lower() == "authorization" for name in headers):
        headers["Authorization"] = f"Bearer {token}"
    cookies = browser_cookies_for(material, host)
    if not cookies and not host_cookie_hosts(material):
        raw_cookies = material.get("cookies")
        if isinstance(raw_cookies, dict):
            cookies = [
                {
                    "name": str(name),
                    "value": str(value),
                    "domain": host,
                    "path": "/",
                }
                for name, value in raw_cookies.items()
                if host
            ]
    prepared: dict[str, object] = {
        "headers": headers,
        "cookies": cookies,
        "storage_state": None,
    }
    applied = bool(headers or cookies or external_state_applied)
    if applied:
        return (resolved_name or identity_name, prepared)
    prepared["refusal_detail"] = identity_refusal_detail(
        str(resolved_name or identity_name), material
    )
    return ("anonymous", prepared)


def _apply_identity_material(
    cmd: list[str], tool_name: str, material: dict, *, probe: bool = False
) -> bool:
    """Inject a named identity's auth headers/cookies into an HTTP command argv so
    the request actually runs AS that identity.

    Returns True when the credentials were applied (the caller may then relabel
    auth_context to the identity); False when there is nothing to apply or the
    tool can't take injected headers. A False return MUST prevent relabeling, so
    a run that did not actually carry the identity's credentials is never counted
    as a distinct identity by the depth ledger's cross-identity rule.

    ``probe=True`` marks the AUTH liveness-probe path, which may also replay a
    ``dead`` identity (that is how a dead verdict gets re-tested).
    """
    if not isinstance(material, dict):
        return False
    if not _identity_material_replayable(material, probe=probe):
        return False
    _warn_degraded_identity(material)
    request_host = kali_resolve.target_host_port(tool_name, cmd)[0]
    state_changing = _request_is_state_changing(cmd)
    pairs = _identity_header_pairs(
        material, request_host=request_host, state_changing=state_changing
    )
    # WARN when the identity carries captured host_cookies that did NOT make it
    # into this request — a request to a host with no matching bucket (or a
    # list-mode run with no single request host) — so a cookie-session app isn't
    # silently probed without its session and read as "session stale" (I-22).
    # Emitted BEFORE the empty-``pairs`` short-circuit: when the identity's only
    # material is per-host cookies and none match this host, we now correctly omit
    # the cross-host flat-union fallback, which can leave ``pairs`` empty — but the
    # operator still needs to know the session did not ride this run.
    bucket_hosts = host_cookie_hosts(material)
    if bucket_hosts and not host_cookies_for(material, request_host):
        print(
            "warning: identity carries captured host_cookies for "
            f"{', '.join(sorted(set(bucket_hosts)))} but none match this run's "
            f"request host '{request_host or '(none / list-mode)'}' — the request "
            "runs without that host session and a cookie-session app may read it "
            "as stale; target a single host this identity has a session for.",
            file=sys.stderr,
        )
    if not pairs:
        return False
    return _apply_identity_headers(cmd, tool_name, dict(pairs)) == "injected"


def _nuclei_stages_disable_callbacks(cmd: list[str], *, depth: int = 0) -> bool:
    if depth > 16:
        return False
    effective = scope_lib._unwrap_launcher_argv(cmd)
    executable = Path(str(effective[0])).name.lower() if effective else ""
    if executable == "nuclei":
        flags = {
            str(token).split("=", 1)[0].lstrip("-") for token in effective[1:]
        }
        return bool({"ni", "no-interactsh"} & flags)
    if executable not in scope_lib._SHELL_BINARIES:
        return "nuclei" not in scope_lib.execution_tools(effective)
    found = False
    for index, option in enumerate(effective[:-1]):
        if not (option.startswith("-") and option.endswith("c")):
            continue
        segments, ambiguous = scope_lib._shell_command_segments(effective[index + 1])
        if ambiguous:
            return False
        for segment in segments:
            if "nuclei" not in scope_lib.execution_tools(segment):
                continue
            found = True
            if not _nuclei_stages_disable_callbacks(segment, depth=depth + 1):
                return False
    return found


def _apply_nuclei_oob_safety(cmd: list[str], *, explicit_oob: bool = False) -> None:
    """Disable nuclei callbacks for raw sync/job commands before audit or spawn."""
    tools = scope_lib.execution_tools(cmd)
    if "nuclei" not in tools:
        return
    if explicit_oob:
        return
    joined = " ".join(str(token) for token in cmd)
    override_pattern = re.compile(
        r"(?<!\S)--?(?:interactsh-url|interactsh-server|iserver)(?==|\s|$)"
    )
    if override_pattern.search(joined):
        raise scope_lib.ScopePolicyError(
            "raw nuclei interactsh configuration is not allowed; use the typed "
            "nuclei wrapper with --oob-mode none|public|vigil"
        )
    effective = scope_lib._unwrap_launcher_argv(cmd)
    executable = Path(str(effective[0])).name.lower() if effective else ""
    if executable == "nuclei":
        normalized_flags = {
            str(token).split("=", 1)[0].lstrip("-") for token in effective[1:]
        }
        if not {"ni", "no-interactsh"} & normalized_flags:
            cmd.append("-ni")
        return
    if not _nuclei_stages_disable_callbacks(cmd):
        raise scope_lib.ScopePolicyError(
            "raw shell-wrapped nuclei must disable callbacks with -ni; use the typed "
            "nuclei wrapper for public or Vigil OOB"
        )


def prepare_execution_command(
    cmd: list[str],
    *,
    tool_name: str,
    engagement_dir: Path,
    identity: str | None = None,
    identity_scope: str = "",
    nuclei_oob_explicit: bool = False,
    prepared_auth_context: str | None = None,
    identity_probe: bool = False,
) -> str:
    """Apply shared identity, attribution, and OOB preparation for sync/jobs.

    Returns the audit ``auth_context``. Program-required attribution headers are
    injected when the tool supports them; an unsupported shape emits a warning
    and still runs.

    ``identity_probe=True`` is reserved for the AUTH liveness probe
    (``auth status --probe``): it may replay a ``dead`` identity, because a
    probe is how a dead verdict gets re-tested.
    """
    _apply_nuclei_oob_safety(cmd, explicit_oob=nuclei_oob_explicit)
    prepared = str(prepared_auth_context or "").strip()
    auth_context = prepared if prepared and prepared != "anonymous" else "anonymous"
    required = _required_headers(engagement_dir)
    if required:
        status = _apply_required_headers(cmd, tool_name, required)
        if status == "warned":
            header_names = ", ".join(sorted(required))
            print(
                "warning: program-required attribution headers could not be "
                f"injected into tool '{tool_name}' ({header_names}); continuing.",
                file=sys.stderr,
            )
    if identity is not None:
        identity_name, material = (
            resolve_identity(engagement_dir, identity, scope_key=identity_scope)
            if identity_scope
            else resolve_identity(engagement_dir, identity)
        )
        if not material:
            raise scope_lib.ScopePolicyError(
                f"requested identity '{identity}' was not found in the credential "
                f"store, so tool '{tool_name}' has nothing to inject; refusing to "
                "run anonymously. List what IS stored with `vigil assess auth "
                "list` (add --include-dead to see probe-proven-dead sessions)."
            )
        elif _apply_identity_material(cmd, tool_name, material, probe=identity_probe):
            auth_context = identity_name or auth_context
        else:
            # Say WHY: state + age + the exact recovery command. A bare
            # "could not be applied" pushed operators onto the anonymous
            # `-H "Cookie: ..."` workaround, which mislabels the audit row.
            raise scope_lib.ScopePolicyError(
                f"requested identity '{identity}' could not be applied to tool "
                f"'{tool_name}'; refusing to run anonymously because "
                f"{identity_refusal_detail(str(identity), material)}."
            )

    return auth_context


# Program-mandated attribution-header classifier + injector
# (``_REQUIRED_HEADER_INJECTABLE`` / ``_REQUIRED_HEADER_SKIP`` /
# ``_apply_required_headers`` / ``_existing_header_names``) now live in
# ``kali_output`` and are imported above, so BOTH this container path
# (``kali_exec``) and the audited host path (the recon host-dispatch wrappers in
# commands/web_discovery.py / dns_discovery.py) apply the SAME rules. The names
# are re-exported from this module for back-compat with existing importers.


def _audit_execution_policy_refusal(
    *,
    cfg: Config,
    eng_key: str,
    eng_dir: Path,
    cmd: list[str],
    tool_name: str,
    technique: str,
    intent: str,
    probe_kind: str,
    phase: str,
    destructive: bool,
    agent_name: str,
    timeout: int,
    run_uuid: str,
    stdout_path: Path,
    stderr_path: Path,
    started_at_iso: str,
    scope_version: str,
    auth_context: str,
    reason: str,
) -> None:
    """Best-effort durable evidence for a policy-denied, never-started run."""
    policy = {"policy_refusal": reason}
    client = AssessmentClient(cfg.base_url, eng_key)
    try:
        row = _post_pre_exec_row(
            client,
            cmd=cmd,
            technique=technique,
            intent=intent,
            probe_kind=probe_kind,
            phase=phase,
            destructive=destructive,
            agent_name=agent_name,
            engagement_dir=eng_dir,
            container_name="",
            timeout=timeout,
            force=False,
            started_at_iso=started_at_iso,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            working_dir=f"/engagements/{eng_key}",
            scope_version=scope_version,
            auth_context=auth_context,
            tool_name=tool_name,
            run_uuid=run_uuid,
            execution_policy=policy,
        )
        run_id = row.get("id")
        if run_id is not None:
            _patch_finalize(
                client,
                run_id=int(run_id),
                status="failed",
                return_code=None,
                ended_at_iso=_utcnow_iso(),
                duration_ms=0,
                stdout_preview="",
                stderr_preview=reason,
                timed_out=False,
                partial_results=False,
                peak_rss_bytes=None,
                cpu_user_seconds=None,
                cpu_system_seconds=None,
            )
    except Exception as exc:  # noqa: BLE001 - refusal still blocks if audit is unavailable
        print(f"warning: could not audit execution-policy refusal: {exc}", file=sys.stderr)
        _write_failed_audit_marker(eng_dir, run_uuid=run_uuid, error=str(exc))
    finally:
        client.close()


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
    force: bool = False,
    container_name: str | None = None,
    config: Config | None = None,
    tool_name: str | None = None,
    identity: str | None = None,
    identity_scope: str = "",
    identity_probe: bool = False,
    rate_override_reason: str = "",
    nuclei_oob_explicit: bool = False,
    prepared_auth_context: str | None = None,
) -> KaliResult:
    """Run `cmd` inside the runtime container with full audit recording.

    The pre-exec audit row is written before docker-exec starts so a crash
    leaves a `running` row that can be reaped by orphan-sweep tooling.
    Stdout/stderr stream to disk from line 1 — never buffered in memory.
    """
    # Resolve the container name at call time (not import time) so a
    # VIGIL_RUNTIME_CONTAINER set after this module was imported — or by a test
    # via monkeypatch.setenv — is honoured. Default stays "vigil" when unset.
    container_name = container_name or default_runtime_container()
    # When the caller passes engagement_dir explicitly (typically via
    # --engagement-dir hoisted by assess.cli), forward it to load_config so
    # config resolution doesn't fall back to env/cwd and erroneously
    # SystemExit with "Cannot resolve engagement directory."
    cfg = config or load_config(str(engagement_dir) if engagement_dir else None)
    eng_dir = _resolve_engagement_dir(engagement_dir, cfg)
    eng_key = eng_dir.name
    resolved_agent = _resolve_agent_name(agent_name)
    technique = normalize_technique(technique)
    probe_kind = normalize_probe_kind(probe_kind)
    if phase:
        phase = phase.strip().lower()
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

    started_at_iso = _utcnow_iso()
    started_monotonic = time.monotonic()
    scope_version = _scope_version(eng_dir)
    auth_context = "anonymous"

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
            resolved_argv=list(cmd),
        )

    derived_tool_name = tool_name or _derive_tool_name(cmd)
    try:
        auth_context = prepare_execution_command(
            cmd,
            tool_name=derived_tool_name,
            engagement_dir=eng_dir,
            identity=identity,
            identity_scope=identity_scope,
            nuclei_oob_explicit=nuclei_oob_explicit,
            prepared_auth_context=prepared_auth_context,
            identity_probe=identity_probe,
        )
        execution_policy = scope_lib.enforce_execution_policy(
            cmd,
            tool_name=derived_tool_name,
            engagement_dir=eng_dir,
        )
    except scope_lib.ScopePolicyError as exc:
        _audit_execution_policy_refusal(
            cfg=cfg,
            eng_key=eng_key,
            eng_dir=eng_dir,
            cmd=cmd,
            tool_name=derived_tool_name,
            technique=technique,
            intent=intent,
            probe_kind=probe_kind,
            phase=phase,
            destructive=destructive,
            agent_name=resolved_agent,
            timeout=timeout,
            run_uuid=run_uuid,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            started_at_iso=started_at_iso,
            scope_version=scope_version,
            auth_context=auth_context,
            reason=str(exc),
        )
        raise AssessError(str(exc)) from exc

    _check_container_running(container_name)

    # CR-36 — host-resolve + --resolve IP-pin. On macOS Docker Desktop the
    # container resolver flaps (I-013), so a container HTTP probe can return
    # http=000 for a name that resolves fine on the host. Pin the host-resolved
    # IP into the argv (curl ONLY — httpx/nuclei/katana/ffuf reject the
    # curl-style --resolve flag and abort; see kali_resolve.RESOLVE_PIN_TOOLS) so
    # target HTTP never depends on the broken container resolver. Transparent
    # no-op off Docker Desktop and when the operator opts out
    # (VIGIL_NO_RESOLVE_PIN) — pinning is idempotent (skipped if a --resolve for
    # this host is already present).
    pinned_ip: str | None = None
    pin_host, pin_port = kali_resolve.target_host_port(derived_tool_name, cmd)
    _pin_eligible = (
        kali_resolve.is_pin_eligible_runtime()
        and not kali_resolve.pinning_disabled()
    )
    if pin_host and pin_port and _pin_eligible:
        _pin_ips = kali_resolve.resolve_host_ips(pin_host)
        pinned_ip = kali_resolve.apply_resolve_pin(
            cmd, derived_tool_name, ips=_pin_ips
        )
        if pinned_ip is not None:
            kali_resolve.warn_resolved_pin(
                pin_host, pin_port, pinned_ip, all_ips=_pin_ips
            )

    container_working_dir = f"/engagements/{eng_key}"
    docker_argv = _build_docker_exec(
        cmd,
        container_name=container_name,
        run_uuid=run_uuid,
        working_dir=container_working_dir,
        engagement_key=eng_key,
    )

    client = AssessmentClient(cfg.base_url, eng_key)
    run_id: int | None = None
    superseded_by_id: int | None = None
    audit_failed = False
    rate_lease_cm = None
    rate_lease_entered = False
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
                working_dir=container_working_dir,
                scope_version=scope_version,
                auth_context=auth_context,
                tool_name=derived_tool_name,
                run_uuid=run_uuid,
                execution_policy=execution_policy,
            )
            run_id = int(row.get("id")) if row.get("id") is not None else None
            superseded_by_id = row.get("superseded_by_id")
            if superseded_by_id and not force:
                # Warn-and-continue: parallel specialists racing on the same
                # wildcard list inside the dedup window should not be hard-
                # blocked. The backend has already inserted a fresh row and
                # linked it to the predecessor via ``superseded_by_id``; the
                # finalize PATCH below targets that NEW row's id.
                # ``--force`` suppresses the warning entirely (and also tells
                # the backend to skip the supersede link).
                print(
                    f"warning: dedup hit — equivalent command-run id={superseded_by_id} "
                    f"is still in flight.",
                    file=sys.stderr,
                )
        except AssessError as exc:
            print(
                f"warning: pre-exec audit POST failed: {exc}; refusing target execution.",
                file=sys.stderr,
            )
            _write_failed_audit_marker(eng_dir, run_uuid=run_uuid, error=str(exc))
            raise AssessError(
                "required pre-exec audit record was not created; refusing execution"
            ) from exc

        reservation = aggregate_rate_reservation(
            str(eng_dir), cmd, derived_tool_name, execution_policy
        )
        if reservation is not None:
            rate_lease_cm = target_rate_lease(
                config=cfg,
                owner=f"kali:{resolved_agent}:{run_uuid}",
                effective_rate_rps=reservation,
                ttl_seconds=max(int(timeout) + 60, 60),
                override_reason=rate_override_reason,
                command_run_id=run_id,
            )
            try:
                rate_lease_cm.__enter__()
                rate_lease_entered = True
            except Exception as exc:
                if run_id is not None and not audit_failed:
                    try:
                        _patch_finalize(
                            client,
                            run_id=run_id,
                            status="failed",
                            return_code=None,
                            ended_at_iso=_utcnow_iso(),
                            duration_ms=0,
                            stdout_preview="",
                            stderr_preview=f"aggregate rate lease refused: {exc}",
                            timed_out=False,
                            partial_results=False,
                            peak_rss_bytes=None,
                            cpu_user_seconds=None,
                            cpu_system_seconds=None,
                        )
                    except Exception:
                        pass
                raise AssessError(f"aggregate rate lease refused: {exc}") from exc

        # One docker-exec attempt + full telemetry snapshot. Factored into a
        # nested closure so the CR-36 false-negative guard can run it a SECOND
        # time (a single host-resolved pinned-IP retry) without duplicating the
        # kill-cascade / rusage / preview logic. Each attempt streams to its own
        # {run_uuid}[.retry1].{out,err} so both attempts' bytes survive on disk;
        # the returned ``out_path``/``err_path`` point at THIS attempt's files.
        def _execute_and_snapshot(
            *, attempt_uuid: str, out_path: Path, err_path: Path
        ) -> SimpleNamespace:
            # Open output files BEFORE Popen so streaming starts at line 1.
            with out_path.open("wb") as out_fh, err_path.open("wb") as err_fh:
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
                    # ``docker`` binary missing on PATH. The pre-exec POST already
                    # wrote a status=running audit row; without this finalize the
                    # row stays "running" forever and confuses sweep-orphans +
                    # operator audit. PATCH it to failed before raising so the row
                    # reflects what actually happened.
                    if run_id is not None and not audit_failed:
                        try:
                            _patch_finalize(
                                client,
                                run_id=run_id,
                                status="failed",
                                return_code=None,
                                ended_at_iso=_utcnow_iso(),
                                duration_ms=0,
                                stdout_preview="",
                                stderr_preview=f"docker not found: {exc}",
                                timed_out=False,
                                partial_results=False,
                                peak_rss_bytes=None,
                                cpu_user_seconds=None,
                                cpu_system_seconds=None,
                            )
                        except AssessError as patch_exc:
                            # Belt-and-braces: if the PATCH also fails, drop a
                            # failed-audit marker so sweep-orphans can pick it up.
                            _write_failed_audit_marker(
                                eng_dir,
                                run_uuid=run_uuid,
                                error=(
                                    f"docker not found AND finalize PATCH failed: "
                                    f"{patch_exc}"
                                ),
                            )
                    raise AssessError(f"docker not found: {exc}") from exc
                a_timed_out = False
                a_partial = False
                a_return_code: int | None = None
                try:
                    a_return_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    a_timed_out = True
                    # Two-namespace kill cascade. ``os.killpg`` only signals the
                    # host-side ``docker exec`` client and any siblings in our
                    # process group — it cannot reach the user command running
                    # inside the container's PID namespace under ``dockerd+tini``,
                    # and dockerd's signal forwarding is best-effort. SIGTERM-
                    # trapping tools (sqlmap, nuclei) survive that path. The
                    # wrapper shell records the in-container PID to a pid file so
                    # we can also send ``docker exec kill`` directly at the user
                    # command across the namespace boundary.
                    container_pid = _read_container_pid(container_name, attempt_uuid)
                    if container_pid is not None:
                        _kill_in_container(container_name, container_pid, "TERM")
                    else:
                        # If the exact PID is unavailable, avoid argv-pattern
                        # cleanup. `pkill -f` can match sibling agent runs inside
                        # the shared runtime container; host-side kill plus
                        # sweep-orphans is safer than a broad in-container signal.
                        print(
                            f"warning: in-container pid file missing for run {attempt_uuid}; "
                            "using host process-group cleanup only.",
                            file=sys.stderr,
                        )
                    try:
                        pgid = os.getpgid(process.pid)
                        os.killpg(pgid, signal.SIGTERM)
                    except (ProcessLookupError, PermissionError):
                        pass
                    try:
                        a_return_code = process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        if container_pid is not None:
                            _kill_in_container(container_name, container_pid, "KILL")
                        try:
                            pgid = os.getpgid(process.pid)
                            os.killpg(pgid, signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            pass
                        try:
                            a_return_code = process.wait(timeout=2)
                        except subprocess.TimeoutExpired:
                            a_return_code = None
                    _cleanup_container_pid_file(container_name, attempt_uuid)

            # Clean up the pid file on the happy path too so /tmp doesn't grow
            # unboundedly.
            if not a_timed_out:
                _cleanup_container_pid_file(container_name, attempt_uuid)

            # Resource snapshot. getrusage(RUSAGE_CHILDREN) accumulates across
            # all waited-for children; for a single-shot CLI call the values are
            # accurate. _read_proc_peak_rss overrides if available (more precise).
            try:
                usage = resource.getrusage(resource.RUSAGE_CHILDREN)
                a_cpu_user = float(usage.ru_utime)
                a_cpu_system = float(usage.ru_stime)
                a_peak_rss: int | None = _peak_rss_kilobytes_to_bytes(int(usage.ru_maxrss))
            except OSError:
                a_cpu_user = None
                a_cpu_system = None
                a_peak_rss = None

            proc_peak = _read_proc_peak_rss(process.pid)
            if proc_peak is not None:
                a_peak_rss = proc_peak

            a_stdout_preview = _read_safely(out_path)
            a_stderr_preview = _read_safely(err_path)

            if a_timed_out and (a_stdout_preview or a_stderr_preview):
                a_partial = True

            return SimpleNamespace(
                return_code=a_return_code,
                timed_out=a_timed_out,
                partial_results=a_partial,
                cpu_user_seconds=a_cpu_user,
                cpu_system_seconds=a_cpu_system,
                peak_rss_bytes=a_peak_rss,
                stdout_preview=a_stdout_preview,
                stderr_preview=a_stderr_preview,
                stdout_path=out_path,
                stderr_path=err_path,
            )

        snap = _execute_and_snapshot(
            attempt_uuid=run_uuid, out_path=stdout_path, err_path=stderr_path
        )

        # CR-36 — HARD false-negative guard. A container HTTP probe that ends in
        # the http=000 / connection-failed / DNS-resolution-failure signature
        # produced NO real HTTP answer, so its terminal status MUST NOT be read
        # as a target verdict (404/patched/gated). On Docker Desktop this is most
        # often the I-013 container-resolver flap, so we auto-retry ONCE with a
        # host-resolved pinned IP before letting the result stand. On native
        # Linux / remote Docker the container resolver is the real resolver and a
        # clean connection-refused IS a legitimate verdict — so the guard only
        # arms on Docker Desktop (no over-flagging elsewhere).
        transport_error = False
        transport_error_detail = ""
        if is_http_prober(derived_tool_name) and kali_resolve.is_pin_eligible_runtime():
            is_te, te_detail = detect_transport_error(
                tool_name=derived_tool_name,
                return_code=snap.return_code,
                stdout_preview=snap.stdout_preview,
                stderr_preview=snap.stderr_preview,
                timed_out=snap.timed_out,
            )
            if is_te:
                # Already pinned on the pre-flight pass and STILL http=000 → a real
                # transport failure, not a resolver flap. Don't retry (it would
                # just fail again); keep the run flagged as a transport error.
                can_retry = not kali_resolve.pinning_disabled() and pinned_ip is None
                print(
                    "RUNTIME ERROR: http=000/connection-failed — this is NOT a "
                    "target verdict; "
                    + (
                        "retrying with host-resolved pinned IP."
                        if can_retry
                        else "already host-pinned, not retrying."
                    ),
                    file=sys.stderr,
                )
                if can_retry:
                    retry_ips = kali_resolve.resolve_host_ips(pin_host) if pin_host else []
                    new_pin = kali_resolve.apply_resolve_pin(
                        cmd, derived_tool_name, ips=retry_ips
                    )
                    if new_pin is not None:
                        pinned_ip = new_pin
                        kali_resolve.warn_resolved_pin(
                            pin_host, pin_port, new_pin, all_ips=retry_ips
                        )
                        # Rebuild docker_argv so it carries the freshly injected
                        # --resolve, then re-run into retry-suffixed files.
                        docker_argv = _build_docker_exec(
                            cmd,
                            container_name=container_name,
                            run_uuid=run_uuid,
                            working_dir=container_working_dir,
                            engagement_key=eng_key,
                        )
                        retry_out = out_dir / f"{run_uuid}.retry1.out"
                        retry_err = out_dir / f"{run_uuid}.retry1.err"
                        snap = _execute_and_snapshot(
                            attempt_uuid=run_uuid, out_path=retry_out, err_path=retry_err
                        )
                        is_te, te_detail = detect_transport_error(
                            tool_name=derived_tool_name,
                            return_code=snap.return_code,
                            stdout_preview=snap.stdout_preview,
                            stderr_preview=snap.stderr_preview,
                            timed_out=snap.timed_out,
                        )
                    else:
                        # apply_resolve_pin() returned None for one of two distinct
                        # reasons; name the real one so the operator isn't told
                        # "resolution failed" when the tool simply takes no --resolve
                        # pin (e.g. wafw00f/nikto are http probers but NOT in
                        # RESOLVE_PIN_TOOLS). Message-only — control flow unchanged.
                        if (
                            kali_resolve._exe_name(cmd)
                            not in kali_resolve.RESOLVE_PIN_TOOLS
                        ):
                            print(
                                f"RUNTIME ERROR: {derived_tool_name} takes no --resolve "
                                "pin (not in the pinnable tool set), so the http=000 result "
                                "cannot be retried with a host-resolved IP — leaving run "
                                "flagged as a transport error (NOT a target verdict). Re-run "
                                "via the host path / verify reachability before any negative "
                                "disposition.",
                                file=sys.stderr,
                            )
                        else:
                            print(
                                "RUNTIME ERROR: host resolution returned no address for "
                                f"{pin_host or 'target'}; cannot pin — leaving run flagged "
                                "as a transport error (NOT a target verdict).",
                                file=sys.stderr,
                            )
                # After any retry, a still-true is_te means a real transport error.
                if is_te:
                    transport_error = True
                    transport_error_detail = te_detail
                    print(
                        "RUNTIME ERROR: http=000/connection-failed persisted after "
                        "the host-resolved retry — recording this run as a TRANSPORT "
                        "ERROR, not a target verdict (404/patched/gated). Re-run "
                        "via the host path / verify reachability before any negative "
                        "disposition.",
                        file=sys.stderr,
                    )

        # W1 — WAF / bot-challenge guard. A real HTTP exchange (rc usually 0,
        # status 200/403) can come back with the WAF's interstitial/bot-challenge
        # body instead of the origin app's response (Cloudflare "Just a moment",
        # Akamai "Access Denied", Imperva "Pardon Our Interruption", or a renamed
        # marker whose SHAPE is a JS-only shell behind a CDN/edge). That body is
        # NOT a target verdict (404/patched/gated). Surfaced exactly like the
        # http=000 guard: out-of-band on the KaliResult + a loud stderr line +
        # an agent-facing status='waf_challenge'. Runs for every HTTP prober
        # regardless of runtime (a WAF challenge is not Docker-Desktop-specific),
        # but never on a transport error (no real body to inspect) and never on
        # non-HTTP-prober tools — in particular NOT on the ``browser`` recovery
        # verb, so re-rendering a flagged surface can never self-flag into a loop.
        waf_challenge = False
        waf_challenge_detail = ""
        if is_http_prober(derived_tool_name) and not transport_error:
            # Thread the REAL response headers when the probe surfaced them
            # (httpx -json carries them in its stdout JSON; curl -i/-D prepends a
            # header block) so header-only vendor markers (Akamai _abck /
            # AkamaiGHost, Imperva x-iinfo) and the status-shape heuristic are not
            # blind. A bare ``curl -sS`` probe emits no headers, so this is None
            # and the body-only fail-safe stands.
            probe_headers = extract_probe_response_headers(
                derived_tool_name, cmd, snap.stdout_preview
            )
            is_waf, waf_detail = detect_waf_challenge(
                snap.stdout_preview, snap.stderr_preview, probe_headers
            )
            if is_waf:
                waf_challenge = True
                waf_challenge_detail = waf_detail
                print(
                    "RUNTIME ERROR: WAF/bot-challenge interstitial detected "
                    f"({waf_detail}) — this is NOT a target verdict (the body is "
                    "the WAF's, not the origin app's). Re-render with `vigil assess "
                    "kali browser <url>` (headless chromium clears the JS challenge) "
                    "before any negative disposition.",
                    file=sys.stderr,
                )

        # Bind the (possibly retried) attempt's telemetry into the names the
        # finalize/return path below already uses.
        return_code = snap.return_code
        timed_out = snap.timed_out
        partial_results = snap.partial_results
        cpu_user_seconds = snap.cpu_user_seconds
        cpu_system_seconds = snap.cpu_system_seconds
        peak_rss_bytes = snap.peak_rss_bytes
        stdout_preview = snap.stdout_preview
        stderr_preview = snap.stderr_preview
        final_stdout_path = snap.stdout_path
        final_stderr_path = snap.stderr_path

        ended_at_iso = _utcnow_iso()
        duration_ms = int((time.monotonic() - started_monotonic) * 1000)

        if return_code is None:
            terminal_status = "killed"
        elif timed_out:
            terminal_status = "timed_out"
        elif return_code != 0:
            terminal_status = "failed"
        else:
            terminal_status = "completed"

        # The backend command-run status enum is {completed,failed,timed_out,
        # killed,lost,running} — it has NO 'transport_error' / 'waf_challenge'
        # member, so backend_status keeps the real terminal value (a WAF
        # challenge is a completed exchange; a connection failure already exits
        # non-zero, and 'failed' never counts as 'tested'/covered in the depth
        # ledger). The CR-36 / W1 distinctions are carried OUT-of-band on the
        # KaliResult flags + the loud stderr lines. The agent-facing
        # KaliResult.status is overridden so it can never be confused with a real
        # terminal verdict.
        backend_status = terminal_status
        if transport_error and backend_status == "failed":
            terminal_status = "transport_error"
        elif waf_challenge and backend_status in ("completed", "failed"):
            terminal_status = "waf_challenge"

        if run_id is not None and not audit_failed:
            try:
                _patch_finalize(
                    client,
                    run_id=run_id,
                    status=backend_status,
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
                )
                finalize_ok = True
            except AssessError as exc:
                # 409 races are now handled inside _patch_finalize; reaching
                # this branch means a real failure (network, 4xx other than
                # 409, 5xx exhaustion) and the row may genuinely need sweep.
                finalize_ok = False
                print(
                    f"warning: finalize PATCH failed: {exc}; row stays running and may need orphan sweep.",
                    file=sys.stderr,
                )

            if finalize_ok:
                # Point evidence at the FINAL attempt's stdout (the retry file
                # when the http=000 guard re-ran) so the probe-run references the
                # bytes the verdict was actually derived from.
                evidence_ref = (
                    f"{container_working_dir}/scans/kali/{final_stdout_path.name}"
                )
                _emit_probe_run(
                    client,
                    engagement_type=_engagement_type(eng_dir),
                    technique=technique,
                    probe_kind=probe_kind,
                    auth_context=auth_context,
                    tool_name=derived_tool_name,
                    agent_name=resolved_agent,
                    return_code=return_code,
                    timed_out=timed_out,
                    cmd=cmd,
                    evidence_ref=evidence_ref,
                )

        return KaliResult(
            run_id=run_id,
            status=terminal_status,
            return_code=return_code,
            stdout_path=str(final_stdout_path),
            stderr_path=str(final_stderr_path),
            duration_ms=duration_ms,
            peak_rss_bytes=peak_rss_bytes,
            stdout_preview=stdout_preview,
            stderr_preview=stderr_preview,
            timed_out=timed_out,
            partial_results=partial_results,
            transport_error=transport_error,
            transport_error_detail=transport_error_detail,
            waf_challenge=waf_challenge,
            waf_challenge_detail=waf_challenge_detail,
            # ``cmd`` has been mutated in place by the identity / required-header /
            # --resolve-pin injectors above, so it is the ACTUAL argv that ran.
            resolved_argv=list(cmd),
        )
    finally:
        if rate_lease_cm is not None and rate_lease_entered:
            rate_lease_cm.__exit__(None, None, None)
        client.close()


# Re-exports for callers and test mocks. These names live in this module's
# globals so:
#   1. ``from assess.lib.kali import <name>`` keeps resolving for command
#      files (kali_job.py, kali_alterx.py, etc.) that import from here.
#   2. ``monkeypatch.setattr(kali, "_check_container_running", stub)``
#      replaces the name the orchestrator code calls, since command code
#      looks up these helpers via the module globals (the imported names).
__all__ = [
    # Audit + validation (from kali_audit)
    "ALLOWED_PHASES",
    "_INTENT_MAX_LEN",
    "_extract_target_host",
    "_post_pre_exec_row",
    "_patch_finalize",
    "_resolve_agent_name",
    "_resolve_engagement_dir",
    "_validate_inputs",
    "_write_failed_audit_marker",
    # CLI scaffolding (from kali_cli)
    "ScopedErrorParser",
    "add_required_kali_flags",
    "add_passthrough_args_flag",
    "extend_cmd_with_extra_args",
    "kali_args_to_kwargs",
    "emit_result",
    "resolve_crawl_rate_limit",
    "CRAWL_RATE_DEFAULT",
    "CRAWL_RATE_HARD_CAP",
    "count_list_targets",
    "parse_list_progress",
    "incomplete_list_run_warning",
    "safe_engagement_dir",
    # Output + RSS (from kali_output)
    "KaliResult",
    "_REQUIRED_HEADER_INJECTABLE",
    "_REQUIRED_HEADER_SKIP",
    "_apply_required_headers",
    "_auth_context",
    "_engagement_type",
    "_existing_header_names",
    "_peak_rss_kilobytes_to_bytes",
    "_read_proc_peak_rss",
    "_read_safely",
    "_required_headers",
    "_scope_version",
    "_utcnow_iso",
    "detect_transport_error",
    "detect_waf_challenge",
    "extract_probe_response_headers",
    "is_http_prober",
    # Runtime exec + kill cascade (from kali_runtime_exec)
    "_build_docker_exec",
    "_check_container_running",
    "_cleanup_container_pid_file",
    "_container_pid_file",
    "_kill_in_container",
    "_read_container_pid",
    # Tool-name derivation (from kali_tool_naming)
    "_SHELL_BINARIES",
    "_SHELL_KEYWORDS",
    "_analyze_tool_name",
    "_derive_tool_name",
    "_is_plausible_executable",
    "_scan_inner_for_first_exec",
    "_split_inner_pipeline_stages",
    # Re-export AssessmentClient + audit enums for tests that patch them
    "AssessmentClient",
    "default_runtime_container",
    "PROBE_KIND_ENUM",
    "TECHNIQUE_ENUM",
    "_emit_probe_run",
    "target_rate_lease",
    # Public surface
    "kali_exec",
]
