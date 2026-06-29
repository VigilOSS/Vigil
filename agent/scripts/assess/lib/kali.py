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
import resource
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace

from . import vuln_taxonomy
from .client import AssessError, AssessmentClient, default_runtime_container
from .config import Config, load_config
from .identity import resolve_identity

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
from .kali_audit import (
    ALLOWED_PHASES,
    _INTENT_MAX_LEN,
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
    ScopedErrorParser,
    add_passthrough_args_flag,
    add_required_kali_flags,
    emit_result,
    extend_cmd_with_extra_args,
    kali_args_to_kwargs,
)
from .kali_output import (
    _REQUIRED_HEADER_INJECTABLE,
    _REQUIRED_HEADER_SKIP,
    KaliResult,
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
from . import kali_resolve
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
    """Best-effort auto-emit one probe_run from a finished kali run (Wave 5 / 2a).

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


_IDENTITY_INJECTABLE_TOOLS = frozenset({"curl", "httpx", "nuclei", "ffuf", "sqlmap", "katana"})


def _identity_header_pairs(material: dict) -> list[tuple[str, str]]:
    """Flatten an identity's auth material into ``(header, value)`` pairs.

    Supports a ``headers`` map, a ``cookies`` map (joined into one ``Cookie``
    header), and an optional bearer ``token``. Order is deterministic.
    """
    pairs: list[tuple[str, str]] = []
    headers = material.get("headers")
    if isinstance(headers, dict):
        for key, value in headers.items():
            if str(key).strip():
                pairs.append((str(key), str(value)))
    cookies = material.get("cookies")
    if isinstance(cookies, dict) and cookies:
        cookie = "; ".join(f"{k}={v}" for k, v in cookies.items())
        pairs.append(("Cookie", cookie))
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


def _apply_identity_material(cmd: list[str], tool_name: str, material: dict) -> bool:
    """Inject a named identity's auth headers/cookies into an HTTP command argv so
    the request actually runs AS that identity.

    Returns True when the credentials were applied (the caller may then relabel
    auth_context to the identity); False when there is nothing to apply or the
    tool can't take injected headers. A False return MUST prevent relabeling, so
    a run that did not actually carry the identity's credentials is never counted
    as a distinct identity by the depth ledger's cross-identity rule.
    """
    if not isinstance(material, dict):
        return False
    pairs = _identity_header_pairs(material)
    if not pairs:
        return False
    exe = os.path.basename(str(cmd[0])).lower() if cmd else ""
    if exe not in _IDENTITY_INJECTABLE_TOOLS:
        return False
    for name, value in pairs:
        cmd.extend(["-H", f"{name}: {value}"])
    return True


# Program-mandated attribution-header classifier + injector
# (``_REQUIRED_HEADER_INJECTABLE`` / ``_REQUIRED_HEADER_SKIP`` /
# ``_apply_required_headers`` / ``_existing_header_names``) now live in
# ``kali_output`` and are imported above, so BOTH this container path
# (``kali_exec``) and the audited host path (the recon host-dispatch wrappers in
# commands/web_discovery.py / dns_discovery.py) apply the SAME rules. The names
# are re-exported from this module for back-compat with existing importers.


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
    container_name: str | None = None,
    config: Config | None = None,
    tool_name: str | None = None,
    identity: str | None = None,
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
    eng_key = engagement_key or eng_dir.name or cfg.engagement_key
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
    # A plain kali exec does not apply credential material. Keep its audit label
    # anonymous unless the caller explicitly asks for an identity and that
    # identity is actually injected into the command below. This avoids a
    # credentials backend read on every recon probe and prevents unauthenticated
    # commands from being counted as active-identity coverage.
    auth_context = "anonymous"
    _identity_name: str | None = None
    _identity_material: dict = {}
    if identity is not None:
        _identity_name, _identity_material = resolve_identity(eng_dir, identity)
        if not _identity_material:
            print(
                f"warning: --identity '{identity}' not found in the credential "
                "store or temporarily unavailable; no auth material to apply.",
                file=sys.stderr,
            )

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
    if identity is not None:
        if _apply_identity_material(cmd, derived_tool_name, _identity_material):
            auth_context = _identity_name or auth_context
        else:
            print(
                f"warning: --identity '{identity}': auth material was NOT applied "
                f"(tool '{derived_tool_name}' takes no injectable -H header, or no "
                "material). Leaving auth_context derived so this run is NOT counted "
                "as a cross-identity probe — inject the identity's auth into the "
                "command manually if this tool needs it.",
                file=sys.stderr,
            )

    # Program-mandated attribution headers (e.g. BugCrowd's ``X-Bug-Bounty:
    # <handle>``) must ride every in-scope HTTP probe. Inject here — after the
    # identity block (so an identity-set header isn't duplicated) and before the
    # IP-pin/exec — so the injected ``-H`` args land in the recorded audit argv.
    # For a ``sh -c``/``bash -c`` wrapper the header is BEST-EFFORT injected into
    # the curl/wget sub-commands inside the script TEXT (W5); a plain argv append
    # would land on the shell, not the inner tool. WARN (never block) only when
    # no safe -H injection is possible — a missing attribution header is a
    # reduced reward, not a ban-risk, so a hard block (which would stall a
    # legitimate multi-curl probe mid-hunt) is never the right call.
    _req_headers = _required_headers(eng_dir)
    if _req_headers:
        status = _apply_required_headers(cmd, derived_tool_name, _req_headers)
        if status == "warned":
            names = ", ".join(_req_headers)
            print(
                f"warning: program requires header(s) {names} but tool "
                f"'{derived_tool_name}' has no known -H injection — this run will "
                "NOT carry the required header; inject it manually if this tool "
                "reaches the in-scope target.",
                file=sys.stderr,
            )

    # CR-36 — host-resolve + --resolve IP-pin. On macOS Docker Desktop the
    # container resolver flaps (I-013), so a container HTTP probe can return
    # http=000 for a name that resolves fine on the host. Pin the host-resolved
    # IP into the argv (curl/httpx/nuclei/ffuf/katana) so target HTTP never
    # depends on the broken container resolver. Transparent no-op off Docker
    # Desktop and when the operator opts out (VIGIL_NO_RESOLVE_PIN) — pinning is
    # idempotent (skipped if a --resolve for this host is already present).
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
                f"warning: pre-exec audit POST failed: {exc}; continuing without audit row.",
                file=sys.stderr,
            )
            _write_failed_audit_marker(eng_dir, run_uuid=run_uuid, error=str(exc))
            audit_failed = True

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
        )
    finally:
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
    # Public surface
    "kali_exec",
]
