"""Output preview, RSS rollup, scope/auth context helpers for kali runs.

Pure-ish I/O: read stdout/stderr files into a head+tail preview capped at
32KB, parse ``/proc/<pid>/status`` for the actual peak RSS (more accurate
than ``getrusage`` for a single child), and derive the scope-version /
auth-context audit fields from engagement files. Also owns the
``KaliResult`` dataclass that the orchestrator returns to callers.
"""
from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Optional


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
    # CR-36 false-negative guard. True when the run ended in the
    # http=000 / connection-failed / DNS-resolution-failure transport signature
    # — i.e. NO real HTTP answer came back — so an agent must NOT read the
    # terminal status as a target verdict (404/patched/gated). Stays False on a
    # legitimate, body-bearing answer (incl. 4xx/5xx walls) and for non-HTTP
    # tools. ``transport_error_detail`` carries a one-line human reason.
    transport_error: bool = False
    transport_error_detail: str = ""


# --------------------------------------------------------------------------- #
# CR-36 false-negative (http=000 / connection-failed / DNS-failure) detection
# --------------------------------------------------------------------------- #

# HTTP prober tools whose run can be classified by the transport-error guard.
# A non-HTTP tool (nmap, subfinder, puredns, ...) never trips the guard — its
# non-zero exit is a legitimate signal, not a masked target verdict.
_HTTP_PROBER_TOOLS = frozenset({"curl", "httpx", "nuclei", "ffuf", "katana", "wafw00f", "nikto"})

# curl/libcurl exit codes that mean the transport never completed an HTTP
# exchange (no answer came back): 6 DNS-resolve-failure, 7 couldn't-connect,
# 28 timeout, 35 TLS-handshake error. These are NOT a target verdict.
_CURL_TRANSPORT_FAIL_EXITS = frozenset({6, 7, 28, 35})

# Telltale stderr fragments emitted by curl / httpx / the underlying resolver
# on the http=000 transport-failure path. Matched case-insensitively. Kept tight
# so a body that merely mentions these words does not trip the guard (we only
# inspect stderr, never stdout/the response body).
_TRANSPORT_FAIL_STDERR_NEEDLES = (
    "could not resolve host",
    "couldn't resolve host",
    "name or service not known",
    "temporary failure in name resolution",
    "no address associated with hostname",
    "failed to connect",
    "connection refused",
    "connection timed out",
    "could not connect to server",
    "no route to host",
    "network is unreachable",
    "operation timed out",
    "empty reply from server",
    "ssl_connect",
    "no such host",
    "i/o timeout",
    "lookup ",  # Go/httpx 'lookup host: no such host'
)


def is_http_prober(tool_name: str) -> bool:
    """True when ``tool_name`` is an HTTP prober the http=000 guard applies to."""
    return (tool_name or "").strip().lower() in _HTTP_PROBER_TOOLS


def detect_transport_error(
    *,
    tool_name: str,
    return_code: int | None,
    stdout_preview: str,
    stderr_preview: str,
    timed_out: bool,
) -> tuple[bool, str]:
    """Detect the http=000 / connection-failed / DNS-failure signature (CR-36).

    Returns ``(is_transport_error, detail)``. This is the SINGLE in-process
    detector the kali path uses to decide a run produced NO real HTTP answer and
    so MUST NOT be read as a target verdict (404/patched/gated). It composes the
    exit-code + empty-body + telltale-stderr signature and delegates the verdict
    semantics to :func:`reachability.classify_probe` (the project-wide single
    source of truth for "a bare http=000 is not a blocked signal").

    The signature requires ALL of:
      * the tool is an HTTP prober (non-HTTP tools never trip the guard);
      * the run did NOT time out (a timeout is its own terminal status, kept
        distinct — it is partial-but-real, handled by the existing cascade);
      * a transport-level failure exit code OR a telltale resolver/connect stderr
        fragment is present; AND
      * the stdout body is empty (a real HTTP answer — even a 4xx/5xx wall — that
        produced ANY body is LIVE and must stand as a verdict).

    A non-HTTP tool, a clean ``return_code == 0``, or any body-bearing answer
    yields ``(False, "")``.
    """
    from . import reachability

    if not is_http_prober(tool_name):
        return False, ""
    if timed_out:
        return False, ""
    # A successful exit with no transport-failure stderr is a real answer.
    if return_code == 0:
        return False, ""

    stderr_l = (stderr_preview or "").lower()
    exit_is_transport_fail = isinstance(return_code, int) and return_code in _CURL_TRANSPORT_FAIL_EXITS
    stderr_needle = next((n for n in _TRANSPORT_FAIL_STDERR_NEEDLES if n in stderr_l), "")

    if not exit_is_transport_fail and not stderr_needle:
        return False, ""

    # A non-empty stdout body does NOT by itself prove an HTTP answer came back:
    # the project's canonical liveness probe
    # ``curl -o /dev/null -w "%{http_code} %{time_connect} %{remote_ip}"`` writes a
    # write-out line (e.g. ``000 0.000000 ``) to stdout EVEN on a transport
    # failure, so a naive "non-empty stdout = LIVE" shortcut would let the most
    # common failed-curl shape through as a clean verdict — the exact false
    # negative CR-36 exists to prevent. Parse the body as a curl ``-w`` write-out
    # and feed the REAL parsed values into the classifier:
    #   * a real (>0) HTTP status, or a body that is not a write-out line at all
    #     (actual HTML/JSON response content) → a genuine verdict (bail);
    #   * a ``000``/empty write-out → no answer; fall through to flag it.
    # Using the parsed time_connect/remote_ip (not a hard-coded http_code="000")
    # also lets the classifier distinguish "connected but no HTTP" (LIVE — a real,
    # if degraded, reach) from "never connected" (the resolver-flap false negative).
    body = (stdout_preview or "").strip()
    parsed = (
        reachability.parse_curl_w(body.splitlines()[0])
        if body
        else {"http_code": "", "time_connect": 0.0, "remote_ip": ""}
    )
    if body:
        try:
            body_is_real_answer = int(str(parsed["http_code"]).strip()) > 0
        except (TypeError, ValueError):
            # First token is not a numeric status → the body is actual response
            # content, not a write-out line → keep it as a real verdict.
            body_is_real_answer = True
        if body_is_real_answer:
            return False, ""

    # Confirm via the project-wide classifier. With no real answer in the body the
    # parsed http_code is 000/empty; classify_probe returns BLACKHOLED (clean
    # connect failure) or UNKNOWN (DNS-resolve failure / TLS) — both mean "no real
    # HTTP verdict came back", which the false-negative guard must flag. Only an
    # explicit LIVE (e.g. TCP connected, write-out carried a remote_ip) keeps the
    # run as a verdict.
    verdict = reachability.classify_probe(
        http_code=parsed["http_code"] or "000",
        time_connect=parsed["time_connect"],
        remote_ip=parsed["remote_ip"],
        curl_exit=return_code if exit_is_transport_fail else None,
        stderr=stderr_preview or "",
    )
    if verdict == reachability.LIVE:
        return False, ""

    reason = stderr_needle or (
        f"exit {return_code}" if exit_is_transport_fail else "http=000"
    )
    detail = (
        f"http=000/connection-failed signature (tool={tool_name}, "
        f"return_code={return_code}, reachability={verdict}, signal='{reason}')"
    )
    return True, detail


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


def _engagement_type(engagement_dir: Path) -> str:
    """Read ``engagement_type`` from ``scope.json`` (web/code/blue/both).

    Used by the Wave-5 (2a) probe-run emission WEB-ONLY guard so the depth
    harness never fires on code/blue engagements. Mirrors the default used by
    ``transition_phase`` (absent/unreadable scope ⇒ ``"web"``), so a legacy
    web engagement without the field still emits probes; only an explicit
    ``code``/``blue`` engagement is skipped.
    """
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return "web"
    try:
        data = json.loads(scope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "web"
    if not isinstance(data, dict):
        return "web"
    return str(data.get("engagement_type", "web")) or "web"


def _required_headers(engagement_dir: Path) -> dict[str, str]:
    """Read ``required_headers`` from ``scope.json``.

    These are program-mandated attribution headers (e.g. BugCrowd's
    ``X-Bug-Bounty: <handle>``) that every in-scope HTTP probe must carry. An
    absent/empty/unreadable scope returns ``{}`` so the no-header path is the
    unchanged default. Only string→string pairs survive; anything else is
    dropped so a malformed scope can never inject a non-header value into argv.
    """
    scope = engagement_dir / "scope.json"
    if not scope.is_file():
        return {}
    try:
        data = json.loads(scope.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    raw = data.get("required_headers")
    if not isinstance(raw, dict):
        return {}
    headers: dict[str, str] = {}
    for name, value in raw.items():
        if isinstance(name, str) and name.strip() and isinstance(value, str):
            headers[name.strip()] = value
    return headers


def _auth_context(engagement_dir: Path) -> str:
    # Audit label for KaliResult — the active identity's mode from the
    # centralized credential store ("none" when no credentials / unreachable).
    from .creds_client import active_material

    material = active_material(str(engagement_dir))
    if not material:
        return "none"
    kind = material.get("mode") or "none"
    return str(kind) or "none"


def _peak_rss_kilobytes_to_bytes(peak_kb: int) -> int:
    # Linux exposes ru_maxrss in KB; macOS exposes it in bytes. Convert only
    # on Linux (the engagement runtime); on macOS the value is already bytes.
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


def _read_safely(path: Path, *, max_bytes: int = 32_768) -> str:
    """Return a preview of ``path`` capped at ``max_bytes``.

    For files smaller than ``max_bytes`` the full content is returned. For
    larger files we read ``head_budget`` bytes from the start and seek to the
    actual end-of-file for the tail — the previous implementation read
    ``max_bytes + 1`` bytes from the START and called the second half "tail",
    which silently lied about file content past the 32K mark (ISSUE-007).
    """
    if not path.is_file():
        return ""
    try:
        size = path.stat().st_size
    except OSError:
        return ""
    if size == 0:
        return ""
    head_budget = max_bytes // 2
    tail_budget = max_bytes - head_budget
    try:
        with path.open("rb") as fh:
            if size <= max_bytes:
                return fh.read().decode("utf-8", errors="replace")
            head = fh.read(head_budget)
            fh.seek(-tail_budget, os.SEEK_END)
            tail = fh.read(tail_budget)
    except OSError:
        return ""
    elided = size - len(head) - len(tail)
    return (
        f"{head.decode('utf-8', errors='replace')}\n"
        f"...\n[truncated {elided} bytes from middle of {size}-byte file]\n...\n"
        f"{tail.decode('utf-8', errors='replace')}"
    )
