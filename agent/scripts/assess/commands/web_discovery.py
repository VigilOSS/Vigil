"""vigil assess web-discovery — composable web-probing pipeline.

Pipes the error-prone glue the LLM should not hand-roll into one synchronous,
audited command:

    de-noise hosts -> httpx liveness (lean, status-only) -> ingest the verdicts
    into the host-liveness ledger -> crawl the LIVE subset with katana ->
    (optional) ingest the crawled URLs into the work buffer (gf-bucketed).

Opinionated, safe-by-construction defaults (de-noised inputs, status-only bulk
httpx so it does not OOM, stdin-safe exec) but every tool knob stays a
first-class flag (`--ports`, `--katana-depth`, `--katana-extra-args`, …) so the
operator/LLM keeps full control. Runs synchronously (Tier-0b rule); each tool
stage writes its own audit row via kali_exec OR the audited host path.

Runtime routing (CR-4/CR-5): on macOS Docker Desktop the BULK httpx liveness
stage auto-routes to the audited HOST path so its many distinct destination IPs
do not wedge the userspace-proxy VM (engagement I-001), and the thread count is
clamped to <=25 (CR-5). The katana crawl + work-buffer ingest stay in the
isolated container (auth'd/exploit HTTP must not leave it). Override the bulk
httpx route with `--runtime {auto,host,container}`. On native Linux / remote
Docker the routing + clamp are a transparent no-op (container path unchanged).
"""
from __future__ import annotations

import json
import os
import shlex
import sys
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

from assess.commands import host_exec, ingest_endpoints
from assess.commands.ingest_httpx import ingest_httpx_results
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.discovery import denoise_hosts
from assess.lib.kali import kali_exec, resolve_crawl_rate_limit
from assess.lib.kali_output import _apply_required_headers, _required_headers
from assess.lib.locking import network_heavy_lock
from assess.lib import no_fire, runtime_route, scope

# CR-5 — bulk httpx concurrency ceiling on macOS Docker Desktop. Every distinct
# destination IP is NAT-tracked by the host userspace proxy (com.docker.backend),
# so a high -threads bulk liveness pass over many hosts wedges the VM (I-001).
_DOCKER_DESKTOP_HTTPX_THREAD_CAP = 25

# I-6 — non-standard HTTP ports the liveness-revalidation pass re-probes on hosts
# that came back dead on the fast default (80,443). httpx -p covers a port list
# natively (tool research: prefer httpx -p over a naabu pre-scan, which is
# allowlisted but not installed), so the revalidation is a second httpx pass over
# ONLY the dead subset — not a fan-out of every host across every port.
_REVALIDATE_PORTS = "8080,8443,8000,8888"


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "web-discovery",
        help="Pipeline: de-noise -> httpx liveness -> ingest liveness ledger -> katana crawl -> (optional) work-buffer ingest.",
    )
    p.add_argument("hosts_file", help="Newline-delimited hosts/URLs (e.g. dns-discovery output)")
    p.add_argument("--ports", default="80,443", help="httpx port list (default: 80,443)")
    p.add_argument("--httpx-threads", dest="httpx_threads", default="50",
                   help="httpx -threads (default 50; clamped to <=25 for the bulk pass on macOS Docker Desktop, CR-5)")
    p.add_argument("--httpx-rate-limit", dest="httpx_rate_limit", default="150", help="httpx -rate-limit (default 150)")
    p.add_argument(
        "--no-revalidate-ports",
        dest="no_revalidate_ports",
        action="store_true",
        help="Skip the I-6 liveness-revalidation pass. By default, hosts that "
             f"came back dead on the fast {{80,443}} pass are re-probed across "
             f"{_REVALIDATE_PORTS} with a longer timeout so a service on a "
             "non-standard port is not silently undercounted.",
    )
    p.add_argument(
        "--revalidate-ports",
        dest="revalidate_ports",
        default=_REVALIDATE_PORTS,
        help=f"Port list for the I-6 dead-host revalidation pass (default {_REVALIDATE_PORTS}).",
    )
    # CR-4/CR-5 — where the BULK httpx liveness stage runs. SAFE DEFAULT: `auto`
    # stays in-container unless the operator opts into host routing via
    # `--runtime host` or VIGIL_RECON_RUNTIME. katana/exploit/auth'd HTTP always
    # stays in the isolated container regardless of this flag.
    p.add_argument("--runtime", dest="runtime", choices=("auto", "host", "container"), default="auto",
                   help="Where the BULK httpx liveness stage runs. host = audited host path (avoids "
                        "the macOS Docker Desktop proxy wedge); container = isolated runtime (default); "
                        "auto = container unless VIGIL_RECON_RUNTIME opts into host/platform-select. "
                        "(katana crawl + exploit HTTP always stay in the container.)")
    p.add_argument("--no-thread-clamp", dest="no_thread_clamp", action="store_true",
                   help="Do NOT clamp bulk httpx threads to <=25 on macOS Docker Desktop (operator override; CR-5).")
    p.add_argument(
        "--tech-detect",
        dest="tech_detect",
        action="store_true",
        help="Add -tech-detect to the bulk httpx pass. OFF by default: tech-detect "
             "amplifies httpx memory and was an OOM (RC137) trigger on large lists.",
    )
    p.add_argument("--no-crawl", dest="no_crawl", action="store_true", help="Skip the katana crawl stage.")
    p.add_argument("--katana-depth", dest="katana_depth", default="4",
                   help="katana -d crawl depth (default 4; the fleet crawl fans the whole live "
                        "set through one blocking call — raise to 5 for a focused re-crawl).")
    p.add_argument("--katana-rate", dest="katana_rate", default="",
                   help="katana -rl req/s for the crawl. Default 10, hard-capped at 20, clamped "
                        "DOWN to the program rate ceiling — so a deep crawl never rides katana's "
                        "built-in 150 req/s.")
    p.add_argument(
        "--katana-extra-args",
        dest="katana_extra_args",
        default="",
        help="Extra katana args (shlex-split), e.g. '-kf all -ef png,jpg' or a custom field/wordlist set.",
    )
    p.add_argument(
        "--db",
        dest="db_path",
        default="",
        help="Enable ingesting the crawled URLs into the backend work buffer "
             "(gf-bucketed) via ingest-endpoints. Pass any non-empty value to enable. "
             "The work buffer is backend-owned now, so a path value here is only a "
             "toggle — it is not used as a filesystem path (ADR 0013).",
    )
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800, help="Per-tool --timeout seconds (default 1800)")
    # Fix 2 (Issue 2) — seat the httpx liveness verdicts as prioritized work
    # items. SAFE DEFAULT: tri-state (None) so an absent flag resolves to ON
    # only when `--db` is set (no db → nothing to seat). `--seat-liveness`
    # forces it on; `--no-seat-liveness` forces it off.
    p.add_argument(
        "--seat-liveness",
        dest="seat_liveness",
        action="store_true",
        default=None,
        help="Seat each LIVE httpx result as a work item (gf-bucketed) via "
             "ingest-endpoints, in addition to the host-liveness ledger. "
             "Default ON when --db is set. Revalidation hits on non-standard "
             "ports (:8080/:8443/:9443/…) are seated FIRST.",
    )
    p.add_argument(
        "--no-seat-liveness",
        dest="seat_liveness",
        action="store_false",
        help="Do NOT seat httpx liveness verdicts as work items (override the "
             "--db default).",
    )
    p.set_defaults(func=run)


def _paths(cfg, name: str) -> tuple[Path, str]:
    host = Path(cfg.engagement_dir) / "scans" / "web-discovery" / name
    container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/{name}"
    return host, container


def _run_paths(cfg, run_uuid: str, name: str) -> tuple[Path, str]:
    relative = f"scans/web-discovery/runs/{run_uuid}/{name}"
    return (
        Path(cfg.engagement_dir) / relative,
        f"/engagements/{cfg.engagement_key}/{relative}",
    )


def _warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


def _host_dispatch(cmd, *, intent, tool_name, timeout, engagement_dir):
    """Run *cmd* via the audited host path (`host-exec`) — same audit fields as the
    container path (route='host_exec'). host_exec.run() ends in sys.exit(rc); we
    catch SystemExit and return a result object with the .return_code kali callers
    expect, so audit rows + downstream ingest are IDENTICAL regardless of route.

    Program-mandated attribution headers are applied here with the SAME
    injectable/skip classifier kali_exec uses (``_apply_required_headers``), so a
    host-routed injectable tool (httpx) carries the engagement's required_headers
    while a skip-set tool (gau/dnsx/subfinder) never leaks the handle to an
    archive/DNS endpoint. The host path does NOT inject IP-pins or auth material;
    only the attribution header is shared with the container path here."""
    cmd = list(cmd)
    _req_headers = _required_headers(Path(engagement_dir)) if engagement_dir else {}
    if _req_headers:
        status = _apply_required_headers(cmd, tool_name, _req_headers)
        if status == "warned":
            names = ", ".join(_req_headers)
            _warn(
                f"program requires header(s) {names} but host-routed tool "
                f"'{tool_name}' has no known -H injection — this run will NOT "
                "carry the required header; inject it manually if it reaches the "
                "in-scope target."
            )
    ns = SimpleNamespace(
        command=list(cmd), tool=tool_name, intent=intent, technique="DISCOVERY",
        phase="recon", target_host="", agent_name=None, scope_host="", cwd=None,
        timeout=int(timeout), audit_source="header", from_json=None,
        allow_destructive=False, require_audit=False, engagement_dir=engagement_dir,
    )
    rc = 0
    try:
        host_exec.run(ns)
    except SystemExit as exc:
        code = exc.code
        rc = code if isinstance(code, int) else (0 if code in (None, "") else 1)
    return SimpleNamespace(return_code=rc)


# CR-4 routing policy — same precedence as dns-discovery: --runtime wins, then
# VIGIL_RECON_RUNTIME (host|container|auto), then SAFE DEFAULT container for a
# bare `auto` (container path unchanged unless the operator opts into host).
_RECON_RUNTIME_ENV = "VIGIL_RECON_RUNTIME"


def _route_for(args, tool: str) -> str:
    requested = (getattr(args, "runtime", "auto") or "auto").strip().lower()
    if requested in ("host", "container"):
        return runtime_route.resolve_runtime(requested, tool=tool)
    env = os.environ.get(_RECON_RUNTIME_ENV, "").strip().lower()
    if env in ("host", "container", "auto"):
        return runtime_route.resolve_runtime(env, tool=tool)
    return "container"


def _clamp_httpx_threads(args, *, route: str = "container") -> int:
    """CR-5: clamp the bulk httpx -threads to <=25 on macOS Docker Desktop (WARN if
    clamped) unless the operator overrode with --no-thread-clamp. The clamp is a
    NAT-tracking userspace-proxy guard, so it only matters when the bulk pass runs
    IN the container; a host-routed pass (`--runtime host`) goes straight out the
    host stack with no proxy to protect, so the clamp is skipped there (defect #6).
    """
    try:
        requested = int(args.httpx_threads)
    except (TypeError, ValueError):
        requested = 50
    if getattr(args, "no_thread_clamp", False):
        return requested
    if route == "host":
        # Host-routed bulk httpx has no userspace proxy to wedge; do not throttle.
        return requested
    rt = runtime_route.detect_runtime()
    if rt.is_docker_desktop and requested > _DOCKER_DESKTOP_HTTPX_THREAD_CAP:
        _warn(
            f"clamped bulk httpx -threads {requested} -> {_DOCKER_DESKTOP_HTTPX_THREAD_CAP} on "
            "macOS Docker Desktop: each distinct destination IP is NAT-tracked by the host "
            "userspace proxy (com.docker.backend), so a high-thread bulk pass wedges the VM "
            "(I-001). Route this stage to the host (--runtime host) for full concurrency, or "
            "pass --no-thread-clamp to override (CR-5)."
        )
        return _DOCKER_DESKTOP_HTTPX_THREAD_CAP
    return requested


def _clamp_httpx_rate_limit(requested: str, rate_cap: float | None) -> int:
    """Resolve the httpx ``-rate-limit`` (req/s) for a bulk pass.

    ``requested`` is the per-verb default (``--httpx-rate-limit``, 150). When the
    engagement configures a global req/s ceiling (``scope.rate_limit`` via ``vigil
    engagement create --rate-limit``), the bulk httpx pass is clamped DOWN to it.
    httpx ``-rate-limit`` is a SINGLE GLOBAL token bucket, so this caps the
    AGGREGATE rate of THIS one bulk pass over the whole in-scope host set probed in
    the invocation (it bounds per-host only as a side effect); an unset cap
    (``None``) keeps the verb default exactly as today (no hard gate, agent keeps
    discretion).

    httpx ``-rate-limit`` is an integer req/s, so a fractional cap truncates DOWN
    (5.9 -> 5) and the emitted rate never exceeds the ceiling. Sub-1 caps are
    rejected up front by ``vigil engagement create``; the ``max(1, …)`` floor only
    guards a hand-edited scope.json so a 0 never stalls the pass.
    """
    try:
        base = int(requested)
    except (TypeError, ValueError):
        base = 150
    if rate_cap is None:
        return base
    return max(1, min(base, int(rate_cap)))


def _extract_live_urls(httpx_jsonl: Path) -> list[str]:
    """Live URLs (answered, not failed) from an httpx -json file, for the crawl seed."""
    urls: list[str] = []
    if not httpx_jsonl.is_file():
        return urls
    with httpx_jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("failed"):
                continue
            url = obj.get("url") or obj.get("final_url") or obj.get("input")
            if url:
                urls.append(str(url))
    return sorted(set(urls))


_ASSET_SUFFIXES = frozenset(
    {".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2"}
)


def _crawl_health(
    seed_urls: list[str],
    katana_jsonl: Path,
    *,
    elapsed_seconds: float,
    budget_seconds: int,
    run_uuid: str,
) -> dict:
    records = _katana_records(katana_jsonl) if katana_jsonl.is_file() else []
    per_host: dict[str, int] = {}
    assets = 0
    for record in records:
        url = str(record.get("url") or "")
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        host = (parsed.hostname or "").lower()
        if host:
            per_host[host] = per_host.get(host, 0) + 1
        if Path(parsed.path).suffix.lower() in _ASSET_SUFFIXES:
            assets += 1
    unique_count = len(records)
    warnings: list[str] = []
    ratio = elapsed_seconds / budget_seconds if budget_seconds > 0 else 0.0
    if seed_urls and unique_count == 0 and ratio <= 0.1:
        warnings.extend(["fast-empty", "possible-spa-undercoverage"])
    return {
        "run_uuid": run_uuid,
        "seed_count": len(seed_urls),
        "unique_url_count": unique_count,
        "per_host_yield": dict(sorted(per_host.items())),
        "elapsed_seconds": round(float(elapsed_seconds), 3),
        "budget_seconds": int(budget_seconds),
        "elapsed_budget_ratio": ratio,
        "asset_count": assets,
        "asset_ratio": assets / unique_count if unique_count else 0.0,
        "warnings": warnings,
    }


def _write_crawl_health(cfg, payload: dict) -> None:
    path, _ = _paths(cfg, "crawl-health.json")
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)


def _write_httpx_health(cfg, run_uuid: str, payload: dict) -> None:
    """Publish lineage only for a fully accepted liveness generation."""
    run_path, _ = _run_paths(cfg, run_uuid, "httpx-health.json")
    canonical_path, _ = _paths(cfg, "httpx-health.json")
    run_path.parent.mkdir(parents=True, exist_ok=True)
    run_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    run_path.replace(canonical_path)


def _answered_record_count(path: Path) -> int:
    """Count accepted httpx JSONL rows without treating malformed output as live."""
    count = 0
    if not path.is_file():
        return count
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict) and not row.get("failed"):
                count += 1
    return count


def _promote_empty_generation(cfg, run_uuid: str, *, stage_timeout: int) -> None:
    for name in (
        "denoised_hosts.txt",
        "revalidate_hosts.txt",
        "httpx_live.jsonl",
        "live_urls.txt",
        "katana.jsonl",
    ):
        run_path, _ = _run_paths(cfg, run_uuid, name)
        canonical_path, _ = _paths(cfg, name)
        run_path.parent.mkdir(parents=True, exist_ok=True)
        run_path.write_text("", encoding="utf-8")
        run_path.replace(canonical_path)
    run_scope_meta, _ = _run_paths(cfg, run_uuid, "scope-filter.meta.json")
    if run_scope_meta.is_file():
        run_scope_meta.replace(_paths(cfg, "scope-filter.meta.json")[0])
    _write_httpx_health(
        cfg,
        run_uuid,
        {
            "run_uuid": run_uuid,
            "state": "accepted-empty",
            "input_count": 0,
            "live_record_count": 0,
            "revalidation_target_count": 0,
            "recovered_count": 0,
            "exit_code": 0,
        },
    )
    health = _crawl_health(
        [],
        _paths(cfg, "katana.jsonl")[0],
        elapsed_seconds=0,
        budget_seconds=stage_timeout,
        run_uuid=run_uuid,
    )
    health.update({"state": "accepted-empty", "exit_code": 0})
    _write_crawl_health(cfg, health)


# Default HTTP(S) ports — a URL on any OTHER explicit port is treated as a
# non-standard / revalidation-recovered surface and seated FIRST (Fix 2).
_DEFAULT_HTTP_PORTS: frozenset[int] = frozenset({80, 443})


def _has_nondefault_port(url: str) -> bool:
    """True when *url* carries an explicit, non-default (not 80/443) port.

    Used to float the I-6 revalidation hits (`:8080/:8443/:9443/:8000/:8888`) to
    the front of the seated batch — those rescued management surfaces are the
    highest-value liveness verdicts to enter the work buffer first."""
    from urllib.parse import urlsplit

    try:
        port = urlsplit(url).port
    except ValueError:
        return False
    return port is not None and port not in _DEFAULT_HTTP_PORTS


def _seat_liveness_work_items(httpx_jsonl: Path) -> list[dict]:
    """Build prioritized work-item JSON rows from LIVE httpx results (Fix 2).

    One row per ANSWERED (non-failed) httpx record, deduped on URL, in the
    ingest-endpoints JSON-line shape: ``{url, method:"GET", content_type,
    response_status, type, source:"web-discovery", live_status:"live",
    signals:["httpx-live"]}``. `type` is emitted as ``unknown`` so the row falls
    through to `classify_type` (Fix 5 override-align) where the threaded
    `content_type` can recover a real type. Non-standard-port (revalidation)
    rows sort FIRST so the rescued management surfaces lead the batch."""
    rows: list[dict] = []
    if not httpx_jsonl.is_file():
        return rows
    seen: set[str] = set()
    with httpx_jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("failed"):
                continue
            url = obj.get("url") or obj.get("final_url") or obj.get("input")
            if not url:
                continue
            url = str(url)
            if url in seen:
                continue
            seen.add(url)
            status = obj.get("status_code")
            rows.append({
                "url": url,
                "method": "GET",
                # httpx only carries content_type when invoked with
                # -content-type; absent here, classify_type falls back to
                # path-shape (no regression). Threaded forward if present.
                "content_type": str(obj.get("content_type") or ""),
                "response_status": status if isinstance(status, int) else None,
                "type": "unknown",
                "source": "web-discovery",
                "live_status": "live",
                "signals": ["httpx-live"],
            })
    # Stable sort: non-default-port (revalidation) hits first, original order
    # preserved within each group.
    rows.sort(key=lambda r: 0 if _has_nondefault_port(r["url"]) else 1)
    return rows


def _bare_host(token: str) -> str:
    """Normalize an httpx ``input`` token (host or URL, maybe with :port) to a bare
    lowercased host, so a default-pass row and a candidate line compare equal."""
    raw = (token or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0]
    # Strip a trailing :port (but keep an IPv6 literal's internal colons — those
    # carry no host:port shape here since httpx inputs are de-noised hosts).
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return raw.rstrip(".")


def _live_input_hosts(httpx_jsonl: Path) -> set[str]:
    """Bare hosts that produced at least one ANSWERED (non-failed) httpx row."""
    live: set[str] = set()
    if not httpx_jsonl.is_file():
        return live
    with httpx_jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("failed"):
                continue
            token = obj.get("input") or obj.get("host") or obj.get("url") or obj.get("final_url")
            host = _bare_host(str(token)) if token else ""
            if host:
                live.add(host)
    return live


def _dead_default_hosts(candidates: list[str], live_jsonl: Path) -> list[str]:
    """Candidate hosts that did NOT answer on the fast default pass — the only
    hosts the I-6 revalidation pass re-probes across non-standard ports."""
    live = _live_input_hosts(live_jsonl)
    dead: list[str] = []
    for raw in candidates:
        host = _bare_host(raw)
        if host and host not in live:
            dead.append(host)
    return sorted(set(dead))


# Backfill every flag when a caller builds a bare args object in-process (e.g. the
# `vigil assess recon` orchestrator, or focused tests). argparse supplies these on
# the real CLI path; this fills absent attributes so an in-process caller that only
# sets hosts_file/engagement_dir never trips on a missing flag. Keep this in sync
# with `register()` defaults (mirrors dns_discovery's full _ARG_DEFAULTS).
_ARG_DEFAULTS = {
    "ports": "80,443",
    "httpx_threads": "50",
    "httpx_rate_limit": "150",
    "no_revalidate_ports": False,
    "revalidate_ports": _REVALIDATE_PORTS,
    "tech_detect": False,
    "no_crawl": False,
    "katana_depth": "4",
    "katana_rate": "",
    "katana_extra_args": "",
    "db_path": "",
    "stage_timeout": 1800,
    "runtime": "auto",
    "no_thread_clamp": False,
    # Fix 2 — tri-state; None resolves to ON only when --db is set (see run()).
    "seat_liveness": None,
    "run_uuid": None,
}


def _apply_arg_defaults(args) -> None:
    for name, default in _ARG_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def _run_httpx_liveness(args, *, in_arg, out_arg, ports, threads, rate_limit, route, timeout, intent):
    """Run one lean status-only httpx liveness pass on either route.

    Shared by the fast default-port pass (Stage 1) and the I-6 dead-host
    revalidation pass (Stage 1b) so both carry identical flags + attribution
    headers (host path injects via _host_dispatch; container path via kali_exec)
    and the same rate cap. Returns the result object (with `.return_code`)."""
    httpx_cmd = [
        "httpx", "-l", str(in_arg), "-p", str(ports),
        "-status-code", "-title", "-web-server", "-ip", "-json", "-silent",
        "-threads", str(threads), "-rate-limit", str(rate_limit),
        "-o", str(out_arg),
    ]
    if args.tech_detect:
        httpx_cmd.append("-tech-detect")
    if route == "host":
        with network_heavy_lock(args.engagement_dir, label="httpx host liveness"):
            return _host_dispatch(
                httpx_cmd, intent=intent, tool_name="httpx",
                timeout=int(timeout), engagement_dir=args.engagement_dir,
            )
    return kali_exec(
        httpx_cmd, technique="DISCOVERY", intent=intent,
        probe_kind="fingerprint", phase="recon", timeout=int(timeout),
        engagement_dir=args.engagement_dir, tool_name="httpx",
    )


def _merge_liveness(primary: Path, extra: Path) -> int:
    """Append the answered (non-failed) rows from a revalidation httpx -json file
    into the primary liveness file. Returns the count of recovered live rows.

    De-dupes on the raw JSON line so a re-run that re-probes the same host on the
    same port is idempotent. Skips failed rows so the merge only ever ADDS live
    hosts (a dead-on-default host that is also dead on the non-standard ports
    contributes nothing)."""
    if not extra.is_file():
        return 0
    existing: set[str] = set()
    if primary.is_file():
        with primary.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                s = line.strip()
                if s:
                    existing.add(s)
    recovered = 0
    new_lines: list[str] = []
    with extra.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            s = line.strip()
            if not s:
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict) or obj.get("failed"):
                continue
            if s in existing:
                continue
            existing.add(s)
            new_lines.append(s)
            recovered += 1
    if new_lines:
        with primary.open("a", encoding="utf-8") as fh:
            for s in new_lines:
                fh.write(s + "\n")
    return recovered


def run(args) -> None:
    _apply_arg_defaults(args)
    cfg = load_config(args.engagement_dir)
    # `--engagement-dir` defaults to None; load_config resolves the real dir (cwd
    # scope.json or launcher session binding). Write it back so post-config reads/stages —
    # rate caps, host-route required-header injection, scope filtering — see the
    # resolved path instead of None (which would raise in rate_caps_for_dir).
    args.engagement_dir = cfg.engagement_dir
    hosts_path = Path(anchor_engagement_relative(args.hosts_file, args.engagement_dir))
    if not hosts_path.is_file():
        print(f"web-discovery: hosts file not found: {hosts_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(cfg.engagement_dir) / "scans" / "web-discovery"
    out_dir.mkdir(parents=True, exist_ok=True)
    run_uuid = str(getattr(args, "run_uuid", None) or uuid.uuid4().hex)

    # --- Stage 0: de-noise -------------------------------------------------
    raw_lines = hosts_path.read_text(encoding="utf-8", errors="replace").splitlines()
    try:
        scope_doc = scope.load_scope(args.engagement_dir)
        raw_lines, scope_metadata = scope.filter_recon_targets(scope_doc, raw_lines)
    except SystemExit:
        scope_metadata = None
    if scope_metadata is not None:
        run_scope_meta, _ = _run_paths(cfg, run_uuid, "scope-filter.meta.json")
        run_scope_meta.parent.mkdir(parents=True, exist_ok=True)
        run_scope_meta.write_text(
            json.dumps(scope_metadata, indent=2), encoding="utf-8"
        )
    clean, dropped = denoise_hosts(raw_lines)
    if not clean:
        _promote_empty_generation(
            cfg, run_uuid, stage_timeout=int(args.stage_timeout)
        )
        print("web-discovery: no hosts left after de-noise; nothing to probe.", file=sys.stderr)
        sys.exit(0)
    denoised_host, _ = _paths(cfg, "denoised_hosts.txt")
    run_denoised_host, run_denoised_container = _run_paths(
        cfg, run_uuid, "denoised_hosts.txt"
    )
    run_denoised_host.parent.mkdir(parents=True, exist_ok=True)
    run_denoised_host.write_text("\n".join(clean) + "\n", encoding="utf-8")
    print(f"web-discovery: {len(clean)} hosts after de-noise ({dropped} dropped as noise)", file=sys.stderr)

    # --- Stage 1: httpx liveness (lean, status-only) -----------------------
    # CR-4 — route the BULK liveness pass to the host on macOS Docker Desktop
    # (avoids the per-dest-IP proxy wedge); container elsewhere / on override.
    # The katana crawl below stays in the container regardless (CR-5: exploit/
    # auth'd HTTP must not leave the isolated runtime).
    #
    # Rate cap (stage 1): an engagement-configured GLOBAL req/s ceiling
    # (scope.rate_limit) clamps the bulk httpx -rate-limit DOWN. httpx
    # -rate-limit is a single global token bucket, so this bounds the AGGREGATE
    # rate of the whole liveness pass over every in-scope host (per-host only as
    # a side effect); unset keeps the verb default (no hard gate). Headers ride
    # automatically (host path injects via _host_dispatch; container path via
    # kali_exec's central injector).
    rate_cap, _ = scope.rate_caps_for_dir(args.engagement_dir)
    rate_limit = _clamp_httpx_rate_limit(args.httpx_rate_limit, rate_cap)
    if rate_cap is not None:
        print(f"web-discovery: global req/s ceiling {rate_cap} configured "
              f"(per-invocation; bounds per-host as a side effect); "
              f"httpx -rate-limit set to {rate_limit}.", file=sys.stderr)
    httpx_route = _route_for(args, "httpx")
    threads = _clamp_httpx_threads(args, route=httpx_route)
    live_host, live_container = _paths(cfg, "httpx_live.jsonl")
    run_live_host, run_live_container = _run_paths(cfg, run_uuid, "httpx_live.jsonl")
    run_live_host.parent.mkdir(parents=True, exist_ok=True)
    # Both routes write to the same host file (the container path is the bind-
    # mounted same inode), so Stage 2 ingest is identical regardless of route.
    in_arg = (
        str(run_denoised_host)
        if httpx_route == "host"
        else run_denoised_container
    )
    out_arg = str(run_live_host) if httpx_route == "host" else run_live_container
    res = _run_httpx_liveness(
        args, in_arg=in_arg, out_arg=out_arg, ports=str(args.ports),
        threads=threads, rate_limit=rate_limit, route=httpx_route,
        timeout=int(args.stage_timeout),
        intent="web-discovery: httpx liveness (status-only)",
    )
    httpx_rc = getattr(res, "return_code", 0)
    if httpx_rc not in (0, None):
        print(
            f"web-discovery: httpx exited {httpx_rc}; rejected run-scoped output "
            f"for generation {run_uuid}.",
            file=sys.stderr,
        )
        sys.exit(int(httpx_rc))
    # Some successful tools omit the output file when the result set is empty.
    # Materialize that accepted empty result, then atomically replace the
    # canonical artifact. A failed generation never reaches this promotion.
    run_live_host.touch(exist_ok=True)

    # --- Stage 1b: I-6 liveness revalidation on non-standard ports ---------
    # The fast default pass only probes 80,443; a service answering on
    # 8080/8443/8000/8888 would be silently undercounted. Re-probe ONLY the
    # dead-on-default subset across the non-standard ports with a longer
    # timeout, then APPEND the recovered rows into the same liveness file so
    # Stage 2 ingest sees them as ordinary live hosts.
    reval_in_host, _ = _paths(cfg, "revalidate_hosts.txt")
    run_reval_in_host, run_reval_in_container = _run_paths(
        cfg, run_uuid, "revalidate_hosts.txt"
    )
    run_reval_in_host.parent.mkdir(parents=True, exist_ok=True)
    run_reval_in_host.write_text("", encoding="utf-8")
    dead: list[str] = []
    recovered = 0
    if not args.no_revalidate_ports:
        dead = _dead_default_hosts(clean, run_live_host)
        revalidate_ports = str(args.revalidate_ports or _REVALIDATE_PORTS)
        if dead and revalidate_ports:
            run_reval_in_host.write_text("\n".join(dead) + "\n", encoding="utf-8")
            reval_out_host, reval_out_container = _run_paths(
                cfg, run_uuid, "httpx_revalidate.jsonl"
            )
            reval_out_host.parent.mkdir(parents=True, exist_ok=True)
            r_in = (
                str(run_reval_in_host)
                if httpx_route == "host"
                else run_reval_in_container
            )
            r_out = str(reval_out_host) if httpx_route == "host" else reval_out_container
            # A longer timeout for the second pass: non-standard ports are more
            # likely to be slow/filtered, and the dead subset is small (1.5x).
            reval_timeout = int(args.stage_timeout) + int(args.stage_timeout) // 2
            rres = _run_httpx_liveness(
                args, in_arg=r_in, out_arg=r_out, ports=revalidate_ports,
                threads=threads, rate_limit=rate_limit, route=httpx_route,
                timeout=reval_timeout,
                intent=f"web-discovery: I-6 liveness revalidation of {len(dead)} "
                       f"dead-on-default hosts across {revalidate_ports}",
            )
            reval_rc = getattr(rres, "return_code", 0)
            if reval_rc not in (0, None):
                print(
                    f"web-discovery: revalidation httpx exited {reval_rc}; "
                    f"generation {run_uuid} is partial and was not ingested.",
                    file=sys.stderr,
                )
                sys.exit(int(reval_rc))
            recovered = _merge_liveness(run_live_host, reval_out_host)
            print(f"web-discovery: revalidation re-probed {len(dead)} dead hosts on "
                  f"{revalidate_ports}; recovered {recovered} live.", file=sys.stderr)

    # The entire default+revalidation generation is now accepted. Promote once
    # so a failed optional pass can never expose a mixed/partial canonical file.
    run_live_host.replace(live_host)
    run_denoised_host.replace(denoised_host)
    run_reval_in_host.replace(reval_in_host)
    run_scope_meta, _ = _run_paths(cfg, run_uuid, "scope-filter.meta.json")
    if run_scope_meta.is_file():
        run_scope_meta.replace(_paths(cfg, "scope-filter.meta.json")[0])
    _write_httpx_health(
        cfg,
        run_uuid,
        {
            "run_uuid": run_uuid,
            "state": "accepted",
            "input_count": len(clean),
            "live_record_count": _answered_record_count(live_host),
            "revalidation_target_count": len(dead),
            "recovered_count": recovered,
            "exit_code": 0,
        },
    )

    # --- Stage 2: ingest the liveness verdicts into the backend ledger -----
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        summary = ingest_httpx_results(live_host, cfg=cfg, source="web-discovery", client=client)
    by_class = " ".join(f"{k}={v}" for k, v in sorted(summary["by_class"].items()))
    print(f"web-discovery: liveness ledger upserted {summary['upserted']} hosts ({by_class or 'none'})", file=sys.stderr)

    # --- Stage 2b: (optional) seat httpx live results as work items (Fix 2) -
    # The ledger upsert above answers "is this host live now"; it does NOT enter
    # the work buffer, so an httpx hit on a non-standard management port
    # (:9443/auth/admin) only ever became a work item if katana later re-crawled
    # it. Seat each LIVE httpx result directly as a gf-bucketed work item through
    # the ingest-endpoints JSON-line path (which threads `content_type` into
    # classify_type). Revalidation hits on non-standard ports lead the batch.
    # SAFE DEFAULT: on only when --db is set (resolve the tri-state flag here).
    seat_liveness = getattr(args, "seat_liveness", None)
    if seat_liveness is None:
        seat_liveness = bool(args.db_path)
    if seat_liveness and args.db_path:
        seated = _seat_liveness_work_items(live_host)
        if seated:
            seat_host, _ = _paths(cfg, "httpx_worklive.jsonl")
            seat_host.write_text(
                "".join(json.dumps(r) + "\n" for r in seated), encoding="utf-8"
            )
            ingest_endpoints.run(_ingest_args(args, str(seat_host)))
            print(f"web-discovery: seated {len(seated)} live httpx results as work items "
                  "(revalidation/non-standard-port hits first)", file=sys.stderr)

    # --- Stage 3: katana crawl of the live subset --------------------------
    katana_host, _ = _paths(cfg, "katana.jsonl")
    run_katana_host, run_katana_container = _run_paths(cfg, run_uuid, "katana.jsonl")
    if not args.no_crawl:
        live_urls = _extract_live_urls(live_host)
        if live_urls:
            seed_host, _ = _paths(cfg, "live_urls.txt")
            run_seed_host, run_seed_container = _run_paths(
                cfg, run_uuid, "live_urls.txt"
            )
            run_seed_host.parent.mkdir(parents=True, exist_ok=True)
            run_seed_host.write_text("\n".join(live_urls) + "\n", encoding="utf-8")
            # I-4 — `-or -ob` omit the stored response + body so a deep crawl does
            # not blow up the engagement disk with every fetched page (the crawl
            # only needs the discovered URL graph here; bodies are fetched
            # selectively downstream by gau-secrets / js-mining).
            # `-jsl` adds jsluice endpoint extraction (real coverage, not just the
            # link graph); `-fs fqdn` keeps the active crawler on the exact seeded
            # in-scope hosts (it never probes an out-of-scope sibling subdomain it
            # finds in a link). `-or -ob` already omit body/raw to bound disk.
            katana_cmd = [
                "katana", "-list", run_seed_container, "-jc", "-jsl",
                "-d", str(args.katana_depth), "-fs", "fqdn",
                "-or", "-ob",
                "-jsonl", "-silent", "-o", run_katana_container,
            ]
            # Safe-by-default crawl rate (stage 3): resolve_crawl_rate_limit
            # defaults to 10 req/s, hard-caps at 20, and clamps DOWN to the
            # program ceiling (rate_cap) when configured — so an uncapped fleet
            # crawl never rides katana's built-in 150 req/s. -rl is req/s and -rlm
            # is req/min (both single global token buckets); set both.
            katana_rl = resolve_crawl_rate_limit(
                args.katana_rate, rate_cap=rate_cap, warn=_warn,
            )
            katana_cmd.extend(["-rl", str(katana_rl), "-rlm", str(katana_rl * 60)])
            try:
                scope_doc = scope.load_scope(args.engagement_dir)
                no_fire_regex = no_fire.crawl_exclusion_regex(scope_doc)
            except SystemExit:
                # In-process compatibility callers may provide a synthetic cfg
                # without a scope file; real CLI resolution already requires it.
                no_fire_regex = ""
            except no_fire.NoFirePolicyError as exc:
                print(f"web-discovery: invalid no-fire policy: {exc}", file=sys.stderr)
                sys.exit(1)
            if no_fire_regex:
                katana_cmd.extend(["-cos", no_fire_regex])
            if args.katana_extra_args:
                katana_cmd.extend(shlex.split(args.katana_extra_args))
            crawl_started = time.monotonic()
            kres = kali_exec(
                katana_cmd, technique="DISCOVERY", intent="web-discovery: katana crawl of live subset",
                probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
                engagement_dir=args.engagement_dir, tool_name="katana",
            )
            elapsed = time.monotonic() - crawl_started
            health = _crawl_health(
                live_urls,
                run_katana_host,
                elapsed_seconds=elapsed,
                budget_seconds=int(args.stage_timeout),
                run_uuid=run_uuid,
            )
            katana_rc = getattr(kres, "return_code", 0)
            health["state"] = "accepted" if katana_rc in (0, None) else "failed"
            health["exit_code"] = katana_rc
            _write_crawl_health(cfg, health)
            if katana_rc not in (0, None):
                print(
                    f"web-discovery: katana exited {katana_rc}; rejected partial "
                    f"generation {run_uuid}.",
                    file=sys.stderr,
                )
                sys.exit(int(katana_rc))
            run_katana_host.touch(exist_ok=True)
            run_katana_host.replace(katana_host)
            run_seed_host.replace(seed_host)
            print(f"web-discovery: crawled {len(live_urls)} live URLs with katana", file=sys.stderr)
            _rargv = getattr(kres, "resolved_argv", None)
            if _rargv:
                print(f"web-discovery: katana argv: {' '.join(_rargv)}", file=sys.stderr)
        else:
            print("web-discovery: no live URLs to crawl; skipping katana.", file=sys.stderr)
            run_katana_host.parent.mkdir(parents=True, exist_ok=True)
            run_katana_host.touch()
            run_katana_host.replace(katana_host)
            seed_host, _ = _paths(cfg, "live_urls.txt")
            run_seed_host, _ = _run_paths(cfg, run_uuid, "live_urls.txt")
            run_seed_host.parent.mkdir(parents=True, exist_ok=True)
            run_seed_host.write_text("", encoding="utf-8")
            run_seed_host.replace(seed_host)
            health = _crawl_health(
                [],
                katana_host,
                elapsed_seconds=0,
                budget_seconds=int(args.stage_timeout),
                run_uuid=run_uuid,
            )
            health.update({"state": "accepted-empty", "exit_code": 0})
            _write_crawl_health(cfg, health)
    else:
        run_katana_host.parent.mkdir(parents=True, exist_ok=True)
        run_katana_host.touch()
        run_katana_host.replace(katana_host)
        seed_host, _ = _paths(cfg, "live_urls.txt")
        run_seed_host, _ = _run_paths(cfg, run_uuid, "live_urls.txt")
        run_seed_host.parent.mkdir(parents=True, exist_ok=True)
        run_seed_host.write_text("", encoding="utf-8")
        run_seed_host.replace(seed_host)
        health = _crawl_health(
            [],
            katana_host,
            elapsed_seconds=0,
            budget_seconds=int(args.stage_timeout),
            run_uuid=run_uuid,
        )
        health.update({"state": "skipped", "exit_code": None})
        _write_crawl_health(cfg, health)

    # --- Stage 4: (optional) ingest crawled URLs into the work buffer ------
    # Fix 3 (Issue 6): emit {url, content_type, ...} JSON lines (not a bare URL
    # list) so ingest-endpoints can thread the crawled response's Content-Type
    # into classify_type. Bare-URL lines still parse downstream, so this stays
    # backward-compatible.
    if not args.no_crawl and args.db_path and katana_host.is_file():
        records = _katana_records(katana_host)
        if records:
            urls_host, _ = _paths(cfg, "katana_urls.jsonl")
            urls_host.write_text(
                "".join(json.dumps(r) + "\n" for r in records), encoding="utf-8"
            )
            ingest_endpoints.run(_ingest_args(args, str(urls_host)))
            print(f"web-discovery: ingested {len(records)} crawled URLs into the work buffer", file=sys.stderr)

    print("web-discovery: done. Liveness in the backend ledger; "
          "run `vigil assess fetch host-liveness` or coverage rollup to review.", file=sys.stderr)


def _katana_records(katana_jsonl: Path) -> list[dict]:
    """Crawled, typed work-item rows from a katana JSONL file.

    Emits ``{url, content_type}`` JSON rows (plus ``response_status``/``tech``
    when the crawl stored the response) so ingest-endpoints can thread the
    crawled Content-Type into `classify_type` — the typer was
    extension/path-shape-only without it. Dedups on URL, enriching the first
    record seen for a URL with the first non-empty metadata, and returns the
    rows sorted by URL (stable, mirrors the prior `sorted(set(...))`).

    Metadata is OPTIONAL by construction: the crawl runs with `-or -ob` (omit
    response + body) so the response block is usually absent and only ``url`` is
    emitted — that bare-shape row still parses downstream. When a crawl IS run
    with response storage, `content_type`/`status`/`tech` flow through."""
    records: dict[str, dict] = {}
    with katana_jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(obj, dict):
                continue
            # katana -jsonl: {"request": {"endpoint": "..."}} or {"endpoint": "..."}.
            endpoint = ""
            req = obj.get("request")
            if isinstance(req, dict):
                endpoint = req.get("endpoint") or req.get("url") or ""
            endpoint = endpoint or obj.get("endpoint") or obj.get("url") or ""
            if not endpoint:
                continue
            endpoint = str(endpoint)
            # Pull response metadata when the crawl stored it (absent under
            # the default -or/-ob disk-saving flags; threaded forward if set).
            content_type = ""
            status = None
            tech = ""
            resp = obj.get("response")
            if isinstance(resp, dict):
                headers = resp.get("headers")
                if isinstance(headers, dict):
                    content_type = (
                        headers.get("content_type")
                        or headers.get("content-type")
                        or ""
                    )
                content_type = content_type or resp.get("content_type") or ""
                sc = resp.get("status_code")
                if isinstance(sc, int):
                    status = sc
                techs = resp.get("technologies") or obj.get("tech")
                if isinstance(techs, list):
                    tech = ",".join(str(t) for t in techs)
                elif techs:
                    tech = str(techs)
            rec = records.get(endpoint)
            if rec is None:
                rec = {"url": endpoint}
                records[endpoint] = rec
            if content_type and not rec.get("content_type"):
                rec["content_type"] = str(content_type)
            if status is not None and rec.get("response_status") is None:
                rec["response_status"] = status
            if tech and not rec.get("tech"):
                rec["tech"] = tech
    return [records[key] for key in sorted(records)]


def _ingest_args(args, urls_file: str):
    from types import SimpleNamespace
    return SimpleNamespace(
        db_path=args.db_path,
        source="web-discovery",
        input_file=urls_file,
        egress_blocked_hosts=None,
        engagement_dir=args.engagement_dir,
    )
