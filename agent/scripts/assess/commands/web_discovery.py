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
from pathlib import Path
from types import SimpleNamespace

from assess.commands import host_exec, ingest_endpoints
from assess.commands.ingest_httpx import ingest_httpx_results
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.discovery import denoise_hosts
from assess.lib.kali import kali_exec
from assess.lib import runtime_route

# CR-5 — bulk httpx concurrency ceiling on macOS Docker Desktop. Every distinct
# destination IP is NAT-tracked by the host userspace proxy (com.docker.backend),
# so a high -threads bulk liveness pass over many hosts wedges the VM (I-001).
_DOCKER_DESKTOP_HTTPX_THREAD_CAP = 25


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
    p.add_argument("--katana-depth", dest="katana_depth", default="2", help="katana -d crawl depth (default 2)")
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
        help="cases.db path. When set, the crawled URLs are ingested into the work "
             "buffer (gf-bucketed) via ingest-endpoints. Relative paths anchor to the engagement dir.",
    )
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=1800, help="Per-tool --timeout seconds (default 1800)")
    p.set_defaults(func=run)


def _paths(cfg, name: str) -> tuple[Path, str]:
    host = Path(cfg.engagement_dir) / "scans" / "web-discovery" / name
    container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/{name}"
    return host, container


def _warn(message: str) -> None:
    print(f"WARN: {message}", file=sys.stderr)


def _host_dispatch(cmd, *, intent, tool_name, timeout, engagement_dir):
    """Run *cmd* via the audited host path (`host-exec`) — same audit fields as the
    container path (route='host_exec'). host_exec.run() ends in sys.exit(rc); we
    catch SystemExit and return a result object with the .return_code kali callers
    expect, so audit rows + downstream ingest are IDENTICAL regardless of route."""
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


# Backfill CR-added flags when a caller builds a bare args object (older callers /
# focused tests). argparse supplies these on the real CLI path; this only fills
# absent attributes so the new routing/clamp code never trips.
_ARG_DEFAULTS = {"runtime": "auto", "no_thread_clamp": False}


def _apply_arg_defaults(args) -> None:
    for name, default in _ARG_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def run(args) -> None:
    _apply_arg_defaults(args)
    cfg = load_config(args.engagement_dir)
    hosts_path = Path(anchor_engagement_relative(args.hosts_file, args.engagement_dir))
    if not hosts_path.is_file():
        print(f"web-discovery: hosts file not found: {hosts_path}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(cfg.engagement_dir) / "scans" / "web-discovery"
    out_dir.mkdir(parents=True, exist_ok=True)

    # --- Stage 0: de-noise -------------------------------------------------
    raw_lines = hosts_path.read_text(encoding="utf-8", errors="replace").splitlines()
    clean, dropped = denoise_hosts(raw_lines)
    if not clean:
        print("web-discovery: no hosts left after de-noise; nothing to probe.", file=sys.stderr)
        sys.exit(0)
    denoised_host, denoised_container = _paths(cfg, "denoised_hosts.txt")
    denoised_host.write_text("\n".join(clean) + "\n", encoding="utf-8")
    print(f"web-discovery: {len(clean)} hosts after de-noise ({dropped} dropped as noise)", file=sys.stderr)

    # --- Stage 1: httpx liveness (lean, status-only) -----------------------
    # CR-4 — route the BULK liveness pass to the host on macOS Docker Desktop
    # (avoids the per-dest-IP proxy wedge); container elsewhere / on override.
    # The katana crawl below stays in the container regardless (CR-5: exploit/
    # auth'd HTTP must not leave the isolated runtime).
    httpx_route = _route_for(args, "httpx")
    threads = _clamp_httpx_threads(args, route=httpx_route)
    live_host, live_container = _paths(cfg, "httpx_live.jsonl")
    # Both routes write to the same host file (the container path is the bind-
    # mounted same inode), so Stage 2 ingest is identical regardless of route.
    in_arg = str(denoised_host) if httpx_route == "host" else denoised_container
    out_arg = str(live_host) if httpx_route == "host" else live_container
    httpx_cmd = [
        "httpx", "-l", in_arg, "-p", str(args.ports),
        "-status-code", "-title", "-web-server", "-ip", "-json", "-silent",
        "-threads", str(threads), "-rate-limit", str(args.httpx_rate_limit),
        "-o", out_arg,
    ]
    if args.tech_detect:
        httpx_cmd.append("-tech-detect")
    if httpx_route == "host":
        res = _host_dispatch(
            httpx_cmd, intent="web-discovery: httpx liveness (status-only)",
            tool_name="httpx", timeout=int(args.stage_timeout), engagement_dir=args.engagement_dir,
        )
    else:
        res = kali_exec(
            httpx_cmd, technique="DISCOVERY", intent="web-discovery: httpx liveness (status-only)",
            probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
            engagement_dir=args.engagement_dir, tool_name="httpx",
        )
    if getattr(res, "return_code", 0) not in (0, None):
        print(f"web-discovery: httpx exited {res.return_code}; continuing with whatever it wrote.", file=sys.stderr)

    # --- Stage 2: ingest the liveness verdicts into the backend ledger -----
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        summary = ingest_httpx_results(live_host, cfg=cfg, source="web-discovery", client=client)
    by_class = " ".join(f"{k}={v}" for k, v in sorted(summary["by_class"].items()))
    print(f"web-discovery: liveness ledger upserted {summary['upserted']} hosts ({by_class or 'none'})", file=sys.stderr)

    # --- Stage 3: katana crawl of the live subset --------------------------
    katana_host, katana_container = _paths(cfg, "katana.jsonl")
    if not args.no_crawl:
        live_urls = _extract_live_urls(live_host)
        if live_urls:
            seed_host, seed_container = _paths(cfg, "live_urls.txt")
            seed_host.write_text("\n".join(live_urls) + "\n", encoding="utf-8")
            katana_cmd = [
                "katana", "-list", seed_container, "-jc", "-d", str(args.katana_depth),
                "-jsonl", "-silent", "-o", katana_container,
            ]
            if args.katana_extra_args:
                katana_cmd.extend(shlex.split(args.katana_extra_args))
            kres = kali_exec(
                katana_cmd, technique="DISCOVERY", intent="web-discovery: katana crawl of live subset",
                probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
                engagement_dir=args.engagement_dir, tool_name="katana",
            )
            if getattr(kres, "return_code", 0) not in (0, None):
                print(f"web-discovery: katana exited {kres.return_code}; crawl output may be partial.", file=sys.stderr)
            print(f"web-discovery: crawled {len(live_urls)} live URLs with katana", file=sys.stderr)
        else:
            print("web-discovery: no live URLs to crawl; skipping katana.", file=sys.stderr)

    # --- Stage 4: (optional) ingest crawled URLs into the work buffer ------
    if args.db_path and katana_host.is_file():
        urls = _katana_urls(katana_host)
        if urls:
            urls_host, _ = _paths(cfg, "katana_urls.txt")
            urls_host.write_text("\n".join(urls) + "\n", encoding="utf-8")
            ingest_endpoints.run(_ingest_args(args, str(urls_host)))
            print(f"web-discovery: ingested {len(urls)} crawled URLs into the work buffer", file=sys.stderr)

    print("web-discovery: done. Liveness in the backend ledger; "
          "run `vigil assess fetch host-liveness` or coverage rollup to review.", file=sys.stderr)


def _katana_urls(katana_jsonl: Path) -> list[str]:
    # TODO(typing P1): emit {url, content_type} JSON lines (instead of a bare
    # URL list) so ingest-endpoints can thread the crawled response's
    # Content-Type into `classify_type` — the typer is extension/path-shape-only
    # without it. Deferred deliberately: katana only records response headers
    # when the crawl is invoked with response storage enabled (see the katana
    # config in web_discovery), the `response.headers` jsonl shape is not pinned
    # by a schema doc here, and the `katana_urls.txt` writer + `_ingest_args`
    # text-file contract would all have to move to JSONL. Scoping that safely is
    # a separate change; the ingest-endpoints JSON `content_type` wiring is in
    # place, so any producer already emitting JSON rows benefits today.
    urls: list[str] = []
    with katana_jsonl.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # katana -jsonl: {"request": {"endpoint": "..."}} or {"endpoint": "..."}.
            endpoint = ""
            if isinstance(obj, dict):
                req = obj.get("request")
                if isinstance(req, dict):
                    endpoint = req.get("endpoint") or req.get("url") or ""
                endpoint = endpoint or obj.get("endpoint") or obj.get("url") or ""
            if endpoint:
                urls.append(str(endpoint))
    return sorted(set(urls))


def _ingest_args(args, urls_file: str):
    from types import SimpleNamespace
    return SimpleNamespace(
        db_path=args.db_path,
        source="web-discovery",
        input_file=urls_file,
        egress_blocked_hosts=None,
        engagement_dir=args.engagement_dir,
    )
