"""aith assess web-discovery — composable web-probing pipeline.

Pipes the error-prone glue the LLM should not hand-roll into one synchronous,
audited command:

    de-noise hosts -> httpx liveness (lean, status-only) -> ingest the verdicts
    into the host-liveness ledger -> crawl the LIVE subset with katana ->
    (optional) ingest the crawled URLs into the work buffer (gf-bucketed).

Opinionated, safe-by-construction defaults (de-noised inputs, status-only bulk
httpx so it does not OOM, stdin-safe exec) but every tool knob stays a
first-class flag (`--ports`, `--katana-depth`, `--katana-extra-args`, …) so the
operator/LLM keeps full control. Runs synchronously (Tier-0b rule); each tool
stage writes its own audit row via kali_exec.
"""
from __future__ import annotations

import json
import shlex
import sys
from pathlib import Path

from assess.commands import ingest_endpoints
from assess.commands.ingest_httpx import ingest_httpx_results
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.discovery import denoise_hosts
from assess.lib.kali import kali_exec


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "web-discovery",
        help="Pipeline: de-noise -> httpx liveness -> ingest liveness ledger -> katana crawl -> (optional) work-buffer ingest.",
    )
    p.add_argument("hosts_file", help="Newline-delimited hosts/URLs (e.g. dns-discovery output)")
    p.add_argument("--ports", default="80,443", help="httpx port list (default: 80,443)")
    p.add_argument("--httpx-threads", dest="httpx_threads", default="50", help="httpx -threads (default 50)")
    p.add_argument("--httpx-rate-limit", dest="httpx_rate_limit", default="150", help="httpx -rate-limit (default 150)")
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


def run(args) -> None:
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
    live_host, live_container = _paths(cfg, "httpx_live.jsonl")
    httpx_cmd = [
        "httpx", "-l", denoised_container, "-p", str(args.ports),
        "-status-code", "-title", "-web-server", "-ip", "-json", "-silent",
        "-threads", str(args.httpx_threads), "-rate-limit", str(args.httpx_rate_limit),
        "-o", live_container,
    ]
    if args.tech_detect:
        httpx_cmd.append("-tech-detect")
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
          "run `aith assess fetch host-liveness` or coverage rollup to review.", file=sys.stderr)


def _katana_urls(katana_jsonl: Path) -> list[str]:
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
