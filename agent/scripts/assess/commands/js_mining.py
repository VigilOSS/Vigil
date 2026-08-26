"""vigil assess js-mining — bounded JS endpoint + secret mining over crawled assets.

Closes the gap that the live engagement's hand-rolled ``fetch_js.sh`` filled
badly (a curl-at-3-req/s loop with a manually-pasted attribution header): routes
ALL target HTTP through the audited, header-injecting, rate-capped Vigil tooling.

Pipeline (runs AFTER the crawl stage, default-on):

    select .js URLs from the crawl output (katana.jsonl) / a passed URL list
      -> httpx -store-response over the .js subset (bounded, attribution header
         injected centrally by kali_exec, rate-capped to scope.rate_limit)
      -> jsluice (AST) endpoint extraction over each stored body, with the
         LinkFinder-style regex (gau_pipeline.extract_js_endpoints) as the
         offline fallback when jsluice yields nothing / is unavailable
      -> trufflehog filesystem secret scan over the stored bodies
      -> ingest extracted endpoints into the work buffer (source='js-extract')

The stage is **best-effort**: a failure in any step is logged and the stage
returns 0 so it never fails the recon pipeline. The asset count is bounded by
``--max-js`` so a huge crawl cannot blow up the fetch.

Tool choices follow the tool-adopt research: jsluice + trufflehog are ALREADY
installed in the runtime image; no new binary is required and no image rebuild.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from shlex import quote
from urllib.parse import urlparse

from assess.commands import ingest_endpoints
from assess.lib import scope
from assess.lib.config import anchor_engagement_relative, load_config
from assess.lib.gau_pipeline import extract_js_endpoints, resolve_js_endpoint
from assess.lib.kali import kali_exec

_JS_SUFFIXES = (".js", ".mjs", ".cjs")
_DEFAULT_MAX_JS = 200


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "js-mining",
        help="Bounded JS asset mining: fetch crawled .js -> jsluice/regex endpoint "
             "extraction -> trufflehog secret scan -> ingest endpoints. Best-effort.",
    )
    p.add_argument(
        "urls_file",
        nargs="?",
        default="",
        help="URL list (one per line) OR a katana -jsonl file to mine .js assets from. "
             "Defaults to the web-discovery crawl output (scans/web-discovery/katana.jsonl).",
    )
    p.add_argument("--target", dest="target", default="",
                   help="Host fallback for relative endpoints (defaults to the .js asset's own host).")
    p.add_argument("--max-js", dest="max_js", type=int, default=_DEFAULT_MAX_JS,
                   help=f"Max number of .js assets to fetch + mine (default {_DEFAULT_MAX_JS}; 0 = no cap).")
    p.add_argument("--httpx-rate-limit", dest="httpx_rate_limit", default="30",
                   help="httpx -rate-limit for the body fetch (default 30; clamped to scope.rate_limit).")
    p.add_argument("--httpx-threads", dest="httpx_threads", default="20",
                   help="httpx -threads for the body fetch (default 20).")
    p.add_argument("--cap-body-bytes", dest="cap_body_bytes", type=int, default=2097152,
                   help="Max bytes per stored body (default 2 MB).")
    p.add_argument("--verify", dest="verify", action="store_true",
                   help="Enable trufflehog verification (off by default).")
    p.add_argument("--no-secrets", dest="no_secrets", action="store_true",
                   help="Skip the trufflehog secret scan (endpoint extraction still runs).")
    p.add_argument("--no-ingest", dest="no_ingest", action="store_true",
                   help="Extract + scan but do NOT ingest endpoints into the backend "
                        "work buffer (ingest is on by default).")
    p.add_argument("--stage-timeout", dest="stage_timeout", type=int, default=900,
                   help="Per-tool --timeout seconds (default 900).")
    p.set_defaults(func=run)


_ARG_DEFAULTS = {
    "urls_file": "",
    "target": "",
    "max_js": _DEFAULT_MAX_JS,
    "httpx_rate_limit": "30",
    "httpx_threads": "20",
    "cap_body_bytes": 2097152,
    "verify": False,
    "no_secrets": False,
    "no_ingest": False,
    "stage_timeout": 900,
}


def _apply_arg_defaults(args) -> None:
    for name, default in _ARG_DEFAULTS.items():
        if not hasattr(args, name):
            setattr(args, name, default)


def _warn(message: str) -> None:
    print(f"WARN: js-mining: {message}", file=sys.stderr)


def _paths(cfg, name: str) -> tuple[Path, str]:
    host = Path(cfg.engagement_dir) / "scans" / "web-discovery" / "js-mining" / name
    container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/{name}"
    return host, container


def _is_js_url(url: str) -> bool:
    bare = url.split("?", 1)[0].split("#", 1)[0].lower()
    return bare.endswith(_JS_SUFFIXES)


def _collect_js_urls(source_path: Path, max_js: int) -> list[str]:
    """Pull the .js URLs out of a plain URL list OR a katana -jsonl file.

    Auto-detects shape per line: a JSON object (katana -jsonl, with the URL at
    request.endpoint / endpoint / url) or a bare URL line. De-dupes, preserves
    first-seen order, and respects --max-js."""
    urls: list[str] = []
    seen: set[str] = set()
    if not source_path.is_file():
        return urls
    with source_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            candidate = ""
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    obj = None
                if isinstance(obj, dict):
                    req = obj.get("request")
                    if isinstance(req, dict):
                        candidate = req.get("endpoint") or req.get("url") or ""
                    candidate = candidate or obj.get("endpoint") or obj.get("url") or ""
            else:
                candidate = line
            candidate = str(candidate).strip()
            if not candidate or not _is_js_url(candidate):
                continue
            if candidate in seen:
                continue
            seen.add(candidate)
            urls.append(candidate)
            if max_js and len(urls) >= max_js:
                break
    return urls


def _resolve_source(args, cfg) -> Path:
    if args.urls_file:
        return Path(anchor_engagement_relative(args.urls_file, args.engagement_dir))
    return Path(cfg.engagement_dir) / "scans" / "web-discovery" / "katana.jsonl"


def _fetch_js_bodies(args, cfg, *, js_list_host: Path, bodies_host: Path, rate_limit: int) -> int:
    """httpx -store-response over the .js subset. Returns the stored body count.

    Runs in-container via kali_exec so the program attribution header is injected
    centrally (httpx is in the injectable set) and the run is audited. The rate
    limit is the scope-capped value computed by the caller."""
    js_list_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/{js_list_host.name}"
    bodies_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/{bodies_host.name}"
    cmd = [
        "httpx", "-l", js_list_container, "-silent",
        "-store-response", "-store-response-dir", bodies_container,
        "-mc", "200",
        "-follow-redirects",
        "-threads", str(args.httpx_threads),
        "-rate-limit", str(rate_limit),
        "-response-size-to-save", str(int(args.cap_body_bytes)),
    ]
    res = kali_exec(
        cmd, technique="RECON", intent="js-mining: JS-only body capture",
        probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir, tool_name="httpx",
    )
    if int(getattr(res, "return_code", 0) or 0) != 0:
        _warn(f"httpx body fetch exited {res.return_code}; mining whatever it stored.")
    if not bodies_host.is_dir():
        return 0
    return sum(1 for entry in bodies_host.rglob("*") if entry.is_file())


def _list_body_files(bodies_host: Path) -> list[Path]:
    if not bodies_host.is_dir():
        return []
    return sorted(entry for entry in bodies_host.rglob("*") if entry.is_file())


def _read_body_payload(body_path: Path) -> str:
    """Strip httpx's stored HTTP headers; return the response body for extraction."""
    raw = body_path.read_text(encoding="utf-8", errors="replace")
    marker = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    if marker in raw:
        return raw.split(marker, 1)[1]
    return raw


_REQUEST_URL_RE = None  # lazy


def _source_url_from_body(body_path: Path) -> str:
    """Recover the request URL httpx records on the first line of a stored body."""
    import re
    global _REQUEST_URL_RE
    if _REQUEST_URL_RE is None:
        _REQUEST_URL_RE = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)")
    try:
        head = body_path.read_text(encoding="utf-8", errors="replace")[:16384]
    except OSError:
        return ""
    m = _REQUEST_URL_RE.search(head)
    if not m:
        return ""
    candidate = m.group(1)
    if candidate.startswith(("http://", "https://")):
        return candidate
    host_m = re.search(r"^Host:\s*(\S+)", head, flags=re.IGNORECASE | re.MULTILINE)
    if not host_m:
        return ""
    scheme = "http" if body_path.name.lower().startswith("http-") else "https"
    return f"{scheme}://{host_m.group(1).strip()}{candidate}"


def _jsluice_endpoints(args, cfg, *, bodies_host: Path) -> tuple[list[str], bool]:
    """Run jsluice (AST) over the stored bodies dir. Returns (raw_urls, ran_ok).

    jsluice `urls` mode parses each JS file with a real AST and recovers endpoints
    the LinkFinder regex misses on concatenated/templated strings. Output is JSON
    lines with a `url` field. Runs in-container (jsluice is installed). On any
    failure the caller falls back to the regex extractor, so this is best-effort."""
    bodies_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/{bodies_host.name}"
    out_host, _ = _paths(cfg, "jsluice.jsonl")
    out_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/jsluice.jsonl"
    cmd = [
        "bash", "-lc",
        (
            f"find {quote(bodies_container)} -type f -print0 | "
            f"xargs -0 -r jsluice urls > {quote(out_container)} 2>/dev/null || true"
        ),
    ]
    res = kali_exec(
        cmd, technique="RECON", intent="js-mining: jsluice AST endpoint extraction",
        probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir, tool_name="jsluice",
    )
    if int(getattr(res, "return_code", 0) or 0) != 0:
        _warn(f"jsluice exited {res.return_code}; using the regex fallback.")
        return [], False
    urls: list[str] = []
    if out_host.is_file():
        with out_host.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(obj, dict):
                    u = obj.get("url") or obj.get("endpoint")
                    if u:
                        urls.append(str(u))
    return urls, True


def _host_matches_target(host: str, target: str) -> bool:
    target = (target or "").lower().strip().rstrip(".")
    if target.startswith(("http://", "https://")):
        target = urlparse(target).hostname or target
    if target.startswith("*."):
        target = target[2:]
    host = (host or "").lower().strip().rstrip(".")
    if not host or not target:
        return False
    return host == target or host.endswith("." + target)


def _run_trufflehog(args, cfg, *, bodies_host: Path) -> dict:
    """trufflehog filesystem scan over the stored bodies. Best-effort digest."""
    bodies_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/{bodies_host.name}"
    out_host, _ = _paths(cfg, "trufflehog.json")
    out_container = f"/engagements/{cfg.engagement_key}/scans/web-discovery/js-mining/trufflehog.json"
    verify_flag = "" if args.verify else "--no-verification"
    cmd = [
        "bash", "-lc",
        (
            f"trufflehog filesystem {quote(bodies_container)} --no-update "
            f"{verify_flag} --concurrency 8 --json > {quote(out_container)} || true"
        ),
    ]
    res = kali_exec(
        cmd, technique="RECON", intent="js-mining: trufflehog secret scan over JS bodies",
        probe_kind="fingerprint", phase="recon", timeout=int(args.stage_timeout),
        engagement_dir=args.engagement_dir, tool_name="trufflehog",
    )
    rc = int(getattr(res, "return_code", 0) or 0)
    if rc not in (0, 183):  # 183 = trufflehog "found secrets"
        _warn(f"trufflehog exited {rc}; secret digest may be empty.")
    detector_counts: dict[str, int] = {}
    findings: list[dict] = []
    if out_host.is_file():
        with out_host.open("r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                detector = str(row.get("DetectorName") or "unknown")
                detector_counts[detector] = detector_counts.get(detector, 0) + 1
                fs = ((row.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {}
                findings.append({
                    "detector": detector,
                    "verified": bool(row.get("Verified")),
                    "file": fs.get("file"),
                    "raw_preview": str(row.get("Raw") or "")[:120],
                })
    return {
        "trufflehog_path": str(out_host),
        "verify_enabled": bool(args.verify),
        "detector_counts": dict(sorted(detector_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "findings_count": len(findings),
        "findings_preview": findings[:25],
    }


def run(args) -> None:
    _apply_arg_defaults(args)
    cfg = load_config(args.engagement_dir)
    # `--engagement-dir` defaults to None; load_config resolves the real dir (cwd
    # scope.json or launcher session binding). Write it back so post-config reads — rate caps
    # and scope filtering — see the resolved path instead of None (which would raise
    # in rate_caps_for_dir and silently no-op the default-on recon JS stage).
    args.engagement_dir = cfg.engagement_dir
    # Extracted endpoints are ingested into the backend work buffer (the single
    # store) unless --no-ingest is passed; ingest is on by default so a full mine
    # never silently drops every extracted endpoint.
    work_host, _ = _paths(cfg, "")
    work_host.parent.mkdir(parents=True, exist_ok=True)

    source_path = _resolve_source(args, cfg)
    js_urls = _collect_js_urls(source_path, int(args.max_js))
    if not js_urls:
        print(f"js-mining: no .js assets found in {source_path}; nothing to mine.", file=sys.stderr)
        return

    # Rate cap: clamp the body-fetch httpx -rate-limit DOWN to the configured
    # global req/s ceiling (httpx -rate-limit is one global token bucket, so it
    # caps the aggregate fetch rate and bounds per-host only as a side effect);
    # unset keeps the conservative default (30). int() truncates a fractional cap
    # DOWN so the emitted rate never exceeds the ceiling; sub-1 caps are rejected
    # at `vigil engagement create`, and the max(1, …) floor only guards a
    # hand-edited scope so a 0 never stalls the fetch. Attribution header rides
    # automatically via kali_exec's central injector (httpx is in the injectable
    # set), so no manual header paste is needed.
    rate_cap, _ = scope.rate_caps_for_dir(args.engagement_dir)
    try:
        base_rate = int(args.httpx_rate_limit)
    except (TypeError, ValueError):
        base_rate = 30
    if rate_cap is not None:
        rate_limit = max(1, min(base_rate, int(rate_cap)))
        print(f"js-mining: global req/s ceiling {rate_cap} configured "
              f"(per-invocation; bounds per-host as a side effect); httpx "
              f"-rate-limit set to {rate_limit}.", file=sys.stderr)
    else:
        rate_limit = base_rate

    # Scope admission: an endpoint discovered INSIDE an in-scope .js bundle may point
    # at an out-of-scope host; drop those before extraction/ingest so off-scope hosts
    # never enter the work buffer (mirrors recon._apply_scope_filter). Degrades to no
    # filtering on a missing/malformed scope or an unauthored allowlist (admitting on
    # an empty allowlist would drop everything).
    try:
        _scope_doc = scope.load_scope(str(args.engagement_dir))
        _allow = scope.scope_entries(_scope_doc)
        _deny = scope.out_of_scope_entries(_scope_doc)
    except SystemExit:
        _allow, _deny = [], []

    js_list_host, _ = _paths(cfg, "js_targets.txt")
    js_list_host.parent.mkdir(parents=True, exist_ok=True)
    js_list_host.write_text("\n".join(js_urls) + "\n", encoding="utf-8")
    bodies_host, _ = _paths(cfg, "bodies")
    bodies_host.mkdir(parents=True, exist_ok=True)

    fetched = 0
    try:
        fetched = _fetch_js_bodies(args, cfg, js_list_host=js_list_host, bodies_host=bodies_host, rate_limit=rate_limit)
    except Exception as exc:  # noqa: BLE001 — best-effort stage
        _warn(f"body fetch errored ({type(exc).__name__}: {exc}); continuing with stored bodies.")

    body_files = _list_body_files(bodies_host)

    # Endpoint extraction: jsluice (AST) first, regex fallback over the same bodies.
    raw_endpoints: list[str] = []
    jsluice_ran = False
    try:
        jsluice_urls, jsluice_ran = _jsluice_endpoints(args, cfg, bodies_host=bodies_host)
        raw_endpoints.extend(jsluice_urls)
    except Exception as exc:  # noqa: BLE001
        _warn(f"jsluice errored ({type(exc).__name__}: {exc}); regex fallback only.")

    # The regex fallback always runs as a second source (it catches different
    # shapes than jsluice and is free over already-loaded bodies); resolution +
    # de-dupe below merges both. jsluice emits absolute URLs already; the regex
    # extractor emits raw endpoints resolved against the body's source URL.
    resolved: list[str] = []
    seen: set[str] = set()
    malformed: list[str] = []

    def _accept(url: str) -> None:
        if not url:
            return
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            # jsluice/regex output is untrusted parser input: a malformed URL
            # literal (e.g. an unbracketed IPv6-like authority) makes urlparse
            # raise ``Invalid IPv6 URL``. Quarantine it instead of letting one
            # bad literal abort the whole mining run and lose every good endpoint.
            malformed.append(url)
            return
        if args.target and host and not _host_matches_target(host, args.target):
            return
        # Drop endpoints on out-of-scope hosts (allow AND not deny). Only when an
        # allowlist is authored and the host is known; never drops hostless URLs.
        if _allow and host and not scope.host_admitted(host, _allow, _deny):
            return
        if url in seen:
            return
        seen.add(url)
        resolved.append(url)

    for u in raw_endpoints:
        _accept(u)

    for body in body_files:
        try:
            payload = _read_body_payload(body)
        except OSError:
            continue
        eps = extract_js_endpoints(payload)
        if not eps:
            continue
        source_url = _source_url_from_body(body) or (
            f"https://{args.target}/" if args.target else ""
        )
        if not source_url:
            continue
        for ep in eps:
            try:
                absolute = resolve_js_endpoint(ep, base_url=source_url)
            except ValueError:
                # resolve_js_endpoint urlparses the raw endpoint; a malformed
                # one is quarantined, not fatal (same untrusted-input rationale).
                malformed.append(ep)
                continue
            if absolute:
                _accept(absolute)

    endpoints_host, _ = _paths(cfg, "js_endpoints.txt")
    endpoints_host.write_text("\n".join(resolved) + "\n", encoding="utf-8")

    # Quarantine sidecar: malformed URL literals that could not be parsed. Kept
    # for a browser-semantic/salvage follow-up rather than silently dropped.
    if malformed:
        malformed_host, _ = _paths(cfg, "js_endpoints_malformed.txt")
        malformed_host.write_text("\n".join(malformed) + "\n", encoding="utf-8")
        _warn(
            f"{len(malformed)} malformed URL(s) quarantined to {malformed_host} "
            "(not fatal; good endpoints still mined)."
        )

    ingested = 0
    if not getattr(args, "no_ingest", False) and resolved:
        try:
            ingest_endpoints.run(_ingest_args(args, str(endpoints_host)))
            ingested = len(resolved)
        except SystemExit as exc:
            if (exc.code or 0) != 0:
                _warn(f"ingest-endpoints exited {exc.code}; endpoints written to {endpoints_host} but not ingested.")
        except Exception as exc:  # noqa: BLE001
            _warn(f"ingest errored ({type(exc).__name__}: {exc}); endpoints written to {endpoints_host}.")

    secrets: dict = {"skipped": True}
    if not args.no_secrets and body_files:
        try:
            secrets = _run_trufflehog(args, cfg, bodies_host=bodies_host)
        except Exception as exc:  # noqa: BLE001
            _warn(f"trufflehog errored ({type(exc).__name__}: {exc}).")
            secrets = {"error": str(exc)}

    print(json.dumps(
        {
            "verb": "js-mining",
            "source": str(source_path),
            "js_assets_selected": len(js_urls),
            "bodies_fetched": fetched,
            "bodies_scanned": len(body_files),
            "jsluice_ran": jsluice_ran,
            "endpoints_extracted": len(resolved),
            "endpoints_ingested": ingested,
            "endpoints_path": str(endpoints_host),
            "secrets": secrets,
        },
        ensure_ascii=False,
        indent=2,
    ))


def _ingest_args(args, urls_file: str):
    from types import SimpleNamespace
    return SimpleNamespace(
        source="js-extract",
        input_file=urls_file,
        egress_blocked_hosts=None,
        engagement_dir=args.engagement_dir,
    )
