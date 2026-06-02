"""vigil assess gau-secrets — gau → uro dedup → httpx body capture → trufflehog.

Body-fetch pipeline for secret extraction. Reuses cached gau output and
cached `bodies/` when present, then runs trufflehog filesystem mode against
the captured bodies. Defaults to `--no-verification`; operators can pass
`--verify` to enable trufflehog's verification step.
"""
from __future__ import annotations

import argparse
import json
from shlex import quote
import sys
import time
from pathlib import Path

from assess.lib.client import AssessError
from assess.lib.config import load_config
from assess.lib.gau_pipeline import (
    GauCacheMeta,
    add_common_audit_defaults,
    add_engagement_flags,
    announce_cache_decision,
    count_lines,
    decide_cache_reuse,
    emit_pipeline_summary,
    gau_cache_key,
    resolve_pipeline_paths,
    utcnow_iso,
    write_cache_meta,
)
from assess.lib.kali import kali_exec


# Extensions worth body-fetching for secret extraction. JS bundles, JSON
# config files, source maps, CSS (rare but sometimes carries inline
# tokens), and HTML (server-rendered config blocks). Everything else is
# either binary noise (images, fonts, archives) or unlikely to carry
# textual credentials.
_BODY_FETCH_EXTENSIONS: frozenset[str] = frozenset({
    ".js", ".mjs", ".cjs",
    ".json", ".jsonp",
    ".map",
    ".html", ".htm",
    ".xml", ".rss", ".atom",
    ".txt", ".env",
})

# Inert extensions that should never enter the httpx body-fetch list, even
# when uro keeps them (uro is structural — it does not know that fonts
# hold no secrets). Mirrors the conservative end of `_INERT_TYPES` in
# `lib/classify_buckets.py` plus a few CSS/font binaries httpx would
# happily download otherwise.
_INERT_DROP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf", ".ttc",
    ".mp3", ".mp4", ".webm", ".avi", ".mov", ".flac", ".wav", ".ogg",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".7z",
    ".exe", ".dll", ".so", ".dylib",
    ".css",  # rarely carries secrets; skip to keep body-fetch volume sane
})


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "gau-secrets",
        help=(
            "Body-fetch pipeline: gau (cached) → uro dedup → httpx "
            "-store-response → trufflehog filesystem scan."
        ),
    )
    p.add_argument("target", help="Target domain or hostname (e.g. example.com).")
    p.add_argument(
        "--subs",
        action="store_true",
        help="Pass --subs to gau so subdomain URLs are included.",
    )
    p.add_argument(
        "--providers",
        dest="providers",
        default="",
        help="Comma-separated provider list (e.g. 'wayback,otx,commoncrawl').",
    )
    p.add_argument(
        "--verify",
        dest="verify",
        action="store_true",
        help="Enable trufflehog secret verification.",
    )
    p.add_argument(
        "--cap-body-bytes",
        dest="cap_body_bytes",
        type=int,
        default=1048576,
        help=(
            "Max bytes per body httpx will store (default 1 MB). "
            "Larger bodies are truncated; trufflehog still scans the "
            "truncated content."
        ),
    )
    p.add_argument(
        "--max-targets",
        dest="max_targets",
        type=int,
        default=0,
        help=(
            "Cap on how many URLs are body-fetched (0 = no cap). Useful "
            "for sanity-checking the pipeline before a full run."
        ),
    )
    p.add_argument(
        "--reuse-bodies",
        dest="reuse_bodies",
        action="store_true",
        help=(
            "Skip the httpx body-fetch step if bodies/ already contains "
            "files. The trufflehog scan still runs against the existing "
            "bodies. Use when iterating on detector flags."
        ),
    )
    add_engagement_flags(p, allow_db_override=False)
    add_common_audit_defaults(p, default_phase="recon")
    p.set_defaults(func=run)


def _ensure_workdir(paths) -> None:
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    paths.bodies_dir.mkdir(parents=True, exist_ok=True)


def _directory_has_files(path: Path) -> bool:
    return path.is_dir() and any(entry.is_file() for entry in path.rglob("*"))


def _filter_url_list(input_path: Path, output_path: Path, max_targets: int) -> int:
    """Drop inert extensions and respect --max-targets when assembling the body-fetch list.

    The classifier already drops inert types from the work buffer; the
    httpx body-fetch path is parallel and does not consult the work
    buffer, so we re-filter here to avoid wasting bandwidth on fonts.
    Restricting to `_BODY_FETCH_EXTENSIONS` is intentionally narrow:
    HTML/JS/JSON cover the secret-bearing surface; expanding pulls in
    binary downloads of marginal value.

    Extension extraction parses the URL and looks only at the path
    component — looking at the full URL string would treat the dot in
    the hostname (`.com`, `.net`) as the file extension and drop every
    extensionless API endpoint.
    """
    from urllib.parse import urlparse
    kept = 0
    with input_path.open("r", encoding="utf-8", errors="replace") as src, \
         output_path.open("w", encoding="utf-8") as dst:
        for line in src:
            url = line.strip()
            if not url:
                continue
            try:
                path = urlparse(url).path or "/"
            except ValueError:
                continue
            path_lower = path.lower()
            last_dot = path_lower.rfind(".")
            last_slash = path_lower.rfind("/")
            # An "extension" only counts when the dot comes after the last
            # slash AND the segment after the dot has no slash itself —
            # otherwise we'd misread `/v1.2/users` as a `.2/users` extension.
            ext = ""
            if last_dot != -1 and last_dot > last_slash:
                candidate = path_lower[last_dot:]
                if "/" not in candidate:
                    ext = candidate
            if ext in _INERT_DROP_EXTENSIONS:
                continue
            # Allow extensionless URLs (likely API endpoints) through; only
            # restrict when an extension exists and isn't in the body-fetch
            # set.
            if ext and ext not in _BODY_FETCH_EXTENSIONS:
                continue
            dst.write(url + "\n")
            kept += 1
            if max_targets and kept >= max_targets:
                break
    return kept


def _run_uro(paths, *, cfg, args, source_path: Path, dest_path: Path) -> int:
    """Run uro inside the runtime container to structurally dedupe URLs."""
    container_src = f"{paths.container_work_dir}/{source_path.name}"
    container_dst = f"{paths.container_work_dir}/{dest_path.name}"
    cmd = [
        "bash", "-lc",
        f"uro -i {quote(container_src)} -o {quote(container_dst)}",
    ]
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"uro structural dedup for {args.target}",
        probe_kind="fingerprint",
        phase=args.phase,
        timeout=int(args.timeout),
        tool_name="uro",
        config=cfg,
    )
    if int(result.return_code or 0) != 0:
        raise AssessError(
            f"uro exited {result.return_code}; see {result.stderr_path}"
        )
    return count_lines(dest_path)


def _run_httpx_store_response(paths, *, cfg, args, target_list_path: Path) -> dict:
    """Run httpx -store-response into the bodies/ dir."""
    container_targets = f"{paths.container_work_dir}/{target_list_path.name}"
    container_bodies = paths.container_bodies_dir
    container_results = f"{paths.container_work_dir}/httpx_results.txt"
    cmd = [
        "bash", "-lc",
        (
            f"httpx -l {quote(container_targets)} -silent "
            f"-store-response -store-response-dir {quote(container_bodies)} "
            f"-mc 200,301,302,401,403 "
            f"-status-code -content-length -title -tech-detect "
            f"-follow-redirects -threads 20 -rate-limit 30 "
            f"-response-size-to-save {int(args.cap_body_bytes)} "
            f"-o {quote(container_results)}"
        ),
    ]
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"httpx body capture for {args.target}",
        probe_kind="fingerprint",
        phase=args.phase,
        timeout=int(args.timeout),
        tool_name="httpx",
        config=cfg,
    )
    if int(result.return_code or 0) != 0:
        raise AssessError(
            f"httpx exited {result.return_code}; see {result.stderr_path}"
        )
    bodies_count = sum(1 for _ in paths.bodies_dir.rglob("*") if _.is_file())
    return {
        "bodies_captured": bodies_count,
        "httpx_results_path": str((paths.work_dir / "httpx_results.txt")),
    }


def _run_trufflehog(paths, *, cfg, args) -> dict:
    """Scan bodies/ with trufflehog filesystem mode."""
    container_bodies = paths.container_bodies_dir
    container_out = f"{paths.container_work_dir}/trufflehog.json"
    verify_flag = "" if args.verify else "--no-verification"
    cmd = [
        "bash", "-lc",
        (
            f"trufflehog filesystem {quote(container_bodies)} "
            f"--no-update {verify_flag} --concurrency 8 --json "
            f"> {quote(container_out)}"
        ),
    ]
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"trufflehog secret scan over bodies for {args.target}",
        probe_kind="fingerprint",
        phase=args.phase,
        timeout=int(args.timeout),
        tool_name="trufflehog",
        config=cfg,
    )
    return_code = int(result.return_code or 0)
    if return_code not in (0, 183):  # 183 = trufflehog "found secrets" exit
        raise AssessError(
            f"trufflehog exited {return_code}; see {result.stderr_path}"
        )

    th_path = paths.work_dir / "trufflehog.json"
    detector_counts: dict[str, int] = {}
    findings: list[dict] = []
    if th_path.is_file():
        with th_path.open("r", encoding="utf-8", errors="replace") as fh:
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
                source_meta = row.get("SourceMetadata") or {}
                fs = (source_meta.get("Data") or {}).get("Filesystem") or {}
                findings.append({
                    "detector": detector,
                    "verified": bool(row.get("Verified")),
                    "file": fs.get("file"),
                    "line": fs.get("line"),
                    "raw_preview": str(row.get("Raw") or "")[:120],
                })
    return {
        "trufflehog_path": str(th_path),
        "verify_enabled": bool(args.verify),
        "detector_counts": dict(sorted(detector_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        "findings_count": len(findings),
        "findings_preview": findings[:25],  # avoid flooding the LLM with everything
    }


def _maybe_run_gau(paths, *, args, cfg, current_cache_key: str) -> tuple[bool, dict]:
    """Reuse cached gau output if valid; otherwise run gau and persist meta.

    Returns (cache_reused, decision_payload) — the wrapper merges the
    payload into the final summary. The cache key is computed by the
    caller so the same value is used for both `decide_cache_reuse` and
    `resolve_pipeline_paths`.
    """
    decision = decide_cache_reuse(
        paths,
        target=args.target,
        refresh=bool(args.refresh),
        max_age_hours=float(args.max_cache_age_hours),
        cache_key=current_cache_key,
    )
    announce_cache_decision(decision, target=args.target)
    if decision.reused:
        return True, {
            "cache_reused": True,
            "cache_decision_reason": decision.reason,
            "cache_age_hours": decision.age_hours,
            "gau_argv": [],
        }
    flags: list[str] = []
    if args.subs:
        flags.append("--subs")
    if args.providers:
        flags.extend(["--providers", args.providers])
    argv = ["gau", *flags, args.target]
    command = " ".join(quote(part) for part in argv)
    cmd = [
        "bash", "-lc",
        f"set -o pipefail; {command} | sort -u > {quote(paths.container_output_path)}",
    ]
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"gau collection for {args.target} (secrets pipeline)",
        probe_kind="fingerprint",
        phase=args.phase,
        timeout=int(args.timeout),
        tool_name="gau",
        config=cfg,
    )
    rc = int(result.return_code or 0)
    if rc != 0 or not paths.output_path.is_file():
        raise AssessError(f"gau exited {rc}; aborting pipeline")
    line_count = count_lines(paths.output_path)
    write_cache_meta(
        paths.meta_path,
        GauCacheMeta(
            target=args.target,
            ran_at_epoch=time.time(),
            ran_at_iso=utcnow_iso(),
            exit_code=rc,
            line_count=line_count,
            output_path=str(paths.output_path),
            gau_argv=cmd,
            cache_key=current_cache_key,
        ),
    )
    return False, {
        "cache_reused": False,
        "cache_decision_reason": decision.reason,
        "cache_age_hours": None,
        "gau_argv": cmd,
    }


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    current_cache_key = gau_cache_key(
        subs=bool(args.subs),
        providers=args.providers,
    )
    paths = resolve_pipeline_paths(cfg, target=args.target, cache_key=current_cache_key)
    _ensure_workdir(paths)

    cache_payload: dict
    try:
        _, cache_payload = _maybe_run_gau(
            paths, args=args, cfg=cfg, current_cache_key=current_cache_key,
        )
    except AssessError as exc:
        print(f"gau-secrets: {exc}", file=sys.stderr)
        sys.exit(1)

    raw_count = count_lines(paths.output_path)

    # Filter inert extensions before uro so the dedup pass is operating on
    # the same set the body-fetch will eventually receive.
    filtered_path = paths.work_dir / "gau_filtered.txt"
    filtered_count = _filter_url_list(paths.output_path, filtered_path, args.max_targets)

    # uro structural dedup.
    deduped_path = paths.work_dir / "gau_deduped.txt"
    try:
        deduped_count = _run_uro(
            paths, cfg=cfg, args=args,
            source_path=filtered_path, dest_path=deduped_path,
        )
    except AssessError as exc:
        print(f"gau-secrets: {exc}", file=sys.stderr)
        sys.exit(1)

    httpx_summary: dict
    if args.reuse_bodies and _directory_has_files(paths.bodies_dir):
        httpx_summary = {
            "bodies_captured": sum(1 for _ in paths.bodies_dir.rglob("*") if _.is_file()),
            "httpx_results_path": str(paths.work_dir / "httpx_results.txt"),
            "reused_bodies": True,
        }
        print(
            f"[gau-secrets] reusing existing bodies/ ({httpx_summary['bodies_captured']} files); "
            f"skipping httpx body-fetch.",
            file=sys.stderr,
        )
    else:
        try:
            httpx_summary = _run_httpx_store_response(
                paths, cfg=cfg, args=args, target_list_path=deduped_path,
            )
        except AssessError as exc:
            print(f"gau-secrets: {exc}", file=sys.stderr)
            sys.exit(1)
        httpx_summary["reused_bodies"] = False

    try:
        truffle_summary = _run_trufflehog(paths, cfg=cfg, args=args)
    except AssessError as exc:
        print(f"gau-secrets: {exc}", file=sys.stderr)
        sys.exit(1)

    emit_pipeline_summary(
        {
            "verb": "gau-secrets",
            "target": args.target,
            **cache_payload,
            "gau_output_path": str(paths.output_path),
            "gau_raw_count": raw_count,
            "filtered_count": filtered_count,
            "deduped_count": deduped_count,
            "bodies_dir": str(paths.bodies_dir),
            **httpx_summary,
            **truffle_summary,
        }
    )
