"""vigil assess gau-js-endpoints — recover endpoints hidden in minified JS bundles.

LLMs and crawlers consistently miss routes that exist only inside JS bundles
(`/admin/users/delete` referenced from `app.bundle.js` but never linked in
HTML). This wrapper closes that gap:

1. Reuse the bodies/ directory from a prior `gau-secrets` run when present;
   otherwise run a JS-only body fetch (httpx -mc 200 over the .js subset of
   the gau corpus).
2. Run the embedded LinkFinder-derived regex over each `.js` body to extract
   endpoint strings.
3. Resolve each extraction against the response's source URL so relative
   paths become absolute.
4. Pipe the absolute URLs into `vigil assess ingest-endpoints` with
   `source='js-extract'` so inline classification scores them like any
   other URL and report-writer can audit which work_items came from JS
   extraction.

The wrapper does NOT shell out to a `linkfinder` binary because installing
it reproducibly inside the runtime image is messy. The regex itself lives
in `assess.lib.gau_pipeline.extract_js_endpoints`.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from pathlib import Path
from shlex import quote
from urllib.parse import urlparse

from assess.lib.client import AssessError
from assess.lib.config import load_config
from assess.lib.gau_pipeline import (
    add_common_audit_defaults,
    extract_js_endpoints,
    gau_cache_key,
    load_cache_meta,
    resolve_db_path,
    resolve_js_endpoint,
    resolve_pipeline_paths,
)
from assess.lib.kali import kali_exec


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "gau-js-endpoints",
        help=(
            "Extract endpoints hidden in JS bundles (LinkFinder-style "
            "regex over httpx-stored bodies) and ingest them into the "
            "work buffer."
        ),
    )
    p.add_argument("target", help="Target domain or hostname (used as the host fallback for relative endpoints).")
    p.add_argument(
        "--source",
        dest="source",
        default="js-extract",
        help="`source` value recorded on each work_items row (default: js-extract).",
    )
    # The verb is a post-processor, but the corpus-flag values are still
    # needed to locate the right `<target>/<cache_key>/bodies/` directory
    # on disk. They must match whatever was passed to the gau-secrets /
    # gau-endpoints run that produced the bodies; mismatch means the
    # bodies dir simply will not exist and the wrapper fails loudly.
    p.add_argument(
        "--subs",
        action="store_true",
        help=(
            "Locate the bodies/ dir produced by a gau-secrets/gau-endpoints "
            "run that used --subs. Must match the producer's flag."
        ),
    )
    p.add_argument(
        "--providers",
        dest="providers",
        default="",
        help=(
            "Locate the bodies/ dir produced by a gau-secrets/gau-endpoints "
            "run that used --providers. Must match the producer's value."
        ),
    )
    p.add_argument(
        "--bodies-dir",
        dest="bodies_dir_override",
        default="",
        help=(
            "Override the bodies/ directory path. Defaults to the "
            "namespaced "
            "<engagement_dir>/scans/gau-pipeline/<target>/<cache_key>/bodies/ "
            "computed from --subs and --providers."
        ),
    )
    p.add_argument(
        "--fetch-if-missing",
        dest="fetch_if_missing",
        action="store_true",
        help=(
            "When bodies/ is empty, run a JS-only httpx body fetch over "
            "the cached gau corpus first. Off by default so the wrapper "
            "is purely a post-processor unless the operator opts in."
        ),
    )
    p.add_argument(
        "--max-bodies",
        dest="max_bodies",
        type=int,
        default=0,
        help="Stop after processing this many JS bodies (0 = no cap).",
    )
    # This verb is a post-processor over an already-collected gau cache,
    # so the cache-reuse flags (--refresh, --max-cache-age-hours) that
    # `add_engagement_flags` would attach do not apply. Only --db is
    # meaningful here, for live-test routing.
    p.add_argument(
        "--db",
        dest="db_override",
        default=None,
        help=(
            "Override path to cases.db. Defaults to "
            "<engagement_dir>/cases.db when omitted."
        ),
    )
    add_common_audit_defaults(p, default_phase="recon")
    p.set_defaults(func=run)


# httpx body files have names like `https-example-com-2c8a1b...txt` with
# the request URL embedded in the first response line. The simplest
# reliable way to recover the original URL is to read it back from the
# stored response payload — httpx writes the request line on the first
# line of each capture file when -store-response is used.
_HTTPX_REQUEST_URL_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)",
)


def _extract_source_url_from_body(body_path: Path) -> str | None:
    """Read the first ~16 KiB and look for the request URL httpx records.

    httpx writes the full HTTP/1.1 request before the response when
    `-store-response` is used. The request line carries the URL directly
    on most builds; on builds where only the path is recorded, the Host
    header on a subsequent line completes the absolute URL.
    """
    try:
        head = body_path.read_text(encoding="utf-8", errors="replace")[:16384]
    except OSError:
        return None
    request_match = _HTTPX_REQUEST_URL_RE.search(head)
    if not request_match:
        return None
    candidate = request_match.group(1)
    if candidate.startswith(("http://", "https://")):
        return candidate
    # Path-only request line; recover host from the Host header and scheme
    # from httpx's sanitized body filename.
    host_match = re.search(r"^Host:\s*(\S+)", head, flags=re.IGNORECASE | re.MULTILINE)
    if not host_match:
        return None
    host = host_match.group(1).strip()
    scheme_hint = _scheme_hint_from_body_name(body_path)
    return f"{scheme_hint}://{host}{candidate}"


def _scheme_hint_from_body_name(body_path: Path) -> str:
    name = body_path.name.lower()
    if name.startswith("http-"):
        return "http"
    return "https"


def _list_js_bodies(bodies_dir: Path, max_bodies: int) -> list[Path]:
    """Return the JS body files httpx stored.

    httpx -store-response saves files with extensions matching the
    response's content-type, but the file names also include the URL.
    We accept any file whose stored URL ends in `.js` OR whose suffix
    is `.js` — covering both response-content extension and URL-shape.
    """
    candidates: list[Path] = []
    for entry in sorted(bodies_dir.rglob("*")):
        if not entry.is_file():
            continue
        if entry.suffix.lower() in {".js", ".mjs", ".cjs"}:
            candidates.append(entry)
            if max_bodies and len(candidates) >= max_bodies:
                break
            continue
        # Fall back to peek the stored request line for `.js` URLs
        try:
            head = entry.read_text(encoding="utf-8", errors="replace")[:4096]
        except OSError:
            continue
        m = _HTTPX_REQUEST_URL_RE.search(head)
        if m and m.group(1).split("?", 1)[0].endswith((".js", ".mjs", ".cjs")):
            candidates.append(entry)
        if max_bodies and len(candidates) >= max_bodies:
            break
    return candidates


def _directory_has_files(path: Path) -> bool:
    return path.is_dir() and any(entry.is_file() for entry in path.rglob("*"))


def _normalize_target_host(target: str) -> str:
    raw = (target or "").lower().strip()
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    target_host = (parsed.hostname or raw).strip().rstrip(".")
    if target_host.startswith("*."):
        target_host = target_host[2:]
    elif target_host.startswith("."):
        target_host = target_host[1:]
    return target_host


def _host_matches_target(host: str, target: str) -> bool:
    """Return true for exact target host or a real subdomain of it."""
    target_host = _normalize_target_host(target)
    host = (host or "").lower().strip().rstrip(".")
    return bool(host and target_host and (host == target_host or host.endswith("." + target_host)))


def _read_js_payload(body_path: Path) -> str:
    """Return the JS body content (httpx prepends headers — strip to just the body).

    httpx writes the response in HTTP wire format: status line, headers,
    blank line, body. We split on the first blank line. If the file
    contains no blank-line marker (very unusual), fall back to returning
    the whole file so the regex still has something to chew on.
    """
    raw = body_path.read_text(encoding="utf-8", errors="replace")
    marker = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    if marker in raw:
        return raw.split(marker, 1)[1]
    return raw


def _fetch_js_bodies(paths, *, cfg, args) -> int:
    """Run a JS-only httpx body fetch over the cached gau corpus.

    The path layout already keys by target + cache-key, so a missing
    `paths.output_path` definitively means no compatible gau run has
    been done for this target/flag combination — the operator needs to
    run gau-endpoints/gau-secrets first with matching flags.
    """
    meta = load_cache_meta(paths.meta_path)
    if not paths.output_path.is_file() or meta is None or meta.exit_code != 0:
        reason = "missing output/meta for this target+flag combination"
        if meta is not None and meta.exit_code != 0:
            reason = f"cached gau run exited {meta.exit_code}"
        raise AssessError(
            f"no usable cached gau corpus at {paths.output_path}: {reason}. "
            f"Run `vigil assess gau-endpoints {args.target}` first (with the "
            f"same --subs/--providers values) or pass --bodies-dir to point "
            f"at an existing bodies directory."
        )
    paths.work_dir.mkdir(parents=True, exist_ok=True)
    paths.bodies_dir.mkdir(parents=True, exist_ok=True)
    js_list = paths.work_dir / "js_targets.txt"
    kept = 0
    with paths.output_path.open("r", encoding="utf-8", errors="replace") as src, \
         js_list.open("w", encoding="utf-8") as dst:
        for line in src:
            url = line.strip()
            if not url:
                continue
            bare = url.split("?", 1)[0].split("#", 1)[0].lower()
            if not bare.endswith((".js", ".mjs", ".cjs")):
                continue
            dst.write(url + "\n")
            kept += 1
    if kept == 0:
        raise AssessError("no .js URLs in cached gau corpus; nothing to body-fetch")
    container_targets = f"{paths.container_work_dir}/{js_list.name}"
    container_bodies = paths.container_bodies_dir
    cmd = [
        "bash", "-lc",
        (
            f"httpx -l {quote(container_targets)} -silent -store-response "
            f"-store-response-dir {quote(container_bodies)} -mc 200 "
            f"-follow-redirects -threads 20 -rate-limit 30 "
            f"-response-size-to-save 2097152"
        ),
    ]
    result = kali_exec(
        cmd,
        technique="RECON",
        intent=f"JS-only body capture for {args.target}",
        probe_kind="fingerprint",
        phase=args.phase,
        timeout=int(args.timeout),
        tool_name="httpx",
        config=cfg,
    )
    if int(result.return_code or 0) != 0:
        raise AssessError(f"httpx exited {result.return_code}; see {result.stderr_path}")
    return kept


def _ingest_extracted_urls(*, db_path: Path, source: str, urls: list[str], engagement_dir: Path) -> int:
    """Write extracted URLs to a temp file and ingest in-process.

    `ingest-endpoints` reads stdin when no `--file` is passed, but calling
    cli.main() in-process means we cannot redirect stdin without monkey-
    patching sys.stdin. The cleaner approach is a temp file the inner
    command reads via --file; the file is unlinked on success.
    """
    if not urls:
        return 0
    import tempfile
    from assess.cli import main as assess_main
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="gau_js_extract_", delete=False, encoding="utf-8",
    )
    try:
        tmp.write("\n".join(urls) + "\n")
        tmp.close()
        argv = [
            "--engagement-dir",
            str(engagement_dir),
            "ingest-endpoints",
            str(db_path),
            source,
            "--file",
            tmp.name,
        ]
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                assess_main(argv)
        except SystemExit as exc:
            if (exc.code or 0) != 0:
                raise AssessError(f"ingest-endpoints exited {exc.code}") from exc
    finally:
        try:
            Path(tmp.name).unlink()
        except OSError:
            pass
    return len(urls)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    cache_key = gau_cache_key(
        subs=bool(args.subs),
        providers=args.providers,
    )
    paths = resolve_pipeline_paths(cfg, target=args.target, cache_key=cache_key)
    db_path = resolve_db_path(cfg, getattr(args, "db_override", None))

    bodies_dir = (
        Path(args.bodies_dir_override).expanduser().resolve()
        if args.bodies_dir_override
        else paths.bodies_dir
    )

    fetched_count = 0
    bodies_dir_has_files = _directory_has_files(bodies_dir)
    if not bodies_dir_has_files:
        if not args.fetch_if_missing:
            print(
                f"gau-js-endpoints: bodies dir {bodies_dir} is empty. "
                "Either run `vigil assess gau-secrets` first (with the same "
                "--subs/--providers values) to populate it, or pass "
                "--fetch-if-missing to body-fetch the .js subset of the "
                "cached gau corpus now.",
                file=sys.stderr,
            )
            sys.exit(1)
        try:
            fetched_count = _fetch_js_bodies(paths, cfg=cfg, args=args)
        except AssessError as exc:
            print(f"gau-js-endpoints: {exc}", file=sys.stderr)
            sys.exit(1)
        bodies_dir = paths.bodies_dir
    # Note: a cross-target target-mismatch check is no longer needed at the
    # default-path branch — the namespaced layout makes it impossible for
    # the default `<target>/<cache_key>/bodies/` to contain bodies for a
    # different target. The `--bodies-dir` override is still on the
    # operator's honor system, since they explicitly pointed there.

    js_bodies = _list_js_bodies(bodies_dir, int(args.max_bodies))

    extracted_total = 0
    resolved_unique: list[str] = []
    seen: set[str] = set()
    per_body: list[dict] = []

    fallback_base = (
        f"https://{args.target}/"
        if not args.target.startswith(("http://", "https://"))
        else args.target.rstrip("/") + "/"
    )

    for body in js_bodies:
        payload = _read_js_payload(body)
        endpoints = extract_js_endpoints(payload)
        extracted_total += len(endpoints)
        source_url = _extract_source_url_from_body(body) or fallback_base
        body_resolved = 0
        for ep in endpoints:
            absolute = resolve_js_endpoint(ep, base_url=source_url)
            if not absolute:
                continue
            # Constrain to the engagement target (or its subs) to avoid
            # ingesting URLs to unrelated CDNs that happened to be
            # referenced. Operators who want everything ingested can
            # post-process the JSON output and re-pipe.
            host = (urlparse(absolute).hostname or "").lower()
            if host and not _host_matches_target(host, args.target):
                continue
            if absolute in seen:
                continue
            seen.add(absolute)
            resolved_unique.append(absolute)
            body_resolved += 1
        per_body.append({
            "body": str(body),
            "source_url": source_url,
            "raw_endpoints": len(endpoints),
            "resolved_in_scope": body_resolved,
        })

    if not db_path.is_file():
        from assess.lib.db import db_init
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.touch()
        db_init(str(db_path))

    try:
        ingested = _ingest_extracted_urls(
            db_path=db_path,
            source=args.source,
            urls=resolved_unique,
            engagement_dir=Path(cfg.engagement_dir),
        )
    except AssessError as exc:
        print(f"gau-js-endpoints: {exc}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(
        {
            "verb": "gau-js-endpoints",
            "target": args.target,
            "bodies_dir": str(bodies_dir),
            "bodies_fetched": fetched_count,
            "js_bodies_scanned": len(js_bodies),
            "raw_endpoints_extracted": extracted_total,
            "unique_in_scope_urls": len(resolved_unique),
            "ingested_count": ingested,
            "ingest_source": args.source,
            "db_path": str(db_path),
            "per_body_preview": per_body[:25],
        },
        ensure_ascii=False,
        indent=2,
    ))
