"""vigil assess gau-endpoints — cache-aware gau → ingest-endpoints pipeline.

One verb that runs gau (or reuses a fresh cached corpus) and seats the URLs
into `work_items` with inline classification. The cache check makes reuse
explicit and loud — both the stderr message and the JSON `cache_reused`
field name the decision so the operator and the LLM can see it.

Each inner kali invocation still produces its own audit row; this wrapper
only composes them.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import sys
from pathlib import Path
from shlex import quote

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
    run_uro_dedup,
    utcnow_iso,
    write_cache_meta,
)
from assess.lib.kali import kali_exec


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "gau-endpoints",
        help=(
            "Run gau (cached) and ingest the resulting URLs into the work "
            "buffer with inline classification."
        ),
    )
    p.add_argument("target", help="Target domain or hostname (e.g. example.com).")
    p.add_argument(
        "--source",
        dest="source",
        default="gau",
        help="`source` value recorded on each work_items row (default: gau).",
    )
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
    add_engagement_flags(p)
    add_common_audit_defaults(p, default_phase="recon")
    p.set_defaults(func=run)


def _build_gau_argv(*, target: str, output_path: str, args: argparse.Namespace) -> list[str]:
    """Build the gau command, redirecting stdout to the cache file.

    gau's CLI uses double-dash for long flags only (`--o`, no `-o`), and
    its `--o` flag has had subtle quoting issues in past releases. We sidestep
    both by using shell stdout redirection — gau always writes its URL list
    to stdout in the absence of `--o`. The shell wrapper also lets us pipe
    through a quick `sort -u` to dedupe in-flight, which gau itself does
    not do.
    """
    flags: list[str] = []
    if args.subs:
        flags.append("--subs")
    if args.providers:
        flags.extend(["--providers", args.providers])
    argv = ["gau", *flags, target]
    command = " ".join(quote(part) for part in argv)
    return [
        "bash", "-lc",
        f"set -o pipefail; {command} | sort -u > {quote(output_path)}",
    ]


def _run_ingest_endpoints(
    *,
    source: str,
    input_file: Path,
    engagement_dir: Path,
) -> dict:
    """Invoke `ingest-endpoints` in-process via the same CLI entrypoint.

    Calling `cli.main(argv)` directly avoids a subprocess boundary while
    still routing through the same argparse + audit + backend-ingest code path
    `vigil assess ingest-endpoints` uses on the host. SystemExit raised by
    the inner command propagates as a non-zero exit, which we translate
    into AssessError so the wrapper can surface it cleanly.
    """
    from assess.cli import main as assess_main
    argv = [
        "--engagement-dir",
        str(engagement_dir),
        "ingest-endpoints",
        source,
        "--file",
        str(input_file),
    ]
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            assess_main(argv)
    except SystemExit as exc:
        if (exc.code or 0) != 0:
            raise AssessError(
                f"ingest-endpoints exited {exc.code}"
            ) from exc
    return {"returncode": 0}


def _summarize_work_buffer(cfg, source: str) -> dict:
    """Read post-ingest counts for `source` from the backend work buffer.

    Scoped to the source we just wrote so concurrent ingests on other sources
    do not skew the numbers. Best-effort: a backend hiccup degrades to zeros
    rather than failing the whole gau run.
    """
    from collections import Counter

    from assess.lib.client import AssessmentClient

    try:
        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            rows = [
                r for r in client.get_all_pages("work-items")
                if (r.get("source") or "") == source
            ]
    except Exception:  # noqa: BLE001 - summary is best-effort
        return {"work_items_total": 0, "work_items_pending": 0, "work_items_skipped": 0, "top_clusters": []}

    pending = sum(1 for r in rows if r.get("status") == "pending")
    skipped = sum(1 for r in rows if r.get("status") == "skipped")
    clusters: Counter = Counter(
        r.get("cluster_key")
        for r in rows
        if r.get("status") == "pending" and r.get("cluster_key")
    )
    return {
        "work_items_total": len(rows),
        "work_items_pending": pending,
        "work_items_skipped": skipped,
        "top_clusters": [{"cluster_key": k, "count": int(n)} for k, n in clusters.most_common(10)],
    }


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    current_cache_key = gau_cache_key(
        subs=bool(args.subs),
        providers=args.providers,
    )
    paths = resolve_pipeline_paths(cfg, target=args.target, cache_key=current_cache_key)

    decision = decide_cache_reuse(
        paths,
        target=args.target,
        refresh=bool(args.refresh),
        max_age_hours=float(args.max_cache_age_hours),
        cache_key=current_cache_key,
    )
    announce_cache_decision(decision, target=args.target)

    gau_argv: list[str] = []
    gau_status = "reused"
    gau_exit_code = 0

    if not decision.reused:
        # bash redirection (`> path`) will not create missing parent
        # directories, so ensure the namespaced work dir exists before
        # kali_exec hands the command off to the container.
        paths.work_dir.mkdir(parents=True, exist_ok=True)
        gau_argv = _build_gau_argv(
            target=args.target,
            output_path=paths.container_output_path,
            args=args,
        )
        try:
            result = kali_exec(
                gau_argv,
                technique="RECON",
                intent=f"Phase 1 gau collection for {args.target}",
                probe_kind="fingerprint",
                phase=args.phase,
                timeout=int(args.timeout),
                tool_name="gau",
                config=cfg,
            )
        except AssessError as exc:
            print(f"gau-endpoints: gau invocation failed: {exc}", file=sys.stderr)
            sys.exit(1)
        gau_exit_code = int(result.return_code or 0)
        gau_status = result.status or "unknown"
        if gau_exit_code != 0 or not paths.output_path.is_file():
            print(
                f"gau-endpoints: gau exited {gau_exit_code}; sidecar meta not "
                f"written so the next run will re-execute.",
                file=sys.stderr,
            )
            sys.exit(gau_exit_code or 1)
        line_count = count_lines(paths.output_path)
        meta = GauCacheMeta(
            target=args.target,
            ran_at_epoch=__import__("time").time(),
            ran_at_iso=utcnow_iso(),
            exit_code=gau_exit_code,
            line_count=line_count,
            output_path=str(paths.output_path),
            gau_argv=gau_argv,
            cache_key=current_cache_key,
        )
        write_cache_meta(paths.meta_path, meta)
    else:
        line_count = decision.meta.line_count if decision.meta else count_lines(paths.output_path)

    # uro structural dedup before ingest (shared with gau-secrets/gau-js so the
    # gau pipelines dedupe consistently): collapse near-duplicate URLs — same
    # path, different param VALUES; cache-busted asset variants — to one
    # representative so the work buffer is not flooded. A uro hiccup must never
    # cost the whole corpus, so on failure WARN and fall back to the raw output
    # (ingest's classifier dedupes by template again downstream).
    ingest_input = paths.output_path
    deduped_count: int | None = None
    deduped_path = paths.work_dir / "gau_deduped.txt"
    try:
        deduped_count = run_uro_dedup(
            paths,
            cfg=cfg,
            phase=args.phase,
            timeout=int(args.timeout),
            target=args.target,
            source_path=paths.output_path,
            dest_path=deduped_path,
        )
        ingest_input = deduped_path
    except AssessError as exc:
        print(
            f"gau-endpoints: uro dedup failed ({exc}); ingesting the undeduped "
            f"gau corpus instead.",
            file=sys.stderr,
        )

    try:
        _run_ingest_endpoints(
            source=args.source,
            input_file=ingest_input,
            engagement_dir=Path(cfg.engagement_dir),
        )
    except AssessError as exc:
        print(f"gau-endpoints: {exc}", file=sys.stderr)
        sys.exit(1)

    work_summary = _summarize_work_buffer(cfg, args.source)

    emit_pipeline_summary(
        {
            "verb": "gau-endpoints",
            "target": args.target,
            "cache_reused": decision.reused,
            "cache_decision_reason": decision.reason,
            "cache_age_hours": decision.age_hours,
            "gau_status": gau_status,
            "gau_exit_code": gau_exit_code,
            "gau_argv": gau_argv,
            "gau_output_path": str(paths.output_path),
            "gau_line_count": line_count,
            "deduped_count": deduped_count,
            "ingest_input_path": str(ingest_input),
            "ingest_source": args.source,
            **work_summary,
        }
    )
