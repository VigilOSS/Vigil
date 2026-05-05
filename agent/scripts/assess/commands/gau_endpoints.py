"""aith assess gau-endpoints — cache-aware gau → ingest-endpoints pipeline.

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
import sqlite3
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
    resolve_db_path,
    resolve_pipeline_paths,
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
        f"{command} | sort -u > {quote(output_path)}",
    ]


def _run_ingest_endpoints(
    *,
    db_path: Path,
    source: str,
    input_file: Path,
    engagement_dir: Path,
) -> dict:
    """Invoke `ingest-endpoints` in-process via the same CLI entrypoint.

    Calling `cli.main(argv)` directly avoids a subprocess boundary while
    still routing through the same argparse + audit + DB write code path
    `aith assess ingest-endpoints` uses on the host. SystemExit raised by
    the inner command propagates as a non-zero exit, which we translate
    into AssessError so the wrapper can surface it cleanly.
    """
    from assess.cli import main as assess_main
    argv = [
        "--engagement-dir",
        str(engagement_dir),
        "ingest-endpoints",
        str(db_path),
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


def _summarize_work_buffer(db_path: Path, source: str) -> dict:
    """Read post-ingest counts directly from cases.db.

    Reading SQL avoids a backend round-trip and gives a deterministic
    snapshot the wrapper can return as part of its summary. We scope to
    the source we just wrote so concurrent ingests on other sources do
    not skew the numbers.
    """
    if not db_path.is_file():
        return {"work_items_total": 0, "work_items_pending": 0, "top_clusters": []}
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    conn.row_factory = sqlite3.Row
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM work_items WHERE source = ?", (source,)
        ).fetchone()[0]
        pending = conn.execute(
            "SELECT COUNT(*) FROM work_items WHERE source = ? AND status = 'pending'",
            (source,),
        ).fetchone()[0]
        skipped = conn.execute(
            "SELECT COUNT(*) FROM work_items WHERE source = ? AND status = 'skipped'",
            (source,),
        ).fetchone()[0]
        clusters = conn.execute(
            """
            SELECT cluster_key, COUNT(*) AS n
            FROM work_items
            WHERE source = ? AND status = 'pending' AND cluster_key IS NOT NULL
            GROUP BY cluster_key
            ORDER BY n DESC
            LIMIT 10
            """,
            (source,),
        ).fetchall()
    finally:
        conn.close()
    return {
        "work_items_total": int(total),
        "work_items_pending": int(pending),
        "work_items_skipped": int(skipped),
        "top_clusters": [{"cluster_key": r["cluster_key"], "count": int(r["n"])} for r in clusters],
    }


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    current_cache_key = gau_cache_key(
        subs=bool(args.subs),
        providers=args.providers,
    )
    paths = resolve_pipeline_paths(cfg, target=args.target, cache_key=current_cache_key)
    db_path = resolve_db_path(cfg, getattr(args, "db_override", None))

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

    # Ensure cases.db exists before we try to write into it. New temp DBs
    # passed via --db must be initialized; existing engagement DBs are
    # already migrated.
    if not db_path.is_file():
        from assess.lib.db import db_init
        db_path.parent.mkdir(parents=True, exist_ok=True)
        db_path.touch()
        db_init(str(db_path))

    try:
        _run_ingest_endpoints(
            db_path=db_path,
            source=args.source,
            input_file=paths.output_path,
            engagement_dir=Path(cfg.engagement_dir),
        )
    except AssessError as exc:
        print(f"gau-endpoints: {exc}", file=sys.stderr)
        sys.exit(1)

    work_summary = _summarize_work_buffer(db_path, args.source)

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
            "ingest_source": args.source,
            "db_path": str(db_path),
            **work_summary,
        }
    )
