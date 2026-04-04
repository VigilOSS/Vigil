"""argparse root + subcommand registration for the assess CLI."""
from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="assess.py",
        description="AI Threat Hunting — assessment coordination CLI",
    )
    parser.add_argument(
        "--engagement-dir",
        dest="engagement_dir",
        default=None,
        help="Engagement directory (default: $ENGAGEMENT_DIR or cwd if it contains scope.json)",
    )

    sub = parser.add_subparsers(dest="command")

    # Import and register every subcommand
    from assess.commands import (
        approve_exploit,
        check_coverage,
        check_exploit_gate,
        code_classify,
        code_coverage,
        code_dispatch,
        code_ingest,
        code_record_analysis,
        code_record_context,
        code_record_modules,
        code_record_threat_model,
        code_setup_lsp,
        dispatch,
        emit_event,
        fetch,
        ingest_endpoints,
        ingest_spec,
        launch_session,
        log_entry,
        merge_finding,
        merge_session,
        patch,
        post,
        record_chain,
        record_finding,
        record_proposal,
        record_surface,
        review_exploits,
    )

    for mod in (
        fetch,
        post,
        patch,
        emit_event,
        log_entry,
        record_finding,
        record_surface,
        record_chain,
        merge_finding,
        dispatch,
        ingest_endpoints,
        ingest_spec,
        check_coverage,
        review_exploits,
        check_exploit_gate,
        approve_exploit,
        launch_session,
        record_proposal,
        merge_session,
        code_ingest,
        code_classify,
        code_record_threat_model,
        code_record_modules,
        code_record_context,
        code_dispatch,
        code_record_analysis,
        code_coverage,
        code_setup_lsp,
    ):
        mod.register(sub)

    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)
