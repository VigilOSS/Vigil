"""aith assess filter-scope — filter URL/host lists to scope.json hosts."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import Config, load_config
from assess.lib.scope import (
    host_from_token,
    host_in_scope,
    host_is_vendor_saas,
    load_scope,
    scope_entries,
)


def _vendor_saas_decided_hosts(cfg: Config) -> set[str]:
    """Return the set of hosts already carrying a recorded scope decision.

    The Vendor-SaaS scope checkpoint records its choice in the orchestrator
    backend (``assessment_dispatch_decisions`` with ``kind='scope_decision'``). A
    failed fetch returns the empty set so the warning fires conservatively
    (better to over-warn than miss a host the operator has not yet decided
    on).
    """
    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        try:
            rows = client.list_decisions(kind="scope_decision")
        except AssessError:
            return set()
    finally:
        client.close()
    decisions: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        host = host_from_token(str(payload.get("host") or payload.get("target") or ""))
        if host:
            decisions.add(host)
    return decisions


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "filter-scope",
        help="Filter a URL/host list to entries matching scope.json hosts",
    )
    p.add_argument(
        "input_file",
        nargs="?",
        default="-",
        help="Input file with one URL/host per line, or '-' for stdin",
    )
    p.add_argument(
        "-o",
        "--output",
        default=None,
        help="Write filtered lines to this file instead of stdout",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    scope = load_scope(cfg.engagement_dir)
    entries = scope_entries(scope)

    warned_vendor_hosts: set[str] = set()
    decided_hosts = _vendor_saas_decided_hosts(cfg)

    output_handle = None
    output_buffer: list[str] | None = None
    output_path: Path | None = None
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        input_path = Path(args.input_file) if args.input_file != "-" else None
        if input_path is not None and input_path.resolve() == output_path.resolve():
            output_buffer = []
        else:
            output_handle = output_path.open("w", encoding="utf-8")

    def _emit(line: str) -> None:
        if output_buffer is not None:
            output_buffer.append(line)
        elif output_handle is not None:
            output_handle.write(line)
        else:
            sys.stdout.write(line)

    try:
        for line in _iter_lines(args.input_file):
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            host = host_from_token(value)
            if not host_in_scope(host, entries):
                continue
            # Vendor-SaaS scope checkpoint: warn the first time an admitted
            # host's CNAME / rDNS shape matches a vendor SaaS suffix and the
            # operator has not yet recorded a scope_decision in the registry.
            # The filter does not block admission — the warning is advisory
            # so the operator can route it through the user-facing
            # checkpoint before recon-specialist dispatches.
            normalized_host = host.rstrip(".").lower() if host else ""
            if normalized_host and normalized_host not in warned_vendor_hosts and normalized_host not in decided_hosts:
                vendor = host_is_vendor_saas(normalized_host)
                if vendor:
                    warned_vendor_hosts.add(normalized_host)
                    print(
                        f"WARN: {normalized_host} matches vendor SaaS pattern '{vendor}'. "
                        f"Surface to operator before recon dispatch.",
                        file=sys.stderr,
                    )
            _emit(line)
    finally:
        if output_handle is not None:
            output_handle.close()
        if output_buffer is not None and output_path is not None:
            output_path.write_text("".join(output_buffer), encoding="utf-8")


def _iter_lines(input_file: str):
    """Yield input lines (with line terminators) without buffering the whole stream."""
    if input_file == "-":
        for line in sys.stdin:
            yield line
        return
    with Path(input_file).open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            yield line
