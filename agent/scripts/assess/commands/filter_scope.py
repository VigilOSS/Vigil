"""aith assess filter-scope — filter URL/host lists to scope.json hosts."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from assess.lib.config import load_config
from assess.lib.scope import (
    host_from_token,
    host_in_scope,
    host_is_vendor_saas,
    host_matches_wildcard_only_apex,
    load_scope,
    scope_entries,
    wildcard_only_entries_lacking_apex,
)


def _vendor_saas_decided_hosts(engagement_dir: str) -> set[str]:
    """Return the set of hosts already carrying a recorded scope decision.

    The Vendor-SaaS scope checkpoint records the user's choice in
    ``$DIR/agent-registry.json`` as ``{kind: "scope_decision", host: ...}``.
    Once a host has a decision row, the filter no longer needs to warn about
    it. A missing or unparseable registry returns the empty set so the
    warning fires conservatively (better to over-warn than miss a host the
    operator has not yet decided on).
    """
    registry_path = Path(engagement_dir) / "agent-registry.json"
    if not registry_path.is_file():
        return set()
    try:
        raw = registry_path.read_text(encoding="utf-8")
    except OSError:
        return set()
    if not raw.strip():
        return set()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return set()
    decisions: set[str] = set()
    rows = data if isinstance(data, list) else data.get("entries") if isinstance(data, dict) else None
    if not isinstance(rows, list):
        return set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("kind") or "").strip() != "scope_decision":
            continue
        host = row.get("host")
        if isinstance(host, str) and host.strip():
            decisions.add(host.strip().rstrip(".").lower())
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

    lines = _read_lines(args.input_file)
    warned_apexes: set[str] = set()
    warned_vendor_hosts: set[str] = set()
    decided_hosts = _vendor_saas_decided_hosts(cfg.engagement_dir)
    kept: list[str] = []
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        host = host_from_token(value)
        if host_in_scope(host, entries):
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
            kept.append(line)
            continue
        # Strict apex semantics: emit a one-line warning the first time we see
        # an apex host that would have matched under the old wildcard-only
        # semantics. The line is still excluded from output — the warning is
        # advisory so the operator can add an explicit apex entry if needed.
        normalized = host.rstrip(".").lower() if host else ""
        if normalized and normalized not in warned_apexes and host_matches_wildcard_only_apex(host, scope):
            warned_apexes.add(normalized)
            wildcard_label = _wildcard_label_for(scope, normalized)
            print(
                f"WARN: {value} matches {wildcard_label} but bare apex is excluded by "
                f"strict semantics. To include the apex, add '{normalized}' as an "
                f"explicit scope entry.",
                file=sys.stderr,
            )

    rendered = "".join(kept)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)


def _read_lines(input_file: str) -> list[str]:
    if input_file == "-":
        return sys.stdin.readlines()
    return Path(input_file).read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)


def _wildcard_label_for(scope: dict, apex_host: str) -> str:
    """Return the matching wildcard scope entry text for the warning, or a fallback."""
    for raw in wildcard_only_entries_lacking_apex(scope):
        stripped = raw.strip()
        if stripped.startswith("*.") and stripped[2:].rstrip(".").lower() == apex_host:
            return stripped
    return f"*.{apex_host}"
