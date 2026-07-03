"""vigil assess auth — list the engagement's stored session identities.

Surfaces EVERY stored identity for the engagement (optionally filtered to a
host) so the LLM can pick one for cross-account IDOR/BOLA testing. The store is
append-only + multi-identity (2026-07 redesign): logout-then-login on one host
holds both sessions simultaneously, and this verb is how a specialist enumerates
them before ``vigil assess kali --identity <name>`` replays as a chosen session.

Subverbs (subparser-with-subverbs pattern, mirrors ``http`` / ``artifact``):
  auth list          GET /credentials[?host=&include_dead=] — one row per identity

The list view carries metadata (auth_context, state, liveness_verdict, age,
last_probed_at) and the cookie NAME set + hosts, but NEVER raw cookie VALUES —
values are sensitive live session material and stay out of the enumeration view.

Read-only. Per-session liveness is verified/persisted by
``vigil assess auth-status --probe --identity <name>``, not here.
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import render_contract_epilog


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "auth",
        help="List the engagement's stored session identities (multi-identity store).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=render_contract_epilog("auth"),
    )
    action_sub = p.add_subparsers(dest="auth_action")
    action_sub.required = True

    sp_list = action_sub.add_parser(
        "list",
        help="List every stored identity (metadata + cookie names/hosts; no raw values).",
    )
    sp_list.add_argument(
        "--host",
        default="",
        help=(
            "Only identities usable at this host (matches a host_cookies bucket, "
            "subdomain-aware). Omit to list every stored identity."
        ),
    )
    sp_list.add_argument(
        "--include-dead",
        dest="include_dead",
        action="store_true",
        help=(
            "Also show probe-proven-dead sessions (state=dead), hidden by default. "
            "`stale` sessions are always shown — re-probe them with auth-status."
        ),
    )
    sp_list.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the raw identities map as JSON (LLM ingestion form).",
    )
    sp_list.set_defaults(func=_run_list)


def _client(args) -> AssessmentClient:
    cfg = load_config(args.engagement_dir)
    return AssessmentClient(cfg.base_url, cfg.engagement_key)


def _build_query(args) -> str:
    """Assemble the /credentials query string from the list flags.

    Mirrors the backend GET /credentials signature (host, include_dead) exactly;
    only non-empty/opted-in filters are emitted."""
    params: list[tuple[str, str]] = []
    host = getattr(args, "host", "") or ""
    if host:
        params.append(("host", host))
    if getattr(args, "include_dead", False):
        params.append(("include_dead", "true"))
    return urlencode(params, quote_via=quote)


def _humanize_age(last_seen_at: str | None) -> str:
    """Render ``now - last_seen_at`` as a compact human age (``3h``, ``2d``, ...).

    Returns ``-`` when there is no timestamp or it cannot be parsed — never
    raises, so a malformed row still lists."""
    if not last_seen_at or not isinstance(last_seen_at, str):
        return "-"
    raw = last_seen_at.strip().replace("Z", "+00:00")
    try:
        seen = datetime.fromisoformat(raw)
    except ValueError:
        return "-"
    if seen.tzinfo is None:
        seen = seen.replace(tzinfo=timezone.utc)
    delta = (datetime.now(timezone.utc) - seen).total_seconds()
    if delta < 0:
        return "0s"
    if delta < 60:
        return f"{int(delta)}s"
    if delta < 3600:
        return f"{int(delta // 60)}m"
    if delta < 86400:
        return f"{int(delta // 3600)}h"
    return f"{int(delta // 86400)}d"


def _cookie_names(material: dict) -> str:
    """Union of cookie NAMES across the flat view + every host bucket (no values).

    The list view must never leak live session cookie VALUES — only the names,
    so the LLM can tell sessions apart and reason about what an identity carries."""
    names: set[str] = set()
    flat = material.get("cookies")
    if isinstance(flat, dict):
        names.update(str(k) for k in flat)
    for bucket in material.get("host_cookies") or []:
        if isinstance(bucket, dict) and isinstance(bucket.get("cookies"), dict):
            names.update(str(k) for k in bucket["cookies"])
    if not names:
        return "-"
    ordered = sorted(names)
    shown = ",".join(ordered[:6])
    if len(ordered) > 6:
        shown += f",+{len(ordered) - 6}"
    return shown


def _cookie_hosts(material: dict) -> str:
    hosts = [
        str(b.get("host"))
        for b in (material.get("host_cookies") or [])
        if isinstance(b, dict) and b.get("host")
    ]
    if not hosts:
        return "-"
    ordered = sorted(set(hosts))
    shown = ",".join(ordered[:4])
    if len(ordered) > 4:
        shown += f",+{len(ordered) - 4}"
    return shown


def _render_identities(listing: dict) -> str:
    identities = listing.get("identities") if isinstance(listing, dict) else None
    identities = identities if isinstance(identities, dict) else {}
    if not identities:
        return "(no identities stored)"
    active = str(listing.get("active_identity") or "")
    header = [
        "identity",
        "auth_context",
        "state",
        "liveness",
        "age",
        "last_probed",
        "cookies",
        "hosts",
    ]
    lines = ["\t".join(header)]
    for name, material in identities.items():
        material = material if isinstance(material, dict) else {}
        label = f"{name}*" if name == active else str(name)
        lines.append(
            "\t".join(
                [
                    label,
                    str(material.get("auth_context") or "-"),
                    str(material.get("state") or "-"),
                    str(material.get("liveness_verdict") or "-"),
                    _humanize_age(material.get("last_seen_at")),
                    str(material.get("last_probed_at") or "-"),
                    _cookie_names(material),
                    _cookie_hosts(material),
                ]
            )
        )
    return "\n".join(lines)


def _run_list(args) -> None:
    client = _client(args)
    try:
        query = _build_query(args)
        endpoint = "credentials" if not query else f"credentials?{query}"
        listing = client.get_engagement(endpoint)
    finally:
        client.close()
    if not isinstance(listing, dict):
        listing = {"identities": {}, "active_identity": ""}
    if getattr(args, "as_json", False):
        print(json.dumps(listing, indent=2, ensure_ascii=False))
    else:
        print(_render_identities(listing))
