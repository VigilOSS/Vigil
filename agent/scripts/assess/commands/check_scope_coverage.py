"""assess.py check-scope-coverage — per-scope-entry coverage audit.

This is a higher-level sibling of `check-coverage`: where that command audits
the backend's `assessment_surfaces` table for surface-level resolution,
`check-scope-coverage` walks every entry in `scope.json` (bare hosts,
wildcards, or http URLs) and reports the coverage state across the
enumeration, collection, and consumption phases.

The audit is rolled up from three data sources:

- Backend `GET /engagements/{key}/assessment/services` — how many live
  endpoints each entry resolves to (used to ground wildcard expansion counts
  and flag apex-only deployments).
- Backend `GET /engagements/{key}/assessment/command-runs` filtered by
  `tool_bin` — detects whether `subfinder`/`puredns`/`dnsx`/`ffuf`/`httpx`
  ran (enum activity), whether `katana`/`gau`/`hakrawler` ran (collection
  activity), and how many `nuclei` sweeps targeted the entry. File-driven
  runs such as `nuclei -l /engagements/<key>/scans/targets.txt` are resolved
  back to the host engagement directory when the referenced target list is
  still present.
- Local `$DIR/cases.db` `work_items` grouped by status (pending / processing
  / done / skipped / error). Scoping is a coarse URL `LIKE '%<host>%'` match
  because the backend carries the canonical surface/service FK but the
  work buffer is local and ingest records aren't guaranteed to carry a
  service_id for every URL source. A consumption-stage gap marks entries
  that still have pending work with no `terminal_reason` set.

Scope-entry → service match heuristics (documented here so operators can
reproduce classifications by eye):

- ``bare_host`` (``target.example`` or ``https://api.target.example/v1``) matches
  services whose ``endpoint`` host segment equals the entry host exactly.
- ``wildcard`` (``*.target.example``) matches services whose endpoint host
  ends with ``.target.example`` OR equals ``target.example`` — both the apex and
  subdomains count so the wildcard entry owns the full wildcard surface.
- URL entries are normalized with `urllib.parse.urlsplit` and collapse to
  the host; the path is ignored intentionally because we're auditing host
  coverage, not path coverage.

Exit codes:

- ``0`` — all required-stage gates clean (or no stage required).
- ``1`` — one or more scope entries fail the required stage gate, or a
  backend/CLI error prevented audit completion.
- ``2`` — invocation-time failure (missing scope.json, unparseable config).

The ``--require-stage`` flag gates only the exit code. All discovery still
happens regardless, so a ``--verbose`` run without a stage gate is still a
useful full-scope overview.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex
import sqlite3
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config


# tool_bin labels that mark each stage of activity. We keep these lowercase
# and match against the lowercased argv[0] the backend stores because tool
# invocations inside Kali MCP use the canonical binary names.
_ENUM_TOOLS: frozenset[str] = frozenset({
    "subfinder",
    "puredns",
    "dnsx",
    "ffuf",
    "httpx",
    "amass",
    "assetfinder",
})
_COLLECTION_TOOLS: frozenset[str] = frozenset({
    "katana",
    "gau",
    "hakrawler",
    "waybackurls",
})
_REACTIVE_NUCLEI_TOOL = "nuclei"
_COMMAND_TARGET_FILE_FLAGS: frozenset[str] = frozenset({
    "-l",
    "-list",
    "--list",
    "-input",
    "--input",
    "-targets",
    "--targets",
    "-target-list",
    "--target-list",
})
_MAX_TARGET_FILE_BYTES = 2_000_000

# Services count as "live" when the backend state is anything except
# `down`/`filtered`. We prefer an allow list over a block list so new
# backend state values default to counting as live (they'd have to opt
# out explicitly), which keeps the audit optimistic during backend
# schema evolution.
_NON_LIVE_SERVICE_STATES: frozenset[str] = frozenset({"down", "filtered", "unreachable"})
_COMMAND_RUN_PAGE_SIZE = 1000


def register(subparsers: argparse._SubParsersAction) -> None:
    p = subparsers.add_parser(
        "check-scope-coverage",
        help="Audit coverage state per scope.json entry across enum/collect/consume phases",
    )
    p.add_argument(
        "--require-stage",
        dest="require_stage",
        choices=("enum", "collection", "consumption"),
        default=None,
        help=(
            "Gate the exit code on a stage. 'enum' requires every scope entry "
            "to have attempted enumeration (bare hosts satisfy this trivially). "
            "'collection' additionally requires katana/gau activity per entry. "
            "'consumption' additionally requires pending==0 or every remaining "
            "pending item to carry terminal_reason."
        ),
    )
    p.add_argument(
        "--json",
        dest="as_json",
        action="store_true",
        help="Emit the full JSON report to stdout instead of the human-readable summary",
    )
    p.add_argument(
        "--verbose",
        dest="verbose",
        action="store_true",
        help="Dump per-entry detail rows even when the summary passes (default: compact)",
    )
    p.set_defaults(func=run)


def run(args: argparse.Namespace) -> None:
    cfg = load_config(args.engagement_dir)
    scope_path = Path(cfg.engagement_dir) / "scope.json"
    if not scope_path.is_file():
        print(f"check-scope-coverage: scope.json not found at {scope_path}", file=sys.stderr)
        sys.exit(2)

    try:
        scope_data = json.loads(scope_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"check-scope-coverage: unable to read scope.json: {exc}", file=sys.stderr)
        sys.exit(2)

    raw_hosts = scope_data.get("hosts") or []
    if not isinstance(raw_hosts, list):
        print("check-scope-coverage: scope.json `hosts` must be a list", file=sys.stderr)
        sys.exit(2)

    entries = [_classify_entry(h) for h in raw_hosts if isinstance(h, str) and h.strip()]
    entries = [e for e in entries if e is not None]

    scope_metadata = _extract_scope_metadata(scope_data)

    client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        try:
            services = client.get("services")
        except AssessError as exc:
            print(f"check-scope-coverage: backend services fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        try:
            command_runs = _fetch_all_command_runs(client)
        except AssessError as exc:
            print(f"check-scope-coverage: backend command-runs fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
        try:
            summary = client.get("summary")
        except AssessError as exc:
            print(f"check-scope-coverage: backend summary fetch failed: {exc}", file=sys.stderr)
            sys.exit(1)
    finally:
        client.close()

    services_list = services if isinstance(services, list) else []
    command_runs_list = command_runs if isinstance(command_runs, list) else []
    summary_dict = summary if isinstance(summary, dict) else {}

    db_path = Path(cfg.engagement_dir) / "cases.db"
    try:
        work_by_host = _load_work_items_by_host(db_path)
    except sqlite3.Error as exc:
        print(f"check-scope-coverage: unable to read work buffer: {exc}", file=sys.stderr)
        sys.exit(1)

    report_entries: list[dict[str, Any]] = []
    for entry in entries:
        report_entries.append(
            _build_entry_report(
                entry=entry,
                services=services_list,
                command_runs=command_runs_list,
                engagement_dir=Path(cfg.engagement_dir),
                summary=summary_dict,
                work_by_host=work_by_host,
                scope_metadata=scope_metadata,
                required_stage=args.require_stage,
            )
        )

    overall_gaps = _collect_overall_gaps(report_entries, args.require_stage)
    ready = not overall_gaps

    report = {
        "engagement_key": cfg.engagement_key,
        "required_stage": args.require_stage,
        "entries": report_entries,
        "overall_gaps": overall_gaps,
        "ready": ready,
    }

    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _render_text(report, verbose=args.verbose)

    if not ready:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Entry classification and matching
# ---------------------------------------------------------------------------


def _classify_entry(raw: str) -> dict[str, Any] | None:
    """Return a dict with `scope_entry`, `entry_kind`, and `host` fields.

    URL entries collapse to their host (scheme + path ignored) so they share
    the matcher with bare hosts. We reject empty strings and any string that
    doesn't resolve to a non-empty host so downstream matching doesn't crash
    on malformed scope rows.
    """
    stripped = raw.strip()
    if not stripped:
        return None

    if stripped.startswith("*.") and len(stripped) > 2:
        host = _normalize_scope_host(stripped[2:])
        if not host:
            return None
        return {
            "scope_entry": stripped,
            "entry_kind": "wildcard",
            "host": host.lower(),
        }

    if "://" in stripped:
        try:
            parts = urlsplit(stripped)
        except ValueError:
            return None
        host = _normalize_scope_host(parts.hostname or "")
        if not host:
            return None
        return {
            "scope_entry": stripped,
            "entry_kind": "url",
            "host": host,
        }

    host = _normalize_scope_host(stripped)
    if not host:
        return None
    return {
        "scope_entry": stripped,
        "entry_kind": "bare_host",
        "host": host,
    }


def _normalize_scope_host(raw: str) -> str:
    return raw.strip().rstrip(".").lower()


def _endpoint_host(endpoint: str) -> str:
    """Return the lowercased host portion of a service endpoint.

    Services store `endpoint` as either a bare host (`target.example`), a
    host:port (`target.example:443`), or a full URL (`https://target.example/api`).
    We unify all three to a lowercased host string for matching.
    """
    raw = (endpoint or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        try:
            return (urlsplit(raw).hostname or "").lower()
        except ValueError:
            return ""
    # host[:port] form
    host = raw.split(":", 1)[0]
    return host


def _entry_matches_host(entry: dict[str, Any], host: str) -> bool:
    """Return True when `host` falls under the scope entry.

    Bare/URL entries require an exact host equality; wildcards accept the
    apex and any subdomain. The matcher is case-insensitive because DNS is.
    """
    if not host:
        return False
    entry_host = entry["host"]
    if entry["entry_kind"] == "wildcard":
        return host == entry_host or host.endswith("." + entry_host)
    return host == entry_host


def _command_run_mentions_host(
    row: dict[str, Any],
    entry: dict[str, Any],
    *,
    engagement_dir: Path | None = None,
) -> bool:
    """Return True when a command-run row references this scope entry.

    We search the command string (argv) and, when a command references a
    target-list file under `/engagements/<key>/...`, read that file from the
    host engagement directory. This catches MCP/Kali patterns such as
    `nuclei -l /engagements/<key>/scans/delta.txt`, where the command text
    contains only a mounted artifact path rather than the actual host names.
    """
    entry_host = entry["host"]
    command = (row.get("command") or "").lower()
    if command:
        if _command_text_mentions_host(command, entry):
            return True

    for host in _command_run_target_hosts(row, engagement_dir=engagement_dir):
        if _entry_matches_host(entry, host):
            return True
    return False


def _command_text_mentions_host(command: str, entry: dict[str, Any]) -> bool:
    host_pattern = re.escape(entry["host"])
    if entry["entry_kind"] == "wildcard":
        pattern = rf"(?<![a-z0-9.-])(?:[a-z0-9-]+\.)*{host_pattern}(?![a-z0-9.-])"
    else:
        pattern = rf"(?<![a-z0-9.-]){host_pattern}(?![a-z0-9.-])"
    return re.search(pattern, command, flags=re.IGNORECASE) is not None


def _command_run_target_hosts(row: dict[str, Any], *, engagement_dir: Path | None) -> set[str]:
    """Extract best-effort target hosts from command text, argv, and target files."""
    tokens = _command_tokens(row)
    hosts: set[str] = set()
    for token in tokens:
        host = _host_from_token(token)
        if host:
            hosts.add(host)

    if engagement_dir is None:
        return hosts

    for file_token in _target_file_tokens(tokens):
        path = _resolve_command_target_file(file_token, engagement_dir)
        if path is None:
            continue
        hosts.update(_hosts_from_target_file(path))
    return hosts


def _command_tokens(row: dict[str, Any]) -> list[str]:
    argv = row.get("argv")
    if isinstance(argv, list) and argv:
        return [str(item) for item in argv]
    command = str(row.get("command") or "")
    if not command:
        return []
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def _target_file_tokens(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    for idx, token in enumerate(tokens):
        if token in _COMMAND_TARGET_FILE_FLAGS and idx + 1 < len(tokens):
            targets.append(tokens[idx + 1])
            continue
        for flag in _COMMAND_TARGET_FILE_FLAGS:
            if token.startswith(flag + "="):
                targets.append(token.split("=", 1)[1])
                break
    return targets


def _resolve_command_target_file(raw: str, engagement_dir: Path) -> Path | None:
    value = raw.strip().strip("'\"")
    if not value:
        return None

    if value.startswith("/engagements/"):
        parts = Path(value).parts
        # /engagements/<engagement_key>/relative/path maps to the current
        # host engagement directory regardless of the fixture/key name.
        if len(parts) < 4:
            return None
        candidate = engagement_dir.joinpath(*parts[3:])
    else:
        path = Path(value).expanduser()
        candidate = path if path.is_absolute() else engagement_dir / path

    try:
        resolved = candidate.resolve()
        resolved.relative_to(engagement_dir.resolve())
    except (OSError, ValueError):
        return None
    if not resolved.is_file():
        return None
    try:
        if resolved.stat().st_size > _MAX_TARGET_FILE_BYTES:
            return None
    except OSError:
        return None
    return resolved


def _hosts_from_target_file(path: Path) -> set[str]:
    hosts: set[str] = set()
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                value = line.strip()
                if not value or value.startswith("#"):
                    continue
                token = value.split()[0]
                host = _host_from_token(token)
                if host:
                    hosts.add(host)
    except OSError:
        return hosts
    return hosts


def _host_from_token(raw: str) -> str:
    token = raw.strip().strip("'\"<>()[],;")
    if not token or token.startswith("-"):
        return ""
    if "://" in token:
        try:
            host = urlsplit(token).hostname or ""
        except ValueError:
            return ""
    elif "/" in token and "." in token:
        try:
            host = urlsplit("http://" + token).hostname or ""
        except ValueError:
            return ""
    else:
        host = token.split(":", 1)[0]
    host = host.rstrip(".").lower()
    if not _looks_like_host(host):
        return ""
    return host


def _looks_like_host(host: str) -> bool:
    if not host:
        return False
    if host == "localhost":
        return True
    if "." in host:
        return True
    parts = host.split(".")
    return len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


# ---------------------------------------------------------------------------
# Per-entry roll-up
# ---------------------------------------------------------------------------


def _build_entry_report(
    *,
    entry: dict[str, Any],
    services: list[dict[str, Any]],
    command_runs: list[dict[str, Any]],
    engagement_dir: Path,
    summary: dict[str, Any],
    work_by_host: dict[str, dict[str, int]],
    scope_metadata: dict[str, dict[str, Any]],
    required_stage: str | None,
) -> dict[str, Any]:
    live_hosts_set: set[str] = set()
    live_host_samples: list[str] = []
    total_services = 0

    for svc in services:
        endpoint_host = _endpoint_host(str(svc.get("endpoint") or ""))
        if not _entry_matches_host(entry, endpoint_host):
            continue
        total_services += 1
        state = str(svc.get("state") or "").lower()
        if state in _NON_LIVE_SERVICE_STATES:
            continue
        if endpoint_host and endpoint_host not in live_hosts_set:
            live_hosts_set.add(endpoint_host)
            if len(live_host_samples) < 10:
                live_host_samples.append(endpoint_host)

    enum_tools_seen: set[str] = set()
    collection_tools_seen: set[str] = set()
    reactive_nuclei_runs = 0

    for row in command_runs:
        if not _command_run_mentions_host(row, entry, engagement_dir=engagement_dir):
            continue
        bin_name = str(row.get("tool_bin") or "").lower()
        tool_name = str(row.get("tool_name") or "").lower()
        label = bin_name or tool_name
        if not label:
            continue
        if label in _ENUM_TOOLS:
            enum_tools_seen.add(label)
        if label in _COLLECTION_TOOLS:
            collection_tools_seen.add(label)
        if label == _REACTIVE_NUCLEI_TOOL:
            reactive_nuclei_runs += 1

    enum_attempted = bool(enum_tools_seen)
    enum_tool_list = sorted(enum_tools_seen)
    # Bare hosts (including URLs) have nothing to enumerate — mark them as
    # trivially enumerated so `--require-stage enum` doesn't flag a fully
    # apex-only scope. Wildcards still require a real enum tool.
    if entry["entry_kind"] in ("bare_host", "url") and not enum_attempted:
        enum_attempted = True
        enum_tool_list = ["bare_host"]

    collection_attempted = bool(collection_tools_seen)
    collection_tool_list = sorted(collection_tools_seen)

    host_work = work_by_host.get(entry["host"], {}) if entry["entry_kind"] != "wildcard" else _aggregate_wildcard_work(
        entry, work_by_host
    )

    work_queued = {
        "pending": int(host_work.get("pending", 0)),
        "processing": int(host_work.get("processing", 0)),
        "done": int(host_work.get("done", 0)),
        "skipped": int(host_work.get("skipped", 0)),
        "error": int(host_work.get("error", 0)),
        "pending_without_terminal_reason": int(host_work.get("pending_without_terminal_reason", 0)),
    }

    observation_count = _extract_observation_count(entry, summary, total_services)

    metadata = scope_metadata.get(entry["host"], {})
    entry_status = str(metadata.get("status") or "").lower()

    gaps: list[str] = []
    # Informational gap: enum ran but produced zero live hosts. Not a
    # --require-stage enum failure because enum ATTEMPTED is the gate.
    if entry["entry_kind"] == "wildcard" and enum_attempted and not live_hosts_set:
        gaps.append("no-live-hosts")
    if required_stage is None:
        pass
    elif required_stage == "enum":
        if not enum_attempted:
            gaps.append("no-enum")
    elif required_stage == "collection":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
    elif required_stage == "consumption":
        if not enum_attempted:
            gaps.append("no-enum")
        if not collection_attempted:
            gaps.append("no-collection")
        if not _consumption_satisfied(work_queued, entry_status):
            gaps.append("pending-work-remains")

    return {
        "scope_entry": entry["scope_entry"],
        "entry_kind": entry["entry_kind"],
        "host": entry["host"],
        "enum_attempted": enum_attempted,
        "enum_tools": enum_tool_list,
        "total_services": total_services,
        "live_hosts": len(live_hosts_set),
        "live_host_samples": live_host_samples,
        "collection_attempted": collection_attempted,
        "collection_tools": collection_tool_list,
        "observations": observation_count,
        "work_queued": work_queued,
        "reactive_nuclei_runs": reactive_nuclei_runs,
        "status": entry_status or None,
        "gaps": gaps,
    }


def _aggregate_wildcard_work(
    entry: dict[str, Any],
    work_by_host: dict[str, dict[str, int]],
) -> dict[str, int]:
    """Sum per-host work counts for a wildcard entry.

    We can't pre-index the work map by wildcard because new subdomains come
    and go between runs — iterate every host key once per wildcard and fold
    in the matching counts. Cheap for the sizes we care about (< 1k hosts).
    """
    aggregate: dict[str, int] = {}
    for host, counts in work_by_host.items():
        if not _entry_matches_host(entry, host):
            continue
        for key, val in counts.items():
            aggregate[key] = aggregate.get(key, 0) + int(val)
    return aggregate


def _consumption_satisfied(work_queued: dict[str, int], entry_status: str) -> bool:
    """Return True when the consumption gate is satisfied.

    A scope entry marked `status=deferred` in scope metadata is terminal —
    the operator decided to skip it, which is a valid terminal state that
    shouldn't block report-time readiness. Otherwise: pending==0 or every
    remaining pending item has terminal_reason set (= implicit consumption
    via classify-work's inert/skipped pipeline).
    """
    if entry_status == "deferred":
        return True
    if int(work_queued.get("pending", 0)) == 0:
        return True
    if int(work_queued.get("pending_without_terminal_reason", 0)) == 0:
        return True
    return False


def _extract_observation_count(
    entry: dict[str, Any],
    summary: dict[str, Any],
    total_services: int,
) -> int:
    """Best-effort request-observation count scoped to this entry.

    The `summary` endpoint exposes engagement-wide totals, not per-host
    breakdowns. When the total is small or when the entry owns every
    service, the engagement-wide count is a reasonable proxy; otherwise we
    fall back to 0 and let operators inspect the raw list via
    `assess.py fetch request-observations` if they need precision.
    """
    raw = summary.get("request_observation_count")
    try:
        total = int(raw) if raw is not None else 0
    except (TypeError, ValueError):
        total = 0
    if total <= 0:
        return 0
    total_services_all = 0
    try:
        total_services_all = int(summary.get("service_count") or 0)
    except (TypeError, ValueError):
        total_services_all = 0
    if total_services_all <= 0 or total_services <= 0:
        return total if total_services_all <= 0 and total_services <= 0 else 0
    # Pro-rate observations by the entry's share of total services. This is
    # deliberately rough — operators who need exact per-host counts should
    # use the raw fetch. The backend doesn't yet surface a per-host
    # request-observation rollup, so we avoid pretending otherwise.
    return round(total * total_services / total_services_all)


def _fetch_all_command_runs(client: AssessmentClient) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    while True:
        page = client.get(f"command-runs?limit={_COMMAND_RUN_PAGE_SIZE}&offset={offset}")
        if not isinstance(page, list):
            raise AssessError("backend command-runs fetch returned non-list payload")
        rows.extend(page)
        if len(page) < _COMMAND_RUN_PAGE_SIZE:
            return rows
        offset += _COMMAND_RUN_PAGE_SIZE


# ---------------------------------------------------------------------------
# scope.json metadata helpers
# ---------------------------------------------------------------------------


def _extract_scope_metadata(scope_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Parse optional per-host status metadata from scope.json.

    Supported shapes (in priority order):

    - ``host_metadata``: a dict keyed by host string, value is a dict with
      at least a `status` field.
    - ``deferred_hosts``: a list of hosts to treat as status=deferred.

    New schemas can be added by extending this parser rather than adding a
    new CLI flag — the CLI treats the metadata as advisory.
    """
    metadata: dict[str, dict[str, Any]] = {}
    raw_map = scope_data.get("host_metadata")
    if isinstance(raw_map, dict):
        for host, info in raw_map.items():
            if isinstance(host, str) and isinstance(info, dict):
                normalized_host = _normalize_scope_metadata_key(host)
                if normalized_host:
                    metadata[normalized_host] = dict(info)

    raw_deferred = scope_data.get("deferred_hosts")
    if isinstance(raw_deferred, list):
        for host in raw_deferred:
            if isinstance(host, str):
                normalized_host = _normalize_scope_metadata_key(host)
                if not normalized_host:
                    continue
                bucket = metadata.setdefault(normalized_host, {})
                if "status" not in bucket:
                    bucket["status"] = "deferred"
    return metadata


def _normalize_scope_metadata_key(raw: str) -> str:
    entry = _classify_entry(raw)
    if entry is None:
        return ""
    return str(entry["host"])


# ---------------------------------------------------------------------------
# cases.db work buffer
# ---------------------------------------------------------------------------


def _load_work_items_by_host(db_path: Path) -> dict[str, dict[str, int]]:
    """Return a ``{host: {status: count, ...}}`` rollup from the local DB.

    The mapping also tracks ``pending_without_terminal_reason`` so the
    consumption gate can distinguish "really pending" from "pending but
    deferred by classify-work". A missing DB yields an empty map rather
    than an error — offline/local-only workflows should still render
    audits so operators can spot drift.
    """
    if not db_path.is_file():
        return {}

    rows: list[tuple[str, str, int]] = []
    rows_with_reason: list[tuple[str, str, int]] = []
    conn = sqlite3.connect(str(db_path), timeout=5.0)
    try:
        conn.execute("PRAGMA busy_timeout=5000")
        cursor = conn.execute(
            """
            SELECT url, status, COUNT(*) AS total
            FROM work_items
            GROUP BY url, status
            """
        )
        rows = [(str(r[0] or ""), str(r[1] or ""), int(r[2] or 0)) for r in cursor.fetchall()]
        cursor = conn.execute(
            """
            SELECT url, COUNT(*) AS total
            FROM work_items
            WHERE status = 'pending' AND (terminal_reason IS NULL OR terminal_reason = '')
            GROUP BY url
            """
        )
        rows_with_reason = [(str(r[0] or ""), "pending_without_terminal_reason", int(r[1] or 0)) for r in cursor.fetchall()]
    finally:
        conn.close()

    agg: dict[str, dict[str, int]] = {}
    for url, status, count in rows + rows_with_reason:
        host = _endpoint_host(url)
        if not host:
            continue
        bucket = agg.setdefault(host, {})
        bucket[status] = bucket.get(status, 0) + count
    return agg


# ---------------------------------------------------------------------------
# Overall gate and rendering
# ---------------------------------------------------------------------------


def _collect_overall_gaps(entries: list[dict[str, Any]], required_stage: str | None) -> list[str]:
    if required_stage is None:
        return []
    messages: list[str] = []
    for entry in entries:
        stage_gaps = [g for g in entry.get("gaps", []) if g != "no-live-hosts"]
        if not stage_gaps:
            continue
        for gap in stage_gaps:
            messages.append(f"scope-entry: {entry['scope_entry']} — {gap}")
    return messages


def _render_text(report: dict[str, Any], *, verbose: bool) -> None:
    entries = report["entries"]
    ready = report["ready"]
    stage = report["required_stage"]
    header = f"scope-coverage: {'ok' if ready else 'blocked'}"
    if stage:
        header = f"{header} (stage={stage})"
    print(header)
    if not entries:
        print("  (no scope entries in scope.json `hosts`)")
        return

    if not verbose and ready:
        for entry in entries:
            live = entry["live_hosts"]
            samples = ", ".join(entry["live_host_samples"][:3]) if entry["live_host_samples"] else "-"
            print(
                f"  - {entry['scope_entry']} [{entry['entry_kind']}] live={live} "
                f"enum={'y' if entry['enum_attempted'] else 'n'} "
                f"collect={'y' if entry['collection_attempted'] else 'n'} "
                f"pending={entry['work_queued']['pending']} samples={samples}"
            )
        return

    for entry in entries:
        print(
            f"  - {entry['scope_entry']} [{entry['entry_kind']}] host={entry['host']}"
        )
        print(
            f"      enum: attempted={entry['enum_attempted']} tools={entry['enum_tools']}"
        )
        print(
            f"      live_hosts={entry['live_hosts']} total_services={entry['total_services']} samples={entry['live_host_samples']}"
        )
        print(
            f"      collection: attempted={entry['collection_attempted']} tools={entry['collection_tools']}"
        )
        print(
            f"      work_queued={entry['work_queued']}"
        )
        print(
            f"      observations={entry['observations']} reactive_nuclei_runs={entry['reactive_nuclei_runs']}"
        )
        if entry.get("status"):
            print(f"      status={entry['status']}")
        if entry["gaps"]:
            print(f"      gaps={entry['gaps']}")

    if report["overall_gaps"]:
        print("gaps:")
        for msg in report["overall_gaps"]:
            print(f"  - {msg}")
