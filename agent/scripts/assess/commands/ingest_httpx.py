"""aith assess ingest-httpx — ingest httpx -json output into the backend host-liveness ledger.

httpx writes liveness verdicts to scattered ``.jsonl`` files that nothing
reconciles back into the backend (the §10.5 gap: ``work_items.live_status`` is
100% NULL, 77 runs stranded on disk). This verb parses an httpx ``-json`` file,
classifies each host with the shared :mod:`assess.lib.reachability` verdict, and
upserts one ``assessment_host_liveness`` row per host so "is this host live now"
becomes a backend query that dispatch context can carry.

Post-run by design (lower risk than a streaming tail): re-run it after any
``httpx ... -json -o out.jsonl`` to fold the results into the ledger.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.lib import reachability
from assess.lib.client import AssessmentClient
from assess.lib.config import anchor_engagement_relative, load_config

# Stored verdicts the backend accepts. classify_probe may return a per-probe
# 'tls13_reset_recover_with_12' (a retry hint, not a stored class); collapse
# anything outside the stored set to 'unknown'.
_STORED_CLASSES = {"live", "dead", "blackholed", "unknown"}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest-httpx",
        help="Parse an httpx -json results file and upsert the host-liveness ledger.",
    )
    p.add_argument("results_file", help="Path to the httpx -json (.jsonl) output file")
    p.add_argument("--source", default="httpx", help="Source label stamped on each row (default: httpx)")
    p.add_argument(
        "--run-id",
        dest="run_id",
        type=int,
        default=None,
        help="Optional assessment_command_runs.id to attribute these verdicts to.",
    )
    p.add_argument(
        "--run-uuid",
        dest="run_uuid",
        default="",
        help="Optional command-run UUID to attribute these verdicts to.",
    )
    p.set_defaults(func=run)


def _host_name(obj: dict) -> str:
    """Pull the hostname (not the IP) from an httpx record.

    httpx's ``host`` field is the resolved IP; the name lives in ``input``/``url``.
    The backend normalizes (strips scheme/port), so a scheme-stripped authority
    is enough here.
    """
    for key in ("input", "url"):
        value = obj.get(key)
        if value:
            s = str(value)
            if "://" in s:
                s = s.split("://", 1)[1]
            return s.split("/", 1)[0]
    return str(obj.get("host") or "")


def _host_ip(obj: dict) -> str:
    ip = obj.get("host_ip") or obj.get("host") or ""
    if not ip:
        a = obj.get("a")
        if isinstance(a, list) and a:
            ip = a[0]
    return str(ip or "")


def _to_row(obj: dict, source: str, run_id, run_uuid: str) -> dict | None:
    host = _host_name(obj)
    if not host:
        return None
    host_ip = _host_ip(obj)
    status_code = obj.get("status_code")
    failed = bool(obj.get("failed"))
    verdict = reachability.classify_probe(
        http_code=status_code,
        remote_ip=host_ip,
        failed=failed,
    )
    if verdict not in _STORED_CLASSES:
        verdict = "unknown"
    tech = obj.get("tech")
    tech_str = ",".join(str(t) for t in tech) if isinstance(tech, list) else str(tech or "")
    tls = obj.get("tls")
    tls_str = json.dumps(tls, ensure_ascii=False) if isinstance(tls, (dict, list)) else str(tls or "")
    return {
        "host": host,
        "status_code": status_code if isinstance(status_code, int) else None,
        "scheme": str(obj.get("scheme") or ""),
        "final_url": str(obj.get("final_url") or obj.get("url") or ""),
        "host_ip": host_ip,
        "tech": tech_str,
        "title": str(obj.get("title") or ""),
        "webserver": str(obj.get("webserver") or obj.get("web_server") or ""),
        "tls": tls_str,
        "failed": failed,
        "reachability_class": verdict,
        "probed_at": str(obj.get("timestamp") or "") or None,
        "source": source,
        "source_run_id": run_id,
        "source_run_uuid": run_uuid or "",
    }


def parse_httpx_rows(results_path: Path, *, source: str, run_id=None, run_uuid: str = "") -> tuple[list[dict], int]:
    """Parse an httpx -json file into classified host-liveness rows.

    Returns (rows, parse_errors). Pure of network/CLI concerns so both the verb
    and the web-discovery pipeline can reuse it.
    """
    rows: list[dict] = []
    parse_errors = 0
    # A tool that found nothing (e.g. httpx with zero live hosts) does not create
    # its -o file. Treat a missing file as zero rows so pipeline callers don't crash.
    if not results_path.is_file():
        return rows, parse_errors
    with results_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                parse_errors += 1
                continue
            if not isinstance(obj, dict):
                continue
            row = _to_row(obj, source, run_id, run_uuid)
            if row is not None:
                rows.append(row)
    return rows, parse_errors


def ingest_httpx_results(
    results_path: Path,
    *,
    cfg,
    source: str = "httpx",
    run_id=None,
    run_uuid: str = "",
    client: AssessmentClient | None = None,
) -> dict:
    """Parse + upsert an httpx -json file into the backend host-liveness ledger.

    Returns a summary dict ``{upserted, rows, by_class, parse_errors}``. Callers
    may pass an existing ``client`` (the web-discovery pipeline reuses one); when
    omitted a client is opened and closed here.
    """
    rows, parse_errors = parse_httpx_rows(results_path, source=source, run_id=run_id, run_uuid=run_uuid)
    by_class: dict[str, int] = {}
    for r in rows:
        by_class[r["reachability_class"]] = by_class.get(r["reachability_class"], 0) + 1
    if not rows:
        return {"upserted": 0, "rows": 0, "by_class": by_class, "parse_errors": parse_errors}

    owns_client = client is None
    if owns_client:
        client = AssessmentClient(cfg.base_url, cfg.engagement_key)
    try:
        result = client.post("host-liveness", {"rows": rows})
    finally:
        if owns_client:
            client.close()
    upserted = result.get("upserted", 0) if isinstance(result, dict) else 0
    return {"upserted": int(upserted), "rows": len(rows), "by_class": by_class, "parse_errors": parse_errors}


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    results_path = Path(anchor_engagement_relative(args.results_file, args.engagement_dir))
    if not results_path.is_file():
        print(f"ingest-httpx: results file not found: {results_path}", file=sys.stderr)
        sys.exit(1)

    summary = ingest_httpx_results(
        results_path, cfg=cfg, source=args.source, run_id=args.run_id, run_uuid=args.run_uuid,
    )
    if summary["rows"] == 0:
        print(f"ingest-httpx: no usable httpx records in {results_path} "
              f"({summary['parse_errors']} unparseable line(s)).", file=sys.stderr)
        sys.exit(0)
    by_class = " ".join(f"{k}={v}" for k, v in sorted(summary["by_class"].items()))
    print(f"[ingest-httpx] upserted {summary['upserted']} host-liveness rows from "
          f"{results_path.name} ({by_class})", file=sys.stderr)
