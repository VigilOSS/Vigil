"""vigil assess recon-status — read the recon pipeline digest.

A pure, read-only projection over ``scans/recon/recon-status.json`` (written by
``vigil assess recon`` after every stage) plus an optional cross-check against
the backend job row. This is what the operator polls and what the recon
completeness-assessor specialist ingests — "% complete + per-stage state +
counts + what's next" — so neither ever holds a blocking call to learn where the
pipeline is.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from assess.commands import recon as _recon
from assess.lib.client import AssessError
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "recon-status",
        help="Show the recon pipeline digest (per-stage state, counts, what's next).",
    )
    p.add_argument("--job-id", dest="job_id", type=int, default=None,
                   help="Also cross-check the backend job row (lazy-finalizes it via the exit marker).")
    p.add_argument("--json", dest="as_json", action="store_true", help="Emit the digest as JSON.")
    p.set_defaults(func=run)


def _load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _digest(status: dict) -> dict:
    stages = status.get("stages", []) or []
    settled = sum(1 for s in stages if s.get("state") in ("done", "skipped"))
    total = len(stages)
    pct = int(round(100 * settled / total)) if total else 0
    nxt = next((s for s in stages if s.get("state") in ("pending", "running", "failed")), None)
    return {
        "overall_state": status.get("overall_state"),
        "percent_complete": pct,
        "apexes": status.get("apexes", []),
        "job_id": status.get("job_id"),
        "started_at": status.get("started_at"),
        "updated_at": status.get("updated_at"),
        "stages": [
            {
                "label": s.get("label"),
                "state": s.get("state"),
                "exit_code": s.get("exit_code"),
                "counts": s.get("counts", {}),
            }
            for s in stages
        ],
        "next": (nxt or {}).get("label"),
    }


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    status = _load_json(_recon.status_path(cfg))
    if status is None:
        print("recon-status: no recon run found for this engagement "
              "(run `vigil assess recon <apexes>` first).", file=sys.stderr)
        sys.exit(1)

    digest = _digest(status)

    if args.job_id is not None:
        # job_status lazy-finalizes the row from the host-side exit marker, so a
        # detached recon job that has finished shows its terminal status here.
        try:
            from assess.lib.kali_jobs import job_status
            row = job_status(int(args.job_id), config=cfg)
            digest["job_status"] = row.get("status")
            digest["job_exit_code"] = row.get("exit_code")
        except AssessError as exc:
            digest["job_status"] = f"unavailable: {exc}"

    if args.as_json:
        print(json.dumps(digest, indent=2, ensure_ascii=False))
        return

    print(f"recon-status: {digest['overall_state']} — {digest['percent_complete']}% complete "
          f"({', '.join(digest['apexes'])})")
    for s in digest["stages"]:
        counts = " ".join(f"{k}={v}" for k, v in sorted((s.get("counts") or {}).items()))
        rc = "" if s.get("exit_code") in (None, 0) else f" rc={s['exit_code']}"
        print(f"  [{s['state']:<8}] {s['label']}{rc}  {counts}")
    if digest.get("job_status"):
        print(f"  job[{digest['job_id']}] backend status: {digest['job_status']}")
    if digest["next"] and digest["overall_state"] != "done":
        print(f"  next: {digest['next']}")
