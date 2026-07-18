"""vigil assess command-run get — fetch a single command-run record with full previews."""
from __future__ import annotations

import json
from pathlib import Path

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "get",
        help="Fetch a single `vigil assess kali` command-run record by id, including previews and artifact refs",
    )
    p.add_argument("command_run_id", type=int, help="numeric id from `vigil assess command-run list`")
    p.add_argument("--json", dest="as_json", action="store_true", help="No-op: `command-run get` always emits JSON.")
    p.add_argument(
        "--live",
        action="store_true",
        help="Read the current on-disk stdout/stderr tails instead of relying only on finalized previews.",
    )
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        row = client.get(f"command-runs/{int(args.command_run_id)}")
    if getattr(args, "live", False):
        engagement_root = Path(cfg.engagement_dir).resolve()
        row["live_output"] = {
            "stdout": _tail_file(row.get("stdout_path"), engagement_root=engagement_root),
            "stderr": _tail_file(row.get("stderr_path"), engagement_root=engagement_root),
        }
    print(json.dumps(row, indent=2, ensure_ascii=False))


def _tail_file(
    raw_path: object, *, engagement_root: Path, max_bytes: int = 65_536
) -> str | None:
    if not raw_path:
        return None
    path = Path(str(raw_path)).resolve()
    if not path.is_relative_to(engagement_root):
        return "[refused: path outside engagement]"
    allowed_roots = (
        engagement_root / "scans" / "kali",
        engagement_root / "scans" / "host-exec",
    )
    if not any(path.is_relative_to(root) for root in allowed_roots):
        return "[refused: path is not a command-output artifact]"
    try:
        with path.open("rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            return handle.read().decode("utf-8", errors="replace")
    except OSError:
        return None
