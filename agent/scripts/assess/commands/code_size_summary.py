"""aith assess code-size-summary — summarize backend-indexed code size."""
from __future__ import annotations

from collections import Counter
import json
import sys
from typing import Any

from assess.lib.client import AssessmentClient
from assess.lib.config import load_config


_PAGE_SIZE = 10000
_LOC_BUCKETS = (
    ("0", 0, 0),
    ("1-100", 1, 100),
    ("101-500", 101, 500),
    ("501-1000", 501, 1000),
    ("1001-5000", 1001, 5000),
    (">5000", 5001, None),
)
_VENDOR_PARTS = (
    "/node_modules/",
    "/vendor/",
    "/third_party/",
    "/third-party/",
    "/external/",
    "/deps/",
    "/Pods/",
    "/Carthage/",
)
_GENERATED_PARTS = (
    "/generated/",
    "/gen/",
    "/build/",
    "/dist/",
    "/target/",
    "/coverage/",
    "/.next/",
    "/.nuxt/",
)
_GENERATED_SUFFIXES = (
    ".pb.go",
    ".pb.cc",
    ".pb.h",
    ".g.cs",
    ".designer.cs",
    ".min.js",
    ".bundle.js",
    ".map",
)


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "code-size-summary",
        help="Summarize backend code_files counts, LOC buckets, ownership splits, and large candidates",
    )
    p.add_argument("--repo-id", type=int, default=None, help="Filter by repository ID")
    p.add_argument(
        "--large-threshold",
        type=int,
        default=1000,
        help="Minimum LOC for critical/high large-file candidates (default 1000)",
    )
    p.add_argument("--top", type=int, default=20, help="Maximum large candidates to print (default 20)")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    p.set_defaults(func=run)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    files = _fetch_code_files(cfg, repo_id=getattr(args, "repo_id", None))
    summary = summarize_code_size(
        files,
        large_threshold=max(0, int(getattr(args, "large_threshold", 1000))),
        top=max(1, int(getattr(args, "top", 20))),
    )
    if getattr(args, "json", False):
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return
    _print_summary(summary)


def _fetch_code_files(cfg, *, repo_id: int | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    offset = 0
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        while True:
            endpoint = f"code/files?limit={_PAGE_SIZE}&offset={offset}"
            if repo_id is not None:
                endpoint += f"&repo_id={int(repo_id)}"
            page = client.get(endpoint)
            if not isinstance(page, list):
                print("code-size-summary: unexpected backend response", file=sys.stderr)
                sys.exit(1)
            rows.extend(row for row in page if isinstance(row, dict))
            if len(page) < _PAGE_SIZE:
                return rows
            offset += _PAGE_SIZE


def summarize_code_size(
    files: list[dict[str, Any]],
    *,
    large_threshold: int = 1000,
    top: int = 20,
) -> dict[str, Any]:
    by_classification: Counter[str] = Counter()
    loc_by_classification: Counter[str] = Counter()
    by_language: Counter[str] = Counter()
    by_status: Counter[str] = Counter()
    ownership_counts: Counter[str] = Counter()
    ownership_loc: Counter[str] = Counter()
    loc_buckets: Counter[str] = Counter()
    skip_reasons: Counter[str] = Counter()
    total_loc = 0
    large_candidates: list[dict[str, Any]] = []

    for row in files:
        loc = _int_value(row.get("loc"))
        total_loc += loc
        classification = str(row.get("classification") or "unclassified")
        language = str(row.get("language") or "unknown")
        status = str(row.get("analysis_status") or "unknown")
        by_classification[classification] += 1
        loc_by_classification[classification] += loc
        by_language[language] += 1
        by_status[status] += 1
        bucket = _loc_bucket(loc)
        loc_buckets[bucket] += 1
        skip_reason = str(row.get("skip_reason") or "").strip()
        if skip_reason:
            skip_reasons[skip_reason] += 1
        ownership = _ownership_bucket(row)
        ownership_counts[ownership] += 1
        ownership_loc[ownership] += loc
        if classification in {"critical", "high"} and loc >= large_threshold:
            large_candidates.append(
                {
                    "file_id": row.get("id"),
                    "repo_id": row.get("repo_id"),
                    "file_path": row.get("file_path"),
                    "classification": classification,
                    "loc": loc,
                    "language": language,
                    "ownership": ownership,
                    "analysis_status": status,
                    "skip_reason": skip_reason,
                }
            )

    large_candidates.sort(key=lambda item: (-int(item["loc"]), str(item["file_path"])))
    return {
        "total_files": len(files),
        "total_loc": total_loc,
        "by_classification": _counter_with_loc(by_classification, loc_by_classification),
        "by_language": dict(sorted(by_language.items())),
        "by_status": dict(sorted(by_status.items())),
        "loc_buckets": {label: loc_buckets.get(label, 0) for label, _, _ in _LOC_BUCKETS},
        "ownership": {
            key: {"files": ownership_counts.get(key, 0), "loc": ownership_loc.get(key, 0)}
            for key in ("app_owned", "generated", "vendor")
        },
        "skip_reasons": dict(sorted(skip_reasons.items())),
        "large_candidates": large_candidates[:top],
        "large_threshold": large_threshold,
    }


def _counter_with_loc(counts: Counter[str], loc_counts: Counter[str]) -> dict[str, dict[str, int]]:
    keys = sorted(set(counts) | set(loc_counts))
    return {key: {"files": counts.get(key, 0), "loc": loc_counts.get(key, 0)} for key in keys}


def _int_value(value: Any) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return 0


def _loc_bucket(loc: int) -> str:
    for label, low, high in _LOC_BUCKETS:
        if loc >= low and (high is None or loc <= high):
            return label
    return ">5000"


def _ownership_bucket(row: dict[str, Any]) -> str:
    path = "/" + str(row.get("file_path") or "").replace("\\", "/")
    lowered = path.lower()
    skip_reason = str(row.get("skip_reason") or "").lower()
    if "vendor" in skip_reason or any(part.lower() in lowered for part in _VENDOR_PARTS):
        return "vendor"
    if (
        "generated" in skip_reason
        or any(part.lower() in lowered for part in _GENERATED_PARTS)
        or any(lowered.endswith(suffix.lower()) for suffix in _GENERATED_SUFFIXES)
    ):
        return "generated"
    return "app_owned"


def _print_summary(summary: dict[str, Any]) -> None:
    print("=== Code Size Summary ===")
    print(f"total_files: {summary['total_files']}")
    print(f"total_loc: {summary['total_loc']}")
    print("\n--- Ownership ---")
    for key, row in summary["ownership"].items():
        print(f"{key}|files={row['files']}|loc={row['loc']}")
    print("\n--- LOC Buckets ---")
    for key, value in summary["loc_buckets"].items():
        print(f"{key}|{value}")
    print("\n--- Classification ---")
    for key, row in summary["by_classification"].items():
        print(f"{key}|files={row['files']}|loc={row['loc']}")
    print("\n--- Analysis Status ---")
    for key, value in summary["by_status"].items():
        print(f"{key}|{value}")
    if summary["skip_reasons"]:
        print("\n--- Skip Reasons ---")
        for key, value in summary["skip_reasons"].items():
            print(f"{key}|{value}")
    print(f"\n--- Critical/High Large Candidates (LOC >= {summary['large_threshold']}) ---")
    candidates = summary["large_candidates"]
    if not candidates:
        print("(none)")
        return
    for row in candidates:
        print(
            f"{row['loc']}|{row['classification']}|{row['ownership']}|"
            f"{row['analysis_status']}|{row['file_path']}"
        )
