"""Surface validation + jsonl sync — replaces lib/surfaces.sh."""
from __future__ import annotations

import json
from pathlib import Path

VALID_SURFACE_TYPES = frozenset({
    "auth_entry",
    "account_recovery",
    "object_reference",
    "privileged_write",
    "file_handling",
    "dynamic_render",
    "api_documentation",
    "workflow_token",
})

VALID_STATUSES = frozenset({
    "discovered",
    "covered",
    "not_applicable",
    "deferred",
})


def surface_file_path(engagement_dir: str) -> str:
    return str(Path(engagement_dir) / "surfaces.jsonl")


def validate_surface_type(surface_type: str) -> None:
    if surface_type not in VALID_SURFACE_TYPES:
        raise SystemExit(f"invalid surface_type: {surface_type}")


def validate_surface_status(status: str) -> None:
    if status not in VALID_STATUSES:
        raise SystemExit(f"invalid surface status: {status}")


def ensure_surface_file(engagement_dir: str) -> None:
    path = Path(surface_file_path(engagement_dir))
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.touch()


def upsert_surface_record(
    engagement_dir: str,
    surface_type: str,
    target: str,
    source: str,
    rationale: str = "",
    evidence_ref: str = "",
    status: str = "discovered",
) -> None:
    """Upsert a surface record in surfaces.jsonl."""
    ensure_surface_file(engagement_dir)
    sf = Path(surface_file_path(engagement_dir))

    rows: list[dict] = []
    seen = False
    for line in sf.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        row = json.loads(line)
        if row.get("surface_type") == surface_type and row.get("target") == target:
            row["source"] = source
            row["rationale"] = rationale
            row["evidence_ref"] = evidence_ref
            row["status"] = status
            seen = True
        rows.append(row)

    if not seen:
        rows.append({
            "surface_type": surface_type,
            "target": target,
            "source": source,
            "rationale": rationale,
            "evidence_ref": evidence_ref,
            "status": status,
        })

    tmp = sf.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as out:
        for row in rows:
            out.write(json.dumps(row, ensure_ascii=True) + "\n")
    tmp.rename(sf)
