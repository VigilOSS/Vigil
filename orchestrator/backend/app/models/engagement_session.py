from __future__ import annotations

from dataclasses import dataclass
from sqlite3 import Row


@dataclass(frozen=True, slots=True)
class EngagementSession:
    id: int
    engagement_id: int
    session_id: str
    session_path: str
    status: str
    merge_state: str
    assigned_findings_json: str
    created_at: str
    updated_at: str
    merged_at: str | None

    @classmethod
    def from_row(cls, row: Row) -> "EngagementSession":
        return cls(
            id=row["id"],
            engagement_id=row["engagement_id"],
            session_id=row["session_id"],
            session_path=row["session_path"],
            status=row["status"],
            merge_state=row["merge_state"],
            assigned_findings_json=row["assigned_findings_json"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            merged_at=row["merged_at"],
        )
