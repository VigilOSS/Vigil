from __future__ import annotations

from dataclasses import dataclass
from sqlite3 import Row


@dataclass(frozen=True, slots=True)
class Engagement:
    id: int
    key: str
    target: str
    status: str
    engagement_root: str
    created_at: str
    updated_at: str
    engagement_type: str | None = None

    @classmethod
    def from_row(cls, row: Row) -> "Engagement":
        # ``engagement_type`` was added in the blue-engagement migration. Older
        # SELECT statements that don't pull the column still need to construct
        # an Engagement, so tolerate missing keys by checking the row's columns.
        engagement_type: str | None = None
        try:
            engagement_type = row["engagement_type"]
        except (IndexError, KeyError):
            engagement_type = None
        return cls(
            id=row["id"],
            key=row["key"],
            target=row["target"],
            status=row["status"],
            engagement_root=row["engagement_root"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            engagement_type=engagement_type,
        )
