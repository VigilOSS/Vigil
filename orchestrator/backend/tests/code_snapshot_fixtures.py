"""Sealed source generations for fixtures that insert ``code_repos`` rows directly."""
from __future__ import annotations

import sqlite3


def seal_generation_files(
    connection: sqlite3.Connection,
    *,
    engagement_id: int,
    repo_id: int,
    repo_generation: int,
    source_manifest_digest: str,
    files: dict[str, int],
) -> None:
    """Seal one generation whose file roster is exactly ``files`` (path -> loc).

    A ``file:`` finding cites a file, and a line inside it, in the generation its
    binding names, so a fixture that binds findings needs the cited files here.
    """

    connection.execute(
        """
        INSERT INTO code_source_generations (
            engagement_id, repo_id, repo_generation, source_manifest_version,
            source_manifest_digest, source_review_identity_digest,
            source_snapshot_quality, repo_path, promoted_at
        ) VALUES (?, ?, ?, 'v1', ?, ?, 'verified', '', CURRENT_TIMESTAMP)
        """,
        (engagement_id, repo_id, repo_generation, source_manifest_digest, source_manifest_digest),
    )
    for file_path, loc in files.items():
        connection.execute(
            """
            INSERT OR IGNORE INTO code_files (engagement_id, repo_id, file_path, loc)
            VALUES (?, ?, ?, ?)
            """,
            (engagement_id, repo_id, file_path, loc),
        )
        file_id = connection.execute(
            "SELECT id FROM code_files WHERE engagement_id = ? AND repo_id = ? AND file_path = ?",
            (engagement_id, repo_id, file_path),
        ).fetchone()[0]
        connection.execute(
            """
            INSERT INTO code_source_generation_files (
                engagement_id, repo_id, repo_generation, file_id, file_path,
                file_hash, loc
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, repo_id, repo_generation, int(file_id), file_path, "ab" * 32, loc),
        )
