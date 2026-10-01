from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from app.code_snapshot import (
    SEALED_SOURCE_MANIFEST_SCHEMA,
    SnapshotAttestationError,
    attest_verified_snapshot,
)


def test_snapshot_attestation_reports_every_metadata_mismatch(tmp_path: Path) -> None:
    engagement = tmp_path / "engagement"
    raw = b"source\n"
    payload = {
        "schema": SEALED_SOURCE_MANIFEST_SCHEMA,
        "repo_key": "example",
        "repo_name": "Example",
        "source_origin_path": "/example",
        "git": {"head": "", "branch": "", "dirty": None},
        "files": [
            {
                "file_path": name, "source_sha256": hashlib.sha256(raw).hexdigest(),
                "size": len(raw), "loc": 9, "language": "text", "executable": False,
            }
            for name in ["first.txt", "second.txt"]
        ],
        "excluded_entries": [],
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    snapshot = engagement / "tools" / "analysis-state" / "code-snapshots" / "example" / digest
    source = snapshot / "source"
    source.mkdir(parents=True)
    manifest_path = snapshot / "manifest.json"
    manifest_path.write_text(json.dumps({**payload, "source_path": str(source), "snapshot_digest": digest}))
    for item in payload["files"]:
        path = source / item["file_path"]
        path.write_bytes(raw)
        path.chmod(0o444)
    manifest_path.chmod(0o444)
    source.chmod(0o555)
    snapshot.chmod(0o555)
    try:
        with pytest.raises(SnapshotAttestationError) as error:
            attest_verified_snapshot(engagement_root=engagement, metadata={
                "repo_key": "example", "name": "Example", "repo_path": str(source),
                "source_origin_path": "/example", "source_kind": "directory",
                "snapshot_manifest_path": str(manifest_path), "snapshot_digest": digest,
                "commit_hash": "", "branch": "", "worktree_dirty": None,
            })
        assert "sealed source loc mismatch: first.txt" in str(error.value)
        assert "sealed source loc mismatch: second.txt" in str(error.value)
    finally:
        snapshot.chmod(0o755)
        source.chmod(0o755)
