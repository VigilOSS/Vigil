"""Durable proof-evidence builders shared by backend API fixtures."""
from __future__ import annotations

import hashlib
import json as json_module
from pathlib import Path
from typing import Any

from app.config import settings


def post_artifact_backed_source_observation(
    client,
    endpoint: str,
    *,
    json: dict[str, Any],
):
    """Post a source observation backed by a real isolated-test artifact."""

    suffix = "/assessment/proof-receipts"
    prefix = "/engagements/"
    assert endpoint.startswith(prefix) and endpoint.endswith(suffix), endpoint
    engagement_key = endpoint[len(prefix) : -len(suffix)]
    assert engagement_key and "/" not in engagement_key, endpoint
    assert json.get("evidence_kind") == "source_observation"
    assert json.get("artifact_id") is None
    assert json.get("source_read_id") is None
    run_id = json.get("run_id")
    assert isinstance(run_id, int) and not isinstance(run_id, bool) and run_id > 0

    evidence = {
        "run_id": run_id,
        "expected_result": str(json.get("expected_result") or ""),
        "observed_result": str(json.get("observed_result") or ""),
    }
    evidence_bytes = (
        json_module.dumps(evidence, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    digest = hashlib.sha256(evidence_bytes).hexdigest()
    relative_path = f"evidence/fixture-source-observation-{run_id}-{digest[:16]}.json"
    engagement_dir = Path(settings.install_dir) / "agent" / "engagements" / engagement_key
    evidence_path = engagement_dir / relative_path
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        evidence_path.write_bytes(evidence_bytes)
    except OSError as exc:
        raise AssertionError(f"could not write fixture evidence {evidence_path}: {exc}") from exc

    artifact = client.post(
        endpoint.removesuffix("/proof-receipts") + "/artifacts",
        json={
            "path": relative_path,
            "kind": "proof",
            "media_type": "application/json",
        },
    )
    assert artifact.status_code == 201, artifact.text
    artifact_id = artifact.json().get("id")
    assert (
        isinstance(artifact_id, int)
        and not isinstance(artifact_id, bool)
        and artifact_id > 0
    ), artifact.text
    return client.post(endpoint, json={**json, "artifact_id": artifact_id})
