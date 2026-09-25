"""Durable proof-evidence builders shared by backend API fixtures."""
from __future__ import annotations

import hashlib
import json as json_module
from pathlib import Path
from typing import Any

from app.config import settings


def completed_confirm_check(*receipt_ids: int) -> dict[str, Any]:
    """A completed attempted disproof for terminal verification fixtures."""

    return {
        "method": "Replay the claim against the expected guard",
        "attempted_falsification": "Check whether the expected guard defeats the claim",
        "expected_result": "The guard prevents the claimed outcome",
        "observed_result": "The claimed outcome still occurs",
        "proof_receipt_ids": list(receipt_ids),
        "completed": True,
    }


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
    assessment_base = endpoint.removesuffix("/proof-receipts")
    run = client.get(f"{assessment_base}/assessment-runs/{run_id}")
    assert run.status_code == 200, run.text
    producer_agent_id = run.json().get("producer_dispatch_agent_id")
    assert isinstance(producer_agent_id, str) and producer_agent_id, run.text

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
        assessment_base + "/artifacts",
        json={
            "path": relative_path,
            "kind": "proof",
            "media_type": "application/json",
            "producer_agent_id": producer_agent_id,
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
