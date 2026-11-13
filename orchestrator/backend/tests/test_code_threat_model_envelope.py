"""A threat model is stored as sent, so a request pasted inside it is refused.

`code-record threat-model` takes the model and its source identity as separate
fields. A model object that itself carries the request's identity keys and a
nested ``threat_model`` is the whole request pasted into the model field; storing
it would leave the real model one level down, where nothing reads it.
"""
from __future__ import annotations

from tests.test_code_analysis_api import _seed_repo


def _write(client, engagement_key: str, repo: dict, threat_model: dict):
    return client.post(
        f"/engagements/{engagement_key}/assessment/code/threat-model",
        json={
            "repo_id": repo["id"],
            "repo_generation": repo["active_generation"],
            "source_manifest_digest": repo["source_manifest_digest"],
            "threat_model": threat_model,
        },
    )


def test_a_request_envelope_inside_the_threat_model_is_refused(client, isolate_settings):
    engagement_key = "2026-11-14-code-threat-model-envelope"
    repo = _seed_repo(client, isolate_settings, engagement_key, repo_key="threat-envelope-repo")
    inner = {"assets": ["Acme notes"], "trust_boundaries": ["anonymous HTTP"]}

    refused = _write(client, engagement_key, repo, {
        "repo_id": repo["id"],
        "repo_generation": repo["active_generation"],
        "threat_model": inner,
    })

    assert refused.status_code == 422, refused.text
    message = str(refused.json()["detail"])
    assert "threat_model" in message and "repo_id" in message
    stored = client.get(
        f"/engagements/{engagement_key}/assessment/code/threat-model/{repo['id']}"
    ).json()
    assert stored["threat_model"] == {}

    accepted = _write(client, engagement_key, repo, inner)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["threat_model"] == inner
