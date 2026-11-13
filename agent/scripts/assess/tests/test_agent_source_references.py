from __future__ import annotations

from pathlib import Path

from assess.commands.agent import _code_source_identity_lines


class _Client:
    def get(self, endpoint):
        assert endpoint == "code/repos"
        return [
            {"id": 1, "repo_key": "application", "repo_role": "analysis",
             "active_generation": 3, "source_manifest_digest": "a" * 64,
             "repo_path": "/sealed/application", "structural_index_schema": "v1",
             "structural_index_manifest_path": "/sealed/index.json"},
            {"id": 2, "repo_key": "framework", "repo_role": "reference",
             "active_generation": 2, "source_manifest_digest": "b" * 64,
             "repo_path": "/sealed/framework"},
        ]


def test_code_dispatch_selects_analysis_repo_and_points_to_reference_repo():
    lines = _code_source_identity_lines(
        _Client(), agent_role="code-vuln-hunter", requested_repo_id=None,
        engagement_dir="/engagements/acme",
    )
    rendered = "\n".join(lines)
    assert "repo_id: 1" in rendered
    assert "framework" in rendered
    assert "navigation only" in rendered


_DIGEST = "c" * 64


class _MovedClient:
    """Backend rows recorded while the engagement lived somewhere else."""

    def get(self, endpoint):
        assert endpoint == "code/repos"
        sealed = f"/old/engagements/acme/tools/analysis-state/code-snapshots/{{key}}/{_DIGEST}/source"
        return [
            {"id": 1, "repo_key": "application", "repo_role": "analysis",
             "active_generation": 3, "source_manifest_digest": "a" * 64,
             "repo_path": sealed.format(key="application"), "structural_index_schema": "v1",
             "structural_index_manifest_path": "/sealed/index.json"},
            {"id": 2, "repo_key": "framework", "repo_role": "reference",
             "active_generation": 2, "source_manifest_digest": "b" * 64,
             "repo_path": sealed.format(key="framework")},
        ]


def test_a_moved_engagement_points_at_its_own_sealed_snapshot(tmp_path: Path):
    engagement = tmp_path / "engagements" / "acme"

    rendered = "\n".join(_code_source_identity_lines(
        _MovedClient(), agent_role="code-vuln-hunter", requested_repo_id=None,
        engagement_dir=engagement,
    ))

    snapshots = engagement.resolve() / "tools" / "analysis-state" / "code-snapshots"
    assert f"snapshot_path: {snapshots / 'application' / _DIGEST / 'source'}" in rendered
    assert f"snapshot_path={snapshots / 'framework' / _DIGEST / 'source'}" in rendered
    assert "/old/engagements" not in rendered
