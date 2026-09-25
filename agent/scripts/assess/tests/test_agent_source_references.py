from __future__ import annotations

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
        _Client(), agent_role="code-vuln-hunter", requested_repo_id=None
    )
    rendered = "\n".join(lines)
    assert "repo_id: 1" in rendered
    assert "framework" in rendered
    assert "navigation only" in rendered
