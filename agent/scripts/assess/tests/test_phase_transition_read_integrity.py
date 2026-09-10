"""Correctness-sensitive phase gates must never accept partial audit reads."""

from __future__ import annotations

from assess.commands import transition_phase


class _MalformedArtifactPageClient:
    def get(self, endpoint: str):
        if endpoint == "artifacts/search?limit=1000&offset=0":
            return [
                {
                    "id": index + 1,
                    "kind": "ir_closeout" if index == 0 else "other",
                    "relative_path": "reports/closeout.md" if index == 0 else "other.txt",
                }
                for index in range(1000)
            ]
        if endpoint == "artifacts/search?limit=1000&offset=1000":
            return {"unexpected": "object page"}
        if endpoint == "findings":
            return []
        raise AssertionError(f"unexpected endpoint: {endpoint}")


def test_blue_complete_gate_blocks_when_later_artifact_page_is_malformed() -> None:
    blockers = transition_phase._blue_check_report_to_complete(
        _MalformedArtifactPageClient()
    )

    assert any(
        blocker["kind"] == "backend_query_failed"
        and "artifacts" in blocker["detail"]
        for blocker in blockers
    )
