from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from assess.commands import agent


class _Client:
    def get(self, endpoint):
        assert endpoint == "code/analysis-queue?repo_id=7&limit=1000&offset=0"
        return {"items": [{"id": 44, "file_path": "app/auth.py", "status": "pending",
                            "repo_generation": 3, "repo_id": 7}], "has_more": False}


def test_selected_queue_ids_render_from_backend_not_authored_file_names():
    lines = agent._backend_queue_manifest(
        _Client(), [44], repo_id=7, repo_generation=3
    )
    assert "app/auth.py" in "\n".join(lines)
    assert "queue_item_id=44" in "\n".join(lines)


def test_selected_queue_id_missing_from_current_repo_fails():
    with pytest.raises(SystemExit):
        agent._backend_queue_manifest(_Client(), [45], repo_id=7, repo_generation=3)


def test_selected_queue_id_from_another_repo_fails():
    class WrongRepo(_Client):
        def get(self, endpoint):
            page = super().get(endpoint)
            page["items"][0]["repo_id"] = 9
            return page

    with pytest.raises(SystemExit):
        agent._backend_queue_manifest(WrongRepo(), [44], repo_id=7, repo_generation=3)


def test_optional_queue_ids_require_integer_list_before_dispatch(capsys):
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields["queue_item_ids"] = ["44"]
    args = argparse.Namespace(prompt_context=fields, prompt_context_json=None)
    with pytest.raises(SystemExit):
        agent._load_prompt_context(args)
    assert "queue_item_ids" in capsys.readouterr().err


def test_prior_state_rejects_unbounded_authored_text(capsys):
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields["prior_state"] = "x" * 4097
    args = argparse.Namespace(prompt_context=fields, prompt_context_json=None)
    with pytest.raises(SystemExit):
        agent._load_prompt_context(args)
    assert "prior_state" in capsys.readouterr().err


def test_dispatch_prompt_quotes_backend_queue_and_attributed_handoff(
    tmp_path: Path, monkeypatch
):
    lane_file = tmp_path / "lane.json"
    lane_file.write_text(json.dumps([
        {"id": 44, "repo_generation": 3, "repo": {"id": 7}, "file": {"file_path": "src/auth/A.java", "loc": 12}},
    ]), encoding="utf-8")
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields.update({"queue_item_ids": [44], "prior_agent_id": "prior-1", "lane_file": str(lane_file)})
    args = argparse.Namespace(prompt_context=fields, prompt_context_json=None,
                              no_target_traffic=True, rate_budget=None)
    class LaneClient(_Client):
        def get(self, endpoint):
            if endpoint == "code/analysis-queue?repo_id=7&limit=1000&offset=0":
                return {"items": [{"id": 44, "file_path": "src/auth/A.java", "status": "pending",
                                    "repo_generation": 3, "repo_id": 7}], "has_more": False}
            if endpoint == "code/files?repo_id=7&limit=10000&offset=0":
                return {"items": [{"file_path": "src/auth/A.java", "loc": 12}], "has_more": False}
            raise AssertionError(f"unexpected endpoint: {endpoint}")
    monkeypatch.setattr(agent, "_render_handoff", lambda _args, _ids: print("#### Handoff from prior-1\n- finding VA-001"))
    prompt = agent._dispatch_prompt(
        {"agent_id": "next-1", "agent_role": "code-vuln-hunter", "task": "review auth"},
        engagement_dir=tmp_path, agent_root=tmp_path,
        source_identity=["repo_id: 7", "repo_generation: 3"],
        args=args, client=LaneClient(),
    )
    assert "queue_item_id=44" in prompt
    assert "src/auth/A.java" in prompt
    assert "Backend handoff attributed to dispatch prior-1" in prompt
    assert '"src/auth/A.java" (12 LOC; queue item 44)' in prompt
    assert prompt.index("Lane file manifest") < prompt.index("--- END PERSISTED PRIOR-STATE DATA ---")
    assert prompt.index("--- BEGIN PERSISTED PRIOR-STATE DATA ---") < prompt.index("Backend handoff attributed")
    assert prompt.index("Backend handoff attributed") < prompt.index("--- END PERSISTED PRIOR-STATE DATA ---")


def test_lane_file_manifest_summarizes_fetch_json(tmp_path: Path):
    lane_file = tmp_path / "lane.json"
    lane_file.write_text(json.dumps([
        {"id": 44, "repo_generation": 3, "repo": {"id": 7}, "file": {"file_path": "src/auth/A.java", "loc": 12}},
        {"id": 45, "repo_generation": 3, "repo": {"id": 7}, "file": {"file_path": "src/web/B.java", "loc": 8}},
    ]), encoding="utf-8")
    class BackendClient:
        def get(self, endpoint):
            if endpoint == "code/analysis-queue?repo_id=7&limit=1000&offset=0":
                return {"items": [
                    {"id": 44, "file_path": "src/auth/A.java", "repo_generation": 3, "repo_id": 7},
                    {"id": 45, "file_path": "src/web/B.java", "repo_generation": 3, "repo_id": 7},
                ], "has_more": False}
            if endpoint == "code/files?repo_id=7&limit=10000&offset=0":
                return {"items": [
                    {"file_path": "src/auth/A.java", "loc": 12},
                    {"file_path": "src/web/B.java", "loc": 8},
                ], "has_more": False}
            raise AssertionError(f"unexpected endpoint: {endpoint}")
    lines = agent._lane_file_manifest(
        lane_file, client=BackendClient(), source_identity=["repo_id: 7", "repo_generation: 3"]
    )
    rendered = "\n".join(lines)
    assert "lane file" in rendered.lower()
    assert "items: 2; total LOC: 20" in rendered
    assert '"src/auth": 1 item(s), 12 LOC' in rendered
    assert '"src/web": 1 item(s), 8 LOC' in rendered
    assert '"src/auth/A.java" (12 LOC; queue item 44)' in rendered


def test_lane_file_manifest_uses_backend_facts_for_fetch_json(tmp_path: Path):
    lane_file = tmp_path / "lane.json"
    lane_file.write_text(json.dumps([
        {"id": 44, "repo_generation": 3, "repo": {"id": 7},
         "file": {"file_path": "operator-edited/wrong.java", "loc": 900}},
    ]), encoding="utf-8")

    class BackendClient:
        def get(self, endpoint):
            if endpoint == "code/analysis-queue?repo_id=7&limit=1000&offset=0":
                return {"items": [{
                    "id": 44, "file_id": 17, "file_path": "src/auth/A.java",
                    "repo_id": 7, "repo_generation": 3, "status": "processing",
                }], "has_more": False}
            if endpoint == "code/files?repo_id=7&limit=10000&offset=0":
                return {"items": [{"file_path": "src/auth/A.java", "loc": 12}], "has_more": False}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

    rendered = "\n".join(agent._lane_file_manifest(
        lane_file, client=BackendClient(),
        source_identity=["repo_id: 7", "repo_generation: 3"],
    ))

    assert '"src/auth/A.java" (12 LOC; queue item 44)' in rendered
    assert '"operator-edited/wrong.java"' not in rendered
    assert "items: 1; total LOC: 12" in rendered


def test_lane_file_manifest_rejects_stale_fetch_json(tmp_path: Path, capsys):
    lane_file = tmp_path / "lane.json"
    lane_file.write_text(json.dumps([
        {"id": 44, "repo_generation": 2, "repo": {"id": 7}, "file": {"file_path": "src/a.py", "loc": 12}},
    ]), encoding="utf-8")

    class BackendClient:
        def get(self, endpoint):
            if endpoint == "code/analysis-queue?repo_id=7&limit=1000&offset=0":
                return {"items": [{"id": 44, "file_path": "src/a.py", "repo_generation": 3,
                                   "repo_id": 7}], "has_more": False}
            if endpoint == "code/files?repo_id=7&limit=10000&offset=0":
                return {"items": [{"file_path": "src/a.py", "loc": 12}], "has_more": False}
            raise AssertionError(f"unexpected endpoint: {endpoint}")

    with pytest.raises(SystemExit):
        agent._lane_file_manifest(
            lane_file, client=BackendClient(), source_identity=["repo_id: 7", "repo_generation: 3"]
        )
    assert "stale" in capsys.readouterr().err


def test_lane_file_manifest_resolves_newline_paths_against_selected_repo(tmp_path: Path):
    lane_file = tmp_path / "lane.txt"
    lane_file.write_text("src/auth/A.java\nsrc/web/B.java\n", encoding="utf-8")

    class FileClient:
        def get(self, endpoint):
            assert endpoint == "code/files?repo_id=7&limit=10000&offset=0"
            return {"items": [
                {"file_path": "src/auth/A.java", "loc": 12},
                {"file_path": "src/web/B.java", "loc": 8},
            ], "has_more": False}

    lines = agent._lane_file_manifest(
        lane_file, client=FileClient(), source_identity=["repo_id: 7", "repo_generation: 3"]
    )
    assert "items: 2; total LOC: 20" in "\n".join(lines)


def test_lane_file_manifest_rejects_ambiguous_json(capsys, tmp_path: Path):
    lane_file = tmp_path / "lane.json"
    lane_file.write_text('{"files": ["src/a.py"]}', encoding="utf-8")
    with pytest.raises(SystemExit):
        agent._lane_file_manifest(lane_file, client=None, source_identity=[])
    assert "unsupported or ambiguous lane-file JSON" in capsys.readouterr().err


def test_lane_file_size_limit_is_checked_before_read(monkeypatch, tmp_path: Path):
    lane_file = tmp_path / "large.txt"
    with lane_file.open("wb") as handle:
        handle.truncate(8 * 1024 * 1024 + 1)

    def unexpected_read(*_args, **_kwargs):
        raise AssertionError("oversize lane file should not be read")

    monkeypatch.setattr(Path, "read_text", unexpected_read)
    with pytest.raises(SystemExit):
        agent._lane_file_manifest(lane_file, client=None, source_identity=[])


def test_invalid_lane_file_is_rejected_before_dispatch_persistence(
    monkeypatch, tmp_path: Path
):
    persisted = []

    class Client:
        def close(self):
            pass

        def record_dispatch(self, payload):
            persisted.append(payload)
            return {"id": 1, "agent_id": "lane-1", "agent_role": "code-vuln-hunter"}

    cfg = type("Cfg", (), {"engagement_dir": str(tmp_path), "agent_root": str(tmp_path)})()
    monkeypatch.setattr(agent.dispatch, "_build_register_payload", lambda _args: {
        "agent_id": "lane-1", "agent_role": "code-vuln-hunter", "task": "review",
    })
    monkeypatch.setattr(agent.dispatch, "_client_for", lambda _args: (Client(), cfg))
    monkeypatch.setattr(agent, "_attach_dispatch_provenance", lambda *_args: [])
    monkeypatch.setattr(agent, "_require_proof_variant_parent_set", lambda *_args: None)
    monkeypatch.setattr(agent, "_code_source_identity_lines", lambda *_args, **_kwargs: [])
    lane_file = tmp_path / "lane.json"
    lane_file.write_text('{"files": ["src/a.py"]}', encoding="utf-8")
    fields = {field: "none" for field in agent._PROMPT_CONTEXT_FIELDS}
    fields["lane_file"] = str(lane_file)
    args = argparse.Namespace(
        prompt_context=fields, prompt_context_json=None, emit_prompt=True,
        allow_duplicate=True, dry_run=False, no_target_traffic=True,
        rate_budget=None, code_repo_id=None,
    )
    with pytest.raises(SystemExit):
        agent._start(args)
    assert persisted == []
