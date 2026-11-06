"""Classification and dispatch writes preserve the complete intended scope."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from assess.commands import code_classify
from assess.commands.dispatch import agent as dispatch_agent
from assess.lib.client import AssessError


@pytest.mark.parametrize("file_id", [[], "1", True])
def test_invalid_direct_classification_id_reports_the_existing_id_contract(
    monkeypatch, tmp_path, capsys, file_id
):
    path = tmp_path / "classifications.json"
    path.write_text(json.dumps([
        {"file_id": 1, "classification": "medium", "analysis_priority": 40},
        {"file_id": file_id, "classification": "low", "analysis_priority": 10},
    ]), encoding="utf-8")
    monkeypatch.setattr(code_classify, "load_config", lambda _path: SimpleNamespace(
        base_url="http://example.com", engagement_key="acme"
    ))

    class Client:
        def __enter__(self):
            pytest.fail("invalid classifications must not open a write client")

        def __exit__(self, *_exc):
            return False

    monkeypatch.setattr(code_classify, "AssessmentClient", lambda *_args: Client())

    with pytest.raises(SystemExit) as failure:
        code_classify.run(SimpleNamespace(
            classifications_json=str(path), engagement_dir=str(tmp_path)
        ))

    assert failure.value.code == 1
    assert "Invalid file_id in classification item" in capsys.readouterr().err


@pytest.mark.parametrize("resolve_paths", [False, True])
def test_duplicate_classifications_across_batches_write_nothing(
    monkeypatch, tmp_path, capsys, resolve_paths
):
    size = code_classify.DEFAULT_BULK_WRITE_SIZE
    payload = [
        {"file_id": index, "classification": "medium", "analysis_priority": 40}
        for index in range(1, size + 1)
    ]
    duplicate = {"classification": "low", "analysis_priority": 10}
    duplicate.update({"file_path": "src/acme.py"} if resolve_paths else {"file_id": 1})
    payload.append(duplicate)
    path = tmp_path / "classifications.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    posts = []

    class Client:
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint, payload, **_options):
            posts.append(payload)
            count = len(payload["classifications"])
            return {"updated": count, "total": count}

    monkeypatch.setattr(code_classify, "AssessmentClient", lambda *_args: Client())
    monkeypatch.setattr(code_classify, "load_config", lambda _path: SimpleNamespace(
        base_url="http://example.com", engagement_key="acme"
    ))
    monkeypatch.setattr(code_classify, "_fetch_code_files", lambda _cfg: [
        {"id": 1, "file_path": "src/acme.py"}
    ])

    with pytest.raises(SystemExit) as failure:
        code_classify.run(SimpleNamespace(
            classifications_json=str(path), engagement_dir=str(tmp_path)
        ))

    assert failure.value.code == 1
    assert posts == []
    assert "duplicate" in capsys.readouterr().err.lower()


def test_a_failed_dispatch_scope_read_does_not_replace_scope(monkeypatch, capsys):
    patches = []
    closed = []

    class Client:
        def get_dispatch(self, _agent_id):
            raise AssessError("temporary GET timeout")

        def update_dispatch(self, agent_id, patch):
            patches.append(patch)
            return {"agent_id": agent_id, **patch}

        def close(self):
            closed.append(True)

    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _args: (Client(), None))
    with pytest.raises(SystemExit) as failure:
        dispatch_agent._update_dispatch_status(SimpleNamespace(
            finding_slugs="VA-002", dispatch_status="completed"
        ), ["acme-reviewer"])

    assert failure.value.code == 1
    assert patches == []
    assert closed == [True]
    assert "temporary GET timeout" in capsys.readouterr().err


def test_dispatch_scope_addition_can_retry_after_a_failed_read(monkeypatch, capsys):
    stored = {"agent_id": "acme-reviewer", "finding_slugs": ["VA-001"]}

    class Client:
        unavailable = True

        def get_dispatch(self, _agent_id):
            if self.unavailable:
                raise AssessError("temporary GET timeout")
            return dict(stored)

        def update_dispatch(self, _agent_id, patch):
            stored.update(patch)
            return dict(stored)

        def close(self):
            pass

    client = Client()
    monkeypatch.setattr(dispatch_agent, "_client_for", lambda _args: (client, None))
    args = SimpleNamespace(finding_slugs="VA-002", dispatch_status="completed")
    with pytest.raises(SystemExit):
        dispatch_agent._update_dispatch_status(args, ["acme-reviewer"])
    assert stored["finding_slugs"] == ["VA-001"]

    client.unavailable = False
    dispatch_agent._update_dispatch_status(args, ["acme-reviewer"])

    assert stored["finding_slugs"] == ["VA-001", "VA-002"]
    assert stored["status"] == "completed"
    assert json.loads(capsys.readouterr().out)["finding_slugs"] == ["VA-001", "VA-002"]
