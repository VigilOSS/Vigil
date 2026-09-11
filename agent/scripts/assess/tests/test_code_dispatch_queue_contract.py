from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import code_dispatch


def _config(tmp_path: Path) -> SimpleNamespace:
    return SimpleNamespace(
        base_url="http://example.test",
        engagement_key="eng",
        engagement_dir=str(tmp_path),
    )


def _queue_file(tmp_path: Path) -> Path:
    path = tmp_path / "queue.json"
    path.write_text(
        json.dumps(
            [
                {
                    "file_id": 7,
                    "priority": 90,
                    "batch_theme": "parser",
                    "slot_types": ["NETWORK-INPUT"],
                }
            ]
        ),
        encoding="utf-8",
    )
    return path


def _install_snapshot_stub(monkeypatch, tmp_path: Path) -> None:
    counter = iter(range(100))

    def fake_snapshot(*_args, **_kwargs):
        path = tmp_path / f"snapshot-{next(counter)}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(code_dispatch, "write_json_snapshot", fake_snapshot)


def test_code_dispatch_queue_posts_explicit_initial_mode(
    monkeypatch, tmp_path, capsys
):
    queue_path = _queue_file(tmp_path)
    _install_snapshot_stub(monkeypatch, tmp_path)
    captured: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict[str, object]):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {
                "mode": "initial",
                "inserted": 1,
                "updated": 0,
                "already_active": 0,
                "conflicts": 0,
                "reanalysis": 0,
                "total": 1,
                "outcomes": [],
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert captured == {
        "endpoint": "code/analysis-queue",
        "payload": {
            "mode": "initial",
            "items": [
                {
                    "file_id": 7,
                    "priority": 90,
                    "batch_theme": "parser",
                    "slot_types": ["NETWORK-INPUT"],
                    "guidance_hypotheses": [],
                }
            ],
        },
    }
    assert "Queue outcomes: inserted=1, updated=0, already-active=0, conflicts=0" in (
        capsys.readouterr().out
    )


def test_code_dispatch_lookup_rejects_unbounded_glob_result(monkeypatch, tmp_path, capsys):
    limit = code_dispatch._MAX_QUEUE_LOOKUP_MATCHES

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, _endpoint: str):
            items = [
                {"id": file_id, "repo_id": 1, "file_path": f"src/{file_id}.py"}
                for file_id in range(1, limit + 2)
            ]
            return {
                "total": len(items),
                "offset": 0,
                "count": len(items),
                "has_more": False,
                "items": items,
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._normalize_queue_items(
            _config(tmp_path),
            [{"file_path": "src/*.py", "repo_id": 1, "priority": 90}],
        )

    assert excinfo.value.code == 1
    assert "exceeds the bounded match cap" in capsys.readouterr().err


def test_code_dispatch_caps_glob_expansion_after_metadata_variants(monkeypatch, capsys):
    rows = [
        {"id": file_id, "repo_id": 1, "file_path": f"src/{file_id}.py"}
        for file_id in range(1, code_dispatch._MAX_QUEUE_NORMALIZED_ITEMS + 1)
    ]
    monkeypatch.setattr(code_dispatch, "_fetch_code_files", lambda _cfg, _selectors: rows)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._normalize_queue_items(
            SimpleNamespace(),
            [
                {"file_path": "src/*.py", "priority": 90},
                {"file_path": "src/*.py", "priority": 89},
            ],
        )

    assert excinfo.value.code == 1
    assert "bounded item cap" in capsys.readouterr().err


def test_code_dispatch_queue_posts_bounded_batches_and_caps_response_snapshots(
    monkeypatch, tmp_path
):
    item_count = code_dispatch._QUEUE_SUBMISSION_BATCH_SIZE + 1
    queue_path = tmp_path / "queue-many.json"
    queue_path.write_text(
        json.dumps(
            [
                {"file_id": file_id, "priority": 90}
                for file_id in range(1, item_count + 1)
            ]
        ),
        encoding="utf-8",
    )
    _install_snapshot_stub(monkeypatch, tmp_path)
    posted_sizes: list[int] = []

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict[str, object]):
            assert endpoint == "code/analysis-queue"
            batch = payload["items"]
            assert isinstance(batch, list)
            posted_sizes.append(len(batch))
            return {
                "mode": "initial",
                "inserted": len(batch),
                "updated": 0,
                "already_active": 0,
                "conflicts": 0,
                "reanalysis": 0,
                "total": len(batch),
                "outcomes": [{"file_id": item["file_id"]} for item in batch],
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert posted_sizes == [code_dispatch._QUEUE_SUBMISSION_BATCH_SIZE, 1]


def test_code_dispatch_reanalyze_requires_reason_and_posts_auditable_mode(
    monkeypatch, tmp_path
):
    queue_path = _queue_file(tmp_path)
    reanalysis_items = json.loads(queue_path.read_text(encoding="utf-8"))
    reanalysis_items[0]["supersedes"] = 6
    queue_path.write_text(json.dumps(reanalysis_items), encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "load_config", lambda _path: _config(tmp_path))
    captured: dict[str, object] = {}
    snapshot_metadata: list[dict[str, object]] = []

    def snapshot(*_args, metadata, **_kwargs):
        snapshot_metadata.append(metadata)
        path = tmp_path / f"snapshot-{len(snapshot_metadata)}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, endpoint: str, payload: dict[str, object]):
            captured["endpoint"] = endpoint
            captured["payload"] = payload
            return {
                "mode": "reanalysis",
                "inserted": 0,
                "updated": 0,
                "already_active": 0,
                "conflicts": 0,
                "reanalysis": 1,
                "total": 1,
                "outcomes": [],
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", snapshot)

    code_dispatch.run(
        SimpleNamespace(
            action="reanalyze",
            extra=[str(queue_path), "Phase 2C independent reread"],
            engagement_dir=tmp_path,
        )
    )

    assert captured["endpoint"] == "code/analysis-queue"
    assert captured["payload"] == {
        "mode": "reanalysis",
        "reason": "Phase 2C independent reread",
        "items": [
            {
                "file_id": 7,
                "priority": 90,
                "batch_theme": "parser",
                "slot_types": ["NETWORK-INPUT"],
                "guidance_hypotheses": [],
                "supersedes": 6,
            }
        ],
    }
    assert [metadata["command"] for metadata in snapshot_metadata] == [
        "code-dispatch reanalyze",
        "code-dispatch reanalyze",
    ]


def test_code_dispatch_queue_rejects_out_of_range_priority_without_clamping(
    monkeypatch, tmp_path, capsys
):
    queue_path = tmp_path / "invalid-priority.json"
    queue_path.write_text(
        json.dumps([{"file_id": 7, "priority": 101}]),
        encoding="utf-8",
    )
    posted = False

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            nonlocal posted
            posted = True
            return {}

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert excinfo.value.code == 1
    assert posted is False
    assert "Queue priority must be between 0 and 100" in capsys.readouterr().err


def test_code_dispatch_queue_rejects_oversized_input_before_json_materialization(
    monkeypatch, tmp_path, capsys
):
    queue_path = tmp_path / "oversized.json"
    queue_path.write_bytes(b"[" + (b" " * 256) + b"]")
    monkeypatch.setattr(code_dispatch, "_MAX_QUEUE_INPUT_BYTES", 128)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert excinfo.value.code == 1
    assert "exceeds the bounded input cap" in capsys.readouterr().err


def test_code_dispatch_queue_rejects_empty_submission_before_opening_client(
    monkeypatch, tmp_path, capsys
):
    queue_path = tmp_path / "empty.json"
    queue_path.write_text("[]", encoding="utf-8")
    monkeypatch.setattr(
        code_dispatch,
        "AssessmentClient",
        lambda *_args: (_ for _ in ()).throw(AssertionError("client opened")),
    )

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert excinfo.value.code == 1
    assert "does not contain any queue items" in capsys.readouterr().err


def test_code_dispatch_queue_requires_explicit_priority(monkeypatch, tmp_path, capsys):
    queue_path = tmp_path / "missing-priority.json"
    queue_path.write_text(json.dumps([{"file_id": 7}]), encoding="utf-8")
    posted = False

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            nonlocal posted
            posted = True
            return {}

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert excinfo.value.code == 1
    assert posted is False
    assert "Queue item requires explicit priority" in capsys.readouterr().err


def test_code_dispatch_queue_conflict_exits_nonzero_after_rendering_outcomes(
    monkeypatch, tmp_path, capsys
):
    queue_path = _queue_file(tmp_path)
    _install_snapshot_stub(monkeypatch, tmp_path)

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return {
                "mode": "initial",
                "inserted": 0,
                "updated": 0,
                "already_active": 0,
                "conflicts": 1,
                "reanalysis": 0,
                "total": 1,
                "outcomes": [
                    {
                        "file_id": 7,
                        "queue_item_id": 41,
                        "outcome": "conflict",
                        "status": "processing",
                        "detail": "live lease metadata differs",
                    }
                ],
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._queue(_config(tmp_path), str(queue_path))

    assert excinfo.value.code == 1
    captured = capsys.readouterr()
    assert captured.err.count("Queue submission reported 1 conflict(s)") == 1
    assert captured.out.count('"outcome": "conflict"') == 1


def test_code_dispatch_fetch_normalizes_backend_assigned_agent_to_agent_name(
    monkeypatch, tmp_path, capsys
):
    snapshots: list[object] = []

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return [
                {
                    "id": 41,
                    "assigned_agent": "hunter-41",
                    "lease_token": "lease-41",
                }
            ]

    def snapshot(*_args, payload, **_kwargs):
        snapshots.append(payload)
        path = tmp_path / "fetch.json"
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", snapshot)

    code_dispatch._fetch(_config(tmp_path), 1, "hunter-41")

    expected = [
        {
            "id": 41,
            "agent_name": "hunter-41",
            "lease_token": "lease-41",
                "scratch_dir": (
                    "tools/analysis-state/code-dispatch-scratch/41/"
                    "lease-ca317535176736f0"
                ),
        }
    ]
    assert snapshots == [expected]
    rendered = json.loads(capsys.readouterr().out)
    assert rendered == expected
    assert "assigned_agent" not in rendered[0]
    assert (tmp_path / rendered[0]["scratch_dir"]).is_dir()


def test_code_dispatch_empty_fetch_explains_why_no_claim_was_returned(
    monkeypatch, tmp_path, capsys
):
    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return []

    _install_snapshot_stub(monkeypatch, tmp_path)
    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    code_dispatch._fetch(
        _config(tmp_path),
        3,
        "idle-hunter",
        {"classification": "critical"},
    )

    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert (
        "No current pending code-analysis queue items matched the claim filters"
        in captured.err
    )
    assert "classification=critical" in captured.err


def test_code_dispatch_fetch_rejects_redirected_scratch_component(
    monkeypatch, tmp_path, capsys
):
    scratch_root = (
        tmp_path / "tools" / "analysis-state" / "code-dispatch-scratch"
    )
    scratch_root.mkdir(parents=True)
    redirected = tmp_path / "other-dispatch"
    redirected.mkdir()
    (scratch_root / "41").symlink_to(redirected, target_is_directory=True)

    class FakeClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return [
                {
                    "id": 41,
                    "assigned_agent": "hunter-41",
                    "lease_token": "lease-41",
                }
            ]

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._fetch(_config(tmp_path), 1, "hunter-41")

    assert excinfo.value.code == 1
    assert "Unsafe code-analysis scratch path" in capsys.readouterr().err
    assert list(redirected.iterdir()) == []


@pytest.mark.parametrize("value", ["0", "41,42", "41.0", "true"])
def test_code_dispatch_heartbeat_rejects_non_positive_single_item_id(
    monkeypatch, tmp_path, capsys, value
):
    monkeypatch.setattr(
        code_dispatch,
        "AssessmentClient",
        lambda *_args: pytest.fail("invalid heartbeat reached the backend"),
    )

    with pytest.raises(SystemExit) as excinfo:
        code_dispatch._heartbeat(_config(tmp_path), value, "hunter", "lease")

    assert excinfo.value.code == 1
    assert "item-id must be one positive integer" in capsys.readouterr().err
