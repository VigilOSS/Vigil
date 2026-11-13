"""`code-dispatch list-triggers` selects the rows a lane settles, and counts the rest.

An engagement can hold hundreds of pending triggers, so the read has to narrow to
one origin, family set or subtree, keep printing rows `requeue-triggers` and
`resolve-triggers` take unchanged, offer counts alone, and always say on stderr
how many rows it printed and how to narrow them. `requeue-triggers` names the
one-command alternative for depth_floor targets whose family cannot occur in the
file.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest
from _fake_client import StubClient

from assess.commands import code_dispatch


def _row(trigger_id: int, origin: str, vuln_class: str, path: str, **extra) -> dict:
    return {
        "id": trigger_id, "repo_id": 48, "origin": origin, "vuln_class": vuln_class,
        "status": "pending", "target_file_path": path,
        "resolved_target_file_path": path, "reason": "Acme reason", **extra,
    }


_ROWS = [
    _row(1, "depth_floor", "ssrf", "src/app/a.js"),
    _row(2, "depth_floor", "file-upload", "src/app/a.js"),
    _row(3, "depth_floor", "ssrf", "src/app_extra/b.js"),
    _row(4, "depth_floor", "ssrf", "Src/app/c.js"),
    _row(5, "cross_file", "ssrf", "src/app/d.js"),
    _row(6, "depth_floor", "injection", "src/app/e.js"),
    _row(7, "depth_floor", "ssrf", "src/app"),
]


def _install(monkeypatch, tmp_path, rows=_ROWS) -> list[str]:
    """Serve `GET code/triggers` as the backend pages it, recording each request."""
    requested: list[str] = []

    class FakeClient(StubClient):
        def get(self, endpoint: str):
            requested.append(endpoint)
            query = parse_qs(urlsplit(endpoint).query)
            origin = query.get("origin", [None])[0]
            limit, offset = int(query["limit"][0]), int(query["offset"][0])
            matching = [dict(row) for row in rows if origin in (None, row["origin"])]
            page = matching[offset:offset + limit]
            return {
                "total": len(matching), "offset": offset, "count": len(page),
                "has_more": offset + len(page) < len(matching), "items": page,
                "by_origin": {
                    kind: sum(1 for row in rows if row["origin"] == kind)
                    for kind in ("cross_file", "depth_floor")
                },
            }

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch, "load_config", lambda *_a, **_k: SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)))
    return requested


def _run(*extra: str) -> None:
    code_dispatch.run(SimpleNamespace(action="list-triggers", extra=list(extra),
                                      engagement_dir="/tmp/acme"))


def test_selection_flags_narrow_the_printed_rows(monkeypatch, tmp_path, capsys):
    requested = _install(monkeypatch, tmp_path)

    _run("--origin", "depth_floor", "--vuln-class", "ssrf", "--vuln-class", "file-upload",
         "--path-prefix", "src/app/")

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [1, 2, 7]
    assert requested == ["code/triggers?status=pending&origin=depth_floor&limit=1000&offset=0"]
    count_line = captured.err.strip().splitlines()[-1]
    assert "3 of 6" in count_line
    assert "depth_floor=3" in count_line
    assert "--origin/--vuln-class/--path-prefix" in count_line and "--summary" in count_line


def test_the_unfiltered_read_still_prints_every_row_and_counts_by_origin(
    monkeypatch, tmp_path, capsys
):
    _install(monkeypatch, tmp_path)

    _run()

    captured = capsys.readouterr()
    assert len(json.loads(captured.out)) == 7
    count_line = captured.err.strip().splitlines()[-1]
    assert "7 rows" in count_line
    assert "depth_floor=6" in count_line and "cross_file=1" in count_line


def test_status_and_repo_id_reach_the_backend_query(monkeypatch, tmp_path, capsys):
    requested = _install(monkeypatch, tmp_path)

    _run("queued", "--repo-id", "48")

    assert requested == ["code/triggers?status=queued&repo_id=48&limit=1000&offset=0"]


def test_every_page_is_read(monkeypatch, tmp_path, capsys):
    rows = [_row(index, "depth_floor", "ssrf", f"src/app/{index}.js") for index in range(1, 6)]
    requested = _install(monkeypatch, tmp_path, rows)
    monkeypatch.setattr(code_dispatch, "_TRIGGER_PAGE_SIZE", 2)

    _run()

    assert [row["id"] for row in json.loads(capsys.readouterr().out)] == [1, 2, 3, 4, 5]
    assert [endpoint.rsplit("offset=", 1)[1] for endpoint in requested] == ["0", "2", "4"]


def test_summary_prints_counts_only(monkeypatch, tmp_path, capsys):
    _install(monkeypatch, tmp_path)

    _run("--path-prefix", "src/app", "--summary")

    summary = json.loads(capsys.readouterr().out)
    assert summary["rows"] == 5
    assert summary["distinct_target_files"] == 4
    assert summary["by_origin"] == {"cross_file": 1, "depth_floor": 4}
    assert {
        (entry["origin"], entry["vuln_class"], entry["status"]): entry["count"]
        for entry in summary["counts"]
    } == {
        ("depth_floor", "ssrf", "pending"): 2,
        ("depth_floor", "file-upload", "pending"): 1,
        ("depth_floor", "injection", "pending"): 1,
        ("cross_file", "ssrf", "pending"): 1,
    }


@pytest.mark.parametrize(
    "extra",
    [
        ("--origin", "backfill"),
        ("--repo-id", "0"),
        ("--vuln-class", " "),
        ("--path-prefix",),
        ("--summary", "--summary"),
        ("--bogus", "x"),
    ],
)
def test_malformed_selection_is_refused_before_any_read(monkeypatch, tmp_path, capsys, extra):
    requested = _install(monkeypatch, tmp_path)

    with pytest.raises(SystemExit) as excinfo:
        _run(*extra)

    assert excinfo.value.code == 1
    assert requested == []


def _requeue_response() -> dict:
    return {
        "input_trigger_count": 2, "target_count": 1, "inserted": 1, "already_queued": 0,
        "already_completed": 0, "blocked": 0, "reopened_terminal_files": 1,
        "not_found": [], "ambiguous": [],
        "outcomes": [{
            "file_id": 9, "file_path": "src/app/a.js", "queue_item_id": 77,
            "outcome": "inserted", "detail": "reopened a terminal file with a new trigger attempt",
            "resolved_trigger_ids": [],
        }],
    }


def _install_requeue(monkeypatch, tmp_path) -> None:
    class FakeClient(StubClient):
        def post(self, endpoint: str, payload: dict):
            return _requeue_response()

    counter = iter(range(100))

    def snapshot(*_a, **_k):
        path = tmp_path / f"snapshot-{next(counter)}.json"
        path.write_text("{}", encoding="utf-8")
        return path

    monkeypatch.setattr(code_dispatch, "AssessmentClient", FakeClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", snapshot)


def test_requeueing_depth_floor_targets_names_the_way_back_to_a_resolve(
    monkeypatch, tmp_path, capsys
):
    """The requeued triggers are `queued`, which `resolve-triggers` cannot reach:
    the hint withdraws the directed attempts it just wrote before resolving."""
    _install_requeue(monkeypatch, tmp_path)
    triggers = tmp_path / "triggers.json"
    triggers.write_text(json.dumps(_ROWS[:2]), encoding="utf-8")

    code_dispatch._requeue_triggers(SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)),
        str(triggers))

    err = capsys.readouterr().err
    assert "2 depth_floor trigger(s) on 1 file(s)" in err
    assert "code-dispatch withdraw 77 --reason" in err
    assert err.index("withdraw 77") < err.index(f"resolve-triggers {triggers} not_applicable")
    assert "reviewed_at_sufficient_depth" in err
    assert "--origin depth_floor" in err


def test_requeueing_cross_file_targets_names_no_depth_alternative(
    monkeypatch, tmp_path, capsys
):
    _install_requeue(monkeypatch, tmp_path)
    triggers = tmp_path / "triggers.json"
    triggers.write_text(json.dumps([_ROWS[4]]), encoding="utf-8")

    code_dispatch._requeue_triggers(SimpleNamespace(
        base_url="http://example.test", engagement_key="eng", engagement_dir=str(tmp_path)),
        str(triggers))

    assert "depth_floor" not in capsys.readouterr().err


def test_a_large_selection_prints_one_page_and_names_the_rest(monkeypatch, tmp_path, capsys):
    rows = [_row(index, "depth_floor", "ssrf", f"src/app/{index}.js") for index in range(1, 8)]
    _install(monkeypatch, tmp_path, rows)
    monkeypatch.setattr(code_dispatch, "TRIGGER_PRINT_PAGE", 3)

    _run()

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [1, 2, 3]
    count_line = captured.err.strip().splitlines()[-1]
    assert "7 rows" in count_line and "printed rows 1-3 of 7 (4 not printed)" in count_line
    assert "--offset 3 --limit 3" in count_line and "--all" in count_line

    _run("--offset", "3", "--limit", "3")
    assert [row["id"] for row in json.loads(capsys.readouterr().out)] == [4, 5, 6]
    _run("--all")
    captured = capsys.readouterr()
    assert len(json.loads(captured.out)) == 7
    assert "not printed" not in captured.err


def test_include_superseded_reaches_the_backend_query(monkeypatch, tmp_path, capsys):
    requested = _install(monkeypatch, tmp_path)

    _run("--include-superseded")

    assert requested == [
        "code/triggers?status=pending&include_superseded=true&limit=1000&offset=0"
    ]


@pytest.mark.parametrize(
    "extra", [("--limit", "0"), ("--offset", "-1"), ("--all", "--limit", "5"), ("--all", "--all")]
)
def test_malformed_paging_is_refused_before_any_read(monkeypatch, tmp_path, capsys, extra):
    requested = _install(monkeypatch, tmp_path)

    with pytest.raises(SystemExit):
        _run(*extra)

    assert requested == []
