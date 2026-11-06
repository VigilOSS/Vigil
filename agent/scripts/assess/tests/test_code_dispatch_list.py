"""A6: `code-dispatch list` recovers queue IDs after insertion output scrolls.

`fetch --ids-file` is the documented precise batching mechanism, but initial
queue outcomes cap at 200 rows and nothing listed the queue, so the IDs were
unrecoverable through the supported operator surface. The machine forms of this
verb must therefore be consumable as an ids file without scraping the table.
"""
from __future__ import annotations

import json
import re
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


_PAGE = {
    "total": 3,
    "offset": 4,
    "count": 2,
    "has_more": True,
    "item_ids": [41, 42],
    "items": [
        {
            "id": 41,
            "file_id": 7,
            "file_path": "src/parser.py",
            "classification": "critical",
            "repo_id": 1,
            "status": "processing",
            "queue_mode": "initial",
            "priority": 100,
            "batch_theme": "parser-core",
            "agent_name": "hunter-a",
            "lease_token": "lease-a",
            "last_heartbeat_at": "2026-09-15T10:00:00Z",
        },
        {
            "id": 42,
            "file_id": 8,
            "file_path": "src/helpers.py",
            "classification": "low",
            "repo_id": 1,
            "status": "pending",
            "queue_mode": "trigger",
            "priority": 10,
            "batch_theme": "helpers",
            "agent_name": "",
            "lease_token": "",
            "last_heartbeat_at": None,
        },
    ],
}


class _FakeClient:
    requested: list[str] = []
    payload: dict = _PAGE

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).requested.append(endpoint)
        return type(self).payload


@pytest.fixture
def fake_client(monkeypatch):
    _FakeClient.requested = []
    _FakeClient.payload = _PAGE
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FakeClient)
    return _FakeClient


def test_list_is_a_registered_action() -> None:
    assert "list" in code_dispatch._ACTION_HELP


def test_list_sends_every_filter_in_one_canonical_query(fake_client, tmp_path, capsys):
    filters, output = code_dispatch._parse_list_filters(
        [
            "--queue-mode", "trigger",
            "--status", "pending",
            "--limit", "2",
            "--repo-id", "1",
            "--classification", "critical",
            "--batch-theme", "parser core",
            "--offset", "4",
        ]
    )
    code_dispatch._list(_config(tmp_path), filters, output)

    assert output == "table"
    assert fake_client.requested == [
        "code/analysis-queue?status=pending&repo_id=1&classification=critical"
        "&batch_theme=parser+core&queue_mode=trigger&limit=2&offset=4"
    ]
    out = capsys.readouterr().out
    assert "41" in out and "42" in out
    assert "src/parser.py" in out
    assert "hunter-a" in out
    assert "--offset 6" in out


def test_list_sends_repeatable_path_filters_in_canonical_order(fake_client, tmp_path):
    typed = [
        "--path-glob", "*.py",
        "--limit", "5",
        "--path-prefix", "src/billing",
        "--status", "pending",
        "--path-prefix", "src/auth",
        "--path-glob", "*/api/*",
    ]
    reordered = [
        "--path-prefix", "src/auth",
        "--status", "pending",
        "--path-glob", "*/api/*",
        "--path-prefix", "src/billing",
        "--path-glob", "*.py",
        "--limit", "5",
    ]
    for tokens in (typed, reordered):
        filters, output = code_dispatch._parse_list_filters(tokens)
        code_dispatch._list(_config(tmp_path), filters, output)

    expected = (
        "code/analysis-queue?status=pending"
        "&path_prefix=src%2Fauth&path_prefix=src%2Fbilling"
        "&path_glob=%2A.py&path_glob=%2A%2Fapi%2F%2A&limit=5"
    )
    assert fake_client.requested == [expected, expected]


def test_list_json_output_is_directly_usable_as_an_ids_file(
    fake_client, tmp_path, capsys
):
    code_dispatch._list(_config(tmp_path), {}, "json")

    payload = json.loads(capsys.readouterr().out)
    assert payload == _PAGE
    ids_file = tmp_path / "ids.json"
    ids_file.write_text(json.dumps(payload), encoding="utf-8")
    assert code_dispatch._ids_from_file(str(ids_file)) == [41, 42]


def test_list_ids_only_output_is_directly_usable_as_an_ids_file(
    fake_client, tmp_path, capsys
):
    code_dispatch._list(_config(tmp_path), {}, "ids")

    out = capsys.readouterr().out
    assert json.loads(out) == [41, 42]
    ids_file = tmp_path / "ids.json"
    ids_file.write_text(out, encoding="utf-8")
    assert code_dispatch._ids_from_file(str(ids_file)) == [41, 42]


@pytest.mark.parametrize(
    "tokens",
    [
        ["--status"],
        ["--unknown", "x"],
        ["--limit", "zero"],
        ["--limit", "0"],
        ["--repo-id", "-1"],
        ["--json", "--ids-only"],
        ["--status", "pending", "--status", "done"],
        ["--path-prefix"],
        ["--path-glob", " "],
        ["stats"],
    ],
)
def test_list_rejects_malformed_filters(tokens, capsys):
    with pytest.raises(SystemExit) as exc:
        code_dispatch._parse_list_filters(tokens)

    assert exc.value.code == 1
    assert capsys.readouterr().err


def test_fetch_passes_queue_mode_filter_to_the_backend(monkeypatch, tmp_path, capsys):
    posted: dict[str, object] = {}

    class _FetchClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            posted.setdefault("scope_reads", []).append(endpoint)  # type: ignore[union-attr]
            return {"total": 0, "offset": 0, "count": 0, "has_more": False,
                    "item_ids": [], "items": []}

        def post(self, endpoint: str, payload: dict[str, object]):
            posted["endpoint"] = endpoint
            posted["payload"] = payload
            return []

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _FetchClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(
        _config(tmp_path),
        3,
        "trigger-hunter",
        code_dispatch._parse_fetch_filters(["--queue-mode", "trigger"]),
    )

    assert posted["payload"] == {
        "limit": 3,
        "agent_name": "trigger-hunter",
        "queue_mode": "trigger",
    }

    code_dispatch._fetch(
        _config(tmp_path),
        3,
        "auth-hunter",
        code_dispatch._parse_fetch_filters(
            [
                "--path-glob", "*.py",
                "--path-prefix", "src/billing",
                "--repo-id", "2",
                "--path-prefix", "src/auth",
            ]
        ),
    )

    assert posted["payload"] == {
        "limit": 3,
        "agent_name": "auth-hunter",
        "repo_id": 2,
        "path_prefix": ["src/auth", "src/billing"],
        "path_glob": ["*.py"],
    }
    assert "path_prefix=src/auth,src/billing" in capsys.readouterr().err


def test_a_truncated_ids_page_says_so_on_stderr(fake_client, tmp_path, capsys):
    """An ids file that is silently short is the defect this verb exists to fix.

    `--ids-only` is meant to be redirected straight into a file and handed to
    `fetch --ids-file`. With nothing but the id array on stdout, a page that
    stopped at the limit produces a short claim set and no signal at all — the
    same lost-IDs failure as scraping truncated insertion output, one layer down.
    """
    code_dispatch._list(_config(tmp_path), {}, "ids")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [41, 42]
    assert "of 3 matching rows" in captured.err
    assert "--offset 6" in captured.err


def test_a_truncated_json_page_says_so_on_stderr(fake_client, tmp_path, capsys):
    code_dispatch._list(_config(tmp_path), {}, "json")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == _PAGE
    assert "matching rows" in captured.err


def test_a_complete_page_warns_about_nothing(fake_client, tmp_path, capsys):
    fake_client.payload = {**_PAGE, "has_more": False}
    code_dispatch._list(_config(tmp_path), {}, "ids")

    captured = capsys.readouterr()
    assert json.loads(captured.out) == [41, 42]
    assert captured.err == ""


def test_list_table_separates_long_values_without_truncating_them(
    fake_client, tmp_path, capsys
):
    item = {
        **_PAGE["items"][0],
        "batch_theme": "acme-compiled-bundle-review-with-a-long-theme",
        "agent_name": "acme-local-source-review-specialist",
        "file_path": "acme/client/compiled/application-bundle.js",
        "heartbeat_age_seconds": 3,
        "current_result_count": 2,
    }
    fake_client.payload = {
        "total": 1, "offset": 0, "has_more": False, "item_ids": [41], "items": [item]
    }

    code_dispatch._list(_config(tmp_path), {}, "table")

    row = next(line for line in capsys.readouterr().out.splitlines() if line.strip().startswith("41"))
    assert re.split(r"\s{2,}", row.strip()) == [
        "41", "processing", "initial", "100", "critical", "3s", "2",
        item["batch_theme"], item["agent_name"], item["file_path"],
    ]

    code_dispatch._list(_config(tmp_path), {}, "json")
    assert json.loads(capsys.readouterr().out) == fake_client.payload


@pytest.mark.parametrize("content,expected", [("56813\n", [56813]), ("56813", [56813]),
    ("56813\n56814\n", [56813, 56814]), ("[56813]", [56813])])
def test_ids_file_accepts_single_and_multiple_plain_ids(tmp_path, content, expected):
    path = tmp_path / "ids.txt"
    path.write_text(content)
    assert code_dispatch._ids_from_file(str(path)) == expected


# --- B10: an empty claim must say WHICH kind of empty it is -----------------


class _EmptyFetchClient:
    """A claim that returns nothing, plus the scope read that explains why."""

    scope_page: dict = {
        "total": 0, "offset": 0, "count": 0, "has_more": False,
        "item_ids": [], "items": [],
    }
    reads: list[str] = []
    claimed: list[dict] = []

    def __init__(self, *_args) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).reads.append(endpoint)
        return type(self).scope_page

    def post(self, _endpoint: str, _payload: dict[str, object]):
        return type(self).claimed


@pytest.fixture
def empty_fetch_client(monkeypatch, tmp_path):
    _EmptyFetchClient.reads = []
    _EmptyFetchClient.claimed = []
    _EmptyFetchClient.scope_page = {
        "total": 0, "offset": 0, "count": 0, "has_more": False,
        "item_ids": [], "items": [],
    }
    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _EmptyFetchClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)
    return _EmptyFetchClient


def test_an_empty_claim_reads_the_same_scope_with_no_status_filter(
    empty_fetch_client, tmp_path, capsys
):
    """The diagnostic must reuse the claim's own scope, minus `status`.

    Anything else can disagree with the claim query, which is the one thing a
    "why did I get nothing" message must never do.
    """
    code_dispatch._fetch(
        _config(tmp_path),
        5,
        "idle-hunter",
        code_dispatch._parse_fetch_filters(
            [
                "--repo-id", "3",
                "--classification", "critical",
                "--batch-theme", "parser core",
                "--queue-mode", "initial",
                "--path-prefix", "src/auth",
                "--path-glob", "*.py",
            ]
        ),
    )

    assert empty_fetch_client.reads == [
        "code/analysis-queue?repo_id=3&classification=critical"
        "&batch_theme=parser+core&queue_mode=initial"
        "&path_prefix=src%2Fauth&path_glob=%2A.py&limit=200"
    ]
    err = capsys.readouterr().err
    assert "No current-generation queue row lies under this scope" in err
    assert "code-coverage --by-path" in err


def test_an_empty_claim_over_busy_rows_names_their_status_and_holders(
    empty_fetch_client, tmp_path, capsys
):
    empty_fetch_client.scope_page = {
        "total": 3,
        "offset": 0,
        "count": 3,
        "has_more": False,
        "item_ids": [41, 42, 43],
        "items": [
            {
                "id": 41, "status": "processing", "agent_name": "hunter-a",
                "heartbeat_age_seconds": 900, "file_path": "src/auth/login.py",
            },
            {
                "id": 42, "status": "processing", "agent_name": "hunter-b",
                "heartbeat_age_seconds": 5, "file_path": "src/auth/session.py",
            },
            {
                "id": 43, "status": "done", "agent_name": "",
                "heartbeat_age_seconds": None, "file_path": "src/auth/token.py",
            },
        ],
    }

    code_dispatch._fetch(
        _config(tmp_path), 5, "idle-hunter", {"path_prefix": ["src/auth"]}
    )

    err = capsys.readouterr().err
    assert "3 row(s) match this scope" in err
    assert "none is claimable now" in err
    assert "processing=2" in err
    assert "done=1" in err
    assert "hunter-a" in err
    assert "15m" in err
    assert "code-coverage --by-path" not in err


def test_a_non_empty_claim_issues_no_diagnostic_read(empty_fetch_client, tmp_path, capsys):
    empty_fetch_client.claimed = [
        {"id": 41, "assigned_agent": "idle-hunter", "lease_token": "lease-41"}
    ]

    code_dispatch._fetch(_config(tmp_path), 5, "idle-hunter", {})

    assert empty_fetch_client.reads == []
    assert "claimable" not in capsys.readouterr().err


def test_the_empty_claim_diagnostic_survives_an_unreadable_scope_page(
    empty_fetch_client, tmp_path, capsys
):
    """A failed diagnostic read must not turn an empty claim into a crash."""
    empty_fetch_client.scope_page = []  # type: ignore[assignment]

    code_dispatch._fetch(_config(tmp_path), 5, "idle-hunter", {"repo_id": 3})

    captured = capsys.readouterr()
    assert json.loads(captured.out) == []
    assert "repo_id=3" in captured.err


# --- G11: a partial --ids-file claim must name every id it did not get ------


def test_a_partial_ids_file_claim_names_the_unclaimed_ids_and_their_status(
    monkeypatch, tmp_path, capsys
):
    """1,560 of 1,574 claimed printed nothing; 14 files were never reviewed."""

    class _PartialClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            assert endpoint.startswith("code/analysis-queue?")
            return {
                "total": 3, "offset": 0, "count": 3, "has_more": False,
                "item_ids": [41, 42, 43],
                "items": [
                    {"id": 42, "status": "processing", "agent_name": "hunter-b",
                     "file_path": "src/b.py", "heartbeat_age_seconds": 12},
                    {"id": 43, "status": "done", "agent_name": "",
                     "file_path": "src/c.py", "heartbeat_age_seconds": None},
                    {"id": 41, "status": "processing", "agent_name": "mine",
                     "file_path": "src/a.py", "heartbeat_age_seconds": 0},
                ],
            }

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return [{"id": 41, "assigned_agent": "mine", "lease_token": "lease-41"}]

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _PartialClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(
        _config(tmp_path), 3, "mine", {"item_ids": [41, 42, 43]}
    )

    captured = capsys.readouterr()
    assert [item["id"] for item in json.loads(captured.out)] == [41]
    err = captured.err
    assert "claimed 1 of the 3 requested id(s)" in err
    assert "42 (processing" in err
    assert "hunter-b" in err
    assert "43 (done" in err
    # The id this lane DID claim is not reported as unclaimed.
    assert "41 (" not in err


def test_a_complete_ids_file_claim_warns_about_nothing(monkeypatch, tmp_path, capsys):
    class _CompleteClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, endpoint: str):
            pytest.fail(f"a complete claim must not issue a diagnostic read: {endpoint}")

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return [
                {"id": 41, "assigned_agent": "mine", "lease_token": "lease-41"},
                {"id": 42, "assigned_agent": "mine", "lease_token": "lease-42"},
            ]

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _CompleteClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(_config(tmp_path), 2, "mine", {"item_ids": [41, 42]})

    assert "requested id(s)" not in capsys.readouterr().err


def test_an_ids_file_claim_that_got_nothing_still_names_every_id(
    monkeypatch, tmp_path, capsys
):
    """A total ids-file failure is the same question, with every id unclaimed."""

    class _NoneClaimedClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, _endpoint: str):
            return {
                "total": 1, "offset": 0, "count": 1, "has_more": False,
                "item_ids": [41],
                "items": [
                    {"id": 41, "status": "processing", "agent_name": "other-lane",
                     "file_path": "src/a.py", "heartbeat_age_seconds": 30},
                ],
            }

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return []

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _NoneClaimedClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(_config(tmp_path), 2, "mine", {"item_ids": [41, 99]})

    err = capsys.readouterr().err
    assert "claimed 0 of the 2 requested id(s)" in err
    assert "41 (processing held by other-lane)" in err
    assert "99: no current-generation queue row found" in err


def test_a_failed_status_lookup_is_not_reported_as_a_missing_row(
    monkeypatch, tmp_path, capsys
):
    """"We could not look" must never render as "the row is gone"."""
    from assess.lib.client import AssessError

    class _BrokenLookupClient:
        def __init__(self, *_args) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def get(self, _endpoint: str):
            raise AssessError("HTTP 503 analysis-queue listing unavailable")

        def post(self, _endpoint: str, _payload: dict[str, object]):
            return [{"id": 41, "assigned_agent": "mine", "lease_token": "lease-41"}]

    snapshot = tmp_path / "snapshot.json"
    snapshot.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(code_dispatch, "AssessmentClient", _BrokenLookupClient)
    monkeypatch.setattr(code_dispatch, "write_json_snapshot", lambda *_a, **_k: snapshot)

    code_dispatch._fetch(_config(tmp_path), 2, "mine", {"item_ids": [41, 42]})

    err = capsys.readouterr().err
    assert "claimed 1 of the 2 requested id(s)" in err
    assert "could not be read back" in err
    assert "42: status unread" in err
    assert "no current-generation queue row found" not in err
