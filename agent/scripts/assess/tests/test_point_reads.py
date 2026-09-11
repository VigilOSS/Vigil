"""Focused contracts for finding/intel point reads and their fetch guidance."""
from __future__ import annotations

import json
import argparse
from types import SimpleNamespace
from urllib.parse import parse_qsl

import pytest

from assess import cli
from assess.commands import fetch
from assess.lib import config, contracts
from assess.lib.client import AssessmentClient, AssessError
from assess.lib.intel_types import INTEL_TYPES


def _engagement(tmp_path):
    (tmp_path / "scope.json").write_text("{}\n", encoding="utf-8")
    return tmp_path


def test_finding_get_reads_one_exact_row(tmp_path, monkeypatch, capsys) -> None:
    engagement = _engagement(tmp_path)
    expected = {
        "slug": "VA-047",
        "title": "Preserve parsed details",
        "details": {"evidence": "full response body"},
    }
    requested: list[str] = []

    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get(_client, endpoint: str):
        requested.append(endpoint)
        return expected

    monkeypatch.setattr(AssessmentClient, "get", get)

    cli.main(
        ["--engagement-dir", str(engagement), "finding", "get", "VA-047"]
    )

    assert requested == ["findings/VA-047"]
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert "UNTRUSTED DATA" in captured.err


@pytest.mark.parametrize("response", [{"slug": "VA-999"}, []])
def test_finding_get_rejects_response_without_requested_slug(
    response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            ["--engagement-dir", str(engagement), "finding", "get", "VA-047"]
        )

    assert exc.value.code == 1
    assert "requested finding VA-047" in capsys.readouterr().err


@pytest.mark.parametrize(
    "intel_type,endpoint_segment",
    [(name, metadata[1]) for name, metadata in sorted(INTEL_TYPES.items())],
)
def test_intel_get_maps_every_type_to_its_backend_route(
    intel_type, endpoint_segment, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    expected = {
        "id": 17,
        "source_name": "recon-specialist",
        "provenance": {"agent_name": "recon-specialist", "command_run_id": 91},
    }
    requested: list[tuple[str, str]] = []

    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)

    def get_engagement(_client, endpoint: str, query: str = ""):
        requested.append((endpoint, query))
        return expected

    monkeypatch.setattr(AssessmentClient, "get_engagement", get_engagement)

    cli.main(
        [
            "--engagement-dir",
            str(engagement),
            "intel",
            "get",
            intel_type,
            "17",
        ]
    )

    assert requested == [(f"intel/{endpoint_segment}/17", "")]
    captured = capsys.readouterr()
    assert json.loads(captured.out) == expected
    assert "UNTRUSTED DATA" in captured.err


def test_intel_get_rejects_unknown_type_with_valid_choices(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get_engagement",
        lambda *_args, **_kwargs: pytest.fail("invalid type reached the backend"),
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "intel",
                "get",
                "technology",
                "17",
            ]
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "unknown intel type 'technology'" in stderr
    assert "tech-component" in stderr


@pytest.mark.parametrize("response", [{"id": 18}, "not-a-record"])
def test_intel_get_rejects_response_without_requested_id(
    response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get_engagement",
        lambda *_args, **_kwargs: response,
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "intel",
                "get",
                "note",
                "17",
            ]
        )

    assert exc.value.code == 1
    assert "requested note 17" in capsys.readouterr().err


@pytest.mark.parametrize("response", [{"id": 43}, []])
def test_command_run_get_rejects_response_without_requested_id(
    response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            ["--engagement-dir", str(engagement), "command-run", "get", "42"]
        )

    assert exc.value.code == 1
    assert "requested command run 42" in capsys.readouterr().err


@pytest.mark.parametrize("response", [{"id": 1}, [{"id": 1}]])
def test_finding_history_rejects_malformed_transition_list(
    response, tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(AssessmentClient, "get", lambda *_args: response)

    with pytest.raises(SystemExit) as exc:
        cli.main(
            [
                "--engagement-dir",
                str(engagement),
                "finding",
                "history",
                "VA-047",
            ]
        )

    assert exc.value.code == 1
    assert "transition history for VA-047" in capsys.readouterr().err


def test_fetch_parser_exposes_explicit_pagination_opt_in() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()
    fetch.register(subparsers)

    args = parser.parse_args(["fetch", "surfaces", "--paginate"])

    assert args.paginate is True


def test_fetch_findings_defaults_to_one_bounded_compact_page(capsys) -> None:
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            return [{"slug": "VA-001", "details": {"evidence": "A" * 4096}}]

    rows = fetch._fetch_assessment_endpoint(_Client(), "findings")

    assert rows == [
        {
            "slug": "VA-001",
            "_point_read": "vigil assess finding get VA-001",
        }
    ]
    assert calls == ["findings?limit=100&offset=0"]
    assert "use --paginate" in capsys.readouterr().err


def test_fetch_findings_paginate_traverses_every_complete_row(capsys) -> None:
    calls: list[tuple[str, int]] = []
    expected = [
        {"slug": "VA-001", "details": {"evidence": "A" * 4096}},
        {"slug": "VA-002", "details": {"evidence": "B" * 4096}},
    ]

    class _Client:
        def get_all_pages(self, endpoint: str, *, page_size: int):
            calls.append((endpoint, page_size))
            return expected

    rows = fetch._fetch_assessment_endpoint(_Client(), "findings", paginate=True)

    assert rows == expected
    assert calls == [("findings", 5000)]
    assert "fetched 2 findings row(s)" in capsys.readouterr().err


def test_fetch_findings_paginate_honors_explicit_window_from_offset(
    monkeypatch, capsys
) -> None:
    calls: list[str] = []
    source = [
        {"slug": f"VA-{index:03d}", "details": {"evidence": str(index)}}
        for index in range(1, 6)
    ]
    monkeypatch.setitem(fetch._PAGED_ASSESSMENT_ENDPOINTS, "findings", 2)

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            _path, _sep, query = endpoint.partition("?")
            params = dict(parse_qsl(query))
            offset = int(params["offset"])
            limit = int(params["limit"])
            return source[offset : offset + limit]

    rows = fetch._fetch_assessment_endpoint(
        _Client(),
        "findings?limit=2&offset=1",
        paginate=True,
    )

    assert rows == source[1:]
    assert calls == [
        "findings?limit=2&offset=1",
        "findings?limit=2&offset=3",
        "findings?limit=2&offset=5",
    ]
    assert "fetched 4 findings row(s)" in capsys.readouterr().err


def test_fetch_findings_offset_only_still_injects_a_bound(capsys) -> None:
    calls: list[str] = []

    class _Client:
        def get(self, endpoint: str):
            calls.append(endpoint)
            return []

    rows = fetch._fetch_assessment_endpoint(_Client(), "findings?offset=100")

    assert rows == []
    assert calls == ["findings?offset=100&limit=100"]
    assert "bounded page" in capsys.readouterr().err


def test_fetch_findings_rejects_malformed_list_page() -> None:
    class _Client:
        def get(self, _endpoint: str):
            return {"items": []}

    with pytest.raises(AssessError, match="fetch findings expected a JSON array"):
        fetch._fetch_assessment_endpoint(_Client(), "findings")


@pytest.mark.parametrize("row", [{"id": 1}, 42])
def test_fetch_findings_rejects_malformed_rows(row) -> None:
    class _Client:
        def get(self, _endpoint: str):
            return [row]

    with pytest.raises(AssessError, match="finding row without a slug"):
        fetch._fetch_assessment_endpoint(_Client(), "findings")


def test_fetch_findings_malformed_page_uses_standard_cli_error(
    tmp_path, monkeypatch, capsys
) -> None:
    engagement = _engagement(tmp_path)
    monkeypatch.setattr(config, "_verify_backend", lambda _cfg: None)
    monkeypatch.setattr(
        AssessmentClient,
        "get",
        lambda *_args: {"items": []},
    )

    with pytest.raises(SystemExit) as exc:
        cli.main(["--engagement-dir", str(engagement), "fetch", "findings"])

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "ERROR: fetch findings expected a JSON array" in stderr


def test_fetch_engagement_list_defaults_to_one_bounded_page(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            return [{"id": 1, "body_markdown": "complete"}]

    rows = fetch._fetch_engagement_endpoint(_Client(), "intel/notes")

    assert rows == [{"id": 1, "body_markdown": "complete"}]
    assert calls == [("intel/notes", "limit=100&offset=0")]
    assert "bounded page" in capsys.readouterr().err


def test_fetch_credential_alias_defaults_to_one_bounded_page(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            return [{"id": 1, "credential_key": "opaque-key"}]

    rows = fetch._fetch_engagement_endpoint(_Client(), "intel/credentials")

    assert rows == [{"id": 1, "credential_key": "opaque-key"}]
    assert calls == [("intel/credentials", "limit=100&offset=0")]
    assert "bounded page" in capsys.readouterr().err


def test_fetch_engagement_list_paginate_preserves_complete_rows(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            if "offset=0" in query:
                return [{"id": 1, "body_markdown": "A" * 4096}]
            if "offset=1" in query:
                return []
            raise AssertionError(query)

    rows = fetch._fetch_engagement_endpoint(
        _Client(), "intel/notes", paginate=True, page_size=1
    )

    assert rows == [{"id": 1, "body_markdown": "A" * 4096}]
    assert calls == [
        ("intel/notes", "limit=1&offset=0"),
        ("intel/notes", "limit=1&offset=1"),
    ]
    assert "fetched 1 intel/notes row(s)" in capsys.readouterr().err


def test_fetch_engagement_list_paginate_honors_explicit_window_from_offset(
    capsys,
) -> None:
    calls: list[tuple[str, str]] = []
    source = [{"id": index, "body_markdown": str(index)} for index in range(5)]

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            params = dict(parse_qsl(query))
            offset = int(params["offset"])
            limit = int(params["limit"])
            return source[offset : offset + limit]

    rows = fetch._fetch_engagement_endpoint(
        _Client(),
        "intel/notes?limit=2&offset=1",
        paginate=True,
    )

    assert rows == source[1:]
    assert calls == [
        ("intel/notes", "limit=2&offset=1"),
        ("intel/notes", "limit=2&offset=3"),
        ("intel/notes", "limit=2&offset=5"),
    ]
    assert "fetched 4 intel/notes row(s)" in capsys.readouterr().err


def test_fetch_activity_paginate_combines_every_complete_entry(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            offset = 0 if "offset=0" in query else 1
            return {
                "total": 2,
                "items": [
                    {"id": offset + 1, "body_markdown": chr(65 + offset) * 4096}
                ],
            }

    result = fetch._fetch_engagement_endpoint(
        _Client(), "activity-entries", paginate=True, page_size=1
    )

    assert result["total"] == 2
    assert [row["id"] for row in result["items"]] == [1, 2]
    assert result["items"][1]["body_markdown"] == "B" * 4096
    assert calls == [
        ("activity-entries", "limit=1&offset=0"),
        ("activity-entries", "limit=1&offset=1"),
    ]
    assert "fetched 2 activity-entries row(s)" in capsys.readouterr().err


def test_fetch_activity_paginate_honors_explicit_window_from_offset(capsys) -> None:
    calls: list[tuple[str, str]] = []

    class _Client:
        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            params = dict(parse_qsl(query))
            offset = int(params["offset"])
            limit = int(params["limit"])
            items = [
                {"id": index + 1, "body_markdown": str(index + 1)}
                for index in range(offset, min(offset + limit, 5))
            ]
            return {"total": 5, "items": items}

    result = fetch._fetch_engagement_endpoint(
        _Client(),
        "activity-entries?limit=2&offset=1",
        paginate=True,
    )

    assert result["total"] == 4
    assert [row["id"] for row in result["items"]] == [2, 3, 4, 5]
    assert calls == [
        ("activity-entries", "limit=2&offset=1"),
        ("activity-entries", "limit=2&offset=3"),
    ]
    assert "fetched 4 activity-entries row(s)" in capsys.readouterr().err


@pytest.mark.parametrize(
    "name,route",
    [
        ("finding get", "GET /assessment/findings/{slug}"),
        ("intel get", "GET /intel/{type-plural}/{id}"),
    ],
)
def test_point_read_has_an_executable_contract(name, route) -> None:
    contract = contracts.get_contract(name)

    assert contract is not None
    assert contract.name == name
    assert contract.schema_name == route
    assert "Read-only" in " ".join(contract.notes)


@pytest.mark.parametrize("parent", ["finding", "intel"])
def test_namespace_contract_advertises_get(parent) -> None:
    rendered = contracts.render_contract(parent)

    assert "get" in rendered
    assert f"vigil assess {parent} get" in rendered


@pytest.mark.parametrize(
    "endpoint,expected_hint",
    [
        ("finding/VA-047", "vigil assess finding get VA-047"),
        ("intel/note/17", "vigil assess intel get note 17"),
    ],
)
def test_fetch_rejects_singular_point_routes_with_actionable_command(
    endpoint, expected_hint, monkeypatch, capsys
) -> None:
    monkeypatch.setattr(
        fetch,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://backend.invalid", engagement_key="example"
        ),
    )
    monkeypatch.setattr(
        fetch,
        "AssessmentClient",
        lambda *_args, **_kwargs: _FetchClient(),
    )

    with pytest.raises(SystemExit) as exc:
        fetch.run(
            SimpleNamespace(
                endpoint=endpoint,
                engagement_dir=None,
                compact=False,
                jq="",
            )
        )

    assert exc.value.code == 1
    stderr = capsys.readouterr().err
    assert "Did you mean" in stderr
    assert expected_hint in stderr


def test_fetch_keeps_valid_finding_subpath_available(monkeypatch, capsys) -> None:
    client = _FetchClient()
    monkeypatch.setattr(
        fetch,
        "load_config",
        lambda *_args, **_kwargs: SimpleNamespace(
            base_url="http://backend.invalid", engagement_key="example"
        ),
    )
    monkeypatch.setattr(fetch, "AssessmentClient", lambda *_args, **_kwargs: client)

    fetch.run(
        SimpleNamespace(
            endpoint="findings/VA-047",
            engagement_dir=None,
            compact=False,
            jq="",
        )
    )

    assert client.assessment_requests == ["findings/VA-047"]
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"slug": "VA-047"}
    assert "UNTRUSTED DATA" in captured.err


class _FetchClient:
    def __init__(self) -> None:
        self.assessment_requests: list[str] = []
        self.engagement_requests: list[str] = []

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> bool:
        return False

    def get(self, endpoint: str):
        self.assessment_requests.append(endpoint)
        return {"slug": "VA-047"}

    def get_engagement(self, endpoint: str):
        self.engagement_requests.append(endpoint)
        return {"id": 17}
