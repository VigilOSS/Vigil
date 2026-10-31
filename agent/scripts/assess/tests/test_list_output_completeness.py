"""Bounded assessment listings expose what was omitted and how to continue."""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from assess.commands import list_command_runs, list_findings, list_intel
from assess.lib.client import AssessError
from assess.lib.list_output import page_from_backend, report_page


class _ContextClient:
    def close(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def _config() -> SimpleNamespace:
    return SimpleNamespace(base_url="http://example.test", engagement_key="eng")


def _finding(index: int) -> dict[str, object]:
    return {
        "id": index,
        "slug": f"VA-{index:03d}",
        "title": f"Finding {index}",
        "severity": "high",
        "workflow_status": "active",
        "verification_status": "unreviewed",
        "canonical_location": f"https://example.test/{index}",
        "source_name": "vulnerability-analyst",
        "details": {"evidence": "E" * 100_000},
        "notes": "N" * 100_000,
        "provenance": {"raw": "P" * 100_000},
    }


def test_finding_list_json_bounds_rows_and_points_to_complete_records(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, endpoint: str):
            calls.append(endpoint)
            return [_finding(1), _finding(2), _finding(3)]

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            severity=None,
            workflow_status=None,
            verification_status=None,
            source_name=None,
            slug=None,
            root_cause_slug=None,
            search=None,
            holding=False,
            limit=2,
            offset=0,
            json=True,
        )
    )

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert calls == ["findings?limit=3&offset=0"]
    assert [row["slug"] for row in rows] == ["VA-001", "VA-002"]
    assert all("details" not in row and "notes" not in row for row in rows)
    assert rows[0]["_point_read"] == "vigil assess finding get VA-001"
    assert "showing 1-2 of at least 3 matching findings" in captured.err
    assert "continue with `vigil assess finding list --limit 2 --offset 2`" in captured.err


def test_finding_list_rejects_removed_unbounded_all_flag(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = argparse.ArgumentParser()
    list_findings.register(parser.add_subparsers(dest="action"))

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["list", "--all"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "--all was removed" in error
    assert "--limit/--offset" in error


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--severity", "urgent"), ("--workflow-status", "verified")],
)
def test_finding_list_rejects_values_outside_backend_vocabularies(
    flag: str,
    value: str,
) -> None:
    parser = argparse.ArgumentParser()
    list_findings.register(parser.add_subparsers(dest="action"))

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["list", flag, value])

    assert exc_info.value.code == 2


def test_intel_type_list_is_bounded_at_the_api_and_compacts_json_rows(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, str]] = []

    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            return [
                {
                    "id": index,
                    "title": f"Lead {index}",
                    "source_name": "osint-analyst",
                    "body_markdown": "B" * 100_000,
                    "provenance": {"raw": "P" * 100_000},
                }
                for index in range(2, 5)
            ]

    monkeypatch.setattr(list_intel, "AssessmentClient", _Client)
    monkeypatch.setattr(list_intel, "load_config", lambda _path: _config())

    list_intel.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            intel_type="note",
            q="",
            limit=2,
            offset=1,
            as_json=True,
        )
    )

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert calls == [("intel/notes", "limit=3&offset=1")]
    assert [row["id"] for row in rows] == [2, 3]
    assert all("body_markdown" not in row and "provenance" not in row for row in rows)
    assert rows[0]["_point_read"] == "vigil assess intel get note 2"
    assert "showing 2-3 of at least 4 matching intel rows" in captured.err


def test_human_root_cause_list_marks_finding_prose_untrusted(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _endpoint: str):
            return {
                "root": {"slug": "VA-001", "title": "target supplied title"},
                "siblings": [
                    {
                        "slug": "VA-002",
                        "title": "target supplied sibling",
                        "root_cause_note": "target supplied note",
                    }
                ],
                "sibling_count": 1,
            }

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            root_cause_slug="VA-001",
            json=False,
            limit=10,
            offset=0,
        )
    )

    captured = capsys.readouterr()
    assert "target supplied note" in captured.out
    assert "UNTRUSTED DATA" in captured.err


def test_finding_list_rejects_malformed_non_list_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _endpoint: str):
            return {"message": "not a finding list"}

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    with pytest.raises(AssessError, match="expected a JSON array"):
        list_findings.run(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                severity=None,
                workflow_status=None,
                verification_status=None,
                source_name=None,
                slug=None,
                root_cause_slug=None,
                search=None,
                holding=False,
                limit=2,
                offset=0,
                json=True,
            )
        )


@pytest.mark.parametrize(("intel_type", "query"), [("note", ""), (None, "oauth")])
def test_intel_row_list_rejects_malformed_non_list_response(
    intel_type: str | None,
    query: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get_engagement(self, _endpoint: str, query: str = ""):
            return {"message": "not an intel row list"}

    monkeypatch.setattr(list_intel, "AssessmentClient", _Client)
    monkeypatch.setattr(list_intel, "load_config", lambda _path: _config())

    with pytest.raises(AssessError, match="expected a JSON array"):
        list_intel.run(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                intel_type=intel_type,
                q=query,
                limit=2,
                offset=0,
                as_json=True,
            )
        )


def test_intel_search_pages_and_omits_hydrated_bodies_from_json(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[tuple[str, str]] = []

    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get_engagement(self, endpoint: str, query: str = ""):
            calls.append((endpoint, query))
            return [
                {
                    "entity_type": "note",
                    "source_id": index,
                    "key": f"Lead {index}",
                    "body": "B" * 100_000,
                    "source_name": "osint-analyst",
                    "rank": -1.0,
                    "record": {"id": index, "body_markdown": "R" * 100_000},
                }
                for index in range(6, 9)
            ]

    monkeypatch.setattr(list_intel, "AssessmentClient", _Client)
    monkeypatch.setattr(list_intel, "load_config", lambda _path: _config())

    list_intel.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            intel_type=None,
            q="oauth",
            limit=2,
            offset=5,
            as_json=True,
        )
    )

    captured = capsys.readouterr()
    rows = json.loads(captured.out)
    assert calls == [("intel/search", "q=oauth&limit=3&offset=5")]
    assert [row["source_id"] for row in rows] == [6, 7]
    assert all("body" not in row and "record" not in row for row in rows)
    assert rows[0]["_point_read"] == "vigil assess intel get note 6"
    assert "showing 6-7 of at least 8 matching intel rows" in captured.err


def test_intel_human_fallback_does_not_dump_an_unbounded_record_body() -> None:
    rendered = list_intel._format_row(
        {
            "id": 9,
            "source_name": "osint-analyst",
            "unrecognized_body_field": "SECRET" * 100_000,
        }
    )

    assert "SECRET" not in rendered
    assert "9" in rendered
    assert "osint-analyst" in rendered


def test_empty_overshoot_page_does_not_invent_an_exact_total(
    capsys: pytest.CaptureFixture[str],
) -> None:
    page = page_from_backend([], limit=2, offset=50, used_lookahead=True)

    report_page(page, noun="records")

    assert page.total is None
    assert page.total_at_least is None
    assert capsys.readouterr().err.strip() == (
        "showing no matching records at offset 50; total unavailable"
    )


def test_command_run_parser_replaces_ambiguous_all_with_explicit_flags(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = argparse.ArgumentParser()
    list_command_runs.register(parser.add_subparsers(dest="action"))

    args = parser.parse_args(["list", "--q", "VA-047 OIDC", "--match-all", "--paginate"])
    assert args.require_all is True
    assert args.paginate is True

    with pytest.raises(SystemExit) as exc_info:
        parser.parse_args(["list", "--all"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "--all was removed because it was ambiguous" in error
    assert "--match-all" in error
    assert "--paginate" in error


def test_command_run_paginate_reaches_the_final_page_without_omission(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, endpoint: str):
            calls.append(endpoint)
            if "offset=0" in endpoint:
                return [{"id": 1}, {"id": 2}]
            if "offset=2" in endpoint:
                return [{"id": 3}, {"id": 4}]
            if "offset=4" in endpoint:
                return [{"id": 5}]
            raise AssertionError(endpoint)

    monkeypatch.setattr(list_command_runs, "AssessmentClient", _Client)
    monkeypatch.setattr(list_command_runs, "load_config", lambda _path: _config())

    list_command_runs.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            q="VA-047 OIDC",
            sort="",
            show_matches=False,
            exact=False,
            require_all=True,
            paginate=True,
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            target_host="",
            audit_source="",
            route="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=False,
            destructive=False,
            not_destructive=False,
            timed_out=False,
            output_attention=False,
            include_output=False,
            limit=2,
            offset=0,
            as_json=True,
        )
    )

    captured = capsys.readouterr()
    assert [row["id"] for row in json.loads(captured.out)] == [1, 2, 3, 4, 5]
    assert calls == [
        "command-runs?q=VA-047%20OIDC&require_all=true&limit=2&offset=0",
        "command-runs?q=VA-047%20OIDC&require_all=true&limit=2&offset=2",
        "command-runs?q=VA-047%20OIDC&require_all=true&limit=2&offset=4",
    ]
    assert "showing 1-5 of 5 matching command runs" in captured.err


def test_command_run_single_page_uses_lookahead_without_printing_the_extra_row(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls: list[str] = []

    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, endpoint: str):
            calls.append(endpoint)
            return [{"id": 1}, {"id": 2}, {"id": 3}]

    monkeypatch.setattr(list_command_runs, "AssessmentClient", _Client)
    monkeypatch.setattr(list_command_runs, "load_config", lambda _path: _config())

    list_command_runs.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            q="",
            sort="",
            show_matches=False,
            exact=False,
            require_all=False,
            paginate=False,
            agent_name="",
            phase="",
            tool_name="",
            tool_bin="",
            target_host="",
            audit_source="",
            route="",
            technique="",
            probe_kind="",
            intent_q="",
            success=False,
            failed=False,
            destructive=False,
            not_destructive=False,
            timed_out=False,
            output_attention=False,
            include_output=False,
            limit=2,
            offset=0,
            as_json=True,
        )
    )

    captured = capsys.readouterr()
    assert calls == ["command-runs?limit=3&offset=0"]
    assert [row["id"] for row in json.loads(captured.out)] == [1, 2]
    assert "showing 1-2 of at least 3 matching command runs" in captured.err


def test_command_run_list_rejects_malformed_non_list_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _endpoint: str):
            return {"message": "not a command-run list"}

    monkeypatch.setattr(list_command_runs, "AssessmentClient", _Client)
    monkeypatch.setattr(list_command_runs, "load_config", lambda _path: _config())

    with pytest.raises(AssessError, match="expected a JSON array"):
        list_command_runs.run(
            SimpleNamespace(
                engagement_dir="/tmp/eng",
                q="",
                sort="",
                show_matches=False,
                exact=False,
                require_all=False,
                paginate=False,
                agent_name="",
                phase="",
                tool_name="",
                tool_bin="",
                target_host="",
                audit_source="",
                route="",
                technique="",
                probe_kind="",
                intent_q="",
                success=False,
                failed=False,
                destructive=False,
                not_destructive=False,
                timed_out=False,
                output_attention=False,
                include_output=False,
                limit=2,
                offset=0,
                as_json=True,
            )
        )


def test_finding_list_json_rows_carry_creation_time(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _endpoint: str):
            return [
                {
                    **_finding(1),
                    "created_at": "2026-10-24T09:00:00Z",
                    "updated_at": "2026-10-30T09:00:00Z",
                }
            ]

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            severity=None,
            workflow_status=None,
            verification_status=None,
            source_name=None,
            slug=None,
            root_cause_slug=None,
            search=None,
            holding=False,
            limit=10,
            offset=0,
            json=True,
        )
    )

    rows = json.loads(capsys.readouterr().out)
    assert rows[0]["created_at"] == "2026-10-24T09:00:00Z"
    assert rows[0]["updated_at"] == "2026-10-30T09:00:00Z"


def test_human_root_cause_list_applies_common_filters_to_siblings(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class _Client(_ContextClient):
        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def get(self, _endpoint: str):
            return {
                "root": {"slug": "VA-001", "severity": "low", "title": "Root"},
                "siblings": [
                    {
                        "slug": "VA-002",
                        "severity": "info",
                        "workflow_status": "active",
                        "verification_status": "confirmed",
                        "title": "Info sibling",
                    },
                    {
                        "slug": "VA-003",
                        "severity": "low",
                        "workflow_status": "active",
                        "verification_status": "confirmed",
                        "title": "Low sibling",
                    },
                ],
                "sibling_count": 2,
            }

    monkeypatch.setattr(list_findings, "AssessmentClient", _Client)
    monkeypatch.setattr(list_findings, "load_config", lambda _path: _config())

    list_findings.run(
        SimpleNamespace(
            engagement_dir="/tmp/eng",
            severity="info",
            workflow_status=None,
            verification_status=None,
            source_name=None,
            slug=None,
            root_cause_slug="VA-001",
            search=None,
            holding=False,
            limit=10,
            offset=0,
            json=False,
        )
    )

    captured = capsys.readouterr()
    assert "VA-002" in captured.out
    assert "VA-003" not in captured.out
    assert "showing 1-1 of 1 matching root-cause siblings" in captured.err
    assert "Siblings: 2 (1 match the filters)" in captured.out
