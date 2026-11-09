"""Call-site affordances on the finding / intel CLI surfaces.

Four defects of one family: the command knows exactly what the caller should
have written and answers with something else.

  * ``intel record note --summary "..."`` takes a JSON document, not content
    flags. argparse attributes the leftover to the ROOT parser, so the answer
    was a usage block naming every top-level verb plus
    ``unrecognized arguments: --summary`` — neither the file argument nor the
    schema behind it.
  * ``finding link`` spells its rationale ``--reason`` while the field it lands
    in is the link's own ``notes``, so ``--notes`` was the natural first attempt
    and got the same root usage dump.
  * ``finding update --payload-file`` demanded ``expected_row_version`` even for
    a pure notes append. The token guards a read-modify-write; an append is not
    one (the concatenation happens inside the same transaction that reads the
    stored notes and checks the compare-and-swap), which is why the backend
    requires it for ``notes_mode`` replace/rotate and ``details_mode`` replace
    only.
  * ``finding show`` is not the verb — ``finding get`` is — and the refusal
    printed the group's whole action roster without pointing at the near match.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json

import pytest
from _fake_client import StubClient

from assess.commands import link_finding, update_finding


def _run_cli(argv: list[str]) -> tuple[int | None, str, str]:
    """Invoke ``assess.cli.main``, capturing both streams and the exit code."""
    from assess import cli

    out, err = io.StringIO(), io.StringIO()
    code: int | None = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main(list(argv))
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


# --------------------------------------------------------------------------- #
# J2 — `intel record` answers an unknown flag with its own schema
# --------------------------------------------------------------------------- #


def test_intel_record_unknown_flag_names_the_json_shape_and_its_fields() -> None:
    code, _out, err = _run_cli(["intel", "record", "note", "--summary", "a note"])

    assert code == 2
    # The offending flag, at this verb's scope.
    assert "--summary" in err
    assert "intel record" in err
    # A one-line runnable example and the schema behind it.
    assert "vigil assess intel record note note.json" in err
    assert "intel-note.schema.json" in err
    # The schema's author-supplied fields, so the caller can place the content
    # they tried to pass as a flag.
    for field in ("title", "source_name", "provenance"):
        assert field in err
    assert "vigil assess contract intel record note" in err
    # NOT the root parser's whole verb roster.
    assert "usage: vigil assess [-h]" not in err
    assert "dns-discovery" not in err


def test_intel_record_unknown_flag_is_answered_before_a_missing_file_argument() -> None:
    """A flag typo must not be reported as a missing positional instead.

    ``--summary`` with no value leaves ``json_file`` unfilled, so argparse's own
    required-argument check would fire first and say nothing about the flag.
    """
    code, _out, err = _run_cli(["intel", "record", "note", "--summary"])

    assert code == 2
    assert "--summary" in err
    assert "vigil assess intel record note note.json" in err


def test_intel_record_without_a_type_still_names_the_generic_contract() -> None:
    code, _out, err = _run_cli(["intel", "record", "--summary", "a note"])

    assert code == 2
    assert "--summary" in err
    assert "vigil assess contract intel record" in err


def test_intel_record_registered_flags_and_help_are_untouched() -> None:
    parser = argparse.ArgumentParser()
    from assess.commands import record_intel

    record_intel.register(parser.add_subparsers(dest="action"))
    args = parser.parse_args(["record", "note", "note.json", "--dry-run"])

    assert (args.intel_type, args.json_file, args.dry_run) == ("note", "note.json", True)


# --------------------------------------------------------------------------- #
# J3 — `finding link --notes` reaches the same rationale as `--reason`
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("flag", ["--reason", "--notes"])
def test_finding_link_accepts_either_spelling_of_the_rationale(flag: str) -> None:
    parser = argparse.ArgumentParser()
    link_finding.register(parser.add_subparsers(dest="action"))

    args = parser.parse_args(["link", "acme-002", "--root-cause", "acme-001", flag, "same parser bug"])

    assert args.reason_text == "same parser bug"


def test_finding_link_notes_reaches_the_generic_link_notes_field(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    posts: list[tuple[str, dict]] = []

    class _Client(StubClient):
        def post(self, path: str, payload: dict) -> dict:
            posts.append((path, payload))
            return {
                "id": 11,
                "link_kind": payload["link_kind"],
                "target_kind": payload["target_kind"],
                "target_ref": payload["target_ref"],
            }

    class _Cfg:
        engagement_dir = str(tmp_path)
        base_url = "http://backend.invalid"
        engagement_key = "test-eng"

    monkeypatch.setattr(link_finding, "load_config", lambda *a, **k: _Cfg())
    monkeypatch.setattr(link_finding, "AssessmentClient", lambda *a, **k: _Client())

    parser = argparse.ArgumentParser()
    link_finding.register(parser.add_subparsers(dest="action"))
    args = parser.parse_args([
        "link", "acme-002", "--link-kind", "unblocked_by", "--target-kind", "finding",
        "--target-ref", "acme-003", "--notes", "credential wall cleared",
    ])
    args.engagement_dir = str(tmp_path)
    link_finding.run(args)
    capsys.readouterr()

    assert posts == [
        (
            "findings/acme-002/links",
            {
                "link_kind": "unblocked_by",
                "target_kind": "finding",
                "target_id": None,
                "target_ref": "acme-003",
                "notes": "credential wall cleared",
                "provenance": {},
            },
        )
    ]


# --------------------------------------------------------------------------- #
# J4 — a payload-file notes append needs no compare-and-swap token
# --------------------------------------------------------------------------- #


class _Cfg:
    def __init__(self, engagement_dir: str) -> None:
        self.engagement_dir = engagement_dir
        self.base_url = "http://backend.invalid"
        self.engagement_key = "test-eng"


class _FakeClient(StubClient):
    def __init__(self) -> None:
        self.gets: list[str] = []
        self.patches: list[tuple[str, dict]] = []

    def get(self, path: str) -> dict:
        self.gets.append(path)
        return {"slug": path.split("/", 1)[-1], "row_version": 7}

    def patch(self, path: str, payload: dict) -> dict:
        self.patches.append((path, payload))
        return {"finding": {"slug": path.split("/", 1)[-1], "row_version": 8}}

def _update_args(argv: list[str], engagement_dir: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    update_finding.register(parser.add_subparsers(dest="action"))
    args = parser.parse_args(argv)
    args.engagement_dir = engagement_dir
    return args


def _write_payload(tmp_path, payload: dict) -> str:
    path = tmp_path / "patch.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_payload_file_notes_append_needs_no_expected_row_version(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(update_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *a, **k: fake)
    payload_file = _write_payload(
        tmp_path,
        {
            "notes": "checkpoint: replayed the chain against acme.example",
            "notes_mode": "append",
            "source_name": "vulnerability-analyst",
        },
    )

    update_finding.run(
        _update_args(["update", "acme-001", "--payload-file", payload_file], str(tmp_path))
    )

    captured = capsys.readouterr()
    assert "expected_row_version" not in captured.err
    # Appending commutes inside the backend transaction; it needs no preceding
    # read that could introduce a conflict with another independent append.
    assert fake.gets == []
    assert fake.patches == [
        (
            "findings/acme-001",
            {
                "notes": "checkpoint: replayed the chain against acme.example",
                "notes_mode": "append",
                "source_name": "vulnerability-analyst",
            },
        )
    ]


@pytest.mark.parametrize(
    "payload",
    [
        # A scalar overwrite IS a read-modify-write of the field it changes.
        {"summary": "rewritten", "notes": "checkpoint", "notes_mode": "append"},
        # A details merge replaces a repeated key's whole value.
        {"details": {"impact": "x"}, "notes": "checkpoint", "notes_mode": "append"},
        # The replacement modes are the ones the backend itself gates.
        {"notes": "rewritten", "notes_mode": "replace"},
        {"notes": "rewritten", "notes_mode": "rotate"},
        {"details": {"impact": "x"}, "details_mode": "replace"},
    ],
)
def test_payload_file_still_requires_the_token_for_a_non_append_patch(
    payload: dict,
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    fake = _FakeClient()
    monkeypatch.setattr(update_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *a, **k: fake)
    payload_file = _write_payload(tmp_path, payload)

    with pytest.raises(SystemExit) as exc_info:
        update_finding.run(
            _update_args(["update", "acme-001", "--payload-file", payload_file], str(tmp_path))
        )

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "expected_row_version" in captured.err
    assert not fake.patches


def test_payload_file_append_with_a_bad_token_is_still_refused(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A token the author DID write must still be a positive integer."""
    fake = _FakeClient()
    monkeypatch.setattr(update_finding, "load_config", lambda *a, **k: _Cfg(str(tmp_path)))
    monkeypatch.setattr(update_finding, "AssessmentClient", lambda *a, **k: fake)
    payload_file = _write_payload(
        tmp_path,
        {"notes": "checkpoint", "notes_mode": "append", "expected_row_version": 0},
    )

    with pytest.raises(SystemExit) as exc_info:
        update_finding.run(
            _update_args(["update", "acme-001", "--payload-file", payload_file], str(tmp_path))
        )

    assert exc_info.value.code == 1
    assert "expected_row_version" in capsys.readouterr().err
    assert not fake.patches


# --------------------------------------------------------------------------- #
# J6 — an unknown group action points at the near match
# --------------------------------------------------------------------------- #


def test_finding_show_points_at_finding_get() -> None:
    code, _out, err = _run_cli(["finding", "show", "acme-001"])

    assert code == 2
    assert "'show'" in err
    assert "Did you mean: get?" in err
    # The full action roster still follows the suggestion, never replaces it.
    assert "record" in err and "verify" in err and "history" in err
    # No multi-line usage dump.
    assert "usage:" not in err


@pytest.mark.parametrize(
    ("group", "typo", "expected"),
    [
        ("finding", "updte", "update"),
        ("finding", "verfy", "verify"),
        ("intel", "show", "get"),
        ("intel", "create", "record"),
        ("command-run", "view", "get"),
    ],
)
def test_group_action_typos_and_synonyms_point_at_the_registered_action(
    group: str, typo: str, expected: str
) -> None:
    code, _out, err = _run_cli([group, typo])

    assert code == 2
    assert f"Did you mean: {expected}?" in err


def test_unrelated_group_action_lists_the_roster_without_inventing_a_match() -> None:
    code, _out, err = _run_cli(["finding", "fizzbuzz"])

    assert code == 2
    assert "'fizzbuzz'" in err
    assert "Did you mean" not in err
    assert "actions:" in err


def test_a_real_group_action_still_dispatches() -> None:
    """The near-match hook must not change a valid invocation's path."""
    code, out, _err = _run_cli(["finding", "list", "--help"])

    assert code == 0
    assert "--json" in out
