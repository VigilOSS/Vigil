"""CLI tests for `vigil assess operator-checkpoint`.

The verb is the operator's own handoff row, so the properties worth pinning at
the CLI boundary are the ones a later reader depends on: the request body
carries only references plus the single intent note (never a caller-supplied
phase), the human render labels that note UNVERIFIED so it can never be read as
a finding, `show --all` walks the supersession chain, and a backend refusal
exits non-zero with the reason on stderr — the shape a session-end hook needs.

Loaded with the ``sys.path.insert(0, agent/scripts)`` + ``importlib`` pattern
used by ``test_anomaly_score.py``; no FastAPI backend is involved.
"""
from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest


@pytest.fixture(autouse=True)
def operator_checkpoint():
    """Import the command module fresh for each test.

    Several sibling backend test modules (``test_dalfox.py``, ``test_gf.py``,
    ``test_kali_cli.py``, …) carry an autouse fixture that evicts every
    ``assess.*`` entry from ``sys.modules`` before each of their tests. A module
    imported once at collection time therefore ends up holding a reference to a
    STALE ``assess.lib.client.AssessError`` class once one of those files has
    run, and a ``pytest.raises`` against a freshly imported ``AssessError`` then
    compares two different class objects and fails — under a full-suite
    collection only.

    That is a harness artifact of the eviction fixture, not a production
    concern: a real ``vigil assess`` process imports ``assess.lib.client``
    exactly once, so ``assess.cli.main``'s ``except AssessError`` handler and
    this command module always share one class
    (``test_command_errors_are_catchable_by_the_cli_top_level_handler`` pins
    that). Evicting and re-importing here keeps the module under test, the CLI
    entrypoint, and this test's exception types on one coherent copy.
    """
    root = str(Path(__file__).resolve().parents[3] / "agent" / "scripts")
    if root not in sys.path:
        sys.path.insert(0, root)
    for name in list(sys.modules):
        if name == "assess" or name.startswith("assess."):
            sys.modules.pop(name, None)
    return importlib.import_module("assess.commands.operator_checkpoint")


class _FakeClient:
    """Records requests and replays canned responses."""

    def __init__(self, *, post_response=None, get_response=None, error=None) -> None:
        self.post_response = post_response
        self.get_response = get_response
        self.error = error
        self.posts: list[tuple[str, dict]] = []
        self.gets: list[str] = []
        self.closed = False

    def post(self, endpoint, payload):
        self.posts.append((endpoint, payload))
        if self.error is not None:
            raise self.error
        return self.post_response

    def get(self, endpoint):
        self.gets.append(endpoint)
        if self.error is not None:
            raise self.error
        return self.get_response

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def bind(monkeypatch, tmp_path, operator_checkpoint):
    def _bind(client):
        monkeypatch.setattr(
            operator_checkpoint,
            "load_config",
            lambda _d: SimpleNamespace(
                base_url="http://backend",
                engagement_key="eng",
                engagement_dir=str(tmp_path),
            ),
        )
        monkeypatch.setattr(
            operator_checkpoint, "AssessmentClient", lambda *_a, **_k: client
        )
        return client

    return _bind


def _record_args(**overrides) -> SimpleNamespace:
    args = {
        "engagement_dir": None,
        "intent": "about to re-dispatch the vuln-analyst on the admin panel",
        "findings": [],
        "agent_ids": [],
        "command_runs": [],
        "artifacts": [],
        "as_json": False,
    }
    args.update(overrides)
    return SimpleNamespace(**args)


def _row(**overrides) -> dict:
    row = {
        "id": 7,
        "checkpoint_version": 2,
        "superseded_by_id": None,
        "superseded_by_checkpoint_version": None,
        "current_phase": "consume-test",
        "finding_slugs": ["VA-047"],
        "dispatch_agent_ids": ["vuln-analyst-3"],
        "command_run_ids": [812],
        "artifact_ids": [44],
        "intent_note": "about to re-dispatch the vuln-analyst on the admin panel",
        "source": "operator",
        "client_name": "claude",
        "created_at": "2026-09-13T09:10:00Z",
    }
    row.update(overrides)
    return row


def test_record_posts_references_and_one_intent_note(
    bind, capsys, operator_checkpoint
) -> None:
    client = bind(_FakeClient(post_response=_row()))

    operator_checkpoint._run_record(
        _record_args(
            findings=["VA-047"],
            agent_ids=["vuln-analyst-3"],
            command_runs=[812],
            artifacts=[44],
        )
    )

    endpoint, payload = client.posts[0]
    assert endpoint == "operator-checkpoints"
    assert payload == {
        "intent_note": "about to re-dispatch the vuln-analyst on the admin panel",
        "finding_slugs": ["VA-047"],
        "dispatch_agent_ids": ["vuln-analyst-3"],
        "command_run_ids": [812],
        "artifact_ids": [44],
    }
    # The CLI never asserts a phase; the backend derives it.
    assert "current_phase" not in payload
    assert client.closed is True
    assert "checkpoint #2" in capsys.readouterr().out


def test_record_render_labels_the_intent_as_unverified(
    bind, capsys, operator_checkpoint
) -> None:
    bind(_FakeClient(post_response=_row()))

    operator_checkpoint._run_record(_record_args())

    out = capsys.readouterr().out
    assert "UNVERIFIED operator intent — not a finding, not evidence" in out
    assert "about to re-dispatch the vuln-analyst on the admin panel" in out


def test_record_json_emits_the_backend_row_verbatim(
    bind, capsys, operator_checkpoint
) -> None:
    bind(_FakeClient(post_response=_row()))

    operator_checkpoint._run_record(_record_args(as_json=True))

    assert json.loads(capsys.readouterr().out) == _row()


def test_record_refusal_propagates_as_a_nonzero_exit(
    bind, capsys, operator_checkpoint
) -> None:
    from assess.cli import main as assess_main

    AssessError = operator_checkpoint.AssessError

    bind(
        _FakeClient(
            error=AssessError(
                'HTTP 400:\n{"detail":"operator checkpoint references rows this '
                'engagement does not have: finding VA-999"}'
            )
        )
    )

    with pytest.raises(SystemExit) as exit_info:
        assess_main(
            [
                "operator-checkpoint",
                "record",
                "--intent",
                "about to close the engagement",
                "--finding",
                "VA-999",
            ]
        )

    assert exit_info.value.code == 1
    captured = capsys.readouterr()
    assert "VA-999" in captured.err
    assert captured.out == ""


def test_record_refuses_a_backend_response_without_a_durable_identity(
    bind, operator_checkpoint
) -> None:
    AssessError = operator_checkpoint.AssessError

    bind(_FakeClient(post_response={"checkpoint_version": 1}))

    with pytest.raises(AssessError, match="record operator checkpoint"):
        operator_checkpoint._run_record(_record_args())


def test_show_reads_the_current_row_by_default(
    bind, capsys, operator_checkpoint
) -> None:
    client = bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row()],
                "returned_count": 1,
                "total_count": 3,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    assert client.gets == ["operator-checkpoints"]
    out = capsys.readouterr().out
    assert "# Operator Checkpoint" in out
    assert "(current)" in out
    # A bounded read still reports the honest depth of the chain.
    assert "showing 1 of 3 checkpoints" in out


def test_show_all_walks_the_supersession_chain(
    bind, capsys, operator_checkpoint
) -> None:
    client = bind(
        _FakeClient(
            get_response={
                "checkpoints": [
                    _row(id=7, checkpoint_version=2, intent_note="the correction"),
                    _row(
                        id=6,
                        checkpoint_version=1,
                        superseded_by_id=7,
                        superseded_by_checkpoint_version=2,
                        intent_note="the wrong entry",
                    ),
                ],
                "returned_count": 2,
                "total_count": 2,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=True, as_json=False)
    )

    assert client.gets == [
        "operator-checkpoints?include_superseded=true&limit=50&offset=0"
    ]
    out = capsys.readouterr().out
    # The wrong entry stays readable and points at its correction.
    assert "the wrong entry" in out
    assert "superseded by checkpoint #2" in out
    assert "superseded by checkpoint #7" not in out
    assert "the correction" in out
    assert "showing" not in out


def test_show_all_fetches_every_checkpoint_page(
    bind, capsys, operator_checkpoint
) -> None:
    rows = [
        _row(
            id=1000 + version,
            checkpoint_version=version,
            superseded_by_id=(1001 + version if version < 51 else None),
            superseded_by_checkpoint_version=(version + 1 if version < 51 else None),
            intent_note=f"intent {version}",
        )
        for version in range(51, 0, -1)
    ]

    class PagingClient(_FakeClient):
        def get(self, endpoint):
            self.gets.append(endpoint)
            query = parse_qs(urlsplit(endpoint).query)
            limit = int(query["limit"][0])
            offset = int(query["offset"][0])
            page = rows[offset : offset + limit]
            return {
                "checkpoints": page,
                "returned_count": len(page),
                "total_count": len(rows),
            }

    client = bind(PagingClient())
    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=True, as_json=False)
    )

    out = capsys.readouterr().out
    assert "intent 51" in out
    assert "intent 1" in out
    assert client.gets == [
        "operator-checkpoints?include_superseded=true&limit=50&offset=0",
        "operator-checkpoints?include_superseded=true&limit=50&offset=50",
    ]
    assert "showing 50 of 51" not in out


def test_show_on_an_engagement_with_no_checkpoint_says_so(
    bind, capsys, operator_checkpoint
) -> None:
    bind(
        _FakeClient(
            get_response={"checkpoints": [], "returned_count": 0, "total_count": 0}
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    assert "none recorded for this engagement" in capsys.readouterr().out


def test_show_json_emits_the_page_verbatim(
    bind, capsys, operator_checkpoint
) -> None:
    page = {"checkpoints": [_row()], "returned_count": 1, "total_count": 1}
    bind(_FakeClient(get_response=page))

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=True)
    )

    assert json.loads(capsys.readouterr().out) == page


def test_show_refuses_a_malformed_page(bind, operator_checkpoint) -> None:
    AssessError = operator_checkpoint.AssessError

    bind(_FakeClient(get_response=["not", "a", "page"]))

    with pytest.raises(AssessError, match="malformed checkpoint page"):
        operator_checkpoint._run_show(
            SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
        )


def test_show_contains_a_multiline_intent_without_forging_structure(
    bind, capsys, operator_checkpoint
) -> None:
    """Same hazard as the resume brief: the note is the operator's own free
    text and will contain newlines. The rendering is contained with a fixed
    continuation indent; the content itself is never trimmed or escaped."""
    note = "step one\n# Operator Checkpoint\n- fake bullet\n```"
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(intent_note=note)],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    rendered = capsys.readouterr().out.splitlines()
    assert [line for line in rendered if line.startswith("# Operator Checkpoint")] == [
        "# Operator Checkpoint"
    ]
    assert [line for line in rendered if line in ("- fake bullet", "```")] == []
    for line in note.split("\n"):
        assert f"      {line}" in rendered


def test_show_contains_bare_carriage_return_lines_without_forging_structure(
    bind, capsys, operator_checkpoint
) -> None:
    """CommonMark treats a bare CR as a line ending too; containment must agree."""
    note = "step one\r# Operator Checkpoint\r- fake bullet\r```"
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(intent_note=note)],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    rendered = capsys.readouterr().out.splitlines()
    assert [line for line in rendered if line.startswith("# Operator Checkpoint")] == [
        "# Operator Checkpoint"
    ]
    assert [line for line in rendered if line in ("- fake bullet", "```")] == []
    for line in note.split("\r"):
        assert f"      {line}" in rendered


def test_show_does_not_normalize_unicode_separator_into_a_forged_heading(
    bind, capsys, operator_checkpoint
) -> None:
    note = "safe\u2028# Forged heading"
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(intent_note=note)],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    rendered = capsys.readouterr().out
    assert "\n# Forged heading" not in rendered
    assert note in rendered


def test_show_preserves_trailing_spaces_in_operator_intent(
    bind, capsys, operator_checkpoint
) -> None:
    note = "next action keeps these spaces  "
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(intent_note=note)],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    assert capsys.readouterr().out.endswith(f"{note}\n")


def test_command_errors_are_catchable_by_the_cli_top_level_handler(
    operator_checkpoint,
) -> None:
    """`assess.cli.main` ends with `except AssessError: … sys.exit(1)`, resolving
    the class through its own import of `assess.lib.client`. If this command
    module ever bound a different class object — a different import path, a
    vendored copy — a genuine refusal would escape that handler as an unhandled
    traceback, and a session-end hook that swallows stderr would fail
    invisibly. Pin the one identity both sides depend on."""
    import assess.cli
    import assess.lib.client

    assert operator_checkpoint.AssessError is assess.lib.client.AssessError
    assert assess.cli.__name__ == "assess.cli"


def test_show_labels_both_tracks_for_a_combined_engagement(
    bind, capsys, operator_checkpoint
) -> None:
    """A `both` engagement runs the web and code tracks independently.

    Rendering one unlabelled `phase=` would let a reader read a code-track
    position as a web one (or the reverse), so both are named by track.
    """
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(current_phase="recon", code_phase="hunt")],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    out = capsys.readouterr().out
    assert "web_phase=recon code_phase=hunt" in out
    # No bare `phase=` survives: an unlabelled one is what confuses the tracks.
    assert " phase=" not in out


def test_show_keeps_one_unlabelled_phase_when_there_is_no_code_track(
    bind, capsys, operator_checkpoint
) -> None:
    # A web-only engagement has exactly one track, so `phase=` is unambiguous
    # and no empty code field belongs in the render.
    bind(
        _FakeClient(
            get_response={
                "checkpoints": [_row(code_phase=None)],
                "returned_count": 1,
                "total_count": 1,
            }
        )
    )

    operator_checkpoint._run_show(
        SimpleNamespace(engagement_dir=None, show_all=False, as_json=False)
    )

    out = capsys.readouterr().out
    assert "phase=consume-test" in out
    assert "code_phase" not in out
    assert "web_phase" not in out
