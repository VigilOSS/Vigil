"""B2 CLI half: binding a prior-art lead to code, and turning it into work.

The binding only earns its place if an operator can reach it: say where the
lead lives, see which bound files still have no analysis queue row, and create
those rows through the one queue write path that already enforces the
canonical-attempt and live-lease rules.
"""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from assess.commands import code_lead
from assess.lib.contracts import render_contract


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    # `--engagement-dir` lives on the assess root parser, so mirror it here or
    # every handler sees a Namespace the real CLI would never hand it.
    parser.add_argument("--engagement-dir", dest="engagement_dir", default=None)
    code_lead.register(parser.add_subparsers(dest="command"))
    return parser


def _binding(**overrides) -> dict:
    row = {
        "id": 1,
        "note_id": 7,
        "lead_title": "SAML signature bypass, 2023",
        "lead_status": "open",
        "repo_id": 3,
        "repo_key": "app-repo",
        "repo_role": "analysis",
        "file_id": 11,
        "file_path": "src/saml/parser.py",
        "repo_generation": 4,
        "line_start": 10,
        "line_end": 40,
        "prior_art_ref": "CVE-2023-9999",
        "rationale": "",
        "binding_status": "current",
        "carries_obligation": True,
        "analysis_priority": 90,
        "classification": "critical",
        "queued": False,
        "queue_item_id": None,
        "queue_status": "",
    }
    row.update(overrides)
    return row


class _Client:
    """Records every write and serves reads the way the real endpoint does.

    The listing endpoint's default filter (`source_superseded_at IS NULL AND
    repo_generation = active_generation`) is the exact complement of `stale`, so
    a stub that hands stale rows to an unfiltered read tests a response the
    backend cannot produce — which is how a caller that never asks for them
    passed a test for reporting them.
    """

    posts: list[tuple[str, dict]] = []
    gets: list[str] = []
    rows: list[dict] = []
    bind_response: dict = {}
    queue_response: dict = {
        "inserted": 1,
        "updated": 0,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
        "outcomes": [],
    }

    def __init__(self, *_args, **_kwargs):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def get(self, endpoint: str):
        type(self).gets.append(endpoint)
        include_superseded = "include_superseded=true" in endpoint
        items = [
            row
            for row in type(self).rows
            if include_superseded or row.get("binding_status") == "current"
        ]
        return {"total": len(items), "items": items}

    def post(self, endpoint: str, payload: dict):
        type(self).posts.append((endpoint, payload))
        if endpoint == "code/analysis-queue":
            return type(self).queue_response
        return type(self).bind_response


@pytest.fixture(autouse=True)
def _wire(monkeypatch, tmp_path):
    _Client.posts = []
    _Client.gets = []
    _Client.rows = []
    _Client.bind_response = _binding()
    _Client.queue_response = {
        "inserted": 1,
        "updated": 0,
        "already_active": 0,
        "conflicts": 0,
        "reanalysis": 0,
        "outcomes": [],
    }
    monkeypatch.setattr(code_lead, "AssessmentClient", _Client)
    monkeypatch.setattr(
        code_lead,
        "load_config",
        lambda *_a, **_k: SimpleNamespace(
            base_url="http://example.test",
            engagement_key="eng-code",
            engagement_dir=str(tmp_path),
        ),
    )
    from assess.commands import code_dispatch

    monkeypatch.setattr(code_dispatch, "AssessmentClient", _Client)


def _run(*argv) -> None:
    args = _parser().parse_args(["code-lead", *argv])
    args.func(args)


def test_bind_posts_the_typed_location_and_names_the_queue_step(capsys):
    _run(
        "bind", "7",
        "--repo-id", "3",
        "--file-path", "src/saml/parser.py",
        "--line-start", "10",
        "--line-end", "40",
        "--prior-art", "CVE-2023-9999",
    )

    endpoint, payload = _Client.posts[0]
    assert endpoint == "code/lead-bindings"
    assert payload == {
        "note_id": 7,
        "repo_id": 3,
        "file_path": "src/saml/parser.py",
        "line_start": 10,
        "line_end": 40,
        "prior_art_ref": "CVE-2023-9999",
        "rationale": "",
        "bound_by": "",
    }
    out = capsys.readouterr().out
    assert "src/saml/parser.py:10-40" in out
    # The next step is named by the command's own output, not by a prompt.
    assert "vigil assess code-lead queue" in out


def test_bind_fails_loudly_when_the_backend_returns_no_durable_binding():
    _Client.bind_response = {"note_id": 7}

    with pytest.raises(Exception) as exc:
        _run("bind", "7", "--repo-id", "3", "--file-path", "src/saml/parser.py")

    assert "do not retry automatically" in str(exc.value)


def test_list_renders_obligation_queue_and_staleness(capsys):
    _Client.rows = [
        _binding(),
        _binding(
            id=2,
            note_id=8,
            lead_title="Framework parser advisory",
            repo_id=4,
            repo_key="keycloak",
            repo_role="reference",
            carries_obligation=False,
            binding_status="stale",
            queued=True,
            queue_item_id=55,
            queue_status="done",
        ),
    ]

    _run("list", "--lead-status", "open", "--include-superseded")

    assert _Client.gets == [
        "code/lead-bindings?lead_status=open&include_superseded=true&limit=500"
    ]
    out = capsys.readouterr().out
    assert "src/saml/parser.py" in out
    assert "CVE-2023-9999" in out
    assert "stale" in out
    assert "reference" in out
    assert "55" in out


def test_list_says_when_every_binding_is_hidden_by_the_default_filter(capsys):
    # After a re-ingest every binding is stale and the default page is empty,
    # while the completion gate still counts those leads. "No lead bindings
    # matched" on its own reads as "there are none".
    _Client.rows = [_binding(binding_status="stale")]

    _run("list", "--lead-status", "open")

    out = capsys.readouterr().out
    assert "No lead bindings matched" in out
    assert "--include-superseded" in out
    assert "1" in out


def test_queue_submits_only_unqueued_current_analysis_bindings(capsys):
    _Client.rows = [
        _binding(),
        # Already has a current queue row: the lead is already work.
        _binding(id=2, note_id=8, file_id=12, queued=True, queue_item_id=55),
        # Reference source owes nothing, so it must never buy a queue row.
        _binding(id=3, note_id=9, file_id=13, repo_role="reference",
                 carries_obligation=False),
        # Stale binding: the line range needs re-reading before it is work.
        _binding(id=4, note_id=10, file_id=14, binding_status="stale"),
    ]

    _run("queue")

    queue_posts = [p for p in _Client.posts if p[0] == "code/analysis-queue"]
    assert len(queue_posts) == 1
    payload = queue_posts[0][1]
    assert payload["mode"] == "initial"
    assert [item["file_id"] for item in payload["items"]] == [11]
    # The priority a queue row carries must be the file's own current band.
    assert payload["items"][0]["priority"] == 90
    assert payload["items"][0]["batch_theme"] == "prior-art-lead"
    assert payload["items"][0]["guidance_hypotheses"] == [
        "prior-art lead 7 (CVE-2023-9999): SAML signature bypass, 2023 "
        "@ src/saml/parser.py:10-40"
    ]
    # Every field the shared normaliser adds, because this write goes through
    # it rather than around it.
    assert payload["items"][0]["slot_types"] == []
    out = capsys.readouterr().out
    assert "stale" in out


def test_queue_reads_the_stale_bindings_the_default_filter_hides(capsys):
    # `stale` is the exact complement of the listing default, so a caller that
    # does not ask for superseded rows can never see one: the re-bind guidance
    # was unreachable and the queue reported "nothing to do" after every
    # re-ingest, while the completion gate went on counting the leads.
    _Client.rows = [_binding(id=4, note_id=10, binding_status="stale")]

    _run("queue")

    assert any("include_superseded=true" in endpoint for endpoint in _Client.gets)
    assert not [p for p in _Client.posts if p[0] == "code/analysis-queue"]
    out = capsys.readouterr().out
    assert "binding 4 (lead 10)" in out
    assert "vigil assess code-lead bind" in out
    # The false explanation: these bindings DO carry an unanswered obligation.
    assert "no bound file carries an unanswered obligation" not in out


def test_queue_items_are_normalised_by_the_same_rules_as_code_dispatch(capsys):
    # The item cap, the priority range and the dedupe are the queue's contract.
    # Reaching `submit_queue_items` without them is safe only by accident.
    _Client.rows = [_binding(analysis_priority=101)]

    with pytest.raises(SystemExit) as exc:
        _run("queue")

    assert exc.value.code == 1
    assert not [p for p in _Client.posts if p[0] == "code/analysis-queue"]


def test_queue_dry_run_prints_what_a_real_run_would_submit(capsys):
    _Client.rows = [_binding()]

    _run("queue", "--dry-run")

    out = capsys.readouterr().out
    assert not [p for p in _Client.posts if p[0] == "code/analysis-queue"]
    printed = json.loads(out[: out.index("[dry-run]")])
    assert printed == [
        {
            "file_id": 11,
            "priority": 90,
            "batch_theme": "prior-art-lead",
            "slot_types": [],
            "guidance_hypotheses": [
                "prior-art lead 7 (CVE-2023-9999): SAML signature bypass, 2023 "
                "@ src/saml/parser.py:10-40"
            ],
        }
    ]


def test_queue_exits_non_zero_when_the_backend_reports_a_conflict(capsys):
    _Client.rows = [_binding()]
    _Client.queue_response = {
        "inserted": 0,
        "updated": 0,
        "already_active": 0,
        "conflicts": 1,
        "reanalysis": 0,
        "outcomes": [],
    }

    with pytest.raises(SystemExit) as exc:
        _run("queue")

    assert exc.value.code == 1


def test_queue_reports_nothing_to_do_without_inventing_work(capsys):
    _Client.rows = [_binding(queued=True, queue_item_id=55)]

    _run("queue")

    assert not [p for p in _Client.posts if p[0] == "code/analysis-queue"]
    assert "no bound file" in capsys.readouterr().out


def test_unbind_requires_a_reason_and_posts_it():
    _Client.bind_response = _binding(binding_status="unbound")

    _run("unbind", "1", "--reason", "bound to the wrong parser")

    assert _Client.posts[0] == (
        "code/lead-bindings/1/unbind",
        {"reason": "bound to the wrong parser"},
    )

    with pytest.raises(SystemExit):
        _parser().parse_args(["code-lead", "unbind", "1"])


def test_contract_documents_every_action_and_the_completion_gate():
    rendered = render_contract("code-lead")

    for action in ("bind", "list", "queue", "unbind"):
        assert f"code-lead {action}" in rendered
    assert "code_leads_unresolved" in rendered
    assert "lead_status" in rendered


def test_readiness_repair_names_the_lead_worklist_and_the_closing_verb(capsys):
    """The blocker is the operator's discovery surface for this whole feature,
    so it has to name both the read that lists the leads and the write that
    closes one."""
    from assess.commands import code_coverage

    code_coverage._print_transition_readiness(
        "complete",
        {
            "target_phase": "complete",
            "transition_ready": False,
            "blockers": [
                {
                    "code": "code_leads_unresolved",
                    "message": "Repository has 2 unanswered prior-art lead(s).",
                    "overrideable": True,
                    "repo_id": 4,
                }
            ],
        },
    )

    out = capsys.readouterr().out
    # The gate counts open AND in_progress leads, stale bindings included, so the
    # repair read must not filter either away.
    assert "vigil assess code-lead list --repo-id 4 --include-superseded" in out
    assert "--lead-status" not in out
    assert "intel update note" in out
    assert "ruled_out" in out
