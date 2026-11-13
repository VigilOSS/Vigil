"""One code phase, two spellings: the track phase and its audit tag.

The code track's roster names its phases (`hunt`, `verify-variant`,
`classify-map`, ...) while command-run rows tag code work with the index-aligned
audit vocabulary (`code-hunt`, `code-verify`, `code-classify`, ...). A dispatch
granted `hunt` whose handoff records `code-hunt` ran the phase it was granted;
`agent start` stores the track spelling for an audit-tag grant and says so; and
a grant from another track's roster is named rather than silently recorded.
"""
from __future__ import annotations

import pytest

from assess.commands import agent
from assess.lib.phases import (
    CODE_PHASE_AUDIT_TAGS,
    CODE_PHASES,
    WEB_PHASES,
    code_audit_tag,
    resolve_track_phase,
)
from test_dispatch_authorized_phase import _start_args
from test_handoff_renderer_provenance import _run_renderer


def test_every_code_audit_tag_resolves_to_its_index_aligned_track_phase():
    assert [resolve_track_phase(tag) for tag in CODE_PHASE_AUDIT_TAGS] == list(CODE_PHASES)


@pytest.mark.parametrize("phase", [*WEB_PHASES, *CODE_PHASES, "recon-pivot", "phase-2b"])
def test_a_phase_that_is_not_a_code_audit_tag_resolves_to_its_canonical_self(phase):
    assert resolve_track_phase(phase) == phase


def test_every_code_track_phase_maps_to_its_index_aligned_audit_tag():
    assert [code_audit_tag(phase) for phase in CODE_PHASES] == list(CODE_PHASE_AUDIT_TAGS)
    assert [code_audit_tag(resolve_track_phase(tag)) for tag in CODE_PHASE_AUDIT_TAGS] == list(
        CODE_PHASE_AUDIT_TAGS
    )


@pytest.mark.parametrize("phase", [*WEB_PHASES, *CODE_PHASE_AUDIT_TAGS, "recon-pivot", "phase-2b"])
def test_a_phase_that_is_not_a_code_track_phase_keeps_its_canonical_spelling(phase):
    assert code_audit_tag(phase) == phase


def test_input_aliases_and_case_resolve_too():
    assert resolve_track_phase(" Consume ") == "consume-test"
    assert resolve_track_phase("CODE-HUNT") == "hunt"


# ── agent start ──────────────────────────────────────────────────────────────


def test_start_stores_the_track_phase_for_a_code_audit_tag_and_echoes_it(
    monkeypatch, tmp_path, capsys
):
    args, client = _start_args(
        monkeypatch, tmp_path, prompt_context={"authorized_phase": "code-hunt"},
    )
    agent._start(args)
    err = capsys.readouterr().err
    packet = client.writes[0]["prompt_packet"]
    assert packet["context"]["authorized_phase"] == "hunt"
    assert "authorized_phase: hunt" in packet["rendered_prompt"]
    assert "'code-hunt'" in err and "'hunt'" in err


@pytest.mark.parametrize(
    ("role", "mode", "granted"),
    [
        ("vulnerability-analyst", "web", "hunt"),
        ("vulnerability-analyst", "web", "verify-variant"),
        ("code-vuln-hunter", "code", "consume-test"),
        ("code-vuln-hunter", "code", "investigate"),
    ],
)
def test_a_grant_from_another_tracks_roster_is_advised_not_refused(
    monkeypatch, tmp_path, capsys, role, mode, granted
):
    args, client = _start_args(
        monkeypatch, tmp_path, role=role, mode=mode,
        prompt_context={"authorized_phase": granted},
    )
    agent._start(args)
    err = capsys.readouterr().err
    assert client.writes[0]["prompt_packet"]["context"]["authorized_phase"] == granted
    advisory = [line for line in err.splitlines() if "ADVISORY" in line and granted in line]
    assert advisory, err
    assert "track" in advisory[0]


@pytest.mark.parametrize(
    ("role", "mode", "granted"),
    [
        ("vulnerability-analyst", "web", "consume-test"),
        ("vulnerability-analyst", "web", "verify"),
        ("code-vuln-hunter", "code", "hunt"),
        ("code-variant-hunter", "code", "verify-variant"),
        # A proof route grants a web phase to whichever role runs the web proof.
        ("exploit-developer", "web", "exploit"),
    ],
)
def test_a_grant_from_the_dispatchs_own_track_draws_no_advisory(
    monkeypatch, tmp_path, capsys, role, mode, granted
):
    args, _client = _start_args(
        monkeypatch, tmp_path, role=role, mode=mode,
        prompt_context={"authorized_phase": granted},
    )
    agent._start(args)
    assert "ADVISORY agent start: authorized_phase" not in capsys.readouterr().err


@pytest.mark.parametrize(
    ("scope", "granted", "advised"),
    [
        ({"engagement_type": "code", "current_phase": "verify-variant"}, "verify-variant", False),
        ({"engagement_type": "code", "current_phase": "fuzz"}, "consume-test", True),
        ({"engagement_type": "web", "current_phase": "report"}, "report", False),
        ({"engagement_type": "web", "current_phase": "report"}, "hunt", True),
    ],
)
def test_a_role_shared_by_both_tracks_takes_the_track_of_a_single_track_engagement(
    monkeypatch, tmp_path, capsys, scope, granted, advised
):
    """A report-writer carries no track of its own; on a one-track engagement the
    scope's track is the one it works, so a grant from that roster is its own."""
    args, _client = _start_args(
        monkeypatch, tmp_path, role="report-writer", mode="", scope=scope,
        prompt_context={"authorized_phase": granted},
    )
    agent._start(args)
    advisory = [
        line for line in capsys.readouterr().err.splitlines()
        if line.startswith("ADVISORY agent start: authorized_phase") and "track" in line
    ]
    assert bool(advisory) is advised, advisory


def test_an_off_roster_phase_advisory_names_the_track_rosters(monkeypatch, tmp_path, capsys):
    args, _client = _start_args(
        monkeypatch, tmp_path, prompt_context={"authorized_phase": "phase-2b"},
    )
    agent._start(args)
    err = capsys.readouterr().err
    advisory = next(line for line in err.splitlines() if "phase-2b" in line)
    for phase in ("hunt", "consume-test", "investigate"):
        assert phase in advisory


# ── render-handoff ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("ran", "granted"),
    [
        ("code-hunt", "hunt"),
        ("code-verify", "verify-variant"),
        ("code-classify", "classify-map"),
        ("hunt", "code-hunt"),
        ("consume", "consume-test"),
    ],
)
def test_the_same_phase_in_either_spelling_is_not_a_divergence(
    tmp_path, monkeypatch, capsys, ran, granted
):
    _run_renderer(
        monkeypatch, tmp_path, dispatch_slugs=[], handoff_slugs=[], max_lines=0,
        dispatch_extra={"agent_role": "code-vuln-hunter"},
        handoff_extra={"phase": ran},
        packet_context={"authorized_phase": granted, "queue_item_ids": [41]},
    )
    assert "differs" not in capsys.readouterr().out.lower()


def test_a_genuinely_different_code_phase_still_diverges(tmp_path, monkeypatch, capsys):
    _run_renderer(
        monkeypatch, tmp_path, dispatch_slugs=[], handoff_slugs=[], max_lines=0,
        handoff_extra={"phase": "code-classify"},
        packet_context={"authorized_phase": "hunt"},
    )
    assert "differs" in capsys.readouterr().out.lower()
