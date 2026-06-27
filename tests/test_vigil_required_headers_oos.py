"""Unit tests for required attribution headers + out-of-scope carve-outs on
`vigil engagement create` and the mid-engagement management commands.

Exercises the pure resolvers, the scope.json wiring in `plan_engagement`, the
read-modify-write management helpers, and the argparse end-to-end dry-run path.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


# --------------------------------------------------------------------------- #
# resolve_required_headers
# --------------------------------------------------------------------------- #


def test_preset_expands_to_program_header():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers("bugcrowd", "vigiloss", []) == {"X-Bug-Bounty": "vigiloss"}
    assert resolve_required_headers("hackerone", "alex", []) == {"X-HackerOne": "alex"}


def test_custom_headers_and_override():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers(None, None, ["X-A: 1", "X-B: two words"]) == {
        "X-A": "1",
        "X-B": "two words",
    }
    # A later --header overrides an earlier preset of the same name.
    assert resolve_required_headers("bugcrowd", "alex", ["X-Bug-Bounty: override"]) == {
        "X-Bug-Bounty": "override"
    }


def test_none_is_empty():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers(None, None, []) == {}


@pytest.mark.parametrize(
    "program,researcher,headers,needle",
    [
        ("bugcrowd", None, [], "requires --researcher"),
        ("zzz", "alex", [], "unknown --program"),
        (None, "alex", [], "only meaningful together with --program"),
        (None, None, ["malformed"], "malformed"),
        (None, None, [": v"], "empty header name"),
    ],
)
def test_required_headers_validation(program, researcher, headers, needle):
    from vigil_cli.engagements import resolve_required_headers

    with pytest.raises(SystemExit) as exc:
        resolve_required_headers(program, researcher, headers)
    assert needle in str(exc.value)


# --------------------------------------------------------------------------- #
# resolve_out_of_scope
# --------------------------------------------------------------------------- #


def test_out_of_scope_normalizes_and_dedups():
    from vigil_cli.engagements import resolve_out_of_scope

    assert resolve_out_of_scope(
        ["mobile.acme.example", "*.mobile.acme.example", "Dup.com", "dup.com"]
    ) == ["mobile.acme.example", "*.mobile.acme.example", "dup.com"]
    assert resolve_out_of_scope(None) == []


def test_out_of_scope_rejects_whitespace():
    from vigil_cli.engagements import resolve_out_of_scope

    with pytest.raises(SystemExit):
        resolve_out_of_scope(["two hosts.com"])


# --------------------------------------------------------------------------- #
# plan_engagement scope.json wiring
# --------------------------------------------------------------------------- #


def _web_opts(**kw):
    from vigil_cli.engagements import CreateEngagementOptions

    base = dict(
        install_root=Path("/tmp"),
        engagement_type="web",
        target="https://t.com",
        hosts=["*.t.com"],
    )
    base.update(kw)
    return CreateEngagementOptions(**base)


def test_plan_wires_scope_for_web():
    from vigil_cli.engagements import plan_engagement

    plan = plan_engagement(
        _web_opts(required_headers={"X-Bug-Bounty": "alex"}, out_of_scope=["a.t.com"])
    )
    assert plan.scope["required_headers"] == {"X-Bug-Bounty": "alex"}
    assert plan.scope["out_of_scope"] == ["a.t.com"]


def test_plan_omits_keys_when_unused():
    from vigil_cli.engagements import plan_engagement

    plan = plan_engagement(_web_opts())
    assert "required_headers" not in plan.scope
    assert "out_of_scope" not in plan.scope


def test_plan_rejects_headers_on_code_engagement():
    from vigil_cli.engagements import CreateEngagementOptions, plan_engagement

    opts = CreateEngagementOptions(
        install_root=Path("/tmp"),
        engagement_type="code",
        name="proj",
        required_headers={"X-Bug-Bounty": "alex"},
    )
    with pytest.raises(SystemExit):
        plan_engagement(opts)


# --------------------------------------------------------------------------- #
# mid-engagement management helpers
# --------------------------------------------------------------------------- #


def _make_engagement(tmp_path: Path) -> Path:
    from vigil_cli.engagements import engagements_root

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    eng = root / "eng1"
    eng.mkdir()
    (eng / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "hosts": ["*.t.com"], "status": "in_progress"})
    )
    return eng


def test_set_and_unset_header_roundtrip(tmp_path):
    from vigil_cli.engagements import set_engagement_header, unset_engagement_header

    eng = _make_engagement(tmp_path)
    assert set_engagement_header(tmp_path, "eng1", "X-Bug-Bounty: alex") == {"X-Bug-Bounty": "alex"}
    assert json.loads((eng / "scope.json").read_text())["required_headers"] == {"X-Bug-Bounty": "alex"}
    # Removing the last header drops the key entirely.
    assert unset_engagement_header(tmp_path, "eng1", "X-Bug-Bounty") == {}
    assert "required_headers" not in json.loads((eng / "scope.json").read_text())


def test_add_and_remove_oos_roundtrip(tmp_path):
    from vigil_cli.engagements import add_out_of_scope, remove_out_of_scope

    eng = _make_engagement(tmp_path)
    merged = add_out_of_scope(tmp_path, "eng1", ["a.t.com", "*.m.t.com", "a.t.com"])
    assert merged == ["a.t.com", "*.m.t.com"]
    assert json.loads((eng / "scope.json").read_text())["out_of_scope"] == ["a.t.com", "*.m.t.com"]
    assert remove_out_of_scope(tmp_path, "eng1", "a.t.com") == ["*.m.t.com"]


def test_management_rejects_non_http_engagement(tmp_path):
    from vigil_cli.engagements import engagements_root, set_engagement_header

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    eng = root / "codeproj"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({"engagement_type": "code", "status": "in_progress"}))
    with pytest.raises(SystemExit):
        set_engagement_header(tmp_path, "codeproj", "X-Bug-Bounty: alex")


def test_unset_missing_header_errors(tmp_path):
    from vigil_cli.engagements import set_engagement_header, unset_engagement_header

    _make_engagement(tmp_path)
    set_engagement_header(tmp_path, "eng1", "X-A: 1")
    with pytest.raises(SystemExit):
        unset_engagement_header(tmp_path, "eng1", "X-Missing")


# --------------------------------------------------------------------------- #
# argparse end-to-end dry-run
# --------------------------------------------------------------------------- #


def test_cli_dry_run_json_wires_scope(capsys):
    from vigil_cli import main

    try:
        main.main(
            [
                "engagement", "create", "https://acme.example",
                "--hosts", "*.acme.example",
                "--program", "bugcrowd", "--researcher", "vigiloss",
                "--out-of-scope", "mobile.acme.example",
                "--dry-run", "--json",
            ]
        )
    except SystemExit as exc:  # tolerate either a normal return or sys.exit(0)
        assert exc.code in (0, None)
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["required_headers"] == {"X-Bug-Bounty": "vigiloss"}
    assert payload["scope"]["out_of_scope"] == ["mobile.acme.example"]


# --------------------------------------------------------------------------- #
# interactive create — the header/OOS questions are ASKED
# --------------------------------------------------------------------------- #


def _interactive_scope(monkeypatch, capsys, answers, extra_argv=()):
    """Drive `vigil engagement create` interactively with scripted answers and
    return the resolved scope dict from a --dry-run --json run."""
    from vigil_cli import main

    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: True)
    it = iter(answers)
    monkeypatch.setattr(main, "_read_line", lambda: next(it))
    argv = ["engagement", "create", "https://t.com", "--hosts", "*.t.com",
            "--dry-run", "--json", *extra_argv]
    try:
        main.main(argv)
    except SystemExit as exc:
        assert exc.code in (0, None)
    return json.loads(capsys.readouterr().out)["scope"]


def test_interactive_preset_header_and_oos_are_asked(monkeypatch, capsys):
    scope = _interactive_scope(
        monkeypatch, capsys,
        ["bugcrowd", "vigiloss", "mobile.acme.example *.mobile.acme.example"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "vigiloss"}
    assert scope["out_of_scope"] == ["mobile.acme.example", "*.mobile.acme.example"]


def test_interactive_custom_header(monkeypatch, capsys):
    scope = _interactive_scope(monkeypatch, capsys, ["custom", "X-HackerOne: alex", ""])
    assert scope["required_headers"] == {"X-HackerOne": "alex"}
    assert "out_of_scope" not in scope


def test_interactive_none_skips_both(monkeypatch, capsys):
    scope = _interactive_scope(monkeypatch, capsys, ["none", ""])
    assert "required_headers" not in scope
    assert "out_of_scope" not in scope


def test_interactive_skipped_when_flags_present(monkeypatch, capsys):
    # No answers scripted: if a prompt fired it would StopIteration. Flags must
    # suppress both prompts.
    scope = _interactive_scope(
        monkeypatch, capsys, [],
        extra_argv=["--program", "bugcrowd", "--researcher", "alex", "--out-of-scope", "a.t.com"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "alex"}
    assert scope["out_of_scope"] == ["a.t.com"]


def test_interactive_header_via_flag_still_asks_oos(monkeypatch, capsys):
    # Mixed path: header given via flag (suppresses the header prompt) but OOS
    # omitted, so the OOS prompt still fires. Only one answer is scripted — a
    # header prompt firing would consume it and break the assertion.
    scope = _interactive_scope(
        monkeypatch, capsys, ["carved.t.com"],
        extra_argv=["--program", "bugcrowd", "--researcher", "alex"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "alex"}
    assert scope["out_of_scope"] == ["carved.t.com"]


def _drive_create(monkeypatch, answers, confirm, tmp_path, extra_argv=()):
    """Run a NON-dry-run interactive create with a stubbed create_engagement and
    _confirm, returning (captured_options_or_None, raised_or_None)."""
    from types import SimpleNamespace
    from vigil_cli import main

    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: True)
    it = iter(answers)
    monkeypatch.setattr(main, "_read_line", lambda: next(it))
    monkeypatch.setattr(main, "_confirm", lambda prompt: confirm)
    captured: dict = {}

    def fake_create(options):
        captured["options"] = options
        return SimpleNamespace(path=tmp_path / "eng", key="eng")

    monkeypatch.setattr(main, "create_engagement", fake_create)
    raised = None
    try:
        main.main(["engagement", "create", "https://t.com", "--hosts", "*.t.com", *extra_argv])
    except SystemExit as exc:
        raised = exc
    return captured.get("options"), raised


def test_interactive_confirm_yes_creates_with_resolved_scope(monkeypatch, capsys, tmp_path):
    options, raised = _drive_create(
        monkeypatch, ["bugcrowd", "vigiloss", "appointments.t.com"], True, tmp_path
    )
    assert raised is None
    assert options.required_headers == {"X-Bug-Bounty": "vigiloss"}
    assert options.out_of_scope == ["appointments.t.com"]
    # The summary actually rendered the header + OOS for confirmation.
    err = capsys.readouterr().err
    assert "X-Bug-Bounty: vigiloss" in err
    assert "out-of-scope:" in err


def test_interactive_confirm_no_aborts_without_creating(monkeypatch, capsys, tmp_path):
    options, raised = _drive_create(
        monkeypatch, ["bugcrowd", "vigiloss", ""], False, tmp_path
    )
    assert isinstance(raised, SystemExit)
    assert "aborted" in str(raised.code)
    assert options is None  # create_engagement never called


def test_interactive_none_and_blank_skips_summary(monkeypatch, capsys, tmp_path):
    # header=none + blank OOS ⇒ asked stays False ⇒ no summary/confirm, create
    # proceeds straight through (the pre-change behavior for a fully-specified run).
    options, raised = _drive_create(monkeypatch, ["none", ""], True, tmp_path)
    assert raised is None
    assert options.required_headers == {}
    assert options.out_of_scope == []
    # asked stayed False, so the summary block never ran.
    assert "engagement summary:" not in capsys.readouterr().err
