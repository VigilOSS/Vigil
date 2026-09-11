"""Unit tests for required attribution headers + out-of-scope carve-outs on
`vigil engagement create` and the mid-engagement management commands.

Exercises the pure resolvers, the scope.json wiring in `plan_engagement`, the
read-modify-write management helpers, and the argparse end-to-end dry-run path.
"""
from __future__ import annotations

import fcntl
import json
import sys
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))


# --------------------------------------------------------------------------- #
# resolve_required_headers
# --------------------------------------------------------------------------- #


def test_preset_expands_to_program_header():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers("bugcrowd", "acme-researcher", []) == {"X-Bug-Bounty": "acme-researcher"}
    assert resolve_required_headers("hackerone", "acme-researcher", []) == {"X-HackerOne": "acme-researcher"}


def test_custom_headers_and_override():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers(None, None, ["X-A: 1", "X-B: two words"]) == {
        "X-A": "1",
        "X-B": "two words",
    }
    # A later --header overrides an earlier preset of the same name.
    assert resolve_required_headers("bugcrowd", "acme-researcher", ["X-Bug-Bounty: override"]) == {
        "X-Bug-Bounty": "override"
    }


def test_none_is_empty():
    from vigil_cli.engagements import resolve_required_headers

    assert resolve_required_headers(None, None, []) == {}


@pytest.mark.parametrize(
    "program,researcher,headers,needle",
    [
        ("bugcrowd", None, [], "requires --researcher"),
        ("zzz", "acme-researcher", [], "unknown --program"),
        (None, "acme-researcher", [], "only meaningful together with --program"),
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
        ["appointments.example.com", "*.MOBILE.example.com", "Dup.com", "dup.com"]
    ) == ["appointments.example.com", "*.mobile.example.com", "dup.com"]
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
        target="https://target.example",
        hosts=["*.target.example"],
    )
    base.update(kw)
    return CreateEngagementOptions(**base)


def test_plan_wires_scope_for_web():
    from vigil_cli.engagements import plan_engagement

    plan = plan_engagement(
        _web_opts(required_headers={"X-Bug-Bounty": "acme-researcher"}, out_of_scope=["a.target.example"])
    )
    assert plan.scope["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    assert plan.scope["out_of_scope"] == ["a.target.example"]


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
        required_headers={"X-Bug-Bounty": "acme-researcher"},
    )
    with pytest.raises(SystemExit):
        plan_engagement(opts)


@pytest.mark.parametrize("engagement_type", ["code", "both", "android"])
def test_new_scope_does_not_write_legacy_repository_keys(engagement_type):
    from vigil_cli.engagements import CreateEngagementOptions, plan_engagement

    opts = CreateEngagementOptions(
        install_root=Path("/tmp"),
        engagement_type=engagement_type,
        target="https://target.example" if engagement_type == "both" else None,
        name="project",
        repos=["/src/project"],
    )

    plan = plan_engagement(opts)

    assert "repos" not in plan.scope
    assert "source_repos" not in plan.scope


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
        json.dumps({"engagement_type": "web", "hosts": ["*.target.example"], "status": "in_progress"})
    )
    return eng


def test_set_and_unset_header_roundtrip(tmp_path):
    from vigil_cli.engagements import set_engagement_header, unset_engagement_header

    eng = _make_engagement(tmp_path)
    assert set_engagement_header(tmp_path, "eng1", "X-Bug-Bounty: acme-researcher") == {"X-Bug-Bounty": "acme-researcher"}
    assert json.loads((eng / "scope.json").read_text())["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    # Removing the last header drops the key entirely.
    assert unset_engagement_header(tmp_path, "eng1", "X-Bug-Bounty") == {}
    assert "required_headers" not in json.loads((eng / "scope.json").read_text())


def test_add_and_remove_oos_roundtrip(tmp_path):
    from vigil_cli.engagements import add_out_of_scope, remove_out_of_scope

    eng = _make_engagement(tmp_path)
    merged = add_out_of_scope(tmp_path, "eng1", ["a.target.example", "*.m.target.example", "a.target.example"])
    assert merged == ["a.target.example", "*.m.target.example"]
    assert json.loads((eng / "scope.json").read_text())["out_of_scope"] == ["a.target.example", "*.m.target.example"]
    assert remove_out_of_scope(tmp_path, "eng1", "a.target.example") == ["*.m.target.example"]


def test_add_track_preserves_existing_phase_and_initializes_only_new_track(tmp_path):
    from vigil_cli import engagements

    assert hasattr(engagements, "add_engagement_track"), "explicit add-track operation is missing"
    add_engagement_track = engagements.add_engagement_track
    engagements_root = engagements.engagements_root

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    code = root / "code1"
    code.mkdir()
    (code / "scope.json").write_text(
        json.dumps({"engagement_type": "code", "current_phase": "hunt", "status": "in_progress"})
    )
    web = root / "web1"
    web.mkdir()
    (web / "scope.json").write_text(
        json.dumps({"engagement_type": "web", "current_phase": "complete", "status": "completed"})
    )

    assert add_engagement_track(tmp_path, "code1", "web") == {
        "engagement_type": "both",
        "current_phase": "recon",
        "code_phase": "hunt",
    }
    assert add_engagement_track(tmp_path, "web1", "code") == {
        "engagement_type": "both",
        "current_phase": "complete",
        "code_phase": "ingest",
    }
    updated_web = json.loads((web / "scope.json").read_text())
    assert updated_web["status"] == "in_progress"
    assert updated_web["code_target_contact_policy"] == (
        "warn-do-not-contact-declared-hosts"
    )
    assert updated_web["track_transitions"][0]["actor"] == "operator"


def test_add_track_is_idempotent_but_rejects_unrelated_transitions(tmp_path):
    from vigil_cli import engagements

    assert hasattr(engagements, "add_engagement_track"), "explicit add-track operation is missing"
    add_engagement_track = engagements.add_engagement_track
    engagements_root = engagements.engagements_root

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    eng = root / "both1"
    eng.mkdir()
    (eng / "scope.json").write_text(
        json.dumps(
            {
                "engagement_type": "both",
                "current_phase": "collect",
                "code_phase": "hunt",
                "status": "in_progress",
            }
        )
    )

    assert add_engagement_track(tmp_path, "both1", "code")["code_phase"] == "hunt"
    with pytest.raises(SystemExit, match="cannot add"):
        add_engagement_track(tmp_path, "both1", "android")


def test_repair_track_state_requires_explicit_both_legacy_shape(tmp_path):
    from vigil_cli import engagements

    assert hasattr(engagements, "repair_engagement_tracks"), "supported track repair is missing"
    repair_engagement_tracks = engagements.repair_engagement_tracks
    engagements_root = engagements.engagements_root

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    legacy = root / "legacy"
    legacy.mkdir()
    (legacy / "scope.json").write_text(
        json.dumps({"engagement_type": "both", "current_phase": "verify", "status": "in_progress"})
    )

    repaired = repair_engagement_tracks(tmp_path, "legacy")
    assert repaired == {
        "engagement_type": "both",
        "current_phase": "verify",
        "code_phase": "ingest",
    }
    with pytest.raises(SystemExit, match="already has"):
        repair_engagement_tracks(tmp_path, "legacy")


def test_add_host_and_set_rate_limit_use_canonical_scope_state(tmp_path):
    from vigil_cli import engagements

    assert hasattr(engagements, "add_engagement_hosts"), "canonical add-host is missing"
    assert hasattr(engagements, "set_engagement_rate_limit"), "canonical set-rate-limit is missing"
    add_engagement_hosts = engagements.add_engagement_hosts
    set_engagement_rate_limit = engagements.set_engagement_rate_limit

    eng = _make_engagement(tmp_path)
    hosts = add_engagement_hosts(tmp_path, "eng1", ["API.TARGET.EXAMPLE", "*.target.example"])
    assert hosts == ["*.target.example", "api.target.example"]
    assert set_engagement_rate_limit(tmp_path, "eng1", 5.9) == 5.9
    scope = json.loads((eng / "scope.json").read_text())
    assert scope["hosts"] == hosts
    assert scope["rate_limit"] == 5.9


@pytest.mark.parametrize(
    "entry",
    [
        "bad host.example",
        "-bad.example",
        "bad-.example",
        "bad..example",
        "foo*.example",
        "*.*.example",
        "10.0.0.0/999",
        "999.999.999.999",
        "example.com/path",
        "https://",
        "https://bad_.example/path",
        "[2001:db8::1",
    ],
)
def test_add_host_rejects_malformed_scope_entries_without_mutating_file(
    tmp_path, entry
):
    from vigil_cli.engagements import add_engagement_hosts

    engagement = _make_engagement(tmp_path)
    scope_path = engagement / "scope.json"
    before = scope_path.read_bytes()

    with pytest.raises(SystemExit, match="invalid host entry"):
        add_engagement_hosts(tmp_path, "eng1", [entry])

    assert scope_path.read_bytes() == before


def test_add_host_canonicalizes_supported_host_wildcard_ip_cidr_and_url(tmp_path):
    from vigil_cli.engagements import add_engagement_hosts

    engagement = _make_engagement(tmp_path)

    hosts = add_engagement_hosts(
        tmp_path,
        "eng1",
        [
            "API.Target.Example.",
            "*.BÜCHER.example",
            "10.0.0.5",
            "10.0.0.9/24",
            "[2001:db8::1]",
            "https://Portal.Example:443/path?q=1",
        ],
    )

    assert hosts == [
        "*.target.example",
        "api.target.example",
        "*.xn--bcher-kva.example",
        "10.0.0.5",
        "10.0.0.0/24",
        "2001:db8::1",
        "https://portal.example:443/path?q=1",
    ]
    assert json.loads((engagement / "scope.json").read_text())["hosts"] == hosts


def test_http_scope_mutation_supports_android_but_not_code(tmp_path):
    from vigil_cli import engagements

    assert hasattr(engagements, "add_engagement_hosts"), "canonical add-host is missing"
    add_engagement_hosts = engagements.add_engagement_hosts
    engagements_root = engagements.engagements_root

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    android = root / "android1"
    android.mkdir()
    (android / "scope.json").write_text(
        json.dumps({"engagement_type": "android", "status": "in_progress"})
    )
    assert add_engagement_hosts(tmp_path, "android1", ["api.mobile.example"] ) == [
        "api.mobile.example"
    ]

    code = root / "code1"
    code.mkdir()
    (code / "scope.json").write_text(
        json.dumps({"engagement_type": "code", "status": "in_progress"})
    )
    with pytest.raises(SystemExit, match="HTTP-target"):
        add_engagement_hosts(tmp_path, "code1", ["api.example"])


@pytest.mark.parametrize(
    ("argv", "helper", "expected"),
    [
        (["engagement", "add-track", "eng1", "code"], "add_engagement_track", ("eng1", "code")),
        (["engagement", "repair-tracks", "eng1"], "repair_engagement_tracks", ("eng1",)),
        (
            ["engagement", "add-host", "eng1", "a.example", "*.b.example"],
            "add_engagement_hosts",
            ("eng1", ["a.example", "*.b.example"]),
        ),
        (
            ["engagement", "set-rate-limit", "eng1", "5"],
            "set_engagement_rate_limit",
            ("eng1", 5.0),
        ),
    ],
)
def test_cli_exposes_canonical_scope_mutations(
    monkeypatch, tmp_path, capsys, argv, helper, expected
):
    from vigil_cli import main

    called = []

    def fake(*args, **_kwargs):
        called.append(args[1:])
        return {"ok": True}

    monkeypatch.setattr(main, helper, fake, raising=False)
    monkeypatch.setattr(main, "resolve_install_root", lambda *_args: tmp_path)
    monkeypatch.setattr(
        main, "_verify_backend_install_root", lambda *_args: True, raising=False
    )
    monkeypatch.setattr(main, "request_proxy_reload", lambda *_args: None)

    main.main(argv)

    assert called == [expected]
    assert json.loads(capsys.readouterr().out) == {"ok": True}


def test_scope_mutation_reports_retryable_backend_sync_partial(
    monkeypatch, tmp_path
):
    from vigil_cli import main

    monkeypatch.setattr(
        main,
        "add_engagement_track",
        lambda *_args: {"engagement_type": "both"},
    )
    monkeypatch.setattr(main, "resolve_install_root", lambda *_args: tmp_path)
    monkeypatch.setattr(main, "_verify_backend_install_root", lambda *_args: False)
    monkeypatch.setattr(
        main,
        "request_proxy_reload",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("proxy reload must wait for backend coherence")
        ),
    )

    with pytest.raises(SystemExit, match="committed.*backend.*sync"):
        main.main(["engagement", "add-track", "eng1", "code"])


def test_scope_management_waits_for_shared_scope_json_lock(tmp_path):
    from vigil_cli.engagements import set_engagement_header

    eng = _make_engagement(tmp_path)
    lock_path = eng / ".locks" / "scope-json.lock"
    lock_path.parent.mkdir(parents=True)
    entered = threading.Event()
    completed = threading.Event()

    def write_header():
        entered.set()
        set_engagement_header(tmp_path, "eng1", "X-Test: value")
        completed.set()

    with lock_path.open("a+", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        writer = threading.Thread(target=write_header)
        writer.start()
        assert entered.wait(timeout=2)
        time.sleep(0.05)
        assert not completed.is_set()
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    writer.join(timeout=2)
    assert completed.is_set()
    updated = json.loads((eng / "scope.json").read_text())
    assert updated["required_headers"] == {"X-Test": "value"}


def test_management_rejects_non_http_engagement(tmp_path):
    from vigil_cli.engagements import engagements_root, set_engagement_header

    root = engagements_root(tmp_path)
    root.mkdir(parents=True, exist_ok=True)
    eng = root / "codeproj"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps({"engagement_type": "code", "status": "in_progress"}))
    with pytest.raises(SystemExit):
        set_engagement_header(tmp_path, "codeproj", "X-Bug-Bounty: acme-researcher")


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
                "engagement", "create", "https://acme-telco.example",
                "--hosts", "*.acme-telco.example",
                "--program", "bugcrowd", "--researcher", "acme-researcher",
                "--out-of-scope", "appointments.example.com",
                "--dry-run", "--json",
            ]
        )
    except SystemExit as exc:  # tolerate either a normal return or sys.exit(0)
        assert exc.code in (0, None)
    payload = json.loads(capsys.readouterr().out)
    assert payload["scope"]["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    assert payload["scope"]["out_of_scope"] == ["appointments.example.com"]


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
    argv = ["engagement", "create", "https://target.example", "--hosts", "*.target.example",
            "--dry-run", "--json", *extra_argv]
    try:
        main.main(argv)
    except SystemExit as exc:
        assert exc.code in (0, None)
    return json.loads(capsys.readouterr().out)["scope"]


def test_interactive_preset_header_and_oos_are_asked(monkeypatch, capsys):
    scope = _interactive_scope(
        monkeypatch, capsys,
        ["bugcrowd", "acme-researcher", "appointments.example.com *.mobile.example.com"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    assert scope["out_of_scope"] == ["appointments.example.com", "*.mobile.example.com"]


def test_interactive_custom_header(monkeypatch, capsys):
    scope = _interactive_scope(monkeypatch, capsys, ["custom", "X-HackerOne: acme-researcher", ""])
    assert scope["required_headers"] == {"X-HackerOne": "acme-researcher"}
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
        extra_argv=["--program", "bugcrowd", "--researcher", "acme-researcher", "--out-of-scope", "a.target.example"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    assert scope["out_of_scope"] == ["a.target.example"]


def test_interactive_header_via_flag_still_asks_oos(monkeypatch, capsys):
    # Mixed path: header given via flag (suppresses the header prompt) but OOS
    # omitted, so the OOS prompt still fires. Only one answer is scripted — a
    # header prompt firing would consume it and break the assertion.
    scope = _interactive_scope(
        monkeypatch, capsys, ["carved.target.example"],
        extra_argv=["--program", "bugcrowd", "--researcher", "acme-researcher"],
    )
    assert scope["required_headers"] == {"X-Bug-Bounty": "acme-researcher"}
    assert scope["out_of_scope"] == ["carved.target.example"]


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
        main.main(["engagement", "create", "https://target.example", "--hosts", "*.target.example", *extra_argv])
    except SystemExit as exc:
        raised = exc
    return captured.get("options"), raised


def test_interactive_confirm_yes_creates_with_resolved_scope(monkeypatch, capsys, tmp_path):
    options, raised = _drive_create(
        monkeypatch, ["bugcrowd", "acme-researcher", "appointments.target.example"], True, tmp_path
    )
    assert raised is None
    assert options.required_headers == {"X-Bug-Bounty": "acme-researcher"}
    assert options.out_of_scope == ["appointments.target.example"]
    # The summary actually rendered the header + OOS for confirmation.
    err = capsys.readouterr().err
    assert "X-Bug-Bounty: acme-researcher" in err
    assert "out-of-scope:" in err


def test_interactive_confirm_no_aborts_without_creating(monkeypatch, capsys, tmp_path):
    options, raised = _drive_create(
        monkeypatch, ["bugcrowd", "acme-researcher", ""], False, tmp_path
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
