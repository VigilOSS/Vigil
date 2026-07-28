"""W1 — `vigil assess kali browser` headless-render verb.

The browser verb drives Playwright/system Chromium inside the runtime to render
a URL and return the origin HTTP status + final DOM + screenshot path. It is the
trustworthy-signal recovery for a curl/httpx run that the WAF-challenge detector
flagged. These tests pin the host-side CLI glue WITHOUT a live container:

  - register() wires the audit-flag set + the url positional and the render flags;
  - run() builds a ``python3 -c <playwright-driver> <execution-plan-json>``
    argv, derives default engagement-relative output paths under scans/browser/,
    honours explicit --screenshot/--dom-out/--wait-selector, attributes the run as
    tool_name='browser', and threads the audit flags through to kali_exec;
  - a missing url is rejected before exec;
  - the verb is a registered, contract-discoverable KALI_TARGET_VERBS member.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from assess.commands import kali_browser as kb
from assess.lib import contracts
from assess.lib.client import AssessError
from assess.lib.kali_output import KaliResult

# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _mk_result() -> KaliResult:
    return KaliResult(
        run_id=1,
        status="completed",
        return_code=0,
        stdout_path="scans/kali/abc.out",
        stderr_path="scans/kali/abc.err",
        duration_ms=10,
        peak_rss_bytes=None,
        stdout_preview='{"http_status": 200, "screenshot": "scans/browser/x.png"}',
        stderr_preview="",
        timed_out=False,
        partial_results=False,
    )


def _browser_args(**overrides) -> SimpleNamespace:
    base = dict(
        url="https://api.example.com/login",
        screenshot="",
        dom_out="",
        wait_selector="",
        page_timeout=30.0,
        settle=2.0,
        eval_js="",
        extra_headers=[],
        attribution_scope="all",
        steps_file="",
        har_out="",
        capture_bodies=False,
        body_dir="",
        max_body_bytes=262144,
        storage_state="",
        technique="RECON",
        intent="render flagged surface",
        probe_kind="baseline",
        phase="recon",
        destructive=False,
        timeout=120,
        force=False,
        kali_agent_name=None,
        kali_agent_id=None,
        identity=None,
        identity_scope="",
        container_name="vigil",
        engagement_dir=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _capture_run(monkeypatch, args) -> dict:
    captured: dict = {}

    def recorder(cmd, *, tool_name, **kwargs):
        captured["cmd"] = list(cmd)
        captured["tool_name"] = tool_name
        captured["kwargs"] = kwargs
        return _mk_result()

    monkeypatch.setattr(kb, "kali_exec", recorder)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        kb.run(args)
    captured["stdout"] = out.getvalue()
    return captured


# --------------------------------------------------------------------------- #
# register()
# --------------------------------------------------------------------------- #


def test_register_wires_url_and_audit_flags():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kb.register(sub)
    args = parser.parse_args(
        [
            "browser",
            "https://t.example/x",
            "--technique",
            "RECON",
            "--intent",
            "render",
            "--probe-kind",
            "baseline",
            "--phase",
            "recon",
            "--timeout",
            "120",
            "--identity",
            "member",
            "--identity-scope",
            "billing",
        ]
    )
    assert args.url == "https://t.example/x"
    assert args.identity == "member"
    assert args.identity_scope == "billing"
    assert args.func is kb.run


# --------------------------------------------------------------------------- #
# run() — argv construction
# --------------------------------------------------------------------------- #


def test_run_builds_python_playwright_driver_argv(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(url="https://api.example.com/login"))
    cmd = cap["cmd"]
    # python3 -c <driver> <validated execution-plan JSON>
    assert cmd[0] == "python3"
    assert cmd[1] == "-c"
    assert cmd[2] == kb._BROWSER_DRIVER
    config = json.loads(cmd[3])
    assert config["url"] == "https://api.example.com/login"
    assert config["screenshot"].startswith("scans/browser/") and config["screenshot"].endswith(".png")
    assert config["dom_path"].startswith("scans/browser/") and config["dom_path"].endswith(".html")
    assert config["page_timeout"] == 30.0
    assert config["settle"] == 2.0
    assert config["wait_selector"] == ""
    assert cap["tool_name"] == "browser"
    assert "playwright.sync_api" in kb._BROWSER_DRIVER
    assert "selenium" not in kb._BROWSER_DRIVER.lower()


def test_run_threads_audit_flags(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args())
    kwargs = cap["kwargs"]
    assert kwargs["technique"] == "RECON"
    assert kwargs["probe_kind"] == "baseline"
    assert kwargs["phase"] == "recon"
    assert kwargs["timeout"] == 120


def test_run_default_paths_derive_from_host(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(url="https://shop.example.com/cart"))
    config = json.loads(cap["cmd"][3])
    assert "shop.example.com" in config["screenshot"]
    assert "shop.example.com" in config["dom_path"]
    # Screenshot and DOM share the same slug/token stem.
    assert config["screenshot"][: -len(".png")] == config["dom_path"][: -len(".html")]


def test_run_honours_explicit_screenshot_and_dom(monkeypatch):
    cap = _capture_run(
        monkeypatch,
        _browser_args(screenshot="scans/browser/custom.png", dom_out="scans/browser/custom.html"),
    )
    config = json.loads(cap["cmd"][3])
    assert config["screenshot"] == "scans/browser/custom.png"
    assert config["dom_path"] == "scans/browser/custom.html"


def test_run_passes_wait_selector_and_timings(monkeypatch):
    cap = _capture_run(
        monkeypatch,
        _browser_args(wait_selector="#app", page_timeout=45.0, settle=5.0),
    )
    config = json.loads(cap["cmd"][3])
    assert config["page_timeout"] == 45.0
    assert config["settle"] == 5.0
    assert config["wait_selector"] == "#app"


def test_run_missing_url_raises(monkeypatch):
    monkeypatch.setattr(kb, "kali_exec", lambda *a, **k: _mk_result())
    with pytest.raises(AssessError):
        kb.run(_browser_args(url=""))


# --------------------------------------------------------------------------- #
# run() — program attribution headers reach the Playwright request router
# --------------------------------------------------------------------------- #


def _write_scope(eng_dir: Path, **fields) -> None:
    """Write a minimal scope.json (an engagement root) under ``eng_dir``."""
    eng_dir.mkdir(parents=True, exist_ok=True)
    payload = {"engagement_type": "web", "hosts": ["api.example.com"]}
    payload.update(fields)
    (eng_dir / "scope.json").write_text(json.dumps(payload), encoding="utf-8")


def test_run_threads_required_headers_into_driver_argv(tmp_path, monkeypatch):
    # An engagement with required_headers must have those headers reach the
    # headless-chromium navigation. kali_exec's -H injector cannot reach a
    # Browser execution cannot consume CLI -H flags, so the verb threads them in
    # as a JSON execution-plan field installed before Playwright navigation.
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    config = json.loads(cap["cmd"][3])
    assert config["required_headers"] == {"X-Bug-Bounty": "vigiloss"}
    # Playwright request routing installs attribution before navigation.
    assert "context.route" in kb._BROWSER_DRIVER
    assert "route.continue_" in kb._BROWSER_DRIVER


def test_run_no_headers_when_scope_has_none(tmp_path, monkeypatch):
    # No required_headers configured → an empty header map (no header is set).
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    assert json.loads(cap["cmd"][3])["required_headers"] == {}


def test_run_no_headers_when_engagement_unresolvable(monkeypatch, tmp_path):
    # An unresolvable engagement (no --engagement-dir, no scope.json reachable)
    # degrades quietly to an empty header map rather than failing the render.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ENGAGEMENT_DIR", raising=False)
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=None))
    assert json.loads(cap["cmd"][3])["required_headers"] == {}


def test_run_required_headers_drop_malformed_pairs(tmp_path, monkeypatch):
    # Only str->str pairs survive (mirrors the shared _required_headers reader),
    # so a malformed scope can never inject a non-header value into the driver.
    eng_dir = tmp_path / "eng"
    _write_scope(
        eng_dir,
        required_headers={"X-Bug-Bounty": "vigiloss", "X-Bad": 5, "": "blank"},
    )
    cap = _capture_run(monkeypatch, _browser_args(engagement_dir=str(eng_dir)))
    assert json.loads(cap["cmd"][3])["required_headers"] == {"X-Bug-Bounty": "vigiloss"}


# --------------------------------------------------------------------------- #
# run() — operator --header merge and --eval threading (LLM-friendly additions)
# --------------------------------------------------------------------------- #


def test_parse_header_args_splits_first_colon_and_trims():
    got = kb._parse_header_args(
        ["X-Debug: 1", "X-Trace:abc", "Authorization: Bearer a:b:c"]
    )
    assert got == {"X-Debug": "1", "X-Trace": "abc", "Authorization": "Bearer a:b:c"}


def test_parse_header_args_skips_malformed():
    assert kb._parse_header_args(["no-colon", "", ": empty-name", "  : x"]) == {}


def test_run_merges_operator_headers_into_driver_argv(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(
        monkeypatch,
        _browser_args(engagement_dir=str(eng_dir), extra_headers=["X-Debug: 1"]),
    )
    config = json.loads(cap["cmd"][3])
    assert config["required_headers"] == {"X-Bug-Bounty": "vigiloss"}
    assert config["operator_headers"] == {"X-Debug": "1"}


def test_run_required_header_wins_over_operator_same_name(tmp_path, monkeypatch):
    # An operator --header must NEVER strip/override a program attribution header
    # of the same name — required headers win the merge.
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(
        monkeypatch,
        _browser_args(
            engagement_dir=str(eng_dir), extra_headers=["X-Bug-Bounty: attacker"]
        ),
    )
    config = json.loads(cap["cmd"][3])
    assert config["required_headers"]["X-Bug-Bounty"] == "vigiloss"
    assert "X-Bug-Bounty" not in config["operator_headers"]


def test_run_required_header_wins_case_insensitive_operator_collision(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir, required_headers={"X-Bug-Bounty": "vigiloss"})
    cap = _capture_run(
        monkeypatch,
        _browser_args(
            engagement_dir=str(eng_dir), extra_headers=["x-bug-bounty: attacker"]
        ),
    )
    config = json.loads(cap["cmd"][3])
    assert config["required_headers"] == {"X-Bug-Bounty": "vigiloss"}
    assert not any(
        name.lower() == "x-bug-bounty" for name in config["operator_headers"]
    )


def test_run_threads_eval_js_as_final_argv(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args(eval_js="return document.title"))
    assert json.loads(cap["cmd"][3])["eval_js"] == "return document.title"


def test_run_eval_js_defaults_empty(monkeypatch):
    cap = _capture_run(monkeypatch, _browser_args())
    assert json.loads(cap["cmd"][3])["eval_js"] == ""


def test_register_wires_eval_and_header_flags():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kb.register(sub)
    args = parser.parse_args(
        [
            "browser", "https://t.example/x",
            "--technique", "RECON", "--intent", "render",
            "--probe-kind", "baseline", "--phase", "recon", "--timeout", "120",
            "--eval", "window.__xss_fired",
            "--header", "X-Debug: 1", "--header", "X-Trace: 2",
        ]
    )
    assert args.eval_js == "window.__xss_fired"
    assert args.extra_headers == ["X-Debug: 1", "X-Trace: 2"]


def test_register_wires_playwright_workflow_flags():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers()
    kb.register(sub)
    args = parser.parse_args(
        [
            "browser", "https://t.example/x",
            "--technique", "RECON", "--intent", "workflow",
            "--probe-kind", "baseline", "--phase", "recon", "--timeout", "120",
            "--attribution-scope", "document-origin",
            "--steps-file", "steps.json",
            "--har-out", "scans/browser/run.har",
            "--capture-bodies",
            "--body-dir", "scans/browser/bodies",
            "--max-body-bytes", "4096",
        ]
    )
    assert args.attribution_scope == "document-origin"
    assert args.steps_file == "steps.json"
    assert args.har_out.endswith("run.har")
    assert args.capture_bodies is True
    assert args.max_body_bytes == 4096


def test_load_steps_accepts_typed_bounded_workflow(tmp_path):
    path = tmp_path / "steps.json"
    path.write_text(
        json.dumps(
            [
                {"action": "navigate", "url": "https://api.example.com/account"},
                {"action": "fill", "selector": "#q", "value": "needle"},
                {"action": "click", "selector": "button[type=submit]"},
                {"action": "wait", "selector": "#results", "timeout_ms": 5000},
                {"action": "eval", "script": "document.title"},
                {"action": "assert", "selector": "#results", "contains": "needle"},
            ]
        ),
        encoding="utf-8",
    )
    steps = kb._load_steps(path)
    assert [step["action"] for step in steps] == [
        "navigate", "fill", "click", "wait", "eval", "assert"
    ]


@pytest.mark.parametrize(
    "payload",
    [
        [{"action": "shell", "command": "curl evil"}],
        [{"action": "fill", "selector": "#x"}],
        [{"action": "navigate", "url": "file:///etc/passwd"}],
        [{"action": "click", "selector": "#x", "unexpected": True}],
        [{"action": "wait", "timeout_ms": 999999}],
    ],
)
def test_load_steps_rejects_untyped_or_unsafe_steps(tmp_path, payload):
    path = tmp_path / "steps.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(AssessError):
        kb._load_steps(path)


def test_load_steps_enforces_step_cap(tmp_path):
    path = tmp_path / "steps.json"
    path.write_text(
        json.dumps([{"action": "click", "selector": "#x"}] * 51),
        encoding="utf-8",
    )
    with pytest.raises(AssessError, match="50"):
        kb._load_steps(path)


def test_run_threads_document_origin_and_steps(tmp_path, monkeypatch):
    steps_file = tmp_path / "steps.json"
    steps_file.write_text(
        json.dumps(
            [{"action": "navigate", "url": "https://api.example.com/account"}]
        ),
        encoding="utf-8",
    )
    cap = _capture_run(
        monkeypatch,
        _browser_args(
            attribution_scope="document-origin",
            steps_file=str(steps_file),
            har_out="scans/browser/run.har",
            capture_bodies=True,
            body_dir="scans/browser/bodies",
            max_body_bytes=4096,
        ),
    )
    config = json.loads(cap["cmd"][3])
    assert config["url"] == "https://api.example.com/login"
    assert config["attribution_scope"] == "document-origin"
    assert config["steps"][0]["url"].endswith("/account")
    assert config["har_out"] == "scans/browser/run.har"
    assert config["capture_bodies"] is True
    assert config["max_body_bytes"] == 4096
    assert "destinations" not in cap["kwargs"]
    assert "no_fire_regex" not in config


def test_document_origin_driver_records_omitted_cross_origin_attribution():
    assert "omitted_attribution_origins" in kb._BROWSER_DRIVER
    assert "document-origin" in kb._BROWSER_DRIVER
    # The handler must install before the first navigation and fail the process
    # when required-attribution routing cannot be established.
    assert kb._BROWSER_DRIVER.index("context.route") < kb._BROWSER_DRIVER.index("page.goto")
    assert "required attribution routing failed" in kb._BROWSER_DRIVER


def test_driver_never_aborts_a_network_request_from_scope_policy():
    route_body = kb._BROWSER_DRIVER.split("def route_request(route, request):", 1)[1].split(
        "def capture_failure", 1
    )[0]
    assert "blocked_request" not in kb._BROWSER_DRIVER
    assert "route.abort" not in route_body
    assert "route.continue_" in route_body


def test_driver_does_not_filter_navigations_by_scope():
    assert "host_allowed" not in kb._BROWSER_DRIVER
    assert "scope_entries" not in kb._BROWSER_DRIVER
    assert "scope_enforcement" not in kb._BROWSER_DRIVER
    assert "no_fire_regex" not in kb._BROWSER_DRIVER


def test_driver_never_sends_identity_headers_to_future_cross_host_navigation():
    route_body = kb._BROWSER_DRIVER.split("def route_request(route, request):", 1)[1].split(
        "def capture_failure", 1
    )[0]
    assert "identity_hosts = set(cfg.get(\"identity_hosts\") or [])" in kb._BROWSER_DRIVER
    assert "if request_host in identity_hosts:" in route_body
    assert "if request_origin in document_origins:" not in route_body


def test_document_navigation_enrolls_origin_for_attribution():
    route_body = kb._BROWSER_DRIVER.split("def route_request(route, request):", 1)[1].split(
        "def capture_failure", 1
    )[0]
    navigation_check = route_body.index("request.is_navigation_request()")
    assert "document_origins.add(request_origin)" in route_body[navigation_check:]


def test_driver_bounds_network_console_and_body_capture():
    assert "MAX_NETWORK_EVENTS" in kb._BROWSER_DRIVER
    assert "MAX_CONSOLE_EVENTS" in kb._BROWSER_DRIVER
    assert "max_body_bytes" in kb._BROWSER_DRIVER
    assert "route_candidates" in kb._BROWSER_DRIVER


def test_driver_visible_false_assertion_waits_for_hidden_state():
    assert 'state="hidden" if step.get("visible") is False else "visible"' in (
        kb._BROWSER_DRIVER
    )
    assert 'if "contains" in step or "equals" in step:' in kb._BROWSER_DRIVER


def test_driver_creates_body_capture_directory_before_response_writes():
    setup = kb._BROWSER_DRIVER.split('result = {', 1)[0]
    assert 'directory = value if key == "body_dir" else os.path.dirname(value)' in setup
    assert "os.makedirs(directory, exist_ok=True)" in setup


def test_run_prepares_identity_for_browser_and_audit(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    monkeypatch.setattr(
        kb,
        "prepare_browser_identity_material",
        lambda *_, **__: (
            "alice",
            {
                "headers": {"Authorization": "Bearer token"},
                "cookies": [{"name": "sid", "value": "abc", "domain": "api.example.com", "path": "/"}],
                "storage_state": {"origins": []},
            },
        ),
    )
    cap = _capture_run(
        monkeypatch,
        _browser_args(engagement_dir=str(eng_dir), identity="alice"),
    )
    config = json.loads(cap["cmd"][3])
    assert config["identity_headers"] == {"Authorization": "Bearer token"}
    assert config["cookies"][0]["name"] == "sid"
    assert config["storage_state"] is None
    assert cap["kwargs"]["identity"] is None
    assert cap["kwargs"]["prepared_auth_context"] == "alice"


def test_run_passes_explicit_scope_to_browser_identity_resolution(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    scopes = []

    def prepare(
        _engagement,
        _identity,
        _url,
        *,
        scope_key="",
        external_state_applied=False,
    ):
        scopes.append((scope_key, external_state_applied))
        return "alice", {"headers": {"X-Auth": "yes"}, "cookies": [], "storage_state": None}

    monkeypatch.setattr(kb, "prepare_browser_identity_material", prepare)
    _capture_run(
        monkeypatch,
        _browser_args(
            engagement_dir=str(eng_dir),
            identity="member",
            identity_scope="billing",
        ),
    )
    assert scopes == [("billing", False)]


def test_run_loads_storage_state_only_from_explicit_engagement_artifact(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    artifact = eng_dir / "tools" / "auth" / "browser-state.json"
    artifact.parent.mkdir(parents=True)
    artifact.write_text(
        json.dumps(
            {
                "cookies": [],
                "origins": [
                    {"origin": "https://api.example.com", "localStorage": []}
                ],
            }
        ),
        encoding="utf-8",
    )
    calls = []

    def prepare(*_args, **kwargs):
        calls.append(kwargs)
        return "member", {"headers": {}, "cookies": [], "storage_state": None}

    monkeypatch.setattr(kb, "prepare_browser_identity_material", prepare)
    cap = _capture_run(
        monkeypatch,
        _browser_args(
            engagement_dir=str(eng_dir),
            identity="member",
            storage_state="tools/auth/browser-state.json",
        ),
    )

    config = json.loads(cap["cmd"][3])
    assert config["storage_state"]["origins"][0]["origin"] == "https://api.example.com"
    assert calls == [{"scope_key": "", "external_state_applied": True}]
    assert cap["kwargs"]["prepared_auth_context"] == "member"


def test_run_rejects_storage_state_without_identity(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    artifact = eng_dir / "state.json"
    artifact.write_text('{"cookies": [], "origins": []}', encoding="utf-8")

    with pytest.raises(AssessError, match="requires --identity"):
        kb.run(
            _browser_args(
                engagement_dir=str(eng_dir), storage_state="state.json"
            )
        )


def test_run_rejects_storage_state_for_missing_or_disabled_identity(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    artifact = eng_dir / "state.json"
    artifact.write_text('{"cookies": [], "origins": []}', encoding="utf-8")
    monkeypatch.setattr(
        kb,
        "prepare_browser_identity_material",
        lambda *_, **__: (
            "anonymous",
            {"headers": {}, "cookies": [], "storage_state": None},
        ),
    )

    with pytest.raises(
        AssessError,
        match="requested identity 'missing-or-dead'.*refusing to run anonymously",
    ):
        kb.run(
            _browser_args(
                engagement_dir=str(eng_dir),
                identity="missing-or-dead",
                storage_state="state.json",
            )
        )


def test_run_rejects_storage_state_artifact_that_escapes_engagement(
    tmp_path, monkeypatch
):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    outside = tmp_path / "outside.json"
    outside.write_text('{"cookies": [], "origins": []}', encoding="utf-8")
    (eng_dir / "state.json").symlink_to(outside)

    with pytest.raises(AssessError, match="inside the engagement"):
        kb.run(
            _browser_args(
                engagement_dir=str(eng_dir), storage_state="state.json"
            )
        )


def test_run_refuses_unprepared_requested_identity(tmp_path, monkeypatch):
    eng_dir = tmp_path / "eng"
    _write_scope(eng_dir)
    monkeypatch.setattr(
        kb,
        "prepare_browser_identity_material",
        lambda *_, **__: (
            "anonymous",
            {"headers": {}, "cookies": [], "storage_state": None},
        ),
    )
    with pytest.raises(
        AssessError,
        match="requested identity 'missing'.*refusing to run anonymously",
    ):
        kb.run(_browser_args(engagement_dir=str(eng_dir), identity="missing"))


def test_run_refuses_requested_identity_without_engagement_context():
    with pytest.raises(AssessError, match="identity requires engagement context"):
        kb.run(_browser_args(identity="member"))


# --------------------------------------------------------------------------- #
# contract discoverability
# --------------------------------------------------------------------------- #


def test_browser_is_a_target_verb():
    assert "browser" in contracts.KALI_TARGET_VERBS


def test_browser_contract_resolves():
    contract = contracts.get_contract("kali browser")
    assert contract is not None
    assert contract.name == "kali browser"
    # Target-facing verb carries the audit-flag author fields.
    joined = " ".join(contract.author_supplied_fields)
    assert "--technique" in joined
    rendered = contracts.render_contract("kali browser")
    assert "browser" in rendered.lower()
