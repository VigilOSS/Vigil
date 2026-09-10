"""Execution-ergonomics contracts for `vigil assess kali` (W4).

Six behaviors an LLM operator depends on, none of which existed before:

1. the run's terminal status reaches `$?` instead of dying in the JSON —
   including on the fan-out verbs, which print their own results and so
   never pass through `emit_result`;
2. `--identity` on an argv shape it cannot inject into says WHY, and
   `--identity-target` gives the caller a way through — on the async job
   lane as well as the synchronous one;
3. hand-written credentials on an identity-less run are called out rather
   than silently filed as `auth_context=anonymous`;
4. `browser` no longer claims required-header injection failed when it did not;
5. `command-run get` rejects the list-only `--include-output` flag;
6. multi-arm curl's global last-wins `-w`/`-D` semantics are surfaced.
"""
from __future__ import annotations

import argparse
import json
from types import SimpleNamespace

import pytest

from assess.lib import kali, kali_output
from assess.commands import (
    arjun_sweep,
    get_command_run,
    kali_job,
    kali_sweep,
    list_command_runs,
)


def _result(status: str, **over):
    kwargs = dict(
        run_id=7,
        status=status,
        return_code=0 if status == "completed" else 1,
        stdout_path="/tmp/x.out",
        stderr_path="/tmp/x.err",
        duration_ms=5,
        peak_rss_bytes=None,
        stdout_preview="",
        stderr_preview="",
        timed_out=status == "timed_out",
        partial_results=False,
    )
    kwargs.update(over)
    return kali.KaliResult(**kwargs)


# --------------------------------------------------------------------------- #
# 1 — terminal status reaches the process exit code
# --------------------------------------------------------------------------- #

def test_exit_code_table_is_the_single_source() -> None:
    # The map IS the contract — `cli.py` renders `kali --help`'s exit-code
    # section straight from it, so a silent re-numbering would drift the docs.
    assert kali_output.KALI_EXIT_CODES == {
        "failed": 3,
        "timed_out": 4,
        "killed": 5,
        "transport_error": 6,
    }


@pytest.mark.parametrize("status", ["completed", "waf_challenge"])
def test_usable_result_statuses_exit_zero(status, capsys) -> None:
    """A `&&` chain must keep working for a run that produced output.

    `waf_challenge` is deliberately 0: the HTTP exchange DID complete, the
    condition is already loud on stderr and in `.status`, and its remedy is to
    re-render with `kali browser` — not to abort the pipeline.
    """
    kali.emit_result(_result(status))
    assert json.loads(capsys.readouterr().out)["status"] == status


@pytest.mark.parametrize(
    "status,expected",
    [("failed", 3), ("timed_out", 4), ("killed", 5), ("transport_error", 6)],
)
def test_unusable_result_statuses_exit_non_zero(status, expected, capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        kali.emit_result(_result(status))
    assert excinfo.value.code == expected
    # The JSON is still emitted in full before the exit — the exit code is an
    # addition to the contract, never a replacement for it.
    assert json.loads(capsys.readouterr().out)["status"] == status


def test_exit_codes_never_collide_with_vigil_side_failures() -> None:
    """1 is `cli.main`'s AssessError exit and 2 is argparse's — a target-run
    verdict must stay distinguishable from a Vigil refusal."""
    assert 1 not in kali_output.KALI_EXIT_CODES.values()
    assert 2 not in kali_output.KALI_EXIT_CODES.values()


# --------------------------------------------------------------------------- #
# 1b — the SAME contract on the fan-out verbs, which print their own results
#      and so never reach `emit_result`
# --------------------------------------------------------------------------- #


def _arm(value: str, status: str):
    return (value, _result(status, run_id=int(value)))


def test_aggregate_rule_is_worst_arm_when_all_failed() -> None:
    """One dead arm out of fifty is a normal, useful sweep — it must not read as
    a failed command, or callers learn to ignore `$?` on the verb most likely to
    run unattended. Only a wholly-dead fan-out is a failure."""
    assert kali_sweep.aggregate_exit_code(["completed"] * 50) == 0
    assert kali_sweep.aggregate_exit_code(["completed"] * 49 + ["timed_out"]) == 0
    assert kali_sweep.aggregate_exit_code(["waf_challenge", "timed_out"]) == 0


def test_aggregate_rule_keeps_a_uniform_diagnosis_and_derives_it_from_the_table() -> None:
    # An all-timed-out fan-out exits the timed_out code, so the diagnosis is not
    # flattened away by the aggregation. A mixed all-failed set has no single
    # honest answer, so it exits `failed` and the JSON names each arm.
    for status, code in kali_output.KALI_EXIT_CODES.items():
        assert kali_sweep.aggregate_exit_code([status] * 3) == code
    assert (
        kali_sweep.aggregate_exit_code(["timed_out", "transport_error"])
        == kali_output.KALI_EXIT_CODES["failed"]
    )


def test_sweep_with_one_live_arm_exits_zero_but_states_the_failure_count(capsys) -> None:
    kali_sweep.emit_sweep_result(
        "b" * 32,
        [_arm("1", "completed"), _arm("2", "timed_out"), _arm("3", "transport_error")],
        as_json=True,
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["total"] == 3
    assert payload["failed"] == 2
    assert payload["failed_by_status"] == {"timed_out": 1, "transport_error": 1}
    assert "2/3 arm(s) produced no usable output" in captured.err
    assert "NOT negatives" in captured.err


def test_sweep_with_every_arm_dead_exits_non_zero(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        kali_sweep.emit_sweep_result(
            "c" * 32, [_arm("1", "timed_out"), _arm("2", "timed_out")], as_json=True
        )
    assert excinfo.value.code == kali_output.KALI_EXIT_CODES["timed_out"]
    captured = capsys.readouterr()
    # The JSON still lands in full before the exit, exactly like emit_result.
    assert json.loads(captured.out)["failed"] == 2
    assert "proves NOTHING about the target" in captured.err


def test_sweep_table_output_also_states_the_failure_count(capsys) -> None:
    kali_sweep.emit_sweep_result("d" * 32, [_arm("1", "completed"), _arm("2", "failed")])
    assert "1 with NO usable output" in capsys.readouterr().out


def test_arjun_sweep_shares_the_one_aggregate_implementation() -> None:
    # Two emitters, one rule: a second copy would drift the moment the table
    # gains a status.
    assert arjun_sweep.aggregate_exit_code is kali_sweep.aggregate_exit_code


# --------------------------------------------------------------------------- #
# 2 — `--identity` on a shape it cannot inject into
# --------------------------------------------------------------------------- #

_MATERIAL = {
    "identity_name": "member",
    "state": "available",
    "headers": {"Cookie": "session=abc"},
}


@pytest.fixture()
def _stub_identity(monkeypatch):
    monkeypatch.setattr(
        kali, "resolve_identity", lambda _eng, requested: (requested, _MATERIAL)
    )


def test_script_file_refusal_names_the_argv_shape(_stub_identity, tmp_path) -> None:
    """`bash /path/poc.sh` used to hit the credential catch-all, which reads as
    "your session is broken" — the reason agents fell back to a hand-written
    Cookie header. The message must name the SHAPE and its remedy instead."""
    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["bash", "/engagements/x/poc.sh"],
            tool_name="bash",
            engagement_dir=tmp_path,
            identity="member",
        )
    message = str(excinfo.value)
    assert "/engagements/x/poc.sh" in message
    assert "bash -c" in message
    # It must NOT blame the stored material.
    assert "carries nothing this tool can take" not in message


def test_unknown_binary_refusal_offers_identity_target(_stub_identity, tmp_path) -> None:
    with pytest.raises(kali.scope_lib.ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["mycurl", "https://app.example.com/account"],
            tool_name="mycurl",
            engagement_dir=tmp_path,
            identity="member",
        )
    message = str(excinfo.value)
    assert "--identity-target" in message
    assert "curl" in message


def test_identity_target_injects_under_the_named_convention(
    _stub_identity, tmp_path, capsys
) -> None:
    cmd = ["mycurl", "https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd,
        tool_name="mycurl",
        engagement_dir=tmp_path,
        identity="member",
        identity_target="curl",
    )
    assert auth_context == "member"
    assert cmd[-2:] == ["-H", "Cookie: session=abc"]
    assert "--identity-target" in capsys.readouterr().err


def test_identity_target_is_ignored_for_a_script_file(
    _stub_identity, tmp_path, capsys
) -> None:
    """Honouring the override here would append `-H` as the script's $1/$2 and
    then stamp auth_context=member on a request that never carried it."""
    cmd = ["bash", "/engagements/x/poc.sh"]
    with pytest.raises(kali.scope_lib.ScopePolicyError):
        kali.prepare_execution_command(
            cmd,
            tool_name="bash",
            engagement_dir=tmp_path,
            identity="member",
            identity_target="curl",
        )
    assert cmd == ["bash", "/engagements/x/poc.sh"]
    assert "--identity-target ignored" in capsys.readouterr().err


def test_identity_target_never_overrides_a_tool_vigil_handles(
    _stub_identity, tmp_path, capsys
) -> None:
    """A stray override must not push a curl-style `-H` onto arjun, which takes
    its headers through `--headers`."""
    cmd = ["arjun", "-u", "https://app.example.com/x", "-m", "GET"]
    kali.prepare_execution_command(
        cmd,
        tool_name="arjun",
        engagement_dir=tmp_path,
        identity="member",
        identity_target="curl",
    )
    assert "-H" not in cmd
    assert "--headers" in cmd
    assert "--identity-target ignored" in capsys.readouterr().err


def test_unknown_identity_target_warns_and_still_refuses(
    _stub_identity, tmp_path, capsys
) -> None:
    with pytest.raises(kali.scope_lib.ScopePolicyError):
        kali.prepare_execution_command(
            ["mycurl", "https://app.example.com/x"],
            tool_name="mycurl",
            engagement_dir=tmp_path,
            identity="member",
            identity_target="telnet",
        )
    assert "not a header-injectable tool" in capsys.readouterr().err


def _parse_job_start(argv: list[str]):
    """Parse a real `kali job start` argv through the module's own registration."""
    parser = argparse.ArgumentParser()
    kali_job.register(parser.add_subparsers())
    return parser.parse_args(["job", "start", *argv])


def test_job_start_registers_identity_target(monkeypatch, tmp_path) -> None:
    """The async lane must offer the same way past the argv-shape refusal.

    `kali job start` builds its own parser and calls prepare_execution_command
    directly, so the sync lane's flag does not reach it for free — an agent that
    hit the refusal here previously had no remedy at all.
    """
    captured: dict = {}

    def fake_prepare(cmd, **kwargs):
        captured.update(kwargs)
        return "member"

    monkeypatch.setattr(kali_job, "prepare_execution_command", fake_prepare)
    monkeypatch.setattr(kali_job.scope_lib, "enforce_execution_policy", lambda *a, **k: {})
    monkeypatch.setattr(kali_job, "_scope_version", lambda _dir: "v1")
    monkeypatch.setattr(kali_job, "start_job", lambda *a, **k: {"id": 1})
    monkeypatch.setattr(
        kali_job,
        "load_config",
        lambda _dir: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )

    args = _parse_job_start([
        "--technique", "RECON", "--intent", "poc replay", "--probe-kind", "baseline",
        "--phase", "recon", "--timeout", "60", "--identity", "member",
        "--identity-target", "curl", "--", "mycurl", "https://app.example.com/x",
    ])
    kali_job._run_start(args)

    assert captured["identity"] == "member"
    assert captured["identity_target"] == "curl"


def test_job_start_identity_target_defaults_to_no_override(monkeypatch, tmp_path) -> None:
    captured: dict = {}

    def fake_prepare(cmd, **kwargs):
        captured.update(kwargs)
        return "anonymous"

    monkeypatch.setattr(kali_job, "prepare_execution_command", fake_prepare)
    monkeypatch.setattr(kali_job.scope_lib, "enforce_execution_policy", lambda *a, **k: {})
    monkeypatch.setattr(kali_job, "_scope_version", lambda _dir: "v1")
    monkeypatch.setattr(kali_job, "start_job", lambda *a, **k: {"id": 1})
    monkeypatch.setattr(
        kali_job,
        "load_config",
        lambda _dir: SimpleNamespace(engagement_dir=str(tmp_path), engagement_key="eng"),
    )

    kali_job._run_start(_parse_job_start([
        "--technique", "RECON", "--intent", "plain run", "--probe-kind", "baseline",
        "--phase", "recon", "--timeout", "60", "--", "curl", "https://app.example.com/x",
    ]))
    assert captured["identity_target"] == ""


def test_bash_dash_c_still_injects_without_any_override(_stub_identity, tmp_path) -> None:
    """The documented remedy has to actually work."""
    cmd = ["bash", "-c", "curl -s https://app.example.com/account"]
    auth_context = kali.prepare_execution_command(
        cmd, tool_name="bash", engagement_dir=tmp_path, identity="member"
    )
    assert auth_context == "member"
    assert "Cookie: session=abc" in cmd[2]


# --------------------------------------------------------------------------- #
# 3 — hand-written credentials on an identity-less run
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "cmd",
    [
        ["curl", "-H", "Cookie: session=abc", "https://app.example.com/x"],
        ["curl", "--header=Authorization: Bearer t", "https://app.example.com/x"],
        ["bash", "-c", "curl -H 'Cookie: a=b' https://app.example.com/x"],
    ],
)
def test_handwritten_credentials_without_identity_warn(cmd, tmp_path, capsys) -> None:
    kali.prepare_execution_command(cmd, tool_name="curl", engagement_dir=tmp_path)
    err = capsys.readouterr().err
    assert "auth_context=anonymous" in err
    assert "--identity" in err


def test_ordinary_anonymous_run_does_not_warn(tmp_path, capsys) -> None:
    kali.prepare_execution_command(
        ["curl", "-H", "X-Trace: 1", "https://app.example.com/x"],
        tool_name="curl",
        engagement_dir=tmp_path,
    )
    assert "auth_context=anonymous" not in capsys.readouterr().err


def test_identity_run_is_not_second_guessed(_stub_identity, tmp_path, capsys) -> None:
    """The injector writes a Cookie header itself; warning about it would fire
    on every correctly-attributed run."""
    kali.prepare_execution_command(
        ["curl", "https://app.example.com/x"],
        tool_name="curl",
        engagement_dir=tmp_path,
        identity="member",
    )
    assert "auth_context=anonymous" not in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# 4 — the browser is self-attributing, not un-attributed
# --------------------------------------------------------------------------- #

def test_browser_is_classified_self_attributing() -> None:
    """The driver applies required headers inside Playwright, so there is
    nothing on the argv to inject and nothing to warn about. It must not be a
    silent `skipped` either — that would assert the browser never speaks HTTP
    to the target and would hide a real driver regression."""
    assert (
        kali_output._apply_required_headers(
            ["browser", "https://app.example.com"], "browser", {"X-HackerOne": "h"}
        )
        == "self_attributed"
    )
    assert "browser" not in kali_output._REQUIRED_HEADER_SKIP
    assert "browser" not in kali_output._REQUIRED_HEADER_INJECTABLE


def test_browser_run_emits_no_attribution_warning(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(kali, "_required_headers", lambda _dir: {"X-HackerOne": "h"})
    kali.prepare_execution_command(
        ["browser", "https://app.example.com"],
        tool_name="browser",
        engagement_dir=tmp_path,
    )
    assert "could not be" not in capsys.readouterr().err


def test_a_genuinely_uninjectable_tool_still_warns(monkeypatch, tmp_path, capsys) -> None:
    monkeypatch.setattr(kali, "_required_headers", lambda _dir: {"X-HackerOne": "h"})
    kali.prepare_execution_command(
        ["wafw00f", "https://app.example.com"],
        tool_name="wafw00f",
        engagement_dir=tmp_path,
    )
    assert "could not be" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# 5 — `command-run get` rejects the list-only `--include-output` flag
# --------------------------------------------------------------------------- #

def _leaf_parser(module, name):
    root = argparse.ArgumentParser()
    sub = root.add_subparsers()
    module.register(sub)
    return root, sub.choices[name]


def test_command_run_get_rejects_list_only_include_output() -> None:
    root, _leaf = _leaf_parser(get_command_run, "get")
    with pytest.raises(SystemExit) as exc:
        root.parse_args(["get", "42", "--include-output"])

    assert exc.value.code == 2


def test_list_include_output_help_does_not_promise_a_table_column() -> None:
    _root, leaf = _leaf_parser(list_command_runs, "list")
    action = next(a for a in leaf._actions if a.dest == "include_output")
    assert "Only --json renders it" in action.help


def test_listing_table_shows_retained_output_size() -> None:
    """The bandwidth control withholds the preview TEXT, not its existence —
    an empty `stdout_preview` in a listing is intended, so the table has to
    show that output EXISTS or a caller reads it as "no output"."""
    table = list_command_runs._render_table(
        [
            {
                "id": 1,
                "return_code": 0,
                "command": "curl https://x",
                "stdout_preview": "",
                "stdout_preview_chars": 4000,
                "stderr_preview_chars": 12,
            }
        ]
    )
    header, row = table.splitlines()
    assert "out/err" in header.split("\t")
    assert "4000/12" in row.split("\t")


def test_listing_table_falls_back_to_preview_length() -> None:
    """With --include-output the backend sends the text and no char count."""
    table = list_command_runs._render_table(
        [{"id": 1, "return_code": 0, "command": "c", "stdout_preview": "abcde"}]
    )
    assert "5/0" in table.splitlines()[1].split("\t")


# --------------------------------------------------------------------------- #
# 6 — multi-arm curl last-wins semantics
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "cmd,flag",
    [
        (
            ["curl", "-o", "a", "https://t/a", "-o", "b", "https://t/b", "-w", "%{http_code}"],
            "-w",
        ),
        (["curl", "-D", "/tmp/h1", "https://t/a", "-D", "/tmp/h2", "https://t/b"], "-D"),
        (["curl", "-w%{http_code}", "https://t/a", "https://t/b"], "-w"),
        (
            ["bash", "-c", "curl -o a https://t/a -o b https://t/b -w '%{http_code}'"],
            "-w",
        ),
    ],
)
def test_multi_arm_curl_last_wins_is_surfaced(cmd, flag) -> None:
    warning = kali_output.curl_multi_arm_warning(cmd)
    assert flag in warning
    assert "--next" in warning


@pytest.mark.parametrize(
    "cmd",
    [
        # Single arm: -w and -D are unambiguous.
        ["curl", "-o", "a", "https://t/a", "-w", "%{http_code}"],
        # Arms already separated: each gets its own -w/-D.
        ["curl", "-o", "a", "https://t/a", "--next", "-o", "b", "https://t/b", "-w", "x"],
        # Several arms but no global last-wins flag in play.
        ["curl", "-o", "a", "https://t/a", "-o", "b", "https://t/b"],
        # A URL-valued flag that does not open an arm.
        ["curl", "-x", "http://proxy:8080", "https://t/a", "-w", "%{http_code}"],
        # Separate invocations in a script are separate processes.
        ["bash", "-c", "curl -w '%{http_code}' https://t/a; curl -w '%{http_code}' https://t/b"],
        # Not curl at all.
        ["nmap", "-sV", "t"],
    ],
)
def test_correct_curl_shapes_are_silent(cmd) -> None:
    assert kali_output.curl_multi_arm_warning(cmd) == ""


def test_multi_arm_warning_is_emitted_on_dispatch(tmp_path, capsys) -> None:
    kali.prepare_execution_command(
        ["curl", "-o", "a", "https://t/a", "-o", "b", "https://t/b", "-w", "%{http_code}"],
        tool_name="curl",
        engagement_dir=tmp_path,
    )
    assert "last-wins" in capsys.readouterr().err.lower()


# --------------------------------------------------------------------------- #
# QC: a `-c` script body that declines injection must not be told to become one
# --------------------------------------------------------------------------- #


def test_unlexable_c_body_names_the_quote_not_a_reshape() -> None:
    # An apostrophe inside a comment makes the whole body unlexable, so the
    # injector declines. The generic argv-shape message told the operator to
    # "re-shape the run as `bash -c '<curl ...>'`" — which is what they already
    # ran — and pointed at --identity-target, which is deliberately ignored for
    # this shape. That is a dead end; the message must name the real cause.
    cmd = ["bash", "-c", "# it's the login flow\ncurl -s https://t/a"]
    detail = kali.identity_argv_shape_detail("user_a", "bash", cmd)
    assert "could not be lexed" in detail
    assert "unbalanced quote" in detail
    assert "--identity-target" not in detail
    assert "re-shape" not in detail


def test_c_body_without_a_header_capable_subcommand_says_so() -> None:
    cmd = ["bash", "-c", "python3 /engagements/x/poc.py"]
    detail = kali.identity_argv_shape_detail("user_a", "bash", cmd)
    assert "no header-capable sub-command" in detail
    assert "--identity-target" not in detail


def test_injectable_c_body_reports_no_gap() -> None:
    # The diagnostic must stay silent on the shape that DOES inject, or the
    # refusal path would start describing working runs.
    assert kali_output.shell_script_body_gap(["bash", "-c", "curl -s https://t/a"]) == ""
    assert kali_output.shell_script_body_gap(["curl", "-s", "https://t/a"]) == ""


def test_identity_target_refusal_on_a_c_body_states_the_real_reason(capsys) -> None:
    # `--identity-target` is ignored for a `-c` body. The old reason claimed
    # "Vigil already knows how to inject into 'bash'", which is flatly false in
    # exactly the case that reaches this message.
    tool = kali._identity_injection_tool(
        ["bash", "-c", "# it's x\ncurl -s https://t/a"],
        tool_name="bash",
        identity_target="curl",
    )
    assert tool == "bash"
    err = capsys.readouterr().err
    assert "sub-commands INSIDE a `-c` script body" in err
    assert "already knows how to inject" not in err
