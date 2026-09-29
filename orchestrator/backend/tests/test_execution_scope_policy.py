"""Pre-execution engagement policy for `vigil assess kali` and `host-exec`.

There is deliberately NO destination filtering: the CLI never refuses a command
for the host it names. `scope.json` `hosts` declares what the engagement is
authorized against and staying inside it is the operator's and the specialist's
job. What these tests pin is the policy that survives, because it does not
require guessing a destination out of an argv — the engagement tool denylist,
the declared-vs-actual tool check, and the `target_facing` signal used for
non-blocking cross-lane activity context. `off_limits_paths` remains engagement guidance and
must never become an outbound-request veto.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[3] / "agent" / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from assess.lib import scope  # noqa: E402


def _engagement(tmp_path: Path, doc: dict) -> Path:
    eng = tmp_path / "eng-key"
    eng.mkdir()
    (eng / "scope.json").write_text(json.dumps(doc), encoding="utf-8")
    return eng


def test_stub_program_brief_blocks_live_target_traffic_until_declared(
    tmp_path: Path, monkeypatch
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    (eng / "ENGAGEMENT.md").write_text("> **STUB — fill this in**\n")

    with pytest.raises(scope.ScopePolicyError, match="STUB"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test/"], tool_name="curl", engagement_dir=eng
        )

    monkeypatch.setattr(
        scope, "_program_brief_decisions",
        lambda _eng: [{"payload": {"choice": "no_separate_program_brief", "reason": "Operator confirmed"}}],
    )
    result = scope.enforce_execution_policy(
        ["curl", "https://example.test/"], tool_name="curl", engagement_dir=eng
    )
    assert result["target_facing"] is True


def test_stub_program_brief_does_not_block_static_source_review(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})
    (eng / "ENGAGEMENT.md").write_text("> **STUB — fill this in**\n")
    result = scope.enforce_execution_policy(
        ["rg", "password", "repo/"], tool_name="rg", engagement_dir=eng
    )
    assert result["target_facing"] is False


def test_canonical_code_only_track_keeps_code_execution_policy(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {
        "engagement_type": "offensive",
        "tracks": {"code": {"phase": "hunt"}},
        "hosts": [],
    })

    result = scope.enforce_execution_policy(
        ["curl", "https://repository.example/"], tool_name="curl", engagement_dir=eng
    )
    assert result["target_facing"] is True


# ---------------------------------------------------------------------------
# No destination filtering
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("tool_name", "command"),
    [
        ("nmap", ["nmap", "-sV", "evil.test"]),
        ("nuclei", ["nuclei", "-u", "https://evil.test"]),
        ("httpx", ["httpx", "-u", "https://evil.test"]),
        ("curl", ["curl", "https://evil.test/anything"]),
        ("wafw00f", ["wafw00f", "https://evil.test"]),
        ("ffuf", ["ffuf", "-u", "https://evil.test/FUZZ"]),
        ("sqlmap", ["sqlmap", "-u", "https://evil.test/?id=1"]),
        ("subfinder", ["subfinder", "-d", "evil.test"]),
        ("gau", ["gau", "evil.test"]),
        ("python3", ["python3", "-c", "import urllib.request", "https://evil.test"]),
        ("sh", ["sh", "-c", "curl -sS https://evil.test/"]),
        ("custom-tool", ["custom-tool", "https://evil.test"]),
    ],
)
def test_command_naming_an_undeclared_host_is_not_refused(
    tmp_path: Path, tool_name: str, command: list[str]
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["allowed.test"]})

    result = scope.enforce_execution_policy(
        command, tool_name=tool_name, engagement_dir=eng
    )

    assert "policy_refusal" not in result


def test_command_naming_an_out_of_scope_carve_out_is_not_refused(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["*.example.test"], "out_of_scope": ["excluded.example.test"]},
    )

    scope.enforce_execution_policy(
        ["curl", "https://excluded.example.test/"],
        tool_name="curl",
        engagement_dir=eng,
    )


def test_target_cidr_wider_than_the_declared_network_is_not_refused(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["10.0.0.0/24"]})

    scope.enforce_execution_policy(
        ["nmap", "10.0.0.0/16"], tool_name="nmap", engagement_dir=eng
    )


def test_unreadable_target_list_does_not_block_the_run(tmp_path: Path) -> None:
    """A list file the CLI cannot inspect is not a reason to refuse.

    Inspecting it only ever served target admission; nothing reads it now, so a
    missing path is the tool's problem to report, not a pre-exec refusal.
    """
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    scope.enforce_execution_policy(
        ["httpx", "-l", "/engagements/eng-key/missing.txt"],
        tool_name="httpx",
        engagement_dir=eng,
    )


def test_dynamic_shell_target_needs_no_declaration(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    result = scope.enforce_execution_policy(
        ["sh", "-c", 'curl -sS "https://$host/health"'],
        tool_name="curl",
        engagement_dir=eng,
    )

    assert result["target_facing"] is True


def test_ambiguous_launcher_form_does_not_block_the_run(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    scope.enforce_execution_policy(
        ["sudo", "--mystery-option", "nuclei", "-u", "https://example.test"],
        tool_name="sudo",
        engagement_dir=eng,
    )


# ---------------------------------------------------------------------------
# Engagement tool policy (survives — it refuses on the TOOL, not the host)
# ---------------------------------------------------------------------------


def test_execution_policy_denied_tool_is_blocked(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "denied_tools": ["nuclei"]},
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'nuclei'.*denied"):
        scope.enforce_execution_policy(
            ["nuclei", "-u", "https://example.test"],
            tool_name="nuclei",
            engagement_dir=eng,
        )


def test_execution_policy_reads_nested_denied_tool_policy(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "tool_policy": {"denied_tools": ["nuclei"]},
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'nuclei'.*denied"):
        scope.enforce_execution_policy(
            ["nuclei", "-u", "https://example.test"],
            tool_name="nuclei",
            engagement_dir=eng,
        )


def test_scope_enforcement_bypass_grants_nothing_at_execution(
    tmp_path: Path,
) -> None:
    """`scope_enforcement: bypass` toggles host-set SHAPING, nothing else.

    It is read by host-set shaping and proxy flow ownership. At execution it
    grants no authority at all, so tool policy refuses exactly as it does
    without it. `off_limits_paths` is advisory at this boundary.
    """
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "scope_enforcement": "bypass",
            "denied_tools": ["nuclei"],
            "off_limits_paths": ["/admin/delete"],
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'nuclei'.*denied"):
        scope.enforce_execution_policy(
            ["nuclei", "-u", "https://example.test"],
            tool_name="nuclei",
            engagement_dir=eng,
        )

    result = scope.enforce_execution_policy(
        ["curl", "https://example.test/admin/delete"],
        tool_name="curl",
        engagement_dir=eng,
    )
    assert result["target_facing"] is True


def test_execution_policy_normalizes_malformed_tool_policy_to_auditable_refusal(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"], "tool_policy": ["nuclei"]})

    with pytest.raises(scope.ScopePolicyError, match="scope.json"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test"],
            tool_name="curl",
            engagement_dir=eng,
        )


def test_execution_policy_checks_actual_executable_when_declared_name_differs(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "tool_policy": {"denied_tools": ["curl"]},
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'curl'.*denied"):
        scope.enforce_execution_policy(
            ["/usr/bin/curl", "https://example.test"],
            tool_name="not-curl",
            engagement_dir=eng,
        )


def test_execution_policy_checks_denied_tools_in_every_shell_pipeline_stage(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "tool_policy": {"denied_tools": ["nuclei"]},
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'nuclei'.*denied"):
        scope.enforce_execution_policy(
            [
                "sh",
                "-c",
                "printf '%s\\n' https://example.test | nuclei -silent -ni",
            ],
            tool_name="sh",
            engagement_dir=eng,
        )


@pytest.mark.parametrize(
    "command",
    [
        ["sh", "-c", "printf ready\nnuclei -u https://example.test -ni"],
        ["sudo", "-n", "nuclei", "-u", "https://example.test", "-ni"],
        ["env", "-i", "MODE=quiet", "nuclei", "-u", "https://example.test", "-ni"],
        ["env", "-S", "nuclei -u https://example.test -ni"],
        ["env", "-Snuclei -u https://example.test -ni"],
        ["env", "--split-string", "nuclei -u https://example.test -ni"],
        ["env", "--split-string=nuclei -u https://example.test -ni"],
        ["timeout", "--signal=TERM", "10s", "nuclei", "-u", "https://example.test", "-ni"],
        ["timeout", "--", "10s", "nuclei", "-u", "https://example.test", "-ni"],
        [
            "sudo",
            "-n",
            "--preserve-env=HTTP_PROXY",
            "nuclei",
            "-u",
            "https://example.test",
            "-ni",
        ],
        ["nice", "-n", "5", "nuclei", "-u", "https://example.test", "-ni"],
        ["stdbuf", "-oL", "nuclei", "-u", "https://example.test", "-ni"],
        ["setsid", "-f", "nuclei", "-u", "https://example.test", "-ni"],
        ["time", "-p", "nuclei", "-u", "https://example.test", "-ni"],
        ["xargs", "-r", "nuclei", "-u", "https://example.test", "-ni"],
        [
            "sh",
            "-c",
            "while nuclei -u https://example.test -ni; do break; done",
        ],
        [
            "bash",
            "-c",
            "env -i MODE=quiet sh -c 'printf x | nuclei -u https://example.test -ni'",
        ],
    ],
    ids=[
        "newline",
        "sudo",
        "env",
        "env-split-short",
        "env-split-short-attached",
        "env-split-long",
        "env-split-long-attached",
        "timeout",
        "timeout-end-options",
        "sudo-preserve-env",
        "nice",
        "stdbuf",
        "setsid",
        "time",
        "xargs",
        "while-condition",
        "nested-shell",
    ],
)
def test_execution_policy_denies_inner_tool_behind_shell_and_launcher_wrappers(
    tmp_path: Path, command: list[str]
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "tool_policy": {"denied_tools": ["nuclei"]},
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="tool 'nuclei'.*denied"):
        scope.enforce_execution_policy(
            command,
            tool_name=command[0],
            engagement_dir=eng,
        )


def test_execution_policy_refuses_ambiguous_env_split_with_a_denylist(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "tool_policy": {"denied_tools": ["nuclei"]},
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="cannot be inspected reliably"):
        scope.enforce_execution_policy(
            ["env", "-S", "$TOOL -u https://example.test"],
            tool_name="env",
            engagement_dir=eng,
        )


def test_execution_tools_reports_every_stage_without_launcher_options() -> None:
    command = [
        "bash",
        "-c",
        (
            "printf x | jq .; sudo -n env -i MODE=quiet timeout --signal TERM 10s "
            "nuclei -u https://example.test -ni\ncurl https://example.test/health"
        ),
    ]

    tools = scope.execution_tools(command)

    assert {"bash", "printf", "jq", "sudo", "env", "timeout", "nuclei", "curl"} <= tools
    assert not ({"-n", "-i", "--signal", "term", "10s"} & tools)


def test_host_declared_tool_consistency_resolves_transparent_launchers(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    command = [
        "sudo",
        "-n",
        "env",
        "-i",
        "timeout",
        "10",
        "nuclei",
        "-u",
        "https://example.test",
        "-ni",
    ]

    result = scope.enforce_execution_policy(
        command,
        tool_name="nuclei",
        engagement_dir=eng,
        require_declared_tool=True,
    )

    assert result["target_facing"] is True


def test_execution_policy_rejects_contradictory_declared_host_tool(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="declared tool 'nmap'.*curl"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test"],
            tool_name="nmap",
            engagement_dir=eng,
            require_declared_tool=True,
        )


# ---------------------------------------------------------------------------
# `off_limits_paths` is guidance, never an outbound-request veto.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        pytest.param(
            ["curl", "https://example.test/api/send-email"],
            id="direct-url",
        ),
        pytest.param(
            ["curl", "https://example.test/admin%252Fdelete"],
            id="encoded-path",
        ),
        pytest.param(
            [
                "sh",
                "-c",
                'host=example.test; path=/admin/delete; curl -sS "https://$host$path"',
            ],
            id="shell-variables",
        ),
        pytest.param(
            ["nuclei", "-u=https://example.test/admin/delete"],
            id="attached-flag",
        ),
        pytest.param(
            ["gobuster", "dir", "-u", "https://example.test/admin/delete"],
            id="unrecognised-tool",
        ),
    ],
)
def test_off_limits_paths_never_refuse_an_outbound_command(
    tmp_path: Path, command: list[str]
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "off_limits_paths": ["/api/send-email", "/admin/delete"],
        },
    )

    result = scope.enforce_execution_policy(
        command,
        tool_name=command[0],
        engagement_dir=eng,
    )
    assert result["target_facing"] is True


def test_off_limits_paths_inside_a_target_list_are_not_read_or_refused(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/delete"]},
    )
    targets = tmp_path / "urls.txt"
    targets.write_text(
        "https://example.test/admin/delete\nhttps://example.test/ok\n",
        encoding="utf-8",
    )

    result = scope.enforce_execution_policy(
        ["nuclei", "-l", str(targets)],
        tool_name="nuclei",
        engagement_dir=eng,
    )

    assert result["target_facing"] is True


# ---------------------------------------------------------------------------
# `target_facing` — a positive rate-governance signal
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        (["curl", "https://example.test/"], True),
        (["nmap", "-sV", "example.test"], True),
        (["sh", "-c", "httpx -l hosts.txt"], True),
        (["python3", "script.py", "https://example.test/"], True),
        (["jq", ".", "results.json"], False),
        (["cat", "/engagements/eng-key/scans/out.txt"], False),
    ],
)
def test_target_facing_marks_recognized_positive_signals(
    tmp_path: Path, command: list[str], expected: bool
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    result = scope.enforce_execution_policy(
        command, tool_name=command[0], engagement_dir=eng
    )

    assert result["target_facing"] is expected


def test_target_facing_honours_a_declared_tool_its_argv_hides(
    tmp_path: Path,
) -> None:
    """`kali browser` drives a real browser at the target under an opaque argv.

    Its argv is `python3 -c <driver> <json-plan>`: the executable is not
    target-facing and the plan's URLs are inside a JSON blob, so nothing lexical
    marks the run. Without the DECLARED tool name it would drive Chromium at the
    estate without the target-facing cross-lane advisory.
    """
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    plan = json.dumps({"url": "https://example.test/dashboard"})

    result = scope.enforce_execution_policy(
        ["python3", "-c", "<driver source>", plan],
        tool_name="browser",
        engagement_dir=eng,
    )

    assert result["target_facing"] is True


def test_container_script_path_for_another_engagement_is_not_rebased(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    script = eng / "probe.py"
    script.write_text(
        'import requests\nrequests.get("https://example.test/health")\n',
        encoding="utf-8",
    )

    with pytest.raises(scope.ScopePolicyError, match="other-engagement"):
        scope.execution_script_path(
            "/engagements/other-engagement/probe.py", eng
        )


def test_container_script_path_for_current_engagement_resolves_exact_file(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    script = eng / "probe.py"
    script.write_text(
        'import requests\nrequests.get("https://example.test/health")\n',
        encoding="utf-8",
    )

    assert scope.execution_script_path(
        "/engagements/eng-key/probe.py", eng
    ) == script.resolve()


@pytest.mark.parametrize(
    ("interpreter", "script_name", "program"),
    [
        ("python3", "probe.py", '# requests.get("https://example.test")\nprint("ok")'),
        ("node", "probe.js", '// fetch("https://example.test")\nconsole.log("ok")'),
    ],
    ids=["python-comment", "node-comment"],
)
def test_inert_script_text_is_not_target_facing(
    tmp_path: Path, interpreter: str, script_name: str, program: str
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})
    (eng / script_name).write_text(program, encoding="utf-8")

    result = scope.enforce_execution_policy(
        [interpreter, script_name], tool_name=interpreter, engagement_dir=eng
    )

    assert result["target_facing"] is False


def test_relative_script_inspection_uses_the_process_working_directory(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})
    (eng / "probe.py").write_text(
        'import requests\nrequests.get("https://example.test")\n',
        encoding="utf-8",
    )
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "probe.py").write_text("print('offline')\n", encoding="utf-8")

    assert scope.execution_script_path(
        "probe.py", eng, execution_cwd=outside
    ) is None


def test_normalized_container_script_escape_is_not_inspected(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="escapes current engagement"):
        scope.execution_script_path(
            "/engagements/eng-key/../other-engagement/probe.py", eng
        )


def test_host_lane_refuses_container_namespace_script_path(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="cannot be executed by host-exec"):
        scope.execution_script_path(
            "/engagements/eng-key/probe.py", eng, container_paths=False
        )


def test_target_facing_run_requires_nonempty_canonical_host_scope(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "web", "hosts": []})

    with pytest.raises(scope.ScopePolicyError, match="non-empty.*hosts"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test/"],
            tool_name="curl",
            engagement_dir=eng,
        )


def test_code_only_research_network_access_is_not_refused(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})

    result = scope.enforce_execution_policy(
        ["curl", "https://docs.python.org/3/"],
        tool_name="curl",
        engagement_dir=eng,
    )

    assert result == {"target_facing": True}


def test_code_only_declared_target_contact_warns_without_refusing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "engagement_type": "code",
            "hosts": ["app.example.test"],
            "code_target_contact_policy": "warn-do-not-contact",
        },
    )

    result = scope.enforce_execution_policy(
        ["curl", "https://app.example.test/health"],
        tool_name="curl",
        engagement_dir=eng,
    )

    assert result == {
        "target_facing": True,
        "code_target_warning": "app.example.test",
    }
    warning = capsys.readouterr().err
    assert "CODE engagement" in warning
    assert "app.example.test" in warning
    assert "advisory" in warning.lower()
    assert "continuing" in warning.lower()


def test_code_only_research_host_does_not_trigger_declared_target_warning(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    eng = _engagement(
        tmp_path,
        {"engagement_type": "code", "hosts": ["app.example.test"]},
    )

    result = scope.enforce_execution_policy(
        ["curl", "https://docs.python.org/3/"],
        tool_name="curl",
        engagement_dir=eng,
    )

    assert result == {"target_facing": True}
    assert "CODE engagement" not in capsys.readouterr().err


def test_code_browser_warns_when_a_later_navigation_reaches_declared_target(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    eng = _engagement(
        tmp_path,
        {"engagement_type": "both", "hosts": ["app.example.test"]},
    )
    plan = json.dumps(
        {
            "url": "https://docs.python.org/3/",
            "steps": [
                {"action": "navigate", "url": "https://app.example.test/account"}
            ],
        }
    )

    result = scope.enforce_execution_policy(
        [
            "python3",
            "-c",
            "# browser driver",
            plan,
            "https://docs.python.org/3/",
            "https://app.example.test/account",
        ],
        tool_name="browser",
        engagement_dir=eng,
        execution_phase="code-hunt",
    )

    assert result["code_target_warning"] == "app.example.test"
    assert "execution is continuing" in capsys.readouterr().err


@pytest.mark.parametrize(
    "command",
    [
        ["node", "-e", "fetch('https://example.test')"],
        ["node", "--eval", "fetch('https://example.test')"],
        ["node", "-p", "fetch('https://example.test')"],
        ["ruby", "-e", "Net::HTTP.get(URI('https://example.test'))"],
        ["perl", "-e", "LWP::UserAgent->new->get('https://example.test')"],
        ["php", "-r", "curl_init('https://example.test');"],
    ],
    ids=["node-e", "node-eval", "node-print", "ruby-e", "perl-e", "php-r"],
)
def test_inline_interpreter_program_is_never_resolved_as_a_script_path(
    tmp_path: Path,
    command: list[str],
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})

    result = scope.enforce_execution_policy(
        command,
        tool_name=command[0],
        engagement_dir=eng,
    )

    assert result == {"target_facing": False}


def test_interpreter_option_value_does_not_hide_foreign_engagement_script(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "web", "hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="other-engagement"):
        scope.enforce_execution_policy(
            [
                "python3",
                "-W",
                "ignore",
                "/engagements/other-engagement/scripts/probe.py",
            ],
            tool_name="python3",
            engagement_dir=eng,
        )


def test_readable_script_does_not_claim_target_facing_completeness(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})
    script = eng / "probe.sh"
    script.write_text("#!/bin/sh\ncurl https://example.test/\n", encoding="utf-8")

    result = scope.enforce_execution_policy(
        ["bash", "probe.sh"],
        tool_name="bash",
        engagement_dir=eng,
    )

    assert result["target_facing"] is False


def test_offline_run_does_not_require_host_scope(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"engagement_type": "code", "hosts": []})

    result = scope.enforce_execution_policy(
        ["jq", ".", "results.json"], tool_name="jq", engagement_dir=eng
    )

    assert result["target_facing"] is False


def test_execution_policy_notes_bound_and_hash_a_long_refusal() -> None:
    reason = "refusing denied tool " + ("x" * 4000)
    policy = {"target_facing": True, "policy_refusal": reason}

    notes = scope.execution_policy_notes(policy)
    decoded = json.loads(notes)

    assert len(notes.encode("utf-8")) < 4096
    assert len(decoded["policy_refusal"]) == 1024
    assert len(decoded["policy_refusal_sha256"]) == 64
    assert decoded["target_facing"] is True
