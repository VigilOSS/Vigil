from __future__ import annotations

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
    (eng / "scope.json").write_text(__import__("json").dumps(doc), encoding="utf-8")
    return eng


def test_execution_policy_rejects_direct_out_of_scope_target(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["*.example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="outside engagement scope.*evil.test"):
        scope.enforce_execution_policy(
            ["nmap", "-sV", "evil.test"], tool_name="nmap", engagement_dir=eng
        )


def test_execution_policy_checks_every_target_in_container_list_file(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["*.example.test"]})
    targets = eng / "targets.txt"
    targets.write_text("api.example.test\nevil.test\n", encoding="utf-8")

    with pytest.raises(scope.ScopePolicyError, match="evil.test"):
        scope.enforce_execution_policy(
            ["nuclei", "-l", "/engagements/eng-key/targets.txt"],
            tool_name="nuclei",
            engagement_dir=eng,
            engagement_key="eng-key",
        )


def test_execution_policy_global_bypass_allows_direct_and_list_targets(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "scope_enforcement": "bypass"},
    )
    targets = eng / "targets.txt"
    targets.write_text("evil.test\n", encoding="utf-8")

    result = scope.enforce_execution_policy(
        ["nuclei", "-l", str(targets)],
        tool_name="nuclei",
        engagement_dir=eng,
    )

    assert result == {
        "scope_enforcement": "bypass",
        "scope_bypassed": True,
        "checked_targets": ["evil.test"],
    }


def test_execution_policy_no_fire_blocks_direct_url_even_during_scope_bypass(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "scope_enforcement": "bypass",
            "off_limits_paths": ["/api/send-email"],
        },
    )

    with pytest.raises(scope.ScopePolicyError, match="no-fire.*api/send-email"):
        scope.enforce_execution_policy(
            ["curl", "https://evil.test/api/send-email"],
            tool_name="curl",
            engagement_dir=eng,
        )


def test_execution_policy_no_fire_checks_every_url_in_target_list(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "off_limits_paths": ["/account/create"],
        },
    )
    targets = eng / "targets.txt"
    targets.write_text(
        "https://example.test/safe\nhttps://example.test/account/create\n",
        encoding="utf-8",
    )

    with pytest.raises(scope.ScopePolicyError, match="no-fire.*account/create"):
        scope.enforce_execution_policy(
            ["nuclei", "-l", str(targets)],
            tool_name="nuclei",
            engagement_dir=eng,
        )


def test_execution_policy_denied_tool_is_blocked_even_during_scope_bypass(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {
            "hosts": ["example.test"],
            "scope_enforcement": "bypass",
            "denied_tools": ["nuclei"],
        },
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


@pytest.mark.parametrize(
    "scope_doc",
    [
        {"hosts": ["example.test"], "tool_policy": ["nuclei"]},
        {"hosts": "example.test"},
    ],
)
def test_execution_policy_normalizes_malformed_scope_to_auditable_refusal(
    tmp_path: Path, scope_doc: dict
) -> None:
    eng = _engagement(tmp_path, scope_doc)

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


def test_execution_policy_uses_actual_executable_to_find_bare_target(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="evil.test"):
        scope.enforce_execution_policy(
            ["/usr/bin/curl", "evil.test"],
            tool_name="misdeclared-tool",
            engagement_dir=eng,
        )


@pytest.mark.parametrize(
    ("tool_name", "command"),
    [
        ("nmap", ["nmap", "-iL", "{list}"]),
        ("subfinder", ["subfinder", "-dL", "{list}"]),
        ("bbot", ["bbot", "-tL", "{list}"]),
        ("alterx", ["alterx", "-l", "{list}"]),
    ],
)
def test_execution_policy_checks_every_typed_target_list_variant(
    tmp_path: Path, tool_name: str, command: list[str]
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    targets = eng / "targets.txt"
    targets.write_text("example.test\nevil.test\n", encoding="utf-8")
    resolved = [
        token.format(list=str(targets)) if token == "{list}" else token
        for token in command
    ]

    with pytest.raises(scope.ScopePolicyError, match="evil.test"):
        scope.enforce_execution_policy(
            resolved,
            tool_name=tool_name,
            engagement_dir=eng,
        )


def test_execution_policy_checks_cero_shell_piped_target_list(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    targets = eng / "targets.txt"
    targets.write_text("example.test\nevil.test\n", encoding="utf-8")

    with pytest.raises(scope.ScopePolicyError, match="evil.test"):
        scope.enforce_execution_policy(
            ["sh", "-c", f"cat {targets} | cero"],
            tool_name="cero",
            engagement_dir=eng,
        )


def test_execution_policy_rejects_target_cidr_wider_than_allowed_network(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["10.0.0.0/24"]})

    with pytest.raises(scope.ScopePolicyError, match="10.0.0.0/16"):
        scope.enforce_execution_policy(
            ["nmap", "10.0.0.0/16"],
            tool_name="nmap",
            engagement_dir=eng,
        )


def test_execution_policy_allows_target_cidr_contained_by_allowed_network(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["10.0.0.0/24"]})

    result = scope.enforce_execution_policy(
        ["nmap", "10.0.0.0/25"],
        tool_name="nmap",
        engagement_dir=eng,
    )

    assert result["checked_targets"] == ["10.0.0.0/25"]


def test_execution_policy_fails_closed_when_target_list_cannot_be_inspected(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="cannot inspect target list"):
        scope.enforce_execution_policy(
            ["httpx", "-l", "/engagements/eng-key/missing.txt"],
            tool_name="httpx",
            engagement_dir=eng,
            engagement_key="eng-key",
        )


def test_execution_policy_records_enforced_mode_for_in_scope_command(tmp_path: Path) -> None:
    eng = _engagement(tmp_path, {"hosts": ["*.example.test"]})

    result = scope.enforce_execution_policy(
        ["curl", "https://api.example.test/v1"],
        tool_name="curl",
        engagement_dir=eng,
    )

    assert result == {
        "scope_enforcement": "enforce",
        "scope_bypassed": False,
        "checked_targets": ["api.example.test"],
    }


def test_execution_policy_does_not_treat_dotted_non_target_values_as_targets(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["api.example.test"]})

    result = scope.enforce_execution_policy(
        [
            "nuclei",
            "-u",
            "https://api.example.test",
            "-t",
            "custom.template.yaml",
            "-H",
            "Origin: https://vendor.example",
        ],
        tool_name="nuclei",
        engagement_dir=eng,
    )

    assert result["checked_targets"] == ["api.example.test"]


@pytest.mark.parametrize(
    ("tool_name", "command"),
    [
        ("nmap", ["nmap", "-sV", "evil.test"]),
        ("nuclei", ["nuclei", "-u", "https://evil.test"]),
        ("httpx", ["httpx", "-u", "https://evil.test"]),
        ("wafw00f", ["wafw00f", "https://evil.test"]),
        ("ffuf", ["ffuf", "-u", "https://evil.test/FUZZ"]),
        ("sqlmap", ["sqlmap", "-u", "https://evil.test/?id=1"]),
        ("subfinder", ["subfinder", "-d", "evil.test"]),
        ("puredns", ["puredns", "bruteforce", "/words.txt", "evil.test"]),
        ("nikto", ["nikto", "-h", "https://evil.test"]),
        ("katana", ["katana", "-u", "https://evil.test"]),
        ("gau", ["gau", "evil.test"]),
        ("arjun", ["arjun", "-u", "https://evil.test"]),
        ("whatweb", ["whatweb", "https://evil.test"]),
        ("cero", ["cero", "-d", "evil.test"]),
        ("alterx", ["alterx", "-d", "evil.test"]),
        ("asnmap", ["asnmap", "-d", "evil.test"]),
        ("bbot", ["bbot", "-t", "evil.test"]),
        ("browser", ["python3", "-c", "driver", "https://evil.test"]),
        ("tlsx", ["tlsx", "-u", "evil.test"]),
        ("dalfox", ["dalfox", "url", "https://evil.test"]),
        ("robots", ["httpx", "-u", "https://evil.test/robots.txt"]),
        ("exec", ["custom-tool", "https://evil.test"]),
    ],
)
def test_every_direct_target_verb_has_an_admission_position(
    tmp_path: Path, tool_name: str, command: list[str]
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["allowed.test"]})

    with pytest.raises(scope.ScopePolicyError, match="evil.test"):
        scope.enforce_execution_policy(
            command,
            tool_name=(command[0] if tool_name in {"robots", "exec"} else tool_name),
            engagement_dir=eng,
        )


def test_execution_policy_allows_only_explicitly_typed_passive_destination(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    command = ["curl", "https://crt.sh/?q=%25.example.test&output=json"]

    with pytest.raises(scope.ScopePolicyError, match="crt.sh"):
        scope.enforce_execution_policy(
            command, tool_name="curl", engagement_dir=eng
        )

    result = scope.enforce_execution_policy(
        command,
        tool_name="curl",
        engagement_dir=eng,
        destinations=(scope.ExecutionDestination("crt.sh", "passive_source"),),
    )

    assert result["checked_targets"] == []
    assert result["external_destinations"] == [
        {"host": "crt.sh", "role": "passive_source"}
    ]
    assert result["target_facing"] is False


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

    assert result["checked_targets"] == ["example.test"]


def test_ambiguous_launcher_form_fails_closed_for_typed_target(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="ambiguous.*launcher"):
        scope.enforce_execution_policy(
            ["sudo", "--mystery-option", "nuclei", "-u", "https://example.test"],
            tool_name="sudo",
            engagement_dir=eng,
            destinations=(scope.ExecutionDestination("example.test", "target"),),
        )


def test_ambiguous_launcher_form_fails_closed_for_literal_target(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="ambiguous.*launcher"):
        scope.enforce_execution_policy(
            ["sudo", "--mystery-option", "nuclei", "-u", "https://example.test"],
            tool_name="sudo",
            engagement_dir=eng,
        )


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


def test_execution_policy_dynamic_target_shell_requires_typed_destinations(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})
    command = ["sh", "-c", 'curl -sS "https://$host/health"']

    with pytest.raises(scope.ScopePolicyError, match="dynamic target.*typed destination"):
        scope.enforce_execution_policy(
            command, tool_name="curl", engagement_dir=eng
        )

    result = scope.enforce_execution_policy(
        command,
        tool_name="curl",
        engagement_dir=eng,
        destinations=(scope.ExecutionDestination("example.test", "target"),),
    )

    assert result["checked_targets"] == ["example.test"]
    assert result["target_facing"] is True


def test_typed_destination_does_not_bypass_determinable_shell_no_fire_path(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/delete"]},
    )
    command = [
        "sh",
        "-c",
        'host=example.test; path=/admin/delete; curl -sS "https://$host$path"',
    ]

    with pytest.raises(scope.ScopePolicyError, match="no-fire.*admin/delete"):
        scope.enforce_execution_policy(
            command,
            tool_name="curl",
            engagement_dir=eng,
            destinations=(scope.ExecutionDestination("example.test", "target"),),
        )


def test_typed_destination_fails_closed_for_unresolved_shell_target_path(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/*"]},
    )

    with pytest.raises(scope.ScopePolicyError, match="unresolved.*no-fire"):
        scope.enforce_execution_policy(
            ["sh", "-c", 'curl -sS "https://example.test$path"'],
            tool_name="curl",
            engagement_dir=eng,
            destinations=(scope.ExecutionDestination("example.test", "target"),),
        )


def test_typed_destination_does_not_bypass_encoded_no_fire_path(tmp_path: Path) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/delete"]},
    )

    with pytest.raises(scope.ScopePolicyError, match="no-fire.*admin%252Fdelete"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test/admin%252Fdelete"],
            tool_name="curl",
            engagement_dir=eng,
            destinations=(scope.ExecutionDestination("example.test", "target"),),
        )


def test_typed_passive_source_with_dynamic_query_is_not_subject_to_no_fire(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/*"]},
    )

    result = scope.enforce_execution_policy(
        ["sh", "-c", 'domain=example.test; curl "https://crt.sh/?q=$domain"'],
        tool_name="curl",
        engagement_dir=eng,
        destinations=(scope.ExecutionDestination("crt.sh", "passive_source"),),
    )

    assert result["checked_targets"] == []
    assert result["external_destinations"] == [
        {"host": "crt.sh", "role": "passive_source"}
    ]
    assert result["target_facing"] is False


def test_typed_control_destination_with_dynamic_path_is_not_subject_to_no_fire(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/callback/*"]},
    )

    result = scope.enforce_execution_policy(
        ["sh", "-c", 'curl "https://oob.test/callback/$token"'],
        tool_name="curl",
        engagement_dir=eng,
        destinations=(scope.ExecutionDestination("oob.test", "control"),),
    )

    assert result["checked_targets"] == []
    assert result["target_facing"] is False


def test_typed_target_dynamic_query_keeps_static_path_no_fire_check(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/*"]},
    )

    result = scope.enforce_execution_policy(
        ["sh", "-c", 'curl "https://example.test/search?q=$term"'],
        tool_name="curl",
        engagement_dir=eng,
        destinations=(scope.ExecutionDestination("example.test", "target"),),
    )

    assert result["checked_targets"] == ["example.test"]


def test_typed_target_dynamic_path_fails_closed_when_no_fire_is_configured(
    tmp_path: Path,
) -> None:
    eng = _engagement(
        tmp_path,
        {"hosts": ["example.test"], "off_limits_paths": ["/admin/*"]},
    )

    with pytest.raises(scope.ScopePolicyError, match="unresolved.*no-fire"):
        scope.enforce_execution_policy(
            ["sh", "-c", 'curl "https://example.test/$path"'],
            tool_name="curl",
            engagement_dir=eng,
            destinations=(scope.ExecutionDestination("example.test", "target"),),
        )


def test_conflicting_typed_roles_for_same_normalized_host_are_rejected(
    tmp_path: Path,
) -> None:
    eng = _engagement(tmp_path, {"hosts": ["example.test"]})

    with pytest.raises(scope.ScopePolicyError, match="conflicting.*example.test"):
        scope.enforce_execution_policy(
            ["curl", "https://example.test/health"],
            tool_name="curl",
            engagement_dir=eng,
            destinations=(
                scope.ExecutionDestination("https://EXAMPLE.test/", "target"),
                scope.ExecutionDestination("example.test", "control"),
            ),
        )


def test_execution_policy_notes_are_bounded_hashed_and_sampled() -> None:
    policy = {
        "scope_enforcement": "enforce",
        "scope_bypassed": False,
        "target_facing": True,
        "checked_targets": [f"host-{index:04d}.example.test" for index in range(1000)],
    }

    notes = scope.execution_policy_notes(policy)
    decoded = __import__("json").loads(notes)

    assert len(notes.encode("utf-8")) < 4096
    assert decoded["checked_target_count"] == 1000
    assert len(decoded["checked_targets_sha256"]) == 64
    assert 0 < len(decoded["checked_targets_sample"]) < 1000
    assert "checked_targets" not in decoded
