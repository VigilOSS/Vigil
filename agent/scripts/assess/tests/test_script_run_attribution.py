"""Script-driven runs: ROE attribution (I-155) and multi-identity carriage (I-156).

Both defects come from the same structural fact: injection is argv REWRITING,
and a shell script FILE has no argv to rewrite — an appended ``-H`` becomes the
script's ``$1`` and never reaches the requests inside it. The consequences
diverged:

  * required attribution headers degraded to a WARNING, so the multi-request
    rehearsal script that produces an engagement's best evidence fired at a
    production target with no deconfliction header and no record of the fact;
  * identity material was correctly REFUSED rather than claimed (stamping
    ``auth_context`` on a request that never carried the credential would be
    fabricated evidence) — which left a two-identity access-control proof, the
    thing the identity system exists for, with no supported shape at all.

Env is the carrier both need: it crosses into a script file, and because the
script must NAME the variable to use it, the audit stays honest.
"""
from __future__ import annotations

import json

import pytest
from assess.lib import kali
from assess.lib.kali_runtime_exec import _build_docker_exec
from assess.lib.scope import ScopePolicyError

_HANDLE = {"X-HackerOne": "vigiloss"}


def _engagement(tmp_path, *, required=None):
    (tmp_path / "scope.json").write_text(
        json.dumps(
            {
                "hostname": "app.example.com",
                "engagement_type": "web",
                **({"required_headers": required} if required else {}),
            }
        )
    )
    return tmp_path


def _script(tmp_path, body: str, name: str = "probe.sh"):
    scripts = tmp_path / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    path = scripts / name
    path.write_text(body)
    return path


# --------------------------------------------------------------------------- #
# I-155 — a script that cannot carry the mandatory header must not fire.
# --------------------------------------------------------------------------- #


def test_script_referencing_the_header_runs_and_records_verification(tmp_path):
    eng = _engagement(tmp_path, required=_HANDLE)
    _script(eng, '#!/bin/bash\ncurl -H "X-HackerOne: vigiloss" https://app.example.com/a\n')
    report: dict = {}

    kali.prepare_execution_command(
        ["bash", "/engagements/eng/scripts/probe.sh"],
        tool_name="bash",
        engagement_dir=eng,
        report=report,
    )

    assert report["required_header_status"] == "verified_in_script"


def test_script_referencing_only_the_env_carrier_is_accepted(tmp_path):
    """The env carrier is what makes the check satisfiable without hand-copying
    the handle into every curl line, so referencing it must count."""
    eng = _engagement(tmp_path, required=_HANDLE)
    _script(eng, '#!/bin/bash\ncurl -H "$VIGIL_REQUIRED_HEADERS" https://app.example.com/a\n')
    report: dict = {}

    kali.prepare_execution_command(
        ["bash", "scripts/probe.sh"],
        tool_name="bash",
        engagement_dir=eng,
        report=report,
    )

    assert report["required_header_status"] == "verified_in_script"


def test_script_without_the_header_refuses_before_any_traffic(tmp_path):
    eng = _engagement(tmp_path, required=_HANDLE)
    _script(eng, "#!/bin/bash\ncurl https://app.example.com/a\n")

    with pytest.raises(ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["bash", "scripts/probe.sh"], tool_name="bash", engagement_dir=eng
        )

    message = str(excinfo.value)
    assert "X-HackerOne" in message
    assert "VIGIL_REQUIRED_HEADERS" in message  # the remedy, not just the refusal


def test_unreadable_or_out_of_engagement_script_refuses_distinctly(tmp_path):
    eng = _engagement(tmp_path, required=_HANDLE)

    with pytest.raises(ScopePolicyError) as excinfo:
        kali.prepare_execution_command(
            ["bash", "/etc/probe.sh"], tool_name="bash", engagement_dir=eng
        )

    assert "cannot read" in str(excinfo.value)


def test_python_script_is_held_to_the_same_rule(tmp_path):
    eng = _engagement(tmp_path, required=_HANDLE)
    _script(eng, "import requests\nrequests.get('https://app.example.com/a')\n", "probe.py")

    with pytest.raises(ScopePolicyError):
        kali.prepare_execution_command(
            ["python3", "scripts/probe.py"], tool_name="python3", engagement_dir=eng
        )


def test_a_program_with_no_required_headers_is_unaffected(tmp_path):
    eng = _engagement(tmp_path)
    _script(eng, "#!/bin/bash\ncurl https://app.example.com/a\n")
    report: dict = {}

    kali.prepare_execution_command(
        ["bash", "scripts/probe.sh"],
        tool_name="bash",
        engagement_dir=eng,
        report=report,
    )

    assert report["required_header_status"] == "none_required"


def test_a_c_body_still_injects_and_is_never_refused(tmp_path):
    """Must NOT regress: the ``-c`` body path rewrites the sub-commands inside
    the script text, so it never reaches the script-file check."""
    eng = _engagement(tmp_path, required=_HANDLE)
    cmd = ["bash", "-c", "curl -sS https://app.example.com/a"]
    report: dict = {}

    kali.prepare_execution_command(
        cmd, tool_name="curl", engagement_dir=eng, report=report
    )

    assert report["required_header_status"] == "injected"
    assert "X-HackerOne: vigiloss" in cmd[2]


def test_a_passive_tool_is_skipped_not_refused(tmp_path):
    """``gau`` reads third-party archives, never the in-scope target — injecting
    there would LEAK the researcher handle to web.archive.org."""
    eng = _engagement(tmp_path, required=_HANDLE)
    report: dict = {}

    kali.prepare_execution_command(
        ["gau", "app.example.com"], tool_name="gau", engagement_dir=eng, report=report
    )

    assert report["required_header_status"] == "skipped"


def test_required_headers_are_exported_for_the_script_to_read(tmp_path):
    pairs = kali.required_header_env_pairs(_HANDLE)
    assert ("VIGIL_REQUIRED_HEADERS", "X-HackerOne: vigiloss") in pairs
    assert ("VIGIL_REQUIRED_HEADER_X_HACKERONE", "vigiloss") in pairs


# --------------------------------------------------------------------------- #
# I-156 — two identities, one script, one audited window.
# --------------------------------------------------------------------------- #


def _identity(name, cookies):
    return {
        "mode": "proxy_capture",
        "state": "available",
        "host_cookies": [{"host": "app.example.com", "cookies": cookies}],
    }


def _stub_identities(monkeypatch, table):
    monkeypatch.setattr(
        kali,
        "resolve_identity",
        lambda _eng, requested, **_kw: (requested, table.get(requested, {})),
    )


def test_two_identities_export_two_distinct_variable_sets(monkeypatch, tmp_path):
    _stub_identities(
        monkeypatch,
        {
            "org2_admin": _identity("org2_admin", {"sid": "ADMIN"}),
            "member_lowpriv": _identity("member_lowpriv", {"sid": "MEMBER"}),
        },
    )

    pairs, names = kali.resolve_identity_env(
        ["ADMIN=org2_admin", "MEMBER=member_lowpriv"],
        engagement_dir=tmp_path,
        tool_name="bash",
        cmd=["bash", "scripts/probe.sh"],
    )

    exported = dict(pairs)
    assert exported["VIGIL_COOKIE_ADMIN"] == "sid=ADMIN"
    assert exported["VIGIL_COOKIE_MEMBER"] == "sid=MEMBER"
    assert exported["VIGIL_IDENTITY_ADMIN"] == "org2_admin"
    assert exported["VIGIL_HEADERS_MEMBER"] == "Cookie: sid=MEMBER"
    assert names == ["org2_admin", "member_lowpriv"]


def test_exported_values_reach_the_container_as_env_arguments(monkeypatch, tmp_path):
    _stub_identities(monkeypatch, {"admin": _identity("admin", {"sid": "A"})})
    pairs, _names = kali.resolve_identity_env(
        ["ADMIN=admin"],
        engagement_dir=tmp_path,
        tool_name="bash",
        cmd=["bash", "scripts/probe.sh"],
    )

    argv = _build_docker_exec(
        ["bash", "scripts/probe.sh"],
        container_name="vigil",
        run_uuid="r1",
        engagement_key="eng",
        env_pairs=pairs,
    )

    assert "--env" in argv
    assert "VIGIL_COOKIE_ADMIN=sid=A" in argv
    # The shared engagement mirror is untouched.
    assert "ENGAGEMENT_KEY=eng" in argv


def test_auth_context_records_every_identity_sorted_and_deduped():
    assert kali.merge_auth_context("anonymous", "member", "admin") == "admin,member"
    assert kali.merge_auth_context("admin", "admin") == "admin"
    assert kali.merge_auth_context("anonymous") == "anonymous"


def test_an_over_long_auth_context_is_refused_not_silently_mangled():
    with pytest.raises(ScopePolicyError) as excinfo:
        kali.merge_auth_context(*[f"identity_number_{n:03d}" for n in range(20)])
    assert "128-char limit" in str(excinfo.value)


@pytest.mark.parametrize(
    "entry", ["ADMIN", "=org2_admin", "ADMIN=", "9BAD=org2_admin", "A-B=org2_admin"]
)
def test_malformed_identity_env_entries_are_refused(monkeypatch, tmp_path, entry):
    _stub_identities(monkeypatch, {"org2_admin": _identity("a", {"sid": "A"})})
    with pytest.raises(ScopePolicyError):
        kali.resolve_identity_env(
            [entry], engagement_dir=tmp_path, tool_name="bash", cmd=["bash", "scripts/probe.sh"]
        )


def test_a_repeated_variable_name_is_refused(monkeypatch, tmp_path):
    """Silently overwriting would leave the script probing ONE identity while the
    audit row claims two."""
    _stub_identities(
        monkeypatch,
        {"a": _identity("a", {"sid": "A"}), "b": _identity("b", {"sid": "B"})},
    )
    with pytest.raises(ScopePolicyError) as excinfo:
        kali.resolve_identity_env(
            ["X=a", "X=b"], engagement_dir=tmp_path, tool_name="bash", cmd=["bash", "scripts/probe.sh"]
        )
    assert "given twice" in str(excinfo.value)


def test_a_missing_identity_in_any_position_refuses(monkeypatch, tmp_path):
    _stub_identities(monkeypatch, {"admin": _identity("admin", {"sid": "A"})})
    with pytest.raises(ScopePolicyError) as excinfo:
        kali.resolve_identity_env(
            ["ADMIN=admin", "MEMBER=ghost"],
            engagement_dir=tmp_path,
            tool_name="bash",
            cmd=["bash", "scripts/probe.sh"],
        )
    assert "'ghost' was not found" in str(excinfo.value)


def test_a_dead_identity_refuses_before_execution(monkeypatch, tmp_path):
    dead = _identity("dead", {"sid": "D"})
    dead["state"] = "revoked"
    _stub_identities(monkeypatch, {"dead": dead})
    with pytest.raises(ScopePolicyError):
        kali.resolve_identity_env(
            ["A=dead"], engagement_dir=tmp_path, tool_name="bash", cmd=["bash", "scripts/probe.sh"]
        )


def test_an_identity_with_nothing_to_export_refuses_rather_than_running_anonymously(
    monkeypatch, tmp_path
):
    empty = {"mode": "proxy_capture", "state": "available", "cookies": {}}
    _stub_identities(monkeypatch, {"hollow": empty})
    with pytest.raises(ScopePolicyError) as excinfo:
        kali.resolve_identity_env(
            ["A=hollow"], engagement_dir=tmp_path, tool_name="bash", cmd=["bash", "scripts/probe.sh"]
        )
    assert "would be empty" in str(excinfo.value)


def test_a_multi_bucket_identity_with_no_argv_host_is_refused_not_bled(
    monkeypatch, tmp_path
):
    """Must NOT regress the cross-host bleed rule: with several captured hosts
    and no URL in the argv there is no defensible bucket, so we refuse rather
    than route one host's session at another."""
    multi = {
        "mode": "proxy_capture",
        "state": "available",
        "cookies": {"sid": "PORTAL", "apikey": "K"},
        "host_cookies": [
            {"host": "portal.example.com", "cookies": {"sid": "PORTAL"}},
            {"host": "api.example.com", "cookies": {"apikey": "K"}},
        ],
    }
    _stub_identities(monkeypatch, {"multi": multi})
    with pytest.raises(ScopePolicyError):
        kali.resolve_identity_env(
            ["A=multi"], engagement_dir=tmp_path, tool_name="bash", cmd=["bash", "scripts/probe.sh"]
        )


def test_a_c_body_url_scopes_the_exported_cookie_to_that_host(monkeypatch, tmp_path):
    multi = {
        "mode": "proxy_capture",
        "state": "available",
        "host_cookies": [
            {"host": "portal.example.com", "cookies": {"sid": "PORTAL"}},
            {"host": "api.example.com", "cookies": {"apikey": "K"}},
        ],
    }
    _stub_identities(monkeypatch, {"multi": multi})

    pairs, _names = kali.resolve_identity_env(
        ["A=multi"],
        engagement_dir=tmp_path,
        tool_name="curl",
        cmd=["bash", "-c", "curl -s 'https://api.example.com/v1/x'"],
    )

    assert dict(pairs)["VIGIL_COOKIE_A"] == "apikey=K"
