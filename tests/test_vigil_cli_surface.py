"""Pinned surface of the `vigil` operator CLI tree and its parse-time output.

The argparse tree is an external contract: every command path and the options,
positionals, arity and choices it accepts are pinned as a structure. Wording is
not pinned: the help, usage and error bytes each command path prints are held to
the bytes the whole tree prints, and the processes that skip the operator modules
are held to what the full CLI does and to the modules they may import.
"""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from vigil_cli import main as cli


# --------------------------------------------------------------------------- #
# The whole `vigil` argparse tree: each command path and what it accepts, as
# operator-visible structure rather than wording. An option is its option
# strings joined by `|`, then `=` when it takes a value, `+=` when it collects
# repeated values, and the arity when it takes several; a positional is its
# dest and arity. Choices follow in braces, and an option that must be given
# says so; a positional's arity says whether it may be omitted. Help,
# descriptions and metavars are wording, left to the output checks below.
# --------------------------------------------------------------------------- #

_FLAGS = (argparse._StoreTrueAction, argparse._HelpAction, argparse._VersionAction)
_VALUES = {argparse._StoreAction: "=", argparse._AppendAction: "+="}
_ARITY = {None: "", "?": "?", "*": "*", "+": "+", argparse.REMAINDER: "..."}


def _accepted(action: argparse.Action) -> str:
    arity = _ARITY.get(action.nargs, f"{{{action.nargs}}}")
    if not action.option_strings:
        shape = action.dest + arity
    elif type(action) in _FLAGS:
        shape = "|".join(action.option_strings)
    else:
        # Any other action kind is named, so adding one changes the pin visibly.
        shape = "|".join(action.option_strings) + _VALUES.get(type(action), f" <{type(action).__name__}>") + arity
    if action.choices is not None:
        shape += " {" + ",".join(str(choice) for choice in action.choices) + "}"
    if action.option_strings and action.required:
        shape += " (required)"
    return shape


def _command_tree(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()) -> dict[str, list[str]]:
    tree = {" ".join(path): [_accepted(action) for action in parser._actions
                             if not isinstance(action, argparse._SubParsersAction)]}
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                tree.update(_command_tree(child, path + (name,)))
    return tree


_COMMAND_TREE = {
    "": ["-h|--help", "--root=", "--source=", "--version|-V"],
    "install": [
        "-h|--help", "install_dir?", "--dry-run", "--make-default", "--force-image", "--skip-image-check",
        "--repair-ambiguous-client-permissions-as-skip", "--refresh-physical-client-rosters",
    ],
    "doctor": ["-h|--help", "--json", "--install-host-tools", "--dry-run"],
    "status": ["-h|--help", "--json", "--write-check"],
    "up": [
        "-h|--help", "--engagement=", "--select", "--no-build", "--json", "--runtime-restart-timeout=",
        "--yes-restart-runtime", "--no-restart-runtime",
    ],
    "update": ["-h|--help", "--release=", "--no-restart"],
    "logs": ["-h|--help", "target {orchestrator,runtime,mitmproxy,oob,all}", "--follow", "--lines="],
    "config": ["-h|--help"],
    "config path": ["-h|--help"],
    "config list": ["-h|--help"],
    "config get": ["-h|--help", "key"],
    "config resolve": ["-h|--help", "key {orchestrator_base_url}", "--engagement-dir="],
    "config set": ["-h|--help", "key", "value"],
    "config unset": ["-h|--help", "key"],
    "config edit": ["-h|--help"],
    "use": ["-h|--help", "key?", "--select", "--clear"],
    "engagement": ["-h|--help"],
    "engagement list": ["-h|--help", "--json"],
    "engagement create": [
        "-h|--help", "target_or_name?", "--type= {web,code,android,remediation}", "--source-dir=", "--name=",
        "--project-config=", "--target=", "--hosts=", "--host+=", "--hosts-file=", "--repo+=", "--apk+=",
        "--package-name=", "--dynamic-mode= {static_only,device,emulator}", "--skip-permissions",
        "--program= {bugcrowd,hackerone,intigriti}", "--researcher=", "--header+=", "--out-of-scope+=",
        "--rate-limit=", "--no-prompt", "--json", "--dry-run",
    ],
    "engagement set-header": ["-h|--help", "key", "header"],
    "engagement unset-header": ["-h|--help", "key", "name"],
    "engagement add-oos": ["-h|--help", "key", "entries+"],
    "engagement remove-oos": ["-h|--help", "key", "entry"],
    "engagement add-track": ["-h|--help", "key", "track {web,code}"],
    "engagement repair-tracks": ["-h|--help", "key"],
    "engagement add-host": ["-h|--help", "key", "entries+"],
    "engagement set-rate-limit": ["-h|--help", "key", "value"],
    "engagement path": ["-h|--help", "key?", "--select"],
    "engagement mode": [
        "-h|--help", "key?", "--json", "--client= {codex,claude,opencode,zcode,goose,kimi,pi}",
    ],
    "engagement client-check": [
        "-h|--help", "key?", "--client= {opencode,zcode}", "--mode= {web,code}", "--json",
    ],
    "engagement current": ["-h|--help"],
    "engagement cd-init": ["-h|--help", "shell? {zsh,bash}"],
    "engagement start": [
        "-h|--help", "key?", "--select", "--client= {codex,claude,opencode,zcode,goose,kimi,pi}",
        "--mode= {web,code,blue,remediation,android}", "--thinking= {off,high,max}", "--no-autoprompt",
        "--skip-preflight",
    ],
    "engagement prove": [
        "-h|--help", "key?", "--select", "--finding=", "--mode= {code,web}", "--objective=", "--host+=",
        "--work=", "--reconcile", "--release", "--reason=", "--json",
    ],
    "engagement open": ["-h|--help", "key?", "--select"],
    "engagement archive": ["-h|--help", "key?", "--select"],
    "engagement export": ["-h|--help", "key?", "--select", "--format= {tar.gz,markdown-tree}", "--output="],
    "engagement export-pdf": ["-h|--help", "key?", "--select", "--output="],
    "blue": ["-h|--help"],
    "blue engage": [
        "-h|--help", "--customer=", "--platform=", "--severity=", "--source=", "--skip-permissions",
        "--skip-preflight", "--start= {codex,claude,opencode,goose,kimi}",
    ],
    "blue customers": ["-h|--help", "--platform=", "--json"],
    "blue alert": ["-h|--help"],
    "blue alert record": [
        "-h|--help", "--body-file= (required)", "-k|--engagement-key=", "--select", "--external-id=",
        "--severity=", "--source=", "--replace",
    ],
    "blue list": ["-h|--help", "--customer=", "--status=", "--phase=", "--json"],
    "blue show": ["-h|--help", "engagement_key?", "--select"],
    "blue tier": [
        "-h|--help", "finding_slug", "--tier= {L1,L2,L3,L4} (required)", "--notes=", "-k|--engagement-key=",
        "--select",
    ],
    "blue verify": [
        "-h|--help", "finding_slug",
        "--disposition= {downgraded,escalated,false_positive,verified} (required)", "--reason= (required)",
        "--evidence-refs=", "--proof-receipt-id+=", "--counter-check-file=", "--confirm-check-file=",
        "--kill-reason=", "--kill-check= {1,2,3,4,5}", "--new-severity=", "--force", "-k|--engagement-key=",
        "--select",
    ],
    "blue propose-contain": [
        "-h|--help", "finding_slug", "--action= (required)", "--target= (required)",
        "--platform= {aws,edr,generic,gws,m365,network,okta} (required)", "--rollback= (required)",
        "--blast-radius= {cross-platform,multi-tenant,multi-user,single-user} (required)", "--note=",
        "-k|--engagement-key=", "--select",
    ],
    "blue contain": [
        "-h|--help", "finding_slug", "--proposal= (required)", "--proof-artifact=", "--command-run-id=",
        "--action=", "--target=", "-k|--engagement-key=", "--select",
    ],
    "blue report": ["-h|--help", "-k|--engagement-key=", "--select", "--template="],
    "blue closeout": ["-h|--help", "-k|--engagement-key=", "--select", "--agent-id="],
    "blue tenant": ["-h|--help"],
    "blue tenant init": ["-h|--help", "--customer= (required)", "--platform= (required)", "--force"],
    "remediation": ["-h|--help", "--engagement-key|-k="],
    "remediation start": ["-h|--help", "--client= {claude,opencode,zcode}", "--session-id="],
    "remediation join": ["-h|--help", "case_id?", "--fresh"],
    "remediation route": ["-h|--help", "--client= {claude,opencode,zcode}", "references+"],
    "remediation session": ["-h|--help", "case_id", "--bind", "--session-id=", "--replace-stopped"],
    "remediation import": [
        "-h|--help", "--source= (required)", "--source-key=", "--title= (required)",
        "--snapshot-file= (required)", "--attachment+=", "--finding-id+=", "--resume-case-id=",
    ],
    "remediation from-finding": [
        "-h|--help", "--finding-engagement= (required)", "--finding= (required)", "--title=",
    ],
    "remediation list": ["-h|--help", "--json"],
    "remediation show": ["-h|--help", "case_id"],
    "remediation handoff": ["-h|--help", "case_id"],
    "remediation identity": ["-h|--help", "case_id", "--provider= (required)", "--key= (required)"],
    "remediation finalize-branch": ["-h|--help", "case_id", "--branch= (required)"],
    "remediation checks": [
        "-h|--help", "case_id", "--actor= (required)", "--name+=", "--shared-environment=",
        "--stage= {verification,publication}",
    ],
    "remediation test": [
        "-h|--help", "case_id", "--method= (required)", "--command= (required)",
        "--expected-failure= (required)", "--fix-path+=", "--directory=", "--setup-command=",
        "--timeout-seconds=",
    ],
    "remediation environment": [
        "-h|--help", "action {acquire,release}", "case_id", "--name= (required)", "--actor= (required)",
        "--token=",
    ],
    "remediation worktree": ["-h|--help", "case_id", "--base=", "--branch="],
    "remediation sync-revision": ["-h|--help", "case_id"],
    "remediation runtime-identity": [
        "-h|--help", "case_id", "--compose-file= (required)", "--service= (required)",
        "--container-path= (required)", "--shared-environment=", "--environment-token=", "--actor=",
    ],
    "remediation evidence": [
        "-h|--help", "case_id", "--kind= (required)", "--method= (required)",
        "--environment= {local,development,test,production} (required)", "--command=",
        "--observed= (required)", "--proved= (required)", "--artifact=", "--revision=",
        "--outcome= {failed_as_expected,passed,failed,blocked}",
        "--execution= {executed,reasoned,unavailable}", "--executed-revision=", "--executed-directory=",
        "--shared-environment=", "--environment-token=",
    ],
    "remediation baseline": [
        "-h|--help", "case_id",
        "--outcome= {runtime_reproduced,code_test_confirmed,unreproduced} (required)",
        "--method= (required)", "--proved= (required)", "--owner-decision= {proceed,pause}",
        "--owner-actor=", "--owner-reason=",
    ],
    "remediation plan": [
        "-h|--help", "case_id", "--file= (required)", "--requirements-file=", "--alternatives-reason=",
    ],
    "remediation release-plan": [
        "-h|--help", "case_id", "--production-canary= {required,not_required,defer} (required)",
        "--rationale= (required)", "--safe-procedure=", "--monitoring= (required)",
    ],
    "remediation approve": [
        "-h|--help", "case_id", "--reviewer= (required)", "--owner-instruction= (required)",
        "--review-digest= (required)",
    ],
    "remediation transition": [
        "-h|--help", "case_id", "status", "--actor= (required)", "--reason= (required)",
    ],
    "remediation deployment": [
        "-h|--help", "case_id", "--workflow= (required)", "--run-id= (required)",
        "--expected-revision= (required)", "--observed-revision= (required)", "--environment= {development}",
        "--actor= (required)",
    ],
    "remediation human-verification": [
        "-h|--help", "case_id", "--actor= (required)", "--result= {passed,failed,blocked} (required)",
        "--observed-revision= (required)", "--notes= (required)",
    ],
    "remediation stagehand": [
        "-h|--help", "case_id", "--script= (required)", "--revision= (required)",
        "--environment= {local,development,test,production}",
        "--purpose= {happy-path,bad-path,other} (required)", "--production-decision=",
        "--production-evidence-policy= {retain-screenshots,no-screenshots}", "--shared-environment=",
        "--environment-token=",
    ],
    "remediation browser": [
        "-h|--help", "case_id", "--driver= {browse,stagehand}", "--script= (required)",
        "--revision= (required)", "--environment= {local,development,test,production}",
        "--purpose= {happy-path,bad-path,other} (required)", "--production-decision=",
        "--production-evidence-policy= {retain-screenshots,no-screenshots}", "--shared-environment=",
        "--environment-token=",
    ],
    "remediation prepare-pr": [
        "-h|--help", "case_id", "--output= (required)", "--root-cause= (required)",
        "--fix-summary= (required)", "--body-file=",
    ],
    "remediation create-pr": [
        "-h|--help", "case_id", "--body-file= (required)", "--actor= (required)", "--template-mapped",
        "--update", "--owner-instruction=", "--title=",
    ],
    "remediation deployment-run": [
        "-h|--help", "case_id", "--actor= (required)", "--owner-instruction= (required)", "--input+=",
        "--additional-tests-decision= {run,skip}", "--new-request",
    ],
    "remediation development-handoff": ["-h|--help", "case_id", "--actor= (required)"],
    "orchestrator": ["-h|--help"],
    "orchestrator start": ["-h|--help", "--build", "--foreground", "--port="],
    "orchestrator stop": ["-h|--help"],
    "orchestrator restart": ["-h|--help", "--port="],
    "orchestrator status": ["-h|--help", "--json"],
    "orchestrator open": ["-h|--help"],
    "orchestrator build": ["-h|--help", "--force"],
    "runtime": ["-h|--help"],
    "runtime build": ["-h|--help", "variant? {full,lightweight}", "--dev"],
    "runtime start": ["-h|--help", "--recreate"],
    "runtime stop": ["-h|--help"],
    "runtime restart": ["-h|--help"],
    "runtime status": ["-h|--help"],
    "runtime shell": ["-h|--help"],
    "runtime shell-exec": ["-h|--help", "shell_command..."],
    "runtime resources": ["-h|--help", "--json"],
    "mitmproxy": ["-h|--help"],
    "mitmproxy start": ["-h|--help", "--port=", "--build"],
    "mitmproxy stop": ["-h|--help"],
    "mitmproxy status": ["-h|--help", "--json"],
    "mitmproxy cert": ["-h|--help"],
    "mitmproxy build": ["-h|--help", "--force"],
    "mitmproxy reload": ["-h|--help"],
    "mitmproxy routes": ["-h|--help", "--json"],
    "email": [
        "-h|--help", "mailbox", "--from=", "--subject=", "--within=", "--match=", "--extract", "--limit=",
        "--timeout-seconds=", "--wait-seconds=", "--poll-seconds=", "--links", "--json",
    ],
    "auth": ["-h|--help"],
    "auth status": [
        "-h|--help", "engagement?", "--select", "--identity=", "--scope=", "--probe", "--probe-url=",
    ],
    "auth show": ["-h|--help", "engagement?", "--select", "--identity="],
    "auth edit": ["-h|--help", "engagement?", "--select", "--identity="],
    "auth clear": ["-h|--help", "engagement?", "--select", "--identity=", "--all"],
    "auth export": ["-h|--help", "engagement?", "--select", "--identity=", "--host=", "--method="],
    "auth quarantine": ["-h|--help", "engagement?", "--select", "--identity= (required)"],
    "auth import": ["-h|--help", "engagement?", "--source=", "--select", "--identity=", "--factor="],
    "auth alias": [
        "-h|--help", "engagement?", "--select", "--name= (required)", "--principal= (required)", "--scope=",
    ],
    "auth env-check": ["-h|--help", "engagement?", "--select", "--keys=+ (required)"],
    "auth set-active": ["-h|--help", "engagement?", "--select", "--identity= (required)"],
    "auth keepalive": [
        "-h|--help", "engagement?", "--select", "--identity+=", "--anchor-cookie+=", "--probe-url=",
        "--scope=", "--liveness-ttl=", "--interval=", "--iters=", "--caps=", "--log=", "--detach",
    ],
    "backup": ["-h|--help"],
    "backup create": ["-h|--help"],
    "backup list": ["-h|--help"],
    "backup show": ["-h|--help", "backup?"],
    "backup restore": ["-h|--help", "backup", "--force"],
    "oob": ["-h|--help"],
    "oob start": ["-h|--help"],
    "oob stop": ["-h|--help"],
    "oob restart": ["-h|--help"],
    "oob status": ["-h|--help", "--json"],
    "oob routing": ["-h|--help", "--format= {all,json,caddy,dns}"],
    "oob test": ["-h|--help"],
    "oob clean": ["-h|--help", "--days=", "--dry-run", "--json"],
    "oob mint": [
        "-h|--help", "--engagement=", "--select", "--client=", "--target-url=", "--param=", "--technique=",
        "--probe-kind=", "--request-hash=", "--notes=", "--json",
    ],
    "oob poll": ["-h|--help", "--engagement=", "--select", "--client= (required)", "--lines=", "--json"],
    "oob client": ["-h|--help"],
    "oob client start": ["-h|--help", "name", "--engagement=", "--select", "--agent="],
    "oob client logs": ["-h|--help", "name", "--follow", "--lines="],
    "oob client stop": ["-h|--help", "name"],
    "oob client list": ["-h|--help"],
    "assess": ["assess_args..."],
}


def _built_parser(argv: list[str]) -> argparse.ArgumentParser:
    """The root parser `vigil <argv>` builds, captured at its parse call."""
    captured: dict[str, argparse.ArgumentParser] = {}
    real_parse_args = argparse.ArgumentParser.parse_args
    real_parse_known_args = argparse.ArgumentParser.parse_known_args

    def _capture(self, args=None, namespace=None):
        if self.prog == "vigil" and "parser" not in captured:
            captured["parser"] = self
            raise SystemExit(0)
        return real_parse_args(self, args, namespace)

    def _capture_known(self, args=None, namespace=None):
        if self.prog == "vigil" and "parser" not in captured:
            captured["parser"] = self
            raise SystemExit(0)
        return real_parse_known_args(self, args, namespace)

    with (
        mock.patch.object(argparse.ArgumentParser, "parse_args", _capture),
        mock.patch.object(argparse.ArgumentParser, "parse_known_args", _capture_known),
    ):
        with pytest.raises(SystemExit):
            cli._main(list(argv))
    parser = captured.get("parser")
    assert parser is not None, f"`vigil {' '.join(argv)}` built no root parser"
    return parser


def _whole_tree() -> argparse.ArgumentParser:
    return _built_parser(["--help"])


def test_vigil_command_paths_accept_what_they_did() -> None:
    assert _command_tree(_whole_tree()) == _COMMAND_TREE


# --------------------------------------------------------------------------- #
# Parse-time output. Every command path's `--help`, every group's missing and
# unknown action, a leaf's unknown flag, the root's version, usage and
# unknown-command errors: `vigil <argv>` must print what the whole tree prints
# for the same argv, byte for byte, with the same exit status.
# --------------------------------------------------------------------------- #


def _command_paths(parser: argparse.ArgumentParser, path: tuple[str, ...] = ()):
    yield path, parser
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, child in action.choices.items():
                yield from _command_paths(child, path + (name,))


def _parse_time_cases() -> list[list[str]]:
    cases: list[list[str]] = [
        [], ["--help"], ["-h"], ["--version"], ["-V"], ["--vers"], ["--version", "status"],
        ["--root", "/acme/vigil", "--version"], ["--root=/acme/vigil", "-V"], ["--root"],
        ["--bogus"], ["bogus"], ["engagment"], ["stauts"], ["oob", "polll"],
        ["engagement", "creat"], ["status", "--json", "--bogus"], ["logs"], ["logs", "nope"],
        ["--help", "status"], ["status", "--help", "--bogus"], ["-h", "bogus"],
        ["--root", "/acme/vigil", "status", "--help"], ["--sour", "/acme/app", "doctor", "-h"],
    ]
    for path, parser in _command_paths(_whole_tree()):
        if not path or path == ("assess",):
            continue
        cases.append([*path, "--help"])
        if any(isinstance(action, argparse._SubParsersAction) for action in parser._actions):
            cases.append(list(path))
            cases.append([*path, "acme-bogus-action"])
        elif path[:2] != ("engagement", "start"):
            # `engagement start` forwards unknown flags to the client instead.
            cases.append([*path, "--acme-unknown-flag"])
    return cases


def _outcome(run) -> tuple[object, str, str]:
    stdout, stderr = io.StringIO(), io.StringIO()
    code: object = None
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            run()
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


def test_each_command_path_prints_what_the_whole_tree_prints(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("COLUMNS", "100")
    monkeypatch.delenv("VIGIL_CLIENT_CONTEXT", raising=False)
    monkeypatch.chdir(tmp_path)
    whole = _whole_tree()
    for argv in _parse_time_cases():
        expected = _outcome(lambda: whole.parse_args(argv))
        if expected[0] is None:
            continue  # parsed: the command would run (`vigil remediation` opens its picker)
        assert _outcome(lambda: cli.main(list(argv))) == expected, argv


# --------------------------------------------------------------------------- #
# `vigil assess` and a bare `vigil --version` run in a process the `vigil`
# command starts for them alone, which does not import the operator commands.
# That process must exec the same program with the same argv and exported
# configuration, and print the same version, as the full CLI does.
# --------------------------------------------------------------------------- #

_ROOT = Path(__file__).resolve().parents[1]
_EXPORTED = (
    "VIGIL_APPLICATION_DIR", "VIGIL_INSTALL_DIR", "VIGIL_ENGAGEMENTS_DIR", "VIGIL_DATA_DIR",
    "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "UV_CACHE_DIR", "VIGIL_OOB_DOMAIN",
    "VIGIL_OOB_SLOT", "VIGIL_OOB_TENANT", "VIGIL_OOB_DNS_PORT", "VIGIL_OOB_REVERSE_PORT",
)
# What each such process may import: no operator command implementation. An assess
# handoff resolves the workspace, application and client context, and exports the
# OOB settings; a version request reads only the release.
_ASSESS_PROCESS_MODULES = {
    "vigil_cli.application", "vigil_cli.argv", "vigil_cli.assessment_clients", "vigil_cli.client_context",
    "vigil_cli.config", "vigil_cli.docker", "vigil_cli.install_fs", "vigil_cli.main", "vigil_cli.oob",
    "vigil_cli.oob_relay", "vigil_cli.opencode_launch", "vigil_cli.paths", "vigil_cli.term", "vigil_cli.workspace",
}
_VERSION_PROCESS_MODULES = {"vigil_cli.argv", "vigil_cli.config", "vigil_cli.main", "vigil_cli.paths"}
_HELPER_PROCESS = """
import json, os, sys
def report(path, argv, env):
    exported = {name: env.get(name) for name in json.loads(os.environ["ACME_EXPORTED"])}
    print(json.dumps({"path": path, "argv": argv, "env": exported}))
    sys.exit(0)
os.execvpe = report
try:
    from vigil_cli.main import main
    main()
finally:
    loaded = sorted(name for name in sys.modules if name.startswith("vigil_cli."))
    print(json.dumps(loaded), file=sys.stderr)
"""


def _helper_process(argv: list[str], env: dict[str, str]) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    result = subprocess.run(
        [sys.executable, "-c", _HELPER_PROCESS, *argv],
        env={**env, "ACME_EXPORTED": json.dumps(_EXPORTED)},
        capture_output=True, text=True, check=False, timeout=120,
    )
    loaded = json.loads(result.stderr.strip().splitlines()[-1])
    return result, loaded


@pytest.fixture
def helper_env(tmp_path, monkeypatch) -> dict[str, str]:
    install = tmp_path / "Acme workspace"
    (install / "engagements" / "acme").mkdir(parents=True)
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path / "home"),
        "PYTHONPATH": str(_ROOT / "src"),
        "VIGIL_APPLICATION_DIR": str(_ROOT),
        "VIGIL_INSTALL_DIR": str(install),
        "VIGIL_CONFIG": str(tmp_path / "config.json"),
        "VIGIL_APPLICATION_CACHE": str(tmp_path / "cache"),
    }
    for name in list(os.environ):
        if name.startswith(("VIGIL_", "ENGAGEMENT_", "ORCHESTRATOR_")):
            monkeypatch.delenv(name)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    monkeypatch.chdir(tmp_path)
    return env


@pytest.mark.parametrize("argv", [
    ["assess", "--engagement-dir", "engagements/acme", "log", "--actor-kind", "hook", "acme", "Bash", "a", "b"],
    ["--root", "Acme workspace", "assess", "code-dispatch", "heartbeat", "1", "HUNT-00", "token"],
    ["assess", "--help"],
    ["assess", "kali", "exec", "--", "acme-tool", "--help"],
])
def test_an_assess_process_execs_what_the_full_cli_execs(helper_env, monkeypatch, argv) -> None:
    captured: dict[str, object] = {}

    def full_cli_exec(path, exec_argv, env):
        captured.update(path=path, argv=exec_argv, env={name: env.get(name) for name in _EXPORTED})
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execvpe", full_cli_exec)
    with pytest.raises(SystemExit):
        cli.main(list(argv))
    result, loaded = _helper_process(argv, helper_env)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == captured
    assert sorted(set(loaded) - _ASSESS_PROCESS_MODULES) == []


@pytest.mark.parametrize("argv", [["--version"], ["-V"]])
def test_a_version_process_prints_what_the_full_cli_prints(helper_env, capsys, argv) -> None:
    with pytest.raises(SystemExit) as full:
        cli.main(list(argv))
    expected = capsys.readouterr().out
    result, loaded = _helper_process(argv, helper_env)
    assert (result.returncode, result.stdout) == (full.value.code, expected)
    assert expected.startswith("vigil ")
    assert sorted(set(loaded) - _VERSION_PROCESS_MODULES) == []
