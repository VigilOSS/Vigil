"""Case-scoped remediation operator commands backed by the Vigil API."""
from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable
import fcntl
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import shutil
import shlex
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from . import restart_manifest, term
from .engagements import CreatedEngagement, EngagementRow, list_engagements, resolve_engagement_path
from .paths import resolve_orchestrator_base_url
from .remediation_vcs import adapter as _vcs
from .remediation_browser import execute as _execute_browse
from .project_config import project_module
from .prompts import prompt_choice
from .remediation_sessions import register_session_parsers, run_session_command, select_conversation_action


def register_remediation_parser(
    sub: argparse._SubParsersAction, *,
    create_parser: argparse.ArgumentParser | None = None,
    create_engagement: Callable[[argparse.Namespace, Path], CreatedEngagement | None] | None = None,
) -> None:
    parser = sub.add_parser(
        "remediation", help="Fix security tickets or reports, verify changes, and prepare reviewed draft PRs",
        usage="%(prog)s [-k KEY] COMMAND ...",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Fix security tickets or reports in your repository; no prior assessment needed.\n"
            "Start here: vigil remediation start\n"
            "Your agent follows PROJECT.md. Give /vigil-remediate a ticket or report."
        ),
        epilog=(
            "Examples:\n"
            "  vigil remediation start\n"
            "  vigil remediation -k KEY start --client claude\n\n"
            "The agent handles case commands; use COMMAND --help for details.\n"
            "Walkthrough: docs/remediation.md"
        ),
    )
    parser.add_argument("--engagement-key", "-k", help="Project key; start asks when omitted on a terminal")
    parser.set_defaults(remediation_help=parser.print_help, remediation_create_parser=create_parser,
                        remediation_create=create_engagement)
    commands = parser.add_subparsers(dest="remediation_command", title="Commands", metavar="COMMAND")
    register_session_parsers(commands)

    intake = commands.add_parser(
        "import", help="Import a retrieved ticket or direct report snapshot",
        description="Import a prepared local JSON snapshot and attachments. This command does not fetch Jira or bounty data. Resume a partial import with --resume-case-id.",
    )
    intake.add_argument("--source", required=True, help="Actual report provider, or report/manual for direct input")
    intake.add_argument("--source-key", help="Report identity; optional for report/manual input")
    intake.add_argument("--title", required=True)
    intake.add_argument("--snapshot-file", required=True, type=Path)
    intake.add_argument("--attachment", action="append", type=Path, default=[], help="Local report attachment; repeatable")
    intake.add_argument("--finding-id", type=int, action="append", default=[], help="Canonical Vigil finding ID sharing this fix; repeatable")
    intake.add_argument("--resume-case-id", help="Resume attachment registration after a partial import")

    from_finding = commands.add_parser("from-finding", help="Create a case from an assessment finding")
    from_finding.add_argument("--finding-engagement", required=True, help="Source assessment engagement key")
    from_finding.add_argument("--finding", required=True, help="Finding slug in the source engagement")
    from_finding.add_argument("--title")

    list_cases = commands.add_parser("list", help="List case IDs and join commands, open cases first")
    list_cases.add_argument("--json", action="store_true", help="Full case records with case_id and join_command for agents and scripts")
    show = commands.add_parser("show", help="Show case and review state")
    show.add_argument("case_id")
    handoff_case = commands.add_parser("handoff", help="Render the current case context for its developer")
    handoff_case.add_argument("case_id")
    identity = commands.add_parser("identity", help="Attach a primary external reference to a case")
    identity.add_argument("case_id")
    identity.add_argument("--provider", required=True, help="External reference provider")
    identity.add_argument("--key", dest="external_key", required=True, help="Provider's exact reference key")
    finalize = commands.add_parser("finalize-branch", help="Rename an unpublished case branch or bookmark")
    finalize.add_argument("case_id")
    finalize.add_argument("--branch", required=True)
    checks = commands.add_parser("checks", help="Execute profile checks against the registered case source")
    checks.add_argument("case_id")
    checks.add_argument("--actor", required=True)
    checks.add_argument("--name", action="append", default=[], help="Run a named check; repeatable, defaults to all")
    checks.add_argument("--shared-environment", help="Acquire exclusive use of the named shared test environment")
    checks.add_argument("--stage", choices=("verification", "publication"), default="verification",
                        help="publication includes all checks; verification omits publication-only checks")
    regression = commands.add_parser("test", help="Run a regression against reverted fix files, then the finished fix")
    regression.add_argument("case_id")
    regression.add_argument("--method", required=True)
    regression.add_argument("--command", dest="test_command", required=True)
    regression.add_argument("--expected-failure", required=True, help="Text identifying the expected failure in red output")
    regression.add_argument("--fix-path", action="append", default=[], help="Changed fix file to restore to base; defaults to plan fix_paths")
    regression.add_argument("--directory", default=".")
    regression.add_argument("--setup-command", help="Prepare dependencies in both tested sources before the regression")
    regression.add_argument("--timeout-seconds", type=int, default=600, help="Timeout for each setup/test command (default: 600)")
    environment = commands.add_parser("environment", help="Acquire or release shared test-environment ownership")
    environment.add_argument("action", choices=("acquire", "release"))
    environment.add_argument("case_id")
    environment.add_argument("--name", required=True)
    environment.add_argument("--actor", required=True)
    environment.add_argument("--token", help="Owning token required for release")

    worktree = commands.add_parser("worktree", help="Create a dedicated JJ workspace or Git worktree for a case")
    worktree.add_argument("case_id")
    worktree.add_argument("--base", help="Override the profile's integration branch for this case")
    worktree.add_argument("--branch")

    sync_revision = commands.add_parser(
        "sync-revision", help="Record the immutable case revision after committing the fix",
        description="Record the revision before green-test evidence, browser verification, or review. Requires a registered case workspace/bookmark or Git worktree/branch. Git must be clean; JJ snapshots edits and rejects conflicts. A rebase onto a newer base branch moves the review base forward. A content or base change makes approval stale.",
    )
    sync_revision.add_argument("case_id")

    runtime = commands.add_parser("runtime-identity", help="Inspect which worktree or image revision Compose containers serve")
    runtime.add_argument("case_id")
    runtime.add_argument("--compose-file", required=True, type=Path)
    runtime.add_argument("--service", required=True)
    runtime.add_argument("--container-path", required=True, help="Application path inside the service container")
    runtime.add_argument("--shared-environment")
    runtime.add_argument("--environment-token")
    runtime.add_argument("--actor")

    evidence = commands.add_parser("evidence", help="Record one evidence run")
    evidence.add_argument("case_id")
    evidence.add_argument("--kind", required=True)
    evidence.add_argument("--method", required=True)
    evidence.add_argument("--environment", choices=("local", "development", "test", "production"), required=True)
    evidence.add_argument("--command", dest="evidence_command")
    evidence.add_argument("--observed", required=True)
    evidence.add_argument("--proved", required=True)
    evidence.add_argument("--artifact", type=Path)
    evidence.add_argument("--revision")
    evidence.add_argument("--outcome", choices=("failed_as_expected", "passed", "failed", "blocked"))
    evidence.add_argument("--execution", choices=("executed", "reasoned", "unavailable"), default="executed")
    evidence.add_argument("--executed-revision")
    evidence.add_argument("--executed-directory")
    evidence.add_argument("--shared-environment")
    evidence.add_argument("--environment-token")

    baseline = commands.add_parser(
        "baseline", help="Record runtime reproduction or code/test support and owner decision",
        description="Record the case's reproduction decision. Record individual runs separately with evidence --kind baseline. Code/test confirmation without runtime reproduction requires an explicit owner decision.",
    )
    baseline.add_argument("case_id")
    baseline.add_argument("--outcome", choices=("runtime_reproduced", "code_test_confirmed", "unreproduced"), required=True)
    baseline.add_argument("--method", required=True)
    baseline.add_argument("--proved", required=True)
    baseline.add_argument("--owner-decision", choices=("proceed", "pause"))
    baseline.add_argument("--owner-actor")
    baseline.add_argument("--owner-reason")

    plan = commands.add_parser("plan", help="Save human preparation and verification requirements")
    plan.add_argument("case_id")
    plan.add_argument("--file", required=True, type=Path)
    plan.add_argument("--requirements-file", type=Path, help="JSON list of case-specific evidence requirements; required for the first plan")
    plan.add_argument("--alternatives-reason", help="Explain the selected verification methods")

    release = commands.add_parser("release-plan", help="Record production canary decision and monitoring")
    release.add_argument("case_id")
    release.add_argument("--production-canary", choices=("required", "not_required", "defer"), required=True)
    release.add_argument("--rationale", required=True)
    release.add_argument("--safe-procedure", default="")
    release.add_argument("--monitoring", required=True)

    approve = commands.add_parser("approve", help="Approve the current code and plan snapshot")
    approve.add_argument("case_id")
    approve.add_argument("--reviewer", required=True)
    approve.add_argument("--owner-instruction", required=True, help="Explicit case-owner instruction to approve the reviewed snapshot")
    approve.add_argument("--review-digest", required=True, help="Digest displayed in the reviewed Vigil case snapshot")

    transition = commands.add_parser("transition", help="Advance a case except through dedicated PR and development handoffs")
    transition.add_argument("case_id")
    transition.add_argument("status")
    transition.add_argument("--actor", required=True)
    transition.add_argument("--reason", required=True)

    deployment = commands.add_parser("deployment", help="Record a manually triggered development deployment")
    deployment.add_argument("case_id")
    deployment.add_argument("--workflow", required=True)
    deployment.add_argument("--run-id", required=True)
    deployment.add_argument("--expected-revision", required=True)
    deployment.add_argument("--observed-revision", required=True)
    deployment.add_argument("--environment", choices=("development",), default="development")
    deployment.add_argument("--actor", required=True)

    human = commands.add_parser("human-verification", help="Record the owner's development verification result")
    human.add_argument("case_id")
    human.add_argument("--actor", required=True)
    human.add_argument("--result", choices=("passed", "failed", "blocked"), required=True)
    human.add_argument("--observed-revision", required=True)
    human.add_argument("--notes", required=True)

    stagehand = commands.add_parser(
        "stagehand", help="Run a trusted local Stagehand script and register evidence",
        description="Attach to configured local Chrome and run a trusted script. Stagehand uses a separate model API key from the configured environment variable; a Claude Code subscription does not authenticate this SDK. Happy-path evidence requires passing steps and a screenshot.",
    )
    stagehand.add_argument("case_id")
    stagehand.add_argument("--script", required=True, type=Path)
    stagehand.add_argument("--revision", required=True)
    stagehand.add_argument("--environment", choices=("local", "development", "test", "production"), default="local")
    stagehand.add_argument("--purpose", choices=("happy-path", "bad-path", "other"), required=True)
    stagehand.add_argument("--production-decision", help="Case owner decision for production Stagehand use")
    stagehand.add_argument("--production-evidence-policy", choices=("retain-screenshots", "no-screenshots"), help="Case-specific production screenshot retention decision")
    stagehand.add_argument("--shared-environment")
    stagehand.add_argument("--environment-token")

    browser = commands.add_parser(
        "browser", help="Run a trusted browser UI rehearsal and retain evidence",
        description="Default browse driver uses the existing Claude Code or Codex session for reasoning, with an isolated local browser and no separate model API key. Install browse@0.11.1. Script must expose async def run(browser, output_dir); passed happy-path results require observed steps, a screenshot, and served_revision matching --revision. Stagehand is optional and requires its own configured provider key.",
    )
    browser.add_argument("case_id")
    browser.add_argument("--driver", choices=("browse", "stagehand"), default="browse", help="browse (default): local tools; stagehand: optional model SDK")
    browser.add_argument("--script", required=True, type=Path)
    browser.add_argument("--revision", required=True)
    browser.add_argument("--environment", choices=("local", "development", "test", "production"), default="local")
    browser.add_argument("--purpose", choices=("happy-path", "bad-path", "other"), required=True)
    browser.add_argument("--production-decision")
    browser.add_argument("--production-evidence-policy", choices=("retain-screenshots", "no-screenshots"))
    browser.add_argument("--shared-environment")
    browser.add_argument("--environment-token")

    draft = commands.add_parser(
        "prepare-pr", help="Generate draft PR content after review approval",
        description="Requires current approval of the clean case revision, evidence, and human verification plan. Generate the body, then map it to the repository's PR template before create-pr.",
    )
    draft.add_argument("case_id")
    draft.add_argument("--output", required=True, type=Path)
    draft.add_argument("--root-cause", required=True, help="Concrete root cause found in the reviewed diff")
    draft.add_argument("--fix-summary", required=True, help="Concrete code change and security boundary restored")
    draft.add_argument("--body-file", type=Path, help="Body authored using the profile's template and writing guidance")

    create_pr = commands.add_parser(
        "create-pr", help="Push approved branch and open a draft PR against the case base",
        description="Requires current approval, a template-mapped body, a final canary decision, origin remote, and authenticated gh. Push the exact approved Git/JJ revision against the captured case base. Retry after partial failure to reconcile the existing draft.",
    )
    create_pr.add_argument("case_id")
    create_pr.add_argument("--body-file", required=True, type=Path, help="Final body mapped to the repository PR template")
    create_pr.add_argument("--actor", required=True)
    create_pr.add_argument("--template-mapped", action="store_true", help="Assert final body maps required content to the actual repository PR template")
    create_pr.add_argument("--update", action="store_true", help="Publish a requested revision to the same draft PR")
    create_pr.add_argument("--owner-instruction", help="Explicit request to publish the requested PR update")
    create_pr.add_argument("--title", help="Title authored using the profile's repository conventions")
    deploy = commands.add_parser("deployment-run", help="Trigger the profile's development workflow after owner consent")
    deploy.add_argument("case_id")
    deploy.add_argument("--actor", required=True)
    deploy.add_argument("--owner-instruction", required=True, help="Explicit instruction approving this development deployment")
    deploy.add_argument("--input", action="append", default=[], help="Approved workflow input KEY=VALUE; repeatable")
    deploy.add_argument("--additional-tests-decision", choices=("run", "skip"), help="Owner's explicit choice about optional additional test suites")
    deploy.add_argument("--new-request", action="store_true", help="Explicitly request another deployment instead of reconciling a previous attempt")

    handoff = commands.add_parser(
        "development-handoff", help="Prepare manual GitHub Actions development deployment",
        description="Record the development handoff and print its expected revision and configured deployment_workflow. A human triggers the actual GitHub Actions workflow; this command does not deploy.",
    )
    handoff.add_argument("case_id")
    handoff.add_argument("--actor", required=True)


def _project(install_root: Path, key: str) -> tuple[Path, dict[str, object]]:
    path = resolve_engagement_path(install_root, key)
    scope = json.loads((path / "scope.json").read_text(encoding="utf-8"))
    if scope.get("engagement_type") != "remediation":
        raise SystemExit(f"{key} is not a remediation engagement")
    from .project_config import project_module

    try:
        config = project_module(install_root).load_engagement_project(path)
    except (OSError, ValueError) as exc:
        raise SystemExit(f"cannot read remediation PROJECT.md: {exc}") from exc
    return path, config


def _policy(config: dict[str, object]) -> dict:
    policy = config.get("remediation", {})
    if not isinstance(policy, dict):
        raise SystemExit("remediation policy must be a table in PROJECT.md")
    return policy


def _case_config(case: dict, live: dict) -> dict:
    recorded = case.get("review_policy")
    return recorded if isinstance(recorded, dict) and recorded.get("repository") else live


def _api(install_root: Path, eng_dir: Path, key: str, method: str, suffix: str, payload: dict | None = None) -> object:
    base = resolve_orchestrator_base_url(install_root, eng_dir).rstrip("/")
    url = f"{base}/engagements/{quote(key, safe='')}/remediation{suffix}"
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=30) as response:
            body = response.read()
            return json.loads(body) if body else {}
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"remediation API {method} {suffix}: HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise SystemExit(f"remediation API unavailable at {base}: {exc.reason}") from exc


def _case_path(case_id: str) -> str:
    if not case_id or not case_id.isascii() or not case_id.isdigit() or int(case_id) <= 0:
        raise SystemExit("case ID must be a positive integer")
    return f"/cases/{int(case_id)}"


def _case(install_root: Path, eng_dir: Path, key: str, case_id: str) -> dict:
    result = _api(install_root, eng_dir, key, "GET", _case_path(case_id))
    if not isinstance(result, dict):
        raise SystemExit("remediation API returned an invalid case")
    return result


def _case_summaries(install_root: Path, eng_dir: Path, key: str) -> list[dict]:
    result = _api(install_root, eng_dir, key, "GET", "/cases")
    if not isinstance(result, list) or any(
        not isinstance(case, dict) or type(case.get("id")) is not int or case["id"] <= 0 for case in result
    ):
        raise SystemExit("remediation API returned invalid case identities")
    if len({case["id"] for case in result}) != len(result):
        raise SystemExit("remediation API returned duplicate case identities")
    recent = sorted(result, key=lambda case: (case.get("updated_at") or case.get("created_at") or "", case["id"]), reverse=True)
    return sorted(recent, key=lambda case: case.get("status") == "closed")


def _resolve_case_id(install_root: Path, engagement: Path, key: str, selector: str) -> str:
    if selector.isascii() and selector.isdigit():
        return selector
    matches = [case for case in _case_summaries(install_root, engagement, key) if case.get("external_key") and (
        selector == f"{case.get('external_provider')}:{case['external_key']}" or selector == case["external_key"]
    )]
    if not matches:
        raise SystemExit(f"No case matches {selector!r}; use list to find its numeric ID")
    if len(matches) != 1:
        raise SystemExit(f"Case reference {selector!r} is ambiguous; use its numeric ID or provider:key")
    return str(matches[0]["id"])


def _case_reference(case: dict) -> str:
    if case.get("external_key"):
        return f"{case.get('external_provider')}:{case['external_key']}"
    if case.get("source_type") in {"manual", "report"} and case.get("source_key") == f"case-{case['id']}":
        return "Direct report"
    return f"{case.get('source_type', '')}:{case.get('source_key', '')}"


def _case_summary_line(case: dict) -> str:
    source = _case_reference(case)
    return (f"case_id={case['id']} status={json.dumps(case.get('status'))} "
            f"source={json.dumps(source, ensure_ascii=False)} title={json.dumps(case.get('title'), ensure_ascii=False)} "
            f"updated_at={json.dumps(case.get('updated_at'))}")


def _select_case(cases: list[dict]) -> dict:
    if not cases:
        raise SystemExit("No remediation cases in this project; use start to open a conversation and supply a report")
    if term.is_terminal(sys.stdin) and shutil.which("fzf"):
        lines = [f"{case['id']}\t#{case['id']}  {_case_status(case)}  {term.single_line(case.get('title'))}  ·  "
                 f"{term.single_line(_case_reference(case))}" for case in cases]
        details = {str(case["id"]): (
            f"Case #{case['id']}\n\n{term.single_line(case.get('title'))}\n\n"
            f"Status: {_case_status(case)}\n"
            f"Reference: {term.single_line(_case_reference(case))}\n"
            f"Updated: {term.single_line(case.get('updated_at') or case.get('created_at'))}\n"
        ) for case in cases}
        index = term.fuzzy_pick(lines, details, prompt="Case > ", action="join",
                                cancelled="Remediation case selection cancelled", invalid="Invalid remediation case selection")
        return cases[index]
    output = term.console(sys.stderr)
    output.print("Choose a remediation case", style="bold")
    output.print("Open first · newest first", style="dim")
    _case_table(output, cases, numbered=True)
    print("Row number> ", end="", file=sys.stderr, flush=True)
    try:
        choice = input().strip()
    except (EOFError, KeyboardInterrupt) as exc:
        raise SystemExit("Remediation case selection cancelled") from exc
    if not choice.isdigit() or not 1 <= int(choice) <= len(cases):
        raise SystemExit("Invalid remediation case selection")
    return cases[int(choice) - 1]


def _case_command(install_root: Path, key: str, command: str, case_id: int | None = None) -> str:
    argv = ["vigil", "--root", str(install_root), "remediation", "-k", key, command]
    if case_id is not None:
        argv.append(str(case_id))
    return shlex.join(argv)


def _case_status(case: dict) -> str:
    return term.single_line(case.get("status")).replace("_", " ").capitalize()


def _case_table(output, cases: list[dict], *, numbered: bool = False) -> None:
    from rich.table import Table
    from rich.text import Text

    table = Table(box=None, padding=(0, 1), expand=True, show_edge=False)
    if numbered:
        table.add_column("Row", no_wrap=True, style="dim")
    table.add_column("ID", no_wrap=True, style="cyan")
    table.add_column("Case", ratio=1, overflow="fold")
    for index, case in enumerate(cases, 1):
        detail = Text(term.single_line(case.get("title")))
        detail.append("\n" + _case_metadata(case), style="dim")
        fields = [Text(f"#{case['id']}"), detail]
        if numbered:
            fields.insert(0, Text(str(index)))
        table.add_row(*fields, end_section=True)
    output.print(table)


def _case_metadata(case: dict) -> str:
    status = _case_status(case)
    source = term.single_line(_case_reference(case))
    updated = term.single_line(case.get("updated_at") or case.get("created_at"))
    return f"{status} · {source} · Updated {updated}"


def _print_case_list(install_root: Path, key: str, cases: list[dict], *, as_json: bool) -> None:
    if as_json:
        records = [{**case, "case_id": case["id"], "engagement_key": key,
                    "join_command": _case_command(install_root, key, "join", case["id"])} for case in cases]
        print(json.dumps(records, indent=2, sort_keys=True))
        return
    if term.is_terminal(sys.stdout):
        output = term.console(sys.stdout)
        output.print(f"Remediation · {term.single_line(key)}", style="bold")
        output.print("Open first · newest first", style="dim")
        output.print()
        if cases:
            _case_table(output, cases)
        else:
            output.print("No remediation cases yet. Use start to supply a report.")
        output.print()
        output.print("start  New repository conversation", style="bold")
        output.print("join   Choose a case, or supply its numeric ID", style="bold")
        output.print("Use the same --root and -k options as this list command.", style="dim")
        output.print("Exact join commands: list --json", style="dim")
        return
    print(f"Remediation project: {json.dumps(key, ensure_ascii=False)}")
    print(f"start: {_case_command(install_root, key, 'start')}  (new repository conversation)")
    print(f"join: {_case_command(install_root, key, 'join')} <case_id>  (recorded case conversation)")
    if not cases:
        print("No remediation cases in this project. Use start to supply a report.")
    for case in cases:
        print(f"\n{_case_summary_line(case)}")
        print(f"  join: {_case_command(install_root, key, 'join', case['id'])}")


def _revision(path: Path) -> str:
    try:
        return _vcs().revision(path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"cannot read worktree revision: {error}") from None


def _worktree_status(path: Path) -> str:
    try:
        return _vcs().status(path)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"cannot read worktree status: {error}") from None


def _is_registered_worktree(repo: Path, path: Path) -> bool:
    return _vcs().registered(repo, path)


def inspect_compose_identity(
    worktree: Path,
    compose_file: Path,
    service: str,
    container_path: str,
    expected_revision: str | None = None,
) -> dict:
    """Read live Compose container identity without inferring from local cwd."""
    root = worktree.resolve()
    compose = compose_file.expanduser().resolve(strict=True)
    if not compose.is_file():
        raise SystemExit("--compose-file must be a file")
    if not container_path.startswith("/"):
        raise SystemExit("--container-path must be absolute")
    container_path = posixpath.normpath(container_path)
    head = _revision(root)
    dirty = bool(_worktree_status(root))
    listed = subprocess.run(
        ["docker", "compose", "-f", str(compose), "ps", "-q", service],
        cwd=root, text=True, capture_output=True,
    )
    if listed.returncode:
        raise SystemExit(listed.stderr.strip() or "Docker Compose service inspection failed")
    containers = []
    for container_id in listed.stdout.splitlines():
        if not container_id.strip():
            continue
        inspected = subprocess.run(["docker", "inspect", container_id.strip()], text=True, capture_output=True)
        if inspected.returncode:
            raise SystemExit(inspected.stderr.strip() or f"docker inspect failed for {container_id}")
        records = json.loads(inspected.stdout)
        if not isinstance(records, list) or len(records) != 1:
            raise SystemExit(f"docker inspect returned unexpected data for {container_id}")
        record = records[0]
        mounts = record.get("Mounts") or []
        labels = (record.get("Config") or {}).get("Labels") or {}
        image_revision = str(labels.get("org.opencontainers.image.revision") or "")
        covering = []
        descendant_overlay = False
        for item in mounts:
            if not isinstance(item, dict):
                continue
            destination = str(item.get("Destination") or "")
            if not destination.startswith("/"):
                continue
            destination = posixpath.normpath(destination)
            if destination.startswith(container_path.rstrip("/") + "/"):
                source = Path(str(item.get("Source") or "/nonexistent")).resolve()
                if item.get("Type") != "bind" or not source.is_relative_to(root):
                    descendant_overlay = True
            if container_path == destination or container_path.startswith(destination.rstrip("/") + "/"):
                covering.append((len(destination.split("/")), destination, item))
        deepest = max((row[0] for row in covering), default=0)
        competing = [row for row in covering if row[0] == deepest]
        conflicting_mounts = len(competing) > 1
        effective = competing[0] if competing else None
        mounted = False
        if effective is not None:
            _, destination, mount = effective
            source = Path(str(mount.get("Source") or "/nonexistent")).resolve()
            suffix = container_path.removeprefix(destination).lstrip("/")
            served_path = (source / suffix).resolve()
            mounted = (
                mount.get("Type") == "bind"
                and source.is_relative_to(root)
                and served_path.is_relative_to(root)
                and served_path.exists()
            )
        match = (mounted if effective is not None else image_revision == head) and not dirty and not descendant_overlay and not conflicting_mounts
        containers.append({
            "container_id": str(record.get("Id") or container_id),
            "image_id": str(record.get("Image") or ""),
            "image_revision_label": image_revision or None,
            "mounts": mounts,
            "effective_mount": effective[2] if effective is not None else None,
            "descendant_overlay": descendant_overlay,
            "conflicting_mounts": conflicting_mounts,
            "served_source": "case_worktree_bind_mount" if mounted and match else "matching_image_revision_label" if effective is None and image_revision == head and match else "unproven",
            "matched": match,
        })
    revision_match = expected_revision is None or expected_revision == head
    return {
        "status": "matched" if containers and all(row["matched"] for row in containers) and revision_match and not dirty else "unproven",
        "worktree_dirty": dirty,
        "worktree": str(root),
        "worktree_revision": head,
        "recorded_case_revision": expected_revision,
        "compose_file": str(compose),
        "service": service,
        "container_path": container_path,
        "containers": containers,
    }


def _require_clean_worktree(path: Path) -> None:
    if _worktree_status(path):
        raise SystemExit("case worktree has uncommitted or untracked files; commit reviewed code before approval or PR creation")


def _require_case_worktree(case: dict, repo: Path) -> Path:
    path = Path(str(case.get("worktree_path") or ""))
    if not path.is_dir():
        raise SystemExit("case worktree is missing")
    if not _is_registered_worktree(repo, path):
        raise SystemExit("case worktree is not registered to the configured repository")
    branch = str(case.get("worktree_branch") or "")
    if not branch:
        raise SystemExit("case has no recorded worktree branch; register the case worktree before continuing")
    if not _vcs().branch_matches(path, branch):
        raise SystemExit(f"case worktree branch differs from recorded branch {branch}; restore it before continuing")
    return path


def _approved_current(case: dict, repo: Path) -> Path:
    if not case.get("approval_current"):
        raise SystemExit("case has no current approval for its code and verification plan")
    path = _require_case_worktree(case, repo)
    recorded = str(case.get("worktree_revision") or "")
    actual = _revision(path)
    if not recorded or recorded != actual:
        raise SystemExit(f"worktree revision changed: reviewed {recorded or '(none)'}, current {actual}")
    _require_clean_worktree(path)
    return path


def _approved_digest(case: dict) -> str:
    approvals = case.get("approvals")
    if not case.get("approval_current") or not isinstance(approvals, list) or not approvals:
        raise SystemExit("case has no current reviewed approval digest")
    digest = str(approvals[-1].get("review_digest") or "")
    if not digest:
        raise SystemExit("latest approval is missing its review digest")
    return digest


def _github_repository(worktree: Path) -> str:
    adapter = _vcs()
    try:
        return adapter.github_repository(worktree)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"cannot resolve GitHub repository from the publishing origin: {error}") from None


def _existing_draft_pr(worktree: Path, branch: str, body: str, *, repository: str | None = None,
                       base_branch: str = "main", allow_update: bool = False) -> str | None:
    repository = repository or _github_repository(worktree)
    listed = subprocess.run(
        ["gh", "pr", "list", "--head", branch, "--base", base_branch, "--state", "all",
         "--json", "url,state,isDraft,headRefName,baseRefName,headRefOid,body", *(["--repo", repository] if repository else [])],
        cwd=worktree, text=True, capture_output=True,
    )
    if listed.returncode:
        raise SystemExit(listed.stderr.strip() or "could not check existing pull requests")
    rows = json.loads(listed.stdout)
    if not isinstance(rows, list):
        raise SystemExit("GitHub returned an invalid pull request listing")
    matches = [row for row in rows if isinstance(row, dict) and row.get("headRefName") == branch and row.get("baseRefName") == base_branch]
    if len(matches) > 1:
        raise SystemExit("multiple pull requests already use this branch; inspect manually")
    if not matches:
        return None
    row = matches[0]
    if row.get("state") != "OPEN" or row.get("isDraft") is not True or not row.get("url"):
        raise SystemExit("an existing pull request for this branch is not an open draft")
    if not allow_update and row.get("headRefOid") != _revision(worktree):
        raise SystemExit("draft PR head revision differs from the approved case worktree; inspect the remote branch before retrying")
    if not allow_update and row.get("body") != body:
        raise SystemExit("draft PR body differs from the reviewed PR content; inspect the draft before retrying")
    return str(row["url"])


def _reviewed_evidence_lines(case: dict) -> list[str]:
    approvals = case.get("approvals") or []
    cutoff = int(approvals[-1].get("evidence_cutoff_id") or 0) if approvals else 0
    lines = []
    for row in case.get("evidence") or []:
        if not isinstance(row, dict) or int(row.get("id") or 0) > cutoff:
            continue
        lines.append(
            f"- {row.get('kind', 'evidence')} via {row.get('method', 'unknown')} "
            f"[environment: {row.get('environment') or 'unknown (historical)'}] "
            f"at {row.get('revision') or 'revision not recorded'}: "
            f"observed {row.get('observed', '')}; proved {row.get('proved', '')}. "
            f"Artifact: {row.get('artifact_path') or 'none'}"
        )
    return lines


def _approved_verification_evidence(case: dict) -> list[dict]:
    approvals = case.get("approvals") or []
    cutoff = int(approvals[-1].get("evidence_cutoff_id") or 0) if approvals else 0
    evidence = [row for row in case.get("evidence") or [] if isinstance(row, dict) and int(row.get("id") or 0) <= cutoff]
    plan = case.get("verification_requirements")
    if not isinstance(plan, dict) or not plan.get("requirements"):
        raise SystemExit("PR content requires explicit verification requirements")
    matches = case.get("verification_matches")
    if not isinstance(matches, list):
        raise SystemExit("backend verification matches are missing; refresh the case using the current backend")
    approved_ids = {row["id"] for row in evidence}
    selected_ids = set()
    for index in range(len(plan["requirements"])):
        match = next((item for item in matches if item.get("requirement_index") == index), None)
        matched_ids = approved_ids.intersection(match.get("evidence_ids", [])) if match else set()
        if not matched_ids:
            raise SystemExit("reviewed case-specific verification evidence is missing")
        selected_ids.update(matched_ids)
    return [row for row in evidence if row["id"] in selected_ids]


def _required_reviewed_evidence_lines(case: dict) -> list[str]:
    return _reviewed_evidence_lines({**case, "evidence": _approved_verification_evidence(case)})


def _register_pr_body(
    install_root: Path, eng_dir: Path, key: str, case_id: str,
    case: dict, body: str, stage: str,
) -> Path:
    digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
    path = eng_dir / "remediation" / "cases" / case_id / "pr" / f"{stage}-{digest[:16]}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text(encoding="utf-8") != body:
        raise SystemExit("existing PR body artifact differs from its content hash")
    path.write_text(body, encoding="utf-8")
    relative = str(path.relative_to(eng_dir))
    if not any(row.get("artifact_path") == relative for row in case.get("evidence") or [] if isinstance(row, dict)):
        _api(install_root, eng_dir, key, "POST", _case_path(case_id) + "/evidence", {
            "kind": "pr_body", "method": stage, "command": "",
            "environment": "not_applicable",
            "observed": f"{stage} PR body saved for review",
            "proved": "Exact PR text is retained with this case",
            "artifact_path": relative, "revision": case.get("worktree_revision"),
        })
    return path


def validate_stagehand_config(config: dict[str, object], environ: dict[str, str]) -> tuple[str, str, str]:
    url = str(config.get("browser_cdp_url") or "")
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"localhost", "127.0.0.1", "::1"} or not parsed.port:
        raise SystemExit("Stagehand requires a loopback Chrome CDP URL with an explicit port")
    model = config.get("stagehand")
    if not isinstance(model, dict):
        raise SystemExit("Stagehand requires an approved model/account configuration")
    name = str(model.get("model") or "")
    account = str(model.get("approved_account") or "")
    env_name = str(model.get("api_key_env") or "")
    if not name or not account or not env_name or not env_name.isidentifier():
        raise SystemExit("Stagehand requires an approved model/account and provider key variable")
    key = environ.get(env_name, "")
    if not key:
        raise SystemExit(f"Stagehand approved provider key is missing from {env_name}")
    return url, name, key


def validate_stagehand_result(result: dict, output: Path, purpose: str) -> None:
    if purpose != "happy-path":
        return
    if result.get("status") != "passed":
        raise SystemExit("happy-path browser result requires explicit passed status")
    if not str(result.get("observed") or "").strip() or not str(result.get("proved") or "").strip():
        raise SystemExit("happy-path browser result requires observed and proved claims")
    steps = result.get("steps")
    if not isinstance(steps, list) or not steps or not all(
        isinstance(step, dict) and str(step.get("action") or "").strip() and str(step.get("observation") or "").strip()
        for step in steps
    ):
        raise SystemExit("happy-path browser result requires structured observed UI steps (action and observation)")
    screenshots = [path for path in output.iterdir() if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg"}]
    if not screenshots or not any(_valid_screenshot(path) for path in screenshots):
        raise SystemExit("happy-path browser result requires at least one nonempty valid screenshot")


def _valid_screenshot(path: Path) -> bool:
    data = path.read_bytes()
    if path.suffix.lower() == ".png":
        return (
            len(data) > 32
            and data.startswith(b"\x89PNG\r\n\x1a\n")
            and data[12:16] == b"IHDR"
            and int.from_bytes(data[16:20], "big") > 0
            and int.from_bytes(data[20:24], "big") > 0
            and data[-8:-4] == b"IEND"
        )
    return len(data) > 4 and data.startswith(b"\xff\xd8") and data.endswith(b"\xff\xd9")


def validate_production_stagehand_policy(args: argparse.Namespace, output: Path | None = None) -> None:
    if args.environment != "production":
        return
    if not args.production_decision or not args.production_decision.strip():
        raise SystemExit("production browser requires a case-specific human decision")
    if not args.production_evidence_policy:
        raise SystemExit("production browser requires a case-specific evidence policy")
    if args.purpose == "happy-path" and args.production_evidence_policy == "no-screenshots":
        raise SystemExit("happy-path evidence requires a screenshot; choose retain-screenshots or run locally")
    if output is not None and args.production_evidence_policy == "no-screenshots" and any(
        path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg"} for path in output.iterdir()
    ):
        raise SystemExit("production evidence policy forbids screenshots; unexpected files are retained for human review")


async def _execute_stagehand(script: Path, output: Path, config: dict[str, object]) -> dict:
    cdp, model, key = validate_stagehand_config(config, dict(os.environ))
    try:
        from stagehand import Stagehand, local_browser  # type: ignore[import-not-found]
    except ImportError as exc:
        raise SystemExit("Install the Stagehand v4 Python SDK on the host before this command") from exc
    spec = importlib.util.spec_from_file_location("vigil_remediation_stagehand_script", script)
    if spec is None or spec.loader is None:
        raise SystemExit(f"cannot load Stagehand script: {script}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    run = getattr(module, "run", None)
    if run is None or not asyncio.iscoroutinefunction(run):
        raise SystemExit("Stagehand script must expose async def run(stagehand, output_dir)")
    browser = await local_browser.connect(cdp_url=cdp)
    stagehand = await Stagehand.create(browser=browser, model=model, model_api_key=key)
    try:
        result = await run(stagehand, output)
    finally:
        await stagehand.close()
    if not isinstance(result, dict):
        raise SystemExit("Stagehand script must return a JSON object")
    return result


def _run_stagehand(install_root: Path, eng_dir: Path, key: str, args: argparse.Namespace, config: dict[str, object]) -> object:
    driver = getattr(args, "driver", "stagehand")
    case_id = args.case_id
    _case_path(case_id)
    case = _case(install_root, eng_dir, key, case_id)
    config = _case_config(case, config)
    if driver == "stagehand":
        validate_stagehand_config(config, dict(os.environ))
    validate_production_stagehand_policy(args)
    if case.get("status") == "closed":
        raise SystemExit("closed remediation cases cannot accept browser evidence")
    shared_environment = getattr(args, "shared_environment", None) or _policy(config).get("shared_environment")
    lease = None
    if shared_environment:
        leases = [row for row in case.get("environment_leases", [])
                  if row.get("environment") == shared_environment and row.get("released_at") is None
                  and row.get("revision") == args.revision and row.get("observed_revision") == args.revision]
        if len(leases) != 1:
            raise SystemExit("acquire the shared environment and confirm its served case revision before browser verification")
        lease = leases[0]
        if getattr(args, "environment_token", None) and args.environment_token != lease["token"]:
            raise SystemExit("browser evidence token differs from the active case environment lease")
    script = args.script.expanduser().resolve(strict=True)
    if not script.is_file() or script.suffix != ".py":
        raise SystemExit("--script must name a Python file")
    output = eng_dir / "remediation" / "cases" / case_id / driver / uuid.uuid4().hex
    output.mkdir(parents=True)
    stored_script = output / "script.py"
    shutil.copy2(script, stored_script)
    result: dict
    try:
        execute = _execute_browse if driver == "browse" else _execute_stagehand
        result = asyncio.run(execute(stored_script, output, config))
        if driver == "browse" and result.get("served_revision") != args.revision:
            raise SystemExit("browse result must identify the served revision matching --revision")
        validate_stagehand_result(result, output, args.purpose)
        validate_production_stagehand_policy(args, output)
        result["driver"] = driver
        result["purpose"] = args.purpose
        result["environment"] = args.environment
        if lease:
            result.update(shared_environment=shared_environment, environment_token=lease["token"])
        if args.production_decision:
            result["production_decision"] = args.production_decision
            result["production_evidence_policy"] = args.production_evidence_policy
    except BaseException as exc:
        result = {"status": "failed", "error": str(exc), "purpose": args.purpose, "environment": args.environment, "driver": driver}
        if args.production_decision:
            result["production_decision"] = args.production_decision
            result["production_evidence_policy"] = args.production_evidence_policy
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        _register_stagehand_files(install_root, eng_dir, key, case_id, output, args.revision, result)
        raise
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return _register_stagehand_files(install_root, eng_dir, key, case_id, output, args.revision, result)


def _register_stagehand_files(install_root: Path, eng_dir: Path, key: str, case_id: str, output: Path, revision: str, result: dict) -> list[object]:
    registered = []
    driver = str(result.get("driver") or "stagehand")
    for file in sorted(output.iterdir()):
        if not file.is_file():
            continue
        kind = "screenshot" if file.suffix.lower() in {".png", ".jpg", ".jpeg"} else driver
        registered.append(_api(install_root, eng_dir, key, "POST", _case_path(case_id) + "/evidence", {
            "kind": kind,
            "method": driver,
            "environment": str(result["environment"]),
            "command": "trusted script run via local browse CLI" if driver == "browse" else "trusted script run via local Chrome CDP",
            "observed": str(result.get("observed") or result.get("status") or ""),
            "proved": str(result.get("proved") or "See recorded run result; no broader claim"),
            "artifact_path": str(file.relative_to(eng_dir)),
            "revision": revision,
            "execution": "executed", "executed_revision": revision,
            "outcome": "passed" if result.get("status") == "passed" else "failed",
            "shared_environment": result.get("shared_environment"), "environment_token": result.get("environment_token"),
        }))
    return registered


def _register_intake_files(
    install_root: Path, eng_dir: Path, key: str, result: dict,
    source_file: Path, attachments: list[Path],
) -> None:
    case_id = str(result["id"])
    intake_dir = eng_dir / "remediation" / "cases" / case_id / "source"
    for directory in (intake_dir, *intake_dir.parents):
        if directory == eng_dir:
            break
        if directory.is_symlink():
            raise SystemExit(f"case intake directory is a symlink: {directory}")
    intake_dir.mkdir(parents=True, exist_ok=True)
    files = [source_file, *attachments]
    existing_evidence = {
        str(row.get("artifact_path")) for row in result.get("evidence", []) if isinstance(row, dict)
    }
    for index, source in enumerate(files):
        stored = intake_dir / ("snapshot.json" if index == 0 else f"{index}-{source.name}")
        if stored.is_symlink():
            raise SystemExit(f"case intake artifact is a symlink: {stored}")
        if stored.exists() and stored.read_bytes() != source.read_bytes():
            raise SystemExit(f"resume file differs from existing case artifact: {stored}")
        shutil.copy2(source, stored)
        item = str(stored.relative_to(eng_dir))
        if item in existing_evidence:
            continue
        _api(install_root, eng_dir, key, "POST", _case_path(case_id) + "/evidence", {
            "kind": "report_snapshot" if index == 0 else "source_attachment",
            "method": "import", "command": "",
            "environment": "not_applicable",
            "observed": "Imported source material retained without interpretation",
            "proved": "This file is the issue or report source snapshot, not a verified behavior",
            "artifact_path": item, "revision": None,
        })


def _remediation_projects(install_root: Path) -> list[EngagementRow]:
    candidates = []
    for row in list_engagements(install_root):
        try:
            if json.loads((row.path / "scope.json").read_text(encoding="utf-8")).get("engagement_type") == "remediation":
                candidates.append(row)
        except (OSError, ValueError):
            continue
    return candidates


def _select_project(projects: list[EngagementRow]) -> str:
    from .engagements import _select_engagement

    if not projects:
        raise SystemExit("No remediation projects found; create one with vigil engagement create --type remediation")
    return _select_engagement(projects).key


def _engagement_key(args: argparse.Namespace, install_root: Path) -> str:
    if args.engagement_key:
        return args.engagement_key
    if os.environ.get("ENGAGEMENT_KEY"):
        return os.environ["ENGAGEMENT_KEY"]
    candidates = _remediation_projects(install_root)
    if len(candidates) == 1:
        return candidates[0].key
    if args.remediation_command == "start" and sys.stdin.isatty():
        return _select_project(candidates)
    raise SystemExit("select a remediation engagement with -k; create one first if none exists")


def _start_engagement_key(args: argparse.Namespace, install_root: Path) -> str:
    """Start always makes the project choice explicit; other verbs retain their resolver."""
    if args.engagement_key:
        return args.engagement_key
    if not sys.stdin.isatty():
        raise SystemExit("Noninteractive remediation start requires an explicit --engagement-key; use vigil remediation -k KEY start")
    rows = [row for row in list_engagements(install_root) if row.engagement_type == "remediation"]
    rows.sort(key=lambda row: row.key)
    rows.sort(key=lambda row: row.last_activity_at, reverse=True)
    choices = [
        f"{row.key} · {row.status} · {row.target} · recent {row.last_activity_at or 'unknown'}"
        + ("; some activity unavailable" if row.activity_incomplete else "")
        for row in rows
    ]
    recovering = bool(getattr(args, "session_id", None))
    if not recovering:
        choices.append("Create new remediation engagement")
    if not choices:
        raise SystemExit("No remediation engagements are available for recovery; pass -k with the original engagement key")
    details = [f"{term.single_line(choice)}\n\nWorkspace: {term.single_line(row.path)}" for row, choice in zip(rows, choices)]
    if not recovering:
        details.append("Create a remediation engagement using the interactive creation questions.")
    selected = prompt_choice("Select remediation engagement", choices[0], choices, searchable=True, details=details)
    if not recovering and selected == choices[-1]:
        parser = getattr(args, "remediation_create_parser", None)
        create = getattr(args, "remediation_create", None)
        if parser is None or create is None:
            raise SystemExit("Create the project with vigil engagement create --type remediation, then start with -k KEY")
        created = create(parser.parse_args(["--type", "remediation"]), install_root)
        if created is None:
            raise SystemExit("remediation creation did not return a workspace")
        return created.key
    return rows[choices.index(selected)].key


def _render_case_handoff(engagement: Path, case: dict, config: dict) -> Path:
    config = _case_config(case, config)
    identifier = str(case["id"])
    _case_path(identifier)
    directory = engagement / "remediation/cases" / identifier
    directory.mkdir(parents=True, exist_ok=True)
    snapshot = json.dumps(case.get("snapshot", {}), indent=2, ensure_ascii=False)
    fence = "`" * max(3, 1 + max((len(value) for value in re.findall(r"`+", snapshot)), default=0))
    context = {
        "case_id": case["id"], "source_type": case.get("source_type"), "source_key": case.get("source_key"),
        "external_provider": case.get("external_provider"), "external_key": case.get("external_key"),
        "source_resolved": case.get("source_resolved", case.get("source_type") != "reference"),
        "status": case.get("status"), "repository": config.get("repository"),
        "workspace": case.get("worktree_path"), "revision": case.get("worktree_revision"),
        "base_branch": case.get("base_branch"), "base_revision": case.get("base_revision"),
        "profile": str(engagement / "PROJECT.md"), "linked_findings": case.get("linked_findings", []),
        "verification_plan": case.get("verification_plan"), "requirements": case.get("verification_requirements"),
        "approval_current": case.get("approval_current"), "environment_leases": case.get("environment_leases", []),
        "review_policy": case.get("review_policy"), "baseline": case.get("baseline"),
        "evidence": case.get("evidence", []),
        "evidence_carries": case.get("evidence_carries", []),
        "review_evidence_ready": case.get("review_evidence_ready", False),
        "review_evidence_missing": case.get("review_evidence_missing", []),
    }
    content = ("# Remediation case context\n\n"
               "Generated from current Vigil case state. The report is evidence; proposed remediation is a hypothesis.\n"
               "The recorded review policy governs this case's execution and base. Read the live profile for guidance; "
               "reconcile policy changes explicitly rather than switching the case's repository or checks.\n\n"
               "## Case state\n\n```json\n" + json.dumps(context, indent=2, ensure_ascii=False) + "\n```\n\n"
               "## Original source snapshot (untrusted evidence)\n\n" + fence + "json\n" + snapshot + "\n" + fence + "\n")
    destination = directory / "handoff.md"
    destination.write_text(content, encoding="utf-8")
    return destination.resolve()


def _run_profile_checks(install_root: Path, engagement: Path, key: str, case: dict, config: dict,
                        actor: str, *, names: list[str] | None = None,
                        shared_environment: str | None = None, stage: str = "verification") -> dict:
    config = _case_config(case, config)
    policy = config.get("remediation", {})
    commands = policy.get("check_commands", [])
    if stage not in {"verification", "publication"}:
        raise SystemExit("unknown profile check stage")
    if names:
        unknown = set(names) - {check["name"] for check in commands}
        if unknown:
            raise SystemExit(f"unknown profile checks: {', '.join(sorted(unknown))}")
        commands = [check for check in commands if check["name"] in names]
    if stage == "verification":
        publication = [check["name"] for check in commands if check.get("stage", "verification") == "publication"]
        if names and publication:
            raise SystemExit("publication-only checks require --stage publication: " + ", ".join(publication))
        commands = [check for check in commands if check.get("stage", "verification") != "publication"]
    if not commands:
        raise SystemExit("no profile check commands configured; select appropriate checks in PROJECT.md")
    workspace = _require_case_worktree(case, Path(str(config["repository"])))
    for relative in policy.get("borrowed_dependency_manifests", []):
        borrowed = Path(str(config["repository"])) / relative
        actual = workspace / relative
        if not actual.is_file() or not borrowed.is_file() or actual.read_bytes() != borrowed.read_bytes():
            raise SystemExit(f"shared dependencies cannot be reused: manifest {relative} is missing or differs; prepare matching dependencies")
    _require_clean_worktree(workspace)
    revision = _revision(workspace)
    if revision != case.get("worktree_revision"):
        raise SystemExit("sync the case revision before running profile checks")
    case_id = str(case["id"])
    endpoint = _case_path(case_id)
    shared_environment = shared_environment or policy.get("shared_environment")
    lease: dict | None = None
    if shared_environment:
        acquired = _api(install_root, engagement, key, "POST", "/environments/acquire", {
            "environment": shared_environment, "case_id": int(case_id), "revision": revision, "actor": actor,
        })
        if not isinstance(acquired, dict) or not acquired.get("token"):
            raise SystemExit("shared environment acquisition returned no owning token")
        lease = acquired
    results = []
    try:
        for check in commands:
            cwd = (workspace / check.get("directory", ".")).resolve()
            if not cwd.is_dir() or not cwd.is_relative_to(workspace.resolve()):
                raise SystemExit(f"check directory is missing or outside the case workspace: {cwd}")
            environment = {**os.environ, "VIGIL_CASE_WORKTREE": str(workspace),
                           "VIGIL_REPOSITORY": str(config["repository"]), "VIGIL_CASE_REVISION": revision,
                           "VIGIL_CASE_BASE_REVISION": str(case.get("base_revision") or "")}
            run = subprocess.run(["/bin/sh", "-c", check["command"]], cwd=cwd, env=environment,
                                 capture_output=True, text=True)
            after = _revision(workspace)
            changed = after != revision or bool(_worktree_status(workspace))
            passed = run.returncode == 0 and not changed
            output = engagement / "remediation/cases" / case_id / "checks" / f"{uuid.uuid4().hex}.txt"
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                f"Check: {check['name']}\nCommand: {check['command']}\nDirectory: {cwd}\n"
                f"Revision: {revision}\nExit code: {run.returncode}\nSource changed: {changed}\n\n"
                f"stdout:\n{run.stdout}\nstderr:\n{run.stderr}", encoding="utf-8",
            )
            evidence = {"kind": "profile-check", "method": check["name"], "environment": "local",
                        "command": check["command"], "observed": f"exit {run.returncode}; source changed: {changed}",
                        "proved": "Configured check passed against the recorded source" if passed else "Check did not pass at the recorded source",
                        "outcome": "passed" if passed else "failed", "revision": revision,
                        "execution": "executed", "executed_revision": revision, "executed_directory": str(cwd),
                        "artifact_path": str(output.relative_to(engagement))}
            if lease:
                evidence.update(shared_environment=shared_environment, environment_token=lease["token"])
            _api(install_root, engagement, key, "POST", endpoint + "/evidence", evidence)
            results.append({"name": check["name"], "outcome": evidence["outcome"], "artifact": str(output)})
            if not passed:
                raise SystemExit(f"check {check['name']} failed or changed source; inspect {output}, commit/sync changes, and rerun")
    finally:
        if lease and lease.get("created", True):
            _api(install_root, engagement, key, "POST", "/environments/release", {
                "environment": shared_environment, "case_id": int(case_id), "token": lease["token"], "actor": actor,
            })
    return {"revision": revision, "checks": results}


def _validate_pr_template(body: str, config: dict) -> None:
    template_path = config.get("remediation", {}).get("pr_template")
    if not template_path:
        return
    template = Path(template_path).read_text(encoding="utf-8")
    preserved = [*re.findall(r"^#{1,6}\s+.+$", template, re.MULTILINE),
                 *re.findall(r"<!--.*?-->", template, re.DOTALL)]
    if any(section not in body for section in preserved):
        raise SystemExit("PR body must preserve the selected template's headings and comments")


def _run_deployment(install_root: Path, engagement: Path, key: str, args: argparse.Namespace, config: dict) -> dict:
    _case_path(args.case_id)
    directory = engagement / "remediation/cases" / args.case_id / "deployments"
    directory.mkdir(parents=True, exist_ok=True)
    # The accepted marker prevents retry dispatch; the lock prevents two callers
    # from both passing the marker check before either has recorded acceptance.
    with (directory / ".dispatch.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        return _run_locked_deployment(install_root, engagement, key, args, config)


def _run_locked_deployment(install_root: Path, engagement: Path, key: str, args: argparse.Namespace, config: dict) -> dict:
    instruction = args.owner_instruction.strip()
    if not instruction:
        raise SystemExit("development deployment requires the owner's explicit instruction")
    case = _case(install_root, engagement, key, args.case_id)
    config = _case_config(case, config)
    workflow = str(config.get("deployment_workflow") or "")
    if not workflow:
        raise SystemExit("select the development workflow through PROJECT.md before deployment")
    policy = config.get("remediation", {})
    inputs = dict(policy.get("deployment_inputs", {}))
    for value in args.input:
        name, separator, setting = value.partition("=")
        if not separator or not name.strip():
            raise SystemExit("workflow inputs must use KEY=VALUE")
        inputs[name] = setting
    requested_tests = [name for name in policy.get("deployment_test_inputs", [])
                       if str(inputs.get(name, "false")).casefold() not in {"false", "", "0", "none"}]
    if requested_tests and args.additional_tests_decision != "run":
        if args.additional_tests_decision == "skip":
            raise SystemExit("the owner chose skip; disable the optional test suite inputs before dispatch")
        raise SystemExit("ask the owner about the optional test suites and pass --additional-tests-decision run")
    workspace = _approved_current(case, Path(str(config["repository"])))
    if case.get("status") not in {"pr_draft", "development"}:
        raise SystemExit("publish the reviewed draft before development deployment")
    branch = str(case["worktree_branch"])
    revision = str(case["worktree_revision"])
    if _vcs().origin_revision(workspace, branch) != revision:
        raise SystemExit("the remote branch differs from the approved case revision; do not deploy it")
    repository = _github_repository(workspace)
    repo_args = ["--repo", repository] if repository else []
    listing = ["gh", "run", "list", "--workflow", workflow, "--branch", branch,
               "--limit", "30", "--json", "databaseId,headSha,event", *repo_args]
    command = ["gh", "workflow", "run", workflow, "--ref", branch, *repo_args]
    for name, value in inputs.items():
        command.extend(["--field", f"{name}={str(value).lower() if isinstance(value, bool) else value}"])
    request = {"workflow": workflow, "branch": branch, "expected_revision": revision, "run_id": None,
               "owner_instruction": instruction, "additional_tests_decision": args.additional_tests_decision,
               "inputs": inputs,
               "verification": "pending; observe the deployed revision before recording deployment evidence"}
    identity = hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()
    directory = engagement / "remediation/cases" / str(case["id"]) / "deployments"
    directory.mkdir(parents=True, exist_ok=True)
    marker = directory / f"request-{identity}.json"
    if getattr(args, "new_request", False):
        marker = directory / f"request-{identity}-{uuid.uuid4().hex}.json"
    if marker.exists():
        request = json.loads(marker.read_text(encoding="utf-8"))
        if request.get("request_state") != "accepted":
            raise SystemExit(f"previous deployment may already have been dispatched; reconcile {marker} before a --new-request")
    else:
        before = subprocess.run(listing, cwd=workspace, capture_output=True, text=True, check=True)
        request.update(previous_run_ids=[row["databaseId"] for row in json.loads(before.stdout)], request_state="dispatching")
        marker.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
        triggered = subprocess.run(command, cwd=workspace, capture_output=True, text=True)
        request["trigger_output"] = triggered.stdout
        if triggered.returncode:
            request.update(request_state="unconfirmed", trigger_error=triggered.stderr)
            marker.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
            raise SystemExit(f"workflow dispatch was not confirmed; reconcile {marker}: {triggered.stderr.strip()}")
        request["request_state"] = "accepted"
        marker.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    previous = set(request.get("previous_run_ids", []))
    try:
        after = subprocess.run(listing, cwd=workspace, capture_output=True, text=True, check=True)
        matches = [row for row in json.loads(after.stdout) if row["databaseId"] not in previous
                   and row.get("headSha") == revision and row.get("event") == "workflow_dispatch"]
        request["run_id"] = str(matches[0]["databaseId"]) if len(matches) == 1 else None
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        request["lookup_error"] = str(exc)
    marker.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    artifact = directory / f"accepted-{hashlib.sha256(json.dumps(request, sort_keys=True).encode()).hexdigest()}.json"
    artifact.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    if not any(row.get("artifact_path") == str(artifact.relative_to(engagement)) for row in case.get("evidence", [])):
        _api(install_root, engagement, key, "POST", _case_path(str(case["id"])) + "/evidence", {
            "kind": "deployment_request", "method": "github-actions", "environment": "development",
            "command": json.dumps(command), "observed": request.get("trigger_output", "").strip() or "Workflow dispatch accepted",
            "proved": "Deployment was requested; served revision is not yet verified",
            "revision": revision, "artifact_path": str(artifact.relative_to(engagement)),
        })
    if case.get("status") == "pr_draft":
        _api(install_root, engagement, key, "POST", _case_path(str(case["id"])) + "/transition", {
            "status": "development", "actor": args.actor, "reason": f"Owner-approved development workflow request: {workflow}",
        })
    return request


def _record_publication(install_root: Path, engagement: Path, key: str, case: dict, url: str, body: str) -> None:
    publication = {"url": url, "revision": case["worktree_revision"], "branch": case["worktree_branch"],
                   "base_branch": case.get("base_branch") or "main", "review_digest": _approved_digest(case),
                   "body_sha256": hashlib.sha256(body.encode()).hexdigest()}
    encoded = json.dumps(publication, indent=2, sort_keys=True) + "\n"
    digest = hashlib.sha256(encoded.encode()).hexdigest()
    path = engagement / "remediation/cases" / str(case["id"]) / "pr" / f"publication-{digest}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(encoded, encoding="utf-8")
    relative = str(path.relative_to(engagement))
    if not any(row.get("kind") == "pr_publication" and row.get("artifact_path") == relative for row in case.get("evidence", [])):
        _api(install_root, engagement, key, "POST", _case_path(str(case["id"])) + "/evidence", {
            "kind": "pr_publication", "method": "github", "environment": "not_applicable",
            "command": "create-pr", "observed": f"Verified draft PR: {url}",
            "proved": "This revision and body were verified on the case's draft PR",
            "revision": case["worktree_revision"], "artifact_path": relative,
        })


def _finalize_case_branch(install_root: Path, engagement: Path, key: str, case: dict,
                          config: dict, new_branch: str) -> dict:
    directory = engagement / "remediation/cases" / str(case["id"])
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ".publication.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        case = _case(install_root, engagement, key, str(case["id"]))
        config = _case_config(case, config)
        if case.get("status") in {"closed", "pr_draft", "development", "verified"} or case.get("deployment") or any(
            item.get("kind") in {"pr_publication", "pr_update", "deployment_request"} for item in case.get("evidence", [])
        ):
            raise SystemExit("published or deployed case branches cannot be finalized")
        if any((directory / "pr").glob("publication-*.json")) or any((directory / "pr").glob("update-intent-*.json")) or any(
            (directory / "deployments").glob("*.json")
        ):
            raise SystemExit("publication or deployment records exist; reconcile them before changing branch identity")
        workspace = Path(str(case.get("worktree_path") or ""))
        if not workspace.is_dir() or not _is_registered_worktree(Path(str(config["repository"])), workspace):
            raise SystemExit("case worktree is not registered to the configured repository")
        old_branch = str(case.get("worktree_branch") or "")
        revision = str(case.get("worktree_revision") or "")
        if not old_branch or not revision:
            raise SystemExit("register the case branch and revision before finalization")
        marker = directory / "branch-finalization.json"
        intent = {"old_branch": old_branch, "new_branch": new_branch, "revision": revision}
        if marker.exists():
            pending = json.loads(marker.read_text(encoding="utf-8"))
            if (pending.get("new_branch") != new_branch or pending.get("revision") != revision
                    or old_branch not in {pending.get("old_branch"), new_branch}):
                raise SystemExit("another branch finalization is pending; retry its original branch and revision first")
            intent = pending
        try:
            _vcs().prepare_branch_finalization(workspace, intent["old_branch"], new_branch, revision)
            _vcs().ensure_unpublished_branches(workspace, [intent["old_branch"], new_branch])
            temporary = marker.with_suffix(".tmp")
            temporary.write_text(json.dumps(intent, indent=2) + "\n", encoding="utf-8")
            temporary.replace(marker)
            _vcs().finalize_branch(workspace, intent["old_branch"], new_branch, revision)
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            raise SystemExit(f"branch finalization failed: {exc}; retry the same command after resolving the cause") from None
        result = _api(install_root, engagement, key, "POST", _case_path(str(case["id"])) + "/finalize-branch", intent)
        if not isinstance(result, dict):
            raise SystemExit("remediation API returned an invalid finalized case; retry the same command")
        marker.unlink()
        return result


def run_remediation(args: argparse.Namespace, install_root: Path) -> None:
    if args.remediation_command is None:
        args.remediation_help()
        return
    identifier = getattr(args, "case_id", None)
    if identifier is not None and str(identifier).isascii() and str(identifier).isdigit():
        if int(identifier) <= 0:
            raise SystemExit("case ID must be positive")
        args.case_id = str(int(identifier))
    elif identifier is not None and args.remediation_command != "join":
        raise SystemExit("case ID must be a positive integer")
    if args.remediation_command in {"identity", "create-pr"}:
        key = _engagement_key(args, install_root)
        engagement, _ = _project(install_root, key)
        _case_path(args.case_id)
        directory = engagement / "remediation/cases" / str(args.case_id)
        directory.mkdir(parents=True, exist_ok=True)
        with (directory / ".publication.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            _run_remediation(args, install_root)
        return
    _run_remediation(args, install_root)


def _run_remediation(args: argparse.Namespace, install_root: Path) -> None:
    cmd = args.remediation_command
    choose_case = cmd == "join" and not getattr(args, "case_id", None)
    if choose_case:
        if not sys.stdin.isatty():
            raise SystemExit("Interactive join needs a terminal; supply -k <project> join <case_id>, or use list --json to find case_id")
        key = args.engagement_key or _select_project(_remediation_projects(install_root))
    else:
        key = _start_engagement_key(args, install_root) if cmd == "start" else _engagement_key(args, install_root)
    args.engagement_key = key
    eng_dir, config = _project(install_root, key)
    if cmd == "start" and not getattr(args, "client", None):
        args.client = (prompt_choice("Select remediation client", "claude", ["claude", "opencode", "zcode"])
                       if sys.stdin.isatty() and not getattr(args, "session_id", None) else "claude")
    backend = restart_manifest.backend_state(install_root, engagement_dir=eng_dir)
    if backend.state == "stale":
        from .preflight import managed_backend_host

        base_url = resolve_orchestrator_base_url(install_root, eng_dir)
        remedy = ("run `" + shlex.join(["vigil", "--root", str(install_root), "orchestrator", "restart"]) + "`"
                  if managed_backend_host(base_url) is not None
                  else f"restart or upgrade the configured backend at {base_url} on its owning host")
        print(
            f"Warning: backend restart required: {backend.detail}; {remedy}",
            file=sys.stderr,
        )
    if choose_case:
        args.case_id = str(_select_case(_case_summaries(install_root, eng_dir, key))["id"])
        if not args.fresh:
            args.fresh = select_conversation_action()
    elif cmd == "join" and getattr(args, "case_id", None):
        args.case_id = _resolve_case_id(install_root, eng_dir, key, args.case_id)
    if cmd in {"start", "route", "session", "join"}:
        selected_case = None
        if cmd in {"session", "join"}:
            with term.activity(f"Loading case #{args.case_id}…", enabled=cmd == "join"):
                selected_case = _case(install_root, eng_dir, key, args.case_id)
                config = _case_config(selected_case, config)
        def read_case(identifier):
            case = (selected_case if selected_case is not None and str(selected_case.get("id")) == str(identifier)
                    else _case(install_root, eng_dir, key, identifier))
            _render_case_handoff(eng_dir, case, config)
            return case
        code = run_session_command(args, install_root, eng_dir, config, case_reader=read_case)
        if code:
            raise SystemExit(code)
        return
    case_id = getattr(args, "case_id", "")
    endpoint = _case_path(case_id) if case_id else "/cases"
    result: object
    if cmd == "from-finding":
        payload: dict = {"remediation_engagement_key": key}
        if args.title:
            payload["title"] = args.title
        result = _api(install_root, eng_dir, args.finding_engagement, "POST", f"/findings/{quote(args.finding, safe='')}/cases", payload)
    elif cmd == "import":
        try:
            source_file = args.snapshot_file.expanduser().resolve(strict=True)
            snapshot = json.loads(source_file.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise SystemExit(f"cannot read --snapshot-file {args.snapshot_file}: {exc}") from exc
        if not isinstance(snapshot, dict):
            raise SystemExit("snapshot must be a JSON object containing the report and attachments")
        if not args.source_key and args.source not in {"manual", "report"}:
            raise SystemExit("--source-key is required for a retrieved report provider")
        attachments = snapshot.get("attachments")
        if attachments is None:
            attachments = []
        if not isinstance(attachments, list):
            raise SystemExit("snapshot attachments must be a list")
        prepared_attachments = []
        for raw in args.attachment:
            attachment = raw.expanduser().resolve(strict=True)
            if not attachment.is_file():
                raise SystemExit(f"attachment is not a file: {attachment}")
            attachments.append({"name": attachment.name})
            prepared_attachments.append(attachment)
        snapshot["attachments"] = attachments
        if args.resume_case_id:
            result = _case(install_root, eng_dir, key, args.resume_case_id)
            if result.get("source_type") != args.source or (args.source_key is not None and result.get("source_key") != args.source_key):
                raise SystemExit("resume case source does not match supplied snapshot identity")
        else:
            result = _api(install_root, eng_dir, key, "POST", "/cases", {
                "source_type": args.source, "source_key": args.source_key, "title": args.title,
                "snapshot": snapshot, "finding_ids": args.finding_id,
            })
        if not isinstance(result, dict) or "id" not in result:
            raise SystemExit("remediation API did not return a case ID")
        try:
            _register_intake_files(install_root, eng_dir, key, result, source_file, prepared_attachments)
        except (OSError, SystemExit) as exc:
            raise SystemExit(
                f"case {result['id']} exists, but intake file registration is incomplete: {exc}. "
                f"Retry import with --resume-case-id {result['id']} and the same files."
            ) from exc
    elif cmd == "list":
        _print_case_list(install_root, key, _case_summaries(install_root, eng_dir, key), as_json=getattr(args, "json", False))
        return
    elif cmd == "show":
        result = _case(install_root, eng_dir, key, case_id)
    elif cmd == "handoff":
        case = _case(install_root, eng_dir, key, case_id)
        result = {"path": str(_render_case_handoff(eng_dir, case, config))}
    elif cmd == "identity":
        case = _case(install_root, eng_dir, key, case_id)
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/identity", {
            "expected_external_provider": case.get("external_provider"), "expected_external_key": case.get("external_key"),
            "external_provider": args.provider, "external_key": args.external_key,
        })
        if not isinstance(result, dict):
            raise SystemExit("remediation API returned an invalid case identity")
        _render_case_handoff(eng_dir, result, config)
    elif cmd == "finalize-branch":
        result = _finalize_case_branch(install_root, eng_dir, key, _case(install_root, eng_dir, key, case_id), config, args.branch)
        _render_case_handoff(eng_dir, result, config)
    elif cmd == "checks":
        case = _case(install_root, eng_dir, key, case_id)
        result = _run_profile_checks(install_root, eng_dir, key, case, config, args.actor,
                                     names=args.name, shared_environment=args.shared_environment,
                                     stage=getattr(args, "stage", "verification"))
    elif cmd == "environment":
        case = _case(install_root, eng_dir, key, case_id)
        revision = str(case.get("worktree_revision") or "")
        if not revision:
            raise SystemExit("record the case revision before acquiring a shared environment")
        payload = {"environment": args.name, "case_id": int(case_id), "actor": args.actor}
        if args.action == "release":
            if not args.token:
                raise SystemExit("environment release requires the owning --token")
            payload["token"] = args.token
        else:
            payload["revision"] = revision
        result = _api(install_root, eng_dir, key, "POST", "/environments/" + args.action, payload)
    elif cmd == "worktree":
        case = _case(install_root, eng_dir, key, case_id)
        if case.get("worktree_path"):
            raise SystemExit("case already has a worktree")
        repo = Path(str(config["repository"]))
        if not repo.is_dir():
            raise SystemExit(f"configured repository is missing: {repo}")
        safe_key = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in key.lower()).strip("-")
        branch = args.branch or f"remediation/{safe_key}-{case_id}"
        base_branch = args.base or str(config.get("base_branch") or "main")
        path = project_module(install_root).workspace_path(config, eng_dir / "remediation/cases" / case_id, branch)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_dir():
                raise SystemExit(f"existing case worktree path is not a directory: {path}")
            legacy_branch = f"codex/remediation-{safe_key}-{case_id}"
            if not args.branch and _vcs().branch_matches(path, legacy_branch):
                branch = legacy_branch
            if not _vcs().branch_matches(path, branch):
                raise SystemExit("existing case worktree branch differs from requested branch; inspect before retry")
            if not _is_registered_worktree(repo, path):
                raise SystemExit("existing case worktree is not registered to the configured repository; inspect before retry")
        else:
            try:
                _vcs().create_workspace(repo, path, branch, base_branch)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                raise SystemExit(f"worktree creation failed: {error}") from None
        result = _api(install_root, eng_dir, key, "PATCH", endpoint, {
            "worktree_path": str(path), "worktree_branch": branch, "worktree_revision": _revision(path),
            "base_branch": base_branch, "base_revision": _vcs().review_base(path, base_branch=base_branch),
        })
    elif cmd == "sync-revision":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        if not config.get("repository"):
            raise SystemExit("case worktree cannot be verified without its configured repository")
        worktree = _require_case_worktree(case, Path(str(config["repository"])))
        _require_clean_worktree(worktree)
        result = _api(install_root, eng_dir, key, "PATCH", endpoint, {"worktree_revision": _revision(worktree)})
    elif cmd == "runtime-identity":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        worktree = _require_case_worktree(case, Path(str(config["repository"])))
        result = inspect_compose_identity(worktree, args.compose_file, args.service, args.container_path, str(case.get("worktree_revision") or ""))
        if getattr(args, "shared_environment", None):
            if not args.environment_token or not args.actor:
                raise SystemExit("persisting runtime identity requires --environment-token and --actor")
            if result.get("status") == "matched":
                result["lease"] = _api(install_root, eng_dir, key, "POST", "/environments/confirm", {
                    "environment": args.shared_environment, "case_id": int(case_id),
                    "token": args.environment_token, "actor": args.actor,
                    "observed_revision": case["worktree_revision"],
                })
    elif cmd == "test":
        from .remediation_regression import run_regression

        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        result = run_regression(args, install_root, eng_dir, key, case, config)
    elif cmd == "evidence":
        if args.kind in {"red-test", "green-test"}:
            expected_outcome = "failed_as_expected" if args.kind == "red-test" else "passed"
            if (args.outcome != expected_outcome
                    or not (args.evidence_command or "").strip() or args.artifact is None
                    or not (args.revision or "").strip()):
                raise SystemExit(
                    f"{args.kind} requires nonempty command, saved output artifact, --revision, "
                    f"and --outcome {expected_outcome}"
                )
        artifact = None
        if args.artifact:
            file = args.artifact.expanduser().resolve(strict=True)
            case_root = eng_dir.resolve() / "remediation" / "cases" / case_id
            if not file.is_file() or not file.is_relative_to(case_root):
                raise SystemExit("evidence artifact must be a file inside this case's remediation directory")
            artifact = str(file.relative_to(eng_dir.resolve()))
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/evidence", {
            "kind": args.kind, "method": args.method, "command": args.evidence_command or "",
            "environment": args.environment,
            "observed": args.observed, "proved": args.proved,
            "artifact_path": artifact, "revision": args.revision, "outcome": args.outcome,
            "execution": getattr(args, "execution", "executed"),
            "executed_revision": getattr(args, "executed_revision", None),
            "executed_directory": getattr(args, "executed_directory", None),
            "shared_environment": getattr(args, "shared_environment", None),
            "environment_token": getattr(args, "environment_token", None),
        })
    elif cmd == "baseline":
        if args.owner_decision and (not args.owner_actor or not args.owner_reason):
            raise SystemExit("owner decision requires --owner-actor and --owner-reason")
        result = _api(install_root, eng_dir, key, "PATCH", endpoint + "/baseline", {
            "outcome": args.outcome, "method": args.method, "proved": args.proved,
            "owner_decision": args.owner_decision, "owner_actor": args.owner_actor,
            "owner_reason": args.owner_reason,
        })
    elif cmd == "plan":
        if not getattr(args, "requirements_file", None):
            case = _case(install_root, eng_dir, key, case_id)
            if not (case.get("verification_plan") or "").strip():
                raise SystemExit("The first plan requires --requirements-file and --alternatives-reason")
        payload = {"verification_plan": args.file.expanduser().read_text(encoding="utf-8")}
        if getattr(args, "requirements_file", None):
            payload["requirements"] = json.loads(args.requirements_file.expanduser().read_text(encoding="utf-8"))
            payload["alternatives_reason"] = getattr(args, "alternatives_reason", None)
        result = _api(install_root, eng_dir, key, "PATCH", endpoint + "/verification-plan", payload)
    elif cmd == "release-plan":
        if args.production_canary == "required" and not args.safe_procedure.strip():
            raise SystemExit("a required production canary needs a safe procedure")
        result = _api(install_root, eng_dir, key, "PATCH", endpoint + "/release-plan", {
            "production_canary_decision": args.production_canary,
            "production_canary_rationale": args.rationale,
            "safe_procedure": args.safe_procedure,
            "monitoring": args.monitoring,
        })
    elif cmd == "approve":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        worktree = _require_case_worktree(case, Path(str(config["repository"])))
        if _revision(worktree) != str(case.get("worktree_revision") or ""):
            raise SystemExit("case worktree revision must match recorded revision before approval")
        _require_clean_worktree(worktree)
        instruction = args.owner_instruction.strip()
        if not instruction:
            raise SystemExit("--owner-instruction must contain the case owner's explicit approval instruction")
        if args.review_digest != case.get("review_digest"):
            raise SystemExit("review digest changed since the owner's reviewed snapshot")
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/approve", {
            "reviewer": args.reviewer, "expected_review_digest": args.review_digest,
            "approval_method": "cli_instruction", "owner_instruction": instruction,
        })
    elif cmd == "transition":
        if args.status == "pr_draft":
            raise SystemExit("use create-pr to enter pr_draft after reconciling the draft PR")
        if args.status == "development":
            raise SystemExit("use development-handoff to enter development with a configured workflow")
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/transition", {
            "status": args.status, "actor": args.actor, "reason": args.reason,
        })
    elif cmd == "deployment":
        if args.expected_revision != args.observed_revision:
            raise SystemExit("deployed revision is unconfirmed: expected and observed revisions differ")
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/deployment", {
            "workflow": args.workflow, "run_id": args.run_id,
            "expected_revision": args.expected_revision, "observed_revision": args.observed_revision,
            "environment": args.environment, "actor": args.actor,
        })
    elif cmd == "human-verification":
        result = _api(install_root, eng_dir, key, "POST", endpoint + "/human-verification", {
            "actor": args.actor, "result": args.result,
            "observed_revision": args.observed_revision, "notes": args.notes,
        })
    elif cmd in {"stagehand", "browser"}:
        result = _run_stagehand(install_root, eng_dir, key, args, config)
    elif cmd == "prepare-pr":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        _approved_current(case, Path(str(config["repository"])))
        if getattr(args, "body_file", None):
            body = args.body_file.expanduser().read_text(encoding="utf-8")
            _explanation(args.root_cause, "root cause")
            _explanation(args.fix_summary, "fix summary")
            _release_plan(case)
            if not body.strip():
                raise SystemExit("authored PR body must be nonempty")
            _validate_pr_template(body, config)
        else:
            if _policy(config).get("pr_template"):
                raise SystemExit("author the body using the profile's template/writing guidance and pass --body-file")
            body = _pr_body(case, config, args.root_cause, args.fix_summary)
        args.output.expanduser().write_text(body, encoding="utf-8")
        retained = _register_pr_body(install_root, eng_dir, key, case_id, case, body, "prepared")
        content_path = eng_dir / "remediation" / "cases" / case_id / "pr-content.json"
        content_path.parent.mkdir(parents=True, exist_ok=True)
        content_path.write_text(json.dumps({
            "approval_digest": _approved_digest(case),
            "root_cause": args.root_cause.strip(),
            "fix_summary": args.fix_summary.strip(),
        }, indent=2) + "\n", encoding="utf-8")
        result = {"path": str(args.output.expanduser().resolve()), "case_artifact": str(retained), "review_digest": _approved_digest(case)}
    elif cmd == "create-pr":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        repo = Path(str(config["repository"]))
        worktree = _approved_current(case, repo)
        if case.get("status") not in {"approved", "pr_draft"}:
            raise SystemExit("case must be approved or already in draft PR state")
        if not args.template_mapped:
            raise SystemExit("map the PR content to the repository's actual template, then pass --template-mapped")
        body_file = args.body_file.expanduser().resolve(strict=True)
        if not body_file.is_file() or not body_file.read_text(encoding="utf-8").strip():
            raise SystemExit("--body-file must contain the reviewed PR content")
        body = body_file.read_text(encoding="utf-8")
        _validate_pr_template(body, config)
        _release_plan(case)
        content_path = eng_dir / "remediation" / "cases" / case_id / "pr-content.json"
        if not content_path.is_file():
            raise SystemExit("prepare reviewed PR content before creating the draft")
        content = json.loads(content_path.read_text(encoding="utf-8"))
        digest = _approved_digest(case)
        if content.get("approval_digest") != digest:
            raise SystemExit("prepared PR content is bound to a different approval; prepare it again")
        explanations = [_explanation(str(content.get("root_cause") or ""), "root cause"),
                        _explanation(str(content.get("fix_summary") or ""), "fix summary")]
        _required_reviewed_evidence_lines(case)
        if any(explanation not in body for explanation in explanations):
            raise SystemExit("final PR body must include the prepared root cause and fix explanation")
        if _policy(config).get("check_commands"):
            _run_profile_checks(install_root, eng_dir, key, case, config, args.actor, stage="publication")
            case = _case(install_root, eng_dir, key, case_id)
            _approved_current(case, repo)
        branch = str(case["worktree_branch"])
        base_branch = str(case.get("base_branch") or config.get("base_branch") or "main")
        if branch == base_branch:
            raise SystemExit("case worktree must be on a dedicated branch")
        github_repository = _github_repository(worktree)
        retained_final = _register_pr_body(install_root, eng_dir, key, case_id, case, body, "final")
        update = getattr(args, "update", False)
        if update and not (getattr(args, "owner_instruction", "") or "").strip():
            raise SystemExit("PR updates require the owner's explicit --owner-instruction to publish")
        options: dict = {"repository": github_repository}
        if base_branch != "main":
            options["base_branch"] = base_branch
        if update:
            options["allow_update"] = True
        url = _existing_draft_pr(worktree, branch, body, **options)
        if update:
            if not url:
                raise SystemExit("no existing open draft PR to update; use initial create-pr instead")
            remote = subprocess.run(["gh", "pr", "view", url, "--json", "headRefOid", "--jq", ".headRefOid"],
                                    cwd=worktree, text=True, capture_output=True, check=True)
            publications = [row for row in case.get("evidence", []) if row.get("kind") == "pr_publication" and row.get("method") == "github"]
            if not publications:
                raise SystemExit("this case has no recorded published revision; reconcile the existing PR before updating")
            published = max(publications, key=lambda row: int(row["id"]))["revision"]
            intent = {"url": url, "previous_revision": published, "target_revision": case["worktree_revision"],
                      "owner_instruction": args.owner_instruction}
            intent_directory = eng_dir / "remediation/cases" / case_id / "pr"
            intent_directory.mkdir(parents=True, exist_ok=True)
            previous_intents = [json.loads(path.read_text(encoding="utf-8")) for path in intent_directory.glob("update-intent-*.json")]
            own_partial_push = remote.stdout.strip() == case["worktree_revision"] and any(
                row.get("url") == url and row.get("previous_revision") == published
                and row.get("target_revision") == case["worktree_revision"] for row in previous_intents)
            if remote.stdout.strip() != published and not own_partial_push:
                raise SystemExit("remote PR changed since Vigil's last publication; review and reconcile those changes before updating")
            _approved_current(case, repo)
            if not own_partial_push:
                intent_path = intent_directory / f"update-intent-{hashlib.sha256(json.dumps(intent, sort_keys=True).encode()).hexdigest()}.json"
                intent_path.write_text(json.dumps(intent, indent=2) + "\n", encoding="utf-8")
                _vcs().push(worktree, branch, str(case["worktree_revision"]), expected_remote_revision=published)
            edited = subprocess.run(["gh", "pr", "edit", url, "--body-file", str(body_file)],
                                    cwd=worktree, text=True, capture_output=True)
            if edited.returncode:
                raise SystemExit(f"code pushed, but PR body update failed; reconcile {url}: {edited.stderr.strip()}")
            if _existing_draft_pr(worktree, branch, body, repository=github_repository, base_branch=base_branch) != url:
                raise SystemExit("updated PR revision or body could not be confirmed; reconcile the existing PR")
            _record_publication(install_root, eng_dir, key, case, url, body)
            _api(install_root, eng_dir, key, "POST", endpoint + "/evidence", {
                "kind": "pr_update", "method": "github", "environment": "not_applicable",
                "command": "create-pr --update", "observed": f"Updated draft PR: {url}",
                "proved": args.owner_instruction, "revision": case["worktree_revision"],
                "artifact_path": str(retained_final.relative_to(eng_dir)),
            })
            if case.get("status") == "approved":
                _api(install_root, eng_dir, key, "POST", endpoint + "/transition", {
                    "status": "pr_draft", "actor": args.actor, "reason": f"Updated draft PR: {url}",
                })
            result = {"pull_request": url, "case_artifact": str(retained_final), "transition": "updated"}
        elif case.get("status") == "pr_draft":
            if not url:
                raise SystemExit("case claims draft PR state, but no open draft PR exists for its branch")
            _record_publication(install_root, eng_dir, key, case, url, body)
            result = {"pull_request": url, "case_artifact": str(retained_final), "transition": "already_recorded"}
        else:
            if not url:
                _api(install_root, eng_dir, key, "POST", endpoint + "/publication-intent", {
                    "branch": branch, "revision": case["worktree_revision"], "review_digest": digest,
                })
                try:
                    _vcs().push(worktree, branch, str(case["worktree_revision"]))
                except (OSError, ValueError, subprocess.SubprocessError) as error:
                    raise SystemExit(f"branch push failed: {error}") from None
                opened = subprocess.run([
                    "gh", "pr", "create", "--draft", "--base", base_branch, "--head", branch,
                    "--title", getattr(args, "title", None) or _publication_title(case),
                    "--body-file", str(body_file), *(["--repo", github_repository] if github_repository else []),
                ], cwd=worktree, text=True, capture_output=True)
                url = _existing_draft_pr(worktree, branch, body, **options)
                if not url:
                    raise SystemExit(opened.stderr.strip() or "draft PR head revision could not be confirmed; retry create-pr after checking the remote branch")
                if opened.returncode == 0 and opened.stdout.strip() != url:
                    raise SystemExit("created draft PR URL differs from the branch's verified draft; inspect before retrying")
            _approved_current(case, repo)
            _record_publication(install_root, eng_dir, key, case, url, body)
            try:
                transition_result = _api(install_root, eng_dir, key, "POST", endpoint + "/transition", {
                    "status": "pr_draft", "actor": args.actor, "reason": f"Draft PR: {url}",
                })
            except SystemExit as exc:
                raise SystemExit(
                    f"draft PR exists at {url}, but Vigil transition was not confirmed: {exc}. "
                    "Retry create-pr with the same body file to reconcile it."
                ) from exc
            result = {"pull_request": url, "case_artifact": str(retained_final), "transition": transition_result}
    elif cmd == "deployment-run":
        result = _run_deployment(install_root, eng_dir, key, args, config)
    elif cmd == "development-handoff":
        case = _case(install_root, eng_dir, key, case_id)
        config = _case_config(case, config)
        _approved_current(case, Path(str(config["repository"])))
        workflow = str(config.get("deployment_workflow") or "")
        if not workflow:
            raise SystemExit("deployment_workflow is not configured; inspect the repository's actual GitHub Actions inputs")
        _approved_current(case, Path(str(config["repository"])))
        transition_result = _api(install_root, eng_dir, key, "POST", endpoint + "/transition", {
            "status": "development", "actor": args.actor,
            "reason": f"Human GitHub Actions handoff for {workflow}; expected revision {case['worktree_revision']}",
        })
        result = {"workflow": workflow, "expected_revision": case["worktree_revision"], "action": "Human triggers the existing GitHub Actions development deployment and records run ID and observed revision", "transition": transition_result}
    else:
        raise SystemExit(f"unknown remediation command: {cmd}")
    if cmd in {"import", "from-finding"} and isinstance(result, dict) and result.get("id"):
        result["handoff_path"] = str(_render_case_handoff(eng_dir, result, config))
    print(json.dumps(result, indent=2, sort_keys=True))


def _publication_title(case: dict) -> str:
    title = str(case.get("title") or "Remediation")
    key = str(case.get("external_key") or "")
    return f"{key} {title}" if key and not title.startswith(key) else title


def _pr_body(case: dict, config: dict[str, object], root_cause: str, fix_summary: str) -> str:
    """A structured draft for mapping to the repository's actual PR template."""
    root_cause = _explanation(root_cause, "root cause")
    fix_summary = _explanation(fix_summary, "fix summary")
    release = _release_plan(case)
    if not str(case.get("verification_plan") or "").strip():
        raise SystemExit("verification plan is required before preparing a PR")
    evidence = _approved_verification_evidence(case)
    test_results = "\n".join(
        f"- {row.get('method')} [environment: {row.get('environment') or 'unknown'}] "
        f"({str(row.get('outcome') or 'unknown').replace('_', ' ')}): {row.get('observed')}"
        for row in evidence
    )
    reference = f"Reference: {case['external_key']}\n\n" if case.get("external_key") else ""
    return (f"{reference}## Root cause\n\n{root_cause}\n\n## Fix\n\n{fix_summary}\n\n"
            f"## Verification\n\n{case['verification_plan']}\n\n{test_results}\n\n"
            f"## Release notes\n\n{release['production_canary_rationale']}\n"
            f"{release['safe_procedure']}\n{release['monitoring']}\n")


def _explanation(value: str, label: str) -> str:
    text = value.strip()
    if len(text) < 20 or text.lower() in {"todo", "tbd", "placeholder"} or "summarize" in text.lower():
        raise SystemExit(f"PR {label} needs a concrete explanation of at least 20 characters")
    return text


def _release_plan(case: dict) -> dict:
    release = case.get("release_plan")
    if not isinstance(release, dict):
        raise SystemExit("case release plan is required before preparing a PR")
    decision = str(release.get("production_canary_decision") or "")
    rationale = str(release.get("production_canary_rationale") or "").strip()
    monitoring = str(release.get("monitoring") or "").strip()
    procedure = str(release.get("safe_procedure") or "").strip()
    if decision not in {"required", "not_required"} or not rationale or not monitoring or (decision == "required" and not procedure):
        raise SystemExit("PR release plan needs a final canary decision, rationale, monitoring, and safe procedure when required")
    return {**release, "monitoring": monitoring}
