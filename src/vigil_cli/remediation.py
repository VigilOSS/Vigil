"""Case-scoped remediation operator commands backed by the Vigil API."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.util
import json
import os
import posixpath
import shutil
import subprocess
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import Request, urlopen

from .engagements import resolve_engagement_path
from .paths import resolve_orchestrator_base_url


def register_remediation_parser(sub: argparse._SubParsersAction) -> None:
    parser = sub.add_parser("remediation", help="Manage remediation cases in one project engagement")
    parser.add_argument("--engagement-key", "-k", required=True)
    commands = parser.add_subparsers(dest="remediation_command", required=True)

    intake = commands.add_parser("import", help="Import a Jira issue or bounty report snapshot")
    intake.add_argument("--source", choices=("jira", "bounty"), required=True)
    intake.add_argument("--source-key", required=True)
    intake.add_argument("--title", required=True)
    intake.add_argument("--snapshot-file", required=True, type=Path)
    intake.add_argument("--attachment", action="append", type=Path, default=[], help="Local report attachment; repeatable")
    intake.add_argument("--finding", help="Existing Vigil Finding slug, when present")
    intake.add_argument("--finding-engagement", help="Engagement key that owns --finding")
    intake.add_argument("--resume-case-id", help="Resume attachment registration after a partial import")

    list_cases = commands.add_parser("list", help="List cases")
    list_cases.add_argument("--json", action="store_true")
    show = commands.add_parser("show", help="Show case and review state")
    show.add_argument("case_id")

    worktree = commands.add_parser("worktree", help="Create a dedicated Git worktree for a case")
    worktree.add_argument("case_id")
    worktree.add_argument("--base", default="main")
    worktree.add_argument("--branch")

    sync_revision = commands.add_parser("sync-revision", help="Record the clean case worktree HEAD after committing the fix")
    sync_revision.add_argument("case_id")

    runtime = commands.add_parser("runtime-identity", help="Inspect which worktree or image revision Compose containers serve")
    runtime.add_argument("case_id")
    runtime.add_argument("--compose-file", required=True, type=Path)
    runtime.add_argument("--service", required=True)
    runtime.add_argument("--container-path", required=True, help="Application path inside the service container")

    evidence = commands.add_parser("evidence", help="Record one evidence run")
    evidence.add_argument("case_id")
    evidence.add_argument("--kind", required=True)
    evidence.add_argument("--method", required=True)
    evidence.add_argument("--environment", choices=("local", "development", "test", "production"), required=True)
    evidence.add_argument("--command")
    evidence.add_argument("--observed", required=True)
    evidence.add_argument("--proved", required=True)
    evidence.add_argument("--artifact", type=Path)
    evidence.add_argument("--revision")
    evidence.add_argument("--outcome", choices=("failed_as_expected", "passed"), help="Typed red/green test outcome")

    baseline = commands.add_parser("baseline", help="Record runtime reproduction or code/test support and owner decision")
    baseline.add_argument("case_id")
    baseline.add_argument("--outcome", choices=("runtime_reproduced", "code_test_confirmed", "unreproduced"), required=True)
    baseline.add_argument("--method", required=True)
    baseline.add_argument("--proved", required=True)
    baseline.add_argument("--owner-decision", choices=("proceed", "pause"))
    baseline.add_argument("--owner-actor")
    baseline.add_argument("--owner-reason")

    plan = commands.add_parser("plan", help="Save a rehearsed human verification brief")
    plan.add_argument("case_id")
    plan.add_argument("--file", required=True, type=Path)

    release = commands.add_parser("release-plan", help="Record production canary decision and monitoring")
    release.add_argument("case_id")
    release.add_argument("--production-canary", choices=("required", "not_required", "defer"), required=True)
    release.add_argument("--rationale", required=True)
    release.add_argument("--safe-procedure", default="")
    release.add_argument("--coralogix-monitoring", required=True)

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

    human = commands.add_parser("human-verification", help="Record the Security Developer's rehearsed procedure result")
    human.add_argument("case_id")
    human.add_argument("--actor", required=True)
    human.add_argument("--result", choices=("passed", "failed", "blocked"), required=True)
    human.add_argument("--observed-revision", required=True)
    human.add_argument("--notes", required=True)

    stagehand = commands.add_parser("stagehand", help="Run a trusted local Stagehand script and register evidence")
    stagehand.add_argument("case_id")
    stagehand.add_argument("--script", required=True, type=Path)
    stagehand.add_argument("--revision", required=True)
    stagehand.add_argument("--environment", choices=("local", "development", "test", "production"), default="local")
    stagehand.add_argument("--purpose", choices=("happy-path", "bad-path", "other"), required=True)
    stagehand.add_argument("--production-decision", help="Case owner decision for production Stagehand use")
    stagehand.add_argument("--production-evidence-policy", choices=("retain-screenshots", "no-screenshots"), help="Case-specific production screenshot retention decision")

    draft = commands.add_parser("prepare-pr", help="Generate draft PR content after review approval")
    draft.add_argument("case_id")
    draft.add_argument("--output", required=True, type=Path)
    draft.add_argument("--root-cause", required=True, help="Concrete root cause found in the reviewed diff")
    draft.add_argument("--fix-summary", required=True, help="Concrete code change and security boundary restored")

    create_pr = commands.add_parser("create-pr", help="Push approved branch and open draft PR against main")
    create_pr.add_argument("case_id")
    create_pr.add_argument("--body-file", required=True, type=Path, help="Final body mapped to the repository PR template")
    create_pr.add_argument("--actor", required=True)
    create_pr.add_argument("--template-mapped", action="store_true", help="Assert final body maps required content to the actual repository PR template")

    handoff = commands.add_parser("development-handoff", help="Prepare manual GitHub Actions development deployment")
    handoff.add_argument("case_id")
    handoff.add_argument("--actor", required=True)


def _project(install_root: Path, key: str) -> tuple[Path, dict[str, object]]:
    path = resolve_engagement_path(install_root, key)
    scope = json.loads((path / "scope.json").read_text(encoding="utf-8"))
    if scope.get("engagement_type") != "remediation":
        raise SystemExit(f"{key} is not a remediation engagement")
    config = json.loads((path / "remediation-project.json").read_text(encoding="utf-8"))
    return path, config


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
    if not case_id or not all(ch.isalnum() or ch in "-_" for ch in case_id):
        raise SystemExit("case ID contains unsupported characters")
    return f"/cases/{quote(case_id, safe='')}"


def _case(install_root: Path, eng_dir: Path, key: str, case_id: str) -> dict:
    result = _api(install_root, eng_dir, key, "GET", _case_path(case_id))
    if not isinstance(result, dict):
        raise SystemExit("remediation API returned an invalid case")
    return result


def _revision(path: Path) -> str:
    process = subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, capture_output=True)
    if process.returncode:
        raise SystemExit(process.stderr.strip() or "cannot read worktree revision")
    return process.stdout.strip()


def _worktree_status(path: Path) -> str:
    process = subprocess.run(["git", "-C", str(path), "status", "--porcelain", "--untracked-files=all"], text=True, capture_output=True)
    if process.returncode:
        raise SystemExit(process.stderr.strip() or "cannot read worktree status")
    return process.stdout.strip()


def _is_registered_worktree(repo: Path, path: Path) -> bool:
    def git_path(directory: Path, argument: str) -> Path | None:
        process = subprocess.run(
            ["git", "-C", str(directory), "rev-parse", "--path-format=absolute", argument],
            text=True, capture_output=True,
        )
        return Path(process.stdout.strip()).resolve() if process.returncode == 0 and process.stdout.strip() else None

    if path.is_symlink() or git_path(path, "--show-toplevel") != path.resolve():
        return False
    common_dir = git_path(repo, "--git-common-dir")
    if common_dir is None or git_path(path, "--git-common-dir") != common_dir:
        return False
    listed = subprocess.run(
        ["git", "-C", str(repo), "worktree", "list", "--porcelain", "-z"],
        text=True, capture_output=True,
    )
    if listed.returncode:
        return False
    return any(
        Path(os.path.abspath(entry.removeprefix("worktree "))) == Path(os.path.abspath(path))
        for entry in listed.stdout.split("\0")
        if entry.startswith("worktree ")
    )


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
    current = subprocess.run(
        ["git", "-C", str(path), "branch", "--show-current"], text=True, capture_output=True,
    )
    if current.returncode or current.stdout.strip() != branch:
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


def _existing_draft_pr(worktree: Path, branch: str, body: str) -> str | None:
    listed = subprocess.run(
        ["gh", "pr", "list", "--head", branch, "--base", "main", "--state", "all",
         "--json", "url,state,isDraft,headRefName,baseRefName,headRefOid,body"],
        cwd=worktree, text=True, capture_output=True,
    )
    if listed.returncode:
        raise SystemExit(listed.stderr.strip() or "could not check existing pull requests")
    rows = json.loads(listed.stdout)
    if not isinstance(rows, list):
        raise SystemExit("GitHub returned an invalid pull request listing")
    matches = [row for row in rows if isinstance(row, dict) and row.get("headRefName") == branch and row.get("baseRefName") == "main"]
    if len(matches) > 1:
        raise SystemExit("multiple pull requests already use this branch; inspect manually")
    if not matches:
        return None
    row = matches[0]
    if row.get("state") != "OPEN" or row.get("isDraft") is not True or not row.get("url"):
        raise SystemExit("an existing pull request for this branch is not an open draft")
    if row.get("headRefOid") != _revision(worktree):
        raise SystemExit("draft PR head revision differs from the approved case worktree; inspect the remote branch before retrying")
    if row.get("body") != body:
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


def _required_reviewed_evidence_lines(case: dict) -> list[str]:
    approvals = case.get("approvals") or []
    cutoff = int(approvals[-1].get("evidence_cutoff_id") or 0) if approvals else 0
    evidence = [row for row in case.get("evidence") or [] if isinstance(row, dict) and int(row.get("id") or 0) <= cutoff]
    required = {"red-test", "green-test", "stagehand"}
    if not required.issubset({str(row.get("kind")) for row in evidence}):
        raise SystemExit("reviewed red/green Laravel and Stagehand evidence are required in PR content")
    lines = _reviewed_evidence_lines(case)
    return [line for line, row in zip(lines, evidence) if row.get("kind") in required]


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
        raise SystemExit("happy-path Stagehand result requires explicit passed status")
    if not str(result.get("observed") or "").strip() or not str(result.get("proved") or "").strip():
        raise SystemExit("happy-path Stagehand result requires observed and proved claims")
    steps = result.get("steps")
    if not isinstance(steps, list) or not steps or not all(
        isinstance(step, dict) and str(step.get("action") or "").strip() and str(step.get("observation") or "").strip()
        for step in steps
    ):
        raise SystemExit("happy-path Stagehand result requires structured observed UI steps (action and observation)")
    screenshots = [path for path in output.iterdir() if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg"}]
    if not screenshots or not any(_valid_screenshot(path) for path in screenshots):
        raise SystemExit("happy-path Stagehand result requires at least one nonempty valid screenshot")


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
        raise SystemExit("production Stagehand requires a case-specific human decision")
    if not args.production_evidence_policy:
        raise SystemExit("production Stagehand requires a case-specific evidence policy")
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
    validate_stagehand_config(config, dict(os.environ))
    validate_production_stagehand_policy(args)
    case_id = args.case_id
    _case_path(case_id)
    case = _case(install_root, eng_dir, key, case_id)
    if case.get("status") == "closed":
        raise SystemExit("closed remediation cases cannot accept Stagehand evidence")
    script = args.script.expanduser().resolve(strict=True)
    if not script.is_file() or script.suffix != ".py":
        raise SystemExit("--script must name a Python file")
    output = eng_dir / "remediation" / "cases" / case_id / "stagehand" / uuid.uuid4().hex
    output.mkdir(parents=True)
    stored_script = output / "script.py"
    shutil.copy2(script, stored_script)
    result: dict
    try:
        result = asyncio.run(_execute_stagehand(stored_script, output, config))
        validate_stagehand_result(result, output, args.purpose)
        validate_production_stagehand_policy(args, output)
        result["purpose"] = args.purpose
        result["environment"] = args.environment
        if args.production_decision:
            result["production_decision"] = args.production_decision
            result["production_evidence_policy"] = args.production_evidence_policy
    except BaseException as exc:
        result = {"status": "failed", "error": str(exc), "purpose": args.purpose, "environment": args.environment}
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
    for file in sorted(output.iterdir()):
        if not file.is_file():
            continue
        kind = "screenshot" if file.suffix.lower() in {".png", ".jpg", ".jpeg"} else "stagehand"
        registered.append(_api(install_root, eng_dir, key, "POST", _case_path(case_id) + "/evidence", {
            "kind": kind,
            "method": "stagehand",
            "environment": str(result["environment"]),
            "command": "trusted script run via local Chrome CDP",
            "observed": str(result.get("observed") or result.get("status") or ""),
            "proved": str(result.get("proved") or "See recorded run result; no broader claim"),
            "artifact_path": str(file.relative_to(eng_dir)),
            "revision": revision,
        }))
    return registered


def _register_intake_files(
    install_root: Path, eng_dir: Path, key: str, result: dict,
    source_file: Path, attachments: list[Path],
) -> None:
    case_id = str(result["id"])
    intake_dir = eng_dir / "remediation" / "cases" / case_id / "source"
    intake_dir.mkdir(parents=True, exist_ok=True)
    files = [source_file, *attachments]
    existing_evidence = {
        str(row.get("artifact_path")) for row in result.get("evidence", []) if isinstance(row, dict)
    }
    for index, source in enumerate(files):
        stored = intake_dir / ("snapshot.json" if index == 0 else f"{index}-{source.name}")
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


def run_remediation(args: argparse.Namespace, install_root: Path) -> None:
    key = args.engagement_key
    eng_dir, config = _project(install_root, key)
    cmd = args.remediation_command
    case_id = getattr(args, "case_id", "")
    endpoint = _case_path(case_id) if case_id else "/cases"
    result: object
    if cmd == "import":
        if bool(args.finding) != bool(args.finding_engagement):
            raise SystemExit("--finding and --finding-engagement must be supplied together")
        source_file = args.snapshot_file.expanduser().resolve(strict=True)
        snapshot = json.loads(source_file.read_text(encoding="utf-8"))
        if not isinstance(snapshot, dict):
            raise SystemExit("snapshot must be a JSON object containing the report and attachments")
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
            if result.get("source_type") != args.source or result.get("source_key") != args.source_key:
                raise SystemExit("resume case source does not match supplied snapshot identity")
        else:
            result = _api(install_root, eng_dir, key, "POST", "/cases", {
                "source_type": args.source, "source_key": args.source_key, "title": args.title,
                "snapshot": snapshot, "linked_finding_slug": args.finding,
                "linked_finding_engagement_key": args.finding_engagement,
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
        result = _api(install_root, eng_dir, key, "GET", "/cases")
    elif cmd == "show":
        result = _case(install_root, eng_dir, key, case_id)
    elif cmd == "worktree":
        case = _case(install_root, eng_dir, key, case_id)
        if case.get("worktree_path"):
            raise SystemExit("case already has a worktree")
        repo = Path(str(config["repository"]))
        if not repo.is_dir():
            raise SystemExit(f"configured repository is missing: {repo}")
        safe_key = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in key.lower()).strip("-")
        branch = args.branch or f"codex/remediation-{safe_key}-{case_id}"
        path = eng_dir / "remediation" / "cases" / case_id / "worktree"
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            if not path.is_dir():
                raise SystemExit(f"existing case worktree path is not a directory: {path}")
            actual_branch = subprocess.run(["git", "-C", str(path), "branch", "--show-current"], text=True, capture_output=True)
            if actual_branch.returncode or actual_branch.stdout.strip() != branch:
                raise SystemExit("existing case worktree branch differs from requested branch; inspect before retry")
            if not _is_registered_worktree(repo, path):
                raise SystemExit("existing case worktree is not registered to the configured repository; inspect before retry")
        else:
            process = subprocess.run(["git", "-C", str(repo), "worktree", "add", "-b", branch, str(path), args.base], text=True, capture_output=True)
            if process.returncode:
                raise SystemExit(process.stderr.strip() or "worktree creation failed")
        result = _api(install_root, eng_dir, key, "PATCH", endpoint, {
            "worktree_path": str(path), "worktree_branch": branch, "worktree_revision": _revision(path),
        })
    elif cmd == "sync-revision":
        case = _case(install_root, eng_dir, key, case_id)
        worktree = Path(str(case.get("worktree_path") or ""))
        expected = eng_dir.resolve() / "remediation" / "cases" / case_id / "worktree"
        if not worktree.is_dir() or worktree.resolve() != expected:
            raise SystemExit("case worktree is missing or outside its case directory")
        _require_case_worktree(case, Path(str(config["repository"])))
        _require_clean_worktree(worktree)
        result = _api(install_root, eng_dir, key, "PATCH", endpoint, {"worktree_revision": _revision(worktree)})
    elif cmd == "runtime-identity":
        case = _case(install_root, eng_dir, key, case_id)
        worktree = Path(str(case.get("worktree_path") or ""))
        if not worktree.is_dir():
            raise SystemExit("case has no local worktree")
        result = inspect_compose_identity(worktree, args.compose_file, args.service, args.container_path, str(case.get("worktree_revision") or ""))
    elif cmd == "evidence":
        if args.kind in {"red-test", "green-test"}:
            expected_outcome = "failed_as_expected" if args.kind == "red-test" else "passed"
            if (args.outcome != expected_outcome or args.method.lower() != "laravel"
                    or not (args.command or "").strip() or args.artifact is None
                    or not (args.revision or "").strip()):
                raise SystemExit(
                    f"{args.kind} requires Laravel method, nonempty command, saved output artifact, --revision, "
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
            "kind": args.kind, "method": args.method, "command": args.command or "",
            "environment": args.environment,
            "observed": args.observed, "proved": args.proved,
            "artifact_path": artifact, "revision": args.revision, "outcome": args.outcome,
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
        result = _api(install_root, eng_dir, key, "PATCH", endpoint + "/verification-plan", {
            "verification_plan": args.file.expanduser().read_text(encoding="utf-8"),
        })
    elif cmd == "release-plan":
        if args.production_canary == "required" and not args.safe_procedure.strip():
            raise SystemExit("a required production canary needs a safe procedure")
        result = _api(install_root, eng_dir, key, "PATCH", endpoint + "/release-plan", {
            "production_canary_decision": args.production_canary,
            "production_canary_rationale": args.rationale,
            "safe_procedure": args.safe_procedure,
            "coralogix_monitoring": args.coralogix_monitoring,
        })
    elif cmd == "approve":
        case = _case(install_root, eng_dir, key, case_id)
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
    elif cmd == "stagehand":
        result = _run_stagehand(install_root, eng_dir, key, args, config)
    elif cmd == "prepare-pr":
        case = _case(install_root, eng_dir, key, case_id)
        _approved_current(case, Path(str(config["repository"])))
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
        release = _release_plan(case)
        content_path = eng_dir / "remediation" / "cases" / case_id / "pr-content.json"
        if not content_path.is_file():
            raise SystemExit("prepare reviewed PR content before creating the draft")
        content = json.loads(content_path.read_text(encoding="utf-8"))
        digest = _approved_digest(case)
        if content.get("approval_digest") != digest:
            raise SystemExit("prepared PR content is bound to a different approval; prepare it again")
        required = [digest, str(case.get("worktree_revision") or ""),
                    str(release["production_canary_decision"]), str(release["production_canary_rationale"]),
                    str(release["coralogix_monitoring"]),
                    _explanation(str(content.get("root_cause") or ""), "root cause"),
                    _explanation(str(content.get("fix_summary") or ""), "fix summary")]
        required.append(str(case.get("verification_plan") or ""))
        required.extend(_required_reviewed_evidence_lines(case))
        if release["production_canary_decision"] == "required":
            required.append(str(release["safe_procedure"]))
        if any(not item or item not in body for item in required):
            raise SystemExit("final PR body is missing reviewed plan, evidence, code explanation, revision, digest, or canary details")
        branch = str(case["worktree_branch"])
        if branch == "main":
            raise SystemExit("case worktree must be on a dedicated branch")
        retained_final = _register_pr_body(install_root, eng_dir, key, case_id, case, body, "final")
        url = _existing_draft_pr(worktree, branch, body)
        if case.get("status") == "pr_draft":
            if not url:
                raise SystemExit("case claims draft PR state, but no open draft PR exists for its branch")
            result = {"pull_request": url, "case_artifact": str(retained_final), "transition": "already_recorded"}
        else:
            if not url:
                _approved_current(case, repo)
                push = subprocess.run(["git", "-C", str(worktree), "push", "-u", "origin", branch], text=True, capture_output=True)
                if push.returncode:
                    raise SystemExit(push.stderr.strip() or "branch push failed")
                opened = subprocess.run([
                    "gh", "pr", "create", "--draft", "--base", "main", "--head", branch,
                    "--title", str(case.get("title") or f"Remediate case {case_id}"),
                    "--body-file", str(body_file),
                ], cwd=worktree, text=True, capture_output=True)
                url = _existing_draft_pr(worktree, branch, body)
                if not url:
                    raise SystemExit(opened.stderr.strip() or "draft PR head revision could not be confirmed; retry create-pr after checking the remote branch")
                if opened.returncode == 0 and opened.stdout.strip() != url:
                    raise SystemExit("created draft PR URL differs from the branch's verified draft; inspect before retrying")
            _approved_current(case, repo)
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
    elif cmd == "development-handoff":
        case = _case(install_root, eng_dir, key, case_id)
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
    print(json.dumps(result, indent=2, sort_keys=True))


def _pr_body(case: dict, config: dict[str, object], root_cause: str, fix_summary: str) -> str:
    """A structured draft for mapping to the repository's actual PR template."""
    root_cause = _explanation(root_cause, "root cause")
    fix_summary = _explanation(fix_summary, "fix summary")
    release = _release_plan(case)
    if not str(case.get("verification_plan") or "").strip():
        raise SystemExit("verification plan is required before preparing a PR")
    _required_reviewed_evidence_lines(case)
    evidence_lines = _reviewed_evidence_lines(case)
    evidence_section = "\n".join(evidence_lines) or "- No evidence recorded."
    return (
        f"# {case.get('title', 'Remediation')}\n\n"
        f"Source: {case.get('source_type', '')} {case.get('source_key', '')}\n"
        f"Reviewed revision: {case.get('worktree_revision', '')}\n"
        f"Review digest: {_approved_digest(case)}\n\n"
        f"## Root cause\n\n{root_cause}\n\n"
        f"## Fix\n\n{fix_summary}\n\n"
        "## Baseline, tests, and browser rehearsal\n\n"
        f"{evidence_section}\n\n"
        "## Human verification\n\n"
        f"{case.get('verification_plan') or '(plan missing)'}\n\n"
        "## Production canary\n\n"
        f"Decision: {release['production_canary_decision']}\n\n"
        f"Reason: {release['production_canary_rationale']}\n\n"
        f"Safe procedure: {release['safe_procedure'] or 'Not applicable'}\n\n"
        f"Coralogix monitoring: {release['coralogix_monitoring']}\n\n"
        f"Development workflow: {config.get('deployment_workflow') or '(configure after observing actual workflow inputs)'}\n"
    )


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
    monitoring = str(release.get("coralogix_monitoring") or "").strip()
    procedure = str(release.get("safe_procedure") or "").strip()
    if decision not in {"required", "not_required"} or not rationale or not monitoring or (decision == "required" and not procedure):
        raise SystemExit("PR release plan needs a final canary decision, rationale, Coralogix monitoring, and safe procedure when required")
    return release
