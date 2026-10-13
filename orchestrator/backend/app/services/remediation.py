from __future__ import annotations

import hashlib
import difflib
import json
import os
import secrets
import select
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO

from fastapi import HTTPException

from .. import db
from .engagements import get_engagement_or_404
from .search import canonical_finding_alias

_AGENT_SCRIPTS = Path(__file__).resolve().parents[4] / "agent" / "scripts"
if str(_AGENT_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_AGENT_SCRIPTS))
from assess.lib import remediation_vcs as _vcs  # noqa: E402
from assess.lib.remediation_project import load_engagement_project  # noqa: E402


TRANSITIONS = {
    "intake": {"baseline", "fixing", "review", "paused"},
    "baseline": {"fixing", "review", "paused"},
    "fixing": {"review", "paused"},
    "review": {"fixing", "approved", "paused"},
    "approved": {"review", "pr_draft", "paused"},
    "pr_draft": {"review", "development", "paused"},
    "development": {"review", "verified", "paused"},
    "verified": {"closed", "review"},
    "paused": {"baseline", "fixing", "review"},
    "closed": set(),
}


def engagement(key: str):
    value = get_engagement_or_404(key)
    if value.engagement_type != "remediation":
        raise HTTPException(404, "Remediation engagement not found")
    return value


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _field(row, name: str, default=None):
    return row[name] if name in row.keys() else default


def _case_project(row, engagement_root: Path) -> dict[str, Any]:
    stored = _field(row, "review_policy_json")
    if stored:
        return json.loads(stored)
    return load_engagement_project(engagement_root)


def _sha256_stream(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def _sha256_file(path: Path) -> str:
    with path.open("rb") as source:
        return _sha256_stream(source)


def _duplicate_details(connection, row) -> list[dict[str, Any]]:
    current = dict(_duplicate_fingerprints(row))
    details: list[dict[str, Any]] = []
    for other in connection.execute(
        "SELECT id,source_key,title,snapshot_json FROM remediation_cases WHERE engagement_id=? AND id<>? ORDER BY id",
        (row["engagement_id"], row["id"]),
    ):
        reasons = [field for field, value in _duplicate_fingerprints(other) if current.get(field) == value]
        if reasons:
            details.append({"case_id": other["id"], "reasons": reasons})
    return details


def _duplicate_fingerprints(row) -> list[tuple[str, str]]:
    snapshot = json.loads(row["snapshot_json"])
    values = {"title": row["title"], "source_key": row["source_key"]}
    values.update({field: snapshot.get(field) for field in ("source_ref", "root_cause_key", "route", "report_id")})
    return [
        (field, value.strip().casefold())
        for field, value in values.items()
        if isinstance(value, str) and value.strip()
    ]


def _row(connection, engagement_id: int, case_id: int):
    row = connection.execute(
        "SELECT * FROM remediation_cases WHERE engagement_id=? AND id=?",
        (engagement_id, case_id),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Remediation case not found")
    return row


def _artifact(root: Path, case_id: int, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts or any(p in {"..", "."} for p in candidate.parts):
        raise HTTPException(400, "Artifact path must be engagement relative")
    if candidate.parts[:3] != ("remediation", "cases", str(case_id)):
        raise HTTPException(400, "Artifact must belong to this case")
    root = root.resolve(strict=True)
    path = root.joinpath(*candidate.parts)
    if any(part.is_symlink() for part in (root.joinpath(*candidate.parts[:n]) for n in range(1, len(candidate.parts) + 1))):
        raise HTTPException(400, "Artifact symlinks are not allowed")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(400, "Artifact does not exist") from None
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise HTTPException(400, "Artifact must be a file under the engagement")
    return resolved


def artifact_file(key: str, case_id: int, evidence_id: int) -> tuple[Path, BinaryIO]:
    owner = engagement(key)
    with db.get_connection() as connection:
        _row(connection, owner.id, case_id)
        evidence = connection.execute(
            "SELECT artifact_path, artifact_sha256 FROM remediation_evidence WHERE case_id=? AND id=?",
            (case_id, evidence_id),
        ).fetchone()
    if evidence is None or evidence["artifact_path"] is None:
        raise HTTPException(404, "Evidence file not found")
    path = _artifact(Path(owner.engagement_root), case_id, evidence["artifact_path"])
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        raise HTTPException(409, "Evidence file cannot be opened safely") from None
    source = os.fdopen(descriptor, "rb")
    if not stat.S_ISREG(os.fstat(source.fileno()).st_mode) or _sha256_stream(source) != evidence["artifact_sha256"]:
        source.close()
        raise HTTPException(409, "Evidence file changed since registration")
    source.seek(0)
    return path, source


def _worktree_digest(path_value: str | None) -> str:
    if not path_value:
        return ""
    root = Path(path_value)
    if not root.is_absolute() or not root.is_dir():
        return "unavailable"
    try:
        if _vcs.is_jj(root):
            # A jj commit already seals the complete snapshotted filesystem;
            # an empty child resolves to the same reviewed content commit.
            changed, changed_truncated = _vcs.revision(root).encode(), False
        else:
            changed, changed_truncated = _bounded_vcs_diff(str(root), "HEAD", limit=_REVIEW_DIFF_LIMIT)
        if changed_truncated:
            return "oversized"
        untracked = _vcs.untracked(root)
    except (OSError, ValueError, subprocess.SubprocessError):
        return "unavailable"
    digest = hashlib.sha256()
    digest.update(changed)
    remaining = _REVIEW_DIFF_LIMIT
    for label in sorted(item for item in untracked if item):
        path = root / os.fsdecode(label)
        digest.update(label + b"\0")
        if path.is_symlink():
            digest.update(b"SYMLINK\0" + os.fsencode(os.readlink(path)))
        else:
            try:
                size = path.stat().st_size
                if size > remaining:
                    # Approval cannot proceed with an oversized review file. Its
                    # size is sufficient to keep the blocked package distinct.
                    digest.update(b"OVERSIZED\0" + str(size).encode())
                    break
                with path.open("rb") as source:
                    raw = source.read(remaining + 1)
                if len(raw) > remaining:
                    digest.update(b"OVERSIZED\0" + str(len(raw)).encode())
                    break
                digest.update(raw)
                remaining -= len(raw)
            except OSError:
                return "unavailable"
        digest.update(b"\0")
    return digest.hexdigest()


def _actual_revision(path_value: str | None) -> str:
    if not path_value:
        return ""
    path = Path(path_value)
    try:
        if _vcs.root(path) != path.resolve():
            return ""
        return _vcs.revision(path)
    except (OSError, ValueError, subprocess.SubprocessError):
        return ""


def _worktree_clean(path_value: str) -> bool:
    try:
        return not _vcs.status(Path(path_value))
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


def _registered_worktree(repo: Path, path: Path) -> bool:
    return _vcs.registered(repo, path)


def _case_worktree_identity(row, engagement_root: Path) -> bool:
    if not (engagement_root / "PROJECT.md").exists() and not (engagement_root / "remediation-project.json").exists():
        return not row["worktree_branch"]
    if not row["worktree_branch"] or not row["worktree_path"]:
        return False
    try:
        repo_value = _case_project(row, engagement_root)["repository"]
        if not isinstance(repo_value, str) or not Path(repo_value).is_absolute():
            return False
        if not _registered_worktree(Path(repo_value), Path(row["worktree_path"])):
            return False
        return _vcs.branch_matches(Path(row["worktree_path"]), row["worktree_branch"])
    except (OSError, ValueError, KeyError, TypeError):
        return False


def _commit_ancestor(path_value: str | None, ancestor: str, descendant: str) -> bool:
    if not path_value or not ancestor or not descendant:
        return False
    try:
        return _vcs.ancestor(Path(path_value), ancestor, descendant)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False


_REVIEW_DIFF_LIMIT = 1024 * 1024


def _bounded_vcs_diff(path_value: str, *revisions: str, limit: int) -> tuple[bytes, bool]:
    command = _vcs.diff_command(Path(path_value), *revisions)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    assert process.stdout is not None
    deadline = time.monotonic() + 30
    output = bytearray()
    try:
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0 or not select.select([process.stdout], [], [], remaining_time)[0]:
                raise subprocess.TimeoutExpired(command, 30)
            chunk = os.read(process.stdout.fileno(), min(64 * 1024, limit + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > limit:
                return bytes(output[:limit]), True
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        if code:
            raise subprocess.CalledProcessError(code, command)
        return bytes(output), False
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()
        process.stdout.close()


def _review_patch(path_value: str | None, base_branch: str = "main", base_revision: str | None = None) -> tuple[str, str, bytes, bool, int]:
    head = _actual_revision(path_value)
    if not head or not path_value:
        raise HTTPException(409, "Case worktree has no confirmed revision")
    root = Path(path_value)
    try:
        base = _vcs.review_base(root, base_branch, base_revision) if base_revision or base_branch != "main" else _vcs.review_base(root)
        committed, committed_truncated = _bounded_vcs_diff(
            path_value, base, "HEAD", limit=_REVIEW_DIFF_LIMIT,
        )
        if committed_truncated:
            return base, head, committed, True, _REVIEW_DIFF_LIMIT + 1
        local, local_truncated = _bounded_vcs_diff(
            path_value, "HEAD", limit=max(0, _REVIEW_DIFF_LIMIT - len(committed) - 1),
        )
        if local_truncated:
            return base, head, (committed + b"\n" + local)[:_REVIEW_DIFF_LIMIT], True, _REVIEW_DIFF_LIMIT + 1
        untracked = _vcs.untracked(root)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise HTTPException(409, f"Cannot establish review diff against {base_branch}") from None
    chunks = [committed, local]
    total = len(committed) + len(local) + 1
    truncated = total > _REVIEW_DIFF_LIMIT
    bytes_total = total
    for label in sorted(item for item in untracked if item):
        if truncated:
            break
        file = root / os.fsdecode(label)
        name = os.fsdecode(label)
        if file.is_symlink():
            target = os.readlink(file)
            chunk = f"Untracked symlink: {name} -> {target}\n".encode()
        else:
            try:
                size = file.stat().st_size
                remaining = max(0, _REVIEW_DIFF_LIMIT - total - 1)
                if size > remaining:
                    chunk = f"Untracked file exceeds review limit: {name} ({size} bytes)\n".encode()
                    truncated = True
                    bytes_total = max(_REVIEW_DIFF_LIMIT + 1, total + size)
                else:
                    with file.open("rb") as source:
                        raw = source.read(remaining + 1)
                    if len(raw) > remaining:
                        chunk = f"Untracked file exceeds review limit: {name} (changed while reading)\n".encode()
                        truncated = True
                        bytes_total = _REVIEW_DIFF_LIMIT + 1
                    elif b"\0" in raw:
                        chunk = f"Binary untracked file: {name} ({len(raw)} bytes, sha256 {hashlib.sha256(raw).hexdigest()})\n".encode()
                    else:
                        content = raw.decode("utf-8", errors="replace").splitlines(keepends=True)
                        chunk = "".join(difflib.unified_diff([], content, fromfile="/dev/null", tofile=name)).encode()
            except OSError:
                raise HTTPException(409, f"Cannot read untracked review file: {name}") from None
        chunks.append(chunk)
        total += len(chunk) + 1
        if total > _REVIEW_DIFF_LIMIT:
            truncated = True
            bytes_total = max(bytes_total, total)
    whole = b"\n".join(chunks)
    return base, head, whole[:_REVIEW_DIFF_LIMIT], truncated, bytes_total if truncated else len(whole)


def review_diff(key: str, case_id: int) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        package = _details(connection, row, Path(owner.engagement_root))
    path_value = row["worktree_path"]
    if not path_value:
        raise HTTPException(409, "Case worktree is not registered")
    root = Path(path_value)
    expected = Path(owner.engagement_root).resolve() / "remediation" / "cases" / str(case_id)
    if not root.resolve().is_relative_to(expected) and not _case_worktree_identity(row, Path(owner.engagement_root)):
        raise HTTPException(409, "Case worktree is outside its case directory")
    base, head, whole, truncated, bytes_total = _row_review_patch(row)
    return {
        "text": whole.decode("utf-8", errors="replace"),
        "truncated": truncated,
        "bytes_total": bytes_total,
        "base_revision": base,
        "head_revision": head,
        "review_digest": package["review_digest"],
    }


def _row_review_patch(row):
    branch = _field(row, "base_branch")
    revision = _field(row, "base_revision")
    return _review_patch(row["worktree_path"], branch or "main", revision) if branch or revision else _review_patch(row["worktree_path"])


def _review_digest(row, evidence: list[dict[str, Any]], engagement_root: Path, finding_ids: list[int]) -> str:
    try:
        review_base, _, review_patch, patch_truncated, patch_size = _row_review_patch(row)
        patch_sha = hashlib.sha256(review_patch).hexdigest()
    except HTTPException:
        review_base, patch_sha, patch_size = "unavailable", "unavailable", -1
        patch_truncated = False
    artifact_state = []
    for item in evidence:
        if item["artifact_path"]:
            try:
                path = _artifact(engagement_root, row["id"], item["artifact_path"])
                artifact_state.append(_sha256_file(path))
            except (HTTPException, OSError):
                artifact_state.append("unavailable")
    material = {
        "title": row["title"],
        "snapshot": json.loads(row["snapshot_json"]),
        "finding_ids": finding_ids,
        "worktree_path": row["worktree_path"],
        "worktree_branch": row["worktree_branch"],
        "worktree_revision": row["worktree_revision"],
        "actual_worktree_revision": _actual_revision(row["worktree_path"]),
        "worktree_content_sha256": _worktree_digest(row["worktree_path"]),
        "review_base_revision": review_base,
        "review_patch_sha256": patch_sha,
        "review_patch_bytes": patch_size,
        "review_patch_truncated": patch_truncated,
        "verification_plan": row["verification_plan"],
        "baseline": json.loads(row["baseline_json"]),
        "release_plan": json.loads(row["release_plan_json"]),
        "evidence": [
            {key: value for key, value in item.items() if key not in {
                "environment", "execution", "executed_revision", "executed_directory", "shared_environment", "environment_token", "runtime_revision"
            } or value is not None}
            for item in evidence
        ],
        "current_artifact_sha256": artifact_state,
    }
    for field in ("base_branch", "base_revision", "review_policy_json", "verification_requirements_json"):
        if _field(row, field) is not None:
            material[field] = row[field]
    project_path = engagement_root / "PROJECT.md"
    if project_path.exists() or project_path.is_symlink():
        from assess.lib.remediation_project import load_engagement_project

        try:
            material["project"] = {
                "source_sha256": _sha256_file(project_path),
                "configuration": load_engagement_project(engagement_root),
            }
            if _field(row, "review_policy_json"):
                from assess.lib.remediation_project import policy_digest
                material["effective_policy_digest"] = policy_digest(json.loads(row["review_policy_json"]))
        except (OSError, ValueError):
            material["project"] = "unavailable"
    return hashlib.sha256(_json(material).encode()).hexdigest()


def _review_evidence_missing(row, evidence: list[dict[str, Any]], engagement_root: Path) -> list[str]:
    plan = _field(row, "verification_requirements_json")
    if plan is not None:
        missing = _explicit_evidence_missing(row, evidence, engagement_root, json.loads(plan))
    else:
        missing = _legacy_review_evidence_missing(row, evidence, engagement_root)
    return missing + _profile_checks_missing(row, evidence, engagement_root)


def _explicit_evidence_missing(row, evidence, engagement_root, plan):
    def satisfies(item, requirement):
        if (item["kind"] != requirement["kind"]
                or item["method"].casefold() not in {value.casefold() for value in requirement["methods"]}
                or item["outcome"] != requirement["outcome"]
                or item.get("execution") != requirement["execution"]
                or not item.get("artifact_path") or not item.get("revision")):
            return False
        if requirement["revision"] == "current" and item["revision"] != row["worktree_revision"]:
            return False
        if requirement["revision"] == "ancestor" and not _commit_ancestor(row["worktree_path"], item["revision"], row["worktree_revision"]):
            return False
        if requirement["execution"] == "executed" and (
            not item["command"].strip() or item.get("executed_revision") != item["revision"]
        ):
            return False
        if requirement.get("shared_environment") and item.get("shared_environment") != requirement["shared_environment"]:
            return False
        browser = item["method"].casefold() in {"stagehand", "browse"}
        if (requirement.get("runtime_identity_required") or browser) and not _evidence_runtime_confirmed(item):
            return False
        if not _evidence_current(engagement_root, row["id"], [item]):
            return False
        if browser:
            driver_evidence = [proof for proof in evidence if proof["method"].casefold() == item["method"].casefold()]
            purpose = requirement.get("browser_purpose") or "happy-path"
            if not item["artifact_path"].endswith("/result.json") or _browser_evidence_missing(
                row, driver_evidence, engagement_root, purpose=purpose,
                require_screenshot=purpose == "happy-path", result_path=item["artifact_path"],
            ):
                return False
        return bool(_artifact(engagement_root, row["id"], item["artifact_path"]).stat().st_size)

    missing = []
    for requirement in plan["requirements"]:
        if not any(satisfies(item, requirement) for item in evidence):
            missing.append(f"{requirement['kind']} ({requirement['execution']}, {requirement['revision']} revision)")
    return missing


def _profile_checks_missing(row, evidence, engagement_root):
    missing = []
    policy = json.loads(_field(row, "review_policy_json") or "{}")
    shared_environment = policy.get("remediation", {}).get("shared_environment", "")
    for check in policy.get("remediation", {}).get("check_commands", []):
        if not any(
            item["kind"] == "profile-check" and item["method"] == check["name"]
            and item["command"] == check["command"] and item.get("execution") == "executed"
            and item.get("revision") == row["worktree_revision"]
            and item.get("executed_revision") == row["worktree_revision"]
            and item.get("executed_directory") == str((Path(row["worktree_path"] or ".") / check.get("directory", ".")).resolve())
            and (not shared_environment or (item.get("shared_environment") == shared_environment and item.get("environment_token")))
            and item["outcome"] == "passed" and item.get("artifact_path")
            and _evidence_current(engagement_root, row["id"], [item])
            and _artifact(engagement_root, row["id"], item["artifact_path"]).stat().st_size
            for item in evidence
        ):
            missing.append(f"profile check: {check['name']}")
    return missing


def _legacy_review_evidence_missing(row, evidence: list[dict[str, Any]], engagement_root: Path) -> list[str]:
    case_id = row["id"]

    def valid_test(kind: str, outcome: str) -> bool:
        for item in evidence:
            if (item["kind"] != kind or (item["method"] or "").casefold() != "laravel"
                    or item["outcome"] != outcome or not item["command"].strip()
                    or not item["revision"] or not item["artifact_path"]
                    or item.get("execution") not in {None, "executed"}):
                continue
            if kind == "green-test" and item["revision"] != row["worktree_revision"]:
                continue
            if kind == "red-test" and not _commit_ancestor(
                row["worktree_path"], item["revision"], row["worktree_revision"]
            ):
                continue
            if _evidence_current(engagement_root, case_id, [item]):
                path = _artifact(engagement_root, case_id, item["artifact_path"])
                if path.stat().st_size:
                    return True
        return False

    missing = []
    if not valid_test("red-test", "failed_as_expected"):
        missing.append("red test with expected failure and saved Laravel output")
    if not valid_test("green-test", "passed"):
        missing.append("green test with passing Laravel output at current revision")
    return missing + _browser_evidence_missing(row, evidence, engagement_root)


def _browser_evidence_missing(row, evidence, engagement_root, *, purpose="happy-path", require_screenshot=True, result_path=None):
    case_id = row["id"]
    missing = []
    stagehand_result = False
    stagehand_script = False
    stagehand_screenshot = False
    registered = {item["artifact_path"]: item for item in evidence if item["artifact_path"]}
    for item in evidence:
        artifact = item["artifact_path"] or ""
        driver = (item["method"] or "").casefold()
        if (driver not in {"stagehand", "browse"} or item["kind"] != driver
                or not artifact.endswith("/result.json") or not item["command"].strip()
                or (result_path is not None and artifact != result_path)
                or item["revision"] != row["worktree_revision"]
                or item.get("execution") not in {None, "executed"}):
            continue
        if not _evidence_current(engagement_root, case_id, [item]):
            continue
        try:
            result = json.loads(_artifact(engagement_root, case_id, artifact).read_text(encoding="utf-8"))
        except (HTTPException, OSError, UnicodeError, json.JSONDecodeError):
            continue
        if not isinstance(result, dict):
            continue
        steps = result.get("steps")
        if (result.get("status") != "passed" or result.get("purpose") != purpose
                or not str(result.get("observed") or "").strip()
                or not str(result.get("proved") or "").strip()
                or not isinstance(steps, list) or not steps
                or not all(isinstance(step, dict) and str(step.get("action") or "").strip()
                           and str(step.get("observation") or "").strip() for step in steps)):
            continue
        parent = str(Path(artifact).parent)
        if driver == "browse":
            transcript = registered.get(f"{parent}/commands.json")
            if (result.get("served_revision") != row["worktree_revision"] or not transcript
                    or transcript["method"].casefold() != driver
                    or transcript["revision"] != row["worktree_revision"]
                    or not _evidence_current(engagement_root, case_id, [transcript])):
                continue
            try:
                commands = json.loads(_artifact(engagement_root, case_id, transcript["artifact_path"]).read_text(encoding="utf-8"))
            except (HTTPException, OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(commands, list) or not commands or not all(
                isinstance(command, dict) and command.get("returncode") == 0
                and isinstance(command.get("argv"), list) and command["argv"]
                and command["argv"][0] == "browse"
                and ("--local" in command["argv"] or "--cdp" in command["argv"]
                     or (len(command["argv"]) == 4
                         and command["argv"][:3] == ["browse", "stop", "--session"]
                         and isinstance(command["argv"][3], str) and command["argv"][3]))
                and isinstance(command.get("stdout"), str) and isinstance(command.get("stderr"), str)
                for command in commands
            ):
                continue
            if not any(command["argv"][1] != "stop" for command in commands if len(command["argv"]) > 1):
                continue
        stagehand_result = True
        script = registered.get(f"{parent}/script.py")
        stagehand_script = bool(script and script["method"].casefold() == driver
                                and script["revision"] == row["worktree_revision"]
                                and _evidence_current(engagement_root, case_id, [script])
                                and _artifact(engagement_root, case_id, script["artifact_path"]).stat().st_size)
        stagehand_screenshot = any(
            path.startswith(f"{parent}/") and Path(path).suffix.lower() in {".png", ".jpg", ".jpeg"}
            and proof["kind"] == "screenshot" and proof["method"].casefold() == driver
            and proof["revision"] == row["worktree_revision"]
            and _evidence_current(engagement_root, case_id, [proof])
            and _valid_screenshot(_artifact(engagement_root, case_id, path))
            for path, proof in registered.items()
        )
        if stagehand_script and (stagehand_screenshot or not require_screenshot):
            break
    if not stagehand_result:
        missing.append(f"passed browser {purpose} result.json at current revision")
    if not stagehand_script:
        missing.append("registered browser script.py")
    if require_screenshot and not stagehand_screenshot:
        missing.append("registered browser screenshot")
    return missing


def _valid_screenshot(path: Path) -> bool:
    size = path.stat().st_size
    if size <= 32:
        return False
    with path.open("rb") as source:
        head = source.read(24)
        source.seek(-8, os.SEEK_END)
        tail = source.read(8)
    if path.suffix.lower() == ".png":
        return (head.startswith(b"\x89PNG\r\n\x1a\n") and head[12:16] == b"IHDR"
                and int.from_bytes(head[16:20], "big") > 0
                and int.from_bytes(head[20:24], "big") > 0 and tail[:4] == b"IEND")
    return path.suffix.lower() in {".jpg", ".jpeg"} and head.startswith(b"\xff\xd8") and tail.endswith(b"\xff\xd9")


def _details(connection, row, engagement_root: Path):
    case_id = row["id"]
    evidence = [dict(item) for item in connection.execute(
        "SELECT * FROM remediation_evidence WHERE case_id=? ORDER BY id", (case_id,)
    )]
    approvals = [dict(item) for item in connection.execute(
        "SELECT * FROM remediation_approvals WHERE case_id=? ORDER BY id", (case_id,)
    )]
    transitions = [dict(item) for item in connection.execute(
        "SELECT * FROM remediation_transitions WHERE case_id=? ORDER BY id", (case_id,)
    )]
    deployment = connection.execute(
        "SELECT * FROM remediation_deployments WHERE case_id=? ORDER BY id DESC LIMIT 1", (case_id,)
    ).fetchone()
    human_verifications = [dict(item) for item in connection.execute(
        "SELECT * FROM remediation_human_verifications WHERE case_id=? ORDER BY id", (case_id,)
    )]
    hint_details = _duplicate_details(connection, row)
    linked_findings = _linked_findings(connection, case_id)
    finding_ids = [item["id"] for item in linked_findings]
    digest = _review_digest(row, evidence, engagement_root, finding_ids)
    approved_evidence = (
        [item for item in evidence if item["id"] <= approvals[-1]["evidence_cutoff_id"]]
        if approvals else []
    )
    approval_digest = (
        _review_digest(row, approved_evidence, engagement_root, finding_ids)
        if approvals else None
    )
    result = dict(row)
    result["linked_findings"] = linked_findings
    result["snapshot"] = json.loads(result.pop("snapshot_json"))
    result["baseline"] = json.loads(result.pop("baseline_json"))
    result["release_plan"] = json.loads(result.pop("release_plan_json"))
    if "coralogix_monitoring" in result["release_plan"] and "monitoring" not in result["release_plan"]:
        result["release_plan"]["monitoring"] = result["release_plan"]["coralogix_monitoring"]
    result["review_policy"] = json.loads(result.pop("review_policy_json") or "null")
    result["verification_requirements"] = json.loads(result.pop("verification_requirements_json") or "null")
    result["source_resolved"] = result["source_type"] != "reference"
    result["duplicate_hints"] = [hint["case_id"] for hint in hint_details]
    result["duplicate_hint_details"] = hint_details
    result["evidence"] = evidence
    result["approvals"] = approvals
    result["transitions"] = transitions
    result["deployment"] = dict(deployment) if deployment else None
    result["human_verifications"] = human_verifications
    result["environment_leases"] = [dict(item) for item in connection.execute(
        "SELECT * FROM remediation_environment_leases WHERE case_id=? ORDER BY acquired_at,token", (case_id,),
    )]
    result["review_digest"] = digest
    result["review_evidence_missing"] = _review_evidence_missing(row, evidence, engagement_root)
    result["review_evidence_ready"] = not result["review_evidence_missing"]
    approved_evidence_missing = (
        result["review_evidence_missing"] if len(approved_evidence) == len(evidence)
        else _review_evidence_missing(row, approved_evidence, engagement_root)
    )
    result["approval_current"] = bool(
        approvals and approvals[-1]["review_digest"] == approval_digest
        and not approved_evidence_missing
        and _case_worktree_identity(row, engagement_root)
    )
    return result


def list_cases(key: str) -> list[dict[str, Any]]:
    owner = engagement(key)
    with db.get_connection() as connection:
        rows = connection.execute(
            "SELECT * FROM remediation_cases WHERE engagement_id=? ORDER BY updated_at DESC, id DESC",
            (owner.id,),
        ).fetchall()
        fingerprints: dict[int, list[tuple[str, str]]] = {
            row["id"]: _duplicate_fingerprints(row) for row in rows
        }
        index: dict[tuple[str, str], list[int]] = {}
        for case_id, values in fingerprints.items():
            for value in values:
                index.setdefault(value, []).append(case_id)
        summaries = []
        for row in rows:
            reasons_by_id: dict[int, list[str]] = {}
            for field, value in fingerprints[row["id"]]:
                for other_id in index[(field, value)]:
                    if other_id != row["id"]:
                        reasons_by_id.setdefault(other_id, []).append(field)
            details = [
                {"case_id": other_id, "reasons": reasons}
                for other_id, reasons in sorted(reasons_by_id.items())
            ]
            approved = connection.execute(
                "SELECT 1 FROM remediation_approvals WHERE case_id=? LIMIT 1", (row["id"],)
            ).fetchone() is not None
            summaries.append({
                "id": row["id"],
                "engagement_id": row["engagement_id"],
                "source_type": row["source_type"],
                "source_key": row["source_key"],
                "title": row["title"],
                "status": row["status"],
                "linked_findings": _linked_findings(connection, row["id"]),
                "worktree_path": row["worktree_path"],
                "worktree_branch": row["worktree_branch"],
                "worktree_revision": row["worktree_revision"],
                "base_branch": row["base_branch"],
                "base_revision": row["base_revision"],
                "baseline_outcome": json.loads(row["baseline_json"]).get("outcome", "pending"),
                "production_canary_decision": json.loads(row["release_plan_json"]).get("production_canary_decision"),
                "approval_recorded": approved,
                "duplicate_hints": [hint["case_id"] for hint in details],
                "duplicate_hint_details": details,
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })
        return summaries


def get_case(key: str, case_id: int) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        return _details(connection, _row(connection, owner.id, case_id), Path(owner.engagement_root))


def create_case(key: str, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        finding_ids = _validate_finding_ids(connection, data.get("finding_ids", []))
        exists = connection.execute(
            "SELECT id FROM remediation_cases WHERE engagement_id=? AND source_type=? AND source_key=?",
            (owner.id, data["source_type"], data["source_key"]),
        ).fetchone()
        if exists:
            raise HTTPException(409, {"message": "Source already has a remediation case", "existing_case_id": exists["id"]})
        cursor = connection.execute(
            "INSERT INTO remediation_cases(engagement_id,source_type,source_key,title,snapshot_json) VALUES(?,?,?,?,?)",
            (owner.id, data["source_type"], data["source_key"], data["title"],
             _json(data["snapshot"])),
        )
        connection.executemany("INSERT INTO remediation_case_findings(case_id,finding_id) VALUES(?,?)", [(cursor.lastrowid, finding_id) for finding_id in finding_ids])
        return _details(connection, _row(connection, owner.id, cursor.lastrowid), Path(owner.engagement_root))


def resolve_source(key: str, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    if data["source_type"] == "reference":
        raise HTTPException(400, "Resolved source must identify the actual report provider")
    with db.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        old = _row(connection, owner.id, case_id)
        if old["source_type"] != "reference" or old["status"] != "intake" or old["worktree_path"]:
            raise HTTPException(409, "Only pending intake can resolve its source")
        existing = connection.execute(
            "SELECT id FROM remediation_cases WHERE engagement_id=? AND source_type=? AND source_key=? AND id<>?",
            (owner.id, data["source_type"], data["source_key"], case_id),
        ).fetchone()
        if existing:
            raise HTTPException(409, {"message": "Source already has a remediation case", "existing_case_id": existing["id"]})
        finding_ids = _validate_finding_ids(connection, data.get("finding_ids", []))
        snapshot = dict(data["snapshot"])
        snapshot["intake_reference"] = {"source_key": old["source_key"], "snapshot": json.loads(old["snapshot_json"])}
        connection.execute(
            "UPDATE remediation_cases SET source_type=?,source_key=?,title=?,snapshot_json=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (data["source_type"], data["source_key"], data["title"], _json(snapshot), case_id),
        )
        connection.executemany("INSERT OR IGNORE INTO remediation_case_findings(case_id,finding_id) VALUES(?,?)", [(case_id, finding_id) for finding_id in finding_ids])
        return _details(connection, _row(connection, owner.id, case_id), Path(owner.engagement_root))


def _finding(connection, engagement_key: str, slug: str):
    slug = canonical_finding_alias(slug) or slug
    row = connection.execute(
        "SELECT f.*,e.key AS engagement_key FROM assessment_findings f JOIN engagements e ON e.id=f.engagement_id WHERE e.key=? AND f.slug=?",
        (engagement_key, slug),
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Finding does not exist in the named engagement")
    return row


def _linked_findings(connection, case_id: int) -> list[dict[str, Any]]:
    return [dict(row) for row in connection.execute(
        "SELECT f.id,e.key AS engagement_key,f.slug,f.title,f.severity,f.verification_status,f.root_cause_key "
        "FROM remediation_case_findings l JOIN assessment_findings f ON f.id=l.finding_id "
        "JOIN engagements e ON e.id=f.engagement_id WHERE l.case_id=? ORDER BY f.id", (case_id,),
    )]


def _validate_finding_ids(connection, finding_ids: list[int]) -> list[int]:
    unique = sorted(set(finding_ids))
    for finding_id in unique:
        if connection.execute("SELECT 1 FROM assessment_findings WHERE id=?", (finding_id,)).fetchone() is None:
            raise HTTPException(400, f"Linked finding {finding_id} does not exist")
    return unique


def finding_cases(key: str, slug: str) -> list[dict[str, Any]]:
    get_engagement_or_404(key)
    with db.get_connection() as connection:
        finding = _finding(connection, key, slug)
        rows = connection.execute(
            "SELECT c.id,e.key AS engagement_key,c.title,c.status,c.worktree_path,c.worktree_branch,c.worktree_revision "
            "FROM remediation_case_findings l JOIN remediation_cases c ON c.id=l.case_id "
            "JOIN engagements e ON e.id=c.engagement_id WHERE l.finding_id=? ORDER BY c.updated_at DESC,c.id DESC", (finding["id"],),
        ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            deployed = connection.execute("SELECT * FROM remediation_deployments WHERE case_id=? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
            item["latest_deployment"] = dict(deployed) if deployed else None
            item["linked_findings"] = _linked_findings(connection, row["id"])
            result.append(item)
        return result


def create_from_finding(key: str, slug: str, destination_key: str, title: str | None = None) -> dict[str, Any]:
    get_engagement_or_404(key)
    engagement(destination_key)
    with db.get_connection() as connection:
        finding = dict(_finding(connection, key, slug))
        snapshot = {"source_engagement_key": key, "finding": finding}
        result = create_case(destination_key, {
            "source_type": "finding", "source_key": str(finding["id"]),
            "title": title or finding["title"], "snapshot": snapshot, "finding_ids": [finding["id"]],
        })
        result["engagement_key"] = destination_key
        return result


def patch_case(key: str, case_id: int, changes: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        old = _row(connection, owner.id, case_id)
        if old["status"] == "closed":
            raise HTTPException(409, "Closed remediation cases cannot be changed")
        changes = dict(changes)
        if ("verification_plan" in changes and not (old["verification_plan"] or "").strip()
                and not changes.get("verification_requirements_json")):
            raise HTTPException(400, "The first verification plan requires explicit evidence requirements and a reason")
        finding_ids = _validate_finding_ids(connection, changes.pop("finding_ids")) if "finding_ids" in changes else None
        if "worktree_path" in changes and changes["worktree_path"]:
            path = Path(changes["worktree_path"])
            if not path.is_absolute() or not path.is_dir():
                raise HTTPException(400, "Worktree path must be an existing absolute directory")
            expected = Path(owner.engagement_root).resolve() / "remediation" / "cases" / str(case_id)
            engagement_root = Path(owner.engagement_root)
            has_project = (engagement_root / "PROJECT.md").exists() or (engagement_root / "remediation-project.json").exists()
            if not path.resolve().is_relative_to(expected) and not has_project:
                raise HTTPException(400, "Worktree must belong to this case")
            if old["worktree_path"] and path.resolve() != Path(old["worktree_path"]).resolve():
                raise HTTPException(409, "Case worktree path is already registered")
            for other in connection.execute("SELECT id,worktree_path FROM remediation_cases WHERE id<>? AND worktree_path IS NOT NULL", (case_id,)):
                if Path(other["worktree_path"]).resolve() == path.resolve():
                    raise HTTPException(409, "Worktree is already owned by another remediation case")
            if has_project:
                try:
                    config = _case_project(old, engagement_root)
                    repo_value = config["repository"]
                except (OSError, ValueError, KeyError, TypeError):
                    raise HTTPException(400, "Remediation project repository is invalid") from None
                if not isinstance(repo_value, str) or not Path(repo_value).is_absolute() or not _registered_worktree(Path(repo_value), path):
                    raise HTTPException(400, "Worktree is not registered with the remediation repository")
                if not (changes.get("worktree_branch") or old["worktree_branch"]):
                    raise HTTPException(400, "Worktree branch is required for this remediation project")
                if old["review_policy_json"] is None:
                    changes["review_policy_json"] = _json(config)
                    changes.setdefault("base_branch", config.get("base_branch") or "main")
        for field in ("base_branch", "base_revision"):
            if field in changes:
                value = changes[field]
                if not isinstance(value, str) or not value.strip():
                    raise HTTPException(400, f"{field} must be nonempty")
                if old[field] and old[field] != value:
                    raise HTTPException(409, f"Case {field} is immutable")
        if changes.get("base_branch") or changes.get("base_revision"):
            path_value = changes.get("worktree_path") or old["worktree_path"]
            if not path_value:
                raise HTTPException(400, "Worktree path is required to register a review base")
            try:
                base = _vcs.review_base(Path(path_value), changes.get("base_branch") or old["base_branch"] or "main",
                                        changes.get("base_revision") or old["base_revision"])
            except (OSError, ValueError, subprocess.SubprocessError):
                raise HTTPException(400, "Case review base cannot be resolved in its worktree") from None
            changes["base_revision"] = base
        if "worktree_branch" in changes:
            branch = changes["worktree_branch"]
            if not isinstance(branch, str) or not branch.strip():
                raise HTTPException(400, "Worktree branch must be nonempty")
            if old["worktree_branch"] and branch != old["worktree_branch"]:
                raise HTTPException(409, "Case worktree branch is already registered")
        branch = changes.get("worktree_branch") or old["worktree_branch"]
        if branch and any(field in changes for field in ("worktree_path", "worktree_branch", "worktree_revision")):
            path_value = changes.get("worktree_path") or old["worktree_path"]
            if not path_value:
                raise HTTPException(400, "Worktree path is required to register a branch")
            if not _vcs.branch_matches(Path(path_value), branch):
                status = 409 if old["worktree_branch"] else 400
                raise HTTPException(status, "Worktree branch differs from checkout branch")
        if old["worktree_branch"] and "worktree_revision" in changes:
            if not _case_worktree_identity(old, Path(owner.engagement_root)):
                raise HTTPException(409, "Case worktree is no longer registered with its repository")
        if "worktree_revision" in changes and old["base_revision"] and "base_revision" not in changes:
            changes.update(_advanced_base(old, changes.get("worktree_path") or old["worktree_path"]))
        if finding_ids is not None:
            connection.execute("DELETE FROM remediation_case_findings WHERE case_id=?", (case_id,))
            connection.executemany("INSERT INTO remediation_case_findings(case_id,finding_id) VALUES(?,?)", [(case_id, finding_id) for finding_id in finding_ids])
        if changes or finding_ids is not None:
            columns = ", ".join([f"{field}=?" for field in changes] + ["updated_at=CURRENT_TIMESTAMP"])
            connection.execute(
                f"UPDATE remediation_cases SET {columns} WHERE id=?",
                (*changes.values(), case_id),
            )
        return _details(connection, _row(connection, owner.id, case_id), Path(owner.engagement_root))


def patch_baseline(key: str, case_id: int, data: dict[str, str | None]) -> dict[str, Any]:
    if data["outcome"] != "runtime_reproduced" and data.get("owner_decision") == "proceed":
        if not data.get("owner_actor") or not data.get("owner_reason"):
            raise HTTPException(400, "Owner decision needs actor and reason")
    return patch_case(key, case_id, {"baseline_json": _json(data)})


def patch_verification_plan(key: str, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
    changes = {"verification_plan": data["verification_plan"]}
    if "requirements" in data:
        if not data["requirements"] or not data.get("alternatives_reason", "").strip():
            raise HTTPException(400, "Verification alternatives require evidence requirements and a reason")
        changes["verification_requirements_json"] = _json({
            "requirements": data["requirements"], "alternatives_reason": data["alternatives_reason"],
        })
    return patch_case(key, case_id, changes)


def patch_release_plan(key: str, case_id: int, data: dict[str, str]) -> dict[str, Any]:
    if "coralogix_monitoring" in data and "monitoring" not in data:
        data = {**data, "monitoring": data["coralogix_monitoring"]}
    return patch_case(key, case_id, {"release_plan_json": _json(data)})


def _advanced_base(old, path_value: str | None) -> dict[str, str]:
    """Move the review base forward when the case was rebased onto a newer base branch."""
    if not path_value:
        return {}
    path = Path(path_value)
    try:
        current = _vcs.review_base(path, old["base_branch"] or "main")
        moved = _vcs.ancestor(path, old["base_revision"], current)
    except (OSError, ValueError, subprocess.SubprocessError):
        return {}
    return {"base_revision": current} if moved else {}


def _evidence_current(engagement_root: Path, case_id: int, evidence: list[dict[str, Any]]) -> bool:
    for item in evidence:
        if not item["artifact_path"]:
            continue
        try:
            path = _artifact(engagement_root, case_id, item["artifact_path"])
            if _sha256_file(path) != item["artifact_sha256"]:
                return False
        except (HTTPException, OSError):
            return False
    return True


def _evidence_revision(path_value: str | None, revision: str) -> str:
    if not path_value or not revision.strip():
        raise HTTPException(400, "Evidence revision must identify a commit in the case worktree")
    try:
        return _vcs.resolve_revision(Path(path_value), revision)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise HTTPException(400, "Evidence revision must identify a commit in the case worktree") from None


def _environment_scope(row, engagement_root: Path) -> str:
    try:
        repository = _case_project(row, engagement_root).get("repository")
    except (OSError, ValueError):
        repository = None
    return str(Path(repository).resolve()) if repository else str(engagement_root.resolve())


def _owned_environment(connection, row, engagement_root: Path, environment: str, token: str | None, revision: str | None):
    lease = connection.execute(
        "SELECT * FROM remediation_environment_leases WHERE scope=? AND environment=? AND released_at IS NULL",
        (_environment_scope(row, engagement_root), environment),
    ).fetchone()
    if not lease or lease["case_id"] != row["id"] or lease["token"] != token or lease["revision"] != revision:
        raise HTTPException(409, "Shared environment is not owned by this case at the evidence revision")
    return lease


def _evidence_runtime_confirmed(item) -> bool:
    if (not item.get("shared_environment") or not item.get("environment_token") or not item.get("revision")
            or item.get("runtime_revision") != item["revision"]):
        return False
    with db.get_connection() as connection:
        return connection.execute(
            "SELECT 1 FROM remediation_environment_leases WHERE token=? AND case_id=? AND environment=? AND revision=? AND observed_revision=?",
            (item["environment_token"], item["case_id"], item["shared_environment"], item["revision"], item["revision"]),
        ).fetchone() is not None


def acquire_environment(key: str, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = _row(connection, owner.id, data["case_id"])
        if row["status"] == "closed" or not _case_worktree_identity(row, Path(owner.engagement_root)):
            raise HTTPException(409, "Shared testing requires an open case and registered workspace")
        revision = _evidence_revision(row["worktree_path"], data["revision"])
        if revision != row["worktree_revision"] or revision != _actual_revision(row["worktree_path"]):
            raise HTTPException(409, "Shared testing revision differs from the current case workspace")
        if not _worktree_clean(row["worktree_path"]):
            raise HTTPException(409, "Shared testing requires committed case source")
        scope = _environment_scope(row, Path(owner.engagement_root))
        current = connection.execute(
            "SELECT * FROM remediation_environment_leases WHERE scope=? AND environment=? AND released_at IS NULL",
            (scope, data["environment"]),
        ).fetchone()
        if current:
            if current["case_id"] == row["id"] and current["revision"] == revision and current["actor"] == data["actor"]:
                return {**dict(current), "created": False}
            raise HTTPException(409, {"message": "Shared environment is already owned", "case_id": current["case_id"], "revision": current["revision"]})
        token = secrets.token_hex(24)
        connection.execute(
            "INSERT INTO remediation_environment_leases(scope,environment,case_id,revision,actor,token) VALUES(?,?,?,?,?,?)",
            (scope, data["environment"], row["id"], revision, data["actor"], token),
        )
        return {**dict(connection.execute("SELECT * FROM remediation_environment_leases WHERE token=?", (token,)).fetchone()), "created": True}


def release_environment(key: str, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = _row(connection, owner.id, data["case_id"])
        lease = connection.execute(
            "SELECT * FROM remediation_environment_leases WHERE scope=? AND environment=? AND released_at IS NULL",
            (_environment_scope(row, Path(owner.engagement_root)), data["environment"]),
        ).fetchone()
        if not lease or lease["case_id"] != row["id"] or lease["token"] != data["token"]:
            raise HTTPException(409, "Only the owning case and lease token can release a shared environment")
        connection.execute(
            "UPDATE remediation_environment_leases SET released_at=CURRENT_TIMESTAMP,released_by=? WHERE token=?",
            (data["actor"], data["token"]),
        )
        return dict(connection.execute("SELECT * FROM remediation_environment_leases WHERE token=?", (data["token"],)).fetchone())


def confirm_environment(key: str, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = _row(connection, owner.id, data["case_id"])
        observed = _evidence_revision(row["worktree_path"], data["observed_revision"])
        lease = _owned_environment(connection, row, Path(owner.engagement_root), data["environment"], data["token"], observed)
        if observed != row["worktree_revision"] or observed != _actual_revision(row["worktree_path"]) or not _worktree_clean(row["worktree_path"]):
            raise HTTPException(409, "Served runtime revision differs from current committed case source")
        if lease["observed_revision"] is None:
            connection.execute(
                "UPDATE remediation_environment_leases SET observed_revision=?,confirmed_at=CURRENT_TIMESTAMP,confirmed_by=? WHERE token=?",
                (observed, data["actor"], data["token"]),
            )
        return dict(connection.execute("SELECT * FROM remediation_environment_leases WHERE token=?", (data["token"],)).fetchone())


def add_evidence(key: str, case_id: int, data: dict[str, Any]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        if row["status"] == "closed":
            raise HTTPException(409, "Closed remediation cases cannot be changed")
        revision = data.get("revision")
        if revision is not None:
            revision = _evidence_revision(row["worktree_path"], revision)
        execution = data.get("execution", "executed")
        executed_revision = data.get("executed_revision")
        if executed_revision is not None:
            executed_revision = _evidence_revision(row["worktree_path"], executed_revision)
            if execution != "executed" or executed_revision != revision:
                raise HTTPException(400, "Executed revision must match the evidence revision and executed evidence")
        executed_directory = data.get("executed_directory")
        if executed_directory is not None:
            directory = Path(executed_directory)
            if execution != "executed" or not directory.is_absolute() or not directory.is_dir():
                raise HTTPException(400, "Executed directory must identify the actual absolute command working directory")
            executed_directory = str(directory.resolve())
        runtime_revision = None
        if data.get("shared_environment"):
            lease = _owned_environment(connection, row, Path(owner.engagement_root), data["shared_environment"],
                                       data.get("environment_token"), revision)
            if data["method"].casefold() in {"stagehand", "browse"} and lease["observed_revision"] != revision:
                raise HTTPException(409, "Browser evidence requires confirmed served runtime revision")
            runtime_revision = lease["observed_revision"]
        artifact_sha = None
        if data.get("artifact_path"):
            artifact_sha = _sha256_file(_artifact(Path(owner.engagement_root), case_id, data["artifact_path"]))
        cursor = connection.execute(
            "INSERT INTO remediation_evidence(case_id,kind,method,environment,command,observed,proved,outcome,artifact_path,artifact_sha256,revision,execution,executed_revision,executed_directory,shared_environment,environment_token,runtime_revision) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (case_id, data["kind"], data["method"], data["environment"], data.get("command", ""), data["observed"],
             data["proved"], data.get("outcome"), data.get("artifact_path"), artifact_sha, revision,
             execution, executed_revision, executed_directory, data.get("shared_environment"), data.get("environment_token"), runtime_revision),
        )
        return dict(connection.execute("SELECT * FROM remediation_evidence WHERE id=?", (cursor.lastrowid,)).fetchone())


def approve(
    key: str, case_id: int, reviewer: str, expected_review_digest: str,
    approval_method: str, owner_instruction: str | None,
) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        if row["status"] != "review" or not row["worktree_revision"] or not row["worktree_path"] or not row["verification_plan"]:
            raise HTTPException(409, "Case needs review status, worktree identity, and verification plan")
        if not _case_worktree_identity(row, Path(owner.engagement_root)):
            raise HTTPException(409, "Case worktree identity differs from registered repository and branch")
        baseline = json.loads(row["baseline_json"])
        if baseline.get("outcome") not in {"runtime_reproduced", "code_test_confirmed", "unreproduced"}:
            raise HTTPException(409, "Baseline outcome has not been recorded")
        if baseline["outcome"] != "runtime_reproduced" and not (
            baseline.get("owner_decision") == "proceed" and baseline.get("owner_actor") and baseline.get("owner_reason")
        ):
            raise HTTPException(409, "Case owner must decide whether to proceed without runtime reproduction")
        if _actual_revision(row["worktree_path"]) != row["worktree_revision"]:
            raise HTTPException(409, "Claimed revision differs from worktree HEAD")
        if not _worktree_clean(row["worktree_path"]):
            raise HTTPException(409, "Commit or remove worktree changes before approval")
        if row["source_type"] == "reference":
            raise HTTPException(409, "Pending source must be resolved before approval")
        _, _, _, review_truncated, _ = _row_review_patch(row)
        if review_truncated:
            raise HTTPException(409, "Review diff is truncated; split or narrow the change before approval")
        package = _details(connection, row, Path(owner.engagement_root))
        if package["review_digest"] != expected_review_digest:
            raise HTTPException(409, "Review package changed since it was presented")
        if package["review_evidence_missing"]:
            raise HTTPException(409, "Review evidence incomplete: " + "; ".join(package["review_evidence_missing"]))
        if not _evidence_current(Path(owner.engagement_root), case_id, package["evidence"]):
            raise HTTPException(409, "Evidence file changed since registration")
        cutoff = max((item["id"] for item in package["evidence"]), default=0)
        cursor = connection.execute(
            "INSERT INTO remediation_approvals(case_id,reviewer,review_digest,approved_revision,evidence_cutoff_id,approval_method,owner_instruction) VALUES(?,?,?,?,?,?,?)",
            (case_id, reviewer, package["review_digest"], row["worktree_revision"], cutoff,
             approval_method, owner_instruction if approval_method == "cli_instruction" else None),
        )
        connection.execute("UPDATE remediation_cases SET status='approved',updated_at=CURRENT_TIMESTAMP WHERE id=?", (case_id,))
        connection.execute(
            "INSERT INTO remediation_transitions(case_id,from_status,to_status,actor,reason) VALUES(?,?,?,?,?)",
            (case_id, "review", "approved", reviewer, "Reviewed code and verification plan"),
        )
        return dict(connection.execute("SELECT * FROM remediation_approvals WHERE id=?", (cursor.lastrowid,)).fetchone())


def transition(key: str, case_id: int, status: str, actor: str, reason: str) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        if status not in TRANSITIONS[row["status"]] or status == "approved":
            raise HTTPException(409, "Invalid remediation transition")
        if status in {"pr_draft", "development", "verified", "closed"}:
            package = _details(connection, row, Path(owner.engagement_root))
            if not package["approval_current"]:
                raise HTTPException(409, "Review approval is no longer current")
        if status == "pr_draft":
            release = json.loads(row["release_plan_json"])
            if release.get("production_canary_decision") not in {"required", "not_required"} or not release.get("production_canary_rationale") or not (release.get("monitoring") or release.get("coralogix_monitoring")):
                raise HTTPException(409, "Production canary decision and monitoring plan are required")
            if release["production_canary_decision"] == "required" and not release.get("safe_procedure"):
                raise HTTPException(409, "Production canary procedure is required")
        if status == "verified":
            deployed = connection.execute(
                "SELECT id,approval_id,expected_revision,observed_revision FROM remediation_deployments WHERE case_id=? AND environment='development' ORDER BY id DESC LIMIT 1",
                (case_id,),
            ).fetchone()
            approval = package["approvals"][-1]
            approved_revision = approval["approved_revision"]
            if (not deployed or deployed["approval_id"] != approval["id"]
                    or deployed["expected_revision"] != approved_revision
                    or deployed["observed_revision"] != approved_revision):
                raise HTTPException(409, "Development revision is not verified")
            human = connection.execute(
                "SELECT result,observed_revision FROM remediation_human_verifications WHERE case_id=? AND deployment_id=? ORDER BY id DESC LIMIT 1",
                (case_id, deployed["id"]),
            ).fetchone()
            if human is None or human["result"] != "passed" or human["observed_revision"] != approved_revision:
                raise HTTPException(409, "Human development verification has not passed")
        connection.execute("UPDATE remediation_cases SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (status, case_id))
        connection.execute(
            "INSERT INTO remediation_transitions(case_id,from_status,to_status,actor,reason) VALUES(?,?,?,?,?)",
            (case_id, row["status"], status, actor, reason),
        )
        return _details(connection, _row(connection, owner.id, case_id), Path(owner.engagement_root))


def deployment(key: str, case_id: int, data: dict[str, str]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        if data["environment"] != "development":
            raise HTTPException(400, "Only development deployments are supported")
        package = _details(connection, row, Path(owner.engagement_root))
        approvals = package["approvals"]
        if row["status"] != "development" or not package["approval_current"] or not approvals:
            raise HTTPException(409, "Current approval and development status are required")
        approved_revision = approvals[-1]["approved_revision"]
        if data["expected_revision"] != approved_revision or data["observed_revision"] != approved_revision:
            raise HTTPException(409, "Deployed revision does not match approved revision")
        cursor = connection.execute(
            "INSERT INTO remediation_deployments(case_id,approval_id,workflow,run_id,environment,expected_revision,observed_revision,actor) VALUES(?,?,?,?,?,?,?,?)",
            (case_id, approvals[-1]["id"], data["workflow"], data["run_id"], data["environment"],
             data["expected_revision"], data["observed_revision"], data["actor"]),
        )
        return dict(connection.execute("SELECT * FROM remediation_deployments WHERE id=?", (cursor.lastrowid,)).fetchone())


def human_verification(key: str, case_id: int, data: dict[str, str]) -> dict[str, Any]:
    owner = engagement(key)
    with db.get_connection() as connection:
        row = _row(connection, owner.id, case_id)
        approval = connection.execute(
            "SELECT id,approved_revision FROM remediation_approvals WHERE case_id=? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        deployed = connection.execute(
            "SELECT * FROM remediation_deployments WHERE case_id=? AND environment='development' ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        if row["status"] != "development" or deployed is None or approval is None:
            raise HTTPException(409, "Confirmed development deployment is required")
        if (deployed["approval_id"] != approval["id"]
                or deployed["expected_revision"] != approval["approved_revision"]
                or deployed["observed_revision"] != approval["approved_revision"]):
            raise HTTPException(409, "Development revision is not verified")
        if data["observed_revision"] != deployed["observed_revision"]:
            raise HTTPException(409, "Human result revision differs from deployed revision")
        cursor = connection.execute(
            "INSERT INTO remediation_human_verifications(case_id,deployment_id,actor,result,observed_revision,notes) VALUES(?,?,?,?,?,?)",
            (case_id, deployed["id"], data["actor"], data["result"], data["observed_revision"], data["notes"]),
        )
        return dict(connection.execute("SELECT * FROM remediation_human_verifications WHERE id=?", (cursor.lastrowid,)).fetchone())
