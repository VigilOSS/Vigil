"""Derive the ``provenance.code_snapshot`` binding a file finding must carry.

The binding is three mechanical values — a repository id plus that repository's
``active_generation`` and ``source_manifest_digest`` — which a caller could only
ever transcribe out of its Code Source Identity block. Transcription is not an
attestation, and never was: what makes a stored binding worth anything is the
sibling ``code_snapshot_attestation`` the backend stamps from the dispatch it
resolves out of ``provenance.agent_id``. So the mechanical half is derived here
from the same repository rows the currency gate reads, and the identity half
stays the caller's to assert.

Deriving does not soften the gate. The values come from the repository's CURRENT
active generation, so a derived binding is current by construction or refused by
``_require_current_code_snapshot`` for the same reason a transcribed one would
be; an authored binding always wins, stale included.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from assess.lib.client import AssessError

BINDING_KEY = "code_snapshot"


def _repo_binding(repo: dict[str, Any], *, operation: str) -> dict[str, Any]:
    repo_id = repo.get("id")
    generation = repo.get("active_generation")
    digest = str(repo.get("source_manifest_digest") or "")
    valid = (
        type(repo_id) is int
        and repo_id >= 1
        and type(generation) is int
        and generation >= 1
        and len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )
    if not valid:
        raise AssessError(
            f"{operation}: code repository {repo.get('repo_key') or repo_id!r} has no "
            "complete source identity (repo id, active generation, manifest digest), so "
            "provenance.code_snapshot cannot be derived. Re-run `vigil assess code-ingest` "
            "and `vigil assess code-index sync`, or pass the binding explicitly."
        )
    return {
        "repo_id": int(repo_id),
        "repo_generation": int(generation),
        "source_manifest_digest": digest,
    }


def is_analysis_repository(repo: Any) -> bool:
    """A published repository that is a reviewed subject, not reference source.

    The same rule `agent start` applies when it renders Code Source Identity: a
    ``reference`` repository is sealed and citable navigation source, never the
    subject a dispatch is handed, so it is never a derivation candidate.
    """
    return (
        isinstance(repo, dict)
        and int(repo.get("active_generation") or 0) > 0
        and repo.get("repo_role") != "reference"
    )


def _paste_ready(repo: dict[str, Any]) -> str:
    """One candidate's binding exactly as ``provenance`` would carry it."""
    binding = {
        "repo_id": repo.get("id"),
        "repo_generation": repo.get("active_generation"),
        "source_manifest_digest": repo.get("source_manifest_digest"),
    }
    return json.dumps({BINDING_KEY: binding}, separators=(",", ":"))


def current_binding(
    client: Any,
    *,
    repo_id: int | None = None,
    stored: bool = False,
    operation: str,
) -> dict[str, Any]:
    """Return the current binding for ``repo_id``, or for the one analysis repo.

    ``repo_id`` comes from the finding's stored binding (``stored=True``) or from
    the caller's ``--code-repo-id``. A caller-selected repository must be active;
    naming a reference repository is a deliberate choice, so it binds with a
    warning that the repository owes no coverage. A stored binding is the
    finding's own record and is read whatever its role.
    Without ``repo_id`` the engagement must hold exactly one active analysis
    repository, because a guess between two repositories would bind a finding
    to source nobody reviewed.
    """

    if repo_id is not None:
        repo = client.get(f"code/repos/{int(repo_id)}")
        if not isinstance(repo, dict):
            raise AssessError(
                f"{operation}: code repository {repo_id} returned an invalid response"
            )
        if not stored and not is_analysis_repository(repo):
            label = f"--code-repo-id {repo_id} ({repo.get('repo_key') or repo_id})"
            if repo.get("repo_role") != "reference" or int(repo.get("active_generation") or 0) < 1:
                raise AssessError(
                    f"{operation}: {label} is not an active analysis repository; pass the "
                    "repo_id of the analysis repository in your Code Source Identity block."
                )
            print(
                f"WARN {operation}: {label} is a reference repository (citable navigation "
                "source, not a reviewed subject); the finding is bound to it as named, and "
                "it carries no coverage obligation. If the defect lives in the reviewed "
                "source, pass the repo_id of the analysis repository in your Code Source "
                "Identity block instead.",
                file=sys.stderr,
            )
        return _repo_binding(repo, operation=operation)

    repos = client.get("code/repos")
    if not isinstance(repos, list):
        raise AssessError(f"{operation}: code repository listing returned an invalid response")
    active = [repo for repo in repos if is_analysis_repository(repo)]
    if not active:
        raise AssessError(
            f"{operation}: a file: finding needs provenance.code_snapshot, and this "
            "engagement has no active indexed analysis repository to derive it from. "
            "Ingest and index the source first (`vigil assess code-ingest`, `vigil "
            "assess code-index sync`), or pass the binding explicitly."
        )
    if len(active) > 1:
        candidates = "\n".join(
            f"  {repo.get('repo_key')} (--code-repo-id {repo.get('id')}): {_paste_ready(repo)}"
            for repo in active
        )
        raise AssessError(
            f"{operation}: {len(active)} active analysis repositories exist, so "
            "provenance.code_snapshot cannot be derived without guessing which source was "
            "reviewed. Pass --code-repo-id <repo-id> (the repo_id in your Code Source "
            "Identity block) or set provenance.code_snapshot explicitly to one of:\n"
            f"{candidates}"
        )
    return _repo_binding(active[0], operation=operation)


def fill_binding(
    provenance: dict[str, Any],
    client: Any,
    *,
    repo_id: int | None = None,
    stored: bool = False,
    operation: str,
) -> None:
    """Fill ``provenance[code_snapshot]`` in place unless the caller authored one."""

    if provenance.get(BINDING_KEY):
        return
    provenance[BINDING_KEY] = current_binding(
        client, repo_id=repo_id, stored=stored, operation=operation
    )
