"""Shared ``evidence_ref`` shape validation — WARN, never block.

``evidence_ref`` is supposed to name ONE engagement-local path the backend can
auto-register as an artifact. What arrives instead, often enough to matter, is a
composite (``scans/a.out; scans/b.out``), a URL, or prose (``command-runs
56052/56054/56061``). The backend indexer already refuses to mint an artifact row
for those shapes (``artifact_index._path_ref``), so a ref of that shape records a
finding whose proof pointer can never resolve.

``finding record`` mirrors the indexer's rules to warn the author at record time
(``record_finding._normalize_evidence_ref``). ``finding update`` and
``record-probe`` write the SAME field through different doors and had no check at
all, so the identical malformed ref entered unremarked. This module is the single
classification those paths share, so they behave identically instead of drifting
into separate opinions about what a valid ref looks like.

WARN, NEVER BLOCK — deliberately. Refusing a finding update or a probe record
mid-hunt risks losing work that is already done, and it contradicts the
harness-not-gate doctrine: ``check-phase-readiness --phase report`` is the terminal
backstop for unindexable evidence, not the moment of writing. The message names
what is wrong and the write proceeds.

KEEP IN SYNC with ``artifact_index._path_ref`` (authoritative) and
``record_finding._is_single_path_shaped``.
"""
from __future__ import annotations

import sys
from pathlib import Path

__all__ = [
    "classify_evidence_ref",
    "evidence_ref_exists",
    "evidence_ref_warning",
    "is_single_path_shaped",
    "warn_evidence_ref",
]

# Composite/prose separators — mirrors ``_COMPOSITE_REF_CHARS`` in the backend
# indexer (orchestrator/backend/app/services/artifact_index.py).
_COMPOSITE_REF_CHARS = (";", "|", "\n", "\r", "\t", "\x00")


def is_single_path_shaped(ref: str) -> bool:
    """True when ``ref`` could be ONE engagement-local path.

    Mirrors ``artifact_index._path_ref``, so the warning matches what the backend
    will actually do: a ref failing this check records fine but mints NO artifact
    row, and saying "nothing exists there" would imply something could.
    """
    stripped = (ref or "").strip()
    if not stripped or "://" in stripped:
        return False
    if "/" not in stripped and "." not in stripped:
        return False
    if "  " in stripped:
        return False
    if any(char in stripped for char in _COMPOSITE_REF_CHARS):
        return False
    tokens = stripped.split(" ")
    if len(tokens) > 1:
        if "/" not in tokens[0] and "." not in tokens[0]:
            return False
        if any("/" in token for token in tokens[1:]):
            return False
    return True


def evidence_ref_exists(ref: str, engagement_dir: str, engagement_key: str) -> bool:
    """True when ``ref`` resolves to something real on disk.

    EXISTENCE, not file-ness: a directory holding a whole capture set is a valid
    evidence_ref. Checks the ref as-is, relative to the engagement dir, and the
    container-path form ``/engagements/<key>/…`` mapped back to the host — the three
    forms an engagement-owned path legitimately arrives in.
    """
    ref = (ref or "").strip()
    if not ref:
        return False
    candidates = [Path(ref)]
    if engagement_dir and not Path(ref).is_absolute():
        candidates.append(Path(engagement_dir) / ref)
    prefix = f"/engagements/{engagement_key}/"
    if engagement_key and engagement_dir and ref.startswith(prefix):
        candidates.append(Path(engagement_dir) / ref[len(prefix):])
    for candidate in candidates:
        try:
            if candidate.exists():
                return True
        except OSError:
            continue
    return False


def classify_evidence_ref(
    ref: str, *, engagement_dir: str = "", engagement_key: str = ""
) -> str:
    """``empty`` | ``url`` | ``exists`` | ``path-missing`` | ``not-single-path``."""
    ref = (ref or "").strip()
    if not ref:
        return "empty"
    if ref.startswith(("http://", "https://")):
        return "url"
    if evidence_ref_exists(ref, engagement_dir, engagement_key):
        return "exists"
    return "path-missing" if is_single_path_shaped(ref) else "not-single-path"


def evidence_ref_warning(
    ref: str, *, engagement_dir: str = "", engagement_key: str = ""
) -> str:
    """The warning sentence for a malformed ref, or ``""`` when the ref is fine.

    An empty ref returns ``""``: on the update / probe paths an omitted value means
    "not changing this", not "recorded nothing" — only ``finding record``, which is
    minting the proof pointer, has a reason to warn about absence.
    """
    kind = classify_evidence_ref(
        ref, engagement_dir=engagement_dir, engagement_key=engagement_key
    )
    ref = (ref or "").strip()
    if kind in ("empty", "exists"):
        return ""
    if kind == "url":
        return (
            f"evidence_ref '{ref}' is a URL, not a registered artifact path; recording "
            "anyway. Put external links in details.references and point evidence_ref at "
            "a captured artifact so report-readiness can index replayable proof."
        )
    if kind == "path-missing":
        return (
            f"evidence_ref '{ref}' looks like a path but nothing exists there; recording "
            "anyway. check-phase-readiness --phase report will flag it until a real "
            "artifact is attached."
        )
    return (
        f"evidence_ref '{ref}' is not a single engagement-local path (it reads as prose "
        "or joins several references), so NO artifact row is created for it; recording "
        "anyway. Point evidence_ref at ONE captured path — a directory of captured "
        "evidence is fine — put external links in details.references, and use `vigil "
        "assess finding link` / details.evidence for the rest."
    )


def warn_evidence_ref(
    ref: str,
    *,
    verb: str,
    engagement_dir: str = "",
    engagement_key: str = "",
    stream=None,
) -> str:
    """Print the shape warning for ``ref`` (if any) and return it.

    Returns the emitted warning so callers can assert on it without capturing
    stderr. NEVER raises and NEVER exits: the write proceeds either way.
    """
    warning = evidence_ref_warning(
        ref, engagement_dir=engagement_dir, engagement_key=engagement_key
    )
    if warning:
        print(f"{verb}: warning — {warning}", file=stream or sys.stderr)
    return warning
