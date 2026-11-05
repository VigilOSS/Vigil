"""What a write to a finding does to its verification verdict.

One owner decides, for every finding write path (patch, re-record, merge,
relocation, relationship links and same-verifier enrichment), whether a change
keeps the verdict, needs an independent claim review, or invalidates it.
Classification compares resolved stored rows, never request arguments, so an
empty merge value or a no-op re-record cannot move a verdict and a resolved
change cannot slip past by arriving through a different verb.

A receipt backs one verification event. An invalidated verdict therefore needs a
fresh proof run; a claim review keeps the verdict until an independent
``claim_equivalence`` decision; a kept verdict needs nothing.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Mapping

from ._common import VERIFICATION_STATUSES

# Bumped when the classification rules change, so each audited transition says
# which rules decided it.
CHANGE_POLICY_VERSION = 1


class Effect(str, Enum):
    KEEP = "keep"
    CLAIM_REVIEW = "claim_review"
    INVALIDATE = "invalidate"


_EFFECT_RANK = {Effect.KEEP: 0, Effect.CLAIM_REVIEW: 1, Effect.INVALIDATE: 2}

# Every status but ``unreviewed`` carries a verdict an invalidation resets.
INVALIDATABLE_VERIFICATION_STATUSES = frozenset(
    str(value) for value in VERIFICATION_STATUSES
) - {"unreviewed"}
# The verdicts a claim review gates: only these reach the report.
CLAIM_REVIEW_VERIFICATION_STATUSES = frozenset({"confirmed", "downgraded"})
KILLED_VERIFICATION_STATUS = "false_positive"

# Write operations the policy classifies. ``reopen`` and ``retract`` are patches
# whose intent is itself an axis.
OPERATIONS = frozenset(
    {"patch", "record", "reopen", "retract", "merge", "relocate", "link"}
)

KEEP, CLAIM_REVIEW, INVALIDATE = Effect.KEEP, Effect.CLAIM_REVIEW, Effect.INVALIDATE

# Stored column -> (axis, effect). ``evidence_ref`` and ``evidence_type`` depend on
# the direction of the change and live in their own table below.
COLUMN_EFFECTS: Mapping[str, tuple[str, Effect]] = {
    "title": ("title", KEEP),
    "notes": ("notes", KEEP),
    "status": ("workflow_status", KEEP),
    "submission_status": ("submission", KEEP),
    "submission_platform": ("submission", KEEP),
    "submission_ref": ("submission", KEEP),
    "submission_url": ("submission", KEEP),
    "provenance_json": ("provenance", KEEP),
    "source_name": ("source_name", KEEP),
    "summary": ("summary", CLAIM_REVIEW),
    "severity": ("severity", INVALIDATE),
    "defect_family": ("defect_family", INVALIDATE),
    "root_cause_key": ("root_cause_key", INVALIDATE),
    "auth_context": ("auth_context", INVALIDATE),
    "canonical_location": ("canonical_location", INVALIDATE),
}

EVIDENCE_FIELD_EFFECTS: Mapping[str, Effect] = {
    "evidence_ref.fill": KEEP,
    "evidence_ref.replace": CLAIM_REVIEW,
    # Dropping the evidence artifact removes a proof dependency.
    "evidence_ref.clear": INVALIDATE,
    "evidence_type.fill": KEEP,
    "evidence_type.replace": CLAIM_REVIEW,
}

# Detail keys with an explicit effect. Every other key is claim wording.
DETAIL_KEY_EFFECTS: Mapping[str, Effect] = {
    "remediation": KEEP,
    "references": KEEP,
    "correction_history": KEEP,
    "replies": KEEP,
    "withdrawal_reason": KEEP,
    "ghsa": KEEP,
    "notes_provenance": KEEP,
    "attempts_summary": KEEP,
    "related_intel_ids": KEEP,
    "discovered_by": KEEP,
    # Verdict rationale recorded by finding verify, not part of the claim.
    "kill_reason": KEEP,
    "kill_check": KEEP,
    "block_reason": KEEP,
    "unblock_requirements": KEEP,
    "cwe_id": INVALIDATE,
}
DEFAULT_DETAIL_AXIS = "details.*"
DEFAULT_DETAIL_EFFECT = CLAIM_REVIEW

# Detail keys the verdict's proof depends on. Rewording one is claim review;
# removing it (or, for ``repro_runs``, dropping a recorded run) invalidates.
PROOF_DEPENDENCY_DETAIL_KEYS = frozenset(
    {
        "evidence",
        "impact",
        "proof",
        "exploitability",
        "steps_to_reproduce",
        "repro_runs",
        "poc_request",
        "poc_response",
        "poc_code",
        "crash_input",
        "asan_report",
    }
)
CVSS_DETAIL_KEYS = ("cvss_score", "cvss_vector")
# Detail keys that carry the technical claim. Merge never fills or replaces them.
TECHNICAL_DETAIL_KEYS = frozenset(
    {key for key, effect in DETAIL_KEY_EFFECTS.items() if effect is INVALIDATE}
    | set(CVSS_DETAIL_KEYS)
)

CVSS_EFFECTS: Mapping[str, Effect] = {
    # Confidentiality / integrity / availability within the same band.
    "cvss.impact": CLAIM_REVIEW,
    # A score revised within its band without a vector to say why.
    "cvss.score": CLAIM_REVIEW,
    "cvss.exploitability": INVALIDATE,
    # A vector added, removed, re-versioned or unreadable.
    "cvss.vector": INVALIDATE,
    "cvss.band": INVALIDATE,
}

RELATIONSHIP_EFFECTS: Mapping[str, Effect] = {
    "link": KEEP,
    "root_cause_link": KEEP,
    # The root fix retires this finding entirely, which changes its claim.
    "root_cause_link.eliminates_finding": CLAIM_REVIEW,
}

OPERATION_EFFECTS: Mapping[str, Effect] = {
    "reopen": INVALIDATE,
    "retraction": INVALIDATE,
}

_CVSS_IMPACT_METRICS = {
    "CVSS:3.0": frozenset({"C", "I", "A"}),
    "CVSS:3.1": frozenset({"C", "I", "A"}),
    "CVSS:4.0": frozenset({"VC", "VI", "VA", "SC", "SI", "SA"}),
}


def detail_key_effect(key: str) -> tuple[str, Effect]:
    if key in DETAIL_KEY_EFFECTS:
        return f"details.{key}", DETAIL_KEY_EFFECTS[key]
    return f"details.{key}", DEFAULT_DETAIL_EFFECT


def effect_table() -> list[tuple[str, str]]:
    """Every (axis, effect) row the policy decides, in a stable order.

    The assess CLI mirrors this table in ``contract_registry.FINDING_CHANGE_EFFECTS``
    for the contract notes; a drift test holds the two together.
    """
    rows: dict[str, Effect] = {}
    for axis, effect in COLUMN_EFFECTS.values():
        rows[axis] = effect
    rows.update(EVIDENCE_FIELD_EFFECTS)
    for key, effect in DETAIL_KEY_EFFECTS.items():
        rows[f"details.{key}"] = effect
    rows[DEFAULT_DETAIL_AXIS] = DEFAULT_DETAIL_EFFECT
    for key in sorted(PROOF_DEPENDENCY_DETAIL_KEYS):
        rows[f"details.{key}.removed"] = INVALIDATE
    rows.update(CVSS_EFFECTS)
    rows.update(RELATIONSHIP_EFFECTS)
    rows.update(OPERATION_EFFECTS)
    return [(axis, effect.value) for axis, effect in rows.items()]


@dataclass(frozen=True)
class FindingChange:
    """The classified change: each moved axis and the strongest effect."""

    axes: tuple[tuple[str, Effect], ...] = field(default_factory=tuple)

    @property
    def effect(self) -> Effect:
        return max(
            (effect for _, effect in self.axes),
            key=_EFFECT_RANK.__getitem__,
            default=KEEP,
        )

    @property
    def changed_axes(self) -> list[str]:
        return [axis for axis, _ in self.axes]

    def axes_with(self, effect: Effect) -> list[str]:
        return [axis for axis, axis_effect in self.axes if axis_effect is effect]

    def audit(self, outcome: Outcome) -> dict[str, Any]:
        """The ``metadata.change_policy`` block written on the transition row.

        ``effect`` is the classification; ``outcome`` is what it did to the stored
        verdict (the write response's ``verification_effect``). They differ when
        the finding holds no verdict the effect applies to.
        """
        return {
            "version": CHANGE_POLICY_VERSION,
            "effect": self.effect.value,
            "outcome": outcome.value,
            "axes": [{"axis": axis, "effect": effect.value} for axis, effect in self.axes],
        }


def _getter(row: Mapping[str, Any] | Any):
    if isinstance(row, Mapping):
        return lambda key: row.get(key)
    keys = set(row.keys())
    return lambda key: row[key] if key in keys else None


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _details(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _present(value: Any) -> bool:
    return value not in (None, "", [], {})


def cvss_band(score: float) -> str:
    if score == 0:
        return "info"
    if score < 4:
        return "low"
    if score < 7:
        return "medium"
    if score < 9:
        return "high"
    return "critical"


def _score(value: Any) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    return None


def _vector_metrics(vector: Any) -> tuple[str, dict[str, str]] | None:
    parts = _text(vector).strip().split("/")
    if not parts or parts[0] not in _CVSS_IMPACT_METRICS:
        return None
    metrics: dict[str, str] = {}
    for part in parts[1:]:
        name, separator, value = part.partition(":")
        if not separator or not name or name in metrics:
            return None
        metrics[name] = value
    return parts[0], metrics


def _cvss_axes(before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, Effect]]:
    if all(before.get(key) == after.get(key) for key in CVSS_DETAIL_KEYS):
        return []
    axes: list[tuple[str, Effect]] = []
    score_before, score_after = _score(before.get("cvss_score")), _score(after.get("cvss_score"))
    band_before = cvss_band(score_before) if score_before is not None else None
    band_after = cvss_band(score_after) if score_after is not None else None
    if band_before != band_after:
        axes.append(("cvss.band", CVSS_EFFECTS["cvss.band"]))
    vector_before, vector_after = before.get("cvss_vector"), after.get("cvss_vector")
    if vector_before != vector_after:
        parsed_before, parsed_after = _vector_metrics(vector_before), _vector_metrics(vector_after)
        if (
            parsed_before is None
            or parsed_after is None
            or parsed_before[0] != parsed_after[0]
        ):
            axes.append(("cvss.vector", CVSS_EFFECTS["cvss.vector"]))
        else:
            impact = _CVSS_IMPACT_METRICS[parsed_before[0]]
            moved = {
                name
                for name in parsed_before[1].keys() | parsed_after[1].keys()
                if parsed_before[1].get(name) != parsed_after[1].get(name)
            }
            if moved - impact:
                axes.append(("cvss.exploitability", CVSS_EFFECTS["cvss.exploitability"]))
            if moved & impact:
                axes.append(("cvss.impact", CVSS_EFFECTS["cvss.impact"]))
    elif score_before != score_after and band_before == band_after:
        axes.append(("cvss.score", CVSS_EFFECTS["cvss.score"]))
    return axes


def comparable_run_ids(value: Any) -> Any:
    """`details.repro_runs` with each id as an int: writes accept 5 and "5" alike."""
    if not isinstance(value, list):
        return value
    return [
        int(entry.strip()) if isinstance(entry, str) and entry.strip().isdigit() else entry
        for entry in value
    ]


def _detail_axes(before: dict[str, Any], after: dict[str, Any]) -> list[tuple[str, Effect]]:
    axes: list[tuple[str, Effect]] = []
    for key in sorted(before.keys() | after.keys()):
        if key in CVSS_DETAIL_KEYS:
            continue
        old, new = before.get(key), after.get(key)
        if key == "repro_runs":
            old, new = comparable_run_ids(old), comparable_run_ids(new)
        if old == new and (key in before) == (key in after):
            continue
        if not _present(old) and not _present(new):
            continue
        if key in PROOF_DEPENDENCY_DETAIL_KEYS and _present(old):
            dropped_run = (
                key == "repro_runs"
                and isinstance(old, list)
                and isinstance(new, list)
                and any(run not in new for run in old)
            )
            if not _present(new) or dropped_run:
                axes.append((f"details.{key}.removed", INVALIDATE))
                continue
        axes.append(detail_key_effect(key))
    return axes + _cvss_axes(before, after)


def _evidence_axis(name: str, before: Any, after: Any) -> list[tuple[str, Effect]]:
    old, new = _text(before), _text(after)
    if old == new:
        return []
    if not old:
        axis = f"{name}.fill"
    elif not new and f"{name}.clear" in EVIDENCE_FIELD_EFFECTS:
        axis = f"{name}.clear"
    else:
        axis = f"{name}.replace"
    return [(axis, EVIDENCE_FIELD_EFFECTS[axis])]


def _relationship_snapshots(change: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    for side in ("before", "after"):
        value = change.get(side)
        items = value if isinstance(value, list) else [value]
        for item in items:
            if isinstance(item, Mapping):
                yield item
    for nested in change.get("changes") or []:
        if isinstance(nested, Mapping):
            yield from _relationship_snapshots(nested)


def _relationship_axes(
    relationship_changes: Iterable[Mapping[str, Any] | None],
) -> list[tuple[str, Effect]]:
    axes: list[tuple[str, Effect]] = []
    for change in relationship_changes:
        if not change:
            continue
        snapshots = list(_relationship_snapshots(change))
        root_cause = [item for item in snapshots if item.get("link_kind") == "root_cause"]
        if not root_cause:
            axis = "link"
        elif any(item.get("root_cause_effect") == "eliminates_finding" for item in root_cause):
            axis = "root_cause_link.eliminates_finding"
        else:
            axis = "root_cause_link"
        if all(existing != axis for existing, _ in axes):
            axes.append((axis, RELATIONSHIP_EFFECTS[axis]))
    return axes


def classify_finding_change(
    before_row: Mapping[str, Any] | Any,
    after_row: Mapping[str, Any] | Any,
    operation: str,
    relationship_changes: Iterable[Mapping[str, Any] | None] = (),
) -> FindingChange:
    """Classify the resolved difference between two stored finding rows."""
    if operation not in OPERATIONS:
        raise ValueError(f"unknown finding change operation: {operation}")
    before, after = _getter(before_row), _getter(after_row)
    axes: list[tuple[str, Effect]] = []
    if operation == "reopen":
        axes.append(("reopen", OPERATION_EFFECTS["reopen"]))
    if operation == "retract":
        axes.append(("retraction", OPERATION_EFFECTS["retraction"]))
    for column, (axis, effect) in COLUMN_EFFECTS.items():
        if _text(before(column)) != _text(after(column)) and all(
            existing != axis for existing, _ in axes
        ):
            axes.append((axis, effect))
    axes += _evidence_axis("evidence_ref", before("evidence_ref"), after("evidence_ref"))
    axes += _evidence_axis("evidence_type", before("evidence_type"), after("evidence_type"))
    axes += _detail_axes(_details(before("details_json")), _details(after("details_json")))
    axes += _relationship_axes(relationship_changes)
    return FindingChange(tuple(axes))


class Outcome(str, Enum):
    """What applying a classified change does to the stored verdict."""

    KEEP = "keep"
    CLAIM_REVIEW = "claim_review"
    INVALIDATE = "invalidate"
    REFUSE = "refuse"


def verdict_outcome(verification_status: str, change: FindingChange, *, operation: str) -> Outcome:
    """Apply the classified effect to one stored verification status.

    An invalidating change on a killed finding is refused rather than leaving a
    false-positive workflow with an unreviewed verdict; the operator reopens it
    first. A rediscovery that folds into a killed finding keeps it killed, which
    is what makes a false positive stay suppressed.
    """
    effect = change.effect
    if verification_status not in INVALIDATABLE_VERIFICATION_STATUSES or effect is KEEP:
        return Outcome.KEEP
    if effect is CLAIM_REVIEW:
        return (
            Outcome.CLAIM_REVIEW
            if verification_status in CLAIM_REVIEW_VERIFICATION_STATUSES
            else Outcome.KEEP
        )
    if verification_status == KILLED_VERIFICATION_STATUS and operation != "reopen":
        return Outcome.KEEP if operation == "record" else Outcome.REFUSE
    return Outcome.INVALIDATE


KILLED_FINDING_REFUSAL = (
    "finding is killed (false_positive) and this change would invalidate its verdict "
    "({axes}); reopen it first with `vigil assess finding update {slug} --status draft "
    "--reason \"<why the kill no longer holds>\"`, then make the change"
)


def response_fields(change: FindingChange, outcome: Outcome) -> dict[str, Any]:
    """The verdict fields patch, merge, relocate and link responses carry."""
    return {
        "verification_effect": outcome.value,
        "verification_invalidated": outcome is Outcome.INVALIDATE,
        "changed_axes": change.changed_axes,
    }


# --- claim digests --------------------------------------------------------------
#
# A claim digest names the claim an equivalence decision or a proof-work binding
# was recorded against. Version 1 covered every claim field, including title and
# evidence reference. Version 2 covers exactly the fields whose change is not
# ``keep`` in the table above, so a kept edit cannot make a recorded decision or
# binding stale. Records without a version were written under version 1 and are
# compared at version 1.
CLAIM_DIGEST_VERSION = 2
LEGACY_CLAIM_DIGEST_VERSION = 1
CLAIM_DIGEST_VERSIONS = frozenset({LEGACY_CLAIM_DIGEST_VERSION, CLAIM_DIGEST_VERSION})

_DIGEST_COLUMNS = tuple(
    column
    for column, (_, effect) in COLUMN_EFFECTS.items()
    if effect is not KEEP
)


def claim_digest(row: Mapping[str, Any] | Any, *, version: int = CLAIM_DIGEST_VERSION) -> str:
    get = _getter(row)
    details = _details(get("details_json"))
    if version == LEGACY_CLAIM_DIGEST_VERSION:
        claim: dict[str, Any] = {
            key: _text(get(key))
            for key in (
                "title", "summary", "severity", "defect_family", "root_cause_key",
                "auth_context", "canonical_location", "evidence_ref",
            )
        }
        claim["details"] = {
            key: value for key, value in details.items() if key != "correction_history"
        }
    elif version == CLAIM_DIGEST_VERSION:
        claim = {column: _text(get(column)) for column in _DIGEST_COLUMNS}
        claim["details"] = {
            key: value
            for key, value in details.items()
            if detail_key_effect(key)[1] is not KEEP
        }
        claim["digest_version"] = CLAIM_DIGEST_VERSION
    else:
        raise ValueError(f"unknown claim digest version: {version}")
    encoded = json.dumps(claim, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def recorded_digest_version(record: Mapping[str, Any]) -> int:
    """The digest version a stored decision or binding was recorded with."""
    version = record.get("claim_digest_version", LEGACY_CLAIM_DIGEST_VERSION)
    return version if version in CLAIM_DIGEST_VERSIONS else LEGACY_CLAIM_DIGEST_VERSION
