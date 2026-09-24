"""Stable CLI contract metadata for helper-owned assessment commands."""
from __future__ import annotations

from dataclasses import dataclass, field
import argparse
import functools
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

from .dependency_picture import (
    DEPENDENCY_OBSERVATION_ORIGINS as DEPENDENCY_OBSERVATION_ORIGINS,
    DEPENDENCY_QUALIFIERS as DEPENDENCY_QUALIFIERS,
    REACHABILITY_OBSERVATIONS as REACHABILITY_OBSERVATIONS,
    SHIPMENT_OBSERVATIONS as SHIPMENT_OBSERVATIONS,
)
from .config import ENGAGEMENT_BINDING_CONTRACT
from .intel_types import INTEL_TYPES
from .kali_audit import ALLOWED_PHASES as ALLOWED_PHASES, _enum_reject_message
from .kali_output import KALI_EXIT_CODES as KALI_EXIT_CODES
from .phases import canonical_phase
from .schema_validation import load_schema
from .surfaces import (
    CREATABLE_STATUSES as CREATABLE_STATUSES,
    VALID_SURFACE_TYPES as VALID_SURFACE_TYPES,
)

# The catalog is static metadata. Keep runtime lookup, schema rendering, and
# dispatch-payload validation here so this module remains the public API that
# command modules import, while the data can be maintained independently.
from .contract_registry import (
    BINDABLE_CLIENTS as BINDABLE_CLIENTS,
    CATALOG_PHASES as CATALOG_PHASES,
    COMMAND_GOALS as COMMAND_GOALS,
    CODE_REPO_ROLES as CODE_REPO_ROLES,
    CommandContract,
    DEPENDENCY_ANALYSIS_GAPS as DEPENDENCY_ANALYSIS_GAPS,
    FINDING_PATCH_FIELDS as FINDING_PATCH_FIELDS,
    FINDING_SEVERITIES as FINDING_SEVERITIES,
    FINDING_WORKFLOW_STATUSES as FINDING_WORKFLOW_STATUSES,
    FRAMEWORK_REGISTRATION_KINDS as FRAMEWORK_REGISTRATION_KINDS,
    KALI_MAINT_VERBS as KALI_MAINT_VERBS,
    KALI_TARGET_VERBS as KALI_TARGET_VERBS,
    KALI_VERBS as KALI_VERBS,
    MAX_LEAD_BINDING_PAGE as MAX_LEAD_BINDING_PAGE,
    MAX_VARIANT_PARENT_FINDINGS as MAX_VARIANT_PARENT_FINDINGS,
    MAX_VARIANT_RECEIPT_PAGE as MAX_VARIANT_RECEIPT_PAGE,
    SPECIALIST_DISPATCH_MODES as SPECIALIST_DISPATCH_MODES,
    SUBMISSION_STATUSES as SUBMISSION_STATUSES,
    VERIFICATION_STATUSES as VERIFICATION_STATUSES,
    VERIFICATION_TRANSITION_STATUSES as VERIFICATION_TRANSITION_STATUSES,
    _CONTRACTS,
    _DEFAULT_DISPATCH_MODE,
    _DISPATCH_MODE_BY_ROLE,
    _KALI_COMMON_MISTAKES,
    _KALI_COMMON_NOTES,
    _INLINE_DOCUMENTED_NAMESPACES,
    _NAMESPACE_PARENTS,
    _NAMESPACE_ROOT_META,
    _RAW_ENDPOINT_RULES,
    _kali_invocation,
)
def default_dispatch_mode_for_role(role: str | None) -> str:
    """Return the default ``dispatch_mode`` for a role (L2-1).

    Falls back to ``hypothesis-driven`` for unknown/empty roles. Case-
    insensitive so ``Vulnerability-Analyst`` resolves like the canonical name.
    """
    role_key = str(role or "").strip().lower()
    return _DISPATCH_MODE_BY_ROLE.get(role_key, _DEFAULT_DISPATCH_MODE)


_SPECIALIST_DISPATCH_REQUIRED_FIELDS: tuple[str, ...] = ()


# Roles exempt from the `skills` requirement. The operator coordinates phases
# and dispatch decisions rather than executing a single skill, so requiring an
# explicit skill list on operator dispatches would be misleading. Every other
# specialist role must declare which skills it loaded so the dispatch row is a
# truthful audit of the specialist context.
_DISPATCH_ROLES_WITHOUT_SKILLS: frozenset[str] = frozenset({"operator"})


def _agent_skills_root() -> Path:
    """Resolve agent/skills/ relative to this file or VIGIL_REPO_ROOT.

    Used for warn-only validation that named skills exist on disk. Returning a
    bogus path is harmless because the caller treats a missing directory as
    "skip the on-disk check" rather than a hard error.
    """
    override = os.environ.get("VIGIL_REPO_ROOT")
    if override:
        candidate = Path(override) / "agent" / "skills"
        if candidate.is_dir():
            return candidate
    here = Path(__file__).resolve()
    for parent in here.parents:
        candidate = parent / "agent" / "skills"
        if candidate.is_dir():
            return candidate
    # Fallback when no parent dir holds an `agent/skills/` (e.g. the file is
    # imported from a copied checkout). `__file__` lives at
    # agent/scripts/assess/lib/contracts.py, so parents[3] is the `agent/`
    # directory itself — append `skills` rather than `agent/skills` to avoid
    # building an `agent/agent/skills` path that never exists.
    return Path(__file__).resolve().parents[3] / "skills"


@dataclass
class SpecialistDispatchContract:
    """Documentation mirror of specialist dispatch payloads for ``vigil assess agent start``.

    Aligns with the Specialist Dispatch Contract table in ``agent/operator-core.md``.
    Use ``validate_specialist_dispatch_contract`` to lint a parsed JSON payload.

    The public operator contract accepts ``requested_model`` /
    ``requested_reasoning``. Launcher-effective and provider-observed identity
    remain unavailable until a trusted integration can supply them; dispatch
    callers cannot self-attest those values. Legacy aliases ``model`` /
    ``reasoning`` are rejected.
    """

    role: str
    dispatch_mode: str
    requested_model: str | None = None
    requested_reasoning: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)


# C4a — technique-cage dispatch lint. A "technique cage" is a prescriptive,
# step-by-step script in a --task that caps a specialist's depth to a fixed
# recipe — the doctrine's opposite of an open-objective dispatch (see
# operator-core.md "Standing dispatch constraint": a less-constrained specialist
# consistently out-finds a caged one). The lint is deliberately CONSERVATIVE: it
# WARNs (never errors) and only when >=2 of three co-occurring signals are
# present, so it does not warning-fatigue on legitimately structured tasks.
_CAGE_IMPERATIVE_VERBS: tuple[str, ...] = (
    "test", "check", "verify", "try", "confirm", "validate", "attempt",
    "send", "run", "fuzz", "enumerate", "probe", "inject", "exploit",
    "brute", "bruteforce", "scan", "hit", "replay",
)

# A step-list line: leading `1.` / `2)` numbering, or a `-` / `*` / `•` bullet.
_CAGE_STEP_RE = re.compile(r"^\s*(?:\d+[.)]|[-*•])\s+")

# An imperative-verb line: an optional leading number/bullet, then one of the
# test-verbs at a word boundary.
_CAGE_VERB_RE = re.compile(
    r"^\s*(?:\d+[.)]\s*|[-*•]\s*)?(?:"
    + "|".join(_CAGE_IMPERATIVE_VERBS)
    + r")\b",
    re.IGNORECASE,
)


def _detect_technique_cage(task: str) -> list[str]:
    """Warn (never error) when a ``--task`` reads as a prescriptive technique cage.

    Conservative by design — it must not warning-fatigue on legitimately
    structured tasks. It detects three signals:

      (i)   a numbered/bulleted STEP LIST — >=3 lines matching ``^\\s*\\d+[.)]``
            or ``^\\s*[-*•]``;
      (ii)  a run of IMPERATIVE test-verbs — >=3 lines starting (after any
            leading number/bullet) with test/check/verify/try/confirm/validate/
            attempt/send/run/fuzz/enumerate/...;
      (iii) pre-named VULN-CLASS tokens from the canonical taxonomy
            (``vuln_taxonomy.all_classes()`` — imported the way ``probe_args.py``
            does, never a hardcoded parallel list).

    It warns ONLY when a STRUCTURED recipe (>=3 step-list lines (i) or >=3
    imperative-verb lines (ii)) also PRE-COMMITS to >=2 named bug classes (iii)
    ON its recipe lines — the cage is "hunt these specific bugs, this way". A
    structured imperative list that names NO bug to hunt (an orientation
    checklist, or a confirmed-finding PoC / reproduction) is NOT a cage; neither
    is a scope list with a single incidental class noun. Both must stay quiet.

    Returns zero or more short WARN strings, each pointing at the alternative:
    ``vigil assess coverage --host <h> --for-dispatch``. WARN-ONLY — the caller
    must NEVER fold these into ``errors``.
    """
    text = str(task or "")
    if not text.strip():
        return []
    lines = text.splitlines()

    step_lines = sum(1 for ln in lines if _CAGE_STEP_RE.match(ln))
    verb_lines = sum(1 for ln in lines if _CAGE_VERB_RE.match(ln))

    from assess.lib.vuln_taxonomy import all_classes

    classes = tuple(all_classes())

    def _names_a_class(fragment: str) -> bool:
        low = fragment.lower()
        return any(
            re.search(r"(?<![a-z0-9])" + re.escape(cls) + r"(?![a-z0-9])", low)
            for cls in classes
        )

    lowered = text.lower()
    named_classes = sorted(
        cls
        for cls in classes
        if re.search(r"(?<![a-z0-9])" + re.escape(cls) + r"(?![a-z0-9])", lowered)
    )
    # Recipe lines (a step OR imperative-verb line) that THEMSELVES pre-name a
    # specific bug class. A cage pre-commits the specialist to >=2 named bug
    # classes inside a structured list. A structured imperative list that names
    # no bug to hunt (an orientation checklist, a confirmed-finding PoC), or a
    # scope list with one incidental class noun, is NOT a cage.
    cage_lines = sum(
        1 for ln in lines
        if (_CAGE_STEP_RE.match(ln) or _CAGE_VERB_RE.match(ln)) and _names_a_class(ln)
    )

    signals: list[str] = []
    if step_lines >= 3:
        signals.append(f"a {step_lines}-item numbered/bulleted step list")
    if verb_lines >= 3:
        signals.append(f"{verb_lines} imperative test-verb lines")
    if named_classes:
        shown = ", ".join(named_classes[:4])
        more = "" if len(named_classes) <= 4 else ", ..."
        signals.append(f"pre-named vuln class(es): {shown}{more}")

    # Warn only on a STRUCTURED recipe (>=3 step lines or >=3 imperative-verb
    # lines) that also pre-commits to >=2 named bug classes ON its recipe lines.
    # The named-bug requirement is what separates a cage ("hunt these specific
    # bugs") from a legitimate imperative checklist / confirmed-finding PoC that
    # prescribes actions but names no bug to hunt.
    has_structure = step_lines >= 3 or verb_lines >= 3
    if not (has_structure and cage_lines >= 2):
        return []

    return [
        "task reads as a prescriptive technique cage ("
        + "; ".join(signals)
        + "). A step-by-step recipe caps a specialist's depth and costs real "
        "severity — dispatch the surface + hard ROE + an OPEN objective and let "
        "the specialist form its own hypotheses. To hand it the MEASURED "
        "coverage picture (covered classes + OPEN gaps) instead of a script, "
        "run `vigil assess coverage --host <h> --for-dispatch` and paste the "
        "COVERAGE block into the dispatch."
    ]


def validate_specialist_dispatch_contract(
    payload: Any,
) -> tuple[list[str], list[str]]:
    """Validate a parsed specialist dispatch payload.

    A missing ``skills`` list is a WARNING, never an error. A specialist chooses
    its skills from what it observes on the surface, so the honest skill list is
    only known once the dispatch has run — requiring it up front would force the
    operator to guess a vulnerability class before the hunt and cap the
    specialist at that guess. The dispatch row records what the operator knew at
    dispatch time; the specialist reports what it actually loaded in its handoff.

    Returns ``(errors, warnings)``.
    """
    errors: list[str] = []
    warnings: list[str] = []

    if not isinstance(payload, dict):
        return ["agent start contract must be a JSON object"], warnings

    for field_name in _SPECIALIST_DISPATCH_REQUIRED_FIELDS:
        if field_name not in payload:
            errors.append(f"missing required field: {field_name}")

    role_value = payload.get("agent_role", payload.get("role"))
    if "role" not in payload and "agent_role" not in payload:
        errors.append("missing required field: role (or agent_role)")
    if "role" in payload and "agent_role" in payload:
        role_text = str(payload.get("role") or "").strip()
        agent_role_text = str(payload.get("agent_role") or "").strip()
        if role_text and agent_role_text and role_text.lower() != agent_role_text.lower():
            errors.append("role and agent_role must match when both are present")

    dispatch_mode = payload.get("dispatch_mode")
    if dispatch_mode is None:
        defaulted_mode = default_dispatch_mode_for_role(role_value)
        warnings.append(
            f"dispatch_mode not set; defaulting to '{defaulted_mode}' for role "
            f"'{role_value or '<unknown>'}'. Pass --dispatch-mode explicitly to override."
        )
    elif dispatch_mode not in SPECIALIST_DISPATCH_MODES:
        warnings.append(
            f"dispatch_mode '{dispatch_mode}' is not a known mode; "
            f"known modes: {', '.join(SPECIALIST_DISPATCH_MODES)}. "
            "Proceeding (stored as-is) in case this is a newly-coined mode."
        )

    # ONE warning for the whole recipe. Two fields of the same uncertainty used
    # to warn separately, and the provenance attach added a third on every
    # dispatch — enough repetition to train operators past the stderr channel
    # real failures use. The permanent half of the uncertainty (ordinary
    # dispatches observe no launcher-effective identity, so any value here is
    # the caller's selection) lives in the `agent start` contract; only the half
    # the caller can still fix warns.
    unrecorded = [
        canonical
        for canonical, shorthand in (
            ("requested_model", "model"),
            ("requested_reasoning", "reasoning"),
        )
        if not payload.get(canonical) and not payload.get(shorthand)
    ]
    if unrecorded:
        warnings.append(
            f"{' and '.join(unrecorded)} not set; the dispatch cannot be compared as a "
            "measured model/reasoning recipe. Record the client model and reasoning "
            "effort you selected — Vigil records the selection, never a provider-observed "
            "value, so an unset field is simply lost."
        )

    for str_field in ("role", "agent_role"):
        value = payload.get(str_field)
        if value is not None and not isinstance(value, str):
            errors.append(f"{str_field} must be a string")
        elif value is not None and not str(value).strip():
            errors.append(f"{str_field} must be a non-empty string")

    # Skills are required for every specialist role so the dispatch row is a
    # truthful audit of which skill context the agent loaded. Operators are
    # exempt because they coordinate phases rather than executing a single
    # skill. Skip on-disk verification when the skills directory cannot be
    # located so the validator stays usable from arbitrary CWDs.
    role_name = str(role_value).strip() if isinstance(role_value, str) else ""
    skills_value = payload.get("skills")
    skills_list: list[str] = []
    if isinstance(skills_value, str):
        skills_list = [s.strip() for s in skills_value.split(",") if s.strip()]
    elif isinstance(skills_value, list):
        for entry in skills_value:
            if isinstance(entry, str) and entry.strip():
                skills_list.append(entry.strip())
            else:
                errors.append("skills entries must be non-empty strings")
                break
    elif skills_value is not None:
        errors.append("skills must be a comma-separated string or a list of strings")

    if role_name and role_name.lower() not in _DISPATCH_ROLES_WITHOUT_SKILLS:
        if not skills_list:
            warnings.append(
                f"skills not set for role '{role_name}'; the dispatch row carries no "
                "skill audit. Set --skills when you already know which skill applies; "
                "otherwise the specialist selects one from the surface and names it in "
                "its handoff."
            )

    if skills_list:
        skills_root = _agent_skills_root()
        if skills_root.is_dir():
            for skill_name in skills_list:
                skill_path = skills_root / skill_name / "SKILL.md"
                if not skill_path.is_file():
                    warnings.append(
                        f"skill '{skill_name}' has no SKILL.md under {skills_root} "
                        "— typo or repo-relative path mismatch?"
                    )

    # C4a: WARN-only technique-cage lint over the free-text task. NEVER appended
    # to `errors` — a prescriptive task is a depth smell, not an invalid dispatch.
    warnings.extend(_detect_technique_cage(str(payload.get("task") or "")))

    return errors, warnings


# Verbs registered under `vigil assess kali ...`. Names are kept in sync with
# the modules under `agent/scripts/assess/commands/kali_*.py`.
#
# Two categories live here so the audit-flag invariants stay truthful:
def _namespace_child_contracts(parent: str) -> list[CommandContract]:
    """The per-action contracts registered under a grouped subcommand parent."""
    prefix = parent + " "
    return [c for key, c in _CONTRACTS.items() if key.startswith(prefix)]


def _namespace_root_phases(parent: str) -> tuple[str, ...]:
    """Union of the child contracts' phase tags (dedup, first-seen order).

    Derived rather than hardcoded so `list-commands --phase <p>` still surfaces
    the collapsed parent for every phase its actions cover — no phase goes empty
    when the per-action rows fold into one parent row.
    """
    seen: list[str] = []
    for child in _namespace_child_contracts(parent):
        for phase in child.phase:
            if phase not in seen:
                seen.append(phase)
    return tuple(seen)


def _namespace_root_goals(parent: str) -> tuple[str, ...]:
    """Union of the child contracts' goal tags (dedup, first-seen order)."""
    seen: list[str] = []
    for child in _namespace_child_contracts(parent):
        for goal in child.goals:
            if goal not in seen:
                seen.append(goal)
    return tuple(seen)


def _namespace_root_contract(parent: str) -> CommandContract:
    """Build the single collapsed catalog/contract row for a grouped parent."""
    meta = _NAMESPACE_ROOT_META[parent]
    return CommandContract(
        name=parent,
        phase=_namespace_root_phases(parent),
        goals=_namespace_root_goals(parent),
        summary=str(meta["summary"]),
        schema_name=f"(per-action argparse; see `vigil assess contract {parent} <action>`)",
        preferred_invocations=tuple(meta["invocations"]),
        author_supplied_fields=(
            f"<action> ({meta['actions']})",
            "action-specific positional/flag args (see the per-action contract)",
        ),
        notes=(
            f"Cosmetic subcommand group: each action keeps its own argument parser. "
            f"Read `vigil assess contract {parent} <action>` for the full per-action "
            f"schema, examples, and common mistakes.",
        ),
    )


def contract_names() -> list[str]:
    names = list(_CONTRACTS)
    names.extend(f"intel record {intel_type}" for intel_type in sorted(INTEL_TYPES))
    # `kali` is ONE dispatcher row, NOT one row per tool. The 27 per-verb
    # `kali <verb>` contracts stay fully resolvable via `get_contract` /
    # `contract kali <verb>` and are enumerated by `list-commands --kali-only`;
    # they are intentionally NOT flattened into the top-level catalog — that
    # expansion is what made the surface read as "~27 kali commands". The
    # `agent`/`intel record` sub-verbs remain expanded here pending their own
    # consolidation pass (they are single rows in `all_command_contracts`).
    names.append("kali")
    names.append("agent")
    names.extend(f"agent {verb}" for verb in AGENT_VERBS)
    names.append("work-buffer")
    names.extend(f"work-buffer {verb}" for verb in _WORK_BUFFER_VERBS)
    # Grouped subcommands render as ONE top-level row each (like `kali`);
    # the per-action `finding <action>` / `intel <action>` / `export <kind>` /
    # `command-run <action>` contracts live in `_CONTRACTS` under their two-token
    # keys (already enumerated by `list(_CONTRACTS)` above), and the bare parent
    # names resolve via `get_contract`.
    names.extend(_NAMESPACE_PARENTS)
    return sorted(names)


def all_command_contracts() -> list[CommandContract]:
    """Every helper-owned command contract, for the per-phase catalog.

    Composes the static ``_CONTRACTS`` registry with the SINGLE collapsed
    ``kali`` dispatcher row (``_kali_root_contract``) — the surface ``vigil
    assess list-commands`` groups by phase. The per-verb ``kali <verb>``
    contracts are deliberately kept OUT of this default catalog so the
    dispatcher renders as ONE row instead of flattening into one per verb; they remain
    fully resolvable via ``get_contract`` / ``contract kali <verb>`` and are
    enumerated on demand by ``kali_verb_contracts`` (the ``list-commands
    --kali-only`` expansion). The dynamically-derived per-intel-type
    (``intel record <type>``) and per-agent-verb (``agent <verb>``) detail
    contracts are likewise excluded — they are drill-down forms of the
    ``intel record`` / ``agent`` catalog rows, not separate commands.
    """
    contracts: list[CommandContract] = [
        contract
        for key, contract in _CONTRACTS.items()
        if not any(key.startswith(parent + " ") for parent in _NAMESPACE_PARENTS)
    ]
    contracts.append(_kali_root_contract())
    contracts.extend(_namespace_root_contract(parent) for parent in _NAMESPACE_PARENTS)
    return contracts


def kali_verb_contracts() -> list[CommandContract]:
    """Every per-verb ``kali <verb>`` contract — the ``--kali-only`` expansion.

    Kept OUT of :func:`all_command_contracts` (the default catalog renders
    ``kali`` as one row); ``vigil assess list-commands --kali-only`` and
    ``vigil assess contract kali <verb>`` use this to drill into the individual
    tool wrappers. Preserves full discoverability of every kali tool without
    inflating the top-level command count.
    """
    verbs: list[CommandContract] = []
    for verb in KALI_VERBS:
        contract = _kali_verb_contract(verb)
        if contract is not None:
            verbs.append(contract)
    return verbs


def commands_by_phase(phase: str) -> list[CommandContract]:
    """Return the command contracts tagged for a given engagement ``phase``.

    ``phase`` is normalized to the canonical CATALOG_PHASES vocabulary (the
    ``consume``→``consume-test`` short alias is resolved). Phase-agnostic
    utilities (empty ``phase`` tuple) are never returned by a phase filter —
    ``list-commands`` surfaces them in a separate group. Results are sorted by
    command name for stable output.
    """
    target = canonical_phase(phase)
    matched = [c for c in all_command_contracts() if target in c.phase]
    return sorted(matched, key=lambda c: c.name)


def get_contract(name: str) -> CommandContract | None:
    if name.startswith("intel record "):
        # `intel record <type>` is the three-token per-type intel contract.
        # Strip the fixed `intel record ` prefix (partition on the first space
        # would wrongly split "intel" from "record <type>").
        intel_type = name[len("intel record "):]
        return _record_intel_contract(intel_type)
    for parent in sorted(_INLINE_DOCUMENTED_NAMESPACES, key=len, reverse=True):
        # Longest prefix first so `kali job start` resolves to `kali job`, not
        # to the `kali` dispatcher. Recurses once to reach dynamically-built
        # parents (`kali job` is composed by _kali_verb_contract, not stored).
        if name.startswith(parent + " "):
            return get_contract(parent)
    if name in _NAMESPACE_PARENTS:
        return _namespace_root_contract(name)
    if name == "kali":
        return _kali_root_contract()
    if name.startswith("kali "):
        _, _, verb = name.partition(" ")
        return _kali_verb_contract(verb)
    if name == "agent":
        return _dispatch_root_contract()
    if name.startswith("agent "):
        _, _, verb = name.partition(" ")
        return _dispatch_verb_contract(verb)
    if name == "work-buffer":
        return _work_buffer_contract()
    if name.startswith("work-buffer "):
        _, _, verb = name.partition(" ")
        return _work_buffer_verb_contract(verb)
    return _CONTRACTS.get(name)


def render_contract(name: str) -> str:
    contract = get_contract(name)
    if contract is None:
        available = ", ".join(contract_names())
        raise ValueError(f"Unknown contract '{name}'. Available contracts: {available}")

    lines = [
        f"Command: {contract.name}",
        f"Summary: {contract.summary}",
        f"Schema: {contract.schema_name}",
    ]
    if contract.goals:
        lines.append(f"Goals: {', '.join(contract.goals)}")
    if contract.phase:
        lines.append(f"Phase: {', '.join(contract.phase)}")
    lines.extend(
        [
            "",
            "Preferred invocation:",
        ]
    )
    lines.extend(f"  - {entry}" for entry in contract.preferred_invocations)
    lines.extend(
        [
            "",
            "Author-supplied fields:",
        ]
    )
    lines.extend(f"  - {entry}" for entry in contract.author_supplied_fields)

    if contract.helper_defaults:
        lines.extend(
            [
                "",
                "Helper defaults:",
            ]
        )
        lines.extend(f"  - {key} = {value}" for key, value in contract.helper_defaults)

    schema_properties = _schema_field_lines(
        contract.schema_name,
        # The top level prints its own "Required top-level fields" summary, and
        # `details` gets a deeper section of its own on the verbs that write it.
        mark_required=False,
        deferred_fields=("details",) if contract.details_schema_name else (),
    ) or [
        f"  - {name} ({domain}) — {meaning}"
        for name, domain, meaning in contract.top_level_fields
    ]
    if schema_properties:
        lines.extend(
            [
                "",
                "Allowed top-level fields:",
            ]
        )
        lines.extend(schema_properties)

    lines.extend(_author_required_lines(contract))

    details_properties = _details_field_lines(contract.details_schema_name)
    if details_properties:
        lines.extend(
            [
                "",
                f"Allowed details keys ({contract.details_schema_name} -> properties.details):",
            ]
        )
        lines.extend(details_properties)

    if contract.common_mistakes:
        lines.extend(
            [
                "",
                "Common mistakes:",
            ]
        )
        lines.extend(f"  - {wrong} -> {fix}" for wrong, fix in contract.common_mistakes)

    if contract.notes:
        lines.extend(
            [
                "",
                "Notes:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in contract.notes)

    if contract.examples:
        lines.extend(
            [
                "",
                "Examples:",
            ]
        )
        for example in contract.examples:
            lines.append(json.dumps(example, indent=2, ensure_ascii=False))

    lines.extend(["", "Assessment binding:", f"  {ENGAGEMENT_BINDING_CONTRACT}"])

    return "\n".join(lines)


# argparse renders an enum miss as:
#   argument --status: invalid choice: 'bogus' (choose from 'pending', 'queued', ...)
# Capture the flag, the offending value, and the choices list so the write-verb
# error path can re-render it through the SAME scoped formatter the kali verbs
# use (_enum_reject_message: did-you-mean first, no multi-line usage dump).
_WRITE_INVALID_CHOICE_RE = re.compile(
    r"argument\s+(?P<flag>-\S+):\s+invalid choice:\s+'(?P<value>.*?)'\s+"
    r"\(choose from (?P<choices>.+)\)",
    re.DOTALL,
)


class ContractErrorParser(argparse.ArgumentParser):
    """ArgumentParser that keeps the ``vigil assess contract <verb>`` pointer
    visible on the ERROR path, not only on ``--help``.

    argparse prints a command's epilog exclusively on ``--help``; a caller who
    fails on a missing/invalid flag never sees the contract pointer. This parser,
    used by the coverage/probe write verbs, (1) re-renders an enum ``invalid
    choice`` miss through :func:`_enum_reject_message` — the same scoped
    did-you-mean formatter the kali verbs use, with no usage dump — and (2)
    appends ``See: vigil assess contract <verb>`` to every other parse error.
    Mirrors ``ScopedErrorParser`` (``kali_cli.py``).
    """

    def __init__(self, *args: Any, contract_name: str = "", **kwargs: Any) -> None:
        self._contract_name = contract_name
        super().__init__(*args, **kwargs)

    def _pointer(self) -> str:
        return f"See: vigil assess contract {self._contract_name}" if self._contract_name else ""

    def error(self, message: str) -> None:  # noqa: D102 - argparse override
        match = _WRITE_INVALID_CHOICE_RE.search(message or "")
        if match:
            # argparse renders the choice list either quoted ('a', 'b') or bare
            # (a, b) depending on the Python version — accept both.
            choices_raw = match.group("choices")
            quoted = re.findall(r"'([^']*)'", choices_raw)
            allowed = tuple(quoted) if quoted else tuple(
                tok.strip() for tok in choices_raw.split(",") if tok.strip()
            )
            if allowed:
                lines = [f"ERROR: {_enum_reject_message(match.group('flag'), match.group('value'), allowed)}"]
                pointer = self._pointer()
                if pointer:
                    lines.append(pointer)
                print("\n".join(lines), file=sys.stderr)
                self.exit(2)
        # Every other parse error: default argparse rendering (usage + message)
        # PLUS the contract pointer appended last so it is the final, most
        # visible line. Replicates ArgumentParser.error so behavior is unchanged
        # except for the trailing pointer.
        self.print_usage(sys.stderr)
        out = f"{self.prog}: error: {message}\n"
        pointer = self._pointer()
        if pointer:
            out += f"{pointer}\n"
        self.exit(2, out)


def add_contract_subparser(subparsers, name: str, *, contract_name: str, **kwargs):
    """Register a subcommand parser that is a :class:`ContractErrorParser`.

    argparse binds the parser class at ``add_subparsers(parser_class=...)`` time,
    so a single subparser cannot opt into a different class via ``add_parser``.
    This temporarily swaps the group's parser factory to inject ``contract_name``,
    registers the one subparser, then restores it — leaving every other verb on
    the group's default parser untouched.
    """
    saved = subparsers._parser_class
    subparsers._parser_class = functools.partial(ContractErrorParser, contract_name=contract_name)
    try:
        return subparsers.add_parser(name, **kwargs)
    finally:
        subparsers._parser_class = saved


def render_contract_epilog(name: str) -> str:
    contract = get_contract(name)
    if contract is None:
        available = ", ".join(contract_names())
        raise ValueError(f"Unknown contract '{name}'. Available contracts: {available}")

    lines = ["Examples:"]
    lines.extend(f"  {entry}" for entry in contract.preferred_invocations)
    lines.extend(
        [
            "",
            "See also:",
            f"  vigil assess contract {contract.name}",
            "",
            "Assessment binding:",
            f"  {ENGAGEMENT_BINDING_CONTRACT}",
        ]
    )
    return "\n".join(lines)


def raw_endpoint_error(method: str, endpoint: str, payload: Any | None = None) -> str | None:
    normalized_method = method.upper()
    normalized_endpoint = endpoint.strip("/")
    for candidate_method, pattern, contract_name, extra_notes in _RAW_ENDPOINT_RULES:
        if normalized_method != candidate_method:
            continue
        if not pattern.match(normalized_endpoint):
            continue
        contract = get_contract(contract_name)
        assert contract is not None
        lines = [*extra_notes]
        if normalized_method == "PATCH" and contract_name == "finding update" and _looks_like_verification_payload(payload):
            lines = [
                "Raw PATCH to findings/{slug} is disabled because verification lifecycle changes must use finding verify.",
                "Use finding update only for non-verification metadata or workflow changes such as draft/reported.",
            ]
        elif normalized_method == "PATCH" and contract_name == "finding update":
            lines = [
                "Raw PATCH to findings/{slug} is disabled because helper-owned finding lifecycle changes should use the dedicated commands.",
                "Use finding update for non-verification metadata or workflow changes, including finding update --status draft to reopen a previously verified or false-positive finding.",
            ]
        lines.append("")
        lines.append("Use instead:")
        if normalized_method == "POST" and normalized_endpoint.endswith("/verify"):
            lines.append(f"  - {contract.preferred_invocations[0]}")
            lines.append(
                '  - vigil assess finding verify <slug> --status false_positive '
                '--reason "..." --counter-check-file counter-check.json'
            )
            lines.append("  - vigil assess contract finding verify")
        else:
            lines.append(f"  - {contract.preferred_invocations[0]}")
            if normalized_method == "PATCH" and contract_name == "finding update":
                lines.append(
                    '  - vigil assess finding update <slug> --status draft --reason "reopening for re-triage"'
                )
            lines.append(f"  - vigil assess contract {contract.name}")
        return "\n".join(lines)
    return None


def common_mistake_hints(name: str, payload: dict[str, Any]) -> list[str]:
    contract = get_contract(name)
    if contract is None:
        return []

    hints: list[str] = []
    for wrong, fix in contract.common_mistakes:
        if wrong.startswith("workflow_status="):
            field_name, _, field_value = wrong.partition("=")
            if payload.get(field_name) == field_value:
                hints.append(f"{field_name}={field_value} -> {fix}")
            continue
        if wrong in payload:
            hints.append(f"{wrong} -> {fix}")
    return hints


_DEFERRED_FIELD_POINTER = 'see "Allowed details keys" below'


def _schema_content_node(prop: dict[str, Any]) -> dict[str, Any]:
    """The node that describes what one value of ``prop`` may contain.

    An array documents its element shape under ``items``, so a span list and a
    span object are the same authoring question one level apart.
    """
    items = prop.get("items")
    return items if isinstance(items, dict) else prop


def _schema_type_label(prop: dict[str, Any]) -> str:
    declared = prop.get("type")
    if isinstance(declared, list):
        label = " or ".join(str(entry) for entry in declared)
    elif isinstance(declared, str):
        label = declared
    else:
        label = "any"
    if label != "array":
        return label
    items = prop.get("items")
    return f"array of {_schema_type_label(items)}" if isinstance(items, dict) else label


def _enum_value_label(value: Any) -> str:
    """One enum member as the author has to WRITE it, in JSON spelling.

    ``str()`` renders a JSON ``null`` as Python's ``None``, which reads as a
    legal string member — an author copying it writes ``"None"`` into a schema
    that rejects it. Booleans have the same mismatch.
    """
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _schema_field_annotation(
    prop: dict[str, Any], *, required: bool, deferred: bool
) -> str:
    """The parenthesised domain of one declared property.

    Type first, then whether it must be supplied, then the facts that decide
    whether a value is legal at all: the enum a string is confined to, and
    whether an object accepts keys beyond the ones listed under it.
    """
    head = _schema_type_label(prop)
    if required:
        head += ", required"
    extras: list[str] = []
    items = prop.get("items")
    enum = prop.get("enum")
    if enum is None and isinstance(items, dict):
        enum = items.get("enum")
    if isinstance(enum, list) and enum:
        extras.append("one of: " + ", ".join(_enum_value_label(value) for value in enum))
    if _schema_content_node(prop).get("additionalProperties") is True:
        extras.append("other keys allowed")
    if deferred:
        extras.append(_DEFERRED_FIELD_POINTER)
    return "; ".join([head, *extras])


def _schema_object_lines(
    node: dict[str, Any],
    *,
    depth: int,
    mark_required: bool,
    deferred_fields: tuple[str, ...],
) -> list[str]:
    """Render one object node's declared properties, nested content included.

    Bundled schemas are strict in both directions: an undeclared key is rejected
    and so is a value outside a declared enum, and both rules bite inside nested
    objects and array elements the top-level name says nothing about. The whole
    rejectable surface therefore has to be printable from the contract, which is
    the only place an agent can read it. Recursion is bounded by the schema's own
    declarations, and every level is name-sorted so the rendering is stable.

    The parenthesised annotation says what a value may LEGALLY be; the schema's
    own ``description`` says what it MEANS, and the two answer different
    questions — ``workflow_status``'s enum does not tell an author which of its
    six values a freshly-recorded finding takes. Those descriptions were already
    authored and already shipped in ``agent/schemas/``; withholding them here
    sent the author back to reading the schema file by hand, so they render as
    trailing prose after the domain. This is on-demand output, not standing
    prompt load, so the cost is paid only by the agent that asked.
    """
    properties = node.get("properties")
    if not isinstance(properties, dict):
        return []
    required = node.get("required")
    required_names = set(required) if isinstance(required, list) else set()
    indent = "    " * depth
    lines: list[str] = []
    for name in sorted(str(key) for key in properties):
        prop = properties[name] if isinstance(properties[name], dict) else {}
        deferred = depth == 0 and name in deferred_fields
        annotation = _schema_field_annotation(
            prop,
            required=mark_required and name in required_names,
            deferred=deferred,
        )
        # Kept on ONE line: the contract is grepped as much as it is read, and a
        # wrapped description would break `grep -A0 '  - <field> ('` on the very
        # fields whose meaning the author came for.
        description = " ".join(str(prop.get("description") or "").split())
        suffix = f" — {description}" if description else ""
        lines.append(f"{indent}  - {name} ({annotation}){suffix}")
        if not deferred:
            lines.extend(
                _schema_object_lines(
                    _schema_content_node(prop),
                    depth=depth + 1,
                    mark_required=True,
                    deferred_fields=(),
                )
            )
    return lines


def _schema_field_lines(
    schema_name: str,
    *,
    mark_required: bool,
    deferred_fields: tuple[str, ...],
) -> list[str]:
    """Authoring surface of a bundled schema's top-level object."""
    if not schema_name.endswith(".schema.json"):
        return []
    return _schema_object_lines(
        load_schema(schema_name),
        depth=0,
        mark_required=mark_required,
        deferred_fields=deferred_fields,
    )


def _details_field_lines(schema_name: str) -> list[str]:
    """Authoring surface of the ``details`` object inside a bundled schema.

    Rendered through the same recursion as the top level, from the same schema,
    so the section an author reads for a sub-key and the section they read for a
    top-level field cannot describe the object differently.
    """
    if not schema_name.endswith(".schema.json"):
        return []
    details = load_schema(schema_name).get("properties", {}).get("details", {})
    if not isinstance(details, dict):
        return []
    return _schema_object_lines(
        details, depth=0, mark_required=True, deferred_fields=()
    )


def _schema_required_names(schema_name: str) -> list[str]:
    if not schema_name.endswith(".schema.json"):
        return []
    schema = load_schema(schema_name)
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return sorted(str(name) for name in required)


def _nested_required_names(schema_name: str, field: str) -> list[str]:
    """The ``required`` array declared INSIDE one top-level object property."""
    if not schema_name.endswith(".schema.json"):
        return []
    prop = load_schema(schema_name).get("properties", {}).get(field)
    if not isinstance(prop, dict):
        return []
    required = _schema_content_node(prop).get("required", [])
    if not isinstance(required, list):
        return []
    return sorted(str(name) for name in required)


def _author_required_lines(contract: CommandContract) -> list[str]:
    """The required-fields section, stated as what an AUTHOR must supply.

    A schema's ``required`` array is the contract the validator enforces, which
    on a helper-normalized verb is a POST-normalization contract: `finding
    record` ``setdefault``s ten of its twelve names before validation runs, so
    printing the array verbatim told authors to supply ten values the helper
    owns — and named ``verification_status`` as required two sections below the
    helper default calling ``unreviewed`` the only record-time value it accepts.

    Subtracting the helper defaults is a derivation, not a second list, so a
    default added or dropped moves this section with it. A name the helper only
    partially fills stays required and carries its own nested ``required`` array:
    `finding record` always CREATES ``details`` (to stamp ``discovered_by``) and
    the object still fails validation without ``evidence`` and ``impact``.
    """
    required = _schema_required_names(contract.schema_name)
    if not required:
        return []
    helper_filled = {key for key, _ in contract.helper_defaults}
    author_required = [name for name in required if name not in helper_filled]
    if not author_required:
        return []
    heading = "Required top-level fields:"
    if len(author_required) < len(required):
        heading = (
            "Required top-level fields (author-supplied; every other name in the "
            "schema's `required` array is filled by the Helper defaults above):"
        )
    lines = ["", heading]
    for name in author_required:
        nested = _nested_required_names(contract.schema_name, name)
        suffix = f" — must carry {', '.join(nested)}" if nested else ""
        lines.append(f"  - {name}{suffix}")
    return lines


_KALI_VERB_NOTES: dict[str, tuple[str, ...]] = {
    "nmap-scan": (
        "Default is top-1000 ports; use --ports full for `-p-`, or pass an explicit list (e.g. 22,80,443).",
        "Defaults to `-sT` (TCP connect). Do NOT use `-sS` here — raw SYN probes are dropped by Docker's userland NAT (esp. Docker Desktop/macOS) and silently return 0-open on live hosts. Use `--scan-type sS` only on a bridged-network Linux runtime.",
        "--scripts default,vuln triggers heavy NSE — run synchronously with --timeout 1800+; a long budget is killed cleanly on expiry.",
    ),
    "nuclei": (
        "Pass either -u or -l. LEAD with explicit `-t` template paths — `-as` (automatic) keys off "
        "tech fingerprinting, which a CDN/WAF defeats, so `-as` under-fires alone; treat it as additive.",
        "WAF-resilience: the wrapper injects `-mhe 50` by default so a host's 403 storm does not make "
        "nuclei ABANDON the host after ~30 errors (its own default). Add `-random-agent` and `-H` "
        "browser headers when the edge blocks scanner UAs.",
        "Politeness `-exclude-tags dos,fuzz,intrusive,brute-force` is injected by default (announced on "
        "stderr); pass your own `-exclude-tags` to override it verbatim. The result's `resolved_argv` "
        "shows the exact command that ran after injection.",
        "Blind callbacks are disabled by default (`--oob-mode none` injects `-ni`). `public` is an explicit data-egress choice; `vigil` uses the OOB domain resolved and exported by the top-level `vigil assess` launcher.",
        "Long sweeps run synchronously with a generous --timeout. `vigil assess kali job start` is operator-only — specialists never background (see kali-exec skill).",
    ),
    "httpx": (
        "Alt-port liveness (I-6): pass -ports/-p <comma-list> (e.g. 80,443,8080,8443) whenever "
        "scope may include non-default ports — httpx probes only 80/443 by default, so an "
        "alt-port-only host reads as dead and is never seeded/crawled without this.",
        "Prefer typed flags over --extra-args: -web-server (Server header; there is NO -server "
        "flag on this wrapper, only -web-server), -content-length/-cl (flag), -path <path> "
        "(probe an appended path), -store-response/-sr + -store-response-dir/-srd (save response "
        "bodies to disk).",
        "--extra-args common passthrough (not yet typed): -mr/-match-regex (regex match), "
        "-body/-d (request body), -method/-x (HTTP method, default GET), and -json field-selection "
        "flags (e.g. -irr/-include-response). Confirm exact spelling with `vigil assess kali "
        "tool-help httpx` before guessing — see references/tools/recon/httpx.md.",
    ),
    "katana": (
        "Deep + disk-bounded by DEFAULT: `-d 5`, `-or -ob` (omit body/raw so a deep crawl does not "
        "fill the disk), `-ef <static set>`, and JS endpoint crawling + jsluice extraction. The wrapper "
        "does not force Katana field scope; pass `-fs` or `-cos` only when the crawl itself calls for an "
        "explicit operator-authored restriction. `--keep-bodies` / `--include-static` undo the disk/asset "
        "defaults for a bounded source pass.",
        "Rate is SAFE by default and decoupled from depth: `-rl 10`, hard-capped at 20 req/s (warn + "
        "clamp above; `--allow-fast-crawl` to exceed) and always clamped DOWN to the program rate "
        "ceiling. Go as deep as you like — politeness comes from the rate cap, not a shallow crawl.",
        "Use `-fs fqdn` for exact-host traversal or `-fs rdn` for registered-domain traversal only "
        "when that restriction is intentional; scope.json does not choose either value.",
        "A `--timeout` cut still yields usable output: katana streams routes to `-o` from line 1, so a "
        "timed-out deep crawl leaves partial-but-ingestible results on disk (`partial_results=true`).",
    ),
    "tool-help": (
        "Prints a runtime tool's live `-h`/`--help` from inside the container so you read the EXACT "
        "flags the INSTALLED version supports instead of guessing into --extra-args.",
        "Maintenance, not a probe: takes NO --technique/--intent/--probe-kind/--phase/--timeout and "
        "writes no audit row. Usage: `vigil assess kali tool-help katana`.",
    ),
    "sqlmap": (
        "sqlmap's own `--technique` is exposed as `--sql-technique` so it doesn't collide with the audit `--technique` flag.",
    ),
    "arjun": (
        "Hidden-parameter discovery. Pass -u <url> for one endpoint or -i <file> for a gated list (build the list with `vigil assess arjun-select` — never aim Arjun at a raw URL dump or inert assets).",
        "JSON output (-oJ) is ALWAYS written under scans/arjun/<target>/<hash>.json (even alongside -oT/-oB) so the run is captured for `vigil assess ingest arjun` — the host-side step that folds discovered params into the work buffer and re-routes the parameterized endpoint (url=->gf:ssrf, file=->gf:lfi, id=->gf:idor/sqli).",
        "-m sets the method: GET (default) | POST | XML | JSON. GET-discovered params land in query_params on ingest; POST/XML/JSON in body_params — set it correctly for modern APIs.",
        "--passive harvests param names from wayback/commoncrawl/otx with no/low target traffic. Use first on rate-sensitive or content-heavy targets, or when active discovery is out of budget.",
        "--headers is auth-aware: pass an authenticated session (Authorization/Cookie) to surface params visible only behind auth. Header-only params are recorded as a signal on ingest (no classifier field maps to a header).",
        "Default wordlist is Arjun's db/large.txt (most thorough); override with -w for a faster list. Politeness knobs: --stable, -d (delay), -T (timeout), -t (threads), --rate-limit.",
        "SQLMAP doctrine: Arjun + the classifier ISOLATE the injectable param; sqlmap confirms and does high-volume blind/time-based extraction. When an enriched row routes to gf:sqli (or carries an id=/numeric param on a DB-ish route), ingest-arjun names `vigil assess kali sqlmap` in triage_rationale as the confirmation step. sqlmap is operator-invoked, never auto-fired. See references/tools/recon/arjun.md.",
    ),
    "cero": (
        "TLS-handshake SAN scraper — connects to TCP/TLS on the listed ports and harvests certificate Subject Alternative Names. Complements CT-log enumeration when targets issue private certs.",
        "Feed CIDR ranges (after asnmap CIDR mapping) for non-DNS subdomain discovery; pass --only-cidrs when the input is exclusively CIDR.",
        "Default ports are 443,8443; add 9443/8444/etc. via -p when the target advertises more TLS endpoints.",
        "Read-only TCP/TLS handshakes — leave --destructive off.",
    ),
    "alterx": (
        "Subdomain permutation generator — emits permutation candidates from known subdomains for downstream resolution. Pair with `kali puredns resolve` so the list is wildcard-filtered before DNS spend.",
        "Default uses alterx built-in patterns; pass -p '{{sub}}-{{word}}.{{suffix}}' (repeatable) only when a custom pattern is justified.",
        "Output is a stream of candidate FQDNs; pipe to puredns or write to file via -o.",
    ),
    "asnmap": (
        "ASN/domain/org to CIDR mapper. Feed owned CIDR ranges into `cero` for TLS SAN discovery that CT logs miss.",
        "Pass at least one of -d, -l, -asn, -org; the wrapper rejects empty invocations before running.",
        "Requires PDCP_API_KEY — without it asnmap exits 0 with EMPTY output. The wrapper detects the missing key and fails loud; pass --allow-no-key to override, or use the whois.cymru.com/RADB/RDAP fallback (see references/tools/recon/asnmap.md).",
    ),
    "bbot": (
        "Multi-module recon scanner. Canonical passive subdomain invocation: `bbot -t <target> -p subdomain-enum -rf passive`. Add modules with -m or presets with -p; gate active modules behind --allow-deadly + --destructive.",
        "--allow-deadly requires --destructive — bbot's deadly modules run real attacks (fuzzing, brute-force, exploit). The CLI hard-fails on --allow-deadly without --destructive so the audit row stays truthful.",
        "Passive sweeps (`-p subdomain-enum`) regularly run 15-30 minutes — set --timeout 1800 or wrap in `kali job start`.",
    ),
    "dnsx": (
        "The typed wrapper applies Docker-safe defaults: --dnsx-profile polite-cdn, --resolver-profile public-tcp, -rl 100, -t 20, -retry 3, -timeout 5.",
        "Do lean bulk resolution first (no -resp/-json), then enrich survivors with -resp -json. Unknown-size or bulk -resp/-json list inputs require --allow-bulk-json.",
        "Rate/thread values above polite-residential require --dnsx-profile bursty-ok; above bursty-ok requires --allow-unsafe-rate.",
        "Common record/filter flags are typed (-aaaa, -mx, -txt, -ns, -soa, -ptr, -asn, -cdn, -rcode, -wd). Use --extra-args only for unmodeled dnsx flags that are not guarded load/transport knobs.",
    ),
    "browser": (
        "Playwright/system-Chromium workflow inside the runtime. Returns origin status, final DOM, screenshot, bounded console/network metadata, route candidates, and typed-step results as one JSON object.",
        "Required attribution follows the SCOPE boundary: mandated headers go to scope.json-admitted hosts only (the shared host_admitted matcher, so in-scope siblings like api.<target> get them and third parties never do), and the origins left unattributed are recorded. --attribution-scope all is the explicit escape hatch — it attributes every origin and warns on stderr. Scope never aborts or filters a request. The one refusal: a program that mandates a header with no resolvable in-scope host stops before navigation. Because scope is a predicate and never gates execution, a run whose OWN target host is absent from scope.json `hosts` (a recon-discovered sibling lives in `discovered_hosts`) navigates it UNATTRIBUTED — that case WARNs on stderr naming the host; declare it or pass --attribution-scope all before treating the traffic as deconflicted.",
        "Use --steps-file for at most 50 typed navigate/click/fill/wait/eval/assert actions. An assert with visible:false waits for the selector to become hidden; text is read only for contains/equals assertions. Declared URLs are syntax-validated before launch; dynamic browser navigations are never admitted or aborted by scope data.",
        "Waiting is composable, not either/or: --wait-until {domcontentloaded|load|networkidle} chooses the initial navigation's completion event, --wait-selector plus --wait-state {attached|visible|hidden|detached} waits for one element (attached is the default and only proves the node exists in the DOM, not that it rendered), and --settle then runs ON TOP of both (--settle 0 skips it). A `wait` step takes the same optional `state` key.",
        "When --timeout does not exceed the driver's own worst-case budget (--page-timeout, again for --wait-selector, plus --settle) the verb WARNs on stderr naming both numbers and still runs: the budget is a CEILING, not the expected cost, so the tight pairing usually completes. Heed the warning when the page is slow — the DOM/screenshot are written at the end and the HAR flushes at context close, so a wrapper kill mid-run leaves zero artifacts and reads exactly like a clean negative. The fix is raising --timeout, not trimming the page waits.",
        "--har-out writes a metadata-only HAR. --capture-bodies is opt-in and stores bounded document/XHR/fetch bodies under --body-dir; --max-body-bytes caps each artifact.",
        "Identity headers/cookies are prepared explicitly for Playwright and the audit auth_context changes only when identity material was actually applied. Storage state is never taken implicitly from a credential record; opt in with an engagement-confined --storage-state JSON artifact plus a live, replayable --identity so authenticated state is never audited as anonymous.",
    ),
    "tlsx": (
        "Bulk TLS cert harvester: opens TLS handshakes against hosts/IPs and pulls SAN/CN/subject-org/issuer fields + JARM/JA3 fingerprints. The SAN/CN harvest expands the subdomain set (private-CA certs that never hit CT logs); the org/issuer + fingerprints drive cert pivoting (siblings sharing a cert/TLS stack).",
        "Pass <host> / -u <host> for one target or -l <file> for a list (hosts/IPs/CIDRs). A bare invocation defaults to the SAN+CN harvest profile (-san -cn -resp-only -silent) — a clean name list for subdomain expansion. Add -so/-cert for issuer/org, -jarm/-ja3 for fingerprint pivoting, -json for the structured per-field form.",
        "Speaks raw TLS, NOT HTTP — it carries no attribution header and is in the required-header SKIP set (parity with nmap). Read-only handshakes: leave --destructive off.",
        "Complements `cero` (also a SAN scraper): tlsx adds structured JSON + JARM/JA3. The Docker per-dest-IP fan-out hazard applies to whole-CIDR feeds — prefer resolved origin/staging IPs (see references/tools/recon/tlsx.md and cero.md).",
    ),
    "dalfox": (
        "Parameter→XSS confirmation. Chain AFTER arjun: arjun isolates the injectable param, dalfox fires reflection-aware payloads and verifies execution (DOM/HTML/attribute context). Pass -u <url> for one target (dalfox `url` mode) or -i <file> for a list (`file` mode); -p <param> focuses dalfox on the arjun-isolated parameter.",
        "Reflective by DEFAULT — no blind/OOB payloads fire unless you pass --blind <callback>, which sends OOB payloads that may persist (stored XSS): pair --blind with --destructive so the audit row is truthful.",
        "WAF-aware: --waf-evasion enables dalfox's evasion mode; --skip-bav drops the basic-another-vuln scan to keep the run focused on XSS. Politeness: --delay (ms), -w workers. dalfox's own request timeout is --dalfox-timeout (renamed to avoid the audit --timeout collision).",
        "dalfox is required-header INJECTABLE (curl-style -H), so a program marker rides every probe automatically; -H/--cookie pass auth so XSS gated behind a session is reachable.",
    ),
    "robots": (
        "Pre-crawl known-file fetch: probes each host for /robots.txt, /sitemap.xml and /.well-known/security.txt BEFORE the katana crawl — Disallow lines + sitemap URLs routinely name admin/staging paths the crawler would otherwise miss. Pass <host>/-u or -l <list>; override the set with --paths.",
        "SCOPE is the marginal pre-crawl fetch ONLY. katana's own -kf (known-files) flag already expands robots/sitemap/well-known DURING the crawl (kali_katana.py) — run robots first for the high-signal seed, then crawl; do not treat -kf as redundant.",
        "Engine is httpx (tool_bin=httpx in the audit row) probing the well-known paths, so it inherits httpx's required-header injection + scope posture. -mc defaults to 200,301,302,401,403 so a gated-but-present file (401/403) still surfaces. Read-only GETs: leave --destructive off.",
    ),
    "gf": (
        "Pattern-bucket a URL corpus by vuln-param family (ssrf/idor/sqli/lfi/redirect/xss/...). Sends NO target traffic — a pure local text filter — so it is a MAINTENANCE verb: it takes NO --technique/--intent/--probe-kind/--phase/--timeout and writes no audit row.",
        "Complements (does not replace) the inline `assess.lib.classify_buckets` classifier, which is the source-of-truth applied automatically at ingest. Reach for `kali gf` for ad-hoc triage of a corpus on disk you have not ingested, or to cross-check one bucket against the upstream gf pattern library.",
        "Usage: `vigil assess kali gf <pattern> -i <urls-file> [-o <out>]`; `--list` enumerates the installed patterns. The corpus is read host-side and piped over `docker exec -i` to gf in the runtime (no container-path translation).",
    ),
    "exec": (
        "Use only when no typed verb fits. Tool-name attribution falls back to argv[0] for audit recording.",
        "THE RUNTIME IS A TOOL SANDBOX, NOT A COPY OF YOUR HOST — these gaps fail silently or mid-run, so plan around them rather than rediscovering them: "
        "(a) `/engagements/$ENGAGEMENT_KEY/...` is the bind mount and the only path whose contents survive back to the host (it is the same bytes as the host's engagement directory); "
        "(b) there is NO `vigil` executable in the container — `command -v vigil` finds nothing, so a helper script that shells out to `vigil assess ...` passes on the host and dies with exit 127 here. A script you run inside the runtime must be self-contained (stdlib, or the image's own installed libraries): pass what it needs in as argv, read manifests and scope.json off the bind mount directly, and make the `vigil assess` recording calls from the host once the run returns; "
        "(c) the `aws` binary is installed but Vigil injects NO credentials — no ~/.aws, no AWS_PROFILE, no AWS_ACCESS_KEY_ID — so every signed call returns NoCredentials. Unsigned calls (--no-sign-request, unauthenticated Cognito) belong here; a signed one runs on the host through `vigil assess host-exec`, which writes the same audit row with route='host_exec' and is therefore an audited route, not a bypass.",
        "A skill's tool list is not proof of installation: `vigil assess kali exec ... -- command -v <tool>` before planning a step around a tool you have not run in this engagement. If a target-facing tool is genuinely missing, rebuild the runtime image rather than falling back to a host or `docker exec` path — the image is the single source of truth for the tool surface.",
        "Reserve `echo` for FUNCTIONAL output only. Stdout is captured to the audit log and the FTS index, not shown to the user, so a commentary-echo bloats the preview and pollutes search without adding retrievable signal. Use --intent for the one-line purpose. `echo` is legitimate when its output IS the point: writing a file, piping into another tool, or generating a payload.",
        "PROCESS CLEANUP TAKES A PID SELECTOR, NEVER A BINARY NAME. `pkill -f nmap` / `killall nuclei` in a shared runtime kills sibling specialists' parallel scans and loses hours of recon. Manual cleanup is rarely needed at all — --timeout expiry already cascades SIGTERM then SIGKILL into the in-container PID, and an operator job stops with `vigil assess kali job stop <id>`. When you must clean up mid-run, every audit row carries a run_uuid and the wrapper records that run's in-container PID to /tmp/vigil-pid-<run_uuid>.pid, so `kill -TERM \"$(cat /tmp/vigil-pid-<run_uuid>.pid)\"` signals only your own run.",
        "A single blocking call must fit in MINUTES, not tens of minutes — above the CLI's own --timeout sits an agent-harness ceiling you do not control, and a call that outruns it is auto-backgrounded with the agent killed (exit 144 / SIGUSR1), orphaning the probe and writing no handoff. A larger --timeout only widens that window. Genuinely long enumeration is an operator-owned job: see `vigil assess contract kali job`.",
    ),
    "job": (
        "Long-running probes go through `vigil assess kali job start ...`. The dtach session is parented by tini so it survives the calling shell.",
        "Job start uses the same pre-execution preparation as synchronous Kali execution: `--identity` material (plus `--identity-scope` for a scoped alias and `--identity-target` for an argv shape Vigil cannot classify), required attribution headers, nuclei OOB safety, target scope, denied tools, and rate policy are applied before audit/spawn.",
        "Subcommands: start | status | tail | stop | list.",
        "OPERATOR-ONLY, AND A DISPATCHED SPECIALIST NEVER USES IT. Target-facing work runs SYNCHRONOUSLY: each `vigil assess kali <verb> ... --timeout N` call is blocking and awaited in-band — no run_in_background, no `job start`, no dtach, no watcher/poll loop. A specialist that backgrounds target traffic and halts for a completion notification gets auto-resumed by the harness, launches the next detached job, and halts again: unbounded relaunch thrash, duplicate probes, near-zero net coverage. A specialist that needs a probe to outlive its dispatch says so in its handoff and lets the operator own the job.",
        "\"Synchronous\" means AWAITED-IN-BAND, not one-call-at-a-time. Several blocking calls in parallel, each awaited in-band, are fine; what is banned is detaching a job and reaping it later. A generous --timeout is the right tool for one long probe — on expiry the audit pipeline cascades SIGTERM then SIGKILL (after 5s) into the in-container PID, the row records timed_out=true, and nothing is orphaned.",
        "The ceiling that makes this a real choice: above the CLI's --timeout sits a separate agent-harness limit you do not control, and a blocking call that runs too long is auto-backgrounded with the agent killed (exit 144 / SIGUSR1) — the probe is orphaned and no handoff is written. So a single synchronous probe must fit in minutes; a sweep that genuinely cannot is what `job start` is for, launched and monitored by the operator, never as a per-step or fan-out pattern.",
    ),
    "sweep": (
        "A DUMB fan-out: it expands ONLY the values you literally typed and reports ONLY what was probed. No seed-id lists, no opaque-id decoding, no hostname/metadata-path invention — `--values` is REQUIRED and a template with no placeholder is an error, so it can never silently run N identical commands.",
        "Each value becomes its own `kali exec` inside the runtime, so every value gets its own command-runs audit row; the summary then clusters the results by distinct response signature.",
        "Clustering reuses the project's EXISTING reachability taxonomy (LIVE / BLACKHOLED / TLS-reset / UNKNOWN, plus the dns-fail vs connection-refused split). `filter-rejected` is derived PURELY from identical reachable responses repeated across distinct values — never from a rule that 'knows' a filter exists.",
        "Politeness: --max-values caps expansion (default 200) and --concurrency defaults to 1; >1 requires --allow-concurrent because of the per-host \"<=1 active target-facing probe\" rule.",
    ),
    "sweep-orphans": (
        "Host-side reconciler for `assessment_command_runs` rows stuck in status=running and terminal host-exec rows committed with output cleanup/integrity pending past --max-age-seconds. Run after a backend restart, host crash, or any window where finalize PATCHes may have failed.",
        "Liveness probe: `docker exec <container> kill -0 <pid>` against the wrapper-recorded pid file at /tmp/vigil-pid-<run_uuid>.pid. run_uuid comes from the row's run_uuid column (stdout_path parsing kept only for older rows).",
        "PID alive -> left alone (still-running). PID dead OR pid file missing -> finalized to status=lost via PATCH command-runs/{id}.",
        "A terminal host-exec row with output_cleanup_status=pending or output_integrity_status=pending is aged only from server-owned output_recovery_observed_at, then receives an idempotent duplicate terminal PATCH. New finalizations stamp that clock with terminal state; migrated pending rows start a recovery baseline when first observed rather than fabricating historical commit time. Recovery counts only when the response proves the same numeric row id and terminal status, recovered_pending_output=true, valid non-pending cleanup/integrity outcomes, and a recognized terminal retention class. Empty, unknown, or transient suppression_pending retention is never accepted as recovery. Unproven recovery remains visible in skipped_unverifiable/pending_recovery_failed; deferred, warning, and integrity_failure outcomes increment recovered_degraded and require operator attention.",
        "Rows are skipped when Docker probing itself fails, since the command cannot distinguish a live job from an unavailable liveness check.",
        "--scope {command-runs|jobs|all} (default command-runs): `jobs` also reconciles stuck assessment_jobs rows (the async dtach-job lifecycle). For jobs the host-readable exit marker is authoritative (marker present -> completed/failed with its real exit code); PID gone with no marker -> lost. This converges any job the agent was killed before it could poll to completion.",
        "Use --dry-run first to inspect candidates without writing — a thorough sweep is cheap, an incorrect finalize is not.",
        "Unlike target-facing verbs, sweep-orphans takes no --technique/--intent/--probe-kind/--phase/--timeout — it is maintenance, not a probe.",
    ),
}


_KALI_VERB_EXAMPLES: dict[str, tuple[dict[str, Any], ...]] = {
    "nmap-scan": (
        {
            "command": "vigil assess kali nmap-scan --target example.com --ports top-1000 --service-detection --technique RECON --intent 'Phase 1 baseline port + service' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "nuclei": (
        {
            "command": "vigil assess kali nuclei -l hosts.txt -t http/cves/,http/misconfiguration/,http/exposures/ -severity high,critical -mhe 50 -random-agent -rate-limit 50 -c 25 -bs 25 -jsonl -o scans/nuclei.jsonl --oob-mode none --technique RECON --intent 'reactive sweep on Phase-1 URL delta (WAF-resilient)' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "katana": (
        {
            "command": "vigil assess kali katana -u https://target.example -o scans/katana_target.jsonl -jsonl --technique DISCOVERY --intent 'deep JS-aware scoped crawl' --probe-kind fingerprint --phase collect --timeout 1800",
        },
        {
            "command": "vigil assess kali katana -u https://app.target.example -headless --allow-fast-crawl -rl 40 -o scans/katana_spa.jsonl -jsonl --technique DISCOVERY --intent 'headless crawl for browser-generated routes' --probe-kind fingerprint --phase collect --timeout 1800",
        },
    ),
    "tool-help": (
        {
            "command": "vigil assess kali tool-help katana",
        },
    ),
    "sqlmap": (
        {
            "command": "vigil assess kali sqlmap -u 'https://target/?id=1' --batch --sql-technique BEUSTQ --level 3 --risk 2 --technique SQLI --intent 'verify SQLi on id parameter' --probe-kind payload --phase consume-test --timeout 1800",
        },
    ),
    "arjun": (
        {
            "command": "vigil assess kali arjun -u https://target/api/item --technique DISCOVERY --intent 'hidden GET param discovery on item endpoint' --probe-kind fingerprint --phase consume-test --timeout 1800",
        },
        {
            "command": "vigil assess kali arjun -i /engagements/$ENGAGEMENT_KEY/scans/arjun/targets.txt.JSON -m JSON --identity user_a --stable --rate-limit 10 --technique DISCOVERY --intent 'authed JSON-API hidden-param discovery on gated route list' --probe-kind fingerprint --phase consume-test --timeout 3600",
        },
        {
            "command": "vigil assess kali arjun -u https://target/search --passive --technique OSINT --intent 'passive param-name harvest (wayback/otx/commoncrawl)' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "cero": (
        {
            "command": "vigil assess kali cero -d 198.51.100.0/24 -p 443,8443,9443 -c 100 -t 4 -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt --technique OSINT --intent 'TLS SAN scraping for non-CT subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "alterx": (
        {
            "command": "vigil assess kali alterx -l /engagements/$ENGAGEMENT_KEY/scans/subs_passive.txt -limit 200000 -o /engagements/$ENGAGEMENT_KEY/scans/perms.txt --technique RECON --intent 'permutation candidate generation from passive subs' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "asnmap": (
        {
            "command": "vigil assess kali asnmap -d example.com -silent -o /engagements/$ENGAGEMENT_KEY/scans/asnmap_cidrs.txt --technique OSINT --intent 'map target-owned CIDRs for TLS SAN sweep' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "bbot": (
        {
            "command": "vigil assess kali bbot -t example.com -p subdomain-enum -rf passive -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs --technique OSINT --intent 'deep passive subdomain enum' --probe-kind fingerprint --phase recon --timeout 1800",
        },
    ),
    "dnsx": (
        {
            "command": "vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt --dnsx-profile polite-cdn --resolver-profile public-tcp -silent -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt --technique RECON --intent 'lean dnsx resolution without bulk JSON' --probe-kind baseline --phase recon --timeout 1200",
        },
    ),
    "browser": (
        {
            "command": "vigil assess kali browser https://app.target.example/login --technique RECON --intent 'headless render of WAF-flagged login surface' --probe-kind baseline --phase recon --timeout 120",
        },
        {
            "command": "vigil assess kali browser https://app.target.example/dashboard --wait-selector '#root' --page-timeout 45 --screenshot scans/browser/dash.png --technique RECON --intent 'render SPA dashboard after auth' --probe-kind baseline --phase consume-test --timeout 180",
        },
    ),
    "tlsx": (
        {
            "command": "vigil assess kali tlsx -l /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -san -cn -resp-only -silent -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_sans.txt --technique RECON --intent 'TLS SAN/CN harvest for subdomain expansion' --probe-kind fingerprint --phase recon --timeout 600",
        },
        {
            "command": "vigil assess kali tlsx -u origin.target.example -cert -jarm -json -o /engagements/$ENGAGEMENT_KEY/scans/tlsx_origin.json --technique OSINT --intent 'issuer + JARM fingerprint for cert pivoting' --probe-kind fingerprint --phase recon --timeout 300",
        },
    ),
    "dalfox": (
        {
            "command": "vigil assess kali dalfox -u 'https://target.example/search?q=test' -p q --skip-bav --silence -o scans/dalfox_q.txt --technique XSS --intent 'confirm reflected XSS on arjun-surfaced q param' --probe-kind payload --phase consume-test --timeout 1800",
        },
        {
            "command": "vigil assess kali dalfox -i /engagements/$ENGAGEMENT_KEY/scans/arjun_xss_candidates.txt --waf-evasion -w 30 --delay 100 --format json -o scans/dalfox_batch.json --technique XSS --intent 'reflective XSS sweep over arjun param-bearing URLs (WAF-aware)' --probe-kind payload --phase consume-test --timeout 3600",
        },
    ),
    "robots": (
        {
            "command": "vigil assess kali robots -l /engagements/$ENGAGEMENT_KEY/scans/live_hosts.txt -o scans/robots_known_files.txt --technique RECON --intent 'pre-crawl robots/sitemap/security.txt fetch for high-signal path seeds' --probe-kind fingerprint --phase recon --timeout 300",
        },
    ),
    "job": (
        {
            "command": "vigil assess kali job start --technique CVE-VALIDATION --intent 'long nuclei sweep' --probe-kind fingerprint --phase recon --timeout 21600 -- nuclei -l targets.txt -t http/cves/ -ni",
        },
        {
            "command": "vigil assess kali job status 42",
        },
    ),
    "sweep-orphans": (
        {
            "command": "vigil assess kali sweep-orphans --dry-run",
        },
        {
            "command": "vigil assess kali sweep-orphans --max-age-seconds 1800 --container-name vigil",
        },
        {
            "command": "vigil assess kali sweep-orphans --scope all --dry-run",
        },
    ),
    "gf": (
        {
            "command": "vigil assess kali gf ssrf -i /engagements/$ENGAGEMENT_KEY/scans/gau_target.txt -o /engagements/$ENGAGEMENT_KEY/scans/gf_ssrf.txt",
        },
        {
            "command": "vigil assess kali gf --list",
        },
    ),
}


# Engagement phase(s) where each kali verb is meaningful, drawn from the
# canonical CATALOG_PHASES / kali_audit.ALLOWED_PHASES vocabulary. Same
# shape/location as _KALI_VERB_NOTES / _KALI_VERB_EXAMPLES: consumed by
# `_kali_verb_contract` to stamp `CommandContract.phase`, which drives
# `vigil assess list-commands --phase <N>`. An empty tuple marks a
# phase-agnostic verb (raw runners + host-side maintenance that run in any
# phase); a verb absent from this map defaults to phase-agnostic too.
_KALI_VERB_PHASES: dict[str, tuple[str, ...]] = {
    # --- target-facing probes ---
    "nmap-scan": ("recon",),
    "nuclei": ("recon", "collect"),
    "httpx": ("recon", "collect"),
    "wafw00f": ("recon",),
    "ffuf": ("collect", "consume-test"),
    "sqlmap": ("consume-test",),
    "subfinder": ("recon", "recon-pivot"),
    "puredns": ("recon", "recon-pivot"),
    "dnsx": ("recon", "recon-pivot"),
    "nikto": ("collect", "consume-test"),
    "katana": ("collect",),
    "gau": ("recon", "collect"),
    "arjun": ("recon", "consume-test"),
    "whatweb": ("recon",),
    "cero": ("recon", "recon-pivot"),
    "alterx": ("recon", "recon-pivot"),
    "asnmap": ("recon", "recon-pivot"),
    "bbot": ("recon",),
    "browser": ("recon", "consume-test", "exploit-recon"),
    "tlsx": ("recon", "recon-pivot"),
    "dalfox": ("consume-test",),
    "robots": ("recon",),
    # exec + job are raw/long-running runners usable in any phase; sweep is a
    # fan-out over exec and inherits the same phase-agnostic reach.
    "exec": (),
    "job": (),
    "sweep": (),
    # --- host-side maintenance (no target traffic, any phase) ---
    "sweep-orphans": (),
    "tool-help": (),
    "gf": (),
}


def _kali_root_phases() -> tuple[str, ...]:
    """Union of every kali verb's phase tags, ordered by CATALOG_PHASES.

    The collapsed ``kali`` catalog row carries this union so ``list-commands
    --phase <p>`` still surfaces the dispatcher in every phase a kali tool runs
    in — including ``recon-pivot`` / ``exploit-recon``, which NO static contract
    covers (only kali verbs do). The per-verb rows stay reachable via
    ``--kali-only``. Derived from ``_KALI_VERB_PHASES`` so it can never drift.
    """
    seen: set[str] = set()
    for verb in KALI_VERBS:
        seen.update(_KALI_VERB_PHASES.get(verb, ()))
    return tuple(phase for phase in CATALOG_PHASES if phase in seen)


def _kali_root_contract() -> CommandContract:
    return CommandContract(
        name="kali",
        phase=_kali_root_phases(),
        summary="Run Kali tools inside the runtime container with audit recording.",
        schema_name="(per-verb argparse + CommandRunRecordRequest backend model)",
        preferred_invocations=(
            "vigil assess kali <verb> [flags]",
            "vigil assess kali --help",
            "vigil assess contract kali <verb>",
        ),
        author_supplied_fields=(
            "--technique <enum>",
            "--intent \"<one-line purpose>\"",
            "--probe-kind {fingerprint|baseline|payload|exploit|replay|cleanup}",
            "--phase <enum>",
            "--timeout <seconds>",
        ),
        notes=_KALI_COMMON_NOTES + (
            f"Target-facing verbs (require the audit-flag set above): "
            f"{', '.join(KALI_TARGET_VERBS)}.",
            f"Host-side maintenance verbs (no audit flags — they do not touch "
            f"the target): {', '.join(KALI_MAINT_VERBS)}.",
        ),
        common_mistakes=_KALI_COMMON_MISTAKES,
        examples=(
            {"command": "vigil assess kali nmap-scan --target example.com --ports top-100 --technique RECON --intent 'fast top-100 sweep' --probe-kind fingerprint --phase recon --timeout 600"},
        ),
    )


def _kali_verb_contract(verb: str) -> CommandContract | None:
    if verb not in KALI_VERBS:
        return None
    examples = _KALI_VERB_EXAMPLES.get(verb, ())

    # `sweep-orphans` is a host-side reconciler, not a target-facing probe —
    # it skips the audit-flag set entirely and has its own flag surface, so
    # composing the standard invocation/author-fields/common-mistakes block
    # would mislead the operator. Document its actual surface instead.
    if verb == "sweep-orphans":
        return CommandContract(
            name="kali sweep-orphans",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Reconcile assessment_command_runs rows stuck in status=running "
                "past a threshold age by probing the in-container PID and "
                "finalizing dead rows to status=lost."
            ),
            schema_name="argparse + CommandRunFinalize backend model",
            preferred_invocations=(
                "vigil assess kali sweep-orphans --dry-run",
                "vigil assess kali sweep-orphans --max-age-seconds 3600",
                "vigil assess kali sweep-orphans --container-name vigil",
                "vigil assess kali sweep-orphans --scope jobs",
            ),
            author_supplied_fields=(
                "--max-age-seconds <int> (default 3600)",
                "--container-name <name> (default vigil)",
                "--scope {command-runs|jobs|all} (default command-runs)",
                "--dry-run (optional, list candidates without writing)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "sweep-orphans is host-side maintenance and does not take audit flags"),
                ("--technique", "sweep-orphans is host-side maintenance and does not take audit flags"),
            ),
            examples=examples,
        )

    if verb == "sweep":
        # Target-facing (it fans out into audited `kali exec` runs) but NOT a tool
        # wrapper: the generic invocation line would hide the required --values
        # and the `-- <template>` positional, which are the whole point.
        return CommandContract(
            name="kali sweep",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Value-agnostic batch: run one audited `kali exec` per --values "
                "entry with the placeholder substituted, then cluster the "
                "responses by distinct signature."
            ),
            schema_name="argparse + one CommandRunRecordRequest per swept value",
            preferred_invocations=(
                "vigil assess kali sweep --technique <enum> --intent \"<one-liner>\" "
                "--probe-kind <kind> --phase <phase> --timeout 1800 --values \"1,2,7-9\" "
                "-- curl -s -o /dev/null -w '%{http_code}' https://app.example.com/orders/{}",
                "vigil assess kali sweep ... --values-file scans/ids.txt --json -- <command with {}>",
            ),
            author_supplied_fields=(
                "--technique <enum>",
                "--intent \"<one-line purpose>\"",
                "--probe-kind <kind>",
                "--phase <phase>",
                "--timeout <seconds>",
                "--values \"<literals and/or a-b integer ranges>\" OR --values-file <path> (exactly one, REQUIRED)",
                "command template (positional after `--`; must contain the placeholder)",
                "--placeholder <token> / --max-values <n> / --concurrency <n> / --allow-concurrent / --json",
            ),
            helper_defaults=(
                ("--placeholder", "{}"),
                ("--max-values", "200"),
                ("--concurrency", "1 (serial); >1 requires --allow-concurrent"),
            ),
            notes=_KALI_COMMON_NOTES + _KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=_KALI_COMMON_MISTAKES
            + (
                ("a template with no placeholder", "sweep refuses it rather than running N identical commands — put {} where the value goes"),
                ("expecting sweep to invent values", "it expands only what --values/--values-file literally contains"),
            ),
            examples=examples,
        )

    if verb == "tool-help":
        return CommandContract(
            name="kali tool-help",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Print a runtime tool's live -h/--help from inside the container "
                "so you read the EXACT flags the installed version supports."
            ),
            schema_name="argparse (no backend audit row)",
            preferred_invocations=(
                "vigil assess kali tool-help katana",
                "vigil assess kali tool-help nuclei --help-flag --help",
            ),
            author_supplied_fields=(
                "<tool> (positional, e.g. katana)",
                "--help-flag <flag> (optional; default tries -h then --help)",
                "--container-name <name> (optional; default the runtime container)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "tool-help is host-side maintenance and does not take audit flags"),
                ("--technique", "tool-help is host-side maintenance and does not take audit flags"),
            ),
            examples=examples,
        )

    if verb == "gf":
        return CommandContract(
            name="kali gf",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary=(
                "Pattern-bucket a URL corpus by vuln-param family (ssrf/idor/sqli/"
                "lfi/redirect/xss/...). A local text filter — sends no target "
                "traffic, so no audit flags. Complements (does not replace) the "
                "inline assess.lib.classify_buckets classifier applied at ingest."
            ),
            schema_name="argparse (docker exec gf; no backend audit row)",
            preferred_invocations=(
                "vigil assess kali gf <pattern> -i <urls-file> -o <out-file>",
                "vigil assess kali gf ssrf -i scans/gau_target.txt -o scans/gf_ssrf.txt",
                "vigil assess kali gf --list",
            ),
            author_supplied_fields=(
                "<pattern> (positional, e.g. ssrf | idor | sqli | lfi | redirect | xss)",
                "-i / --input <url-file> (the corpus to bucket)",
                "-o / --output <file> (optional; default stdout)",
                "--list (optional, enumerate installed patterns)",
                "--container-name <name> (optional; default the runtime container)",
            ),
            notes=_KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=(
                ("--phase", "gf is a local filter (no target traffic) and does not take audit flags"),
                ("--technique", "gf is a local filter (no target traffic) and does not take audit flags"),
                ("expecting gf to replace the inline classifier", "the classify_buckets classifier runs automatically at ingest; gf is for ad-hoc on-disk triage"),
            ),
            examples=examples,
        )

    notes = _KALI_COMMON_NOTES + _KALI_VERB_NOTES.get(verb, ())
    invocation = _kali_invocation(verb)
    author_fields: tuple[str, ...] = (
        "--technique <enum>",
        "--intent \"<one-line purpose>\"",
        "--probe-kind <kind>",
        "--phase <phase>",
        "--timeout <seconds>",
        "tool-specific flags (see `vigil assess kali "
        + verb
        + " --help`)",
    )
    # `exec` and `job` are raw-passthrough wrappers; they do not expose the
    # typed-verb `--extra-args` flag because every argument after the audit
    # metadata is already raw passthrough. `browser` drives a self-contained
    # Playwright execution plan, so appending raw tool flags is meaningless — it
    # exposes typed workflow and artifact flags instead.
    if verb not in ("exec", "job", "browser"):
        author_fields = author_fields + (
            "--extra-args \"<raw flags>\" (optional, shlex-split passthrough for long-tail flags)",
        )
    return CommandContract(
        name=f"kali {verb}",
        phase=_KALI_VERB_PHASES.get(verb, ()),
        summary=f"Run `{verb}` inside the runtime container with audit recording.",
        schema_name="argparse + CommandRunRecordRequest backend model",
        preferred_invocations=invocation,
        author_supplied_fields=author_fields,
        notes=notes,
        common_mistakes=_KALI_COMMON_MISTAKES,
        examples=examples,
    )


def _record_intel_contract(intel_type: str) -> CommandContract | None:
    if intel_type not in INTEL_TYPES:
        return None
    schema_name, endpoint_segment = INTEL_TYPES[intel_type]
    required = tuple(_schema_required_names(schema_name))
    schema = load_schema(schema_name)
    properties = schema.get("properties", {})
    author_fields = list(required or ("type-specific fields",))
    for optional in (
        "source_name", "confidence", "evidence_ref", "provenance", "notes",
        # The interpretation triple on the authored types (note, org-fact). It is
        # listed here rather than left to the field dump because an author who
        # never writes it silently takes the backend's revalidation defaults.
        "authored_by", "scope", "validity_context",
    ):
        if isinstance(properties, dict) and optional in properties and optional not in author_fields:
            author_fields.append(optional)

    example = _intel_example_payload(intel_type)
    notes = [
        f"Posts to /intel/{endpoint_segment}. Use the helper, not raw post, so local schema validation catches payload drift first.",
        "Intel schemas are strict: a field not listed under Allowed top-level fields is rejected before the backend is contacted.",
    ]
    # Keyed off the schema, not a hard-coded type list: a type that gains the
    # interpretation triple gains the authoring rule with it, and one that loses
    # the fields stops advertising a rule its payload can no longer carry.
    if isinstance(properties, dict) and {
        "authored_by", "scope", "validity_context"
    } <= set(properties):
        notes.append(
            f"A `{intel_type}` row is AUTHORED INTERPRETATION, not an observation, so supply "
            "`authored_by`, `scope`, and `validity_context` whenever you know them — they are "
            "top-level strings, distinct from `provenance`, which carries source evidence such "
            "as agent_name or artifact_ref. The backend fills visible unknown-author, "
            "engagement-scope, and unreviewed-validity defaults when you leave them out; those "
            "defaults are a REVALIDATION WARNING, never authorization or permission to act on "
            "the row."
        )
    return CommandContract(
        name=f"intel record {intel_type}",
        summary=f"Record one `{intel_type}` intel row via the intel record helper.",
        schema_name=schema_name,
        preferred_invocations=(
            f"vigil assess intel record {intel_type} {intel_type}.json",
        ),
        author_supplied_fields=tuple(author_fields),
        notes=tuple(notes),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent_name", "use source_name, or provenance.agent_name when provenance detail is useful"),
        ),
        examples=(example,) if example else (),
    )


def _intel_example_payload(intel_type: str) -> dict[str, Any]:
    examples: dict[str, dict[str, Any]] = {
        "tech-component": {
            "component": "Salesforce",
            "version": "",
            "source_name": "source-analyzer",
            "confidence": "confirmed",
            "evidence_ref": "scans/httpx-tech.txt:7",
        },
        "person": {
            "name": "Jane Doe",
            "role": "Engineering",
            "source_name": "osint-analyst",
        },
        "email": {
            "address": "security@example.com",
            "source_name": "osint-analyst",
        },
        "domain": {
            "identity": "api.example.com",
            "kind": "subdomain",
            "source_name": "subdomain-enumeration",
        },
        "cve": {
            "cve_id": "CVE-2024-1234",
            "affected_component": "example-app",
            "source_name": "osint-analyst",
        },
        "dns-record": {
            "name": "api.example.com",
            "record_type": "A",
            "value": "192.0.2.10",
            "source_name": "subdomain-enumeration",
        },
        "social-profile": {
            "subject_kind": "org",
            "platform": "linkedin",
            "handle": "example",
            "url": "https://www.linkedin.com/company/example/",
            "source_name": "osint-analyst",
        },
        "breach-record": {
            "subject": "user@example.com",
            "breach_name": "Example breach",
            "source_name": "osint-analyst",
        },
        "org-fact": {
            "fact_key": "helpdesk-provider",
            "fact_value": "ExampleDesk",
            "source_name": "osint-analyst",
        },
        "note": {
            "title": "Login page leaks stack trace",
            "body_markdown": "Verbose error references internal package names.",
            "source_name": "vulnerability-analyst",
        },
    }
    return examples.get(intel_type, {})


def _looks_like_verification_payload(payload: Any | None) -> bool:
    if not isinstance(payload, dict):
        return False
    verification_keys = {"verification_status"}
    if verification_keys.intersection(payload):
        return True
    return payload.get("workflow_status") == "false_positive"


# ---------------------------------------------------------------------------
# Agent / work-buffer command contracts
#
# Work-buffer primitives (stats, fetch, done, …) are documented inline on
# ``vigil assess work-buffer``. Contract entries advertise backend-backed agent
# lifecycle helpers plus ``render-handoff``, whose markdown output is pasted into
# the next dispatch prompt.
# ---------------------------------------------------------------------------

# Agent lifecycle sub-verbs that have their own contract entry. The Contract-First
# Rule directs operators to read these before first use, and the
# `vigil assess contract` resolver uses this tuple to advertise what is
# discoverable. Read-only sub-verbs (`list`, `get`) are intentionally absent
# because they do not mutate state and have nothing to validate.
AGENT_VERBS: tuple[str, ...] = (
    "render-handoff",
    "continue",
    "start",
    "start-swarm",
    "bind-client-handle",
    "done",
    "close",
    "reconcile-stale",
    "abort-duplicate",
    "decision",
    "handoff",
)


def _dispatch_root_contract() -> CommandContract:
    return CommandContract(
        name="agent",
        summary=(
            "Backend agent lifecycle helpers (start / done / list / get / decision / "
            "handoff / render-handoff for cross-dispatch continuity)."
        ),
        schema_name="(per-action argparse; backend-backed via assessment_dispatches / _dispatch_handoffs / _dispatch_decisions)",
        preferred_invocations=(
            "vigil assess agent start --role <role> --task \"...\" --dispatch-mode <mode> --skills <skills> (--rate-budget <authored> | --no-target-traffic) [--prompt-context-json <context.json> --emit-prompt]",
            "vigil assess agent bind-client-handle <agent-id> --client <client> --session-namespace <scope> --handle <session-id>",
            "vigil assess agent done <agent-id> --finding-slugs <slug1,slug2>",
            "vigil assess agent handoff --from-json <handoff.json>",
            "vigil assess agent close <agent-id>",
            "vigil assess agent reconcile-stale --dry-run",
            "vigil assess agent list [--filter-role <role>] [--status <status>]",
            "vigil assess agent render-handoff <agent-id>",
            "vigil assess agent continue <prior-agent-id> --task \"...\"",
        ),
        author_supplied_fields=(
            "<action> (e.g. start, done, handoff, render-handoff, decision, ...)",
            "action-specific positional args",
        ),
        notes=(
            "Agent lifecycle and work-buffer operations are separate backend-backed command "
            "families. Work-buffer uses `vigil assess work-buffer <action>` and never takes "
            "a local database path.",
            "Dispatch state lives in the orchestrator backend. `agent start` logs a dispatch, "
            "but does not spawn a specialist. Launch the specialist in the active client using "
            "the Runtime Identity block printed by `agent start`, then run "
            "`agent bind-client-handle` so the row names the session you launched and a "
            "mid-flight message no longer depends on a mapping you keep by hand. `agent done` "
            "patches lifecycle directly, `agent handoff` writes a repeatable checkpoint, "
            "`agent close` consumes a ready/blocked handoff into closure, and "
            "`agent render-handoff` assembles the blob the next dispatch prompt pastes verbatim.",
            "`agent start` defaults a missing --dispatch-mode from the role (warn, not block) and accepts a newly-coined mode (advisory warn). "
            "--skills is optional: set it when the applicable skill is already known, otherwise the specialist selects one from the surface and names it in its handoff. The advisory overlap scan is default-on across in-progress and completed rows; it streams paged history, ranks the five displayed rows by relevance/findings produced with deterministic tie-breaks, and prints the total count. Use --allow-duplicate only when the overlap is intentional.",
            "`agent start` also lints --task for a prescriptive 'technique cage' — a step-by-step recipe that caps a specialist's depth (>=2 of: a numbered/bulleted step list, a run of imperative test-verbs, a pre-named vuln class). This is WARN-only and NEVER blocks the dispatch; the fix is to hand the specialist the measured coverage picture instead of a script via `vigil assess coverage --host <h> --for-dispatch` (paste the COVERAGE block) plus an open objective.",
            f"Verbs with their own contract entries: {', '.join(AGENT_VERBS)}.",
        ),
        common_mistakes=(
            (
                "transcript paste",
                "use `vigil assess agent render-handoff <prior-agent-id>` and paste the "
                "rendered blob verbatim — it pulls findings, artifacts, and credentials "
                "from durable state so the prompt stays small",
            ),
            (
                "mixing agent and work-buffer actions",
                "use `vigil assess agent <action>` for lifecycle/handoffs and "
                "`vigil assess work-buffer <action>` for queued assessment work; neither "
                "accepts a local database path",
            ),
            (
                "defer-items <ids> with stale id list",
                "`defer-items` exits 1 (not 0) when zero rows match — by design, so a typo "
                "or already-processed id list surfaces loudly. `reset-stale` first if the "
                "rows you meant to defer are now in `processing`.",
            ),
        ),
    )


def _work_buffer_contract() -> CommandContract:
    return CommandContract(
        name="work-buffer",
        summary="Operate on the backend assessment_work_items work-buffer queue.",
        schema_name="backend assessment_work_items schema",
        preferred_invocations=(
            "vigil assess work-buffer stats --by status|source|cluster|host [--status pending]",
            "vigil assess work-buffer peek <type> [limit]",
            "vigil assess work-buffer fetch <type> <limit> <agent-name>",
            "vigil assess work-buffer fetch-by-priority <limit> auto",
            "vigil assess work-buffer fetch-by-unit [--unit-id ID] [--path PREFIX] [--class TYPE] [--limit N] [--agent auto|NAME]",
            "vigil assess work-buffer done <id1,id2,...>",
            "vigil assess work-buffer defer-cluster <cluster_key> --reason \"...\" [--reason-tag already-covered] [--dry-run]",
            "vigil assess work-buffer defer-items <id...> --reason \"...\" [--dry-run]",
            "vigil assess work-buffer set-rationale <id...> --rationale \"...\"",
            "vigil assess work-buffer reclassify [--reclassify-all|--reclassify-stale|--reclaim-skipped|--retype|--retype-all]",
            "vigil assess work-buffer link-surface --surface-id <id> --cluster <key>",
        ),
        author_supplied_fields=(
            "<action>",
            "action-specific item ids, type, limit, agent name, or reason",
        ),
        notes=(
            "Work-buffer rows are backend batching state (assessment_work_items), NOT backend agent "
            "lifecycle rows. Use `vigil assess agent …` for backend dispatch rows, handoffs, and decisions.",
            "Mark items done only after the specialist has written durable backend state "
            "(findings, surfaces, probe runs, or coverage) for the work.",
            "Use --dry-run on defer-items/defer-cluster to preview the exact pending rows before mutation. Use reason-tag=already-covered when retiring work against durable covering evidence rather than mislabelling it as noise.",
            "stats --by host accepts --status so a pending-only queue census does not mix in terminal rows. set-rationale persists triage conclusions on selected work items.",
            "fetch-by-unit selects the highest-EV unsatisfied application unit when --unit-id is omitted. "
            "Omitting --limit derives a deterministic batch from depth tier and recent probe saturation; an explicit limit always wins and work-item priority scores are never rewritten.",
            "reclassify (folded-in classify-work) re-applies gf-style priority/cluster classification (default: unscored rows only); --retype/--retype-all re-derive `type` from stored fields. link-surface (folded-in link-surface-work-items) links backend surfaces to the request variants behind selected work_items. See `vigil assess contract work-buffer reclassify` / `contract work-buffer link-surface`.",
        ),
        common_mistakes=(
            ("using agent handoff syntax here", "`work-buffer` never records handoffs; use `vigil assess agent handoff`"),
            ("calling the backend work-items API directly", "use the CLI verb so classification, status transitions, and terminal_reason semantics stay consistent"),
        ),
    )


_WORK_BUFFER_VERBS: tuple[str, ...] = ("reclassify", "link-surface")


def _work_buffer_verb_contract(verb: str) -> CommandContract | None:
    if verb == "reclassify":
        return CommandContract(
            name="work-buffer reclassify",
            summary="Re-apply gf-style priority/cluster classification to the work buffer (folded-in classify-work).",
            schema_name="reads GET work-items, writes POST work-items/update (ADR 0013)",
            preferred_invocations=(
                "vigil assess work-buffer reclassify",
                "vigil assess work-buffer reclassify --reclassify-all",
                "vigil assess work-buffer reclassify --reclassify-stale",
                "vigil assess work-buffer reclassify --reclaim-skipped",
                "vigil assess work-buffer reclassify --retype",
                "vigil assess work-buffer reclassify --retype-all",
            ),
            author_supplied_fields=(
                "one optional mode flag (default: unscored rows only)",
                "--batch N (rows per update POST, default 500)",
            ),
            notes=(
                "Classification runs inline at ingest, so this is the maintenance path: re-score after a `_BUCKETS` change (--reclassify-all), re-score only stale-version rows leaving `manual` untouched (--reclassify-stale), un-strand skipped rows the inert policy no longer excludes (--reclaim-skipped).",
                "--retype re-derives `type` for type='unknown' rows from stored method/url_path/content_type/body then re-buckets changed rows; --retype-all widens that to every row (can overwrite a hand-set type). Idempotent.",
            ),
            common_mistakes=(
                ("expecting reclassify to rewrite manual rows", "rows stamped classifier_version='manual' are protected from --reclassify-stale; mark rows manual with `work-buffer mark-manual`"),
            ),
        )
    if verb == "link-surface":
        return CommandContract(
            name="work-buffer link-surface",
            summary="Link backend surfaces to the request variants behind selected work_items (folded-in link-surface-work-items).",
            schema_name="reads GET work-items, writes POST surface-request-variant-links",
            preferred_invocations=(
                "vigil assess work-buffer link-surface --surface-id 5 --cluster gf:cluster",
                "vigil assess work-buffer link-surface --surface-id 9 --queue-key variant:200:api_route",
                "vigil assess work-buffer link-surface --surface-id 1,2 --cluster gf:dup --relation primary-endpoint",
            ),
            author_supplied_fields=(
                "--surface-id <id> (repeatable or comma-separated; at least one required)",
                "--cluster <key> and/or --queue-key <key> (at least one selector required)",
                "--relation / --link-evidence-ref (optional)",
            ),
            notes=(
                "The durable cross-reference is `request_variant_id` (returned when a request observation is posted), NOT the local work_item id. A work_item that never posted to the backend has a NULL request_variant_id and is skipped with a warning rather than failing the whole run; two work_items sharing a request_variant_id produce ONE link per surface (deduped).",
            ),
        )
    return None


def _dispatch_verb_contract(verb: str) -> CommandContract | None:
    if verb == "render-handoff":
        return CommandContract(
            name="agent render-handoff",
            summary=(
                "Render a bounded handoff blob for a prior dispatch's agent_id, "
                "pulled from the assessment backend (dispatch + handoff rows) plus "
                "per-slug finding fetches."
            ),
            schema_name="(reads GET dispatch-handoffs/{agent_id} + GET dispatches/{agent_id} + GET findings/{slug})",
            preferred_invocations=(
                "vigil assess agent render-handoff <agent-id>",
                "vigil assess agent render-handoff <agent-id> --max-lines 60",
                "vigil assess agent render-handoff <agent-id> --include-evidence",
            ),
            author_supplied_fields=(
                "<agent-id> (the prior dispatch's agent_id from `vigil assess agent list`)",
            ),
            helper_defaults=(
                ("--max-lines", "40 (hard cap; findings list collapses with '... and N more')"),
                ("--include-evidence", "off (one short evidence excerpt per finding when set)"),
                ("--engagement-dir", "explicit flag, then engagement CWD, then launcher session"),
                ("scope", "handoff payload's summary / coverage_gaps / next_steps / "
                          "runtime_issues / working_artifacts / open_questions / "
                          "recommended_next_agent / extras"),
                ("credentials filter", "fetched only for vulnerability-analyst and "
                                       "exploit-developer roles, filtered by source_name"),
            ),
            notes=(
                "Exits 2 when no handoff exists for the agent-id (404 on dispatch-handoffs/{agent_id}) — the dispatch never wrote one, or the id is mistyped. Specialists are expected to write a handoff before exiting.",
                "A 404 on a finding slug renders inline as 'slug missing in backend' (distinct from 'fetch error: <reason>') instead of failing the whole render — the operator may have killed the finding between dispatch and handoff.",
                "The dispatch row is fetched best-effort; when missing, the renderer falls back to the handoff row's metadata.",
                "Cross-reference: agent/operator-core.md 'Cross-Dispatch Continuity'.",
            ),
            common_mistakes=(
                (
                    "transcript excerpts in dispatch prompt",
                    "paste render-handoff output instead of copy-pasting from the prior agent's transcript",
                ),
                (
                    "raising --max-lines past ~80",
                    "the cap keeps the prompt bounded — if the blob is too small, narrow the registry's finding_slugs list rather than widening the cap",
                ),
            ),
            examples=(
                {
                    "command": "vigil assess agent render-handoff a424a88b02054913d",
                },
                {
                    "command": "vigil assess agent render-handoff a424a88b02054913d --max-lines 60 --include-evidence",
                },
            ),
        )
    if verb == "continue":
        return CommandContract(
            name="agent continue",
            summary="Create a replacement dispatch from an exact saved prompt packet and a bounded live-state delta.",
            schema_name="reads prior dispatch + prompt packet; writes one linked DispatchCreate row",
            preferred_invocations=(
                "vigil assess agent continue <prior-agent-id> --task \"Finish the unresolved authorization pass\"",
            ),
            author_supplied_fields=("<prior-agent-id>", "--task", "--agent-id (optional replacement identity)"),
            notes=(
                "The predecessor stays immutable history. Continue refuses a fresh in-progress predecessor so it cannot silently duplicate a live specialist; use agent start --allow-duplicate for intentional parallel work.",
                "A saved packet exists only when the original agent start used --emit-prompt. The replacement prompt preserves the original packet verbatim and directs the specialist to hydrate current state through resume-brief before target-facing work.",
            ),
        )
    if verb == "start-swarm":
        return CommandContract(
            name="agent start-swarm",
            summary=(
                "Partition a line-delimited item file into bounded contiguous batches and "
                "record one durable swarm dispatch per batch."
            ),
            schema_name="argparse batch plan + backend DispatchCreate rows (POST /dispatches)",
            preferred_invocations=(
                "vigil assess agent start-swarm --role <role> --task \"...\" "
                "--workers <n> --batch-size <n> --items-file <path> "
                "(--rate-budget \"<authored>\" | --no-target-traffic)",
            ),
            author_supplied_fields=(
                "--role (specialist role shared by every worker)",
                "--task (shared objective; each row receives its own item range)",
                "--workers (maximum number of dispatch rows to record)",
                "--batch-size (contiguous items assigned to each worker)",
                "--items-file (non-empty line-delimited work list)",
                "exactly one traffic declaration: --rate-budget <authored text> or --no-target-traffic",
                "optional --skills / --model / --reasoning / --code-repo-id / --finding-slugs / --vuln-classes / --identity / --application-unit-id / --tier shared by every row",
            ),
            helper_defaults=(
                ("dispatch_mode", "swarm"),
                ("agent_id", "generated as <role>-swarm-<batch-id>-<worker-number>"),
            ),
            notes=(
                "This command records dispatch rows; it does not launch specialists. The JSON and Markdown table preserve every attempted worker row so successful writes remain usable after a partial failure.",
                "If any durable dispatch write fails, the command prints failed_to_record for that row, reports the swarm as incomplete, and exits non-zero. Launch only successfully recorded rows; never treat partial registration as a complete swarm.",
                "Items beyond workers × batch-size are explicitly reported as uncovered and require a later swarm against the tail.",
            ),
        )
    if verb in {"register", "start"}:
        return CommandContract(
            name="agent start",
            summary=(
                "Register a specialist dispatch in the backend audit ledger so the "
                "row carries role, task, optional application-unit attribution, "
                "requested model/reasoning, dispatch-mode, and the skills "
                "the agent loaded."
            ),
            schema_name="backend DispatchCreate (POST /dispatches)",
            preferred_invocations=(
                "vigil assess agent start --agent-id <id> --role <role> "
                "--task \"...\" [--application-unit-id <id>] "
                "[--code-repo-id <repo-id>] "
                "--model <name> --reasoning <level> "
                "--dispatch-mode <mode> --skills \"<skill>[,<skill>...]\" "
                "(--rate-budget \"<authored>\" | --no-target-traffic) "
                "[--prompt-context-json <context.json> --emit-prompt]",
                "vigil assess agent start --from-json <payload.json> [--emit-prompt]",
                "vigil assess agent start --from-json <payload.json> --dry-run [--emit-prompt]",
            ),
            author_supplied_fields=(
                "--agent-id (unique per dispatch)",
                "--role (specialist role; operator role is reserved for phase coordination)",
                "--dispatch-mode (hypothesis-driven|item-iterating|deep-manual|variant-rotation)",
                "--skills (comma-separated; optional — omitting it WARNs, never blocks)",
                "--task (one-line objective)",
                "--application-unit-id (optional concrete application-unit identity for depth attribution)",
                "--code-repo-id (code roles: selects the active backend repository used to render Code Source Identity; required when several active repositories exist)",
                "--finding-slugs (optional canonical related/input finding set; required for a receipt-bearing code-variant-hunter dispatch)",
                "exactly one traffic declaration: --rate-budget <authored text> or --no-target-traffic (JSON: top-level rate_budget string or no_target_traffic=true)",
                "--prompt-context-json when --emit-prompt is set (or JSON: top-level prompt_context object) with every canonical prompt-only field documented by dispatch-template.md",
                "--dry-run to perform the same validation and rendering without persisting a dispatch row",
            ),
            helper_defaults=(
                ("status", "in-progress (set on insert)"),
                ("dispatched_at", "now() when omitted"),
                ("--allow-duplicate", "off — bounded ranked overlap history is checked by default"),
                ("--emit-prompt", "off — when set, requires complete prompt context and validates it before the dispatch write"),
            ),
            notes=(
                "This command only writes the backend dispatch row; it does not spawn or "
                "launch the specialist. After it succeeds, launch the specialist in the active "
                "client and pass the printed Runtime Identity block, then run "
                "`vigil assess agent bind-client-handle <agent-id> ...` so the row names the "
                "session you launched — the handle cannot be supplied here because it does not "
                "exist yet, and it is never a precondition for starting a dispatch. For code "
                "roles the helper validates one active indexed repository before recording and "
                "prints the backend-derived Code Source Identity block immediately after "
                "Runtime Identity.",
                "Every output path prints the exact authored rate budget (or an explicit no-target-traffic declaration). --emit-prompt requires the complete prompt-only object (authorized_phase, target, hunt_scope, mindset_lens, depth_expectation, oob, auth_context, credential_id, prior_state, coverage, cleanup, human_reach_decision, role_specific_additions); missing or empty values fail before the dispatch write. On a blue engagement it also validates and injects customer, platforms, and every owned regular-file tenant reference from scope.json before the write.",
                "`skills` on a specialist dispatch is a WARNING when missing, never a rejection — neither the CLI nor the backend blocks on it. A specialist picks its skills from what it observes, so the honest list is often known only after the dispatch runs. Set it when the applicable skill is already clear; otherwise name it in the handoff.",
                "requested_model and requested_reasoning record the recipe YOU selected. An ordinary dispatch carries no launcher-effective or provider-observed model/reasoning — no trusted launcher integration attests them — so the row is an asserted recipe, never measured truth, and caller-supplied actual_/launcher_effective_ fields are dropped rather than stored. Leaving either unset is visible warning debt: the dispatch stays usable but is not replayable. Never invent a runtime model the client does not expose.",
                "Discover skill names with `vigil assess list-skills` — each value must match a directory under `agent/skills/<name>/`.",
                "Pair with `agent done` when the dispatch finishes; rows left `in-progress` past the dispatch's actual lifetime corrupt dedup checks.",
            ),
            common_mistakes=(
                ("role", "use --role for the agent command; the backend stores agent_role"),
                ("operator role with --skills", "operator dispatches carry no skill audit at all; pass --skills only for specialist roles"),
                ("--skills agent/skills/foo/SKILL.md", "pass the bare skill name (e.g. 'gau-triage'); the validator resolves it on disk"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent start --agent-id va-7f3 "
                        "--role vulnerability-analyst --task 'review SSRF candidates' "
                        "--application-unit-id 42 --model claude-opus-4-8 "
                        "--reasoning high --dispatch-mode item-iterating "
                        "--skills 'ssrf-testing,case-dispatching' "
                        "--rate-budget 'rate=4; concurrency=2' "
                        "--prompt-context-json dispatch-context.json --emit-prompt"
                    ),
                },
            ),
        )
    if verb == "bind-client-handle":
        return CommandContract(
            name="agent bind-client-handle",
            summary=(
                "Bind a recorded dispatch to the client session it is actually "
                "running as, so a mid-flight message can be routed from backend "
                "state instead of a hand-kept mapping."
            ),
            schema_name="backend DispatchClientBindingCreate (POST /dispatches/{agent_id}/client-bindings)",
            preferred_invocations=(
                "vigil assess agent bind-client-handle <agent-id> --client <client> "
                "--session-namespace <scope> --handle <session-id>",
                "vigil assess agent bind-client-handle <agent-id> --client <client> "
                "--session-namespace <scope> --handle <session-id> --note \"<why>\"",
                "vigil assess fetch dispatches/<agent-id>/client-bindings",
            ),
            author_supplied_fields=(
                "<agent-id> (the dispatch from `vigil assess agent start` / `agent list`)",
                "--client (" + "|".join(BINDABLE_CLIENTS) + ")",
                "--session-namespace (the scope the handle is unique within: working "
                "directory, workspace, or host — a bare session id is ambiguous across "
                "clients and machines)",
                "--handle (the client's own identifier for the live session)",
                "--note (optional; why this binding was recorded — most useful on a correction)",
            ),
            helper_defaults=(
                ("binding_version", "1 on the first bind, then N+1 per re-bind"),
                ("bound_at", "now() at the time the bind runs"),
                ("provider_observed_handle", "always 'unknown' — see the notes"),
            ),
            notes=(
                "Run this AFTER launching the client, never before. The handle does not exist "
                "when `agent start` writes the dispatch row, so no flag on `start` could carry "
                "it and a handle is never a precondition for starting a dispatch.",
                "Every stored field is YOUR assertion — you read the handle out of your client "
                "and typed it. The columns are named asserted_client / "
                "asserted_session_namespace / asserted_client_handle for that reason, and "
                "provider_observed_handle stays 'unknown' because no supported client exposes a "
                "stable session id at this boundary. A bound handle is an operator claim about a "
                "live session, NOT verified provenance, and it changes nothing about the "
                "dispatch row's own asserted-recipe semantics.",
                "Binding history is append-only. A correction is a NEW version that stamps the "
                "previous one's superseded_by_id; nothing is ever overwritten, so the record of "
                "what was bound when survives every correction. Re-binding the SAME "
                "client/namespace/handle is refused with 409 rather than adding a duplicate "
                "version that would bury the real corrections.",
                "stdout is one JSON object: {\"binding\": <the new binding>, \"superseded\": "
                "<the binding it replaced, or null>}. Each binding carries id, agent_id, "
                "binding_version, superseded_by_id, asserted_client, asserted_session_namespace, "
                "asserted_client_handle, provider_observed_handle, note, bound_at. A supersede "
                "also prints one stderr line naming both versions, because the retained prior "
                "binding is the part a reader most often misses.",
                "Read the whole history with `vigil assess fetch dispatches/<agent-id>/client-bindings` "
                "(oldest version first). The CURRENT binding and a client_binding_count ride on "
                "every dispatch read, so `agent list`, `agent get`, and `resume-brief` show which "
                "session a dispatch is reachable at — and a count above 1 means the binding was "
                "corrected and the history is worth reading.",
                "A dispatch with no binding is the normal state between `agent start` and the "
                "client launch: client_binding is null and client_binding_count is 0.",
            ),
            common_mistakes=(
                (
                    "treating a bound handle as proof of what ran",
                    "it is caller-asserted; use the instruction-identity fields "
                    "(operator_instruction_sha256 / specialist_instruction_sha256 / "
                    "instruction_identity_status) for the parts the system actually observed",
                ),
                (
                    "re-binding to fix a typo and expecting the bad value to disappear",
                    "the wrong binding stays readable as a superseded version — that IS the "
                    "audit record; pass --note to say what was wrong with it",
                ),
                (
                    "--handle with no --session-namespace",
                    "both are required: a session id without the scope it is unique within "
                    "cannot be used to reach the session",
                ),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent bind-client-handle code-hunter-3 "
                        "--client claude --session-namespace ~/vigil/engagements/acme "
                        "--handle 01JQZ4S8K2A0"
                    ),
                },
                {
                    "command": (
                        "vigil assess agent bind-client-handle code-hunter-3 "
                        "--client codex --session-namespace acme-workspace "
                        "--handle conv_7f31 --note 'claude session died; relaunched in codex'"
                    ),
                },
            ),
        )
    if verb in {"update-status", "done"}:
        return CommandContract(
            name="agent done",
            summary="Patch the lifecycle status (and optionally finding_slugs / completed_at) of a registered dispatch row.",
            schema_name="backend DispatchUpdate (PATCH /dispatches/{agent_id})",
            preferred_invocations=(
                "vigil assess agent done <agent-id> --status completed --finding-slugs <slug1,slug2>",
                "vigil assess agent done <agent-id> --status failed",
                "vigil assess agent done <agent-id> --status aborted",
                "vigil assess agent done AG-1 AG-2 AG-3 --status completed",
            ),
            author_supplied_fields=(
                "<agent-id> (one or more; batch applies the same flags to each)",
                "--status (in-progress|completed|failed|aborted|blocked)",
            ),
            helper_defaults=(
                ("--completed-at", "now() when --status is terminal and the flag is omitted"),
                ("--finding-slugs", "appended additively to the row, not replaced"),
            ),
            notes=(
                "Call when a dispatch returns so cross-dispatch dedup, reporting, and the audit trail see the actual outcome.",
                "Pair `--status completed --finding-slugs <slugs>` so the row names the slugs the specialist produced; `vigil assess agent render-handoff` reads from there.",
            ),
            common_mistakes=(
                ("status=done", "status enum is in-progress / completed / failed / aborted / blocked — 'done' is rejected"),
                ("missing finding-slugs on completed run", "the slug list is what links the dispatch to its produced findings; missing it means the next operator cannot trace what came out"),
            ),
            examples=(
                {
                    "command": "vigil assess agent done va-7f3 --status completed --finding-slugs VA-001,VA-002",
                },
            ),
        )
    if verb == "close":
        return CommandContract(
            name="agent close",
            summary="Consume the latest ready/blocked handoff and close the matching dispatch row.",
            schema_name="GET dispatch-handoffs/{agent_id} + PATCH dispatches/{agent_id} + decision-record",
            preferred_invocations=(
                "vigil assess agent close <agent-id>",
                "vigil assess agent close <agent-id> --reason \"ready handoff reviewed\"",
                "vigil assess agent close AG-1 AG-2 AG-3",
            ),
            author_supplied_fields=(
                "<agent-id> (one or more; batch closes each ready/blocked handoff)",
                "--reason",
            ),
            notes=(
                "Use after a specialist checkpoint marks handoff_status=ready or blocked. Checkpointed handoffs stay open.",
                "Batch: list several agent-ids to close each in a resilient loop; a non-closable/checkpointed dispatch is reported and skipped, not fatal.",
                "Records a dispatch_closed_from_handoff decision row so automated/stale closure stays auditable.",
            ),
        )
    if verb == "reconcile-stale":
        return CommandContract(
            name="agent reconcile-stale",
            summary="List stale in-progress dispatches and optionally close those with ready/blocked handoffs.",
            schema_name="GET dispatches + GET dispatch-handoffs",
            preferred_invocations=(
                "vigil assess agent reconcile-stale --dry-run",
                "vigil assess agent reconcile-stale --max-age-hours 12 --dry-run",
            ),
            author_supplied_fields=(
                "--max-age-hours",
                "--dry-run",
            ),
            notes=(
                "Dry-run is the review surface: it groups stale rows by handoff availability/status.",
                "Without --dry-run, only ready/blocked handoffs are closable; checkpointed or missing handoffs remain in-progress.",
                "Terminal completed/blocked/failed/aborted dispatches without handoffs are also reported. Record an `agent decision --kind dispatch_reconciliation` carrying payload.agent_id to adjudicate an honest no-output terminal row without fabricating a handoff.",
            ),
        )
    if verb in {"record-handoff", "handoff"}:
        return CommandContract(
            name="agent handoff",
            summary=(
                "Persist a specialist's structured exit handoff (summary, next steps, "
                "coverage gaps, runtime issues, working artifacts) into the backend "
                "audit ledger so the next dispatch can render it."
            ),
            schema_name="backend handoff-record (POST /dispatch-handoffs, idempotent upsert)",
            preferred_invocations=(
                "vigil assess agent handoff --from-json <handoff.json>",
            ),
            author_supplied_fields=(
                "--from-json <path|-> containing the complete structured handoff",
                "agent_id, role, and summary (≤2000 chars; required when creating a handoff)",
                "structured arrays: next_steps / coverage_gaps / runtime_issues / working_artifacts / open_questions",
            ),
            helper_defaults=(
                ("upsert", "POST then PATCH on 409 — the operation is idempotent so checkpointing is safe"),
                ("handoff_status", "checkpointed unless --handoff-status is supplied"),
                ("confidence", "omitted when not specified"),
                ("summary length", "measured before the request: an over-long summary is refused locally with its character count, never truncated or split, so the 2000-char cap is not something you learn from a 422"),
            ),
            notes=(
                "Specialists call this from their closing sequence before exiting; the row is then the canonical 'what was done, what's missing, what's next' record for the dispatch.",
                "For an existing handoff, a partial JSON object performs a PATCH and preserves omitted summary and structured arrays.",
                "`render-handoff <agent-id>` reads this row, fetches each named finding, and emits the bounded markdown blob the next dispatch pastes.",
                "JSON payload schema: agent/references/runtime-guides/handoff-schema.md.",
            ),
            common_mistakes=(
                ("transcript paste in summary", "summary is 2000 chars and bounded — use coverage_gaps / next_steps / runtime_issues for structured continuation, not a transcript dump"),
                ("missing recommended_next_agent", "without it, the operator has to re-derive who picks up; set it from the specialist's perspective"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent handoff --from-json handoff.json"
                    ),
                },
            ),
        )
    if verb in {"record-decision", "decision"}:
        return CommandContract(
            name="agent decision",
            summary=(
                "Record a structured operator decision (scope, egress reputation, "
                "dispatch-blocked, vendor-SaaS gate, etc.) into dispatch_decisions for audit."
            ),
            schema_name="backend decision-record (POST /dispatch-decisions)",
            preferred_invocations=(
                "vigil assess agent decision --kind scope_decision --host <host> --vendor <vendor> --choice pending --surfaced-to-user",
                "vigil assess agent decision --kind egress_decision --payload-json '{\"choice\": \"browser-based-tool\", \"egress_block_pct\": 67}'",
                "vigil assess agent decision --kind dispatch_blocked --phase recon --reason \"missing massdns binary in runtime image\" --surfaced-to-user",
                "vigil assess agent decision --kind human_reach_decision --surfaced-to-user --payload-json '{\"choice\": \"pending\", \"endpoint\": \"<path-or-url>\", \"action\": \"<what-it-does>\", \"live_attempts_used\": <n>, \"destination_class\": \"real_third_party|unknown\", \"evidence\": \"<what steps 1-3 showed>\"}'",
                "vigil assess agent decision --kind depth_deferral --surfaced-to-user --payload-json '{\"host\": \"<host>\", \"path_prefix\": \"<prefix>\", \"vuln_classes\": [\"sqli\"], \"reason\": \"<why>\"}'",
            ),
            author_supplied_fields=(
                "--kind (scope_decision|egress_decision|dispatch_blocked|human_reach_decision|depth_deferral|... — the backend accepts any string but report-writer only renders known kinds)",
                "--payload-json OR shorthand flags (--host / --vendor / --choice / --note / --reason / --phase) that build the payload dict",
                "--surfaced-to-user (set when the operator presented the decision to the human; controls whether it appears in user-visible logs)",
            ),
            helper_defaults=(
                ("payload", "constructed from --host/--vendor/--choice/--note/--reason/--phase when --payload-json is omitted"),
                ("surfaced_to_user", "false unless --surfaced-to-user is set"),
            ),
            notes=(
                "Vendor-SaaS scope warnings, egress-block decisions, and dispatch-blocked rows all share this table — keep the --kind taxonomy disciplined so report-writer can summarize by kind.",
                "Set --surfaced-to-user for operator-facing decisions (vendor-SaaS, egress reputation, blocked dispatch) so the human-visible audit log matches what the operator was shown.",
                "--payload-json WINS OUTRIGHT: when it is supplied the shorthand flags are ignored entirely, so a top-level --choice alongside --payload-json is silently dropped and any gate that reads `payload.choice` never fires. Put `choice` INSIDE the JSON object, never as a sibling flag.",
                # --- human_reach_decision: the side-effect preflight -------------
                "`--kind human_reach_decision` IS THE SIDE-EFFECT PREFLIGHT GATE. Run the preflight before sending any request that could create persistent state or reach a human — signup, request-access, support/report/ticket, password-reset, contact-form, or any endpoint whose name or path suggests a write that notifies someone. The posture is CAPPED LIVE-FIRE, not zero-fire: static characterization is unlimited, and genuine ambiguity earns a small, hard, audited budget gated by this recorded decision.",
                "Preflight step 1 — UNLIMITED static characterization, mandatory first. No request budget at all: run as many read-only, non-triggering probes as it takes to learn the methods and parameters the endpoint accepts, the response shape on a non-triggering GET/HEAD/OPTIONS (status, headers, body fields — never the write verb itself), and what the source, API spec, or documentation say it does. Cross-reference ENGAGEMENT.md §4 (No-Fire Endpoints) and §5 (Irreversible and Notifying Flows), including its Known-Safe Test Destinations table, for a pre-declared answer.",
                "Preflight step 2 — the REACHES-A-REAL-THIRD-PARTY test. Ask whether success OR failure lands in a real inbox, queue, or audit trail, or notifies a real person who is not the researcher. POSITIVE (examples, not exhaustive): a live support/ticket queue a real agent reads and actions; an email, SMS, or push delivered to a non-researcher-owned address; a role/access request routed to a real approver; a pager/on-call alert; a post to a customer-visible channel (public comment, shared workspace, forum). NEGATIVE (examples, not exhaustive): a researcher-owned test identity — account, mailbox, or phone number the researcher provisioned and controls; a documented sandbox/staging environment with no live inbox behind it; a mock/stub queue that accepts the request but has no delivery path; a self-directed notification to the researcher's own test account. A proven-NEGATIVE endpoint is ORDINARY SURFACE — hunt it fully, it carries no side-effect risk. Step 1 should aim to reach one of these two answers; only genuine ambiguity after a thorough static pass proceeds.",
                "Preflight step 3 — a HARD 1-3 LIVE-FIRE BUDGET, per endpoint/action, for the WHOLE ENGAGEMENT. If step 2 resolves POSITIVE, or static characterization leaves it genuinely unknown, you may spend 1-3 live requests to resolve the ambiguity, and you stop the instant either condition is met: the probe CONFIRMS the endpoint reaches a real third party, or the budget is exhausted. This is a prompt-enforced discipline and a WARN backstop — nothing in the CLI counts or blocks it — so hold yourself to it with the discipline of a hard cap anyway: it exists to bound the harm of a wrong 'unknown' call, not to license routine live-fire against notify-shaped endpoints. 1-3 is the GLOBAL CEILING; ENGAGEMENT.md may only TIGHTEN it for a program (cap at 1, or reinstate zero-fire for a named endpoint), never loosen it.",
                "CROSS-DISPATCH RULE — check before every fire, and never re-spend. The budget is per endpoint/action for the whole engagement, NOT per dispatch and NOT per specialist: a fresh dispatch does not get a fresh budget, and two specialists must not each independently spend 3 against the same target. Before ANY live human-reach fire, query the authoritative kind-filtered log — `vigil assess fetch \"dispatch-decisions?kind=human_reach_decision\"` (it pages at 100 rows by default; grep the returned JSON for the target host/endpoint) — and if a row on that exact endpoint/action already carries a `payload.choice` of `pending` or `denied`, treat it as BLOCKED and do not fire, regardless of what your own dispatch has spent. The operator is expected to inject any open gate into the dispatch context before sending a specialist at the surface, so the state is inherited rather than rediscovered; check directly anyway.",
                "RECORDING AND CONTINUATION GATE. Any specialist records the decision itself (same pattern as scope_decision) — see the human_reach_decision invocation above for the payload shape — and then does NOT continue live-firing that endpoint/action until the operator resolves it. Four resolution values, recorded on the decision row: `approved_continue` (proceed with further live-fire; rare — the operator has independent grounds the destination is safe), `approved_limited` (proceed under a named, narrower constraint), `denied` (do not fire again; permanently blocked for this endpoint/action), and `not_real_recipient` (the destination was confirmed NOT a real third party — this RETROACTIVELY LIFTS the cap for that endpoint and its siblings, reverting it to ordinary surface per the step-2 negative list). Irreversible and notifying side-effects are not proved by triggering them past this bounded, gated budget; firing past the budget, or past an open pending/denied gate, is the exact harm the preflight exists to prevent. This gate survives every exploit_policy value, `full_send` included, and applies per-action.",
            ),
            common_mistakes=(
                ("freeform reason in --kind", "kinds are vocabulary; put the prose in --note or --reason"),
                ("missing --surfaced-to-user", "user-facing decisions invisible to audit defeats the purpose; set the flag whenever the operator showed the gate to the human"),
                ("--payload-json '{...}' --choice pending", "--payload-json is used verbatim and the shorthand flags are dropped; the cross-dispatch gate reads payload.choice, so put choice inside the JSON"),
                ("a fresh 1-3 human-reach budget per dispatch", "the budget is per endpoint/action for the whole engagement; query dispatch-decisions?kind=human_reach_decision before firing"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent decision --kind scope_decision "
                        "--host api.foo.com --vendor 'Vendor SaaS' --choice pending "
                        "--surfaced-to-user"
                    ),
                },
                {
                    "command": (
                        "vigil assess agent decision --kind human_reach_decision "
                        "--surfaced-to-user --payload-json "
                        "'{\"choice\": \"pending\", \"endpoint\": \"/api/support/ticket\", "
                        "\"action\": \"creates a real support ticket\", "
                        "\"live_attempts_used\": 1, "
                        "\"destination_class\": \"real_third_party\", "
                        "\"evidence\": \"OPTIONS + docs confirm delivery to the vendor queue\"}'"
                    ),
                },
            ),
        )
    if verb == "abort-duplicate":
        return CommandContract(
            name="agent abort-duplicate",
            summary=(
                "Mark an accidentally-duplicated specialist dispatch as aborted and "
                "record a `dispatch_duplicate` decision pointing at the replacement."
            ),
            schema_name="backend DispatchUpdate (PATCH /dispatches/{agent_id}) + decision-record (POST /dispatch-decisions)",
            preferred_invocations=(
                "vigil assess agent abort-duplicate <agent-id> --replacement-agent-id <new-id> --reason \"<text>\"",
            ),
            author_supplied_fields=(
                "<agent-id> (the duplicate to abort)",
                "--replacement-agent-id (the active dispatch that replaces it)",
                "--reason (free text; goes into the decision payload)",
            ),
            helper_defaults=(
                ("status", "aborted"),
                ("completed_at", "now() at the time the abort runs"),
            ),
            notes=(
                "Use instead of `agent done` when the duplicate was noticed AFTER register, so audit retains both the bad row (now aborted) and a paired decision row pointing at the replacement.",
                "`--replacement-agent-id` must already exist in the dispatch registry; the helper checks before aborting so a typo cannot leave the duplicate pointing at a missing canonical dispatch.",
            ),
            common_mistakes=(
                ("aborting the wrong direction", "abort the DUPLICATE id and point --replacement-agent-id at the row you want to keep — flipping these orphans the active dispatch"),
            ),
            examples=(
                {
                    "command": "vigil assess agent abort-duplicate va-bad --replacement-agent-id va-good --reason 'start fired twice — the second one is canonical'",
                },
            ),
        )
    return None
