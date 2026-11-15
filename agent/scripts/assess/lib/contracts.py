"""Stable CLI contract metadata for helper-owned assessment commands."""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import difflib
import argparse
import functools
import json
import os
import re
import sys
from collections.abc import Iterable
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
    MIXED_ASSESSMENT_ROLES as MIXED_ASSESSMENT_ROLES,
    NEXT_TEST_FIELDS as NEXT_TEST_FIELDS,
    NEXT_TEST_ROUTE_HINTS as NEXT_TEST_ROUTE_HINTS,
    CATALOG_PHASES as CATALOG_PHASES,
    COMMAND_GOALS as COMMAND_GOALS,
    CODE_REPO_ROLES as CODE_REPO_ROLES,
    CODE_SKIP_REASONS as CODE_SKIP_REASONS,
    CommandContract,
    ContractVariant,
    GATED_DECISION_KINDS as GATED_DECISION_KINDS,
    DEPENDENCY_ANALYSIS_GAPS as DEPENDENCY_ANALYSIS_GAPS,
    DISPATCH_FINDING_SLUGS_WRITE as DISPATCH_FINDING_SLUGS_WRITE,
    DISPATCH_MODES_BY_ROLE as DISPATCH_MODES_BY_ROLE,
    FINDING_PATCH_FIELDS as FINDING_PATCH_FIELDS,
    FINDING_SEVERITIES as FINDING_SEVERITIES,
    FINDING_WORKFLOW_STATUSES as FINDING_WORKFLOW_STATUSES,
    FRAMEWORK_REGISTRATION_KINDS as FRAMEWORK_REGISTRATION_KINDS,
    KALI_AUDIT_FIELDS as KALI_AUDIT_FIELDS,
    KALI_BLOCKING_TIMEOUT_FIELD,
    KALI_AGENT_ID_FIELD,
    KALI_JOB_AGENT_FIELD,
    KALI_JOB_NOTES,
    KALI_JOB_TIMEOUT_FIELD,
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
    _KALI_COMMON_MISTAKES,
    _KALI_COMMON_NOTES,
    _NAMESPACE_PARENTS,
    _NAMESPACE_ROOT_META,
    _RAW_ENDPOINT_RULES,
    _kali_invocation,
    dispatch_finding_slugs_help,
)
def default_dispatch_mode_for_role(role: str | None) -> str:
    """Return the default ``dispatch_mode`` for a role (L2-1).

    Falls back to ``hypothesis-driven`` for unknown/empty roles. Case-
    insensitive so ``Vulnerability-Analyst`` resolves like the canonical name.
    """
    role_key = str(role or "").strip().lower()
    return DISPATCH_MODES_BY_ROLE.get(role_key, (_DEFAULT_DISPATCH_MODE,))[0]


_SPECIALIST_DISPATCH_REQUIRED_FIELDS: tuple[str, ...] = ()


# Roles exempt from the `skills` requirement. The operator coordinates phases
# and dispatch decisions rather than executing a single skill, so requiring an
# explicit skill list on operator dispatches would be misleading. `general` is
# the blind packet reviewer, and its exemption is the stronger case: `agent
# start` renders a "you MUST read and follow <skill>" line for every skill
# named, while the role's defining rule is that it reads no repository file, so
# `agent/skills/blind-triage/SKILL.md` instructs the operator to name none. For
# that role the warning advises the one thing the gating skill forbids.
# Every other specialist role must declare which skills it loaded so the
# dispatch row is a truthful audit of the specialist context.
_DISPATCH_ROLES_WITHOUT_SKILLS: frozenset[str] = frozenset({"operator", "general"})


def role_declares_no_skills(role: str | None) -> bool:
    """Whether this role is exempt from declaring a skill list.

    The exemption decides two things that must not disagree: whether the
    contract warns about an absent `skills`, and what the dispatch packet says
    in place of the per-skill mandatory-read block. Both read this, so a role
    added to the set above cannot end up warned about by one and instructed by
    the other.
    """
    return bool(role) and str(role).strip().lower() in _DISPATCH_ROLES_WITHOUT_SKILLS


def _agent_skills_root() -> Path:
    """Resolve agent/skills/ relative to this file or VIGIL_REPO_ROOT.

    Used to validate explicitly named skills against the installed catalogue.
    A missing catalogue prevents validating supplied names; omitted skills
    remain valid so specialists can select their own context.
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

    Aligns with the Specialist Dispatch Contract section in ``agent/operator-core.md``.
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

    # Omitted skills permit specialist self-selection. Explicit names must
    # resolve to catalogue directory names before a dispatch is persisted.
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
        if not skills_root.is_dir():
            errors.append("skill catalogue is unavailable; repair the matched Vigil installation before specifying --skills")
        else:
            for skill_name in skills_list:
                if Path(skill_name).name != skill_name or not (skills_root / skill_name / "SKILL.md").is_file():
                    errors.append(
                        f"unknown skill '{skill_name}'; use `vigil assess list-skills` "
                        "and pass the catalogue directory name"
                    )

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
            f"`vigil assess contract {parent} <action>` prints one action's usage, "
            f"fields and example.",
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


def _base_contract(name: str) -> CommandContract | None:
    """The contract registered or built under exactly ``name`` (no variant)."""
    if name.startswith("intel record "):
        # `intel record <type>` is the three-token per-type intel contract.
        # Strip the fixed `intel record ` prefix (partition on the first space
        # would wrongly split "intel" from "record <type>").
        intel_type = name[len("intel record "):]
        return _record_intel_contract(intel_type)
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


def _variant_parent(name: str) -> tuple[CommandContract, str] | None:
    """The variant-bearing contract ``name`` extends, and the rest of ``name``.

    Longest prefix first, so `kali job start` reaches the `kali job` verb
    contract rather than the `kali` dispatcher.
    """
    tokens = name.split()
    for cut in range(len(tokens) - 1, 0, -1):
        parent = _base_contract(" ".join(tokens[:cut]))
        if parent is not None and parent.variants:
            return parent, " ".join(tokens[cut:])
    return None


def _match_variant(parent: CommandContract, rest: str) -> ContractVariant | None:
    """The longest variant of ``parent`` that ``rest`` names.

    A variant that documents a family of sub-actions (`run-audit obligation`)
    also answers for them (`run-audit obligation release`).
    """
    for variant in sorted(parent.variants, key=lambda v: len(v.name), reverse=True):
        if rest == variant.name or rest.startswith(variant.name + " "):
            return variant
    return None


def _mentioned_variants(text: str, parent: CommandContract) -> set[str]:
    """The variants of ``parent`` a note, mistake or default names.

    An action is named in backticks (`` `release` ``, `` `release <id>` ``) or
    after its command (`code-dispatch release`); a bare English word such as
    "list" or "done" does not count.
    """
    named: set[str] = set()
    for variant in parent.variants:
        word = re.escape(variant.name)
        if re.search(rf"`{word}[`\s]|{re.escape(parent.name)} {word}(?![\w-])", text):
            named.add(variant.name)
    return named


def _applies_to(
    text: str, parent: CommandContract, variant: ContractVariant, *, entry: str | None = None
) -> bool:
    """Whether an entry shows under ``variant``: the actions a `Scoped` entry
    states, else the actions it names, else every action."""
    actions = getattr(entry if entry is not None else text, "actions", None)
    if actions is not None:
        return variant.name in actions
    named = _mentioned_variants(text, parent)
    return not named or variant.name in named


def _variant_view(parent: CommandContract, variant: ContractVariant) -> CommandContract:
    """``parent`` narrowed to one action: what `contract <parent> <action>` renders."""
    runs = re.compile(rf"vigil assess {re.escape(parent.name)} {re.escape(variant.name)}(?:\s|$)")
    return replace(
        parent,
        name=f"{parent.name} {variant.name}",
        preferred_invocations=tuple(
            line for line in parent.preferred_invocations if runs.search(line)
        ),
        author_supplied_fields=parent.author_supplied_fields + variant.fields,
        examples=variant.examples,
        helper_defaults=tuple(
            (key, value)
            for key, value in parent.helper_defaults
            if _applies_to(f"{key} {value}", parent, variant, entry=key)
        ),
        notes=tuple(note for note in parent.notes if _applies_to(note, parent, variant)),
        common_mistakes=tuple(
            (wrong, fix)
            for wrong, fix in parent.common_mistakes
            if _applies_to(f"{wrong} {fix}", parent, variant, entry=wrong)
        ),
        variants=(),
    )


def get_contract(name: str) -> CommandContract | None:
    contract = _base_contract(name)
    if contract is not None:
        return contract
    found = _variant_parent(name)
    if found is None:
        return None
    parent, rest = found
    variant = _match_variant(parent, rest)
    return _variant_view(parent, variant) if variant is not None else None


def _require_contract(name: str) -> CommandContract:
    """The contract `name` resolves to, or the refusal that names every one.

    Every rendering entry point asks the same question and owes the reader the
    same answer, so the lookup and its message live here once. An unknown
    action of a known command names that command's actions instead of the whole
    catalogue.
    """
    contract = get_contract(name)
    if contract is not None:
        return contract
    found = _variant_parent(name)
    if found is not None:
        parent, rest = found
        actions = ", ".join(_action_names(parent))
        raise ValueError(
            f"Unknown action '{rest}' for `{parent.name}`. Actions: {actions}. "
            f"`vigil assess contract {parent.name}` lists their invocations."
        )
    children = _family_members(name)
    if children:
        raise ValueError(
            f"`{name}` is a group of contracts: {', '.join(children)}. "
            f"Run `vigil assess contract <one of them>`."
        )
    # A miss inside a family (`kali nmapscan`) owes the family, not the catalogue.
    tokens = name.split()
    for cut in range(len(tokens) - 1, 0, -1):
        family = " ".join(tokens[:cut])
        members = _family_members(family)
        if members:
            close = difflib.get_close_matches(name, members, n=3, cutoff=0.6)
            hint = f" Did you mean: {', '.join(close)}?" if close else ""
            raise ValueError(
                f"Unknown contract '{name}'.{hint} The `{family}` contracts: {', '.join(members)}."
            )
    names = contract_names()
    raise ValueError(f"Unknown contract '{name}'. Available contracts: {', '.join(names)}")


def _family_members(prefix: str) -> list[str]:
    """Every contract name under ``prefix`` (`kali` → `kali alterx`, ...)."""
    names = set(contract_names()) | {f"kali {verb}" for verb in KALI_VERBS}
    return sorted(entry for entry in names if entry.startswith(prefix + " "))


def _action_names(contract: CommandContract) -> list[str]:
    """A multi-action command's actions: its variants, then the actions that are
    contracts of their own (`work-buffer reclassify`)."""
    actions = [variant.name for variant in contract.variants]
    for member in _family_members(contract.name):
        action = member.removeprefix(contract.name + " ")
        if " " not in action and action not in actions:
            actions.append(action)
    return actions


# --------------------------------------------------------------------------- #
# Rendering. `vigil assess contract <command>` prints the compact view: usage,
# the fields one line each, one example, and a header that counts everything it
# leaves out and names the flag that prints it. `--field`, `--notes` and
# `--examples` print those parts; a refused write prints the sections of the
# fields it got wrong (`render_field_sections`).
# --------------------------------------------------------------------------- #

# The tracks `assess.lib.tracks.track_phases` reads out of scope.json, which
# `contract --track` accepts.
CONTRACT_TRACKS: tuple[str, ...] = ("web", "code", "blue", "android", "remediation")

# The schema extensions (`x-vigil-extension: blue/v1`) whose fields the compact
# view shows only on their own track. The backend accepts every extension on
# every track, so a `web/v1` or `code/v1` field stays visible everywhere (a code
# finding's proof still writes poc_request/poc_response); the blue IR keys mean
# nothing outside a blue engagement, and they are a fifth of `details`.
_TRACK_BOUND_EXTENSIONS: frozenset[str] = frozenset({"blue"})

# A helper default this short is printed whole on the field's compact line. A
# longer one prints its head (the text before " — ") when that is short, and the
# header counts it, because the rest is the field's full text behind `--field`.
_INLINE_DEFAULT_CHARS = 100
_INLINE_DEFAULT_HEAD_CHARS = 40


@dataclass(frozen=True)
class _Field:
    """One writable field of a contract, as the compact view and `--field` see it."""

    path: str
    compact: str
    full: tuple[str, ...]
    track: str = ""


def _contract_schema(contract: CommandContract) -> dict[str, Any]:
    if not contract.schema_name.endswith(".schema.json"):
        return {}
    return load_schema(contract.schema_name)


def _field_track(prop: dict[str, Any]) -> str:
    extension = str(prop.get("x-vigil-extension") or "")
    track = extension.partition("/")[0]
    return track if track in _TRACK_BOUND_EXTENSIONS else ""


def _inline_default(value: str) -> str:
    """What of a helper default its field's compact line prints ("" for none)."""
    if len(value) <= _INLINE_DEFAULT_CHARS:
        return value
    head = value.split(" — ", 1)[0].strip()
    return head if len(head) <= _INLINE_DEFAULT_HEAD_CHARS else ""


def _compact_annotation(
    prop: dict[str, Any], *, required: bool, default: str | None
) -> str:
    """The parenthesised domain on a field's compact line.

    Type, then whether the author must supply it or the helper fills it, then
    what a value may legally be: the enum, and the keys of an object (``*``
    marks a key the object requires). Descriptions are the field's full text.
    """
    parts = [_schema_type_label(prop)]
    if required:
        parts[0] += ", required"
    elif default is not None:
        inline = _inline_default(default)
        parts.append(f"default {inline}" if inline else "helper-filled")
    node = _schema_content_node(prop)
    enum = prop.get("enum")
    if enum is None:
        enum = node.get("enum")
    if isinstance(enum, list) and enum:
        parts.append("one of: " + ", ".join(_enum_value_label(value) for value in enum))
    properties = node.get("properties")
    if isinstance(properties, dict) and properties:
        nested_required = node.get("required")
        marked = set(nested_required) if isinstance(nested_required, list) else set()
        parts.append(
            "keys: " + ", ".join(
                key + ("*" if key in marked else "") for key in sorted(properties)
            )
        )
    if node.get("additionalProperties") is True:
        parts.append("other keys allowed")
    return "; ".join(parts)


def _schema_fields(contract: CommandContract) -> list[_Field]:
    """The fields of a schema-backed contract: top level, then ``details.*``.

    A name the schema requires but a helper default fills is not author-required,
    which is a derivation from the defaults rather than a second list. The
    ``details`` object of the verb that owns its vocabulary renders key by key.
    """
    schema = _contract_schema(contract)
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return []
    defaults = dict(contract.helper_defaults)
    required = schema.get("required")
    author_required = {
        name for name in (required if isinstance(required, list) else ())
        if name not in defaults
    }
    expand = "details" if contract.details_schema_name else ""
    fields: list[_Field] = []

    def _add(node: dict[str, Any], prefix: str, required_here: set[str]) -> None:
        props = node.get("properties")
        if not isinstance(props, dict):
            return
        for name in sorted(str(key) for key in props):
            prop = props[name] if isinstance(props[name], dict) else {}
            path = prefix + name
            if path == expand:
                nested_required = prop.get("required")
                _add(
                    prop,
                    path + ".",
                    set(nested_required) if isinstance(nested_required, list) else set(),
                )
                continue
            is_required = name in required_here
            annotation = _compact_annotation(
                prop, required=is_required, default=defaults.get(path)
            )
            fields.append(
                _Field(
                    path=path,
                    compact=f"  - {path} ({annotation})",
                    full=tuple(_schema_path_lines(schema, path, helper_filled=defaults)),
                    track=_field_track(prop),
                )
            )

    _add(schema, "", author_required)
    # Top-level fields first, then the expanded `details.*` keys.
    return sorted(fields, key=lambda item: (bool(expand) and item.path.startswith(expand + "."), item.path))


def compact_field_line(name: str, path: str) -> str:
    """The compact line for one schema field at any depth, keys and all.

    A field the compact view prints gets that exact line; a deeper one (an
    object inside ``details``) gets the same annotation, built from its schema.
    """
    contract, _ = _resolve_view(name)
    for item in _contract_fields(contract):
        if item.path == path:
            return item.compact
    node: dict[str, Any] = _contract_schema(contract)
    prop: dict[str, Any] = {}
    required = False
    for part in path.split("."):
        props = node.get("properties")
        child = props.get(part) if isinstance(props, dict) else None
        if not isinstance(child, dict):
            raise ValueError(f"`{contract.name}` declares no field '{path}'")
        declared = node.get("required")
        required = isinstance(declared, list) and part in declared
        prop, node = child, _schema_content_node(child)
    return f"  - {path} ({_compact_annotation(prop, required=required, default=None)})"


def _top_level_fields(contract: CommandContract) -> list[_Field]:
    """The fields of a verb whose request shape is a backend model."""
    if contract.schema_name.endswith(".schema.json"):
        return []
    return [
        _Field(
            path=name,
            compact=f"  - {name} ({domain})",
            full=(f"  - {name} ({domain}) — {meaning}",),
        )
        for name, domain, meaning in contract.top_level_fields
    ]


def _contract_fields(contract: CommandContract) -> list[_Field]:
    return _schema_fields(contract) or _top_level_fields(contract)


def _visible(fields: list[_Field], tracks: Iterable[str] | None) -> tuple[list[_Field], dict[str, int]]:
    """Split ``fields`` into those the active tracks write and per-track hidden counts."""
    if tracks is None:
        return fields, {}
    active = set(tracks)
    shown: list[_Field] = []
    hidden: dict[str, int] = {}
    for item in fields:
        if item.track and item.track not in active:
            hidden[item.track] = hidden.get(item.track, 0) + 1
        else:
            shown.append(item)
    return shown, hidden


def _example_text(example: dict[str, Any]) -> str:
    return json.dumps(example, indent=2, ensure_ascii=False)


def _count(number: int, noun: str) -> str:
    return f"{number} {noun}" + ("" if number == 1 else "s")


def _not_shown_line(
    contract: CommandContract,
    fields: list[_Field],
    hidden_tracks: dict[str, int],
    *,
    parent: CommandContract | None,
) -> str:
    """The header that counts what the compact view leaves out and how to print it."""
    command = f"vigil assess contract {contract.name}"
    # A default printed whole on its field's compact line is shown; any other
    # (a nested key, a flag, a long default whose line carries only its head)
    # is counted here.
    lined = {item.path for item in fields} if _contract_schema(contract) else set()
    hidden_defaults = [
        key for key, value in contract.helper_defaults
        if key not in lined or _inline_default(value) != value
    ]
    parts: list[str] = []
    if fields:
        parts.append(f"each field's description and rules (`{command} --field <name>`)")
    else:
        parts.append(f"everything said about one field or flag (`{command} --field <name>`)")
    rest = [
        _count(len(contract.notes), "note") if contract.notes else "",
        _count(len(contract.common_mistakes), "common mistake") if contract.common_mistakes else "",
        _count(len(hidden_defaults), "helper default") if hidden_defaults else "",
    ]
    rest = [entry for entry in rest if entry]
    if rest:
        parts.append(f"{', '.join(rest)} (`{command} --notes`)")
    if len(contract.examples) > 1:
        parts.append(f"{_count(len(contract.examples) - 1, 'more example')} (`{command} --examples`)")
    for track, number in sorted(hidden_tracks.items()):
        parts.append(f"{number} {track}-track field{'s' if number != 1 else ''} (`{command} --track {track}`)")
    if contract.variants:
        parts.append(
            f"each action's fields and example (`vigil assess contract {contract.name} <action>`)"
        )
    if parent is not None:
        others = _other_actions_counts(parent, contract)
        if others:
            parts.append(
                f"{others} about other actions (`vigil assess contract {parent.name} --notes`)"
            )
    return "Not shown: " + "; ".join(parts) + "."


def _other_actions_counts(parent: CommandContract, view: CommandContract) -> str:
    """The notes, mistakes and defaults an action's view filtered out, counted."""
    hidden = [
        (len(parent.notes) - len(view.notes), "note"),
        (len(parent.common_mistakes) - len(view.common_mistakes), "common mistake"),
        (len(parent.helper_defaults) - len(view.helper_defaults), "helper default"),
    ]
    return ", ".join(_count(number, noun) for number, noun in hidden if number > 0)


def _resolve_view(name: str) -> tuple[CommandContract, CommandContract | None]:
    """The contract ``name`` names, and its variant-bearing parent when it is an action."""
    contract = _require_contract(name)
    if _base_contract(name) is not None:
        return contract, None
    found = _variant_parent(name)
    return contract, (found[0] if found is not None else None)


def render_contract(
    name: str,
    *,
    tracks: Iterable[str] | None = None,
    track_source: str = "",
    track_fallback: str = "",
) -> str:
    """The compact view `vigil assess contract <command>` prints.

    ``tracks`` hides the fields of a track-bound extension
    (``_TRACK_BOUND_EXTENSIONS``) the caller's tracks do not include; ``None``
    shows every track. ``track_source`` says where the tracks came from, and
    ``track_fallback`` why every track is shown, for the header.
    """
    contract, parent = _resolve_view(name)
    fields, hidden_tracks = _visible(_contract_fields(contract), tracks)
    lines = [
        f"Command: {contract.name} — {contract.summary}",
        _not_shown_line(contract, fields, hidden_tracks, parent=parent),
    ]
    if contract.schema_name.endswith(".schema.json"):
        lines.append(f"Schema: agent/schemas/{contract.schema_name}")
    if any(item.track for item in _contract_fields(contract)):
        scope = ", ".join(sorted(tracks)) if tracks is not None else "every track"
        if tracks is not None and track_source:
            scope += f" (from {track_source})"
        elif tracks is None and track_fallback:
            scope += f" ({track_fallback})"
        lines.append(f"Track fields shown: {scope}")
    if contract.preferred_invocations:
        lines.extend(["", "Usage:"])
        lines.extend(f"  {entry}" for entry in contract.preferred_invocations)
    if contract.variants:
        lines.extend(["", "Actions: " + ", ".join(_action_names(contract))])
    if contract.author_supplied_fields:
        lines.extend(["", "Author supplies:"])
        lines.extend(f"  - {entry}" for entry in contract.author_supplied_fields)
    if fields:
        lines.extend(["", "Fields (one line each; `required` = you must supply it):"])
        lines.extend(item.compact for item in fields)
    if contract.examples:
        lines.extend(["", "Example:", _example_text(contract.examples[0])])
    return "\n".join(lines)


def _term_pattern(term: str) -> re.Pattern[str]:
    return re.compile(rf"(?<![\w.-]){re.escape(term)}(?![\w-])")


def _search_terms(name: str) -> list[str]:
    """What a `--field` name matches in prose: itself, and a flag spelling of it."""
    clean = name.strip()
    terms = [clean]
    if clean and not clean.startswith(("-", "<")):
        terms.append("--" + clean)
    return terms


def _mentions(text: str, terms: list[str]) -> bool:
    return any(_term_pattern(term).search(text) for term in terms)


def _schema_paths(schema: dict[str, Any]) -> list[str]:
    """Every dotted property path a schema declares, nested content included."""
    paths: list[str] = []

    def _walk(node: dict[str, Any], prefix: str) -> None:
        props = node.get("properties")
        if not isinstance(props, dict):
            return
        for key in sorted(str(k) for k in props):
            prop = props[key] if isinstance(props[key], dict) else {}
            paths.append(prefix + key)
            _walk(_schema_content_node(prop), prefix + key + ".")

    _walk(schema, "")
    return paths


def _schema_path_lines(
    schema: dict[str, Any], path: str, *, helper_filled: Iterable[str] = ()
) -> list[str]:
    """One declared property, at any depth, rendered with its description and content.

    ``required`` is the declaring object's own array, less the names a helper
    default fills (the top level of a helper-normalized verb), so it always
    means "the author must supply it".
    """
    node: dict[str, Any] = schema
    parts = path.split(".")
    for part in parts[:-1]:
        props = node.get("properties")
        child = props.get(part) if isinstance(props, dict) else None
        if not isinstance(child, dict):
            return []
        node = _schema_content_node(child)
    props = node.get("properties")
    if not isinstance(props, dict) or parts[-1] not in props:
        return []
    required = node.get("required")
    single = {
        "properties": {parts[-1]: props[parts[-1]]},
        "required": [parts[-1]]
        if isinstance(required, list) and parts[-1] in required and path not in set(helper_filled)
        else [],
    }
    lines = _schema_object_lines(single, depth=0, mark_required=True, deferred_fields=())
    if lines:
        lines[0] = lines[0].replace(f"  - {parts[-1]} (", f"  - {path} (", 1)
    return lines


def _field_matches(contract: CommandContract, name: str) -> list[str]:
    """The schema paths a `--field` name resolves to: exact, else by unique leaf."""
    schema = _contract_schema(contract)
    paths = _schema_paths(schema) if schema else [item.path for item in _top_level_fields(contract)]
    clean = name.strip().removeprefix("payload.")
    if clean in paths:
        return [clean]
    return [path for path in paths if path.endswith("." + clean)]


def _contract_terms(contract: CommandContract) -> list[str]:
    """Every field and flag name the contract's text uses, for did-you-mean."""
    found: list[str] = []
    texts = [
        *contract.preferred_invocations,
        *contract.author_supplied_fields,
        *(key for key, _ in contract.helper_defaults),
    ]
    pattern = re.compile(r"--[a-z][a-z0-9-]*|<[^<>\s]+>|\b[a-z][a-z0-9]*(?:[_.][a-z0-9]+)+\b")
    for text in texts:
        for term in pattern.findall(text):
            if term not in found:
                found.append(term)
    schema = _contract_schema(contract)
    for path in _schema_paths(schema) if schema else [f.path for f in _top_level_fields(contract)]:
        if path not in found:
            found.append(path)
    return found


def _field_section(contract: CommandContract, name: str) -> list[str]:
    """Everything a contract says about one field; empty when it says nothing."""
    schema = _contract_schema(contract)
    lines: list[str] = []
    matches = _field_matches(contract, name)
    terms = list(dict.fromkeys(term for match in matches or [name] for term in _search_terms(match)))
    for match in matches:
        if schema:
            helper_filled = [key for key, _ in contract.helper_defaults]
            lines.extend(_schema_path_lines(schema, match, helper_filled=helper_filled))
        else:
            lines.extend(
                line for item in _top_level_fields(contract) if item.path == match for line in item.full
            )
    author = [entry for entry in contract.author_supplied_fields if _mentions(entry, terms)]
    usage = [entry for entry in contract.preferred_invocations if _mentions(entry, terms)]
    defaults = [
        f"  - {key} = {value}" for key, value in contract.helper_defaults
        if _mentions(key, terms) or (not schema and _mentions(value, terms))
    ]
    mistakes = [
        f"  - {wrong} -> {fix}" for wrong, fix in contract.common_mistakes
        if _mentions(f"{wrong} {fix}", terms)
    ]
    notes = [f"  - {note}" for note in contract.notes if _mentions(note, terms)]
    if not matches and usage:
        lines.extend(["  Usage:", *(f"    {entry}" for entry in usage)])
    if author:
        lines.extend(["  Author supplies:", *(f"    - {entry}" for entry in author)])
    if defaults:
        lines.extend(["  Helper default:", *(f"  {line}" for line in defaults)])
    if mistakes:
        lines.extend(["  Common mistakes:", *(f"  {line}" for line in mistakes)])
    if notes:
        lines.extend(["  Notes:", *(f"  {line}" for line in notes)])
    return lines


def render_field_sections(
    name: str, fields: Iterable[str], *, strict: bool = True
) -> str:
    """The full text for each named field: `contract <command> --field <name>`.

    Also what a refused write prints for the fields it got wrong (``strict=False``):
    a name the contract says nothing about gets a did-you-mean line instead of
    raising, and the block ends with the pointer to every other field.
    """
    contract, _ = _resolve_view(name)
    command = f"vigil assess contract {contract.name}"
    blocks: list[str] = []
    for field_name in fields:
        section = _field_section(contract, field_name)
        if section:
            blocks.append("\n".join([f"{contract.name} --field {field_name}", *section]))
            continue
        close = difflib.get_close_matches(field_name, _contract_terms(contract), n=4, cutoff=0.6)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        message = f"`{contract.name}` says nothing about '{field_name}'.{hint}"
        if strict:
            raise ValueError(f"{message} `{command}` lists its fields.")
        blocks.append(message)
    blocks.append(
        f"Any other field: `{command} --field <name>`; every field on one line each: `{command}`."
    )
    return "\n\n".join(blocks)


def render_contract_notes(name: str) -> str:
    """Everything the compact view leaves out that is not one field's text or an example."""
    contract, parent = _resolve_view(name)
    lines = [f"Command: {contract.name} — notes"]
    lines.append(f"Schema: {contract.schema_name}")
    if contract.phase:
        lines.append(f"Phase: {', '.join(contract.phase)}")
    if contract.goals:
        lines.append(f"Goals: {', '.join(contract.goals)}")
    if contract.helper_defaults:
        lines.extend(["", "Helper defaults:"])
        lines.extend(f"  - {key} = {value}" for key, value in contract.helper_defaults)
    if contract.common_mistakes:
        lines.extend(["", "Common mistakes:"])
        lines.extend(f"  - {wrong} -> {fix}" for wrong, fix in contract.common_mistakes)
    if contract.notes:
        lines.extend(["", "Notes:"])
        lines.extend(f"  - {note}" for note in contract.notes)
    others = _other_actions_counts(parent, contract) if parent is not None else ""
    if parent is not None and others:
        lines.extend([
            "",
            f"These are the entries that apply to `{contract.name.removeprefix(parent.name + ' ')}` "
            f"or to every action; `vigil assess contract {parent.name} --notes` also prints "
            f"{others} about other actions.",
        ])
    lines.extend(["", "Assessment binding:", f"  {ENGAGEMENT_BINDING_CONTRACT}"])
    return "\n".join(lines)


def render_contract_examples(name: str) -> str:
    """Every example the contract carries (the compact view prints the first)."""
    contract, _ = _resolve_view(name)
    if not contract.examples:
        return f"Command: {contract.name} — no examples; see its Usage lines."
    return "\n".join(
        [f"Command: {contract.name} — examples", *(_example_text(e) for e in contract.examples)]
    )


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
    contract = _require_contract(name)

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


_DEFERRED_FIELD_POINTER = "its keys print one at a time with `--field <field>.<key>`"


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
    values a freshly-recorded finding takes. Those descriptions were already
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


def _schema_required_names(schema_name: str) -> list[str]:
    if not schema_name.endswith(".schema.json"):
        return []
    schema = load_schema(schema_name)
    required = schema.get("required", [])
    if not isinstance(required, list):
        return []
    return sorted(str(name) for name in required)


_KALI_VERB_NOTES: dict[str, tuple[str, ...]] = {
    "nmap-scan": (
        "Default is top-1000 ports; use --ports full for `-p-`, or pass an explicit list (e.g. 22,80,443).",
        "Defaults to `-sT` (TCP connect). Do NOT use `-sS` here — raw SYN probes are dropped by Docker's userland NAT (esp. Docker Desktop/macOS) and silently return 0-open on live hosts. Use `--scan-type sS` only on a bridged-network Linux runtime.",
        "--scripts default,vuln triggers heavy NSE: scope it to the open ports from a first pass so it fits one blocking call (--timeout 600 or less); a sweep that cannot fit is an operator-owned `kali job` a specialist names in next_steps.",
    ),
    "nuclei": (
        "Templates live under the runtime's persistent /data/nuclei-templates; a fresh runtime "
        "starts downloading them in the background, and `kali nuclei --update-templates` (no "
        "target; nuclei exits after updating) downloads or refreshes them.",
        "Pass either -u or -l. LEAD with explicit `-t` template paths — `-as` (automatic) keys off "
        "tech fingerprinting, which a CDN/WAF defeats, so `-as` under-fires alone; treat it as additive.",
        "WAF-resilience: the wrapper injects `-mhe 50` by default so a host's 403 storm does not make "
        "nuclei ABANDON the host after ~30 errors (its own default). Add `-random-agent` and `-H` "
        "browser headers when the edge blocks scanner UAs.",
        "Politeness `-exclude-tags dos,fuzz,intrusive,brute-force` is injected by default (announced on "
        "stderr); pass your own `-exclude-tags` to override it verbatim. The result's `resolved_argv` "
        "shows the exact command that ran after injection.",
        "Blind callbacks are disabled by default (`--oob-mode none` injects `-ni`). `public` is an explicit data-egress choice; `vigil` uses the OOB domain resolved and exported by the top-level `vigil assess` launcher.",
        "A sweep runs as blocking calls of --timeout 600 or less: split the host list or template set so each call fits. A sweep that cannot be split to fit is an operator-owned `kali job`; a specialist names it in next_steps and never starts a job itself.",
    ),
    "httpx": (
        "Alt-port liveness: pass -ports/-p <comma-list> (e.g. 80,443,8080,8443) whenever "
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
        "fill the disk), `-ef <static set>`, and JS endpoint crawling + jsluice extraction. "
        "`--keep-bodies` / `--include-static` undo the disk/asset defaults for a bounded source pass.",
        "The crawl follows only the hosts scope.json declares: with no wildcard entry each seed stays on "
        "its own host (`-fs fqdn`), a `*.example.com` entry lets it follow that apex and every subdomain "
        "(a custom `-fs` host regex), an anchored `-cs` regex admits exactly the declared hosts, and each "
        "`out_of_scope` host is excluded with `-cos`. stderr names the fence and warns about a `-u` seed "
        "scope.json does not declare (its links are not followed). `-cos` adds an exclusion of your own.",
        "Rate is SAFE by default and decoupled from depth: `-rl 10`, hard-capped at 20 req/s (warn + "
        "clamp above; `--allow-fast-crawl` to exceed) and always clamped DOWN to the program rate "
        "ceiling. Go as deep as you like — politeness comes from the rate cap, not a shallow crawl.",
        "An explicit `-fs` (`dn`, `rdn`, `fqdn` or a host regex) replaces the fence's field scope and "
        "keeps its scope.json `-cs`; `-fs`, `-cs` or `-ns` inside --extra-args replace the whole fence "
        "with a WARN, so the run crawls the boundary you stated and the audit row records the argv.",
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
        "--passive adds parameter names harvested from wayback/commoncrawl/otx to the wordlist and then scans the target actively, so it raises request volume rather than lowering it. Bare --passive harvests the -u target's own domain and needs -u; pass --passive <domain> with -i. Keep --stable --rate-limit set on a rate-sensitive target.",
        "--headers is auth-aware: pass an authenticated session (Authorization/Cookie) to surface params visible only behind auth. Header-only params are recorded as a signal on ingest (no classifier field maps to a header).",
        "Default wordlist is Arjun's db/large.txt (most thorough); override with -w for a faster list. Politeness knobs: --stable, -d (delay), -T (timeout), -t (threads), --rate-limit.",
        "SQLMAP doctrine: Arjun + the classifier ISOLATE the injectable param; sqlmap confirms and does high-volume blind/time-based extraction. When an enriched row routes to gf:sqli (or carries an id=/numeric param on a DB-ish route), ingest-arjun names `vigil assess kali sqlmap` in triage_rationale as the confirmation step. sqlmap is operator-invoked, never auto-fired. See references/tools/recon/arjun.md.",
    ),
    "cero": (
        "TLS-handshake SAN scraper — connects to TCP/TLS on the listed ports and harvests certificate Subject Alternative Names. Complements CT-log enumeration when targets issue private certs.",
        "Default feed is the de-duplicated A-record IPs of resolved origin/staging hosts; a whole asnmap CIDR is a gated escalation (target-owned non-cloud netblock, runtime not Docker Desktop) — see references/tools/recon/cero.md.",
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
        "The full passive preset (`-p subdomain-enum -rf passive`) regularly runs 15-30 minutes, past the 600 s blocking-call ceiling. A specialist runs a focused module set (`-m`) that fits one call and names the full sweep in next_steps; the operator runs that as a `kali job`.",
    ),
    "dnsx": (
        "The typed wrapper applies Docker-safe defaults: --dnsx-profile polite-cdn, --resolver-profile public-tcp, -rl 100, -t 20, -retry 3, -timeout 5.",
        "Do lean bulk resolution first (no -resp/-json), then enrich survivors with -resp -json. Unknown-size or bulk -resp/-json list inputs require --allow-bulk-json.",
        "Rate/thread values above polite-residential require --dnsx-profile bursty-ok; above bursty-ok requires --allow-unsafe-rate.",
        "Common record/filter flags are typed (-aaaa, -mx, -txt, -ns, -soa, -ptr, -asn, -cdn, -rcode, -wd). Use --extra-args only for unmodeled dnsx flags that are not guarded load/transport knobs.",
    ),
    "browser": (
        "Playwright/system-Chromium workflow inside the runtime. Returns origin status, final DOM, screenshot, bounded console/network metadata, route candidates, and typed-step results as one JSON object. The printed result names the driver program by sha256 in `resolved_argv`, and `stdout_preview` keeps the first entries of each list followed by a `[vigil] browser preview omitted:` line counting what it left out (and what the driver's own caps dropped) and naming the run's full stdout file, the HAR and the DOM that hold the rest.",
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
        "WAF-aware: --waf-evasion enables dalfox's evasion mode; --skip-bav drops the basic-another-vuln scan to keep the run focused on XSS. Politeness: --delay (ms), -w workers. Two timeouts, two meanings: --timeout (required) is the run's wall-clock audit budget, while --dalfox-timeout is dalfox's PER-REQUEST timeout and is passed through as dalfox's own --timeout inside the container. Setting one does not bound the other.",
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
        "Keep a blocking call's --timeout at 600 seconds or less. Above the CLI's own --timeout sits an agent-harness ceiling you do not control; a call that outruns it is auto-backgrounded with the agent killed (exit 144 / SIGUSR1), orphaning the probe and writing no handoff, while a --timeout under it lets the CLI's SIGTERM/SIGKILL end the run cleanly. Size the sweep (host list, wordlist, rate) to fit; work that cannot fit is an operator-owned job (`vigil assess contract kali job`) a specialist names in next_steps.",
    ),
    "job": (
        "The operator runs a probe that cannot fit one blocking call (--timeout 600 or less) as `vigil assess kali job start ...`. The dtach session is parented by tini so it survives the calling shell.",
        "Job start uses the same pre-execution preparation as synchronous Kali execution: `--identity` material (plus `--identity-scope` for a scoped alias and `--identity-target` for an argv shape Vigil cannot classify), required attribution headers, nuclei OOB safety, target scope, denied tools, and rate policy are applied before audit/spawn.",
        "OPERATOR-ONLY, AND A DISPATCHED SPECIALIST NEVER USES IT. Target-facing work runs SYNCHRONOUSLY: each `vigil assess kali <verb> ... --timeout N` call is blocking and awaited in-band — no run_in_background, no `job start`, no dtach, no watcher/poll loop. A specialist that backgrounds target traffic and halts for a completion notification gets auto-resumed by the harness, launches the next detached job, and halts again: unbounded relaunch thrash, duplicate probes, near-zero net coverage. A specialist that needs a probe to outlive its dispatch names it in next_steps and lets the operator own the job.",
        "\"Synchronous\" means AWAITED-IN-BAND, not one-call-at-a-time. Several blocking calls in parallel, each awaited in-band, are fine; what is banned is detaching a job and reaping it later. Each blocking call keeps --timeout at 600 seconds or less — on expiry the audit pipeline cascades SIGTERM then SIGKILL (after 5s) into the in-container PID, the row records timed_out=true, and nothing is orphaned.",
        "The ceiling that makes this a real choice: above the CLI's --timeout sits a separate agent-harness limit you do not control, and a blocking call that runs too long is auto-backgrounded with the agent killed (exit 144 / SIGUSR1) — the probe is orphaned and no handoff is written. So a single synchronous probe keeps --timeout at 600 seconds or less; a sweep that genuinely cannot fit is what `job start` is for, launched and monitored by the operator, never as a per-step or fan-out pattern.",
    ),
    "sweep": (
        "A DUMB fan-out: it expands ONLY the values you literally typed and reports ONLY what was probed. No seed-id lists, no opaque-id decoding, no hostname/metadata-path invention — `--values` is REQUIRED and a template with no placeholder is an error, so it can never silently run N identical commands.",
        "Each value becomes its own `kali exec` inside the runtime, so every value gets its own command-runs audit row; the summary then clusters the results by distinct response signature.",
        "Clustering reuses the project's EXISTING reachability taxonomy (LIVE / BLACKHOLED / TLS-reset / UNKNOWN, plus the dns-fail vs connection-refused split). `filter-rejected` is derived PURELY from identical reachable responses repeated across distinct values — never from a rule that 'knows' a filter exists.",
        "Politeness: --max-values caps expansion (default 200) and --concurrency defaults to 1; >1 requires --allow-concurrent because of the per-host \"<=1 active target-facing probe\" rule.",
        "--timeout bounds each value's run, and the values run --concurrency at a time, so the whole sweep blocks for up to (values / concurrency) × --timeout. Keep that within the 600 s blocking-call ceiling: split a longer value list across calls.",
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
            "command": "vigil assess kali nmap-scan --target example.com --ports top-1000 --service-detection --technique RECON --intent 'Phase 1 baseline port + service' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "nuclei": (
        {
            "command": "vigil assess kali nuclei -l hosts.txt -t http/cves/,http/misconfiguration/,http/exposures/ -severity high,critical -mhe 50 -random-agent -rate-limit 50 -c 25 -bs 25 -jsonl -o scans/nuclei.jsonl --oob-mode none --technique RECON --intent 'reactive sweep on Phase-1 URL delta (WAF-resilient)' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "katana": (
        {
            "command": "vigil assess kali katana -u https://target.example -o scans/katana_target.jsonl -jsonl --technique DISCOVERY --intent 'JS-aware scoped crawl' --probe-kind fingerprint --phase collect --timeout 600",
        },
        {
            "command": "vigil assess kali katana -u https://app.target.example -headless --allow-fast-crawl -rl 40 -o scans/katana_spa.jsonl -jsonl --technique DISCOVERY --intent 'headless crawl for browser-generated routes' --probe-kind fingerprint --phase collect --timeout 600",
        },
    ),
    "tool-help": (
        {
            "command": "vigil assess kali tool-help katana",
        },
    ),
    "sqlmap": (
        {
            "command": "vigil assess kali sqlmap -u 'https://target/?id=1' --batch --sql-technique BEUSTQ --level 3 --risk 2 --technique SQLI --intent 'verify SQLi on id parameter' --probe-kind payload --phase consume-test --timeout 600",
        },
    ),
    "arjun": (
        {
            "command": "vigil assess kali arjun -u https://target/api/item --technique DISCOVERY --intent 'hidden GET param discovery on item endpoint' --probe-kind fingerprint --phase consume-test --timeout 600",
        },
        {
            "command": "vigil assess kali arjun -i /engagements/$ENGAGEMENT_KEY/scans/arjun/targets.txt.JSON -m JSON --identity user_a --stable --rate-limit 10 --technique DISCOVERY --intent 'authed JSON-API hidden-param discovery on gated route list' --probe-kind fingerprint --phase consume-test --timeout 600",
        },
        {
            "command": "vigil assess kali arjun -u https://target/search --passive --stable --rate-limit 10 --technique PARAM-DISCOVERY --intent 'hidden-param discovery with archive-mined names (wayback/otx/commoncrawl)' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "cero": (
        {
            "command": "vigil assess kali cero -l /engagements/$ENGAGEMENT_KEY/scans/origin_ips.txt -p 443,8443,9443 -c 100 -t 4 -o /engagements/$ENGAGEMENT_KEY/scans/cero_sans.txt --technique OSINT --intent 'TLS SAN scrape across resolved origin/staging IPs' --probe-kind fingerprint --phase recon --timeout 600",
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
            "command": "vigil assess kali bbot -t example.com -m crt -m certspotter -m hackertarget -rf passive -o /engagements/$ENGAGEMENT_KEY/scans/bbot_subs --technique OSINT --intent 'focused passive subdomain pass' --probe-kind fingerprint --phase recon --timeout 600",
        },
    ),
    "dnsx": (
        {
            "command": "vigil assess kali dnsx -l /engagements/$ENGAGEMENT_KEY/scans/candidates.txt --dnsx-profile polite-cdn --resolver-profile public-tcp -silent -o /engagements/$ENGAGEMENT_KEY/scans/candidates_resolved.txt --technique RECON --intent 'lean dnsx resolution without bulk JSON' --probe-kind baseline --phase recon --timeout 600",
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
            "command": "vigil assess kali dalfox -u 'https://target.example/search?q=test' -p q --skip-bav --silence -o scans/dalfox_q.txt --technique XSS --intent 'confirm reflected XSS on arjun-surfaced q param' --probe-kind payload --phase consume-test --timeout 600",
        },
        {
            "command": "vigil assess kali dalfox -i /engagements/$ENGAGEMENT_KEY/scans/arjun_xss_candidates.txt --waf-evasion -w 30 --delay 100 --format json -o scans/dalfox_batch.json --technique XSS --intent 'reflective XSS sweep over arjun param-bearing URLs (WAF-aware)' --probe-kind payload --phase consume-test --timeout 600",
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
            f"<verb>, target-facing (takes every flag below): {', '.join(KALI_TARGET_VERBS)}",
            f"<verb>, host-side maintenance (no audit flags; touches no target): {', '.join(KALI_MAINT_VERBS)}",
            *KALI_AUDIT_FIELDS,
        ),
        notes=_KALI_COMMON_NOTES,
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
                "--probe-kind <kind> --phase <phase> --timeout 30 --values \"1,2,7-9\" "
                "-- curl -s -o /dev/null -w '%{http_code}' https://app.example.com/orders/{}",
                "vigil assess kali sweep ... --values-file scans/ids.txt --json -- <command with {}>",
            ),
            author_supplied_fields=(
                *KALI_AUDIT_FIELDS,
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
        *KALI_AUDIT_FIELDS,
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
    if verb == "job":
        # Only `job start` runs a tool, so the audit-flag set is that action's;
        # the other actions address a recorded job by id.
        return CommandContract(
            name="kali job",
            phase=_KALI_VERB_PHASES.get(verb, ()),
            summary="Run a long-lived tool inside the runtime container as an audited dtach job, and inspect or stop it.",
            schema_name="argparse + CommandRunRecordRequest backend model",
            preferred_invocations=invocation,
            author_supplied_fields=(),
            notes=KALI_JOB_NOTES + _KALI_VERB_NOTES.get(verb, ()),
            common_mistakes=_KALI_COMMON_MISTAKES,
            variants=(
                ContractVariant(
                    "start",
                    fields=tuple(
                        {
                            KALI_BLOCKING_TIMEOUT_FIELD: KALI_JOB_TIMEOUT_FIELD,
                            KALI_AGENT_ID_FIELD: KALI_JOB_AGENT_FIELD,
                        }.get(entry, entry)
                        for entry in KALI_AUDIT_FIELDS
                    )
                    + ("the command after `--`",),
                    examples=examples[:1],
                ),
                ContractVariant("status", fields=("<job-id>",), examples=examples[1:2]),
                ContractVariant("tail", fields=("<job-id> [--follow]",)),
                ContractVariant("stop", fields=("<job-id>, or --all to reap every in-flight job",)),
                ContractVariant("list", fields=("--status <status> / --parent-run-id <id>",)),
            ),
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
    examples = [example] if example else []
    provenance_schema = properties.get("provenance") if isinstance(properties, dict) else None
    if isinstance(provenance_schema, dict) and "waf" in (provenance_schema.get("properties") or {}):
        notes.append(
            "A WAF measurement closes the per-host `waf_tier` readiness objective for each host "
            "it names: set `provenance.waf` to {\"verdict\": \"detected\" | \"none_detected\", "
            "\"hosts\": [<host>, ...]} with `provenance.command_run_id` naming the run that "
            "measured them (wafw00f or an equivalent probe). The run must have completed "
            "successfully and record each named host as its target: its target_host (a "
            "list-mode run records the hosts its list file holds), or, with no target_host, "
            "a target URL or host its wafw00f argv names; the command text is never read "
            "for a host. Record a measured negative as `none_detected`, and name a WAF in "
            "`component` only when the run saw one. A row that says 'no WAF' only in its "
            "text closes nothing; the backend refuses a measurement whose run is not in this "
            "engagement, did not succeed, or did not target a named host, and names the host. "
            "A row is keyed on component+version, so recording the same component once per "
            "measured host merges into one row: the reply says it deduplicated into id=N and "
            "which hosts it added, re-measured, or kept, and every earlier host keeps its own "
            "run in `provenance.waf_measurements` (a host measured again keeps only its newest run)."
        )
        examples.append({
            "component": "WAF: none detected",
            "source_name": "recon-specialist",
            "confidence": "high",
            "evidence_ref": "scans/wafw00f_results.csv",
            "provenance": {
                "command_run_id": 77920,
                "waf": {"verdict": "none_detected", "hosts": ["api.example.com", "www.example.com"]},
            },
        })
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
        examples=tuple(examples),
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

# Agent lifecycle sub-verbs that have their own contract entry. Prompts direct an
# author to read `vigil assess contract <verb>` before hand-authoring a payload, and the
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
            "vigil assess agent start --role <role> --task \"...\" --dispatch-mode <mode> --skills <skills> (--rate-budget <authored> | --no-target-traffic) [--prompt-context-json <context.json>] [--packet-file <assignment.md>] [--standing-brief-file <brief.md>]",
            "vigil assess agent start --role exploit-developer --assessment-mode code|web --task \"...\" --dispatch-mode deep-manual --skills <skills> (--rate-budget <authored> | --no-target-traffic) (--assessment-mode is required for exploit-developer and source-analyzer)",
            "vigil assess agent bind-client-handle <agent-id> --client <client> --session-namespace <scope> --handle <session-id>",
            "vigil assess agent handoff --agent-id <agent-id> --from-json <handoff.json>",
            "vigil assess agent close <agent-id>",
            "vigil assess agent done <agent-id> --status failed",
            "vigil assess agent reconcile-stale --dry-run",
            "vigil assess agent list [--filter-role <role>] [--status <status>]",
            "vigil assess agent render-handoff <agent-id>",
            "vigil assess agent continue <prior-agent-id> --task \"...\" [--assessment-mode code|web]",
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
            "mid-flight message does not depend on a mapping you keep by hand. `agent handoff` "
            "writes a repeatable checkpoint, `agent close` consumes a ready/blocked handoff "
            "into closure and records its decision, while `agent done --status ...` is an "
            "explicit raw lifecycle write for recovery. "
            "`agent render-handoff` assembles the blob the next dispatch prompt pastes verbatim.",
            "`agent start` defaults a missing --dispatch-mode from the role (warn, not block) and accepts a newly-coined mode (advisory warn). "
            "--skills is optional: set it when the applicable skill is already known, otherwise the specialist selects one from the surface and names it in its handoff. The advisory overlap scan is default-on across in-progress and completed rows; it streams paged history, ranks the five displayed rows by relevance/findings produced with deterministic tie-breaks, and prints the total count. Use --allow-duplicate only when the overlap is intentional.",
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
        author_supplied_fields=(),
        # `reclassify` and `link-surface` have contracts of their own
        # (`_work_buffer_verb_contract`), which resolve before these.
        variants=(
            ContractVariant("stats", fields=("--by status|source|cluster|host|reason|classifier_version / --status <status>",)),
            ContractVariant("peek", fields=("<type> [limit]",)),
            ContractVariant("fetch", fields=("<type> <limit> <agent-name>",)),
            ContractVariant("fetch-by-priority", fields=("<limit> <agent-name|auto>",)),
            ContractVariant("fetch-by-unit", fields=("--unit-id / --path / --class / --limit / --agent",)),
            ContractVariant("done", fields=("<id1,id2,...>",)),
            ContractVariant("defer-cluster", fields=("<cluster_key> --reason <text> [--reason-tag <tag>] [--dry-run]",)),
            ContractVariant("defer-items", fields=("<id...> --reason <text> [--dry-run]",)),
            ContractVariant("set-rationale", fields=("<id...> --rationale <text>",)),
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
            "reclassify re-applies gf-style priority/cluster classification (default: unscored rows only); --retype/--retype-all re-derive `type` from stored fields. link-surface links backend surfaces to the request variants behind selected work_items. See `vigil assess contract work-buffer reclassify` / `contract work-buffer link-surface`.",
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
            summary="Re-apply gf-style priority/cluster classification to the work buffer.",
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
            summary="Link backend surfaces to the request variants behind selected work_items.",
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
                ("--max-lines", "40 (context excerpt; 0 returns the complete recorded handoff)"),
                ("--include-evidence", "off (one short evidence excerpt per finding when set)"),
                ("--engagement-dir", "explicit flag, then engagement CWD, then launcher session"),
                ("scope", "handoff payload's summary / coverage_gaps / next_steps / "
                          "runtime_issues / working_artifacts / open_questions / "
                          "recommended_next_agent / extras"),
                ("credentials", "every engagement credential row, for every role: one line "
                                "with the row count and ids (no material)"),
            ),
            notes=(
                "Exits 2 when no handoff exists for the agent-id (404 on dispatch-handoffs/{agent_id}) — the dispatch never wrote one, or the id is mistyped. Specialists are expected to write a handoff before exiting.",
                "A 404 on a finding slug renders inline as 'slug missing (deleted or never recorded)' (distinct from 'fetch error: <reason>') instead of failing the whole render — the operator may have killed the finding between dispatch and handoff.",
                "The dispatch row is fetched best-effort; when missing, the renderer falls back to the handoff row's metadata.",
                "Cross-reference: agent/operator-core.md 'Cross-Dispatch Continuity'.",
            ),
            common_mistakes=(
                (
                    "transcript excerpts in dispatch prompt",
                    "paste render-handoff output instead of copy-pasting from the prior agent's transcript",
                ),
                (
                    "treating a capped excerpt as the entire specialist result",
                    "use --max-lines 0 to inspect complete next steps, uncertainty, and observations; select only relevant context for a new dispatch",
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
            summary="Capture a fresh replacement assignment with one effective identity, current task, preserved authority boundaries, and immutable predecessor pointers.",
            schema_name="reads prior dispatch + prompt packet; writes one linked DispatchCreate row",
            preferred_invocations=(
                "vigil assess agent continue <prior-agent-id> --task \"Finish the unresolved authorization pass\"",
                "vigil assess agent continue <prior-agent-id> --task \"Finish the live proof\" --assessment-mode web",
            ),
            author_supplied_fields=(
                "<prior-agent-id>",
                "--task",
                "--agent-id (optional replacement identity)",
                "--assessment-mode code|web (mixed roles only, when the prior dispatch recorded none)",
            ),
            notes=(
                "The predecessor stays immutable history. Continue refuses a fresh in-progress predecessor so it cannot silently duplicate a live specialist; use agent start --allow-duplicate for intentional parallel work.",
                "The replacement inherits the prior assessment_mode. An exploit-developer or source-analyzer predecessor recorded before assessment_mode existed has none, so pass --assessment-mode code|web; a value contradicting a recorded mode is refused, because the saved packet was rendered for that mode.",
                "Every start captures its packet. Continuation retains known traffic, authorization, and source boundaries while rendering one replacement identity and current task. It links the immutable predecessor packet by digest and directs current-state reads through resume-brief/handoff pointers instead of appending historical prompt text. Missing boundaries or changed source require a freshly scoped dispatch. Proof owners use proof-work release/reclaim.",
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
                "[--assessment-mode code|web] "
                "(--rate-budget \"<authored>\" | --no-target-traffic)",
            ),
            author_supplied_fields=(
                "--role (specialist role shared by every worker)",
                "--task (shared objective; each row receives its own item range)",
                "--workers (maximum number of dispatch rows to record)",
                "--batch-size (contiguous items assigned to each worker)",
                "--items-file (non-empty line-delimited work list)",
                "--assessment-mode code|web (required for mixed-role workers)",
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
                "ADVISORY: when --workers plus the engagement's in-progress dispatches exceeds the client concurrency budget, stderr warns that the excess specialists queue in the native client rather than run in parallel; every row is still recorded. The budget defaults to 20 (Claude Code's concurrent-subagent limit) and is set with VIGIL_CLIENT_CONCURRENCY_BUDGET or `client.concurrency_budget` in the Vigil config (~/.config/vigil/config.json), the environment winning; a value that is not a positive integer is ignored with a warning.",
            ),
        )
    if verb in {"register", "start"}:
        return CommandContract(
            name="agent start",
            summary=(
                "Register a specialist dispatch in the backend audit ledger so the "
                "row carries role, task, optional application-unit attribution, "
                "requested model/reasoning, dispatch-mode, assessment-mode, and the skills "
                "the agent loaded."
            ),
            schema_name="backend DispatchCreate (POST /dispatches)",
            preferred_invocations=(
                "vigil assess agent start --agent-id <id> --role <role> "
                "--task \"...\" [--application-unit-id <id>] "
                "[--code-repo-id <repo-id>] "
                "--model <name> --reasoning <level> "
                "--dispatch-mode <mode> --skills \"<skill>[,<skill>...]\" "
                "[--assessment-mode code|web] "
                "(--rate-budget \"<authored>\" | --no-target-traffic) "
                "[--prompt-context-json <context.json>] [--packet-file <assignment.md>] [--standing-brief-file <brief.md>]",
                "vigil assess agent start --from-json <payload.json> ",
                "vigil assess agent start --from-json <payload.json> --dry-run ",
            ),
            author_supplied_fields=(
                "--agent-id (unique per dispatch)",
                "--role (specialist role; operator role is reserved for phase coordination)",
                "--dispatch-mode (hypothesis-driven|item-iterating|deep-manual|variant-rotation)",
                "--assessment-mode code|web (required for exploit-developer and source-analyzer; proof-work supplies its authoritative route)",
                "--skills (comma-separated; optional — omitting it WARNs, never blocks)",
                "--task (one-line objective)",
                "--standing-brief-file (optional engagement-contained shared briefing; or JSON prompt_context.standing_brief_file; the flag wins)",
                "--application-unit-id (optional concrete application-unit identity for depth attribution)",
                "--code-repo-id (code roles: selects the active analysis repository used to render Code Source Identity; required when several analysis repositories exist; reference repositories are navigation pointers)",
                "--finding-slugs (optional canonical related/input finding set; required for a receipt-bearing code-variant-hunter dispatch)",
                "exactly one traffic declaration: --rate-budget <authored text> or --no-target-traffic (JSON: top-level rate_budget string or no_target_traffic=true)",
                "--prompt-context-json (optional partial context; or JSON: prompt_context). The two are NOT mutually exclusive: supplying both SHALLOW-MERGES them, with the flag's keys winning key by key, under the same rule as every other CLI flag here. So shared wave boilerplate (target, prior_state, coverage, cleanup, oob) is authored once in --from-json and overridden per lane by --prompt-context-json; validation then runs on the merged object, so an unknown key from either side is still rejected by name. --packet-file captures an engagement-contained UTF-8 assignment supplement; canonical identity and authority cannot be overridden",
                "--dry-run to perform the same validation and rendering without persisting a dispatch row",
            ),
            helper_defaults=(
                ("status", "in-progress (set on insert)"),
                ("dispatched_at", "now() when omitted"),
                ("--allow-duplicate", "off — bounded ranked overlap history is checked by default"),
                ("packet capture", "always — atomic with dispatch registration; launch receipt follows immutable local materialization"),
            ),
            notes=(
                "This command only writes the backend dispatch row; it does not spawn or "
                "launch the specialist. After its launch_required=true receipt succeeds, launch the specialist in the active "
                "client using only launch_message, which points to the captured packet and SHA-256, then run "
                "`vigil assess agent bind-client-handle <agent-id> ...` so the row names the "
                "session you launched — the handle cannot be supplied here because it does not "
                "exist yet, and it is never a precondition for starting a dispatch. For code "
                "roles the helper validates one active indexed repository before recording and "
                "captures the backend-derived Code Source Identity block immediately after "
                "Runtime Identity.",
                "Every start captures a canonical packet before native launch. Success receipts identify its immutable local path, SHA-256, bytes, lines, short launch_message, and the `authorized_phase` the packet shipped — read that back before launching, because it is the authority grant the role gates enforce. --dry-run validates without capture or launch permission. Exact registration retries recover the same dispatch with launch_required=false; changed input under the same ID conflicts. Local materialization failures print no success receipt. The helper does not attest whether a native process started; inspect client bindings and execution before recovering an uncertain launch.",
                "`authorized_phase` is NOT ordinary optional context — it is the authority grant the code role gates enforce, so it is always established before the packet renders. An explicit value always wins, because a dispatch is routinely authorized for a phase other than the campaign's current one (a proof-route packet is, by contract); a code audit tag (`code-hunt`, `code-verify`, ...) is stored as the code track phase it tags (`hunt`, `verify-variant`, ...) and that is echoed on stderr; any other spelling outside the canonical roster earns an ADVISORY and is recorded as authored, never refused. When the key is omitted — or carries a placeholder like 'not supplied' — `agent start` resolves the engagement's own track phase from scope.json (through the same roster reader `transition-phase` uses), stamps it, and echoes on stderr which track it came from. When scope.json cannot answer unambiguously — a two-track engagement dispatching a role that belongs to neither, or a track sitting at unknown/repair-required/complete — the field carries the literal marker \"MISSING (malformed dispatch)\" and a WARN, and the code role gates stop that dispatch before it reads source. A phase is never guessed: supply it in --prompt-context-json.",
                "Traffic classification remains explicit. Optional context fields include authorized_phase, target, hunt_scope, mindset_lens, depth_expectation, oob, auth_context, credential_id, prior_state, coverage, cleanup, human_reach_decision, role_specific_additions. Unknown keys are rejected by name; the objective belongs in --task or --packet-file. Omitted fields remain unknown and grant no authority. Blue tenant refs are validated and injected before capture. --packet-file is bounded to 64KiB, UTF-8, regular, engagement-contained inputs. A rendered packet over 12,000 bytes draws a size advisory; it never blocks.",
                "prompt_context prior_state is losslessly contained data with a 16384-character safety limit; prefer compact working-state pointers. Optional queue_item_ids (1–20 current code queue IDs) are resolved against the selected analysis repository into a backend-derived file/status manifest before dispatch through exact selected-ID reads. Optional lane_file names a generated code queue-fetch JSON file or newline list of indexed paths; it is validated before the write and rendered as exact item/LOC totals with bounded file/directory previews; a queue-fetch preview names each leased item's scratch_dir and current backend family floor. Required families render as one common list plus each file's additions, whose union is the complete per-file floor; suggested families remain hints. Exact path selections read only the selected file facts; paths whose encoded selector exceeds the URL batch bound use the read-only code/files/lookup body endpoint. The ledger total uses a count-only projection. Optional prior_agent_id quotes a bounded `agent render-handoff` result inside the untrusted prior-state boundary. Missing/stale queue IDs, an invalid lane file, or a missing handoff fail before the dispatch row is written.",
                "--standing-brief-file captures an engagement-contained regular UTF-8 file, up to the same 64KiB input bound as --packet-file, once under tools/dispatch-briefs/<sha256>.md. The packet and launch receipt carry its path and SHA-256, not its body. The specialist reads the captured briefing before work; identity, scope, approval and proof authority retain precedence. Changing the authoring file creates a new capture for a new start; continuation retains and validates its predecessor's capture. A missing or changed captured brief refuses launch/continuation. Dry run validates and renders the reference without publishing its local capture. Captured metadata is helper-owned, not authorable prompt_context.standing_brief.",
                "`--prompt-context-json` and a `prompt_context` object inside `--from-json` are not mutually exclusive: supplying both SHALLOW-MERGES them key by key, with the flag winning each key it names and leaving the rest of the JSON object intact. Author the wave's shared boilerplate (target, prior_state, coverage, cleanup, oob) once in --from-json and override per lane with --prompt-context-json. Validation runs on the MERGED object, so an unknown key from either side is still rejected by name.",
                "`--vuln-classes` must name canonical vuln class tokens. A token the taxonomy does not know is refused before the dispatch row is written, and the refusal names the nearest canonical class for each bad token so a typo is recoverable at the keyboard — list them with `vigil assess list-skills --json` or read agent/references/runtime-guides/vuln-taxonomy.md. The value is the dispatch's own declaration and the depth ledger never reads it for coverage, but every class-keyed view does, so an unresolvable token is stored nowhere.",
                "`--role` is checked against the installed role roster (agent/agents/<role>.md) before the row is written: an unregistered role is REFUSED, with the nearest registered role and the full registered list, because the packet would send the specialist to a prompt that does not exist and it would run with no role prompt and none of its mandatory references. When the roster directory itself does not resolve — a deployment without the agent tree — nothing is provable, so that case WARNs and proceeds instead, the same way unresolvable instruction-identity files report rather than block.",
                "Runtime Identity always states `assigned_finding_slugs`: the --finding-slugs set as JSON, or `none`. Authored guidance (prompt_context.role_specific_additions or the --packet-file text) is the operator's and is never rewritten or scanned, so scope any per-finding obligation in it to that set. A proof-bearing variant dispatch (web verify `variant-rotation`, code `verify-variant`) without --finding-slugs is refused.",
                "`skills` on a specialist dispatch is a WARNING when missing, never a rejection. Explicitly supplied names must resolve to installed skill directories; unknown names are rejected by the CLI before dispatch creation. A specialist picks its skills from what it observes, so the honest list is often known only after the dispatch runs. Set it when the applicable skill is already clear; otherwise name it in the handoff.",
                "requested_model and requested_reasoning record the recipe YOU selected on the dispatch row; specialist packets carry actionable assignment context without model/reasoning placeholders or empty optional rows. An ordinary dispatch carries no launcher-effective or provider-observed model/reasoning — no trusted launcher integration attests them — so the row is an asserted recipe, never measured truth, and caller-supplied actual_/launcher_effective_ fields are dropped rather than stored. Leaving either unset is visible warning debt: the dispatch stays usable but is not replayable. Never invent a runtime model the client does not expose.",
                "Discover skill names with `vigil assess list-skills` — each value must match a directory under `agent/skills/<name>/`.",
                "On return, render the handoff and use `agent close` for ready/blocked handoffs; rows left `in-progress` past the dispatch's actual lifetime corrupt dedup checks. Use `agent done --status ...` for an explicit raw recovery write.",
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
                        "--application-unit-id 42 --model claude-opus-5 "
                        "--reasoning high --dispatch-mode item-iterating "
                        "--skills 'ssrf-testing,case-dispatching' "
                        "--rate-budget 'rate=4; concurrency=2' "
                        "--prompt-context-json dispatch-context.json"
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
                "client/namespace/handle adds no duplicate version that would bury the real "
                "corrections (see the note on the answered no-op below).",
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
                "Re-binding the identical client/namespace/handle is an answered no-op: HTTP 200 with the current binding, `superseded: null`, `already_bound: true`, and no new version. A new binding answers 201 with `already_bound: false`.",
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
                "--status (completed|failed|aborted|blocked)",
            ),
            helper_defaults=(
                ("--completed-at", "now() when --status is terminal and the flag is omitted"),
                # Rendered from contract_registry.DISPATCH_FINDING_SLUGS_WRITE so
                # the line states the raw route's write semantics as they are,
                # alongside the merge this verb performs client-side.
                ("--finding-slugs", dispatch_finding_slugs_help()),
            ),
            notes=(
                "Without --status, an id whose handoff is ready or blocked is closed the way `agent close` closes it (the dispatch_closed_from_handoff decision is recorded, --finding-slugs joins the recorded scope, and stderr names the routing); other ids get the raw write. Pass --status for a deliberate raw lifecycle write.",
                "For recovery, pair `--status completed --finding-slugs <slugs>` so the row names the slugs the specialist produced; `vigil assess agent render-handoff` reads from there. render-handoff renders the UNION of the dispatch row's slugs and the handoff's own, so a slug on either row still reaches the next dispatch.",
                "--status words fold case and separator (`Completed` -> `completed`); `agent close --status` and `agent list --status` fold the same way.",
            ),
            common_mistakes=(
                ("status=done", "--status is completed / failed / aborted / blocked — 'done' is rejected"),
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
            summary="Close a final handoff, or record failed-return recovery without losing checkpoint evidence.",
            schema_name="GET dispatch-handoffs/{agent_id} + PATCH dispatches/{agent_id} + decision-record",
            preferred_invocations=(
                "vigil assess agent close <agent-id>",
                "vigil assess agent close <agent-id> --reason \"ready handoff reviewed\"",
                "vigil assess agent close AG-1 AG-2 AG-3",
                "vigil assess agent close --all-ready --quiet",
                'vigil assess agent close <agent-id> --status failed --reason "<observed return and execution state>"',
                'vigil assess agent close <agent-id> --status blocked --reason "<durable work produced; scope left incomplete>"',
            ),
            author_supplied_fields=(
                "<agent-id> (one or more; batch closes each ready/blocked handoff) — omitted with --all-ready",
                "--reason",
                "--completed-at (ISO-8601 completion time stamped on each listed dispatch; default the close time; refused with --all-ready, whose ids come from backend state)",
                "--status (failed|blocked; only for an absent or checkpointed handoff, and only with --reason)",
                "--all-ready (close every in-progress dispatch whose handoff is ready or blocked; derives the ids from backend state)",
                "--quiet (drop the per-dispatch JSON; the stderr tally and the audit rows remain)",
            ),
            notes=(
                "Use only after observing the native worker return and checking owned execution ended. Run kali sweep-orphans, inspect command-run list and proof runs/jobs, and wait or stop active execution; proof-work reconcile reports durable proof blockers. Age or chat closure alone does not prove execution ended.",
                "Normal close consumes ready/blocked handoffs. For absent or checkpointed handoffs, --status requires a nonblank --reason of at most 8192 characters; it records an operator-authored blocked handoff, preserves checkpoint evidence, and closes an in-progress dispatch terminally. Ordinary work may then continue; proof work requires release and a fresh claim.",
                "--status failed means the lane returned NO usable output; --status blocked means it produced durable work (receipts, released leases, a checkpoint) but could not finish its scope. The operator_recovery stamp, the --reason requirement and the preserved checkpoint are identical for both — only the recorded terminal status differs, so a lane that did work is not filed as if it had done none.",
                "Batch: list several agent-ids to close each in a resilient loop; a non-closable/checkpointed dispatch is reported and skipped, not fatal. --all-ready runs the same loop over the ids it selects.",
                "--all-ready applies `reconcile-stale`'s closable predicate with NO age threshold — every in-progress dispatch whose handoff reads ready or blocked, so a wave that just returned is closable immediately. It cannot be combined with explicit agent ids (the ids come from backend state), with --status (that records a return which has no final handoff; close those by id), or with --completed-at (one time cannot be each selected dispatch's observed completion; list the ids instead). The selected ids print to stderr before the loop.",
                "Close PATCHes the stable UNION of the dispatch row's slug list (the input/related scope `agent start --finding-slugs` recorded) and the handoff's own (what the specialist produced), because the raw route replaces the column — sending the handoff's list alone would drop an input slug its author did not repeat. A code-variant-hunter dispatch is exempt — its scope is the immutable parent-finding set the backend 409s any change to, so its produced slugs stay on the handoff.",
                "Records a dispatch_closed_from_handoff decision row so automated/stale closure stays auditable. Failed-return checkpoint updates compare the observed handoff version and refuse a concurrent newer return. Retrying the same failed recovery can complete a missing audit write without changing its completion timestamp.",
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
                "vigil assess agent handoff --agent-id <agent-id> --from-json <handoff.json>",
            ),
            author_supplied_fields=(
                "--agent-id <your dispatch agent_id>; the payload's agent_id must match it, so a re-sent handoff file written by another dispatch is refused",
                "--from-json <path|-> containing the complete structured handoff",
                "agent_id and summary (target about 2000 characters, hard maximum 16384; required when creating a handoff); agent_role is optional and, when sent, must be the dispatch's registered role",
                "structured arrays: next_steps / coverage_gaps / runtime_issues / working_artifacts / open_questions — see the field list and the example payload below for each entry's keys",
            ),
            # Shape source: `HandoffCreate` in
            # orchestrator/backend/app/api/assessment_operator.py. The model sets
            # extra="forbid", so a name missing here is a name no specialist can
            # discover and a name invented here is a 422. The nested per-entry keys
            # are the ones agent/references/runtime-guides/handoff-schema.md fixes;
            # the backend stores each entry opaquely, so they are the convention the
            # renderer and the next dispatch read, not a validated sub-schema.
            # test_cli_canonical_shapes pins the roster and the example against the
            # live model.
            top_level_fields=(
                ("agent_id", "string, required", "Your dispatch agent_id from the Runtime Identity block. Must equal --agent-id, so a handoff file written by another dispatch is refused rather than overwriting that dispatch's row."),
                ("agent_role", "string", "The role file the dispatch ran under (`recon-specialist`, `vulnerability-analyst`, `code-vuln-hunter`, ...). Optional: when absent the backend stores the dispatch's registered role and names it on the response's `derived` list; a different role contradicts the dispatch `agent_id` names and is refused (409)."),
                ("summary", "string, required", "Plain prose: what was done and the headline outcome, so the operator can choose the next dispatch. Target about 2000 characters; 16384 is the hard limit, measured locally before the request."),
                ("phase", "string", "The phase tag the dispatch was authorized for, from the canonical phase vocabulary (`vigil assess list-commands --phase`). Optional at the backend boundary; a final handoff should carry it."),
                ("confidence", "string; one of: low, medium, high", "How much of the summary was PROVEN versus inferred. Optional at the backend boundary; a final handoff should carry it."),
                ("finding_slugs", "array of string", "Slug strings only. The rich data stays on the findings; `render-handoff` fetches title and severity per slug."),
                ("coverage_gaps", "array of object", "What this dispatch did NOT cover. Each entry: {area, reason, recommended_followup}."),
                ("next_steps", "array of object", "What the next dispatch should do. Each entry: {action, target, recommended_agent, rationale}."),
                ("runtime_issues", "array of object", "Tool/runtime problems that shaped the result. Each entry: {kind, tool_or_target, detail, severity}."),
                ("working_artifacts", "array of object", "Files this dispatch produced. Each entry: {path, description, kind}, where `path` should be ENGAGEMENT-RELATIVE (`scans/acme_billing.txt`). Every path is stat'd against the engagement root: one that resolves INSIDE it reads `present` when the file exists (an absolute path inside the engagement is accepted) and `missing` when it does not; a path resolving outside the root, or a non-file URL, reads `out-of-engagement` because no artifact row can exist for it."),
                ("open_questions", "array of string", "Free-text questions only the operator or human can answer (vendor-SaaS in/out, scope ambiguity, a missing credential)."),
                ("recommended_next_agent", "string", "The role you would hand off to, from this dispatch's own perspective."),
                ("handoff_status", "string; one of: checkpointed, ready, blocked, superseded", "`checkpointed` (the helper default) is a mid-flight checkpoint. Set `ready` or `blocked` on the FINAL handoff so `agent close` can consume it; a ready/blocked handoff whose dispatch stays in-progress becomes a stale_dispatch_ready_handoff readiness blocker."),
                ("closed_dispatch_status", "string; one of: completed, failed, aborted, blocked", "The dispatch status `agent close` should apply when it consumes this handoff."),
                ("extras", "object", "Opaque role-extras object: role-specific counters and context with no fixed shape (osint CVE-match counts, fuzzer hit/miss ratio, recon live_host_count). Nothing validates its keys, and nothing else accepts an unknown name — the whole payload sets extra=forbid, so role-specific values belong HERE, not at the top level. ONE key is reserved by a reader: `extras.skills_loaded` is where `render-handoff` looks for the skills the lane actually loaded, as a comma-separated string or a list of names (de-duplicated, order kept). It renders that as reported loaded skills, separately from the operator's requested `skills`, so a self-selecting dispatch — the normal case, since `--skills` is optional — only reports its loadout to the next dispatch if it records it under that exact spelling."),
                ("expected_handoff_version", "integer >= 1; UPDATE-only", "The `handoff_version` you read, as a read-version guard on an existing row: the backend compares it and returns 409 if the row moved under you, so a lifecycle promotion cannot overwrite a concurrent return. Forbidden when CREATING a handoff (it guards a row that does not exist yet), and never a string."),
            ),
            helper_defaults=(
                ("upsert", "POST then PATCH on 409 — the operation is idempotent so checkpointing is safe"),
                ("handoff_status", "checkpointed unless --handoff-status is supplied"),
                ("confidence", "omitted when not specified"),
                ("summary length", "measured before the request: an over-long summary is refused locally with its character count, never truncated or split, and includes the saved version/timestamp on success"),
            ),
            notes=(
                "Specialists call this from their closing sequence before exiting; the row is then the canonical 'what was done, what's missing, what's next' record for the dispatch.",
                "For an existing handoff, a partial JSON object performs a PATCH and preserves omitted summary and structured arrays.",
                "An unknown key is rejected BY NAME before the request, on the create and the update path alike, so a misspelling fails loudly instead of being dropped behind a success receipt. The keys most often copied back out of a prior row are backend-managed and belong to nobody else: `handoff_version` (pass expected_handoff_version to guard instead), `last_checkpoint_at`, `created_at`, `id` (--agent-id addresses the row) and `engagement_id` (resolved from the engagement, never sent).",
                "A payload carrying `expected_handoff_version` always takes the UPDATE route, even when it also carries a summary — the guard is a statement about an existing row, so it is refused when the agent_id has no handoff yet. Without the guard, a payload with a summary is an idempotent upsert (POST, then PATCH on a duplicate agent_id). Anything less is a partial update.",
                "The receipt lists every `working_artifacts` path with its state (`present` / `missing` / `out-of-engagement`) and warns per unverifiable path. `checkpointed` and `blocked` keep that a warning — an aborted write legitimately names a file it never finished. A `ready` write that claims an absent path exits NON-ZERO, and the row is stored first: the exit reports an unsubstantiated artifact claim, not a failed write, so re-run the same command once the files exist rather than re-authoring the handoff.",
                "`render-handoff <agent-id>` reads this row, fetches each named finding, and emits the bounded markdown blob the next dispatch pastes.",
                "JSON payload schema: agent/references/runtime-guides/handoff-schema.md.",
                "agent_role is optional; the handoff records the dispatch's registered role. An absent one is filled from the dispatch and named on the response's `derived` list; one that differs is refused (409) rather than replaced, so omit it or send the registered role.",
                "`handoff_status` and `closed_dispatch_status` words fold case and separator (`Ready` -> `ready`).",
            ),
            common_mistakes=(
                ("transcript paste in summary", "summary aims for about 2000 characters with a 16384-character safety limit; use coverage_gaps / next_steps / runtime_issues when their meaning fits, never to arbitrarily split prose"),
                ("missing recommended_next_agent", "without it, the operator has to re-derive who picks up; set it from the specialist's perspective"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent handoff --agent-id <agent-id> --from-json handoff.json"
                    ),
                },
                # One complete payload, one entry per array. Everything a
                # specialist had to reverse-engineer from a previous
                # engagement's handoff.json is here: the nested per-entry keys,
                # the engagement-relative artifact path, and the ready/closed
                # pair that lets `agent close` consume this row.
                {
                    "agent_id": "va-7f3",
                    "agent_role": "vulnerability-analyst",
                    "phase": "consume-test",
                    "summary": (
                        "Exercised the authenticated billing surface on app.acme.example: "
                        "14 endpoints tested, one IDOR confirmed on "
                        "GET /api/v1/invoices/{id} (VA-001, sequential object ids, "
                        "cross-tenant read). The refund webhook rejects unsigned "
                        "callbacks, so the replay hypothesis is disproved. The admin "
                        "export route was never reached — it needs a tenant-admin "
                        "credential the engagement does not hold."
                    ),
                    "confidence": "high",
                    "finding_slugs": ["VA-001"],
                    "coverage_gaps": [
                        {
                            "area": "admin export route on app.acme.example",
                            "reason": "no tenant-admin credential in the engagement credential set",
                            "recommended_followup": "obtain a tenant-admin test account, then re-dispatch this surface",
                        }
                    ],
                    "next_steps": [
                        {
                            "action": "measure how far the confirmed IDOR enumerates across tenants",
                            "target": "https://app.acme.example/api/v1/invoices/",
                            "recommended_agent": "exploit-developer",
                            "rationale": "object ids are sequential, so the impact band depends on the reachable range",
                        }
                    ],
                    "runtime_issues": [
                        {
                            "kind": "tool-degraded",
                            "tool_or_target": "app.acme.example",
                            "detail": "edge returned 429 above ~4 rps, so enumeration depth was capped",
                            "severity": "medium",
                        }
                    ],
                    "working_artifacts": [
                        {
                            "path": "scans/acme-billing-idor.txt",
                            "description": "request/response pairs for the confirmed cross-tenant read",
                            "kind": "evidence",
                        }
                    ],
                    "open_questions": [
                        "Is billing-vendor.example in scope? It serves the invoice PDF and scope.json does not name it.",
                    ],
                    "recommended_next_agent": "exploit-developer",
                    "handoff_status": "ready",
                    "closed_dispatch_status": "completed",
                    "extras": {"endpoints_tested": 14, "identity_used": "acme-tenant-a"},
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
                "vigil assess agent decision --kind claim_equivalence --payload-json '{\"finding_slug\":\"<slug>\",\"verdict\":\"equivalent\",\"claim_transition_id\":<id>,\"new_claim_sha256\":\"<digest>\",\"verifier_dispatch_agent_id\":\"<agent-id>\",\"reason\":\"<why the verified claim is unchanged>\"}'",
                "vigil assess agent decision --kind submission_qc_verdict --payload-json '{\"finding_slug\":\"<slug>\",\"packet_id\":\"<triage-packet-id>\",\"reviewer_dispatch_agent_id\":\"<qc-report-writer-id>\",\"writer_dispatch_agent_id\":\"<writer-id>\",\"verdict\":\"blocked\",\"failed_rows\":[{\"row\":\"<checklist row>\",\"quote\":\"<exact failing text>\"}]}'",
                "vigil assess agent decision --kind report_qc_verdict --payload-json '{\"artifact_id\":<report.md artifact id>,\"sha256\":\"<registered report.md sha256>\",\"reviewer_dispatch_agent_id\":\"<qc-report-writer-id>\",\"writer_dispatch_agent_id\":\"<writer-id>\",\"verdict\":\"pass\",\"failed_rows\":[]}'",
                "vigil assess agent decision --kind severity_variance --payload-json '{\"finding_slug\":\"<slug>\",\"reason\":\"<why the severity departs from its CVSS band>\"}'",
                "vigil assess agent decision --kind repro_rehearsal --payload-json '{\"finding_slug\":\"<slug>\",\"verdict\":\"followed\",\"proof_mode\":\"live\",\"verifier_dispatch_agent_id\":\"<agent-id>\",\"observed_outcome\":\"<actual result>\",\"runs_checked\":[<authored-run-id>,<reviewer-run-id>]}'",
                "vigil assess agent decision --kind coverage_deferral --supersedes <decision-id> --surfaced-to-user --payload-json '{\"hosts\": [\"<host>\"], \"deferred_objectives\": [\"directory_fuzz\"], \"reason\": \"<corrected reason>\"}'",
            ),
            author_supplied_fields=(
                "--kind (scope_decision|egress_decision|dispatch_blocked|human_reach_decision|depth_deferral|... — kinds are open text, except the gated kinds ("
                + ", ".join(GATED_DECISION_KINDS)
                + "): another case or separator spelling of one is stored under it and named on the response's `derived`, and a misspelling is refused with a did-you-mean; report-writer only renders known kinds)",
                "--payload-json OR shorthand flags (--host / --vendor / --choice / --note / --reason / --phase) that build the payload dict",
                "--surfaced-to-user (set when the operator presented the decision to the human; controls whether it appears in user-visible logs)",
                "--supersedes <decision-id> (optional): the earlier row of the same --kind this row replaces",
                "--agent-id <your dispatch agent_id> (a specialist recording the decision; from your packet's Runtime Identity): the row's `recorded_by` names that dispatch and its recorded role; an id no dispatch of this engagement holds is refused. Omitted, `recorded_by` is the operator",
            ),
            helper_defaults=(
                ("payload", "constructed from --host/--vendor/--choice/--note/--reason/--phase when --payload-json is omitted"),
                ("surfaced_to_user", "false unless --surfaced-to-user is set"),
                ("recorded_by", "the operator unless --agent-id names your dispatch; $AGENT_NAME / $VIGIL_AGENT_NAME are never read for it"),
            ),
            notes=(
                "Vendor-SaaS scope warnings, egress-block decisions, and dispatch-blocked rows all share this table — keep the --kind taxonomy disciplined so report-writer can summarize by kind.",
                "Set --surfaced-to-user for operator-facing decisions (vendor-SaaS, egress reputation, blocked dispatch) so the human-visible audit log matches what the operator was shown.",
                "A vuln_family_exclusion records a program or user ruling the operator surfaces to the user, so the operator records it: one recorded with --agent-id naming a dispatch is refused. A specialist that finds such a ruling reports it in its handoff for the operator.",
                "--supersedes <decision-id> CORRECTS A ROW INSTEAD OF STACKING ONE: the new row records `supersedes_id`, the named row is stamped `superseded_by_id` in the same write, and every gate, readiness reader and approval flow reads only current rows. The superseded row stays readable (`vigil assess fetch dispatch-decisions/<id>`, or `dispatch-decisions?include_superseded=true` for the history) and can no longer be resolved. Refused: a row of another kind (record the correction under that kind), a row this engagement does not hold, a row already superseded (supersede its replacement), and severity_variance (it attaches to the current verification; correct it on a fresh `finding verify --severity-variance-file`).",
                "For coverage_deferral, deferred_objectives accepts exactly the per-host objectives `check-phase-readiness --by-host` evaluates (its `objectives:` line; a refusal names them). A deferred step that is none of them (authenticated recon, a skipped scan) is not a coverage_deferral; record it as an ungated kind such as `phase_step_deferral` with the hosts, step and reason, which no gate reads.",
                "--payload-json COMPOSES, THEN THE FLAGS WIN: the JSON object is loaded into the payload first and each supplied shorthand flag (--host / --vendor / --choice / --note / --reason / --phase) then overrides its own key, exactly as `agent start --from-json` and `host-exec --from-json` behave. Supply a value once: a flag repeating a JSON key wins, a flag naming a key the JSON omits adds it, and a flag you leave off changes nothing. The gate reads `payload.choice`, so `choice` must come from one of the two — inside the JSON object or as --choice — and must not be spelled differently in each.",
                "For claim_equivalence, read finding GET's verification_audit.claim_transition_id and current_claim_sha256. A recorded vulnerability-analyst, code-vuln-verifier, incident-verifier, or exploit-developer dispatch, distinct from the original finding author and from any dispatch that edited the claim (the dispatch_agent_id a `finding update --agent-id` records on the edit), compares the changed finding with the verified claim and records verdict=equivalent or changed with those exact values. Equivalent clears claim_review_pending; changed requires a new canonical edit and terminal verification. Report readiness and final export block while review is pending.",
                "SUBMISSION FLOW (per finding, every severity): the writer authors, renders --draft, runs the checklist without recording a verdict, builds `export triage-packet` with the exact outgoing attachments, and hands back. A separate report-writer dispatch reviews that packet (review only; fixes go back to the writer) and records submission_qc_verdict. A verifier then records repro_rehearsal from a cold start, then claim_equivalence when a claim review is pending. Medium-or-above findings then get blind_triage_verdict on the same packet. Final export runs next, and `finding update --status reported` follows only an exit-0 final export.",
                "For submission_qc_verdict, include finding_slug, packet_id (a triage packet of that finding), reviewer_dispatch_agent_id, writer_dispatch_agent_id, verdict (pass|blocked) and failed_rows. Each failed_rows entry is {row, quote}: the checklist row and the exact text that fails it; blocked needs at least one, pass has none. Reviewer and writer are distinct recorded report-writer dispatches; the reviewer also differs from the finding provenance author, from every dispatch that edited the finding, and from every dispatch that registered a version of its submission workspace, so writers pass --agent-id on `finding update`, and `export submission` records the rendering writer (resolved from the in-progress report-writer dispatch when --agent-id is omitted). Final export of an offensive engagement requires the latest verdict to pass on a packet matching the exported body, platform, platform fields, recipient guidance, attachments and program brief; a content change needs a new packet and review. Web and code `transition-phase complete` also block (missing_submission_qc) on any submittable verified finding with a registered submission whose latest verdict does not pass.",
                "For report_qc_verdict, include artifact_id and sha256 of the registered report.md, reviewer_dispatch_agent_id, writer_dispatch_agent_id, verdict (pass|blocked) and failed_rows (same shape and rules as submission_qc_verdict). The reviewer is a report-writer dispatch distinct from the writer and from every agent that has registered report.md; the reviewed bytes must carry a producer attribution, so register them as the writer (`artifact register report.md --agent-id <writer>`; every --agent-id must name a recorded dispatch), and must still match on disk. The backend refuses bytes with no producer and a reviewer who is one of report.md's producers; it does not compare the producer with writer_dispatch_agent_id. When report.md is registered, web and code `transition-phase complete` block (missing_report_qc) unless the file is present and the latest verdict passes for that artifact id and its current sha256.",
                "For severity_variance, include finding_slug and reason: why the severity departs from the band its cvss_score implies. It attaches to the finding's current receipt-backed confirmed or downgraded verification without fresh proof, because the verdict does not change; normal_band, chosen_severity, actor (the verifier whose receipts decide that verification) and proof_receipt_id are derived, and an authored value that disagrees is refused. A finding with no band departure, no such verification, or a variance already on its current verification is refused; report readiness then lists the departure as severity_cvss_band_divergence with the reason.",
                "For blind_triage_verdict, include finding_slug, packet_id, verdict, reviewer_dispatch_agent_id and writer_dispatch_agent_id. Both identities must be recorded dispatches in the engagement; the writer has report-writer role. The reviewer differs from the writer and finding provenance author. This enforces attribution, not native context independence. New or changed external content requires a new attributed packet review.",
                "For repro_rehearsal, verdict is followed, failed, or equivalent; proof_mode is live, source, or fuzz; source requires a finding whose reproduction_basis is source; unknown means no current verification receipts and grants no source exemption. Fuzz requires a file finding. The verifier_dispatch_agent_id must name an independent dispatch with the matching role: vulnerability-analyst, code-vuln-verifier, or code-fuzz-engineer. A followed live/fuzz check needs observed_outcome, all authored repro_runs IDs in runs_checked, and a completed reviewer command run. A followed source check names the independently observed outcome. A failed check needs failed_step. An equivalent step edit needs prior_decision_id of a followed check, a fresh verifier dispatch, and reason. The backend stamps a digest of current steps and ordered run IDs; final publication requires the latest successful digest to match.",
                # --- human_reach_decision: the side-effect preflight -------------
                "`--kind human_reach_decision` IS THE SIDE-EFFECT PREFLIGHT GATE. Run the preflight before sending any request that could create persistent state or reach a human — signup, request-access, support/report/ticket, password-reset, contact-form, or any endpoint whose name or path suggests a write that notifies someone. The posture is CAPPED LIVE-FIRE, not zero-fire: static characterization is unlimited, and genuine ambiguity earns a small, hard, audited budget gated by this recorded decision.",
                "Preflight step 1 — UNLIMITED static characterization, mandatory first. No request budget at all: run as many read-only, non-triggering probes as it takes to learn the methods and parameters the endpoint accepts, the response shape on a non-triggering GET/HEAD/OPTIONS (status, headers, body fields — never the write verb itself), and what the source, API spec, or documentation say it does. Cross-reference ENGAGEMENT.md §4 (No-Fire Endpoints) and §5 (Irreversible and Notifying Flows), including its Known-Safe Test Destinations table, for a pre-declared answer.",
                "Preflight step 2 — the REACHES-A-REAL-THIRD-PARTY test. Ask whether success OR failure lands in a real inbox, queue, or audit trail, or notifies a real person who is not the researcher. POSITIVE (examples, not exhaustive): a live support/ticket queue a real agent reads and actions; an email, SMS, or push delivered to a non-researcher-owned address; a role/access request routed to a real approver; a pager/on-call alert; a post to a customer-visible channel (public comment, shared workspace, forum). NEGATIVE (examples, not exhaustive): a researcher-owned test identity — account, mailbox, or phone number the researcher provisioned and controls; a documented sandbox/staging environment with no live inbox behind it; a mock/stub queue that accepts the request but has no delivery path; a self-directed notification to the researcher's own test account. A proven-NEGATIVE endpoint is ORDINARY SURFACE — hunt it fully, it carries no side-effect risk. Step 1 should aim to reach one of these two answers; only genuine ambiguity after a thorough static pass proceeds.",
                "Preflight step 3 — a HARD 1-3 LIVE-FIRE BUDGET, per endpoint/action, for the WHOLE ENGAGEMENT. If step 2 resolves POSITIVE, or static characterization leaves it genuinely unknown, you may spend 1-3 live requests to resolve the ambiguity, and you stop the instant either condition is met: the probe CONFIRMS the endpoint reaches a real third party, or the budget is exhausted. This is a prompt-enforced discipline and a WARN backstop — nothing in the CLI counts or blocks it — so hold yourself to it with the discipline of a hard cap anyway: it exists to bound the harm of a wrong 'unknown' call, not to license routine live-fire against notify-shaped endpoints. 1-3 is the GLOBAL CEILING; ENGAGEMENT.md may only TIGHTEN it for a program (cap at 1, or reinstate zero-fire for a named endpoint), never loosen it.",
                "CROSS-DISPATCH RULE — check before every fire, and never re-spend. The budget is per endpoint/action for the whole engagement, NOT per dispatch and NOT per specialist: a fresh dispatch does not get a fresh budget, and two specialists must not each independently spend 3 against the same target. Before ANY live human-reach fire, query the authoritative kind-filtered log — `vigil assess fetch \"dispatch-decisions?kind=human_reach_decision\"` (it pages at 100 rows by default; grep the returned JSON for the target host/endpoint) — and if a row on that exact endpoint/action already carries a `payload.choice` of `pending` or `denied`, treat it as BLOCKED and do not fire, regardless of what your own dispatch has spent. The operator is expected to inject any open gate into the dispatch context before sending a specialist at the surface, so the state is inherited rather than rediscovered; check directly anyway.",
                "RECORDING AND CONTINUATION GATE. Any specialist records the decision itself (same pattern as scope_decision) — see the human_reach_decision invocation above for the payload shape — and then does NOT continue live-firing that endpoint/action until the operator resolves it. Four resolution values, recorded on the decision row: `approved_continue` (proceed with further live-fire; rare — the operator has independent grounds the destination is safe), `approved_limited` (proceed under a named, narrower constraint), `denied` (do not fire again; permanently blocked for this endpoint/action), and `not_real_recipient` (the destination was confirmed NOT a real third party — this RETROACTIVELY LIFTS the cap for that endpoint and its siblings, reverting it to ordinary surface per the step-2 negative list). Irreversible and notifying side-effects are not proved by triggering them past this bounded, gated budget; firing past the budget, or past an open pending/denied gate, is the exact harm the preflight exists to prevent. This gate survives every exploit_policy value, `full_send` included, and applies per-action.",
                "A malformed repro_rehearsal or blind_triage_verdict payload is refused naming each `payload.<field>` and what it accepts; an unknown QC-verdict field is named with a did-you-mean. `verdict` (both kinds) and `proof_mode` fold case (`accept@p2` -> `Accept@P2`, `Followed` -> `followed`).",
            ),
            common_mistakes=(
                ("freeform reason in --kind", "kinds are vocabulary; put the prose in --note or --reason"),
                ("missing --surfaced-to-user", "user-facing decisions invisible to audit defeats the purpose; set the flag whenever the operator showed the gate to the human"),
                ("--payload-json '{\"choice\": \"approved_continue\"}' --choice pending", "the flag overrides the JSON key, so the row records choice=pending — the opposite of the JSON you authored. Set each payload key in one place only"),
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
