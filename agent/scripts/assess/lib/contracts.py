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

from .config import ENGAGEMENT_BINDING_CONTRACT
from .intel_types import INTEL_TYPES
from .kali_audit import ALLOWED_PHASES, _enum_reject_message
from .schema_validation import load_schema


# Canonical engagement-phase vocabulary for the per-phase command catalog. This
# is the SAME enum the kali audit path validates `--phase` against — imported
# from kali_audit, not re-declared — so `vigil assess list-commands --phase <N>`
# and the audit gate can never drift to two divergent phase enums.
CATALOG_PHASES: tuple[str, ...] = ALLOWED_PHASES

# The readiness command (check_phase_readiness) labels the canonical persisted
# "consume-test" phase with the short form "consume" internally. Accept both
# spellings on a --phase filter so a caller who types either resolves to the
# canonical value; this is the one explicit alias bridging the short readiness
# labels to CATALOG_PHASES.
_PHASE_FILTER_ALIASES: dict[str, str] = {
    "consume": "consume-test",
    "consume_test": "consume-test",
}


def canonical_phase(phase: str) -> str:
    """Normalize a phase token to its CATALOG_PHASES spelling.

    Lower-cases and resolves the ``consume``→``consume-test`` short alias so a
    ``--phase`` filter written in either form matches the canonical tags.
    """
    key = (phase or "").strip().lower()
    return _PHASE_FILTER_ALIASES.get(key, key)


# Canonical cross-cutting "goal" vocabulary for `vigil assess list-commands
# --goal <goal>`. A goal is an intent-oriented lens ORTHOGONAL to `phase`: it
# groups commands by what a caller is trying to accomplish (submit a finding,
# reason about scope, probe HTTP, ...) rather than by when in the engagement
# they run. Only clearly-matching contracts are tagged; an untagged command
# simply never matches a `--goal` filter. Dynamically-built contracts (kali
# verbs, intel record <type>, agent <verb>) default to no goals.
COMMAND_GOALS: tuple[str, ...] = (
    "submission",
    "scope",
    "recon",
    "discovery",
    "dns",
    "http-probe",
    "artifact",
    "finding-lifecycle",
    "dispatch",
    "code-analysis",
    "oob",
)


SPECIALIST_DISPATCH_MODES: tuple[str, ...] = (
    "hypothesis-driven",
    "item-iterating",
    "deep-manual",
    "variant-rotation",
    "swarm",
)


# Canonical external-submission vocabulary for `finding update --submission-status`.
# MIRRORS the backend `SubmissionStatus` StrEnum / `SUBMISSION_STATUSES` set in
# orchestrator/backend/app/services/state_manager/_common.py. The CLI (agent/
# scripts) and backend (orchestrator) are separate packages and cannot import
# each other, so the set is duplicated here and pinned in sync by
# test_submission_status (the same convention as SPECIALIST_DISPATCH_MODES vs the
# backend _KNOWN_DISPATCH_MODES). submission_status is ORTHOGONAL to
# workflow_status — it never changes report-inclusion.
SUBMISSION_STATUSES: tuple[str, ...] = (
    "none",
    "submitted",
    "accepted",
    "needs_info",
    "rejected",
    "duplicate",
)


# Per-role default `--dispatch-mode` when the flag is omitted. MUST mirror the
# per-role "Default when omitted" in each role file + operator-core.md's
# "Iteration-mode (dispatch_mode) Declaration" list (single source of the docs).
_DISPATCH_MODE_BY_ROLE: dict[str, str] = {
    "vulnerability-analyst": "item-iterating",
    "recon-specialist": "hypothesis-driven",
    "surface-collector": "item-iterating",
    "source-analyzer": "item-iterating",
    "fuzzer": "variant-rotation",
    "exploit-developer": "deep-manual",
    "osint-analyst": "hypothesis-driven",
    "report-writer": "deep-manual",
    "code-architect": "hypothesis-driven",
    "code-vuln-hunter": "item-iterating",
    "code-variant-hunter": "hypothesis-driven",
    "code-vuln-verifier": "deep-manual",
    "code-fuzz-engineer": "deep-manual",
}

_DEFAULT_DISPATCH_MODE = "hypothesis-driven"


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


# Roles whose dispatches must target a host that is actually in scope. OSINT
# and recon are intentionally NOT here: OSINT is permissible against
# adjacent/related domains (cert chains, DNS history, GitHub mirrors), and
# recon-specialist fingerprinting fires before scope-host is even meaningful.
# Vulnerability-analyst and exploit-developer probe live targets, so their
# scope_host must be in `scope.json` hosts (with wildcard semantics applied).
_SCOPE_GATED_ROLES: frozenset[str] = frozenset({
    "vulnerability-analyst",
    "exploit-developer",
})


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

    The orchestrator expects ``requested_model`` / ``requested_reasoning`` (and optional
    ``actual_model`` / ``actual_reasoning``). Legacy aliases ``model`` / ``reasoning``
    remain valid on POST and populate the requested columns server-side.
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
    *,
    engagement_dir: str | None = None,
) -> tuple[list[str], list[str]]:
    """Validate a parsed specialist dispatch payload.

    When ``engagement_dir`` is provided, additionally check that ``scope_host``
    is in the engagement's ``scope.json`` ``hosts`` for scope-gated roles
    (``vulnerability-analyst``, ``exploit-developer``). This prevents the
    operator-side mistake of dispatching active probing against a related-but-
    out-of-scope domain that recon surfaced. OSINT and recon are NOT gated
    because they legitimately reach adjacent/related domains during discovery.
    The engagement-wide ``scope_enforcement: bypass`` disables this target
    allow/deny gate just as it does at execution and standalone ingest.

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

    # Scope-host gate for active-probing roles. Imported lazily so the
    # contracts module stays importable in test/CI contexts that do not have
    # an engagement directory layout. Missing scope.json silently skips the
    # gate — other paths surface that error; the validator should not
    # duplicate it. Malformed scope.json (exists but unparseable) warns.
    if engagement_dir and role_name and role_name.lower() in _SCOPE_GATED_ROLES:
        scope_host = payload.get("scope_host")
        if isinstance(scope_host, str) and scope_host.strip():
            scope_path = Path(engagement_dir) / "scope.json"
            if scope_path.is_file():
                try:
                    from .scope import (
                        host_admitted,
                        host_in_scope,
                        load_scope,
                        out_of_scope_entries,
                        scope_enforcement,
                        scope_entries,
                    )
                    scope = load_scope(engagement_dir)
                    entries = scope_entries(scope)
                    deny = out_of_scope_entries(scope)
                except (SystemExit, ValueError, OSError) as exc:
                    warnings.append(f"scope_host gate skipped: {exc}")
                else:
                    probed_host = scope_host.strip()
                    if (
                        scope_enforcement(scope) != "bypass"
                        and entries
                        and not host_admitted(probed_host, entries, deny)
                    ):
                        if host_in_scope(probed_host, entries):
                            # Host IS in the allowlist but is carved out by an
                            # out_of_scope denylist entry — distinct, sharper error.
                            errors.append(
                                f"scope_host '{scope_host}' matches an out_of_scope "
                                "carve-out in scope.json `out_of_scope` and must not "
                                "be probed."
                            )
                        else:
                            errors.append(
                                f"scope_host '{scope_host}' is not in scope.json `hosts` "
                                f"for role '{role_name}'. Active-probing dispatches "
                                "(vulnerability-analyst, exploit-developer) must target a "
                                "host that is explicitly in scope. If this is intentional "
                                "(e.g. cert-chain pivot), reframe as recon/osint, or add "
                                "the host to scope.json first."
                            )

    # C4a: WARN-only technique-cage lint over the free-text task. NEVER appended
    # to `errors` — a prescriptive task is a depth smell, not an invalid dispatch.
    warnings.extend(_detect_technique_cage(str(payload.get("task") or "")))

    return errors, warnings


# Verbs registered under `vigil assess kali ...`. Names are kept in sync with
# the modules under `agent/scripts/assess/commands/kali_*.py`.
#
# Two categories live here so the audit-flag invariants stay truthful:
# - KALI_TARGET_VERBS — target-facing probes that REQUIRE the standard
#   audit-flag set (`--technique`, `--intent`, `--probe-kind`, `--phase`,
#   `--timeout`). Common notes and common mistakes apply.
# - KALI_MAINT_VERBS — host-side maintenance commands. They do not touch the
#   target and do not take the audit-flag set. Common notes do NOT apply;
#   each gets a bespoke contract entry.
#
# `KALI_VERBS` is the union for command registration / discovery, but
# documentation and validation must use the right subset so prompts cannot
# tell the operator that `sweep-orphans` requires `--phase` (it does not).
KALI_TARGET_VERBS: tuple[str, ...] = (
    "nmap-scan",
    "nuclei",
    "httpx",
    "wafw00f",
    "ffuf",
    "sqlmap",
    "subfinder",
    "puredns",
    "dnsx",
    "nikto",
    "katana",
    "gau",
    "arjun",
    "whatweb",
    "cero",
    "alterx",
    "asnmap",
    "bbot",
    "browser",
    "tlsx",
    "dalfox",
    "robots",
    "exec",
    "job",
)

KALI_MAINT_VERBS: tuple[str, ...] = (
    "sweep-orphans",
    "tool-help",
    "gf",
)

KALI_VERBS: tuple[str, ...] = KALI_TARGET_VERBS + KALI_MAINT_VERBS


_KALI_COMMON_NOTES: tuple[str, ...] = (
    "Every target-facing kali verb requires --technique, --intent, --probe-kind, --phase, and --timeout. The CLI rejects a call missing any of these before it reaches the backend.",
    "Target inputs and target-list files are admitted through scope.json before execution. Passive sources and reachability controls require explicit typed destinations. `scope_enforcement: bypass` overrides target allow/deny admission only; tool policy, audit, rate governance, and no-fire policy remain enforced.",
    "When scope.json defines `rate_limit_aggregate_rps` (set at creation with `--aggregate-rate-limit`), target-facing runs reserve capacity after their pre-exec audit and before process launch, including commands whose target is supplied through a typed dynamic shell input. Use --rate-override-reason only for an authorized, durable exception.",
    "--technique must be one of TECHNIQUE_ENUM: use HEALTH for runtime/tool inventory, META for operator-side metadata, LOG-READ for artifact reads, OTHER only when no specific class fits.",
    "--agent-name resolves from the flag, then $AGENT_NAME, $VIGIL_AGENT_NAME, then `operator`. Specialists must export AGENT_NAME in their wrapper or pass --agent-name <role>.",
    "--phase is REQUIRED — pass the phase the dispatch was authorized for, NOT scope.json.current_phase. Allowed (from kali_audit.ALLOWED_PHASES; the two half-phase tags recon-pivot and exploit-recon are the trailing entries): "
    + ", ".join(ALLOWED_PHASES)
    + ".",
    "--destructive marks a write/edit/delete on the target (POST/PUT/PATCH/DELETE, file upload, account creation). Leave off for read-only probes.",
    "--force bypasses the dedup window. Use only when re-running an identical command is intentional.",
    "--extra-args \"<string>\" (optional, every typed verb): shlex-split and appended to the tool argv after the typed-flag args. Use sparingly for long-tail flags the verb does not model; the audit row records the full final argv. Set --destructive too if the extra args toggle a destructive mode.",
)


_KALI_COMMON_MISTAKES: tuple[tuple[str, str], ...] = (
    ("missing --phase", "always pass --phase explicitly; no env-var fallback exists"),
    ("technique=recon", "uppercase the audit technique tag (RECON, SSRF, SQLI, ...)"),
    ("intent>200 chars", "intent is trimmed to 200 chars; keep it as a one-line purpose"),
    ("--via-mcp", "the MCP path was removed — `vigil assess kali` is the only path"),
)


def _kali_invocation(verb: str) -> tuple[str, ...]:
    if verb == "exec":
        return (
            "vigil assess kali exec --technique <enum> --intent \"<one-liner>\" "
            "--probe-kind <kind> --phase <phase> --timeout 1800 -- <command...>",
        )
    return (
        f"vigil assess kali {verb} --technique <enum> --intent \"<one-liner>\" "
        f"--probe-kind <kind> --phase <phase> --timeout 1800 [verb-flags]",
    )


@dataclass(frozen=True)
class CommandContract:
    name: str
    summary: str
    schema_name: str
    preferred_invocations: tuple[str, ...]
    author_supplied_fields: tuple[str, ...]
    helper_defaults: tuple[tuple[str, str], ...] = ()
    notes: tuple[str, ...] = ()
    common_mistakes: tuple[tuple[str, str], ...] = ()
    examples: tuple[dict[str, Any], ...] = ()
    # Engagement phase(s) where this command is meaningful, drawn from the
    # canonical CATALOG_PHASES vocabulary. Drives `vigil assess list-commands
    # --phase <N>`. An empty tuple means a phase-agnostic utility (recorded /
    # queried in any phase) — it is grouped separately, not under a phase.
    phase: tuple[str, ...] = ()
    # Cross-cutting intent tags drawn from COMMAND_GOALS, ORTHOGONAL to `phase`.
    # Drives `vigil assess list-commands --goal <goal>`. Only clearly-matching
    # commands are tagged; the empty-tuple default means the command never
    # matches a `--goal` filter. Dynamically-built contracts default to ().
    goals: tuple[str, ...] = ()


_CONTRACTS: dict[str, CommandContract] = {
    "intel record": CommandContract(
        name="intel record",
        goals=("recon",),
        phase=("recon", "collect"),
        summary="Record one structured intel row through a type-specific intel schema.",
        schema_name="type-specific intel schema",
        preferred_invocations=(
            "vigil assess intel record <type> <intel-json-file>",
            "vigil assess contract intel record <type>",
        ),
        author_supplied_fields=(
            "type-specific required fields",
            "source_name",
            "evidence_ref or provenance when available",
        ),
        notes=(
            "Read `vigil assess contract intel record <type>` before authoring the JSON. Intel schemas set `additionalProperties=false`, so an alias like `source` is rejected where the schema says `source_name`.",
            "Valid intel types: " + ", ".join(sorted(INTEL_TYPES)),
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent", "use source_name or provenance.agent_name"),
        ),
        examples=(
            {
                "component": "nginx",
                "version": "1.24.0",
                "source_name": "osint-analyst",
                "confidence": "medium",
                "evidence_ref": "scans/whatweb.txt:12",
            },
        ),
    ),
    "finding record": CommandContract(
        name="finding record",
        goals=("finding-lifecycle",),
        phase=("consume-test", "verify", "exploit", "code-hunt"),
        summary="Create or upsert a finding through helper-normalized lifecycle defaults.",
        schema_name="finding-record.schema.json",
        preferred_invocations=(
            "vigil assess finding record <agent-name> <finding-json-file>",
            "vigil assess finding record <agent-name> <finding-json-file> --update <existing-slug>",
        ),
        author_supplied_fields=(
            "title",
            "details.evidence",
            "details.impact",
        ),
        helper_defaults=(
            ("slug", "allocated from the engagement-local finding sequence when omitted"),
            ("source_name", "<agent-name>"),
            ("severity", "medium"),
            ("workflow_status", "active"),
            ("verification_state", "unreviewed"),
            ("verification_disposition", "none"),
            ("defect_family", "title when omitted"),
            ("root_cause_key", '""'),
            ("auth_context", "anonymous"),
            ("canonical_location", '""'),
            ("summary", "title when omitted"),
            ("evidence_ref", '""'),
            ("notes", '""'),
            ("details.discovered_by", "<agent-name>"),
            ("provenance.agent_name", "<agent-name>"),
            ("provenance.artifact", ""),
            ("links", "[]"),
        ),
        notes=(
            "Omit top-level lifecycle fields unless you are intentionally overriding a helper default. The CLI fills workflow_status, verification_state, verification_disposition, and provenance — supply only the fields shown in the examples.",
            "Code-specific detail fields are valid: details.entry_point, details.sink, details.taint_path, details.guards_evaluated, details.slot_type, details.variant_of, details.original_pattern.",
            "details.poc_code holds exploit scripts; details.poc_request / details.poc_response hold a structured HTTP request/response pair.",
            "details.references is an array of strings for CVE links, advisories, or related docs.",
            "Set details.chain_required/details.chain_rationale/details.required_followup when the finding is concrete but only becomes exploitation-worthy as part of a larger chain. Specialists own these via finding record/finding update; verification reviews but does not own them.",
            "Blocked-attempt convention (schema-validated under details): when a technique is proven-shaped but walled off by missing provisioning, set details.block_reason (short why), details.unblock_requirements {kind, description, requested_from}, and details.attempts_summary (what was already tried). These keys are validated by finding-record.schema.json under details (additionalProperties=false); only `kind` carries a documented vocabulary (account|line|device|credential|access) — that vocabulary is a convention, NOT a JSON-Schema-enforced enum. A blocked finding stays OUT of the report; record the wall with `vigil assess block-technique` and, once a finding/chain satisfies it, connect them from the finding side with `vigil assess finding link <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>`.",
            "Do not put `link_kind=root_cause` in the `links` array. Record the finding first, then `vigil assess finding link` after verification — root/sibling grouping is an explicit lifecycle action.",
            "evidence_ref must point at an existing engagement file (auto-registered and linked on record). URL refs, prose refs, and path-shaped refs with no file are REJECTED — they cannot satisfy report-readiness artifact indexing. Put external URLs in details.references; pass --allow-unindexed-evidence only for a theoretical/code-inferred finding with no file.",
            "Dedup keys on (defect_family + root_cause_key + auth_context + canonical_location). A net-new record whose tuple collides with an EXISTING reported/active finding under a different slug is REFUSED, not silently merged. For a genuinely-distinct sibling on the same root cause, give it its OWN root_cause_key/defect_family and attach it with finding link; pass --update <slug> ONLY to intentionally modify that exact existing finding.",
            "Kill re-mint guard (D4): a net-new record that shares the same defect_family (technique) AND a normalized endpoint/canonical-location signal with a finding previously KILLED as false_positive is REFUSED — this catches a source-line vs runtime rediscovery that would otherwise resurrect a disproven finding at a different canonical_location. If the earlier kill was wrong, reopen it with `finding update <slug> --status draft --reason \"...\"`; if this is a genuinely NEW finding that only coincides on endpoint + technique, re-record with --allow-remint (a.k.a. --force).",
        ),
        common_mistakes=(
            ("status", "use workflow_status for lifecycle overrides, or omit it and keep the helper default"),
            ("evidence_ref URL/free-text prose", "point it at an existing artifact file; put URLs in details.references; use --allow-unindexed-evidence only for findings with genuinely no artifact"),
            ("confidence", "confidence belongs in code-record-analysis output, not finding records"),
            ("cwe", "use details.cwe_id"),
            ("description", "use summary for the short finding statement or notes for replayable proof"),
            ("evidence", "use details.evidence"),
            ("impact", "use details.impact"),
            ("links[].link_kind=root_cause", "use `vigil assess finding link <sibling-slug> --root-cause <root-slug>` after verification"),
            ("reusing a reported finding's root_cause_key + canonical_location for a new finding", "differentiate the root_cause_key/defect_family and use finding link, or pass --update <slug> to modify the existing finding"),
        ),
        examples=(
            {
                "title": "Blind SQL injection in search",
                "severity": "high",
                "defect_family": "sql-injection",
                "canonical_location": "https://target.example/search?q",
                "summary": "Boolean-blind SQL injection on the search endpoint",
                "evidence_ref": "scans/sqlmap.txt",
                "notes": "curl 'https://target.example/search?q=test%27+AND+1%3D1--+-' -> 200 with results",
                "details": {
                    "owasp_category": "A03:2021 Injection",
                    "cwe_id": "CWE-89",
                    "request_method": "GET",
                    "parameter": "q",
                    "evidence": "Replayable request/response pair in scans/sqlmap.txt",
                    "impact": "Anonymous attackers can extract arbitrary data from the backing store",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cvss_score": 7.5,
                    "remediation": "Use parameterized queries for all search input",
                    "steps_to_reproduce": [
                        "Send GET /search?q=test'+AND+1=1--+-",
                        "Observe normal search results returned",
                    ],
                    "poc_request": {
                        "method": "GET",
                        "url": "https://target.example/search?q=test'+AND+1=1--+-",
                        "headers": {"Accept": "text/html"},
                        "body": "",
                    },
                    "poc_response": {
                        "status": 200,
                        "headers": {"Content-Type": "text/html"},
                        "body_excerpt": "<div class='results'>3 items found</div>",
                    },
                    "chain_required": False,
                    "references": ["https://cwe.mitre.org/data/definitions/89.html"],
                },
            },
            {
                "title": "Heap buffer overflow in URL parser via overlong scheme",
                "severity": "high",
                "defect_family": "buffer-overflow",
                "canonical_location": "file:lib/urlapi.c:342",
                "summary": "Attacker-controlled URL scheme exceeding 64 bytes overflows heap buffer in parseurl()",
                "details": {
                    "cwe_id": "CWE-122",
                    "impact": "Remote code execution via heap corruption",
                    "evidence": "memcpy(buf, scheme, schemelen) copies attacker-controlled bytes without a bounds check",
                    "entry_point": "curl_url_set(CURLURLPART_URL, attacker_url)",
                    "sink": "memcpy(buf, scheme, schemelen) at lib/urlapi.c:342",
                    "taint_path": "curl_url_set(CURLURLPART_URL, attacker_url) -> parseurl() -> memcpy(buf, scheme, schemelen)",
                    "guards_evaluated": "No bounds check on schemelen before memcpy",
                    "slot_type": "URL-COMPONENT",
                    "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cvss_score": 8.1,
                    "remediation": "Add bounds check on schemelen before memcpy; reject URLs with scheme longer than 63 bytes",
                    "steps_to_reproduce": [
                        "Craft URL with scheme > 64 bytes",
                        "Pass to curl_url_set",
                        "Observe heap corruption under ASAN",
                    ],
                    "chain_required": True,
                    "chain_rationale": "The primitive is meaningful for exploitation, but final report impact depends on chaining it to a reachable crash or controlled allocation path.",
                    "required_followup": [
                        "Exercise the URL parser through a network-reachable caller",
                        "Confirm whether the overflow produces controlled corruption under sanitizer instrumentation",
                    ],
                    "references": ["https://cwe.mitre.org/data/definitions/122.html"],
                },
            },
            {
                "title": "BFLA on role-grant endpoint (blocked: needs org-admin group)",
                "severity": "high",
                "defect_family": "broken-function-level-authorization",
                "canonical_location": "https://target.example/api/roles/grant",
                "summary": "The role-grant endpoint appears to lack function-level authz, but confirming it requires an account provisioned into the org-admin group.",
                "notes": "Anonymous + member roles 403 at the gate; the grant call is only reachable once inside org-admin — provisioning not available this engagement.",
                "details": {
                    "impact": "If confirmed, a low-privilege user could grant themselves arbitrary roles (privilege escalation).",
                    "evidence": "GET /api/roles/grant returns 403 for member; the UI only renders the grant control for org-admin.",
                    "block_reason": "Cannot reach the role-grant endpoint without an org-admin-group account.",
                    "unblock_requirements": {
                        "kind": "account",
                        "description": "A test account provisioned into the org-admin group with role-management entitlement.",
                        "requested_from": "program contact / target admin",
                    },
                    "attempts_summary": "Tried anonymous, member, and billing-admin sessions; all 403 at the function gate. Recorded via block-technique (BFLA on this host).",
                },
            },
        ),
    ),
    "finding link": CommandContract(
        name="finding link",
        goals=("finding-lifecycle",),
        phase=("verify", "report"),
        summary="Group findings by root cause, attach intel, or record a generic typed finding link (incl. the unblock path for blocked findings).",
        schema_name="backend RootCauseLinkRequest / FindingLinkRequest",
        preferred_invocations=(
            "vigil assess finding link <sibling-slug> --root-cause <root-slug> --effect eliminates_finding",
            "vigil assess finding link <sib1> <sib2> <sib3> --root-cause <root-slug>",
            "vigil assess finding link <sibling-slug> --root-cause <root-slug> --effect eliminates_attack_path --note 'Root removes this exploit chain; residual XXE remains.'",
            "vigil assess finding link <sibling-slug> --clear-root-cause",
            "vigil assess finding link <blocked-slug> --link-kind unblocked_by --target-kind finding --target-ref <unblocking-slug>",
            "vigil assess finding link <slug> --link-id 123 --target-ref <corrected-slug>",
            "vigil assess finding link <slug> --link-id 123 --retire",
            "vigil assess finding link <slug> --link-id 123 --reactivate",
            "vigil assess finding link <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>",
            "vigil assess finding link <slug> --link-kind related --target-kind chain --target-id 12",
        ),
        author_supplied_fields=(
            "finding_slug",
            "root_cause mode: root_cause_slug, root_cause_effect, note",
            "generic mode: --link-kind, --target-kind, and --target-id or --target-ref",
            "generic update mode: --link-id plus fields to patch, --retire, or --reactivate",
        ),
        helper_defaults=(
            ("source_name", "operator"),
            ("sibling_order", "next available order when omitted"),
            ("provenance", "{}"),
            ("link_kind", "related (generic mode)"),
        ),
        notes=(
            "Batch: list several sibling slugs positionally to attach them all to one --root-cause (or apply the same --intel / generic / --clear-root-cause op to each) in a resilient loop with a per-slug failure tally.",
            "Root-cause mode (--root-cause): use after findings are verified enough to consolidate. Records intentional grouping without touching root_cause_key, so dedup and human grouping stay separate.",
            "Each finding has at most one active root-cause link. Reissuing --root-cause updates that row in place, preserving its id, note, and order unless replacements are supplied; --clear-root-cause retires it without deleting evidence.",
            "Root-cause and sibling groupings cannot be nested, and merged/false-positive findings cannot appear on either end.",
            "Use --effect eliminates_attack_path when fixing the root removes only the demonstrated chain and the sibling still needs standalone remediation; use eliminates_finding when the root fix retires the sibling entirely.",
            "Generic mode (--link-kind + --target-kind + --target-id/--target-ref): records an arbitrary typed link (POST /findings/{slug}/links). link_kind=root_cause is refused here — use --root-cause.",
            "Generic update mode (--link-id): patches, retires, or reactivates an existing non-root-cause link. Retirement is reversible and evidence-preserving; self-links are rejected on create and update.",
            "Unblock path (first-class): a blocked finding stays OUT of the report, but when a finding/chain that satisfies the wall lands, link it with `--link-kind unblocked_by --target-kind finding --target-ref <unblocking-slug>` (or --target-kind chain --target-id <id>) so the operator and the next engagement see the connection.",
            "Blocked TECHNIQUE (from block-technique) unblock: a blocked technique has no slug and cannot be a link SUBJECT — record it on the FINDING side with `--link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>` (the unblocking finding points at the technique key). target_kind is free text, so blocked_technique is accepted without a backend change.",
        ),
        common_mistakes=(
            ("root_cause_key", "do not repurpose root_cause_key as a display grouping field; use finding link for intentional groups"),
            ("related", "generic related links do not suppress duplicate-root-cause report blockers"),
            ("omitting --order in a rerun", "an existing root-cause link keeps its order; a new sibling receives max(active sibling_order)+1, so reruns do not duplicate orders"),
        ),
    ),
    "block-technique": CommandContract(
        name="block-technique",
        phase=("consume-test", "exploit"),
        summary="Record a technique walled off on a target (account/device/credential/policy wall, WAF) so it is not silently re-attempted.",
        schema_name="backend BlockedTechniqueRecordRequest",
        preferred_invocations=(
            "vigil assess block-technique --technique SSRF --target-kind host --target-ref api.example.com --reason 'egress firewalled; internal metadata endpoint unreachable' --retry-state no_retry",
            "vigil assess block-technique --technique BFLA --target-kind finding --target-ref VA-047 --reason 'needs an account in the org-admin group to reach the role-grant endpoint' --retry-state pending",
            "vigil assess list-blocked-techniques",
        ),
        author_supplied_fields=(
            "--technique (TECHNIQUE_ENUM)",
            "--target-kind",
            "--target-ref",
            "--reason",
        ),
        helper_defaults=(
            ("technique_key", "derived '<technique>:<target_kind>:<target_ref>' when omitted (stable upsert key)"),
            ("retry_state", "pending"),
            ("source_name", "operator"),
        ),
        notes=(
            "A do-today pointer, NOT a finding — a blocked technique stays OUT of the report. It records what was tried-and-walled-off so the operator and the next engagement do not rediscover the wall per-dispatch. Surfaced under the resume-brief Attempts section.",
            "retry_state soft vocab: pending (block may lift once a prerequisite lands) | retryable (worth another attempt now) | no_retry (permanent wall). Free text; these are the documented, resume-legible values.",
            "A blocked technique has NO slug, so it can never be the SUBJECT of finding link. Record the unblock from the FINDING side: when a finding/chain satisfies the wall, `vigil assess finding link <unblocking-finding-slug> --link-kind unblocks --target-kind blocked_technique --target-ref <technique_key>`. The unblock path is first-class even though the blocked technique itself is not reported.",
            "Put the wall's provisioning need in details.unblock_requirements on the RELATED finding (kind ∈ account|line|device|credential|access, description, requested_from); the block-technique row carries the short reason + retry_state, and --notes is a one-line cue (also shown in the resume brief), not the durable home for unblock requirements.",
        ),
    ),
    "auth": CommandContract(
        name="auth",
        phase=("consume-test", "exploit"),
        summary="List the engagement's stored session identities (append-only multi-identity store) so you can pick one for cross-account IDOR/BOLA.",
        schema_name="engagement_credentials table / GET /credentials[?host=&include_dead=]",
        preferred_invocations=(
            "vigil assess auth list",
            "vigil assess auth list --host api.example.com",
            "vigil assess auth list --include-dead --json",
        ),
        author_supplied_fields=(
            "subcommand: list",
            "list filters: --host / --include-dead / --json",
        ),
        helper_defaults=(
            ("host", "unset (lists every stored identity)"),
            ("include_dead", "false (probe-proven-dead sessions hidden; `stale` always shown)"),
        ),
        notes=(
            "The store is append-only + multi-identity: logout-then-login on one host keeps BOTH sessions, so `auth list` can show two live identities for the same site — pick one with `vigil assess kali --identity <name>` (or auth status --probe --identity) for the account you are testing as. When the name is a scoped alias, also pass `--identity-scope <logical-scope>`; Vigil never guesses logical scope from the target URL.",
            "The list view shows cookie NAMES + hosts and metadata (auth_context, state, liveness, age, last_probed) but NEVER raw cookie VALUES — session material stays out of the enumeration view.",
            "state: available | stale (8h age backstop — re-probe) | dead (probe-proven; hidden unless --include-dead) | missing. Only a failed liveness probe marks a session dead; age never does.",
            "liveness is UNKNOWN until you actively probe: run `vigil assess auth status --probe --identity <name> --probe-url <url> --scope <logical-scope>` to persist a TTL-bound observation for that identity and scope.",
            "A literal identity name always wins. Otherwise a configured alias resolves only to the freshest non-expired live capability for its durable principal_id and requested scope.",
            "The active identity is marked with a trailing `*` in the text view.",
        ),
        common_mistakes=(
            ("--include-dead to see stale sessions", "stale sessions are always listed; --include-dead only un-hides probe-proven-dead ones"),
            ("reading raw cookie values from the list", "the list view is names-only by design; the runtime injects values host-scoped via `kali --identity`"),
        ),
    ),
    "http": CommandContract(
        name="http",
        summary="Query, export, and configure captured full-flow HTTP traffic (the canonical mitmproxy flow store + per-engagement capture policy).",
        schema_name="assessment_http_flows + assessment_capture_policy tables / /assessment/http-flows + /assessment/capture-policy endpoints",
        preferred_invocations=(
            "vigil assess http list --host api.example.com --method POST --content-type json",
            "vigil assess http show <flow_uid>",
            "vigil assess http search 'admin' --auth-context anonymous --json",
            "vigil assess http export-har --host api.example.com -o traffic/api.har",
            "vigil assess http import-har traffic/api.har",
            "vigil assess http policy",
            "vigil assess http policy set --enabled --capture-request-bodies --max-body-bytes 262144 --content-type-allow application/json",
        ),
        author_supplied_fields=(
            "subcommand: list | show | search | export-har | import-har | policy [set]",
            "list/search/export-har filters: --host / --method / --status / --content-type / --auth-context / --truncated|--no-truncated / --q / --limit / --offset",
            "show: <flow_uid> (or numeric id) positional",
            "export-har: -o/--output <file>",
            "import-har: <har-file> positional",
            "policy set: --enabled/--no-enabled, --capture-request-bodies, --capture-response-bodies, --max-body-bytes, --content-type-allow, --content-type-deny, --redaction-profile",
        ),
        helper_defaults=(
            (
                "capture policy",
                "full-flow recording is OFF by default; `policy set` is a partial update "
                "(unset fields retain their stored value)",
            ),
            ("query filters", "only non-empty filters are sent; the backend caps list/search at 5000 rows"),
        ),
        notes=(
            "Capture is a per-engagement POLICY (backend state + a `capture-policy.json` filesystem mirror the addon reads offline), NOT a proxy start selector — the shared selector-less proxy routes by hostname and honours this policy per host.",
            "The policy has three useful states: disabled records only the always-on compact request observation; enabled with both body flags false records full-flow metadata/index rows without bodies; enabled with either body flag records that selected body side as an engagement-local sidecar.",
            "`show` and `export-har` expose only engagement-local metadata + body sidecars; raw bodies stay engagement-local by default.",
            "`export-har` writes HAR 1.2 with Vigil routing/auth/truncation metadata on each entry's `_vigil` field; `import-har` reads `_vigil` for a lossless round-trip.",
            "Prefer these verbs over raw `vigil assess fetch \"http-flows?...\"` — they keep query-string details out of operator instructions.",
        ),
        common_mistakes=(
            (
                "assuming --enabled stores bodies",
                "--enabled turns full-flow metadata recording on; select request and/or response body sidecars explicitly with the body flags",
            ),
            ("policy set with no fields", "pass at least one field — an empty update is rejected"),
        ),
    ),
    "record-probe": CommandContract(
        name="record-probe",
        phase=("consume-test", "exploit"),
        summary="Record ANY probe outcome — covering (tested|signal, evidence required) or non-covering (attempted|blocked|no-signal|error) — to the probe ledger. A covering probe carrying a coverage-item/request-variant link drains its work-items and advances its surface(s) by default.",
        schema_name="backend ProbeRunRecordRequest (POST /probe-runs)",
        preferred_invocations=(
            "vigil assess record-probe --result-status tested --attack-family idor --target-host app.example.com --target-path /orders/1001 --input-slot path:id --auth-context member --evidence-ref scans/idor-orders.txt --coverage-item-id 77",
            "vigil assess record-probe --result-status signal --attack-family ssrf --target-host api.example.com --target-path /fetch --input-slot query:url --auth-context anonymous --lens blind-oob --evidence-ref scans/ssrf-oob.txt --outcome-assertion 'callback host matched the issued token' --finding VA-047",
            "vigil assess record-probe --result-status blocked --attack-family ssrf --lens tenant-boundary --target-host api.example.com --target-path /fetch --input-slot query:url --auth-context anonymous --notes 'WAF 403 on every internal host'",
            "vigil assess record-probe --result-status no-signal --attack-family idor --target-host app.example.com --target-path /orders/1001 --auth-context member --input-slot path",
        ),
        author_supplied_fields=(
            "--result-status (tested|signal — covering, evidence required — or attempted|blocked|no-signal|error — non-covering)",
            "--attack-family (a vuln_taxonomy CLASS token — not a family heading; see agent/references/runtime-guides/vuln-taxonomy.md)",
            "--evidence-ref (REQUIRED for a covering status tested|signal; optional for the non-covering four)",
            "--outcome-assertion (REQUIRED for signal; name the body/application marker that proves the positive outcome)",
            "--input-slot (REQUIRED — 'slot:name' or a bare coarse slot; 'unknown'/empty rejected)",
            "--auth-context (REQUIRED — explicit identity; no silent anonymous)",
            "--target-host (REQUIRED unless a --request-variant-id/--service-id anchor is passed) / --target-path / --lens as applicable",
            "--request-variant-id / --service-id / --coverage-item-id from the fetched work-item (links the probe to the exact request/coverage item; the default cascade keys on them)",
            "--work-item-ids <id...> (OVERRIDE — narrow the default drain to exactly these ids)",
            "--resolve-surface <id> (OVERRIDE — advance exactly that surface instead of the FK-linked ones)",
            "--no-drain (SUPPRESS the default cascade — leave the buffer and surfaces untouched)",
        ),
        helper_defaults=(
            ("tool_name", "manual"),
            ("lens", '"" (part of the probe key: a different lens is a distinct probe)'),
        ),
        notes=(
            "One verb for every probe outcome (it absorbed the former record-attempt). Covering (tested|signal) advances the coverage map and REQUIRES --evidence-ref; non-covering (attempted|blocked|no-signal|error) records that the target was TOUCHED under a --lens without counting as coverage, so the resume-brief Attempts ledger surfaces it and the next dispatch does not re-run a dead end (evidence optional).",
            "`--evidence-ref` on a covering probe is mandatory: a covering verdict with no evidence is exactly the self-attested signal the doctrine forbids, and the depth ledger only counts covering probes with a real result.",
            "A `signal` result also requires --outcome-assertion. Without a body/application-level marker, the backend demotes it to non-covering `attempted`; status code and response size alone can never manufacture a positive verdict.",
            "1b default cascade: a COVERING probe carrying --coverage-item-id drains the work-items FK-linked to that coverage item (marked `done` in the SAME transaction), and one carrying --request-variant-id advances the discovered surface(s) FK-linked to that variant to `partially-covered` — no extra verbs, so `vigil assess work-buffer stats` and the surface ledger stop disagreeing with the probe-derived coverage. It is covering-gated (a non-covering attempt never auto-cascades), never auto-promotes coverage_items.status to `covered`, and never regresses a human surface verdict.",
            "Override/suppress the cascade: --work-item-ids <id...> narrows the drain to explicit ids (unknown ids skipped, not an error); --resolve-surface <id> advances exactly that surface; --no-drain suppresses the whole cascade. Both overrides fire regardless of the covering gate.",
            "The same target under a DIFFERENT --lens is a distinct probe (lens is hashed into the probe key), not a dedup collision. Name the specific input as `--input-slot slot:name` (e.g. `header:X-Forwarded-Host`, `query:uid`) so per-input coverage stays queryable; a bare slot is fine for whole-slot probes.",
            "--finding <slug> backfills the probe→finding link (finding_id); COALESCE-backfilled on a re-run of the same probe. An out-of-vocab --attack-family WARNs but is stored verbatim. Replaces the old raw `post probe-runs <json>` (that raw POST is disabled — the `post` guard points here).",
            "Verdict → status (there is NO `refuted` status — a runtime-refuted hypothesis is `no-signal`): confirmed vuln → `tested|signal` (evidence); the probe fired but proved nothing → `attempted`; a WAF/auth/egress wall stopped it → `blocked`; hypothesis disproven / nothing distinguishing the response → `no-signal`; the probe itself errored → `error`. A durable technique-level wall on a target belongs in `vigil assess block-technique`, not a single `blocked` probe. Vocabulary source: coverage.py:PROBE_RESULT_STATUSES.",
        ),
        common_mistakes=(
            ("omitting --evidence-ref on tested/signal", "a covering verdict requires evidence; without it, record it with a non-covering status (attempted/blocked/no-signal/error) or attach the evidence path"),
            ("signal from status/size alone", "name the application-level success marker in --outcome-assertion; otherwise the result is recorded as inconclusive attempted work"),
            ("recording a wall as a bare blocked probe when it is a durable technique wall", "a one-off `blocked` probe is a lead; a durable technique-level wall on a target belongs in `vigil assess block-technique`"),
        ),
    ),
    "finding report": CommandContract(
        name="finding report",
        goals=("finding-lifecycle",),
        phase=("report",),
        summary="Fetch the grouped report finding projection that report-writer consumes.",
        schema_name="backend grouped report-findings projection",
        preferred_invocations=(
            "vigil assess finding report --mode final --json",
            "vigil assess finding report --mode draft --json",
            "vigil assess finding report --mode final",
        ),
        author_supplied_fields=(
            "mode",
        ),
        helper_defaults=(
            ("mode", "final"),
            ("view", "grouped root-cause projection"),
        ),
        notes=(
            "Use this helper instead of raw `vigil assess fetch report-findings?...`. It makes grouped root-cause output the contract and keeps query-string details out of operator instructions.",
            "`--mode final` enforces report-readiness and exits non-zero while blockers remain; `--mode draft` inspects the grouped projection before readiness passes.",
            "`--json` is the report-writer/LLM ingestion form. The default text form is for quick human inspection.",
        ),
    ),
    "resume-brief": CommandContract(
        name="resume-brief",
        summary="Render a bounded resume brief from backend state, command history, handoffs, and indexed artifacts.",
        schema_name="GET /assessment/resume-brief",
        preferred_invocations=(
            "vigil assess resume-brief",
            "vigil assess resume-brief --finding VA-047",
            "vigil assess resume-brief --q \"OIDC static state\" --json",
        ),
        author_supplied_fields=(
            "--q",
            "--finding",
            "--agent-id",
        ),
        notes=(
            "First resume primitive — use instead of manually chaining findings, handoffs, command-runs, and local notes.",
            "Before reading the brief, the helper performs a bounded one-hour orphan sweep across command runs, async jobs, and precisely-owned host processes so stale runtime state is not presented as active work.",
            "Output is bounded; use command-run get and artifact get for drill-down.",
            "Carries aggregate Surfaces (status×type + top uncovered) and Work Buffer (pending coverage by gf-bucket) rollups plus coverage/read-first intel notes — drill into per-item coverage-items / request-variants / work-buffer only when a rollup flags a bucket.",
            "Carries an Attempts do-today ledger (recorded blocked techniques and roe_blocked findings) — read it BEFORE re-dispatching a surface so a walled-off technique is not silently re-attempted.",
            "Carries a Per-Input Coverage grid grouping every probe by (host × path × attack_family × input_slot × auth_context) — covering AND non-covering, with the latest verdict and any wall code (e.g. 403). Read it to see which specific input was tested for which class as which identity before re-probing; it supersedes the old flat non-covering probe list.",
        ),
        common_mistakes=(
            ("loading local notes first", "run resume-brief, then artifact search/get for linked files"),
        ),
    ),
    "artifact": CommandContract(
        name="artifact",
        goals=("artifact",),
        summary="Register, refresh, search, fetch, or scratch-mark indexed engagement-local artifact metadata.",
        schema_name="assessment_artifacts table + /assessment/artifacts endpoints",
        preferred_invocations=(
            "vigil assess artifact search VA-047",
            "vigil assess artifact search --finding VA-047",
            "vigil assess artifact get <id>",
            "vigil assess artifact register notes/foo.md --kind note --finding VA-047",
            "vigil assess artifact refresh",
            "vigil assess artifact mark-scratch notes/triage.md",
            "vigil assess artifact mark-scratch --under notes/scratch/",
            "vigil assess artifact unmark-scratch notes/triage.md",
        ),
        author_supplied_fields=(
            "subcommand: search | get | register | mark-scratch | unmark-scratch",
            "register: <path> (positional, required)",
            "get: <artifact_id> (positional int, required)",
            "search: [query...] (positional, optional free-text)",
            "register: --finding / --kind / --agent-id / --command-run-id / --sensitive",
            "search: --finding / --limit / --offset",
            "mark-scratch / unmark-scratch: <target> (id or path) or --under <prefix>",
        ),
        notes=(
            "Each action is a typed subcommand — run `vigil assess artifact <action> --help` for per-action flags.",
            "Large/raw files stay on disk; the backend stores hashes, capped previews, presence, and entity links.",
            "Register paths relative to the engagement root; absolute paths are accepted only when they resolve inside the engagement directory.",
            "`mark-scratch` flags a note non-durable so `check-phase-readiness --phase report` stops blocking on it; the row stays searchable.",
        ),
        common_mistakes=(
            ("pasting full artifact content into prompts", "search first, then get a specific id; content stays capped"),
            ("deleting unlinked notes to clear blockers", "use `mark-scratch` to keep the audit row; delete only when the file should not exist"),
        ),
    ),
    "finding verify": CommandContract(
        name="finding verify",
        goals=("finding-lifecycle",),
        phase=("verify", "code-verify"),
        summary="Apply a verification transition to an existing finding through the audit ledger.",
        schema_name="backend FindingVerifyRequest",
        preferred_invocations=(
            'vigil assess finding verify <slug> --disposition confirmed --reason "..."',
            'vigil assess finding verify <slug> --disposition downgraded --reason "..." --new-severity low',
            'vigil assess finding verify <slug> --disposition false_positive --reason "..." --kill-reason "..." --kill-check 2',
            "vigil assess finding verify <slug> --payload-file verify.json",
            'vigil assess finding verify VA-001 VA-002 VA-003 --disposition confirmed --reason "batch: all reproduced"',
        ),
        author_supplied_fields=(
            "disposition",
            "reason_text",
        ),
        notes=(
            "Use for confirmed, downgraded, and disputed verification outcomes.",
            "For false_positive, pass --disposition false_positive with details.kill_reason/details.kill_check (via --kill-reason/--kill-check).",
            "Use explicit flags for ordinary transitions. --payload-file is for a final, complete verification-transition document; it is mutually exclusive with request-content flags, while --narrative may accompany it.",
            "The generic --inline and trailing positional JSON forms were REMOVED. Use explicit flags or --payload-file <path>.",
            "Batch: list several slugs positionally to apply the SAME disposition or payload file to each (resilient loop with a per-slug failure tally).",
        ),
        common_mistakes=(
            ("rationale", "use reason_text"),
            ("status", "verification is a transition, not a raw status patch"),
        ),
        examples=(
            {
                "disposition": "confirmed",
                "reason_text": "Reproduced as written.",
            },
            {
                "disposition": "downgraded",
                "reason_text": "Impact is lower after retest.",
                "new_severity": "low",
            },
        ),
    ),
    "finding update": CommandContract(
        name="finding update",
        goals=("finding-lifecycle",),
        summary="Patch non-verification finding fields on an existing slug.",
        schema_name="backend FindingPatchRequest",
        preferred_invocations=(
            "vigil assess finding update <slug> --payload-file patch.json",
            'vigil assess finding update <slug> --status reported --reason "Published in report"',
            'vigil assess finding update <slug> --status draft --reason "Needs more evidence"',
            'vigil assess finding update <slug> --expected-row-version <version> --summary "..."',
            'vigil assess finding update <slug> --details-inline \'{"chain_required":true,"chain_rationale":"...","required_followup":["..."]}\'',
            'vigil assess finding update <slug> --expected-row-version <version> --details-inline \'{"cvss_score":9.1}\' --details-replace',
            'vigil assess finding update VA-006 VA-007 --status reported --reason "batch: published"',
        ),
        author_supplied_fields=(
            "at least one patch field",
        ),
        notes=(
            "Use explicit flags for small patches. --payload-file accepts a partial writable patch for exactly one slug, is mutually exclusive with request-content flags, and must contain expected_row_version.",
            "A successful update returns the next row_version. Refresh the staging file yourself before reusing it; Vigil reads but never rewrites that file.",
            "When a payload file contains notes, it must set notes_mode to replace for a cumulative working document or append for a deliberate checkpoint.",
            "details and provenance merge by default. Set details_mode='replace' in a versioned payload file, or pair --details-inline with --details-replace plus --expected-row-version, only when stale detail keys must be removed. --notes-replace has the same compare-and-swap requirement.",
            "The generic --inline and trailing positional JSON forms were REMOVED. Use explicit flags or --payload-file <path>.",
            "Batch: list several slugs positionally only with explicit flags (resilient loop with a per-slug failure tally). The helper fetches each slug's current row_version and sends a separate compare-and-swap patch; one stale row cannot silently overwrite another.",
            "Use for workflow and metadata updates that are NOT verification lifecycle transitions.",
            "Reopening a verified or false-positive finding for re-triage: finding update --status draft.",
            "Verification disposition changes, disputed reviews, and false_positive kills belong in finding verify --disposition false_positive.",
            "--submission-status tracks EXTERNAL bug-bounty/program submission state and is ORTHOGONAL to "
            "--workflow-status (which is report-inclusion). Setting one never changes the other. Allowed values: "
            + ", ".join(SUBMISSION_STATUSES)
            + " (default 'none' = not submitted).",
            "--details-inline '<json object>' merges the given object into the finding's stored details "
            "(the patch payload field is `details`). Pair with "
            "--details-replace to overwrite the whole details object instead of merging — --details-replace "
            "requires a details payload via --details-inline; payload files instead set details_mode='replace' "
            "because running it without one would wipe existing details.",
            "The patch payload field is `details` on write; the API returns it back as `details_json` on read "
            "(GET/list responses). They are the same data under two names — do not conclude a `details` write "
            "was dropped just because the read-back shows `details_json` instead. A top-level `details_json` "
            "key in the patch payload itself is rejected with a 422 (unknown field) — always write `details`.",
        ),
        common_mistakes=(
            ("verification_state", "use finding verify for verification lifecycle changes"),
            ("verification_disposition", "use finding verify for verification lifecycle changes"),
            ("workflow_status=false_positive", "use finding verify --disposition false_positive instead of finding update"),
            ("submission_status to mark a finding reported", "submission_status is external submission state; use --workflow-status reported for report-inclusion"),
            ("details_json as a top-level patch field", "the payload field is details (it is stored as / read back as details_json); details_json is rejected with a 422"),
        ),
        examples=(
            {
                "workflow_status": "reported",
                "reason_text": "Published in report.",
                "expected_row_version": 17,
            },
            {
                "severity": "low",
                "summary": "Retest reduced the confirmed impact.",
                "expected_row_version": 17,
            },
            {
                "submission_status": "accepted",
                "reason_text": "Program triaged the report as accepted.",
                "expected_row_version": 17,
            },
            {
                "notes": "Current cumulative verification notes.",
                "notes_mode": "replace",
                "details": {"cvss_score": 7.5},
                "expected_row_version": 17,
            },
            {
                "details": {
                    "chain_required": True,
                    "chain_rationale": "This primitive becomes meaningful only after pivoting into the admin export flow.",
                    "required_followup": [
                        "Test sibling privileged write routes",
                        "Attempt authenticated export with stolen token",
                    ],
                },
                "reason_text": "Tagged chain-required after Phase 4 review.",
                "expected_row_version": 17,
            },
        ),
    ),
    "resolve": CommandContract(
        name="resolve",
        phase=("collect", "consume-test", "verify"),
        summary="PATCH a surface OR a coverage-item by id (target-kind positional + status + rationale). Post-1b (recording advances surfaces/drains work by default) this is the manual-override / negative-verdict path.",
        schema_name="backend SurfaceUpdateRequest (surface) / CoverageItemUpdateRequest (coverage-item)",
        preferred_invocations=(
            'vigil assess resolve surface <id> --status covered --rationale "..."',
            'vigil assess resolve surface <id> --status not_applicable --rationale "..."',
            'vigil assess resolve surface <id> --status partially-covered --rationale "..." --followup-condition "..."',
            'vigil assess resolve surface 42 99 17 --status deferred --rationale "batch: same triage verdict"',
            'vigil assess resolve coverage-item <id> --status covered --rationale "idor tested across two identities; user_b got 403"',
            'vigil assess resolve coverage-item 77 88 99 --status not_applicable --rationale "batch: static render, no id-bearing param"',
        ),
        author_supplied_fields=(
            "target-kind positional: surface | coverage-item",
            "one or more ids (batch)",
            "--status (surface: covered|not_applicable|deferred|partially-covered; coverage-item: pending|queued|deferred|covered|not_applicable|blocked)",
            "--rationale (required)",
            "--followup-condition (surface only, REQUIRED for --status partially-covered)",
        ),
        notes=(
            "One verb, a target-kind positional (it absorbed resolve-surface + resolve-coverage-item). Each kind keeps its OWN status vocabulary; --source-name / --evidence-ref / --followup-condition are surface-only (rejected on a coverage-item).",
            "Batch: list several ids positionally to resolve them all with the SAME --status/--rationale (resilient loop with a per-id failure tally). --rationale is appended to the existing rationale (surface) / notes (coverage-item), so the audit trail accumulates.",
            "surface: resolve a discovered surface after triage. `discovered` is the seed state and not a resolution; --followup-condition names what the next coverage pass must satisfy for `partially-covered`. Post-1b, recording a covering probe already advances a linked surface to `partially-covered` by default — use `resolve surface ... --status covered` to record the deliberate, rationale-bearing human `covered` verdict (never auto-attested).",
            "coverage-item: seeded `pending` at ingest — one per implied vuln-class on a surface. Resolve every implied class, not just the cluster winner (a surface's `covered` on one class does NOT cover its siblings); the depth ledger's signal_classes_uncovered stays open otherwise. --rationale is required for EVERY status; the backend additionally rejects an empty rationale for `covered` / `not_applicable`. Coverage-item status is a HUMAN verdict — recording a probe never auto-promotes it to `covered`.",
            "Replaces the old raw `patch coverage-items/<id> <json>` (now redirected here).",
        ),
        common_mistakes=(
            ("resolve surface --status discovered", "discovered is the seed state; resolve to covered, not_applicable, deferred, or partially-covered"),
            ("reason", "use --rationale for the resolution explanation"),
            ("resolve surface partially-covered without --followup-condition", "the follow-up condition is mandatory for partially-covered so the audit trail names what the next pass must satisfy"),
            ("resolve coverage-item ... --status covered with no --rationale", "covered means tested with a stated reason; the backend rejects an evidence-free covered"),
            ("resolving only the cluster-winner coverage-item class", "resolve every coverage item the surface accrued (one per implied class), or the depth ledger's signal_classes_uncovered stays open"),
            ("--followup-condition on a coverage-item", "that flag is surface-only; a coverage-item takes only --status and --rationale"),
        ),
    ),
    "intel update": CommandContract(
        name="intel update",
        goals=("recon",),
        summary="PATCH an existing intel row by id without inserting a new history record.",
        schema_name="backend IntelUpdateRequest (per-type updatable column whitelist)",
        preferred_invocations=(
            "vigil assess intel update <type> <id> <patch.json>",
            "vigil assess intel update <type> <id> --inline '{...}'",
        ),
        author_supplied_fields=(
            "at least one updatable column",
        ),
        notes=(
            "intel update does in-place metadata edits; intel supersede retains the prior row for audit and inserts a new record.",
            "The backend rejects fields outside the per-type updatable column whitelist, so guessed aliases surface immediately.",
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("agent", "use source_name or provenance.agent_name"),
        ),
        examples=(
            {"validation_status": "exploited"},
            {"notes": "Confirmed working PoC against staging"},
        ),
    ),
    "intel supersede": CommandContract(
        name="intel supersede",
        goals=("recon",),
        summary="Insert a replacement intel row; old row stays for audit but is filtered from reports.",
        schema_name="type-specific intel schema for the new payload",
        preferred_invocations=(
            'vigil assess intel supersede <type> <id> <new.json> --rationale "..."',
            'vigil assess intel supersede <type> <id> --inline \'{...}\' --rationale "..."',
        ),
        author_supplied_fields=(
            "type-specific natural-key fields for the new replacement record",
            "--rationale (free text)",
        ),
        notes=(
            "Use when an intel row was wrong but the prior observation must stay for audit.",
            "Metadata-only edits belong in intel update; intel supersede requires the replacement row's full natural key.",
            "Report-writer filters on superseded_by_id IS NULL, so superseded rows drop out of reports but stay queryable for cascade-delete and audit.",
        ),
        common_mistakes=(
            ("source", "use source_name"),
            ("rationale-collision", "if the new natural key matches the existing row, use intel update instead"),
        ),
        examples=(
            {
                "component": "nginx",
                "version": "1.27.0",
                "source_name": "vulnerability-analyst",
                "confidence": "confirmed",
            },
        ),
    ),
    "code-dispatch": CommandContract(
        name="code-dispatch",
        goals=("dispatch", "code-analysis"),
        phase=("code-classify", "code-hunt"),
        summary="Operate the backend code-analysis queue and cross-file trigger lifecycle.",
        schema_name="backend code-analysis queue / trigger request models",
        preferred_invocations=(
            "vigil assess code-dispatch fetch <limit> <agent-name>",
            "vigil assess code-dispatch fetch <limit> <agent-name> --repo-id <id> --classification <tier> --batch-theme <theme>",
            "vigil assess code-dispatch fetch <limit> <agent-name> --ids-file <queue-ids-json>",
            "vigil assess code-dispatch heartbeat <item-id> <agent-name> <lease-token>",
            "vigil assess code-dispatch done <item-id> <agent-name> <lease-token> <disposition> <cwe-coverage-json-file> [notes]",
            "vigil assess code-dispatch list-triggers [status]",
            "vigil assess code-dispatch resolve-triggers <triggers-json-file> <resolution-status> <note>",
            "vigil assess code-dispatch requeue-triggers <triggers-json-file>",
            "vigil assess code-dispatch retry-error <id1,id2,...> [reason]",
            "vigil assess code-dispatch retry-needs-context <id1,id2,...> <reason>",
        ),
        author_supplied_fields=(
            "queue item id(s)",
            "optional atomic fetch filters: repo_id, classification, batch_theme, and item_ids",
            "the fetched agent_name + lease_token for heartbeat, results, and closeouts",
            "bare JSON array for cwe_coverage when completing a queue item",
            "trigger_id/id or file_path/target_file_path when resolving triggers",
            "resolution_status: external_context_unavailable, source_equivalent_analyzed, or not_applicable",
            "resolution_note explaining why the trigger is accepted without requeue",
        ),
        notes=(
            "Fetch filters are applied inside the same serialized SQL claim that changes pending rows to processing. The returned agent_name, lease_token, and repo_generation identify the owned analysis generation; reuse the agent and lease on heartbeat, result, and closeout writes.",
            "A finding/suspicious closeout requires a current same-disposition result for the active lease with inline evidence or evidence_ref. A clean closeout requires non-empty family coverage and review notes; skipped retains its structured skip reason.",
            "Analysis-result retries are idempotent within a lease. Coverage detail derives result-row, evidenced-row, and distinct-function effort from current nonsuperseded records instead of trusting the submitted effort counter alone.",
            "`resolve-triggers` records accepted terminal trigger gaps — use it when the target implementation is outside the supplied source snapshot, a source equivalent was analyzed, or the trigger family is genuinely not applicable.",
            "Do not inflate CWE effort numbers to satisfy the gate. Use `disposition=not_applicable` on the coverage entry, or `resolve-triggers` for cross-file gaps that cannot be queued.",
            "`list-triggers` defaults to pending triggers, so operators can inspect blockers before resolving or requeueing.",
            "`retry-error` recovers queue items stuck at status='error' back to 'pending' so they re-enter the fetch rotation — `reset-stale` only recovers abandoned 'processing' rows on a time window and never touches 'error' rows.",
            "`retry-needs-context` returns reviewed context gaps to pending and supersedes their old needs-context result projection.",
        ),
        common_mistakes=(
            ("filtering a fetched batch client-side", "pass repo/classification/theme/id filters to fetch so unrelated rows are never claimed"),
            ("closing finding/suspicious before recording evidence", "record the same-disposition result with evidence or evidence_ref under the active lease first"),
            ("closing clean without notes", "summarize the reviewed paths and guards in non-empty closeout notes"),
            ("cwe_coverage object wrapper", "`done` requires a bare JSON array, not {'cwe_coverage': [...]}"),
            ("analysis_priority", "queue payloads use `priority`; classification payloads use `analysis_priority`. Preserve the architect's ordering by mapping analysis_priority to priority when queueing."),
            ("missing resolution_note", "accepted trigger gaps need a durable rationale"),
            ("using resolve-triggers for pending source that exists", "use requeue-triggers when the target file is available and needs analysis"),
        ),
        examples=(
            {
                "command": "vigil assess code-dispatch resolve-triggers missing.json external_context_unavailable 'storage DLL source not provided'",
            },
            {
                "command": "vigil assess code-dispatch done 42 code-vuln-hunter <lease-token> clean cwe/42.json 'reviewed parser'",
            },
            {
                "command": "vigil assess code-dispatch retry-error 42 'transient parser crash, retrying'",
            },
        ),
    ),
    "code-sourcemap-extract": CommandContract(
        name="code-sourcemap-extract",
        goals=("code-analysis",),
        phase=("code-ingest",),
        summary=(
            "Extract embedded source-map sources into a traversal-safe immutable tree, "
            "then print the explicit code-ingest handoff."
        ),
        schema_name="hash-namespaced source-map manifest (local artifact)",
        preferred_invocations=(
            "vigil assess code-sourcemap-extract <map-root>",
            "vigil assess code-sourcemap-extract <map-root> --refresh",
            "vigil assess code-sourcemap-extract <map-root> --output-root <snapshot-parent>",
        ),
        author_supplied_fields=(
            "map_root containing .js.map/.css.map files",
            "--refresh only when changed map inputs should create a new immutable snapshot",
        ),
        notes=(
            "The command never calls the backend. It writes sourcesContent plus a manifest and prints a separate `code-ingest` command; that existing refresh stage/commit remains the only publication path.",
            "Extracted files are source equivalents. Ingest the extracted tree, not the mapped minified bundle, so coverage does not count both representations.",
            "Traversal, absolute, URL, and symlink escapes are rejected and recorded. Malformed maps and missing sourcesContent stay visible in the manifest rather than silently disappearing.",
            "An unchanged rerun reuses the same content-addressed snapshot. Changed input requires --refresh and creates a new directory without overwriting the prior snapshot.",
        ),
        common_mistakes=(
            ("expecting automatic ingest", "run the manifest's printed `code-ingest` command explicitly after reviewing extraction health"),
            ("ingesting bundle and extracted tree", "treat extracted sources as the covering representation; mapped minified artifacts remain non-covering"),
        ),
    ),
    "code-ingest": CommandContract(
        name="code-ingest",
        goals=("code-analysis",),
        phase=("code-ingest",),
        summary="Walk a source repository, fingerprint analyzable files, and register them with the code-analysis backend.",
        schema_name="backend code/repos + code/files ingest (no JSON author-file)",
        preferred_invocations=(
            "vigil assess code-ingest <repo-path> --dry-run",
            "vigil assess code-ingest <repo-path>",
            "vigil assess code-ingest <repo-path> --name <repo-name> --repo-key <repo-key>",
            "vigil assess code-ingest <repo-path> --include-path '**/ResetPassword.min.js'",
        ),
        author_supplied_fields=(
            "repo_path (positional, required)",
            "--name / --repo-key when the derived defaults need overriding",
        ),
        helper_defaults=(
            ("--name", "repository directory basename"),
            ("--repo-key", "stable name+realpath hash"),
            ("--language", "unset (does NOT auto-tag unknown files)"),
            ("--default-language-for-unknown", "unset (unknown-extension files stay language-less)"),
            ("--max-included-skipped-bytes", "2000000"),
            ("--skipped-manifest", "tools/analysis-state/skipped-artifacts/<repo-key>.json"),
        ),
        notes=(
            "First code step: run before code-index / code-index-sync. It stages a complete source manifest and atomically promotes it, returning a repo_id that is also written into scope.json source_repos. Interrupted batches never replace the active tree; changed files invalidate their old analysis and removed files leave coverage in the same commit.",
            "Use --dry-run to report added, changed, renamed, and removed paths against the active backend generation without staging or committing.",
            "Generated/binary/minified files and skip-dirs (node_modules, vendor, dist, ...) are excluded and accounted in the skipped-artifacts manifest. --include-minified, --include-skipped, and --include-path <glob> (repeatable) opt specific artifacts back in, capped by --max-included-skipped-bytes.",
            "--language sets only the repo's primary language; use --default-language-for-unknown to stamp a language on unrecognized-extension files (use sparingly — a wrong stamp pollutes coverage math and structural indexing).",
        ),
        common_mistakes=(
            ("--language to tag unknown files", "--language sets the repo primary language only; use --default-language-for-unknown to stamp unrecognized-extension files"),
        ),
    ),
    "code-index build": CommandContract(
        name="code-index build",
        goals=("code-analysis",),
        phase=("code-ingest",),
        summary="Build the structural index under the engagement analysis-state directory.",
        schema_name="structural-index aggregate manifest, per-repo manifest, and per-file index JSON",
        preferred_invocations=(
            "vigil assess code-index build <repo-path> --repo-key <repo-key>",
            "vigil assess code-index build <repo-path> --output-dir <engagement-dir>/tools/analysis-state",
            "vigil assess code-index sync --repo-key <repo-key>",
        ),
        author_supplied_fields=(
            "repo_path",
            "repo_key when available",
            "--output-dir only for intentional non-engagement output",
        ),
        helper_defaults=(
            ("output_dir", "<engagement_dir>/tools/analysis-state"),
            ("aggregate manifest", "structural-index-manifest.json"),
            ("per-repo manifest", "structural-index/<repo_key>-manifest.json"),
            ("per-file indexes", "structural-index/<repo_key>/<sha16>.json"),
        ),
        notes=(
            "The aggregate manifest is keyed by repo_key, so multiple source repos share one engagement analysis-state tree without relative-path collisions.",
            "The default output directory is the one code-index sync consumes, so indexing and sync stay in one engagement-owned tree.",
            "Run inside the launched engagement session or pass --engagement-dir when outside its tree; the helper fails closed rather than write an unsynced .code-index tree into the source repo.",
        ),
        common_mistakes=(
            ("running outside engagement context", "pass --engagement-dir or --output-dir explicitly"),
            ("sync cannot find manifest", "use the default tools/analysis-state output or pass the same explicit output path consistently"),
            ("legacy manifest with multiple repos", "pass --repo-id or rebuild the index so repo_key metadata is available"),
        ),
    ),
    "code-index sync": CommandContract(
        name="code-index sync",
        goals=("code-analysis",),
        phase=("code-ingest",),
        summary="Push structural-index metadata (function/entry-point/sink/export counts) from the analysis-state manifest to the backend.",
        schema_name="code/files bulk-structural-metadata (reads structural-index manifest + per-file index JSON)",
        preferred_invocations=(
            "vigil assess code-index sync",
            "vigil assess code-index sync --repo-key <repo-key>",
            "vigil assess code-index sync --repo-id <repo-id>",
        ),
        author_supplied_fields=(
            "--repo-key or --repo-id only to restrict sync to one repo",
            "--manifest / --index-dir only for non-default analysis-state locations",
        ),
        helper_defaults=(
            ("--manifest", "<engagement_dir>/tools/analysis-state/structural-index-manifest.json"),
            ("--index-dir", "<manifest-dir>/structural-index/"),
            ("--repo-id", "unset (sync every repo in the manifest)"),
            ("--repo-key", "unset (sync every repo in the manifest)"),
        ),
        notes=(
            "Run after code-index has built the structural index into the default analysis-state tree; this consumes that manifest, so both must share the same output directory (the code-index default).",
            "The aggregate manifest is keyed by repo_key, so multiple source repos sync from one engagement tree. Use --repo-key (or --repo-id) to re-sync just one repo.",
            "A legacy single-repo manifest with no repo identity requires --repo-id when the engagement has more than one backend repo; otherwise rebuild the index with current code-index so repo_key metadata is recorded.",
        ),
        common_mistakes=(
            ("manifest not found", "run code-index first, or point --manifest at the same output dir code-index wrote"),
            ("--repo-id against an aggregate manifest with no matching identity", "pass --repo-key, or rebuild the index so repo_key/repo_path metadata matches the backend repo"),
        ),
    ),
    "code-record classify": CommandContract(
        name="code-record classify",
        goals=("code-analysis",),
        phase=("code-classify",),
        summary="Bulk-classify code files and persist architect-assigned analysis priority.",
        schema_name="code-file-classification.schema.json",
        preferred_invocations=(
            "vigil assess contract code-record classify",
            "vigil assess code-record classify <classifications-json-file>",
        ),
        author_supplied_fields=(
            "file_id or file_path",
            "classification",
            "role",
            "slot_types",
            "analysis_priority",
        ),
        helper_defaults=(
            ("file_path", "resolved client-side to file_id before posting"),
            ("repo_id", "optional disambiguator for duplicate file_path values"),
        ),
        notes=(
            "analysis_priority sets classification ordering. The code-dispatch queue has a separate `priority` field; map analysis_priority to priority only when queueing hunt work.",
            "Classification tiers: critical/high/medium/low/skip. analysis_priority is a 0-100 score that orders files inside a tier.",
            "Read `vigil assess contract code-record classify` before authoring the file.",
        ),
        common_mistakes=(
            ("priority", "use analysis_priority in code-record classify payloads"),
            ("slot_types_json", "use slot_types"),
            ("repo_id without file_path", "repo_id only disambiguates file_path lookup; file_id can stand alone"),
        ),
        examples=(
            {
                "file_id": 42,
                "classification": "critical",
                "role": "parser",
                "slot_types": ["NETWORK-INPUT"],
                "analysis_priority": 95,
            },
        ),
    ),
    "code-record modules": CommandContract(
        name="code-record modules",
        goals=("code-analysis",),
        phase=("code-ingest", "code-classify"),
        summary="Record repository module boundaries from the architecture mapping pass.",
        schema_name="backend CodeModuleRecord list",
        preferred_invocations=(
            "vigil assess contract code-record modules",
            "vigil assess code-record modules <repo-id> <modules-json-file>",
        ),
        author_supplied_fields=(
            "repo_id",
            "module_key or name",
            "name",
            "description",
            "trust_boundary",
            "files",
            "file_ids",
        ),
        helper_defaults=(
            ("module_key", "derived from name when omitted; collisions are rejected"),
        ),
        notes=(
            "This contract is the module-map shape source for code-architect output. Name this helper in prompts rather than embedding a module JSON template.",
            "Provide explicit module_key values when names normalize to the same slug.",
        ),
        common_mistakes=(
            ("module map only in artifacts", "persist durable module boundaries with code-record modules"),
            ("duplicate auto-derived module_key", "provide explicit module_key values"),
        ),
    ),
    "code-record threat-model": CommandContract(
        name="code-record threat-model",
        goals=("code-analysis",),
        phase=("code-ingest", "code-classify"),
        summary="Record the repository threat model produced by code-architect.",
        schema_name="backend threat_model object",
        preferred_invocations=(
            "vigil assess contract code-record threat-model",
            "vigil assess code-record threat-model <repo-id> <threat-model-json-file>",
        ),
        author_supplied_fields=(
            "repo_id",
            "threat_model object",
        ),
        notes=(
            "This contract is the threat-model shape source for code-architect output. The backend stores the object as durable analysis context for later dispatches.",
            "Keep implementation detail in the artifact; persist durable attacker surfaces, trust boundaries, sensitive operations, and missing context through this helper.",
        ),
        common_mistakes=(
            ("threat model only in markdown", "persist durable threat-model context with code-record threat-model"),
        ),
    ),
    "code-record analysis": CommandContract(
        name="code-record analysis",
        goals=("code-analysis",),
        phase=("code-hunt", "code-verify"),
        summary="Record a code-vuln-hunter result against the claimed queue item that produced it.",
        schema_name="code-analysis-result.schema.json",
        preferred_invocations=(
            "vigil assess contract code-record analysis",
            "vigil assess code-record analysis <analysis-results-json-file>",
        ),
        author_supplied_fields=(
            "queue_item_id",
            "agent_name",
            "lease_token",
            "function_name",
            "hypothesis",
            "evidence and/or evidence_ref for finding/suspicious dispositions",
            "disposition",
            "confidence",
            "finding_slug when disposition=finding",
            "cwe_coverage",
            "cross_file_triggers",
        ),
        helper_defaults=(
            ("file_id", "derived by the backend from queue_item_id; optional client-side consistency check only"),
            ("confidence", "medium"),
            ("audit_metadata", "{}"),
            ("cwe_coverage", "[]"),
            ("cross_file_triggers", "[]"),
        ),
        notes=(
            "Record analysis results only for queue items fetched by code-dispatch. queue_item_id, agent_name, and lease_token are required; reclaimed leases reject stale writes.",
            "The backend copies the claimed repository generation onto the result and makes exact retries idempotent within that lease. Refresh or requeue supersedes old-generation results so projections use current nonsuperseded rows.",
            "For finding and suspicious dispositions, include concrete inline evidence or an engagement-owned evidence_ref before closeout; the backend verifies that evidence on the active lease.",
            "When file_id is supplied, the backend treats it as a consistency check and rejects it if it differs from the queue item's file.",
            "For a confirmed finding, run finding record first, then put that slug in finding_slug.",
        ),
        common_mistakes=(
            ("file_id-only result", "include queue_item_id; file_id is optional and queue-derived"),
            ("artifact path only in notes", "put an engagement-owned path in evidence_ref so evidence-aware closeout can verify it"),
            ("confidence in finding record", "confidence belongs in code-record analysis, not finding record"),
            ("cross_file_triggers object wrapper", "cross_file_triggers is a bare array on the analysis result"),
        ),
        examples=(
            {
                "queue_item_id": 42,
                "agent_name": "code-vuln-hunter",
                "lease_token": "<fetched-lease-token>",
                "function_name": "parse_message",
                "hypothesis": "Attacker-controlled bytes reach length-sensitive copy code",
                "evidence": "parse_message() bounds checks len before memcpy; no bypass found",
                "disposition": "clean",
                "confidence": "high",
                "cwe_coverage": [
                    {"family": "buffer-overflow", "effort": 85, "notes": "All parser entry chains traced"}
                ],
                "cross_file_triggers": [],
            },
        ),
    ),
    "code-coverage": CommandContract(
        name="code-coverage",
        goals=("code-analysis",),
        phase=("code-hunt", "code-verify"),
        summary="Display code-analysis coverage, per-file CWE effort, and the coverage-gate verdict.",
        schema_name="backend code/coverage projection (read-only)",
        preferred_invocations=(
            "vigil assess code-coverage",
            "vigil assess code-coverage --cwe-matrix",
            "vigil assess code-coverage --require-gate-pass",
            "vigil assess code-coverage --repo-id <repo-id> --cwe-matrix --require-gate-pass",
        ),
        author_supplied_fields=(
            "--repo-id to scope one repo",
            "--cwe-matrix / --require-gate-pass flags as needed",
        ),
        helper_defaults=(
            ("--repo-id", "unset (aggregate across all repos)"),
            ("--cwe-matrix", "off (summary view; on shows the per-file CWE effort matrix)"),
            ("--require-gate-pass", "off (informational; on exits non-zero unless the gate passes)"),
        ),
        notes=(
            "The code Core-Loop coverage check — read it each iteration to see which files and vuln classes are under-tested before dispatching more hunt work.",
            "--cwe-matrix renders the per-file CWE effort table with a structural-verification cross-check (functions_analyzed vs the structural index) and flags critical/high files below their effort threshold.",
            "--require-gate-pass makes the command a gate: it exits non-zero when the backend coverage gate has not passed (or, under --cwe-matrix, when a critical file has an effort gap), so it can front a phase transition.",
        ),
    ),
    "code-size-summary": CommandContract(
        name="code-size-summary",
        goals=("code-analysis",),
        phase=("code-ingest", "code-classify"),
        summary="Summarize backend-indexed code_files: counts, LOC buckets, ownership splits, and large-file candidates.",
        schema_name="backend code/files projection (read-only aggregate)",
        preferred_invocations=(
            "vigil assess code-size-summary",
            "vigil assess code-size-summary --repo-id <repo-id>",
            "vigil assess code-size-summary --large-threshold 1500 --top 30",
            "vigil assess code-size-summary --json",
        ),
        author_supplied_fields=(
            "--repo-id to scope one repo",
            "--large-threshold / --top / --json as needed",
        ),
        helper_defaults=(
            ("--repo-id", "unset (aggregate across all repos)"),
            ("--large-threshold", "1000 (minimum LOC for critical/high large-file candidates)"),
            ("--top", "20 (maximum large candidates printed)"),
            ("--json", "off (text summary; on emits the structured summary object)"),
        ),
        notes=(
            "Sizing view for the ingest/classify pass: shows LOC buckets, language and analysis-status splits, and app-owned vs generated vs vendor ownership so classification effort lands on app-owned surface, not vendored/generated bulk.",
            "large_candidates lists only critical/high-classified files at or above --large-threshold LOC — the oversized attack surface worth splitting into focused hunt dispatches.",
        ),
    ),
    # --- Discovery / navigation / read-query utilities (phase-agnostic) ---
    # These orient a specialist across the CLI surface and are usable in ANY
    # phase, so they carry no `phase` tag and group under "phase-agnostic" in
    # `vigil assess list-commands`. They are first-class catalog rows so the
    # catalog is a COMPLETE index of what a specialist reaches for — not only
    # the write/probe verbs. `vigil assess contract <name>` resolves each via
    # `get_contract` -> `_CONTRACTS.get(name)` with no extra wiring.
    "list-commands": CommandContract(
        name="list-commands",
        goals=("discovery",),
        summary="Per-phase catalog of helper-owned assess commands (this command); each row points at `vigil assess contract <verb>`.",
        schema_name="assess.lib.contracts registry (CommandContract + kali verb table)",
        preferred_invocations=(
            "vigil assess list-commands",
            "vigil assess list-commands --phase consume-test",
            "vigil assess list-commands --goal submission",
            "vigil assess list-commands --kali-only --grep sqlmap",
            "vigil assess list-commands --json",
        ),
        author_supplied_fields=(),
        helper_defaults=(
            ("--phase", "unset (show every phase group plus the phase-agnostic utilities)"),
            ("--goal", "unset (show all; set to filter to a task goal — AND-composes with --phase)"),
        ),
        notes=(
            "Discovery command — the commands analogue of `list-skills` / `list-references`. Sourced from the contract registry, so a new command with a `phase` tag is picked up automatically (never hand-maintained).",
            "`--phase <N>` accepts the canonical kali_audit.ALLOWED_PHASES vocabulary; the `consume` short alias resolves to `consume-test`.",
            "`--goal <g>` filters by task goal (submission, scope, recon, discovery, dns, http-probe, artifact, finding-lifecycle, dispatch, code-analysis, oob); it AND-composes with `--phase` and surfaces in each row and in `contract <verb>`. Use it to answer 'which command produces the final submission?' (`--goal submission`).",
            "`--kali-only` restricts to `kali <verb>` wrappers; `--grep <s>` substring-filters name/summary; `--json` emits the structured rows (the downstream contract).",
            "Phase-agnostic utilities (empty phase tuple) group separately at the bottom and are omitted from a `--phase` filter.",
        ),
    ),
    "list-skills": CommandContract(
        name="list-skills",
        goals=("discovery",),
        summary="List available skills with compact descriptions.",
        schema_name="agent/skills/*/SKILL.md frontmatter",
        preferred_invocations=(
            "vigil assess list-skills",
            "vigil assess list-skills --json",
        ),
        author_supplied_fields=(),
        notes=(
            "Discovery command — the skills analogue of `list-commands` / `list-references`. Name a skill from here in a dispatch's `skills` list.",
            "--skills-dir overrides the default agent/skills lookup for non-standard checkouts.",
        ),
    ),
    "list-references": CommandContract(
        name="list-references",
        goals=("discovery",),
        summary="List available reference docs with compact descriptions.",
        schema_name="agent/references/**/*.md frontmatter",
        preferred_invocations=(
            "vigil assess list-references",
            "vigil assess list-references --skill kali-exec",
            "vigil assess list-references --category recon --grep subdomain",
            "vigil assess list-references --json",
        ),
        author_supplied_fields=(),
        notes=(
            "Discovery command. Filter by `--skill <name>` (references whose `skill:` frontmatter includes it), `--category <label>`, or `--grep <s>`.",
        ),
    ),
    "list-mindsets": CommandContract(
        name="list-mindsets",
        goals=("discovery", "dispatch"),
        summary="List the Dispatch-Mindset lens packets (agent/rules/mindsets/) with compact descriptions.",
        schema_name="agent/rules/mindsets/*.md (H1 + preamble; no frontmatter by design)",
        preferred_invocations=(
            "vigil assess list-mindsets",
            "vigil assess list-mindsets --sections",
            "vigil assess list-mindsets --grep access-control",
            "vigil assess list-mindsets --json",
        ),
        author_supplied_fields=(),
        notes=(
            "Discovery command — the mindsets analogue of `list-skills` / `list-references` / `list-commands`. The lens library was the last discovery axis enumerated by hand in per-doc menus; this command discovers it from disk so a new packet is picked up on the next run.",
            "Name exactly ONE packet per dispatch in the `mindset lens:` row — a menu handed to a specialist defeats the point of the lens.",
            "Mindset packets carry NO YAML frontmatter on purpose (they are prose the specialist reads top-to-bottom, and a metadata block would head its context window). `title` is the H1 and `description` is derived from the file's own preamble.",
            "`--sections` expands each packet into its `##` headings — the detail needed to choose a lens without opening the file; `--grep <s>` filters on name/title/description/headings; `--json` emits the structured rows.",
        ),
    ),
    "contract": CommandContract(
        name="contract",
        goals=("discovery",),
        summary="Show schema, defaults, and examples for a helper-owned CLI contract.",
        schema_name="assess.lib.contracts.render_contract",
        preferred_invocations=(
            "vigil assess contract finding record",
            "vigil assess contract kali sqlmap",
            "vigil assess contract intel record tech-component",
        ),
        author_supplied_fields=(
            "name (a contract name from `vigil assess list-commands` / contract_names)",
            "variant (optional, e.g. the intel type for `intel record <type>` or the verb for `kali <verb>`)",
        ),
        notes=(
            "The detail half of the discovery pair: `list-commands` finds the command, `contract` shows its full schema (preferred invocations, helper defaults, author-supplied fields, common mistakes, JSON examples).",
            "Generated from the same source as the CLI's argparse, so it never drifts from the real command.",
        ),
    ),
    "export submission": CommandContract(
        name="export submission",
        goals=("submission",),
        phase=("report",),
        summary="Render one finding into a platform-shaped submission.md (+ context JSON); --draft diagnoses gaps, final mode fails closed on durable proof, lifecycle, readiness, and hygiene.",
        schema_name="backend finding + report-readiness + artifact-index projections, rendered by finding_render.py",
        preferred_invocations=(
            "vigil assess export submission <slug> --platform direct --draft",
            "vigil assess export submission <slug> --platform bugcrowd --vrt-category <c>",
            "vigil assess export submission <slug> --platform hackerone --weakness <w>",
            "vigil assess export submission <slug> --platform direct --json",
        ),
        author_supplied_fields=(
            "slug (finding slug to render, e.g. VA-047)",
            "--platform bugcrowd|hackerone|direct (required)",
            "--vrt-category <c> (Bugcrowd; else read from details.vrt_category)",
            "--weakness <w> (HackerOne; else details.weakness, then details.cwe_id)",
        ),
        helper_defaults=(
            ("--draft", "unset (strict final mode; --draft always writes with diagnostics and [NEEDS: ...] markers)"),
            ("--output", "$ENGAGEMENT_DIR/submissions/<slug>/"),
        ),
        notes=(
            "The submission-first replacement for the retired red/code report.md path. Final requires a verified confirmed/downgraded report candidate; authored Summary, Steps to Reproduce, Evidence, Impact, and Remediation; complete platform fields; a contained evidence_ref artifact linked to that finding, indexed, and present on disk now; and no target-specific report-readiness blocker or hygiene warning. Inline PoC remains supporting content, not durable proof.",
            "Command evidence comes ONLY from explicit finding-links (target_kind=command_run) plus evidence_ref/poc_* — no fuzzy command search. Run a targeted `command-run list --q <url/param>` to find and link the reproducing command first.",
            "Final output must stay inside the engagement and artifact registration must succeed. The export never sets submission_status. Draft mode surfaces internal UUID / absolute-path / cases.db hygiene diagnostics; final mode blocks until clean.",
        ),
    ),
    "scope explain": CommandContract(
        name="scope explain",
        goals=("scope",),
        summary="Explain the scope verdict for one or more URLs/hosts: admitted/denied, the matching allow/deny entry, required headers, rate limit, vendor-SaaS warning (read-only, no network).",
        schema_name="assess.lib.scope (scope.json allow/deny entries)",
        preferred_invocations=(
            "vigil assess scope explain https://api.example.com",
            "vigil assess scope explain 10.0.0.5 example.com --json",
            "vigil assess scope explain --input-file hosts.txt --json",
        ),
        author_supplied_fields=(
            "targets (zero or more URLs/hosts to explain)",
            "--input-file <path> (read additional URLs/hosts one per line; '-' for stdin)",
        ),
        notes=(
            "Read-only scope oracle — pure composition over the scope primitives, no writes and no backend/network call. Every verdict names the exact allow/deny entry that drove the decision (denylist wins).",
            "--json emits the verdict structs; the text view emits a vendor-SaaS WARN to stderr when a host matches a known SaaS-fronted suffix.",
        ),
    ),
    "check-phase-readiness": CommandContract(
        name="check-phase-readiness",
        summary="Phase-aware readiness gate: per-phase coverage/scope/depth/exploit/intel checks before a phase transition (read-only).",
        schema_name="backend readiness aggregates (coverage/scope/depth/exploit/intel)",
        preferred_invocations=(
            "vigil assess check-phase-readiness --phase consume-test",
            "vigil assess check-phase-readiness --phase report",
            "vigil assess check-phase-readiness --phase consume-test --depth --by-host",
        ),
        author_supplied_fields=(
            "--phase (required; accepts the persisted `consume-test` and its `consume` short alias)",
        ),
        notes=(
            "Consolidates the former check-coverage / check-scope-coverage / check-report-readiness / check-exploit-gate / check-intel-readiness commands into one phase-aware gate. Pair with `transition-phase` as the phase-boundary checkpoint.",
            "Read-only: it reports blockers, it does not move the engagement. `--depth` / `--by-host` / `--by-app-unit` expand the ledger; `--auto-redispatch` suggests follow-up coverage dispatches.",
        ),
    ),
    "transition-phase": CommandContract(
        name="transition-phase",
        summary="Guarded phase transition for scope.json (checks blockers, then advances current_phase).",
        schema_name="scope.json current_phase (guarded write)",
        preferred_invocations=(
            "vigil assess transition-phase consume-test",
            "vigil assess transition-phase report --reason 'coverage + verification complete'",
            "vigil assess transition-phase exploit --force --reason '...'",
        ),
        author_supplied_fields=(
            "target_phase (positional)",
            "--reason (recommended; recorded with the transition)",
        ),
        notes=(
            "The write counterpart to `check-phase-readiness`: run the readiness check first, then transition. `--force` proceeds past blockers with warnings.",
            "`--track {auto|web|code|blue}` selects the phase track for `both` engagements (default: infer from the target phase).",
        ),
        common_mistakes=(
            ("transitioning past blockers silently", "run check-phase-readiness first; use --force only with an explicit --reason"),
        ),
    ),
    "coverage": CommandContract(
        name="coverage",
        summary="Coverage ledger (read-only). Default: per-host route/real_app/verdict state. --by-family: per application-unit × attack-family GAP grid. --for-dispatch --host <h>: a paste-ready COVERAGE block for a dispatch prompt. --attempts: the recorded probe-attempt ledger.",
        schema_name="backend per-host coverage projection (+ coverage-readiness/by-family for --by-family/--for-dispatch; GET /assessment/attempts for --attempts)",
        preferred_invocations=(
            "vigil assess coverage",
            "vigil assess coverage --route-threshold 6",
            "vigil assess coverage --by-family",
            "vigil assess coverage --for-dispatch --host app.example.com --path-prefix /api",
            "vigil assess coverage --attempts --host app.example.com",
            "vigil assess coverage --attempts --attack-family idor --result-status no-signal",
            "vigil assess coverage --json",
        ),
        author_supplied_fields=(),
        helper_defaults=(
            ("--route-threshold", "6 (distinct LIVE url_path count at/above which a host counts as a real_app on routes alone; default per-host view only)"),
        ),
        notes=(
            "Read-only orientation for where coverage stands per host. `--json` is the machine form for dispatch planning.",
            "--by-family renders the per application-unit × attack-family grid from `coverage-readiness/by-family`: GAP cells (missing_block/missing_warn or zero covering probes) are marked, covered cells show the verdict + covering/total probe counts, and finding-linked cells are flagged (e.g. finding#45). --json passes the raw by-family payload through.",
            "--for-dispatch --host <h> [--path-prefix <p>] reuses the SAME by-family grid (no extra backend call), filters CLIENT-SIDE to that application-unit, and emits a paste-ready COVERAGE: block listing covered vs OPEN-gap families — hand it to a specialist alongside an open objective instead of a prescriptive technique cage (which `agent start` now WARN-lints).",
            "--attempts reads the recorded probe-attempt ledger (the read side of record-probe), grouped by lens × result_status with per-row finding linkage. Filters: --finding <slug> / --surface <id> / --host / --attack-family / --result-status / --lens, plus --limit / --offset. Use it before dispatching more probing to dedup against what a lens/family already tried on a host.",
            "Scoping vocabulary: on the default/grid views, --host / --path-prefix select application-UNITS (grid rows). Under --attempts, --surface is a surface-ID and --host is the target-host filter — keep the two straight.",
        ),
    ),
    "finding list": CommandContract(
        name="finding list",
        goals=("finding-lifecycle",),
        summary="List findings with common CLI-side filters (severity, workflow/verification state, root-cause group, free-text search).",
        schema_name="GET /assessment/findings",
        preferred_invocations=(
            "vigil assess finding list",
            "vigil assess finding list --workflow-status active --severity high",
            "vigil assess finding list --root-cause VA-047",
            "vigil assess finding list --search 'sql injection' --json",
        ),
        author_supplied_fields=(),
        notes=(
            "Read-only. Filters: --severity, --workflow-status/--status, --verification-state, --verification-disposition, --source-name, --slug, --root-cause <slug> (root plus linked siblings), --search.",
            "--limit / --offset / --all page the result set; --json is the machine form.",
        ),
    ),
    "intel list": CommandContract(
        name="intel list",
        goals=("recon",),
        summary="List intel records per-type or via full-text search.",
        schema_name="GET /assessment/intel (+ /intel/search)",
        preferred_invocations=(
            "vigil assess intel list",
            "vigil assess intel list tech-component",
            "vigil assess intel list --q nginx --json",
        ),
        author_supplied_fields=(),
        notes=(
            "Read-only. Pass an intel type positionally to list that type, or --q for an FTS query across types. --limit caps search rows.",
        ),
    ),
    "command-run list": CommandContract(
        name="command-run list",
        summary="Search the `vigil assess kali` command-run audit ledger for this engagement.",
        schema_name="GET /assessment/command-runs",
        preferred_invocations=(
            "vigil assess command-run list",
            "vigil assess command-run list --q sqlmap --show-matches",
            "vigil assess command-run list --target-host api.example.com --technique SSRF",
        ),
        author_supplied_fields=(),
        notes=(
            "Read-only audit search. `--q` is a fuzzy keyword search over command/tool/previews/metadata/finding-aliases; `--sort {relevance|recent|distant}` (distant surfaces coverage-gap candidates); filters include --agent-name / --phase / --tool-name / --tool-bin / --target-host / --technique / --route.",
            "Drill into a single row with `vigil assess command-run get <id>`.",
        ),
    ),
    "command-run get": CommandContract(
        name="command-run get",
        summary="Fetch a single kali command-run record by id, including previews and artifact refs.",
        schema_name="GET /assessment/command-runs/{id}",
        preferred_invocations=(
            "vigil assess command-run get <id>",
        ),
        author_supplied_fields=(
            "command_run_id (positional int, from command-run list)",
        ),
        notes=(
            "Read-only drill-down for `command-run list` / `resume-brief`. Always emits JSON (the `--json` flag is a no-op accepted for symmetry).",
        ),
    ),
}


_RAW_ENDPOINT_RULES = (
    (
        "POST",
        re.compile(r"^findings$"),
        "finding record",
        (
            "Raw POST to findings is disabled because finding record owns slug allocation and lifecycle defaults.",
        ),
    ),
    (
        "POST",
        re.compile(r"^findings/[^/]+/verify$"),
        "finding verify",
        (
            "Raw POST to findings/{slug}/verify is disabled because finding verify owns the verification lifecycle.",
            "For a false_positive, use finding verify --disposition false_positive --kill-reason ... --kill-check N.",
        ),
    ),
    (
        "PATCH",
        re.compile(r"^findings/[^/]+$"),
        "finding update",
        (
            "Raw PATCH to findings/{slug} is disabled because finding update owns finding patch operations.",
        ),
    ),
    (
        "POST",
        re.compile(r"^probe-runs$"),
        "record-probe",
        (
            "Raw POST to probe-runs is disabled because record-probe owns the flag set, the evidence discipline, and the default FK-derived cascade.",
            "Covering probe (tested|signal) → record-probe --result-status tested|signal (requires --evidence-ref).",
            "Non-covering probe (attempted|blocked|no-signal|error) → record-probe --result-status attempted|blocked|no-signal|error.",
        ),
    ),
    (
        "PATCH",
        re.compile(r"^coverage-items/[^/]+$"),
        "resolve",
        (
            "Raw PATCH to coverage-items/{id} is disabled because `resolve coverage-item` owns the status vocabulary and the rationale-on-covered rule.",
        ),
    ),
)


# Grouped namespacing: verbs re-shelved under a subcommand parent so the
# top-level count drops without changing behavior. Each parent renders as ONE
# catalog row (mirroring `kali`); the per-action contracts live in `_CONTRACTS`
# under their two-token keys (`finding record`, `intel supersede`, …) and stay
# fully resolvable via `contract <parent> <action>`.
_NAMESPACE_PARENTS: tuple[str, ...] = ("finding", "intel", "export", "command-run")


# Per-parent root-row metadata (summary + representative invocations + the action
# menu). Phase/goal tags are NOT hardcoded here — they are derived as the union of
# the child contracts' tags so the root can never drift from its actions.
_NAMESPACE_ROOT_META: dict[str, dict[str, Any]] = {
    "finding": {
        "summary": "Finding lifecycle group: record, update, verify, merge, link, list, and the grouped report projection.",
        "actions": "record | update | verify | merge | link | list | report",
        "invocations": (
            "vigil assess finding record <agent-name> <finding-json-file>",
            "vigil assess finding verify <slug> --disposition confirmed --reason \"...\"",
            "vigil assess finding update <slug> --status reported --reason \"...\"",
            "vigil assess finding link <sibling-slug> --root-cause <root-slug>",
            "vigil assess finding list --severity high --status active",
            "vigil assess finding report --mode final --json",
            "vigil assess contract finding <action>",
        ),
    },
    "intel": {
        "summary": "Intel group: record, update, list, and supersede structured intel rows.",
        "actions": "record | update | list | supersede",
        "invocations": (
            "vigil assess intel record <type> <intel-json-file>",
            "vigil assess intel list [<type>] [--q <query>]",
            "vigil assess intel update <type> <id> --inline '{...}'",
            "vigil assess intel supersede <type> <id> <new-json-file> --rationale \"...\"",
            "vigil assess contract intel <action>",
        ),
    },
    "export": {
        "summary": "Export group: render findings.md, a platform-shaped submission, a program reply, or surfaces.jsonl from backend state.",
        "actions": "findings | submission | reply | surfaces",
        "invocations": (
            "vigil assess export findings",
            "vigil assess export submission <slug> --platform bugcrowd",
            "vigil assess export reply <slug> --in-response-to \"...\" --draft",
            "vigil assess export surfaces",
            "vigil assess contract export <kind>",
        ),
    },
    "command-run": {
        "summary": "Command-run group: list `vigil assess kali` audit records or fetch a single run by id.",
        "actions": "list | get",
        "invocations": (
            "vigil assess command-run list [--q <query>] [--technique <enum>]",
            "vigil assess command-run get <id> [--live]",
            "vigil assess contract command-run <action>",
        ),
    },
}


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
    assess list-commands`` groups by phase. The 27 per-verb ``kali <verb>``
    contracts are deliberately kept OUT of this default catalog so the
    dispatcher renders as ONE row instead of flattening into ~27; they remain
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
    if name.startswith("resolve "):
        # `contract resolve surface` / `contract resolve coverage-item`: the single
        # `resolve` contract documents both target-kinds — accept the two-token form
        # so it mirrors `contract work-buffer <verb>`.
        return _CONTRACTS.get("resolve")
    if name.startswith("auth "):
        # `contract auth list` / `contract auth status`: the single `auth` contract
        # documents both identity subcommands — accept the two-token form so it
        # mirrors `contract resolve <target>` (both list/status resolve to it).
        return _CONTRACTS.get("auth")
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

    schema_properties = _schema_property_names(contract.schema_name)
    if schema_properties:
        lines.extend(
            [
                "",
                "Allowed top-level fields:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in schema_properties)

    schema_required = _schema_required_names(contract.schema_name)
    if schema_required:
        lines.extend(
            [
                "",
                "Required top-level fields:",
            ]
        )
        lines.extend(f"  - {entry}" for entry in schema_required)

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
                '  - vigil assess finding verify <slug> --disposition false_positive '
                '--reason "..." --kill-reason "..." --kill-check 2'
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


def _schema_property_names(schema_name: str) -> list[str]:
    if not schema_name.endswith(".schema.json"):
        return []
    schema = load_schema(schema_name)
    properties = schema.get("properties", {})
    if not isinstance(properties, dict):
        return []
    return sorted(str(name) for name in properties)


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
        "Deep + scope-safe + disk-bounded by DEFAULT: `-d 5`, `-fs fqdn` (crawl only the exact seeded "
        "hosts — never wander to out-of-scope sibling subdomains found in links), `-or -ob` (omit "
        "body/raw so a deep crawl does not fill the disk), `-ef <static set>`, and JS endpoint crawling "
        "+ jsluice extraction. Override each with one flag; `--keep-bodies` / `--include-static` undo "
        "the disk/asset defaults for a bounded source pass.",
        "Rate is SAFE by default and decoupled from depth: `-rl 10`, hard-capped at 20 req/s (warn + "
        "clamp above; `--allow-fast-crawl` to exceed) and always clamped DOWN to the program rate "
        "ceiling. Go as deep as you like — politeness comes from the rate cap, not a shallow crawl.",
        "Use `-fs rdn` ONLY when every seed root is itself a wildcard-scoped in-scope entry. Recover "
        "wildcard breadth via subdomain-enum + passive gau, NOT by letting the active crawler roam.",
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
        "Required attribution is installed before navigation and fails closed. --attribution-scope document-origin applies it to admitted document navigations and their same-origin requests so cross-origin SPA preflights are not poisoned; omitted cross-origin attribution origins are recorded.",
        "Use --steps-file for at most 50 typed navigate/click/fill/wait/eval/assert actions. An assert with visible:false waits for the selector to become hidden; text is read only for contains/equals assertions. Every declared navigation is admitted before launch, while dynamic browser navigations are admitted and enrolled by the runtime scope/no-fire request router.",
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
    ),
    "job": (
        "Long-running probes go through `vigil assess kali job start ...`. The dtach session is parented by tini so it survives the calling shell.",
        "Job start uses the same pre-execution preparation as synchronous Kali execution: `--identity` material (plus `--identity-scope` for a scoped alias), required attribution headers, nuclei OOB safety, target scope, denied tools, and rate policy are applied before audit/spawn.",
        "Subcommands: start | status | tail | stop | list.",
    ),
    "sweep-orphans": (
        "Host-side reconciler for `assessment_command_runs` rows stuck in status=running past --max-age-seconds. Run after a backend restart, host crash, or any window where finalize PATCHes may have failed.",
        "Liveness probe: `docker exec <container> kill -0 <pid>` against the wrapper-recorded pid file at /tmp/vigil-pid-<run_uuid>.pid. run_uuid comes from the row's run_uuid column (stdout_path parsing kept only for older rows).",
        "PID alive -> left alone (still-running). PID dead OR pid file missing -> finalized to status=lost via PATCH command-runs/{id}.",
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
    # exec + job are raw/long-running runners usable in any phase.
    "exec": (),
    "job": (),
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
    for optional in ("source_name", "confidence", "evidence_ref", "provenance", "notes"):
        if isinstance(properties, dict) and optional in properties and optional not in author_fields:
            author_fields.append(optional)

    example = _intel_example_payload(intel_type)
    return CommandContract(
        name=f"intel record {intel_type}",
        summary=f"Record one `{intel_type}` intel row via the intel record helper.",
        schema_name=schema_name,
        preferred_invocations=(
            f"vigil assess intel record {intel_type} {intel_type}.json",
        ),
        author_supplied_fields=tuple(author_fields),
        notes=(
            f"Posts to /intel/{endpoint_segment}. Use the helper, not raw post, so local schema validation catches payload drift first.",
            "Intel schemas are strict: a field not listed under Allowed top-level fields is rejected before the backend is contacted.",
        ),
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
    verification_keys = {"verification_state", "verification_disposition"}
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
    "start",
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
            "vigil assess agent start --role <role> --task \"...\" --dispatch-mode <mode> --skills <skills>",
            "vigil assess agent done <agent-id> --finding-slugs <slug1,slug2>",
            "vigil assess agent handoff --agent-id <id> --role <role> --summary '...' --handoff-status ready",
            "vigil assess agent close <agent-id>",
            "vigil assess agent reconcile-stale --dry-run",
            "vigil assess agent list [--filter-role <role>] [--status <status>]",
            "vigil assess agent render-handoff <agent-id>",
            "vigil assess work-buffer <db_path> stats|fetch|done|...",
        ),
        author_supplied_fields=(
            "<action> (e.g. start, done, handoff, render-handoff, decision, ...)",
            "action-specific positional args",
        ),
        notes=(
            "Work-buffer actions live under `vigil assess work-buffer <db_path> ...`; "
            "agent lifecycle actions never take a cases.db path.",
            "Dispatch state lives in the orchestrator backend. `agent start` logs a dispatch, "
            "`agent done` patches lifecycle directly, `agent handoff` writes a repeatable checkpoint, `agent close` consumes a ready/blocked handoff into closure, and `agent render-handoff` assembles the blob the next dispatch prompt pastes verbatim.",
            "`agent start` defaults a missing --dispatch-mode from the role (warn, not block) and accepts a newly-coined mode (advisory warn). "
            "--skills is optional: set it when the applicable skill is already known, otherwise the specialist selects one from the surface and names it in its handoff. Pass --check-overlap to opt into the advisory in-progress-overlap scan.",
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
                "stale local DB syntax",
                "backend dispatch actions use `vigil assess agent handoff ...`; "
                "`vigil assess work-buffer cases.db handoff ...` is rejected so handoffs "
                "cannot land on the wrong state surface",
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
    if verb in {"register", "start"}:
        return CommandContract(
            name="agent start",
            summary=(
                "Register a specialist dispatch in the backend audit ledger so the "
                "row carries role, task, scope, requested model/reasoning, dispatch-mode, and the skills "
                "the agent loaded."
            ),
            schema_name="backend DispatchCreate (POST /dispatches)",
            preferred_invocations=(
                "vigil assess agent start --agent-id <id> --role <role> "
                "--task \"...\" --scope-host <host> --model <name> --reasoning <level> "
                "--dispatch-mode <mode> --skills \"<skill>[,<skill>...]\"",
                "vigil assess agent start --from-json <payload.json>",
            ),
            author_supplied_fields=(
                "--agent-id (unique per dispatch)",
                "--role (specialist role; operator role is reserved for phase coordination)",
                "--dispatch-mode (hypothesis-driven|item-iterating|deep-manual|variant-rotation)",
                "--skills (comma-separated; required for non-operator roles)",
                "--task (one-line objective)",
            ),
            helper_defaults=(
                ("status", "in-progress (set on insert)"),
                ("dispatched_at", "now() when omitted"),
                ("--allow-duplicate", "off — overlapping in-progress dispatches log a warning"),
            ),
            notes=(
                "Specialist dispatches must include `skills`: the backend rejects them otherwise, and the CLI runs the same check locally before sending so typos surface early.",
                "Discover skill names with `vigil assess list-skills` — each value must match a directory under `agent/skills/<name>/`.",
                "Pair with `agent done` when the dispatch finishes; rows left `in-progress` past the dispatch's actual lifetime corrupt dedup checks.",
            ),
            common_mistakes=(
                ("role", "use --role for the agent command; the backend stores agent_role"),
                ("operator role with --skills", "operator dispatches are exempt from the skills requirement; pass --skills only for specialist roles"),
                ("--skills agent/skills/foo/SKILL.md", "pass the bare skill name (e.g. 'gau-triage'); the validator resolves it on disk"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent start --agent-id va-7f3 "
                        "--role vulnerability-analyst --task 'review SSRF candidates' "
                        "--scope-host api.example.com --model claude-opus-4-8 "
                        "--reasoning high --dispatch-mode item-iterating "
                        "--skills 'ssrf-testing,case-dispatching'"
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
                "vigil assess agent handoff --agent-id <id> --role <role> "
                "--summary \"...\" --handoff-status ready --next-step \"...\" --coverage-gap \"<area>: <reason>\"",
                "vigil assess agent handoff --agent-id <id> --handoff-status ready",
            ),
            author_supplied_fields=(
                "--agent-id",
                "--role and --summary (≤2000 chars; required when creating a handoff)",
                "structured payload via --from-json OR repeated --next-step / --coverage-gap / --runtime-issue / --working-artifact / --open-question",
            ),
            helper_defaults=(
                ("upsert", "POST then PATCH on 409 — the operation is idempotent so checkpointing is safe"),
                ("handoff_status", "checkpointed unless --handoff-status is supplied"),
                ("confidence", "omitted when not specified"),
            ),
            notes=(
                "Specialists call this from their closing sequence before exiting; the row is then the canonical 'what was done, what's missing, what's next' record for the dispatch.",
                "For an existing handoff, supplying only --agent-id plus changed fields performs a partial PATCH and preserves the specialist's summary and structured arrays.",
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
                        "vigil assess agent handoff --agent-id va-7f3 "
                        "--role vulnerability-analyst "
                        "--summary 'SSRF candidates triaged; 2 confirmed, 1 deferred for OOB' "
                        "--next-step 'Validate confirmed findings against staging' "
                        "--coverage-gap 'admin-panel: requires auth refresh'"
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
            ),
            author_supplied_fields=(
                "--kind (scope_decision|egress_decision|dispatch_blocked|... — the backend accepts any string but report-writer only renders known kinds)",
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
            ),
            common_mistakes=(
                ("freeform reason in --kind", "kinds are vocabulary; put the prose in --note or --reason"),
                ("missing --surfaced-to-user", "user-facing decisions invisible to audit defeats the purpose; set the flag whenever the operator showed the gate to the human"),
            ),
            examples=(
                {
                    "command": (
                        "vigil assess agent decision --kind scope_decision "
                        "--host api.foo.com --vendor 'Vendor SaaS' --choice pending "
                        "--surfaced-to-user"
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
