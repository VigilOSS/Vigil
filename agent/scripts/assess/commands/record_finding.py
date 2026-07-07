"""vigil assess record-finding — most complex command.

Slug allocate → normalize defaults → schema validate → POST → emit event.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from assess.lib.client import AssessError, AssessmentClient
from assess.lib.config import load_config
from assess.lib.contracts import common_mistake_hints, render_contract
from assess.lib.findings import finding_lock_path, next_finding_id
from assess.lib.locking import file_lock
from assess.lib.schema_validation import collect_validation_errors, load_schema


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "record-finding",
        help="Record a structured finding",
        epilog="See `vigil assess contract record-finding` for the canonical payload shape and examples.",
    )
    p.add_argument("agent_name", help="Agent name (e.g. vulnerability-analyst)")
    p.add_argument("json_file", help="Path to finding JSON file")
    p.add_argument(
        "--allow-unindexed-evidence",
        dest="allow_unindexed_evidence",
        action="store_true",
        help="Silence record-time warnings about an unindexed evidence_ref (prose, URL, or a "
             "non-existent path). Recording always succeeds either way — check-phase-readiness --phase report "
             "is the backstop for missing evidence; a URL is rerouted into details.references "
             "regardless. Use for theoretical/code-inferred findings with no captured file yet.",
    )
    p.add_argument(
        "--update",
        dest="update_slug",
        metavar="SLUG",
        default="",
        help="Intentionally MODIFY the existing finding SLUG instead of recording a net-new one "
             "(I-21 opt-in). A net-new record whose dedup tuple (defect_family + root_cause_key + "
             "auth_context + canonical_location) collides with a reported/active finding under a "
             "different slug is otherwise REFUSED, to avoid silently overwriting it. Pass --update "
             "<slug> only when you mean to change that exact finding; for a distinct sibling on the "
             "same root cause, give it a distinct root_cause_key/defect_family and use link-finding.",
    )
    p.add_argument(
        "--allow-remint",
        "--force",
        dest="allow_remint",
        action="store_true",
        help="D4 override: mint this finding even though it shares an endpoint + technique with a "
             "finding previously KILLED as false_positive. Without this flag such a re-mint is "
             "REFUSED so a disproven finding cannot silently resurrect at a different "
             "canonical_location. Use only for a genuinely NEW finding that merely coincides on "
             "endpoint + technique; if the prior kill was wrong, run `reset-finding <slug>` instead.",
    )
    p.set_defaults(func=run)


_FINDING_SCHEMA = load_schema("finding-record.schema.json")


def _normalize_payload(payload: dict, *, agent_name: str, candidate_slug: str) -> dict:
    normalized = dict(payload)
    normalized["slug"] = candidate_slug
    normalized.setdefault("source_name", agent_name)
    normalized.setdefault("severity", "medium")
    normalized.setdefault("workflow_status", "active")
    normalized.setdefault("verification_state", "unreviewed")
    normalized.setdefault("verification_disposition", "none")
    normalized.setdefault("defect_family", normalized.get("title", candidate_slug))
    normalized.setdefault("root_cause_key", "")
    normalized.setdefault("auth_context", "anonymous")
    normalized.setdefault("canonical_location", "")
    normalized.setdefault("summary", normalized.get("title", candidate_slug))
    normalized.setdefault("evidence_ref", "")
    normalized.setdefault("notes", "")

    details = normalized.get("details") or {}
    if not isinstance(details, dict):
        details = {}
    details.setdefault("discovered_by", agent_name)
    normalized["details"] = details

    provenance = normalized.get("provenance") or {}
    if not isinstance(provenance, dict):
        provenance = {}
    provenance.setdefault("agent_name", agent_name)
    normalized["provenance"] = provenance

    normalized.setdefault("links", [])
    return normalized


def _evidence_file_exists(ref: str, eng_dir: str, engagement_key: str) -> bool:
    """True when evidence_ref resolves to a real file (so the backend will
    auto-register it). Checks the ref as-is, relative to the engagement dir, and
    the container-path form ``/engagements/<key>/...`` mapped back to the host."""
    candidates = [Path(ref)]
    if not Path(ref).is_absolute():
        candidates.append(Path(eng_dir) / ref)
    prefix = f"/engagements/{engagement_key}/"
    if ref.startswith(prefix):
        candidates.append(Path(eng_dir) / ref[len(prefix):])
    return any(c.is_file() for c in candidates)


def _normalize_evidence_ref(payload: dict, *, eng_dir: str, engagement_key: str, allow_unindexed: bool) -> None:
    """Normalize evidence_ref at record time WITHOUT blocking the record.

    Doctrine (master plan §0 / L4-2): recording a real finding mid-hunt must
    always work, even before proof is a registered artifact — check-report-
    readiness is the terminal backstop for missing evidence, not record time.
    So this warns and, for URLs, reroutes — it never exits.

    - existing on-disk file -> accepted as-is (the backend auto-registers it).
    - URL -> rerouted into ``details.references`` and evidence_ref cleared
      (a URL is never an auto-registerable artifact path).
    - prose / non-existent path -> warned; the record still proceeds.
    - empty -> warned; evidence may be attached on a later update.

    ``allow_unindexed`` silences the warnings for intentionally-unindexed
    (theoretical / code-inferred) findings; the URL reroute still happens so
    the URL is never lost.
    """
    ref = (payload.get("evidence_ref") or "").strip()

    if ref.startswith(("http://", "https://")):
        details = payload.get("details")
        if not isinstance(details, dict):
            details = {}
            payload["details"] = details
        refs = details.setdefault("references", [])
        if isinstance(refs, list) and ref not in refs:
            refs.append(ref)
        payload["evidence_ref"] = ""
        if not allow_unindexed:
            print(
                f"record-finding: evidence_ref '{ref}' is a URL, not a registered artifact path "
                "— rerouted into details.references and cleared evidence_ref. Attach a captured "
                "artifact later so report-readiness can index replayable proof.",
                file=sys.stderr,
            )
        return

    if allow_unindexed:
        return

    if not ref:
        print(
            "record-finding: warning — no evidence_ref set; check-phase-readiness --phase report will flag "
            "this finding as missing evidence. Set evidence_ref to a captured artifact path or "
            "pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )
        return

    if _evidence_file_exists(ref, eng_dir, engagement_key):
        return  # existing artifact — the backend registers + links it on record.

    looks_like_path = ("/" in ref or "." in ref) and "  " not in ref
    if looks_like_path:
        print(
            f"record-finding: warning — evidence_ref '{ref}' looks like a path but no file exists "
            "there; recording anyway. check-phase-readiness --phase report will flag it until a real artifact is "
            "attached. Pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )
    else:
        print(
            f"record-finding: warning — evidence_ref '{ref}' is free-text prose, not an artifact "
            "path or URL; recording anyway. Put external links in details.references and attach a "
            "captured artifact for report-readiness. Pass --allow-unindexed-evidence to silence.",
            file=sys.stderr,
        )


# I-21 (clobber guard): the backend dedup UPSERT matches a net-new record onto
# an existing finding by the (defect_family + root_cause_key + auth_context +
# canonical_location) tuple, NOT by slug. Recording a net-new finding that
# collides that tuple with a load-bearing (reported/active) finding under a
# DIFFERENT slug silently overwrote it. This CLI check fails fast with the same
# actionable guidance the backend match enforces (dual enforcement: a CLI bypass
# cannot defeat the authoritative HTTP guard in state_manager/findings.py).
# ``draft`` is fair game for the historical upsert; ``false_positive`` / ``merged``
# stay semantically sticky — both are outside the guard set, matching the backend.
_CLOBBER_GUARDED_STATUSES = frozenset({"active", "reported"})

# Marker phrases the backend embeds in its refusal 409 details. Used to translate
# a backstop refusal (e.g. a title-tier clobber match the CLI tuple-check does not
# model, a race, or the D4 killed-finding re-mint guard which has no CLI mirror)
# into a clean operator message instead of a raw HTTP dump.
_BACKEND_CLOBBER_MARKER = "Refusing to clobber"
_BACKEND_REMINT_MARKER = "Refusing to re-mint"


def _find_clobbered_finding(
    existing_findings,
    *,
    candidate_slug: str,
    defect_family: str,
    root_cause_key: str,
    auth_context: str,
    canonical_location: str,
) -> dict | None:
    """Return an existing finding a net-new record would silently clobber.

    Mirrors the backend dedup tuple. Returns the matching reported/active finding
    recorded under a DIFFERENT slug, or ``None`` when the record is safe. An empty
    ``defect_family``/``root_cause_key`` cannot collide on the tuple, so the check
    is skipped — the backend's title-fallback tier remains the backstop.
    """
    if not (defect_family and root_cause_key):
        return None
    for finding in existing_findings:
        if not isinstance(finding, dict):
            continue
        if str(finding.get("slug", "")) == candidate_slug:
            continue
        if str(finding.get("workflow_status", "")).strip().lower() not in _CLOBBER_GUARDED_STATUSES:
            continue
        if (
            str(finding.get("defect_family", "")) == defect_family
            and str(finding.get("root_cause_key", "")) == root_cause_key
            and str(finding.get("auth_context", "")) == auth_context
            and str(finding.get("canonical_location", "")) == canonical_location
        ):
            return finding
    return None


def _refuse_clobber(existing: dict) -> None:
    existing_slug = str(existing.get("slug", ""))
    existing_status = str(existing.get("workflow_status", ""))
    print(
        f"record-finding: REFUSED — this finding's dedup tuple (defect_family + root_cause_key "
        f"+ auth_context + canonical_location) collides with existing finding {existing_slug} "
        f"(workflow_status={existing_status}); recording it would silently overwrite that "
        f"{existing_status} finding.\n"
        f"  - Distinct sibling on the same root cause? Give it a DISTINCT root_cause_key/"
        f"defect_family, then attach it after recording with "
        f"`vigil assess link-finding <this-slug> --root-cause {existing_slug}`.\n"
        f"  - Intend to MODIFY {existing_slug}? Re-run with `--update {existing_slug}`.",
        file=sys.stderr,
    )
    sys.exit(1)


def _resolve_update_target(update_slug: str, json_slug: str, *, base_url: str, engagement_key: str) -> str:
    """Resolve ``--update <slug>`` to the target slug, validating operator intent.

    --update is the explicit opt-in to MODIFY an existing finding (I-21): it must
    name an EXISTING slug and may not contradict a slug embedded in the JSON. The
    resolved slug becomes the record's slug so the backend matches it directly
    (its first tier) rather than re-running the net-new dedup collision.
    """
    if json_slug and json_slug != update_slug:
        print(
            f"record-finding: --update {update_slug} conflicts with slug '{json_slug}' in the "
            f"JSON payload. Drop the JSON slug or set it to {update_slug}.",
            file=sys.stderr,
        )
        sys.exit(1)
    with AssessmentClient(base_url, engagement_key) as client:
        try:
            existing = client.get(f"findings/{update_slug}")
        except AssessError as exc:
            if "HTTP 404" in str(exc):
                existing = None
            else:
                raise
    if not isinstance(existing, dict) or not existing.get("slug"):
        print(
            f"record-finding: --update {update_slug} names a finding that does not exist. Record "
            f"it without --update to create a new finding, or pass the correct existing slug.",
            file=sys.stderr,
        )
        sys.exit(1)
    return update_slug


def _guard_finding_clobber(payload: dict, *, candidate_slug: str, base_url: str, engagement_key: str) -> None:
    """Refuse a net-new record that would silently overwrite a reported/active
    finding under a different slug (I-21). The backend match is the authoritative
    backstop; this fails fast before the POST with the same guidance."""
    with AssessmentClient(base_url, engagement_key) as client:
        findings = client.get("findings")
    if not isinstance(findings, list):
        return
    clobbered = _find_clobbered_finding(
        findings,
        candidate_slug=candidate_slug,
        defect_family=str(payload.get("defect_family", "")),
        root_cause_key=str(payload.get("root_cause_key", "")),
        auth_context=str(payload.get("auth_context", "")),
        canonical_location=str(payload.get("canonical_location", "")),
    )
    if clobbered is not None:
        _refuse_clobber(clobbered)


def _print_backend_clobber_refusal(exc: AssessError) -> bool:
    """If ``exc`` is a backend clobber-guard or D4 re-mint-guard 409, print its
    actionable detail and return True (caller should exit 1). Otherwise return
    False so the caller re-raises and other errors keep their existing handling."""
    message = str(exc)
    if "HTTP 409" not in message or (
        _BACKEND_CLOBBER_MARKER not in message and _BACKEND_REMINT_MARKER not in message
    ):
        return False
    _, _, body = message.partition("\n")
    detail = body
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError:
        parsed = None
    if isinstance(parsed, dict) and isinstance(parsed.get("detail"), str):
        detail = parsed["detail"]
    print(f"record-finding: REFUSED — {detail}", file=sys.stderr)
    return True


def _report_validation_errors(payload: dict, errors: list[str]) -> None:
    print("finding payload invalid after helper defaults:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)

    hints = common_mistake_hints("record-finding", payload)
    if hints:
        print("Common legacy-field fixes:", file=sys.stderr)
        for hint in hints:
            print(f"  - {hint}", file=sys.stderr)

    print("", file=sys.stderr)
    print("Run `vigil assess contract record-finding` for the canonical helper contract.", file=sys.stderr)
    print("", file=sys.stderr)
    print(render_contract("record-finding"), file=sys.stderr)
    sys.exit(1)


def run(args) -> None:
    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir

    json_path = Path(args.json_file)
    if not json_path.is_file():
        print(f"finding json file not found: {args.json_file}", file=sys.stderr)
        sys.exit(1)

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        print("finding payload must be a JSON object", file=sys.stderr)
        sys.exit(1)

    agent_name = args.agent_name
    update_slug = (getattr(args, "update_slug", "") or "").strip()

    lock_path = finding_lock_path(eng_dir)
    with file_lock(lock_path):
        candidate_slug = payload.get("slug", "")
        if update_slug:
            # --update names the EXACT existing finding to modify; it is the
            # explicit opt-in past the clobber guard. The slug becomes the target
            # so the backend matches by slug rather than by a net-new collision.
            candidate_slug = _resolve_update_target(
                update_slug,
                candidate_slug,
                base_url=cfg.base_url,
                engagement_key=cfg.engagement_key,
            )
        elif not candidate_slug:
            candidate_slug = next_finding_id(cfg.base_url, cfg.engagement_key, agent_name)

        payload = _normalize_payload(payload, agent_name=agent_name, candidate_slug=candidate_slug)
        validation_errors = collect_validation_errors(payload, _FINDING_SCHEMA)
        if validation_errors:
            _report_validation_errors(payload, validation_errors)

        _normalize_evidence_ref(
            payload,
            eng_dir=eng_dir,
            engagement_key=cfg.engagement_key,
            allow_unindexed=getattr(args, "allow_unindexed_evidence", False),
        )

        if not update_slug:
            _guard_finding_clobber(
                payload,
                candidate_slug=candidate_slug,
                base_url=cfg.base_url,
                engagement_key=cfg.engagement_key,
            )

        # D4 override: injected AFTER schema validation (it is a control flag, not a
        # finding-record.schema.json field) so the backend's killed-remint guard is
        # skipped for an intentional distinct re-mint.
        if getattr(args, "allow_remint", False):
            payload["allow_remint"] = True

        with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
            try:
                response = client.post("findings", payload)
            except AssessError as exc:
                # Backstop: the authoritative backend guard refused a clobber the
                # CLI tuple-check did not model (title-tier match, or a race).
                if _print_backend_clobber_refusal(exc):
                    sys.exit(1)
                raise

        finding = response.get("finding", {})
        if not finding.get("slug") or not finding.get("title"):
            print("record-finding: orchestrator backend did not return a canonical finding record", file=sys.stderr)
            sys.exit(1)

        finding_slug = finding["slug"]

    # Emit event (outside lock)
    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        client.post_event({
            "event_type": "finding.created",
            "phase": os.environ.get("ORCHESTRATOR_PHASE", "unknown"),
            "task_name": finding_slug,
            "agent_name": agent_name,
            "summary": f"Recorded {finding_slug}",
        })

    print(finding_slug)
