"""Wave 6c — the depth ledger (depth-gate §5.3).

For every ``deep_required`` app unit (Wave 6a, ``app_units.py``) this module
computes the EXPECTED vuln-class set (each class gated by an EXECUTABLE
applicability predicate over the unit's durable signals), the COVERED set, the
DEDICATED-DISPATCH obligation, a per-unit ``depth_satisfied`` verdict, and an
EV rank. It is the executable form of the depth-gate §5.3 predicate table.

DOCTRINE (master plan §0, depth-gate §5.3):
  * **ADVISORY + EV-RANKED, NEVER A HARD BLOCK.** Mid-engagement this ledger
    only reports; it MUST NOT refuse a transition or exit non-zero. The single
    terminal block is a LATER wave. Nothing here raises to gate.
  * **NEVER count a self-attested-without-evidence signal.** A failed/blocked/
    empty probe, an evidence-free "covered" coverage_item, or a dispatch merely
    flagged ``status="completed"`` does NOT satisfy a class (S5/S7).
  * **STRUCTURED dispatch match, NEVER task-text** (S7). Dispatches resolve to
    classes via their structured ``vuln_classes`` / ``skills`` columns and their
    ``(scope_host, scope_path_prefix)`` containment — the free-text ``task``
    column is never read.
  * **WEB-ONLY.** Built on the web-guarded app-unit scorer; a non-web
    engagement yields an empty, skipped ledger.
  * **Read OUTCOMES, not tool runs.** Reads probe_runs / coverage_items /
    surfaces / findings / handoffs / (structured) dispatches. It NEVER joins
    ``assessment_command_runs``.

Disclosure is the load-bearing soft-signal guard: it is EXPECTED for every
deep_required unit but satisfied ONLY by a CONCRETE non-self-attested signal —
a completed ``gau-secrets``/trufflehog probe_run OR a JS/source-analysis probe
tied to the unit's host. A bare "I looked for secrets" probe never counts
(depth-gate §5.3).
"""
from __future__ import annotations

import functools
import json
from typing import Any

from .taxonomy_bridge import vuln_taxonomy

from ..events import _engagement_or_404
from . import _common
from ._common import _fetch_all
from .app_units import (
    score_application_units,
    _path_has_segment_token,
    _path_under_prefix,
    _port_class,
    _id_like_keys,
    _schema_nonempty,
    _surface_host_path,
    _params_match_tokens,
    _SSRF_PARAM_TOKENS,
    _FILE_TOKENS,
    _AUTH_PATH_TOKENS,
    _WORKFLOW_TOKENS,
    _DECISIVE_SURFACE_TYPES,
    CONF_HIGH,
)
from .coverage import PROBE_RESULT_STATUSES_COVERING


BLOCK_HIGH = "high"
BLOCK_WARN = "warn"

_FAMILY_BLOCK_LEVEL: dict[str, str] = {
    "access-control": BLOCK_HIGH,
    "auth": BLOCK_HIGH,
    "injection": BLOCK_HIGH,
    "ssrf": BLOCK_HIGH,
    "file": BLOCK_HIGH,
    "disclosure": BLOCK_WARN,
    "client-side": BLOCK_WARN,
    "business-logic": BLOCK_WARN,
    "protocol": BLOCK_WARN,
}

ACCESS_CONTROL_FAMILY = "access-control"

_GENERIC_FAMILIES: frozenset[str] = frozenset(
    {"endpoint-review", "parameter-review", "session-review",
     "header-review", "service-validation"}
)

_DISCLOSURE_CONCRETE_TOOLS: tuple[str, ...] = (
    "gau-secrets", "trufflehog", "gitleaks", "secretfinder",
    "gau-js-endpoints", "linkfinder", "jsluice", "subjs", "getjs",
    "sourcemapper", "js-beautify", "retire",
)

_CORS_HEADER_TOKENS: frozenset[str] = frozenset(
    {"access-control-allow-origin", "access-control-allow-credentials"}
)

_STATE_CHANGING_METHODS: frozenset[str] = frozenset({"PUT", "PATCH", "DELETE"})

_SSRF_PATH_TOKENS: tuple[str, ...] = ("webhook", "import", "proxy", "fetch", "callback", "redirect")

_PROXY_CDN_TOKENS: tuple[str, ...] = (
    "cloudflare", "akamai", "fastly", "varnish", "nginx", "haproxy",
    "envoy", "cloudfront", "squid", "traefik", "ats", "trafficserver",
)


_TIER_WEIGHT: dict[str, int] = {
    "thin": 0,
    "endpoint-cluster": 1,
    "app-unit": 2,
    "application": 3,
}


def depth_ledger(engagement_id: int) -> dict[str, Any]:
    """Compute the per-unit depth ledger, EV-ranked, for an engagement.

    ADVISORY/READ-ONLY: never raises to block; never mutates state. WEB-ONLY:
    for code/blue engagements returns ``{"skipped": True, ...}`` (the app-unit
    scorer persists nothing for them, so there is nothing to score).

    Returns::

        {
          "skipped": bool,
          "units": [ <per-unit ledger>, ... ],   # EV-ranked, highest first
          "summary": {"deep_required": N, "depth_satisfied": M, ...},
        }

    Each per-unit ledger has the §5.3 shape::

        {
          "unit": {id, host, port_class, path_prefix, depth_tier, risk_score, ...},
          "expected": [{class, family, block_level, predicate_fired_on}, ...],
          "covered":  [{class/family, via}, ...],
          "missing_block": [...], "missing_warn": [...], "deferred": [...],
          "dedicated_dispatch_satisfied": bool,
          "depth_satisfied": bool,
          "ev_rank": int,
        }
    """
    engagement = _engagement_or_404(engagement_id)
    etype = str(getattr(engagement, "engagement_type", "") or "").lower()
    if etype in ("code", "blue"):
        return {
            "skipped": True,
            "reason": f"non-web engagement_type={engagement.engagement_type!r}; "
                      "depth ledger is web-only",
            "units": [],
            "summary": {"deep_required": 0, "depth_satisfied": 0},
        }
    if vuln_taxonomy is None:
        return {
            "skipped": True,
            "reason": "canonical vuln taxonomy unavailable (agent tree not importable)",
            "units": [],
            "summary": {"deep_required": 0, "depth_satisfied": 0},
        }

    eng_id = engagement.id
    with _common.get_connection() as connection:
        units = _fetch_all(
            connection,
            "SELECT * FROM assessment_application_units WHERE engagement_id = ? "
            "AND deep_required = 1 ORDER BY host, port_class, path_prefix",
            (eng_id,),
        )
        variants = _fetch_all(
            connection,
            "SELECT id, scheme, host, port, method, normalized_path, auth_context, "
            "content_type_family, query_schema_json, body_schema_json, path_schema_json, "
            "header_schema_json FROM assessment_request_variants WHERE engagement_id = ?",
            (eng_id,),
        )
        observations = _fetch_all(
            connection,
            "SELECT request_variant_id, response_status FROM assessment_request_observations "
            "WHERE engagement_id = ?",
            (eng_id,),
        )
        surfaces = _fetch_all(
            connection,
            "SELECT surface_type, target_descriptor FROM assessment_surfaces WHERE engagement_id = ?",
            (eng_id,),
        )
        coverage_items = _fetch_all(
            connection,
            "SELECT id, application_unit_id, request_variant_id, attack_family, status, notes "
            "FROM assessment_coverage_items WHERE engagement_id = ?",
            (eng_id,),
        )
        probes = _fetch_all(
            connection,
            "SELECT id, application_unit_id, request_variant_id, attack_family, result_status, "
            "tool_name, target_host, target_path, target_port, auth_context "
            "FROM assessment_probe_runs WHERE engagement_id = ?",
            (eng_id,),
        )
        dispatches = _fetch_all(
            connection,
            "SELECT id, agent_id, agent_role, scope_host, scope_path_prefix, vuln_classes, "
            "skills, status, finding_slugs_json FROM assessment_dispatches WHERE engagement_id = ?",
            (eng_id,),
        )
        findings = _fetch_all(
            connection,
            "SELECT slug, canonical_location, defect_family "
            "FROM assessment_findings WHERE engagement_id = ?",
            (eng_id,),
        )
        creds = _fetch_all(
            connection,
            "SELECT credential_key, principal, provenance_json "
            "FROM assessment_credentials WHERE engagement_id = ?",
            (eng_id,),
        ) if _table_exists(connection, "assessment_credentials") else []

    variant_by_id = {int(v["id"]): v for v in variants}
    status_by_variant: dict[int, list[int]] = {}
    for obs in observations:
        vid = obs.get("request_variant_id")
        st = obs.get("response_status")
        if vid is not None and st is not None:
            status_by_variant.setdefault(int(vid), []).append(int(st))

    parsed_surfaces: list[tuple[str, str, str]] = []
    for s in surfaces:
        host, path = _surface_host_path(str(s.get("target_descriptor") or ""))
        if host:
            parsed_surfaces.append((host, path, str(s.get("surface_type") or "")))

    cred_hosts: set[str] = set()
    for c in creds:
        for raw in (c.get("credential_key"), c.get("principal"), c.get("provenance_json")):
            for tok in _extract_host_tokens(str(raw or "")):
                cred_hosts.add(tok)

    active_deferrals = _active_depth_deferrals(eng_id)

    result_units: list[dict[str, Any]] = []
    n_satisfied = 0
    for unit in units:
        ledger = _unit_ledger(
            unit,
            variant_by_id=variant_by_id,
            status_by_variant=status_by_variant,
            parsed_surfaces=parsed_surfaces,
            cred_hosts=cred_hosts,
            coverage_items=coverage_items,
            probes=probes,
            dispatches=dispatches,
            findings=findings,
            active_deferrals=active_deferrals,
        )
        if ledger["depth_satisfied"]:
            n_satisfied += 1
        result_units.append(ledger)

    result_units.sort(
        key=lambda L: (-L["ev_rank"], L["unit"]["host"], L["unit"]["path_prefix"]),
    )

    return {
        "skipped": False,
        "units": result_units,
        "deferral_count": len(active_deferrals),
        "summary": {
            "deep_required": len(units),
            "depth_satisfied": n_satisfied,
            "depth_unsatisfied": len(units) - n_satisfied,
        },
    }


def _table_exists(connection, name: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?", (name,),
    ).fetchone()
    return row is not None


import re as _re  # noqa: E402

_HOST_TOKEN_RE = _re.compile(r"\b([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", _re.IGNORECASE)


def _extract_host_tokens(value: str) -> set[str]:
    """Parse bare-host tokens out of a free-text credential field.

    Credentials carry their target host inside ``credential_key`` /
    ``principal`` (e.g. ``admin@rock.example.com`` / ``rock.example.com:web``)
    or a ``provenance_json`` URL. We pull every dotted-host token so the §5.3
    auth predicate can match it against the unit's host. URL/host:port shapes
    are normalized through the same surface parser used elsewhere.
    """
    out: set[str] = set()
    if not value:
        return out
    parsed_host, _ = _surface_host_path(value)
    if parsed_host and "." in parsed_host:
        out.add(parsed_host)
    for m in _HOST_TOKEN_RE.finditer(value):
        out.add(m.group(1).lower())
    return out


def _unit_ledger(
    unit: dict[str, Any],
    *,
    variant_by_id: dict[int, dict[str, Any]],
    status_by_variant: dict[int, list[int]],
    parsed_surfaces: list[tuple[str, str, str]],
    cred_hosts: set[str],
    coverage_items: list[dict[str, Any]],
    probes: list[dict[str, Any]],
    dispatches: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    active_deferrals: list[dict[str, Any]],
) -> dict[str, Any]:
    unit_id = int(unit["id"])
    host = str(unit["host"]).lower()
    port_class = str(unit["port_class"])
    prefix = str(unit["path_prefix"])
    risk_score = int(unit.get("risk_score") or 0)
    depth_tier = str(unit.get("depth_tier") or "thin")

    unit_variants: list[dict[str, Any]] = []
    for v in variant_by_id.values():
        if str(v.get("host") or "").lower() != host:
            continue
        if _port_class(str(v.get("scheme") or ""), int(v.get("port") or 0)) != port_class:
            continue
        if _path_under_prefix(str(v.get("normalized_path") or "/"), prefix):
            unit_variants.append(v)

    paths = [str(v.get("normalized_path") or "/") for v in unit_variants]
    methods = {str(v.get("method") or "").upper() for v in unit_variants}
    statuses: list[int] = []
    for v in unit_variants:
        statuses.extend(status_by_variant.get(int(v["id"]), []))

    unit_surface_types: set[str] = set()
    for s_host, s_path, s_type in parsed_surfaces:
        if s_host == host and _path_under_prefix(s_path, prefix):
            unit_surface_types.add(s_type)

    unit_variant_ids = {int(v["id"]) for v in unit_variants}

    # Bucket each cross-cutting list to THIS unit ONCE. The covering scan, the
    # touched fallback, the signal-class scan, and the dispatch work-evidence
    # check each previously re-ran the same `_probe_maps_to_unit` /
    # `_coverage_maps_to_unit` / `_finding_maps_to_unit` predicate over the FULL
    # lists (and the dispatch check re-scanned every probe per dispatch), making
    # the ledger O(units x dispatches x probes) and timing out at ~900 probes.
    # Membership is IDENTICAL — only the recomputation is removed.
    unit_probes = [
        p for p in probes
        if _probe_maps_to_unit(p, unit_id, unit_variant_ids, host, port_class, prefix)
    ]
    unit_coverage = [
        ci for ci in coverage_items if _coverage_maps_to_unit(ci, unit_id, unit_variant_ids)
    ]
    unit_findings = [f for f in findings if _finding_maps_to_unit(f, host, prefix)]
    unit_has_covering_probe = any(
        str(p.get("result_status") or "").strip().lower() in PROBE_RESULT_STATUSES_COVERING
        for p in unit_probes
    )
    # Dispatch work-evidence (S7) asks only "does this UNIT have a covering probe
    # OR a finding" — it is dispatch-INDEPENDENT, so it is a per-unit constant, not
    # a per-dispatch probe rescan.
    unit_has_work_evidence = unit_has_covering_probe or bool(unit_findings)

    covering_probe_families: set[str] = set()
    covering_identities_by_family: dict[str, set[str]] = {}
    disclosure_concrete = False
    for p in unit_probes:
        rs = str(p.get("result_status") or "").strip().lower()
        if rs not in PROBE_RESULT_STATUSES_COVERING:
            continue
        fam = vuln_taxonomy.family_of(
            vuln_taxonomy.normalize_class(str(p.get("attack_family") or ""))
        )
        if fam:
            covering_probe_families.add(fam)
            ident = str(p.get("auth_context") or "").strip()
            if ident:
                covering_identities_by_family.setdefault(fam, set()).add(ident)
        tool = str(p.get("tool_name") or "").strip().lower()
        if any(tok in tool for tok in _DISCLOSURE_CONCRETE_TOOLS):
            disclosure_concrete = True

    covering_cov_families: set[str] = set()
    for ci in unit_coverage:
        status_val = str(ci.get("status") or "").strip().lower()
        if status_val not in ("covered", "not_applicable", "not-applicable"):
            continue
        if not str(ci.get("notes") or "").strip():
            continue
        fam = vuln_taxonomy.family_of(
            vuln_taxonomy.normalize_class(str(ci.get("attack_family") or ""))
        )
        if fam and fam not in _GENERIC_FAMILIES:
            covering_cov_families.add(fam)

    covered_families = covering_probe_families | covering_cov_families

    ac_identities = covering_identities_by_family.get(ACCESS_CONTROL_FAMILY, set())
    cross_identity_satisfied = len(ac_identities) >= 2

    deferred_families: set[str] = set()
    deferred_records: list[dict[str, Any]] = []
    for row in active_deferrals:
        payload = row.get("payload") or {}
        if not _deferral_applies_to_unit(payload, host, prefix):
            continue
        for cls in payload.get("vuln_classes") or []:
            fam = vuln_taxonomy.family_of(vuln_taxonomy.normalize_class(str(cls)))
            if fam:
                deferred_families.add(fam)
        deferred_records.append({
            "decision_id": row.get("id"),
            "vuln_classes": payload.get("vuln_classes") or [],
            "reason": payload.get("reason"),
            "engagement_wide": bool(payload.get("engagement_wide")),
        })

    expected = _expected_families(
        unit_variants=unit_variants,
        paths=paths,
        methods=methods,
        statuses=statuses,
        unit_surface_types=unit_surface_types,
        host=host,
        cred_hosts=cred_hosts,
    )

    covered_out: list[dict[str, Any]] = []
    missing_block: list[dict[str, Any]] = []
    missing_warn: list[dict[str, Any]] = []
    deferred_out: list[dict[str, Any]] = []
    for fam, fired_on in expected.items():
        block_level = _FAMILY_BLOCK_LEVEL.get(fam, BLOCK_WARN)
        entry = {"family": fam, "block_level": block_level, "predicate_fired_on": fired_on}
        is_deferred = fam in deferred_families
        if fam == "disclosure":
            is_covered = disclosure_concrete
            covered_via = "coverage"
        elif fam == ACCESS_CONTROL_FAMILY:
            is_covered = cross_identity_satisfied
            covered_via = f"cross-identity ({', '.join(sorted(ac_identities))})"
        else:
            is_covered = fam in covered_families
            covered_via = "coverage"
        if is_covered:
            covered_out.append({**entry, "via": covered_via})
        elif is_deferred:
            covered_out.append({**entry, "via": "deferral"})
            deferred_out.append(entry)
        else:
            miss_entry = dict(entry)
            if fam == ACCESS_CONTROL_FAMILY:
                n_ident = len(ac_identities)
                miss_entry["needs"] = "a second identity"
                miss_entry["detail"] = (
                    "needs a second identity"
                    if n_ident <= 1
                    else f"covered via cross-identity ({', '.join(sorted(ac_identities))})"
                )
                miss_entry["identities_seen"] = sorted(ac_identities)
            (missing_block if block_level == BLOCK_HIGH else missing_warn).append(miss_entry)

    block_families = {f for f, lvl in (
        (fam, _FAMILY_BLOCK_LEVEL.get(fam, BLOCK_WARN)) for fam in expected
    ) if lvl == BLOCK_HIGH}
    dedicated = _dedicated_dispatch_satisfied(
        block_families=block_families,
        host=host,
        prefix=prefix,
        dispatches=dispatches,
        unit_has_work_evidence=unit_has_work_evidence,
    )

    depth_satisfied = (not missing_block) and dedicated

    # A unit is "touched" if there is ANY work evidence under it: a covering
    # probe/coverage family, a covering probe whose family didn't resolve, or a
    # finding. A completed dispatch adds nothing here — its work-evidence test is
    # the SAME probe/finding-under-unit check already captured by
    # `unit_has_covering_probe` / `unit_findings` — so the redundant
    # O(dispatches x probes) dispatch scan is gone.
    touched = (
        bool(covering_probe_families)
        or bool(covering_cov_families)
        or unit_has_covering_probe
        or bool(unit_findings)
    )

    decisive_surface = bool(unit_surface_types & _DECISIVE_SURFACE_TYPES)

    n_missing_high = len(missing_block)
    ev_rank = _TIER_WEIGHT.get(depth_tier, 1) * max(n_missing_high, 0) * max(risk_score, 1)
    if not depth_satisfied and ev_rank == 0:
        ev_rank = _TIER_WEIGHT.get(depth_tier, 1) * max(risk_score, 1)

    # Per-class signal coverage (ADVISORY, additive — does NOT feed
    # `depth_satisfied`, `missing_block`, or the family math above, all of which
    # stay byte-identical). The gf coverage_items carry the SPECIFIC implied vuln
    # CLASS in `attack_family` (e.g. 'sqli'/'idor', from GF_BUCKET_TO_CLASS), but
    # `covered_families` collapses every class to its family — so a sibling-class
    # probe (e.g. an `ssti` probe) marks the whole `injection` family covered and a
    # `sqli` signal is never independently demanded, the single-class blind spot.
    # Surface the high-signal classes a unit was flagged for (via its gf
    # coverage_items, families that BLOCK_HIGH) that still lack a CLASS-SPECIFIC
    # covering probe / coverage_item, so the operator can drain coverage per CLASS
    # rather than per family. Reuses the same unit-mapped probes/coverage_items.
    signal_classes_expected: set[str] = set()
    for ci in unit_coverage:
        cls = vuln_taxonomy.normalize_class(str(ci.get("attack_family") or ""))
        if not cls or not vuln_taxonomy.is_valid_class(cls):
            continue
        fam = vuln_taxonomy.family_of(cls)
        if fam and fam not in _GENERIC_FAMILIES and _FAMILY_BLOCK_LEVEL.get(fam) == BLOCK_HIGH:
            signal_classes_expected.add(cls)

    signal_classes_covered: set[str] = set()
    if signal_classes_expected:
        for p in unit_probes:
            if str(p.get("result_status") or "").strip().lower() not in PROBE_RESULT_STATUSES_COVERING:
                continue
            signal_classes_covered.add(
                vuln_taxonomy.normalize_class(str(p.get("attack_family") or ""))
            )
        for ci in unit_coverage:
            if str(ci.get("status") or "").strip().lower() not in (
                "covered", "not_applicable", "not-applicable"
            ):
                continue
            if not str(ci.get("notes") or "").strip():
                continue
            signal_classes_covered.add(
                vuln_taxonomy.normalize_class(str(ci.get("attack_family") or ""))
            )

    signal_classes_uncovered = sorted(
        signal_classes_expected - signal_classes_covered - {
            vuln_taxonomy.normalize_class(str(c))
            for rec in deferred_records
            for c in (rec.get("vuln_classes") or [])
        }
    )

    return {
        "unit": {
            "id": unit_id,
            "host": host,
            "port_class": port_class,
            "path_prefix": prefix,
            "depth_tier": depth_tier,
            "risk_score": risk_score,
            "structure_score": int(unit.get("structure_score") or 0),
            "total_score": int(unit.get("total_score") or 0),
            "confidence": str(unit.get("confidence") or ""),
        },
        "expected": [
            {"family": f, "block_level": _FAMILY_BLOCK_LEVEL.get(f, BLOCK_WARN),
             "predicate_fired_on": fired}
            for f, fired in expected.items()
        ],
        "covered": covered_out,
        "missing_block": missing_block,
        "missing_warn": missing_warn,
        "deferred": deferred_out,
        "dedicated_dispatch_satisfied": dedicated,
        "depth_satisfied": depth_satisfied,
        "touched": touched,
        "decisive_surface": decisive_surface,
        "confidence": str(unit.get("confidence") or ""),
        "ev_rank": ev_rank,
        # Per-class gap (see computation above): specific high-signal (BLOCK_HIGH)
        # vuln classes this unit's gf coverage_items implied that still lack a
        # class-specific covering probe / evidence-bearing coverage_item and are
        # not deferred. Empty for units with no per-class signal. It does NOT
        # affect the family verdict `depth_satisfied` (which stays byte-identical),
        # but it IS load-bearing at the terminal edge: `terminal_depth_block`
        # promotes a non-empty set to a CLASS-LEVEL hard block for decisive /
        # high-confidence units only (ADR 0012). Non-decisive units keep it
        # advisory-only.
        "signal_classes_uncovered": signal_classes_uncovered,
    }


def _expected_families(
    *,
    unit_variants: list[dict[str, Any]],
    paths: list[str],
    methods: set[str],
    statuses: list[int],
    unit_surface_types: set[str],
    host: str,
    cred_hosts: set[str],
) -> dict[str, str]:
    """Return {family: predicate_fired_on} for every expected family.

    Encodes the §5.3 table EXACTLY. ``predicate_fired_on`` records WHICH clause
    of the predicate matched, for operator transparency.
    """
    expected: dict[str, str] = {}

    auth_gated = any(s in (401, 403) for s in statuses)
    has_params = any(
        _schema_nonempty(v.get("query_schema_json"))
        or _schema_nonempty(v.get("body_schema_json"))
        or _schema_nonempty(v.get("path_schema_json"))
        for v in unit_variants
    )
    id_refs = any(
        _id_like_keys(v.get("query_schema_json"))
        or _id_like_keys(v.get("path_schema_json"))
        or _id_like_keys(v.get("body_schema_json"))
        for v in unit_variants
    )

    if "object_reference" in unit_surface_types:
        expected["access-control"] = "object_reference surface"
    elif id_refs:
        expected["access-control"] = "id-bearing params"
    elif auth_gated:
        expected["access-control"] = "auth-gated routing (401/403)"

    if unit_surface_types & {"auth_entry", "account_recovery"}:
        expected["auth"] = "auth_entry/account_recovery surface"
    elif any(_path_has_segment_token(p, _AUTH_PATH_TOKENS) for p in paths):
        expected["auth"] = "login/session path"
    elif auth_gated:
        expected["auth"] = "auth-gated routing (401/403)"
    elif host in cred_hosts:
        expected["auth"] = "credentials exist for host"

    if has_params:
        expected["injection"] = "endpoint carries params"

    if any(_params_match_tokens(v, _SSRF_PARAM_TOKENS) for v in unit_variants):
        expected["ssrf"] = "url/redirect/callback param"
    elif any(_path_has_segment_token(p, _SSRF_PATH_TOKENS) for p in paths):
        expected["ssrf"] = "webhook/import/proxy path"

    if "file_handling" in unit_surface_types:
        expected["file"] = "file_handling surface"
    elif any(_params_match_tokens(v, _FILE_TOKENS) for v in unit_variants) or any(
        _path_has_segment_token(p, _FILE_TOKENS) for p in paths
    ):
        expected["file"] = "upload/download/file param or path"

    expected["disclosure"] = "deep_required unit (always expected)"

    has_form = any(
        "form" in str(v.get("content_type_family") or "").lower() for v in unit_variants
    )
    cross_origin = any(
        _header_has_token(v.get("header_schema_json"), _CORS_HEADER_TOKENS)
        for v in unit_variants
    )
    if has_params or has_form:
        expected["client-side"] = "reflected params / forms"
    elif cross_origin:
        expected["client-side"] = "cross-origin response headers"

    if "workflow_token" in unit_surface_types:
        expected["business-logic"] = "workflow_token surface"
    elif any(_path_has_segment_token(p, _WORKFLOW_TOKENS) for p in paths):
        expected["business-logic"] = "cart/checkout/payment path"
    elif methods & _STATE_CHANGING_METHODS:
        expected["business-logic"] = "state-changing methods (PUT/PATCH/DELETE)"

    if any("ws" in str(v.get("scheme") or "").lower() for v in unit_variants):
        expected["protocol"] = "websocket endpoint"
    elif any(_path_has_segment_token(p, ("ws", "websocket", "socket")) for p in paths):
        expected["protocol"] = "websocket path"
    elif any(
        _header_has_token(v.get("header_schema_json"), frozenset(_PROXY_CDN_TOKENS))
        for v in unit_variants
    ):
        expected["protocol"] = "proxy/CDN fingerprint"

    return expected


def _header_has_token(raw: Any, tokens: frozenset[str]) -> bool:
    try:
        obj = json.loads(raw) if isinstance(raw, str) else raw
    except (ValueError, TypeError):
        return False
    if not isinstance(obj, dict):
        return False
    for key, value in obj.items():
        k = str(key).lower()
        if k in tokens or any(tok in k for tok in tokens):
            return True
        v = str(value).lower()
        if any(tok in v for tok in tokens):
            return True
    return False


def _probe_maps_to_unit(
    probe: dict[str, Any], unit_id: int, unit_variant_ids: set[int],
    host: str, port_class: str, prefix: str,
) -> bool:
    """A probe maps to the unit via non-null application_unit_id, OR a
    request_variant_id resolving to a unit variant, OR populated
    target_host/target_path containment. A null-target probe NEVER counts (S6).
    """
    aui = probe.get("application_unit_id")
    if aui is not None and int(aui) == unit_id:
        return True
    vid = probe.get("request_variant_id")
    if vid is not None and int(vid) in unit_variant_ids:
        return True
    t_host = str(probe.get("target_host") or "").strip().lower()
    if not t_host:
        return False
    if t_host != host:
        return False
    t_port = probe.get("target_port")
    pc = _port_class("", int(t_port)) if t_port else "web"
    if pc != port_class:
        return False
    t_path = str(probe.get("target_path") or "/") or "/"
    return _path_under_prefix(t_path, prefix)


def _coverage_maps_to_unit(
    ci: dict[str, Any], unit_id: int, unit_variant_ids: set[int],
) -> bool:
    aui = ci.get("application_unit_id")
    if aui is not None and int(aui) == unit_id:
        return True
    vid = ci.get("request_variant_id")
    return vid is not None and int(vid) in unit_variant_ids


def _dispatch_classes(dispatch: dict[str, Any]) -> set[str]:
    """Resolve a dispatch to canonical FAMILIES via STRUCTURED metadata only.

    ``vuln_classes`` (comma-list) if present, ELSE the declared ``skills``
    resolved to classes via the Wave 1 taxonomy skill->class index. NEVER the
    free-text ``task`` column (S7).
    """
    families: set[str] = set()
    raw_classes = str(dispatch.get("vuln_classes") or "").strip()
    if raw_classes:
        for tok in raw_classes.replace(",", " ").split():
            fam = vuln_taxonomy.family_of(vuln_taxonomy.normalize_class(tok))
            if fam:
                families.add(fam)
    if not families:
        skill_to_families = _skill_to_families()
        for sk in str(dispatch.get("skills") or "").replace(",", " ").split():
            families |= skill_to_families.get(sk.strip(), frozenset())
    return families


@functools.lru_cache(maxsize=1)
def _skill_to_families() -> dict[str, frozenset[str]]:
    """Inverse skill -> declared FAMILIES index, derived once from the canonical
    taxonomy. ``build_class_to_skills`` re-reads the whole skills dir (a glob plus
    a frontmatter parse per ``SKILL.md``), so resolving it inside
    ``_dispatch_classes`` ran it once per dispatch×unit in the synchronous
    terminal-block request path. The skills tree is baked at install time and
    does not change while the orchestrator runs, so a process-lifetime cache is
    safe (a re-install restarts the service)."""
    skill_to_families: dict[str, set[str]] = {}
    for cls, skills in vuln_taxonomy.build_class_to_skills().items():
        fam = vuln_taxonomy.family_of(cls)
        if not fam:
            continue
        for sk in skills:
            skill_to_families.setdefault(sk, set()).add(fam)
    return {sk: frozenset(fams) for sk, fams in skill_to_families.items()}


def _dispatch_contains_unit(
    dispatch: dict[str, Any], host: str, prefix: str,
) -> bool:
    """(scope_host, scope_path_prefix) of the dispatch contains the unit."""
    d_host = str(dispatch.get("scope_host") or "").strip().lower()
    if not d_host or d_host != host:
        return False
    d_prefix = str(dispatch.get("scope_path_prefix") or "/").strip() or "/"
    return _path_under_prefix(prefix, d_prefix)


def _dedicated_dispatch_satisfied(
    *,
    block_families: set[str],
    host: str,
    prefix: str,
    dispatches: list[dict[str, Any]],
    unit_has_work_evidence: bool,
) -> bool:
    """≥1 completed dispatch with WORK EVIDENCE that, between qualifying
    dispatches, covers every block-level Expected class for the unit (S7).

    A dispatch QUALIFIES when:
      * ``status='completed'`` AND
      * (scope_host, scope_path_prefix) contains the unit AND
      * ``unit_has_work_evidence`` — the unit has corroborating durable output
        (≥1 covering probe OR a recorded finding under it). ``status='completed'``
        ALONE, or accompanied only by a self-attested handoff, does NOT satisfy:
        the handoff ``summary``/``coverage_gaps`` are agent self-attestation and
        the doctrine forbids counting a self-attested-without-evidence signal
        (else one completed dispatch with a broad ``scope_path_prefix`` + a bare
        handoff would satisfy every unit on the host). Legitimate work the harness
        missed is recovered via the recorded depth-deferral / ``--force --reason``
        valve, not by trusting free text.

    Work evidence is a per-UNIT property (does the unit have a covering probe or a
    finding), NOT per-dispatch — so the caller computes it ONCE and passes it in,
    rather than re-scanning every probe per dispatch (the old O(dispatches x
    probes) hot path). With no work evidence, no dispatch can qualify.

    The union of qualifying dispatches' resolved classes must cover every
    block-level family. When there are NO block-level families (degenerate), a
    deep_required unit still owes ≥1 qualifying dispatch.
    """
    covered_block: set[str] = set()
    any_qualifying = False
    if unit_has_work_evidence:
        for d in dispatches:
            if str(d.get("status") or "").strip().lower() != "completed":
                continue
            if not _dispatch_contains_unit(d, host, prefix):
                continue
            any_qualifying = True
            covered_block |= _dispatch_classes(d) & block_families
    if not block_families:
        return any_qualifying
    return block_families.issubset(covered_block)


def _finding_maps_to_unit(
    finding: dict[str, Any], host: str, prefix: str,
) -> bool:
    loc = str(finding.get("canonical_location") or "")
    if not loc:
        return False
    f_host, f_path = _surface_host_path(loc)
    return bool(f_host) and f_host == host and _path_under_prefix(f_path, prefix)


def _active_depth_deferrals(engagement_id: int) -> list[dict[str, Any]]:
    """Return every active (``resolved=0``) ``depth_deferral`` decision row for
    the engagement, newest-first. Reads directly through ``get_connection`` to
    avoid the public ``list_decisions`` limit cap (mirrors
    ``coverage._active_coverage_deferrals``)."""
    from .dispatches import _serialize_decision

    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            "SELECT * FROM assessment_dispatch_decisions "
            "WHERE engagement_id = ? AND kind = ? AND resolved = 0 "
            "ORDER BY created_at DESC, id DESC",
            (engagement.id, "depth_deferral"),
        )
        return [_serialize_decision(row) for row in cursor.fetchall()]


def _deferral_applies_to_unit(
    payload: dict[str, Any], host: str, prefix: str,
) -> bool:
    """A depth_deferral applies to a unit when it is engagement_wide, OR its
    (host, path_prefix) contains the unit (host match + prefix containment)."""
    if not isinstance(payload, dict):
        return False
    if payload.get("engagement_wide") is True:
        return True
    d_host = str(payload.get("host") or "").strip().lower()
    if not d_host:
        return False
    parsed_host, _ = _surface_host_path(d_host)
    norm_host = parsed_host or d_host
    if norm_host != host:
        return False
    d_prefix = str(payload.get("path_prefix") or "/").strip() or "/"
    return _path_under_prefix(prefix, d_prefix)


def terminal_depth_block(engagement_id: int) -> dict[str, Any]:
    """Return the units that BLOCK the terminal ``report``/``complete`` edge.

    Returns::

        {
          "skipped": bool,                  # True for code/blue (web-only)
          "blocking": [ <unit-block-detail>, ... ],
          "warned_under_observed": [ <unit-warn-detail>, ... ],
          "deferred": [ <unit-defer-detail>, ... ],
          "deferral_count": int,            # active depth_deferral decision rows
        }

    ``blocking`` is the BLOCKING set. Each entry carries a ``block_grain``:
    ``"family"`` — the historical block: a decisive/high-confidence unit that is
    unsatisfied AND undeferred AND UNTOUCHED (``missing_block_families`` names the
    uncovered BLOCK_HIGH families); or ``"class"`` — the coverage-grain-unbundle
    block (ADR 0012): a decisive/high-confidence unit with a non-empty
    ``signal_classes_uncovered`` (``uncovered_classes`` names the specific
    BLOCK_HIGH classes flagged but never class-specifically covered), which fires
    even when the family looks covered/touched. ``warned_under_observed`` lists
    block-set / under-observed units that are surfaced but never block
    (touched-but-unsatisfied at the family level, OR low-confidence non-decisive
    deep_required units). ``deferred`` lists units whose block classes are covered
    by an active ``depth_deferral`` so the "option D" write-off stays a counted,
    recorded decision (``deferral_count`` makes the deferral rate visible).
    """
    score_application_units(engagement_id)
    ledger = depth_ledger(engagement_id)
    if ledger.get("skipped"):
        return {
            "skipped": True,
            "reason": ledger.get("reason", ""),
            "blocking": [],
            "warned_under_observed": [],
            "deferred": [],
            "deferral_count": 0,
        }

    deferral_count = int(ledger.get("deferral_count") or 0)

    blocking: list[dict[str, Any]] = []
    warned: list[dict[str, Any]] = []
    deferred: list[dict[str, Any]] = []

    for u in ledger.get("units", []):
        unit = u["unit"]
        high_conf = str(u.get("confidence") or "") == CONF_HIGH
        decisive = bool(u.get("decisive_surface"))
        in_block_set = high_conf or decisive
        if not in_block_set:
            warned.append(_warn_detail(u, reason="under-observed (low confidence, "
                                                  "no decisive surface)"))
            continue

        block_set_via = ("high-confidence deep_required" if high_conf
                         else "decisive risk surface")

        if u.get("deferred"):
            deferred.append({
                "unit": unit,
                "deferred_families": [e["family"] for e in u["deferred"]],
            })

        # CLASS-LEVEL hard block (coverage-grain unbundle / ADR 0012), for
        # DECISIVE / HIGH-CONFIDENCE units ONLY. ``signal_classes_uncovered`` is
        # the already-computed set of specific BLOCK_HIGH *classes* this unit was
        # flagged for (via its gf coverage_items) that still lack a class-specific
        # covering probe or evidence-bearing coverage_item and are NOT deferred —
        # carrying the SAME anti-self-attestation guards as the family gate
        # (whitelisted ``result_status`` / notes-bearing coverage_item;
        # ``status="completed"`` alone never counts) and the SAME ``depth_deferral``
        # subtraction. Making it load-bearing here closes the single-class blind
        # spot the family collapse leaves open (a sibling-class probe — e.g.
        # ``ssti`` — marking the whole ``injection`` family covered while ``sqli``
        # was never demanded), so it can fire even when the unit is family-
        # ``depth_satisfied`` or merely touched. NON-decisive / non-high-confidence
        # units never reach this branch — their family-level behaviour and the
        # touched->WARN downgrade below are UNCHANGED — and because the set is
        # already restricted to BLOCK_HIGH classes, a BLOCK_WARN class never enters
        # the hard set alone. Cleared by covering the class, a ``depth_deferral``
        # naming it, or ``--force --reason`` (same valves as the family block).
        uncovered_classes = list(u.get("signal_classes_uncovered") or [])
        if uncovered_classes:
            blocking.append({
                "unit": unit,
                "block_set_via": block_set_via,
                "decisive_surface": decisive,
                "block_grain": "class",
                "uncovered_classes": uncovered_classes,
                "missing_block_families": [e["family"] for e in u.get("missing_block", [])],
            })
            continue

        satisfied = bool(u.get("depth_satisfied"))
        if satisfied:
            continue

        if not u.get("missing_block"):
            warned.append(_warn_detail(u, reason="dedicated-dispatch obligation unmet"))
            continue

        touched = bool(u.get("touched"))
        if touched:
            warned.append(_warn_detail(
                u, reason="touched but unsatisfied (started, not finished deep)"))
            continue

        blocking.append({
            "unit": unit,
            "block_set_via": block_set_via,
            "decisive_surface": decisive,
            "block_grain": "family",
            "missing_block_families": [e["family"] for e in u["missing_block"]],
        })

    return {
        "skipped": False,
        "blocking": blocking,
        "warned_under_observed": warned,
        "deferred": deferred,
        "deferral_count": deferral_count,
    }


def _warn_detail(unit_ledger: dict[str, Any], *, reason: str) -> dict[str, Any]:
    return {
        "unit": unit_ledger["unit"],
        "reason": reason,
        "confidence": str(unit_ledger.get("confidence") or ""),
        "decisive_surface": bool(unit_ledger.get("decisive_surface")),
        "missing_block_families": [e["family"] for e in unit_ledger.get("missing_block", [])],
        "missing_warn_families": [e["family"] for e in unit_ledger.get("missing_warn", [])],
        "signal_classes_uncovered": list(unit_ledger.get("signal_classes_uncovered") or []),
    }


__all__ = ["depth_ledger", "terminal_depth_block"]
