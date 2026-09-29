"""Application-unit depth ledger.

For every ``deep_required`` app unit from ``app_units.py``, this module
computes the EXPECTED vuln-class set (each class gated by an EXECUTABLE
applicability predicate over the unit's durable signals), the COVERED set, the
DEDICATED-DISPATCH obligation, a per-unit ``depth_satisfied`` verdict, and an
EV rank. It is the executable form of the depth-gate §5.3 predicate table.

INVARIANTS:
  * **ADVISORY + EV-RANKED, NEVER A HARD BLOCK.** Mid-engagement this ledger
    only reports; it MUST NOT refuse a transition or exit non-zero. The single
    terminal backstop is a separate projection. Nothing here raises to gate.
  * **NEVER count a self-attested-without-evidence signal.** A failed/blocked/
    empty probe, an evidence-free "covered" coverage_item, or a dispatch merely
    flagged ``status="completed"`` does NOT satisfy a class (S5/S7).
  * **CLASS COVERAGE COMES FROM EVIDENCE, NOT DECLARATIONS** (S7). Which classes
    a unit covered is decided by the ``attack_family`` on recorded probe_runs and
    coverage_items — what was demonstrably probed. A dispatch matches a unit only
    by its concrete ``application_unit_id`` plus ``status``; its
    self-declared ``vuln_classes``/``skills`` and its free-text ``task`` are never
    read as coverage, so no dispatch can satisfy a class it did not probe and the
    operator never has to name the vulnerability class before the hunt.
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

import json
from pathlib import Path
from typing import Any

from .taxonomy_bridge import vuln_taxonomy

from ..events import _engagement_or_404
from ..engagement_tracks import has_track
from . import _common
from ._common import _fetch_all
from .app_units import (
    score_application_units,
    _path_has_segment_token,
    _path_under_prefix,
    _port_class,
    _id_like_keys,
    _schema_nonempty,
    _split_host_path,
    _surface_host_path,
    _params_match_tokens,
    _SSRF_PARAM_TOKENS,
    _FILE_TOKENS,
    _AUTH_PATH_TOKENS,
    _WORKFLOW_TOKENS,
    _DECISIVE_SURFACE_TYPES,
    CONF_HIGH,
)
from .coverage import (
    PROBE_RESULT_STATUSES_COVERING,
    _engagement_scope_admission,
    _host_admitted_by_scope,
)


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

_IDENTITY_OUTCOME_DIFFERENCE_LIMIT = 20


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
    if not has_track(Path(engagement.engagement_root), "web"):
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
            "tool_name, target_host, target_path, target_port, auth_context, "
            "observed_http_status, outcome_assertion, evidence_ref, finding_id "
            "FROM assessment_probe_runs WHERE engagement_id = ?",
            (eng_id,),
        )
        dispatches = _fetch_all(
            connection,
            "SELECT id, agent_id, agent_role, application_unit_id, vuln_classes, "
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

    # I-07 scope admission: drop out-of-scope units (wildcard co-tenants, vendor/
    # SSO/CDN hosts) so a host the engagement does not own never becomes a depth
    # blocker — the SAME primitive ``web_uncovered_high_route_hosts`` uses. The
    # scorer already excludes them at write time and ``_prune_stale_units`` clears
    # any pre-existing rows; this read-side filter keeps the projection correct
    # even against a stale keyset. None => scope undeterminable => fail OPEN.
    scope_admission = _engagement_scope_admission(engagement)
    if scope_admission is not None:
        units = [
            u
            for u in units
            if _host_admitted_by_scope(
                str(u["host"] or "").lower(), scope_admission[0], scope_admission[1]
            )
        ]

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
    # RAW split: this matches a cred host against an already-trusted unit host, so
    # it must not be gated by the ingest-side hostname validator (the dotted
    # ``_HOST_TOKEN_RE`` pass below is the real extractor either way).
    parsed_host, _ = _split_host_path(value)
    if parsed_host and "." in parsed_host:
        out.add(parsed_host)
    for m in _HOST_TOKEN_RE.finditer(value):
        out.add(m.group(1).lower())
    return out


def _unit_scope(
    unit: dict[str, Any],
    *,
    variant_by_id: dict[int, dict[str, Any]],
    status_by_variant: dict[int, list[int]],
    parsed_surfaces: list[tuple[str, str, str]],
) -> dict[str, Any]:
    """Assemble the per-unit derived scope both ``_unit_ledger`` and the
    by-family grid builder need: the unit's identity (host/port_class/prefix),
    its mapped request variants (+ ids), their paths/methods/observed statuses,
    and the surface types under it.

    Pure and side-effect-free — factored out of ``_unit_ledger`` so the by-family
    grid (``by_family_coverage``) computes ``_expected_families`` over the SAME
    inputs without duplicating the variant/surface assembly. ``_unit_ledger``'s
    behavior (and therefore ``depth_ledger()``'s output) is unchanged.
    """
    host = str(unit["host"]).lower()
    port_class = str(unit["port_class"])
    prefix = str(unit["path_prefix"])

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

    return {
        "unit_id": int(unit["id"]),
        "host": host,
        "port_class": port_class,
        "prefix": prefix,
        "unit_variants": unit_variants,
        "paths": paths,
        "methods": methods,
        "statuses": statuses,
        "unit_surface_types": unit_surface_types,
        "unit_variant_ids": {int(v["id"]) for v in unit_variants},
    }


def _covered_families_for_unit(
    unit_probes: list[dict[str, Any]],
    unit_coverage: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compute the COVERED-family evidence for a unit from its already-bucketed
    probes + coverage_items (§5.3 Covered definition).

    Returns the covering-probe families, the per-family covering identity sets
    (for the access-control cross-identity test), the disclosure-concrete flag,
    the covering coverage_item families, and their union ``covered_families``.

    Pure extraction of the inline block ``_unit_ledger`` used to carry; both
    ``_unit_ledger`` and ``by_family_coverage`` now share it. NEVER counts a
    self-attested-without-evidence signal: only whitelisted covering probe
    ``result_status`` values and notes-bearing covered/not-applicable
    coverage_items contribute (S5/S7). ``depth_ledger()`` output is unchanged.
    """
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

    return {
        "covering_probe_families": covering_probe_families,
        "covering_identities_by_family": covering_identities_by_family,
        "disclosure_concrete": disclosure_concrete,
        "covering_cov_families": covering_cov_families,
        "covered_families": covering_probe_families | covering_cov_families,
    }


def _identity_outcome_differences(
    unit_probes: list[dict[str, Any]],
    variant_by_id: dict[int, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return observed per-identity HTTP differences without inferring impact.

    ``observed_http_status`` is evidence, not a vulnerability verdict. Authored
    outcome assertions and finding links therefore live under a separate
    ``conclusions`` object and never change depth or coverage classification.
    """
    probes_by_variant: dict[int, list[dict[str, Any]]] = {}
    for probe in unit_probes:
        request_variant_id = probe.get("request_variant_id")
        if request_variant_id is None:
            continue
        probes_by_variant.setdefault(int(request_variant_id), []).append(probe)

    differences: list[dict[str, Any]] = []
    for request_variant_id in sorted(probes_by_variant):
        probes = probes_by_variant[request_variant_id]
        statuses_by_identity: dict[str, set[int]] = {}
        observed_probes_by_identity: dict[str, list[dict[str, Any]]] = {}
        for probe in probes:
            auth_context = str(probe.get("auth_context") or "").strip()
            observed_status = probe.get("observed_http_status")
            if not auth_context or observed_status is None:
                continue
            statuses_by_identity.setdefault(auth_context, set()).add(
                int(observed_status)
            )
            observed_probes_by_identity.setdefault(auth_context, []).append(probe)
        if len(statuses_by_identity) < 2:
            continue
        distinct_outcomes = {
            tuple(sorted(statuses)) for statuses in statuses_by_identity.values()
        }
        if len(distinct_outcomes) < 2:
            continue

        by_identity = []
        for auth_context in sorted(statuses_by_identity):
            identity_probes = observed_probes_by_identity[auth_context]
            by_identity.append(
                {
                    "auth_context": auth_context,
                    "observed_http_statuses": sorted(
                        statuses_by_identity[auth_context]
                    ),
                    "probe_count": len(identity_probes),
                    "evidence_refs": sorted(
                        {
                            str(probe.get("evidence_ref") or "").strip()
                            for probe in identity_probes
                            if str(probe.get("evidence_ref") or "").strip()
                        }
                    ),
                }
            )

        recorded_assertions = sorted(
            {
                (
                    str(probe.get("auth_context") or "").strip(),
                    str(probe.get("outcome_assertion") or "").strip(),
                    str(probe.get("evidence_ref") or "").strip(),
                )
                for probe in probes
                if str(probe.get("outcome_assertion") or "").strip()
            }
        )
        linked_finding_ids = sorted(
            {
                int(probe["finding_id"])
                for probe in probes
                if probe.get("finding_id") is not None
            }
        )
        variant = variant_by_id.get(request_variant_id, {})
        differences.append(
            {
                "request_variant_id": request_variant_id,
                "method": str(variant.get("method") or ""),
                "path": str(variant.get("normalized_path") or ""),
                "observation": {
                    "kind": "identity_http_status_difference",
                    "identity_count": len(statuses_by_identity),
                    "by_identity": by_identity,
                },
                "conclusions": {
                    "derived_from_status_difference": False,
                    "recorded_outcome_assertions": [
                        {
                            "auth_context": auth_context,
                            "assertion": assertion,
                            "evidence_ref": evidence_ref,
                        }
                        for auth_context, assertion, evidence_ref in recorded_assertions
                    ],
                    "linked_finding_ids": linked_finding_ids,
                },
            }
        )
    return differences


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
    scope = _unit_scope(
        unit,
        variant_by_id=variant_by_id,
        status_by_variant=status_by_variant,
        parsed_surfaces=parsed_surfaces,
    )
    unit_id = scope["unit_id"]
    host = scope["host"]
    port_class = scope["port_class"]
    prefix = scope["prefix"]
    risk_score = int(unit.get("risk_score") or 0)
    depth_tier = str(unit.get("depth_tier") or "thin")
    unit_variants = scope["unit_variants"]
    paths = scope["paths"]
    methods = scope["methods"]
    statuses = scope["statuses"]
    unit_surface_types = scope["unit_surface_types"]
    unit_variant_ids = scope["unit_variant_ids"]

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
    identity_outcome_differences = _identity_outcome_differences(
        unit_probes, variant_by_id
    )
    unit_has_covering_probe = any(
        str(p.get("result_status") or "").strip().lower() in PROBE_RESULT_STATUSES_COVERING
        for p in unit_probes
    )
    # Dispatch work-evidence (S7) asks only "does this UNIT have a covering probe
    # OR a finding" — it is dispatch-INDEPENDENT, so it is a per-unit constant, not
    # a per-dispatch probe rescan.
    unit_has_work_evidence = unit_has_covering_probe or bool(unit_findings)

    covered = _covered_families_for_unit(unit_probes, unit_coverage)
    covering_probe_families = covered["covering_probe_families"]
    covering_identities_by_family = covered["covering_identities_by_family"]
    disclosure_concrete = covered["disclosure_concrete"]
    covering_cov_families = covered["covering_cov_families"]
    covered_families = covered["covered_families"]

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

    dedicated = _dedicated_dispatch_satisfied(
        unit_id=unit_id,
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
        # Audit-only observation projection. It is intentionally excluded from
        # `covered`, `missing_*`, `depth_satisfied`, and EV calculations: a
        # status difference between identities is a review signal, not proof of
        # a vulnerability. Authored assertions/finding links remain separate.
        "identity_outcome_differences": identity_outcome_differences[
            :_IDENTITY_OUTCOME_DIFFERENCE_LIMIT
        ],
        "identity_outcome_difference_count": len(identity_outcome_differences),
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

    expected["disclosure"] = "every application unit (always expected)"

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


def _dispatch_targets_unit(dispatch: dict[str, Any], unit_id: int) -> bool:
    """Return whether the dispatch names this concrete application unit."""
    value = dispatch.get("application_unit_id")
    return value is not None and int(value) == unit_id


def _dedicated_dispatch_satisfied(
    *,
    unit_id: int,
    dispatches: list[dict[str, Any]],
    unit_has_work_evidence: bool,
) -> bool:
    """≥1 completed dispatch WITH WORK EVIDENCE was aimed at this unit (S7).

    A dispatch QUALIFIES when:
      * ``status='completed'`` AND
      * application_unit_id identifies the unit AND
      * ``unit_has_work_evidence`` — the unit has corroborating durable output
        (≥1 covering probe OR a recorded finding under it). ``status='completed'``
        ALONE, or accompanied only by a self-attested handoff, does NOT satisfy:
        the handoff ``summary``/``coverage_gaps`` are agent self-attestation and
        the doctrine forbids counting a self-attested-without-evidence signal
        (else one completed dispatch plus a bare handoff could satisfy a unit
        without work). Legitimate work the harness
        missed is recovered via the recorded depth-deferral / ``--force --reason``
        valve, not by trusting free text.

    Work evidence is a per-UNIT property (does the unit have a covering probe or a
    finding), NOT per-dispatch — so the caller computes it ONCE and passes it in,
    rather than re-scanning every probe per dispatch. With no work evidence, no
    dispatch can qualify.

    This answers only "was this unit actually worked", never "which classes did it
    cover". Class coverage is decided by ``missing_block`` from recorded probe and
    coverage-item ``attack_family`` — i.e. from what was demonstrably probed. A
    dispatch's declared ``vuln_classes``/``skills`` are an intent label the agent
    writes about itself, so gating on them would let a declaration that no probe
    backs satisfy the unit, while forcing the operator to name the vulnerability
    class up front — the pre-naming that caps a specialist at the operator's
    guess. Evidence answers the coverage question; this function answers only the
    assignment question.
    """
    if not unit_has_work_evidence:
        return False
    return any(
        str(d.get("status") or "").strip().lower() == "completed"
        and _dispatch_targets_unit(d, unit_id)
        for d in dispatches
    )


def _finding_maps_to_unit(
    finding: dict[str, Any], host: str, prefix: str,
) -> bool:
    loc = str(finding.get("canonical_location") or "")
    if not loc:
        return False
    # RAW split: ``host`` is the already-trusted unit host, so an equality match
    # must not be pre-filtered by the ingest-side hostname validator (avoids a
    # NEW false-block if a unit host is single-label / internal).
    f_host, f_path = _split_host_path(loc)
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
    # RAW split (compare-to-trusted-unit-host, ``or d_host`` fallback preserves
    # the exact deferral-host semantics regardless of hostname shape).
    parsed_host, _ = _split_host_path(d_host)
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


def by_family_coverage(connection, engagement_id: int) -> dict[str, Any]:
    """Engagement-wide (application-unit × vuln-family) coverage grid (A1).

    Unlike ``depth_ledger()`` — which scores only ``deep_required`` units for the
    depth gate — this projection walks EVERY application unit and, for each,
    reports one cell per vuln FAMILY in ``union(expected, probed)`` so an operator
    can SEE never-probed gaps vs probed-and-walled vs finding-linked BEFORE a phase
    exit. It is read-only/advisory (never mutates, never blocks).

    Each cell's ``status`` reuses the SAME covered/expected/deferred classification
    ``_unit_ledger`` applies (covering-probe evidence; disclosure needs a concrete
    tool; access-control needs ≥2 identities; a family with an active
    ``depth_deferral`` counts as deferred), so the grid never disagrees with the
    depth ledger on a shared cell. Per-family probe/finding stats are read off the
    SAME one-pass unit bucketing (``_probe_maps_to_unit``) the ledger uses — no
    O(units × probes) rescan per family.

    Shape::

        {"units": [{application_unit_id, host, port_class, path_prefix,
                    deep_required, families: [{family, expected_reason, status,
                    probe_count, covering_probe_count, has_finding, finding_id},
                    ...]}, ...],
         "totals": {units, cells, covered, missing_block, missing_warn,
                    deferred, with_finding}}
    """
    zero_totals = {
        "units": 0, "cells": 0, "covered": 0, "missing_block": 0,
        "missing_warn": 0, "deferred": 0, "with_finding": 0,
    }
    if vuln_taxonomy is None:
        return {"units": [], "totals": dict(zero_totals)}

    units = _fetch_all(
        connection,
        "SELECT * FROM assessment_application_units WHERE engagement_id = ? "
        "ORDER BY host, port_class, path_prefix",
        (engagement_id,),
    )
    variants = _fetch_all(
        connection,
        "SELECT id, scheme, host, port, method, normalized_path, auth_context, "
        "content_type_family, query_schema_json, body_schema_json, path_schema_json, "
        "header_schema_json FROM assessment_request_variants WHERE engagement_id = ?",
        (engagement_id,),
    )
    observations = _fetch_all(
        connection,
        "SELECT request_variant_id, response_status FROM assessment_request_observations "
        "WHERE engagement_id = ?",
        (engagement_id,),
    )
    surfaces = _fetch_all(
        connection,
        "SELECT surface_type, target_descriptor FROM assessment_surfaces WHERE engagement_id = ?",
        (engagement_id,),
    )
    coverage_items = _fetch_all(
        connection,
        "SELECT id, application_unit_id, request_variant_id, attack_family, status, notes "
        "FROM assessment_coverage_items WHERE engagement_id = ?",
        (engagement_id,),
    )
    probes = _fetch_all(
        connection,
        "SELECT id, application_unit_id, request_variant_id, attack_family, result_status, "
        "tool_name, target_host, target_path, target_port, auth_context, finding_id "
        "FROM assessment_probe_runs WHERE engagement_id = ?",
        (engagement_id,),
    )
    creds = _fetch_all(
        connection,
        "SELECT credential_key, principal, provenance_json "
        "FROM assessment_credentials WHERE engagement_id = ?",
        (engagement_id,),
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
        s_host, s_path = _surface_host_path(str(s.get("target_descriptor") or ""))
        if s_host:
            parsed_surfaces.append((s_host, s_path, str(s.get("surface_type") or "")))

    cred_hosts: set[str] = set()
    for c in creds:
        for raw in (c.get("credential_key"), c.get("principal"), c.get("provenance_json")):
            for tok in _extract_host_tokens(str(raw or "")):
                cred_hosts.add(tok)

    active_deferrals = _active_depth_deferrals(engagement_id)

    totals = dict(zero_totals)
    totals["units"] = len(units)
    result_units: list[dict[str, Any]] = []

    for unit in units:
        scope = _unit_scope(
            unit,
            variant_by_id=variant_by_id,
            status_by_variant=status_by_variant,
            parsed_surfaces=parsed_surfaces,
        )
        unit_id = scope["unit_id"]
        host = scope["host"]
        port_class = scope["port_class"]
        prefix = scope["prefix"]
        unit_variant_ids = scope["unit_variant_ids"]

        expected = _expected_families(
            unit_variants=scope["unit_variants"],
            paths=scope["paths"],
            methods=scope["methods"],
            statuses=scope["statuses"],
            unit_surface_types=scope["unit_surface_types"],
            host=host,
            cred_hosts=cred_hosts,
        )

        # ONE bucketing pass per unit (identical predicate to the depth ledger).
        unit_probes = [
            p for p in probes
            if _probe_maps_to_unit(p, unit_id, unit_variant_ids, host, port_class, prefix)
        ]
        unit_coverage = [
            ci for ci in coverage_items if _coverage_maps_to_unit(ci, unit_id, unit_variant_ids)
        ]
        covered = _covered_families_for_unit(unit_probes, unit_coverage)

        deferred_families: set[str] = set()
        for row in active_deferrals:
            payload = row.get("payload") or {}
            if not _deferral_applies_to_unit(payload, host, prefix):
                continue
            for cls in payload.get("vuln_classes") or []:
                fam = vuln_taxonomy.family_of(vuln_taxonomy.normalize_class(str(cls)))
                if fam:
                    deferred_families.add(fam)

        # Per-family probe stats off the SAME bucketed probes — never a per-family
        # rescan. ``finding_id`` is the MIN non-null linkage in the family bucket
        # (probes carry it; per-input coverage cells do not) — ``min`` rather than
        # "first row seen" so the reported id is DETERMINISTIC regardless of the
        # unordered ``SELECT`` scan order. ``has_finding`` stays "any probe in the
        # bucket carries a finding".
        probe_stats: dict[str, dict[str, Any]] = {}
        observed_families: set[str] = set()
        for p in unit_probes:
            fam = vuln_taxonomy.family_of(
                vuln_taxonomy.normalize_class(str(p.get("attack_family") or ""))
            )
            if not fam:
                continue
            observed_families.add(fam)
            st = probe_stats.setdefault(
                fam, {"probe_count": 0, "covering_probe_count": 0, "finding_id": None}
            )
            st["probe_count"] += 1
            if str(p.get("result_status") or "").strip().lower() in PROBE_RESULT_STATUSES_COVERING:
                st["covering_probe_count"] += 1
            fid = p.get("finding_id")
            if fid is not None:
                fid = int(fid)
                if st["finding_id"] is None or fid < st["finding_id"]:
                    st["finding_id"] = fid

        ac_identities = covered["covering_identities_by_family"].get(ACCESS_CONTROL_FAMILY, set())

        families_out: list[dict[str, Any]] = []
        for fam in sorted(expected.keys() | observed_families):
            block_level = _FAMILY_BLOCK_LEVEL.get(fam, BLOCK_WARN)
            if fam == "disclosure":
                is_covered = covered["disclosure_concrete"]
            elif fam == ACCESS_CONTROL_FAMILY:
                is_covered = len(ac_identities) >= 2
            else:
                is_covered = fam in covered["covered_families"]

            if is_covered:
                status_label = "covered"
            elif fam in deferred_families:
                status_label = "deferred"
            elif block_level == BLOCK_HIGH:
                status_label = "missing_block"
            else:
                status_label = "missing_warn"

            stats = probe_stats.get(fam)
            probe_count = int(stats["probe_count"]) if stats else 0
            covering_probe_count = int(stats["covering_probe_count"]) if stats else 0
            finding_id = stats["finding_id"] if stats else None
            has_finding = finding_id is not None

            families_out.append({
                "family": fam,
                "expected_reason": expected.get(fam),
                "status": status_label,
                "probe_count": probe_count,
                "covering_probe_count": covering_probe_count,
                "has_finding": has_finding,
                "finding_id": finding_id,
            })

            totals["cells"] += 1
            totals[status_label] += 1
            if has_finding:
                totals["with_finding"] += 1

        result_units.append({
            "application_unit_id": unit_id,
            "host": host,
            "port_class": port_class,
            "path_prefix": prefix,
            "deep_required": bool(int(unit.get("deep_required") or 0)),
            "families": families_out,
        })

    return {"units": result_units, "totals": totals}


__all__ = ["depth_ledger", "terminal_depth_block", "by_family_coverage"]
