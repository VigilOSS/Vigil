"""vigil assess ingest-candidates — ingest metadata-rich surface candidate JSONL."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from assess.lib.auth import auth_active_context
from assess.lib.bulk_ingest import DEFAULT_BULK_WRITE_SIZE, post_request_observations_bulk
from assess.lib.candidate_records import candidate_metadata, candidate_type, json_text, signal_tokens, surface_refs
from assess.lib.classify_buckets import CLASSIFIER_VERSION, INERT_TYPES, tagged_terminal_reason
from assess.lib.client import AssessmentClient
from assess.lib.config import load_config
from assess.lib.params import extract_path_params, extract_query_params, extract_url_path, generate_params_sig
from assess.lib.scope import host_admitted, ingest_scope_filter
from assess.lib.surface_links import create_surface_request_variant_link


def _coerce_header_params(value: object) -> dict[str, str]:
    """Normalize a candidate record's header field to dict[str, str].

    Accepts the dict shape (``{"X-Api-Key": "demo"}``, matching the backend's
    ``header_schema``) and the list-of-names shape used elsewhere in this
    codebase (``["X-Api-Key"]``, e.g. arjun_enrich.py/ingest_arjun.py),
    mapping list entries to an empty example value. Anything else (string,
    number, None) falls back to ``{}`` rather than reaching the backend as a
    non-dict and 422-ing the whole candidate.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, list):
        return {str(name): "" for name in value if str(name).strip()}
    return {}


def register(subparsers) -> None:
    p = subparsers.add_parser(
        "ingest-candidates",
        help="Ingest metadata-rich surface candidate JSONL into assessment state",
    )
    p.add_argument("source", help="Source name (e.g. surface-collector-curated)")
    p.add_argument("records_file", help="Path to candidate_records.jsonl")
    p.set_defaults(func=run)


def run(args) -> None:
    records_file = args.records_file
    source = args.source

    if not Path(records_file).is_file():
        print(f"ERROR: candidate records file not found: {records_file}", file=sys.stderr)
        sys.exit(1)

    cfg = load_config(args.engagement_dir)
    eng_dir = cfg.engagement_dir
    auth_context = auth_active_context(eng_dir)
    count = 0

    # Scope admission gate (defense-in-depth) — same per-URL semantics as
    # ingest-endpoints. A curated candidate row whose host is not admitted by
    # scope.json (e.g. carried through from a gau/wayback corpus) is recorded
    # skipped instead of admitted as probeable work. Inactive when scope.json has
    # no allowlist or enables the global bypass (see scope.ingest_scope_filter).
    scope_allow, scope_deny, scope_filter_active = ingest_scope_filter(eng_dir)
    out_of_scope_count = 0
    out_of_scope_warned_hosts: set[str] = set()
    skipped_backend = 0
    links_created = 0
    links_skipped = 0

    with AssessmentClient(cfg.base_url, cfg.engagement_key) as client:
        pending_rows: list[dict] = []
        pending_observations: list[dict] = []
        pending_direct: list[dict] = []

        def _flush_direct() -> None:
            if not pending_direct:
                return
            items = list(pending_direct)
            pending_direct.clear()
            for start in range(0, len(items), DEFAULT_BULK_WRITE_SIZE):
                chunk = items[start:start + DEFAULT_BULK_WRITE_SIZE]
                if chunk:
                    client.post("work-items/bulk", {"items": chunk})

        def _flush_observations() -> None:
            nonlocal count, skipped_backend, links_created, links_skipped
            if not pending_observations:
                return
            rows = list(pending_rows)
            observations = list(pending_observations)
            pending_rows.clear()
            pending_observations.clear()

            responses = post_request_observations_bulk(
                client,
                observations,
                warn_prefix="ingest-candidates",
                fallback_individual=True,
            )
            for row, response in zip(rows, responses, strict=True):
                if isinstance(response, Exception):
                    skipped_backend += 1
                    print(
                        f"ingest-candidates: backend rejected {row['url']}: "
                        f"{response}; skipping this candidate",
                        file=sys.stderr,
                    )
                    continue
                # The work item is derived server-side from the observation's
                # work_item block (ADR 0013). We still read the response's
                # request_variant id to attach surface_refs links.
                request_variant_id = None
                try:
                    request_variant_id = response.get("request_variant", {}).get("id")
                except (AttributeError, TypeError):
                    pass
                count += 1

                if row["surface_refs"]:
                    if not request_variant_id:
                        # A service-only resolution (no request_variant_id) has
                        # nothing for the link to attach to — surface_refs is
                        # silently unusable here, but the operator must see why.
                        links_skipped += len(row["surface_refs"])
                        print(
                            f"ingest-candidates: {row['url']} resolved to a service "
                            f"only (no request_variant_id); dropping {len(row['surface_refs'])} "
                            f"surface_refs link(s)",
                            file=sys.stderr,
                        )
                    else:
                        for surface_id in row["surface_refs"]:
                            try:
                                create_surface_request_variant_link(
                                    client,
                                    surface_id=surface_id,
                                    request_variant_id=int(request_variant_id),
                                    evidence_ref=row["evidence_ref"],
                                )
                                links_created += 1
                            except Exception as link_exc:  # noqa: BLE001 - a bad surface ref must not drop ingest
                                links_skipped += 1
                                print(
                                    f"ingest-candidates: failed to link surface {surface_id} "
                                    f"to request_variant {request_variant_id} for {row['url']}: "
                                    f"{link_exc}; skipping this link",
                                    file=sys.stderr,
                                )

        with open(records_file, "r", encoding="utf-8") as input_stream:
            for line in input_stream:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue

                method = str(record.get("method") or "GET").upper()
                url = str(record.get("url") or "").split()[0]
                if not url or any(tok in url for tok in ("FUZZ", "PARAM", "{{")):
                    continue
                if not url.startswith(("http://", "https://")):
                    if re.match(r"^[a-zA-Z0-9][-a-zA-Z0-9.]*\.[a-zA-Z]{2,}", url):
                        url = f"https://{url}"
                if not url:
                    continue

                url_path = str(record.get("url_path") or record.get("path") or "")
                if not url_path or url_path == "null":
                    url_path = extract_url_path(url)
                query_params = record.get("query_params") or extract_query_params(url)
                body_params = record.get("body_params") or {}
                path_params = record.get("path_params") or extract_path_params(url_path)
                cookie_params = record.get("cookie_params") or {}
                # `header_params` is conventionally a list[str] of header names
                # elsewhere in this codebase (arjun_enrich.py, ingest_arjun.py),
                # but the backend's header_schema is dict[str, Any] — coerce
                # either shape so a list-shaped record doesn't 422 the whole
                # candidate (header_schema was previously always {}, so this
                # path was unreachable before headers were wired through).
                header_params = _coerce_header_params(record.get("headers") or record.get("header_params"))
                evidence_ref = str(record.get("evidence_ref") or "")

                signals = signal_tokens(record)
                case_type = candidate_type(record, method, url_path, signals)
                metadata = candidate_metadata(record, case_type, signals)
                params_sig = generate_params_sig(query_params, body_params)
                parsed = urlparse(url)
                cand_host = (parsed.hostname or "").rstrip(".").lower()

                # Out-of-scope candidates are recorded skipped and never POSTed as
                # observations (so no service/surface is created for an
                # out-of-scope host) — auditable + reversible, identical to the
                # ingest-endpoints gate.
                if (
                    scope_filter_active
                    and cand_host
                    and not host_admitted(cand_host, scope_allow, scope_deny)
                ):
                    out_of_scope_count += 1
                    if cand_host not in out_of_scope_warned_hosts:
                        out_of_scope_warned_hosts.add(cand_host)
                        print(
                            f"WARN: {cand_host} is out of scope (no scope.json "
                            f"allowlist match, or matched an out_of_scope carve-out). "
                            f"Recording its candidate URLs as skipped "
                            f"(terminal_reason='out-of-scope') instead of admitting them.",
                            file=sys.stderr,
                        )
                    pending_direct.append({
                        "queue_key": f"skipped:out-of-scope:{cand_host}:{url}",
                        "method": method,
                        "url": url,
                        "url_path": url_path,
                        "host": cand_host,
                        "query_params": json.dumps(query_params) if isinstance(query_params, dict) else str(query_params),
                        "body_params": json.dumps(body_params) if isinstance(body_params, dict) else str(body_params),
                        "path_params": json.dumps(path_params) if isinstance(path_params, dict) else str(path_params),
                        "cookie_params": json.dumps(cookie_params) if isinstance(cookie_params, dict) else str(cookie_params),
                        "type": case_type,
                        "source": source,
                        "status": "skipped",
                        "params_key_sig": params_sig,
                        "auth_context": auth_context,
                        "cluster_key": "skipped:out-of-scope",
                        "terminal_reason": tagged_terminal_reason("out-of-scope", cand_host),
                    })
                    if len(pending_direct) >= DEFAULT_BULK_WRITE_SIZE:
                        _flush_direct()
                    continue

                observation_payload: dict[str, object] = {
                    "source": source,
                    "candidate_metadata": metadata,
                }
                observation = {
                    "url": url,
                    "method": method,
                    "auth_context": auth_context,
                    "content_type_family": "unknown",
                    "query_schema": query_params,
                    "body_schema": body_params,
                    "path_schema": path_params,
                    "cookie_schema": cookie_params,
                    "header_schema": header_params,
                    "path_template": "",
                    "discovery_source": source,
                    "notes": str(metadata.get("triage_rationale") or ""),
                    "response_status": None,
                    "evidence_ref": evidence_ref,
                    "observation_payload": observation_payload,
                    "target_identity": parsed.hostname or "",
                    "target_kind": "host",
                    "target_notes": "",
                    "target_ip_address": None,
                    "target_hostname": parsed.hostname,
                    "banner": "",
                    "coverage_candidates": [],
                    "auto_generate_coverage": True,
                    # Curated work-buffer derivation block — the backend derives
                    # the assessment_work_items row from this in the same
                    # transaction, carrying the candidate's curated metadata.
                    "work_item": {
                        "case_type": case_type,
                        "source": source,
                        "status": "skipped" if case_type in INERT_TYPES else "pending",
                        "url_path": url_path,
                        "query_params": json.dumps(query_params) if isinstance(query_params, dict) else str(query_params),
                        "body_params": json.dumps(body_params) if isinstance(body_params, dict) else str(body_params),
                        "path_params": json.dumps(path_params) if isinstance(path_params, dict) else str(path_params),
                        "cookie_params": json.dumps(cookie_params) if isinstance(cookie_params, dict) else str(cookie_params),
                        "headers": json.dumps(header_params) if isinstance(header_params, dict) and header_params else "",
                        "params_key_sig": params_sig,
                        "priority_score": metadata.get("priority_score") or 0,
                        "priority_reason": metadata.get("priority_reason") or "",
                        "cluster_key": metadata.get("cluster_key") or "",
                        "terminal_reason": metadata.get("terminal_reason") or "",
                        "classifier_version": CLASSIFIER_VERSION,
                        "signals": json_text(metadata.get("signals")) if metadata.get("signals") else "",
                        "selected_by": metadata.get("selected_by") or "",
                        "triage_rationale": metadata.get("triage_rationale") or "",
                        "live_status": metadata.get("live_status") or "",
                    },
                }

                pending_rows.append(
                    {
                        "method": method,
                        "url": url,
                        "url_path": url_path,
                        "query_params": query_params,
                        "body_params": body_params,
                        "path_params": path_params,
                        "cookie_params": cookie_params,
                        "headers": header_params,
                        "case_type": case_type,
                        "params_sig": params_sig,
                        "metadata": metadata,
                        "evidence_ref": evidence_ref,
                        "surface_refs": surface_refs(record),
                    }
                )
                pending_observations.append(observation)
                if len(pending_observations) >= DEFAULT_BULK_WRITE_SIZE:
                    _flush_observations()
        _flush_observations()
        _flush_direct()

    print(f"[ingest] Ingested {count} candidate records from source '{source}'")
    if links_created or links_skipped:
        print(
            f"[ingest] Created {links_created} surface link(s) from candidate "
            f"surface_refs; skipped {links_skipped}."
        )
    if skipped_backend:
        print(
            f"[ingest] Skipped {skipped_backend} candidate(s) rejected by the backend "
            f"(see warnings above).",
            file=sys.stderr,
        )
    if out_of_scope_count:
        print(
            f"[ingest] Excluded {out_of_scope_count} candidate(s) across "
            f"{len(out_of_scope_warned_hosts)} out-of-scope host(s) "
            f"(status='skipped', terminal_reason='out-of-scope'). Reachable but not "
            f"in scope.json — fix scope.json and re-ingest to admit them; review with "
            f"`vigil assess work-buffer stats --by reason`.",
            file=sys.stderr,
        )
