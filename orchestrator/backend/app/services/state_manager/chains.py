from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from fastapi import HTTPException, status

from ...retry_state import RETRY_STATES
from ..events import _engagement_or_404
from .. import credentials as _credential_store

from . import _common
from . import findings as _findings
from ._common import _fetch_all, _json_text, _merge_object_text, _normalize_severity, _resolve_existing_finding_slug, _slugify


def _require_retry_state(value: str) -> str:
    retry_state = str(value or "").strip()
    if retry_state not in RETRY_STATES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"invalid retry_state: {value!r}; expected one of "
                + ", ".join(RETRY_STATES)
            ),
        )
    return retry_state



def _upsert_chain_link(
    connection,
    engagement_id: int,
    *,
    chain_id: int,
    relation: str,
    entity_kind: str,
    entity_id: int | None,
    entity_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    if str(entity_kind) == "finding" and entity_ref:
        entity_ref = _resolve_existing_finding_slug(
            connection,
            engagement_id,
            entity_ref,
            field="entity_ref",
        )
    row = connection.execute(
        """
        SELECT *
        FROM assessment_attack_chain_links
        WHERE engagement_id = ? AND chain_id = ? AND relation = ? AND entity_kind = ? AND entity_id IS ? AND entity_ref = ?
        """,
        (engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref),
    ).fetchone()
    if row is None:
        cursor = connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (
                engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, chain_id, relation, entity_kind, entity_id, entity_ref, notes, _json_text(provenance)),
        )
        row = connection.execute("SELECT * FROM assessment_attack_chain_links WHERE id = ?", (cursor.lastrowid,)).fetchone()
    else:
        connection.execute(
            """
            UPDATE assessment_attack_chain_links
            SET notes = ?, provenance_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (_common._append_notes(row["notes"], notes), _merge_object_text(row["provenance_json"], provenance), row["id"]),
        )
        row = connection.execute("SELECT * FROM assessment_attack_chain_links WHERE id = ?", (row["id"],)).fetchone()
    assert row is not None
    return dict(row)

def create_attack_chain(
    engagement_id: int,
    *,
    chain_key: str | None,
    title: str,
    status_value: str,
    severity: str,
    narrative: str,
    evidence_ref: str,
    provenance: dict[str, Any] | None,
    links: list[dict[str, Any]] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    resolved_key = chain_key or _slugify(title)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """
            INSERT INTO assessment_attack_chains (
                engagement_id, chain_key, title, status, severity, narrative, evidence_ref, provenance_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, chain_key) DO UPDATE SET
                title = excluded.title,
                status = excluded.status,
                severity = excluded.severity,
                narrative = CASE WHEN excluded.narrative = '' THEN assessment_attack_chains.narrative ELSE excluded.narrative END,
                evidence_ref = COALESCE(NULLIF(excluded.evidence_ref, ''), assessment_attack_chains.evidence_ref),
                provenance_json = excluded.provenance_json,
                updated_at = CURRENT_TIMESTAMP
            """,
            (engagement.id, resolved_key, title, status_value, _normalize_severity(severity), narrative, evidence_ref, _json_text(provenance)),
        )
        row = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? AND chain_key = ?",
            (engagement.id, resolved_key),
        ).fetchone()
        assert row is not None
        chain = dict(row)
        chain_links = [
            _upsert_chain_link(
                connection,
                engagement.id,
                chain_id=chain["id"],
                relation=str(item.get("relation", "step")),
                entity_kind=str(item.get("entity_kind", "unknown")),
                entity_id=item.get("entity_id"),
                entity_ref=str(item.get("entity_ref", "")),
                notes=str(item.get("notes", "")),
                provenance=item.get("provenance"),
            )
            for item in (links or [])
        ]
    if evidence_ref:
        artifact_id = _common._register_artifact_reference(
            engagement.id,
            evidence_ref,
            kind="chain-evidence",
            related_chain_key=str(chain["chain_key"]),
        )
        with _common.get_connection() as connection:
            connection.execute(
                "UPDATE assessment_attack_chains SET evidence_artifact_id = ? WHERE id = ?",
                (artifact_id, int(chain["id"])),
            )
            chain = dict(connection.execute(
                "SELECT * FROM assessment_attack_chains WHERE id = ?",
                (int(chain["id"]),),
            ).fetchone())
    return {"chain": chain, "links": chain_links}

def create_attack_chain_link(
    engagement_id: int,
    *,
    chain_key: str,
    relation: str,
    entity_kind: str,
    entity_id: int | None,
    entity_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        chain = connection.execute(
            "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? AND chain_key = ?",
            (engagement.id, chain_key),
        ).fetchone()
        if chain is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="attack chain not found")
        return _upsert_chain_link(
            connection,
            engagement.id,
            chain_id=int(chain["id"]),
            relation=relation,
            entity_kind=entity_kind,
            entity_id=entity_id,
            entity_ref=entity_ref,
            notes=notes,
            provenance=provenance,
        )

def list_attack_chains(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_attack_chains WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def list_attack_chain_links(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        rows = connection.execute(
            """
            SELECT links.*, chains.chain_key
            FROM assessment_attack_chain_links AS links
            JOIN assessment_attack_chains AS chains ON chains.id = links.chain_id
            WHERE links.engagement_id = ?
            ORDER BY links.updated_at DESC, links.id DESC
            """,
            (engagement.id,),
        ).fetchall()
    return [dict(row) for row in rows]

def _upsert_simple_entity(
    connection,
    *,
    table: str,
    engagement_id: int,
    key_column: str,
    key_value: str,
    values: dict[str, Any],
) -> dict[str, Any]:
    columns = ", ".join(["engagement_id", key_column, *values.keys()])
    placeholders = ", ".join(["?"] * (2 + len(values)))
    assignments = ", ".join([f"{column} = excluded.{column}" for column in values.keys()])
    connection.execute(
        f"""
        INSERT INTO {table} ({columns})
        VALUES ({placeholders})
        ON CONFLICT(engagement_id, {key_column}) DO UPDATE SET
            {assignments},
            updated_at = CURRENT_TIMESTAMP
        """,
        (engagement_id, key_value, *values.values()),
    )
    row = connection.execute(
        f"SELECT * FROM {table} WHERE engagement_id = ? AND {key_column} = ?",
        (engagement_id, key_value),
    ).fetchone()
    assert row is not None
    return dict(row)

def record_credential(
    engagement_id: int,
    *,
    credential_key: str,
    kind: str,
    principal: str,
    secret: str,
    source_name: str,
    status_value: str,
    notes: str,
    provenance: dict[str, Any] | None,
    identity: str = "",
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    is_discovered = (status_value or "").strip().lower() == "discovered"
    with _common.get_connection() as connection:
        if is_discovered:
            # A discovered credential auto-mints a candidate finding. Validate
            # that finding's immutable author before persisting the credential,
            # otherwise an author refusal would leave a half-bridged row behind.
            existing_finding = connection.execute(
                """
                SELECT * FROM assessment_findings
                WHERE engagement_id = ?
                  AND defect_family = 'exposed-credential'
                  AND root_cause_key = ?
                  AND auth_context = 'unauthenticated'
                  AND canonical_location = ?
                  AND status != 'merged'
                ORDER BY id
                LIMIT 1
                """,
                (
                    engagement.id,
                    f"discovered-credential:{credential_key}",
                    f"credential:{credential_key}",
                ),
            ).fetchone()
            _findings._require_record_author_dispatch(
                connection,
                engagement.id,
                existing=existing_finding,
                provenance=provenance,
            )
        record = _upsert_simple_entity(
            connection,
            table="assessment_credentials",
            engagement_id=engagement.id,
            key_column="credential_key",
            key_value=credential_key,
            values={
                "kind": kind,
                "principal": principal,
                "secret": secret,
                "source_name": source_name,
                "status": status_value,
                "notes": notes,
                "provenance_json": _json_text(provenance),
                "identity": identity or "",
            },
        )
    # WS7 (multi-identity session store): a genuinely-DISCOVERED credential
    # (status 'discovered' — a find, not an operator-supplied known cred) is
    # auto-bridged to (a) a candidate finding whose severity the LLM confirms
    # from what it unlocks, and (b) — iff the secret is a session artifact — a
    # replayable engagement-credential identity, cross-linked back onto this row.
    # Operator-known creds (any other status) are recorded exactly as before.
    if is_discovered:
        bridged = _bridge_discovered_credential(
            engagement.id,
            record,
            kind=kind,
            secret=secret,
            source_name=source_name,
            provenance=provenance,
        )
        if bridged is not None:
            record = bridged
    return record


# --- WS7: found-credential -> intel + minted-identity + candidate-finding bridge ---

# Credential ``kind`` values (case-insensitive) that name a bearer/token secret
# outright, so a non-JWT opaque bearer still mints a replayable identity.
_BEARER_CREDENTIAL_KINDS = frozenset(
    {"bearer", "jwt", "token", "access_token", "session_token", "api_token", "session"}
)


def _looks_like_jwt(token: str) -> bool:
    """True when ``token`` has the three-segment shape of a JWT whose payload
    base64url-decodes to a JSON object (no signature check).

    Classification-only ("is this a session bearer?"); distinct from
    :func:`credentials._jwt_payload_claim`, which extracts an identity anchor and
    returns ``None`` for a valid-but-anchorless JWT.
    """
    parts = token.split(".")
    if len(parts) != 3 or not all(parts):
        return False
    payload = parts[1]
    try:
        padded = payload + "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        return isinstance(json.loads(decoded.decode("utf-8")), dict)
    except (ValueError, TypeError, json.JSONDecodeError, UnicodeDecodeError):
        return False


def _session_material_for_secret(kind: str, secret: str) -> dict[str, Any] | None:
    """Return engagement-credential material to mint when ``secret`` is a session
    artifact (a bearer/JWT, or a ``name=value`` session cookie), else ``None``.

    Reuses the session-cookie hint set + dequoting from
    :mod:`app.services.credentials` (import, don't duplicate) so this
    classification stays aligned with the capture-path derivation. A plain login
    password is NOT a session artifact -> ``None`` (the LLM will try logging in);
    the credential is still recorded as intel and still flags a candidate finding.
    """
    secret = (secret or "").strip()
    if not secret:
        return None
    kind_l = (kind or "").strip().lower()

    # 1. name=value session cookie — the NAME must be a known session-cookie hint
    #    (a plain `user=alice` or a rotating anti-CSRF cookie is not a session).
    if "=" in secret:
        name, _, raw_value = secret.partition("=")
        name = name.strip()
        value = _credential_store._dequote_cookie_value(raw_value.strip())
        if (
            name.lower() in _credential_store._SESSION_HINT_COOKIE_NAMES
            and isinstance(value, str)
            and value
        ):
            return {"cookies": {name: value}}

    # 2. bearer / JWT token — either it decodes as a JWT, or the credential kind
    #    explicitly names a bearer/token secret (opaque bearers have no shape).
    token = secret
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if token and (_looks_like_jwt(token) or kind_l in _BEARER_CREDENTIAL_KINDS):
        return {
            "headers": {"Authorization": f"Bearer {token}"},
            "tokens": {"access_token": token},
        }
    return None


def _mint_discovered_identity(
    engagement_id: int, *, kind: str, secret: str, credential_key: str
) -> str | None:
    """Mint a replayable engagement-credential identity from a discovered session
    artifact and return its ``identity_name``; ``None`` when the secret is not a
    session artifact (a plain password) so nothing is minted.

    The identity name is derived by the SAME
    :func:`credentials.derive_capture_identity` the proxy capture path uses, so a
    discovered session and a later proxy capture of the same login coalesce to one
    row (idempotent + churn-free) instead of appending a duplicate.
    """
    material = _session_material_for_secret(kind, secret)
    if material is None:
        return None
    identity_name = _credential_store.derive_capture_identity(
        material.get("cookies", {}) or {},
        material.get("headers", {}) or {},
        material.get("tokens", {}) or {},
    )
    if not identity_name:
        # Defensive: a session artifact should always derive an anchor, but never
        # skip minting on a surprise — fall back to a stable per-credential name.
        identity_name = "disc-" + hashlib.sha1(
            (credential_key or secret).encode("utf-8"), usedforsecurity=False
        ).hexdigest()[:10]
    material.setdefault("mode", "discovered")
    material.setdefault("auth_context", "authenticated")
    material.setdefault(
        "notes", f"Minted from discovered credential {credential_key}"
    )
    # A discovered secret is unreviewed: keep it opt-in. `make_active=False` alone
    # is not enough because default resolution falls back to the first non-dead row
    # when nothing is active — so mark it not-usable-for-requests too. It stays
    # selectable by explicit `--identity` and becomes usable once the operator
    # activates it (or a proxy capture of the same login upgrades it).
    material.setdefault("use_for_requests", False)
    _credential_store.upsert_material(
        engagement_id, identity_name, material, make_active=False
    )
    return identity_name


def _flag_discovered_credential_finding(
    engagement_id: int,
    *,
    credential_key: str,
    credential_id: int | None,
    principal: str,
    kind: str,
    source_name: str,
    minted_identity: str | None,
    provenance: dict[str, Any] | None,
) -> str:
    """Record (or refresh) a conservative candidate finding for a discovered
    credential and return its slug.

    Dedup is by the finding service's own semantic tuple — a stable
    ``root_cause_key``/``canonical_location`` derived from ``credential_key`` means
    re-recording the same credential UPDATES the one finding rather than spawning a
    duplicate. Severity is left at ``info`` (a placeholder) for the LLM to confirm
    from what the credential unlocks; the credential is referenced via the finding
    details/provenance and a ``credential`` link (no new schema column).
    """
    who = principal or kind or "unknown"
    if minted_identity:
        impact = (
            "A replayable session identity was minted from this secret "
            f"({minted_identity}); list it via the credential store, pick it, and "
            "probe what it unlocks."
        )
    else:
        impact = (
            "This looks like a login credential (not a session artifact); attempt "
            "authentication to establish what it unlocks."
        )
    summary = (
        f"Discovered credential recorded (principal {who!r}, kind {kind or 'unknown'}"
        f", source {source_name or 'unknown'}). {impact} Severity is a conservative "
        "placeholder — confirm real impact from what this credential grants."
    )
    details = {
        "discovered_credential": {
            "credential_key": credential_key,
            "credential_id": credential_id,
            "principal": principal,
            "kind": kind,
            "minted_identity": minted_identity,
            "session_minted": bool(minted_identity),
        }
    }
    finding_provenance = dict(provenance or {})
    finding_provenance.setdefault("discovered_credential_key", credential_key)
    links = [
        {
            "link_kind": "related",
            "target_kind": "credential",
            "target_id": credential_id,
            "target_ref": credential_key,
            "notes": "",
            "provenance": {},
        }
    ]
    result = _findings.create_finding(
        engagement_id,
        slug=None,
        title=(
            f"Discovered credential ({who}) — impact depends on what it unlocks"
        ),
        severity="info",
        workflow_status="draft",
        verification_status="unreviewed",
        defect_family="exposed-credential",
        root_cause_key=f"discovered-credential:{credential_key}",
        auth_context="unauthenticated",
        canonical_location=f"credential:{credential_key}",
        summary=summary,
        evidence_ref="",
        notes="",
        source_name=source_name or "operator",
        details=details,
        provenance=finding_provenance,
        request_variant_id=None,
        service_id=None,
        surface_id=None,
        links=links,
    )
    return str(result["finding"]["slug"])


def _bridge_discovered_credential(
    engagement_id: int,
    credential_row: dict[str, Any],
    *,
    kind: str,
    secret: str,
    source_name: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Bridge a just-recorded DISCOVERED credential to intel + finding + identity.

    Fires only from the ``status == 'discovered'`` record path. Always flags a
    candidate finding; additionally mints a replayable identity iff the secret is a
    session artifact. Finally cross-links this credential row back to the minted
    identity (``identity`` column) and the originating finding (``provenance_json``)
    and returns the refreshed row. Idempotent: the finding dedups on a stable tuple
    and the mint UPSERTs on a derived ``identity_name``, so re-recording the same
    credential neither duplicates the finding nor appends a second identity.
    """
    credential_key = str(credential_row.get("credential_key") or "")
    principal = str(credential_row.get("principal") or "")
    credential_id = credential_row.get("id")

    minted_identity = _mint_discovered_identity(
        engagement_id, kind=kind, secret=secret, credential_key=credential_key
    )
    finding_slug = _flag_discovered_credential_finding(
        engagement_id,
        credential_key=credential_key,
        credential_id=credential_id,
        principal=principal,
        kind=kind,
        source_name=source_name,
        minted_identity=minted_identity,
        provenance=provenance,
    )
    return _crosslink_discovered_credential(
        engagement_id,
        credential_key,
        minted_identity=minted_identity,
        finding_slug=finding_slug,
    )


def _crosslink_discovered_credential(
    engagement_id: int,
    credential_key: str,
    *,
    minted_identity: str | None,
    finding_slug: str,
) -> dict[str, Any] | None:
    """Cross-link the credential row to its minted identity + candidate finding.

    Sets ``identity`` to the minted identity name (preserving an
    operator-supplied identity if one is already present) and records the
    originating finding slug in ``provenance_json`` — both via existing columns,
    no schema change. Returns the refreshed row (or ``None`` if it vanished).
    """
    with _common.get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM assessment_credentials WHERE engagement_id = ? AND credential_key = ?",
            (engagement_id, credential_key),
        ).fetchone()
        if row is None:
            return None
        new_identity = str(row["identity"] or "") or (minted_identity or "")
        crosslink: dict[str, Any] = {"candidate_finding_slug": finding_slug}
        if minted_identity:
            crosslink["minted_identity"] = minted_identity
        merged_provenance = _merge_object_text(row["provenance_json"], crosslink)
        connection.execute(
            """
            UPDATE assessment_credentials
            SET identity = ?, provenance_json = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (new_identity, merged_provenance, row["id"]),
        )
        refreshed = connection.execute(
            "SELECT * FROM assessment_credentials WHERE id = ?",
            (row["id"],),
        ).fetchone()
    return dict(refreshed) if refreshed is not None else None

def list_credentials(
    engagement_id: int,
    *,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    sql = (
        "SELECT * FROM assessment_credentials WHERE engagement_id = ? "
        "ORDER BY updated_at DESC, id DESC"
    )
    params: list[Any] = [engagement.id]
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params.extend((int(limit), int(offset)))
    with _common.get_connection() as connection:
        return _fetch_all(connection, sql, tuple(params))

def record_credential_test(
    engagement_id: int,
    *,
    credential_id: int,
    service_id: int | None,
    target_ref: str,
    auth_context: str,
    outcome: str,
    evidence_ref: str,
    notes: str,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO assessment_credential_tests (
                engagement_id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement.id, credential_id, service_id, target_ref, auth_context, outcome, evidence_ref, notes),
        )
        row = connection.execute("SELECT * FROM assessment_credential_tests WHERE id = ?", (cursor.lastrowid,)).fetchone()
    assert row is not None
    return dict(row)

def list_credential_tests(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_credential_tests WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_access_record(
    engagement_id: int,
    *,
    access_key: str,
    credential_id: int | None,
    service_id: int | None,
    principal: str,
    access_level: str,
    target_ref: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_access_records",
            engagement_id=engagement.id,
            key_column="access_key",
            key_value=access_key,
            values={
                "credential_id": credential_id,
                "service_id": service_id,
                "principal": principal,
                "access_level": access_level,
                "target_ref": target_ref,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_access_records(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_access_records WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_pivot(
    engagement_id: int,
    *,
    pivot_key: str,
    access_record_id: int | None,
    source_ref: str,
    destination_ref: str,
    technique: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_pivots",
            engagement_id=engagement.id,
            key_column="pivot_key",
            key_value=pivot_key,
            values={
                "access_record_id": access_record_id,
                "source_ref": source_ref,
                "destination_ref": destination_ref,
                "technique": technique,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_pivots(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_pivots WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_tunnel(
    engagement_id: int,
    *,
    tunnel_key: str,
    pivot_id: int | None,
    tunnel_type: str,
    source_endpoint: str,
    destination_endpoint: str,
    status_value: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _upsert_simple_entity(
            connection,
            table="assessment_tunnels",
            engagement_id=engagement.id,
            key_column="tunnel_key",
            key_value=tunnel_key,
            values={
                "pivot_id": pivot_id,
                "tunnel_type": tunnel_type,
                "source_endpoint": source_endpoint,
                "destination_endpoint": destination_endpoint,
                "status": status_value,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )

def list_tunnels(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_tunnels WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))

def record_blocked_technique(
    engagement_id: int,
    *,
    technique_key: str,
    technique: str,
    target_kind: str,
    target_ref: str,
    reason: str,
    retry_state: str,
    evidence_ref: str,
    notes: str,
    provenance: dict[str, Any] | None,
    revalidation_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    engagement = _engagement_or_404(engagement_id)
    retry_state = _require_retry_state(retry_state)
    with _common.get_connection() as connection:
        previous = connection.execute(
            """
            SELECT * FROM assessment_blocked_techniques
            WHERE engagement_id = ? AND technique_key = ?
            """,
            (engagement.id, technique_key),
        ).fetchone()
        record = _upsert_simple_entity(
            connection,
            table="assessment_blocked_techniques",
            engagement_id=engagement.id,
            key_column="technique_key",
            key_value=technique_key,
            values={
                "technique": technique,
                "target_kind": target_kind,
                "target_ref": target_ref,
                "reason": reason,
                "retry_state": retry_state,
                "evidence_ref": evidence_ref,
                "notes": notes,
                "provenance_json": _json_text(provenance),
            },
        )
        previous_retry_state = (
            str(previous["retry_state"]) if previous is not None else None
        )
        if previous_retry_state is None:
            event_kind = "created"
        elif previous_retry_state == retry_state:
            event_kind = "revalidated"
        else:
            event_kind = "retry_state_changed"
        connection.execute(
            """
            INSERT INTO assessment_blocked_technique_history (
                engagement_id, blocked_technique_id, technique_key, event_kind,
                from_retry_state, to_retry_state, reason, evidence_ref, notes,
                provenance_json, revalidation_context_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement.id,
                int(record["id"]),
                technique_key,
                event_kind,
                previous_retry_state,
                retry_state,
                reason,
                evidence_ref,
                notes,
                _json_text(provenance),
                _json_text(revalidation_context),
            ),
        )
        return record

def list_blocked_techniques(engagement_id: int) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    with _common.get_connection() as connection:
        return _fetch_all(connection, "SELECT * FROM assessment_blocked_techniques WHERE engagement_id = ? ORDER BY updated_at DESC, id DESC", (engagement.id,))


def list_blocked_technique_history(
    engagement_id: int,
    *,
    technique_key: str = "",
    limit: int = 100,
) -> list[dict[str, Any]]:
    engagement = _engagement_or_404(engagement_id)
    bounded_limit = max(1, min(int(limit), 500))
    clauses = ["engagement_id = ?"]
    params: list[Any] = [engagement.id]
    if technique_key:
        clauses.append("technique_key = ?")
        params.append(technique_key)
    params.append(bounded_limit)
    with _common.get_connection() as connection:
        rows = _fetch_all(
            connection,
            "SELECT * FROM assessment_blocked_technique_history WHERE "
            + " AND ".join(clauses)
            + " ORDER BY id DESC LIMIT ?",
            tuple(params),
        )
    for row in rows:
        row["provenance"] = _common._json_object(row.pop("provenance_json", "{}"))
        row["revalidation_context"] = _common._json_object(
            row.pop("revalidation_context_json", "{}")
        )
        row["legacy_payload"] = _common._json_object(
            row.pop("legacy_payload_json", "{}")
        )
    return rows
