"""Current authored reproduction identity shared by decision writes and exports."""
from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Iterable, Literal

from ._common import is_file_finding
from .proofs import proof_receipts_for_finding

ReproductionBasis = Literal["source", "runtime"]


def reproduction_sha256(finding: dict[str, Any]) -> str:
    details = finding.get("details")
    if not isinstance(details, dict):
        try:
            details = json.loads(str(finding.get("details_json") or "{}"))
        except json.JSONDecodeError:
            details = {}
    if not isinstance(details, dict):
        details = {}
    authored = {
        "steps_to_reproduce": details.get("steps_to_reproduce"),
        "repro_runs": details.get("repro_runs"),
    }
    raw = json.dumps(
        authored, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def reproduction_basis_for_receipts(
    canonical_location: str, receipts: Iterable[dict[str, Any]]
) -> ReproductionBasis:
    """``source`` when a file finding's current verdict rests only on source reads.

    A source-derived code finding is reproduced by reading the cited source, so no
    command run stands behind its steps. Any artifact or command receipt, a
    non-file location, or no current receipt at all makes the basis ``runtime``.
    """
    kinds = [str(receipt.get("evidence_kind") or "") for receipt in receipts]
    if (
        is_file_finding(canonical_location)
        and kinds
        and all(kind == "source_observation" for kind in kinds)
    ):
        return "source"
    return "runtime"


def reproduction_basis(
    connection: sqlite3.Connection, engagement_id: int, finding: dict[str, Any] | Any
) -> ReproductionBasis:
    record = dict(finding)
    return reproduction_basis_for_receipts(
        str(record.get("canonical_location") or ""),
        proof_receipts_for_finding(connection, engagement_id, int(record["id"])),
    )
