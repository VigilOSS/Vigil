"""Regression tests for the post-implementation review fixes to the
classify-context-and-surface-buckets work.

Covers four defects found by the adversarial review:
  * cloud_metadata `/computeMetadata` path rule was DEAD (literal uppercase `M`
    against a lowercased, case-sensitive haystack) — now lowercased + anchored.
  * cloud_metadata `/latest/meta-data` and `/metadata/instance` were un-anchored
    substrings that false-positived on benign REST paths — now boundary-anchored.
  * oauth-oidc extension §C.11 was missing the `/connect/register` DCR endpoint.

Mirrors the `_classify_buckets()` loader convention in test_classify_precision.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(url_path: str, *, case_type: str = "unknown", query_params=None, body_params=None):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# --- cloud_metadata: the previously-dead GCP path form now fires --------------

def test_cloud_metadata_computemetadata_path_form_fires():
    """`/computeMetadata/...` is the GCP IMDS path form. It must cluster
    gf:cloud_metadata (weight 40) via the lowercased, anchored path rule — this
    was silently dead before the literal `M` was lowercased."""
    a = _classify("/computeMetadata/v1/instance/service-accounts/")
    assert a["cluster_key"] == "gf:cloud_metadata"
    assert a["priority_score"] == 40


def test_cloud_metadata_aws_meta_data_path_form_fires():
    a = _classify("/latest/meta-data/iam/security-credentials/")
    assert a["cluster_key"] == "gf:cloud_metadata"
    assert a["priority_score"] == 40


def test_cloud_metadata_azure_instance_path_form_fires():
    # Azure IMDS: `/metadata/instance?api-version=...` — the `?` is a boundary.
    a = _classify("/metadata/instance", query_params={"api-version": "2021-02-01"})
    assert a["cluster_key"] == "gf:cloud_metadata"


# --- cloud_metadata: anchoring rejects benign look-alike paths ----------------

def test_cloud_metadata_negative_plural_instances():
    """`/api/metadata/instances` (a plural listing route) must NOT fire
    cloud_metadata — the trailing `s` breaks the segment boundary."""
    a = _classify("/api/metadata/instances")
    assert "cloud_metadata" not in (a["priority_reason"] or "")
    assert a["cluster_key"] != "gf:cloud_metadata"


def test_cloud_metadata_negative_instance_types():
    a = _classify("/api/metadata/instance-types")
    assert "cloud_metadata" not in (a["priority_reason"] or "")


def test_cloud_metadata_negative_meta_database():
    """`/files/latest/meta-database` must NOT match the `/latest/meta-data` rule
    (the `meta-data` prefix of `meta-database` is no longer a substring hit)."""
    a = _classify("/files/latest/meta-database")
    assert "cloud_metadata" not in (a["priority_reason"] or "")
    assert a["cluster_key"] != "gf:cloud_metadata"


# --- oauth-oidc: DCR endpoint (§C.11) -----------------------------------------

def test_oauth_oidc_connect_register_is_dcr():
    """`/connect/register` is the OIDC Dynamic Client Registration endpoint.
    oauth-oidc is declared before trust_surface, so it must own the cluster
    (gf:oauth-oidc, weight 35) rather than the generic trust_surface `/connect`."""
    a = _classify("/connect/register")
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert "oauth-oidc" in a["priority_reason"]
    assert a["priority_score"] == 35
