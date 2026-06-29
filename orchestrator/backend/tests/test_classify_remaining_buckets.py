"""Contract tests for the Phase 3 remaining gf buckets + extensions + floor.

classify-context-and-surface 2026-06, Part 3 Phase 3:

  * ``devops_console`` (weight 30) -> class ``debug-exposure``   (§A.7)
  * ``nosqli``         (weight 35) -> class ``nosqli``           (§A.8)
  * ``cloud_metadata`` (weight 40, FULL-URL regex) -> class ``ssrf`` (§B.10)
  * ``sso`` += ``/federationmetadata``                          (§C.12)
  * ``interestingext`` += VCS/IaC dotfiles                      (§C.13)
  * ``debug_logic`` += build/dependency manifests               (§C.13)
  * ``object-storage`` += bucket-listing params + host markers  (§C.14)
  * ``_TYPE_FLOOR["privileged_write"]`` -> ``privileged_action``/30 (§D.16)

Module/fixture conventions mirror ``test_classify_high_value_buckets.py`` /
``test_classify_buckets_storage_deser_debug.py`` (the ``_classify_buckets``
loader + the ``classify_from_fields`` call shape). The ``cloud_metadata`` and
``object-storage`` host-marker cases pass the full ``url`` kwarg (the boost-only
context input threaded by ``db.py``), exercising the supplementary
``_FULL_URL_REGEX_BUCKETS`` pass.
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


def _classify(
    url_path: str,
    *,
    case_type: str = "unknown",
    query_params: dict | None = None,
    body_params: dict | None = None,
    url: str | None = None,
):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
        url=url,
    )


# ---------------------------------------------------------------------------
# devops_console (weight 30) -> debug-exposure (§A.7)
# ---------------------------------------------------------------------------


def test_devops_console_grafana_fragment() -> None:
    a = _classify("/grafana/dashboards")
    assert a["cluster_key"] == "gf:devops_console"
    assert a["priority_score"] == 30
    assert "devops_console" in a["matched_buckets"]


def test_devops_console_api_datasources_fragment() -> None:
    a = _classify("/api/datasources")
    assert a["cluster_key"] == "gf:devops_console"
    assert a["priority_score"] == 30


def test_devops_console_docker_registry_catalog() -> None:
    """`/v2/_catalog` co-fires api-versioning(25, `/v2`); devops_console(30) wins."""
    a = _classify("/v2/_catalog")
    assert a["cluster_key"] == "gf:devops_console"
    assert a["priority_score"] == 30
    assert "devops_console" in a["matched_buckets"]


def test_devops_console_pprof_keeps_debug_logic_cluster() -> None:
    """`/debug/pprof` matches BOTH debug_logic(30, `/debug`) and devops_console(30,
    `/debug/pprof`); debug_logic is declared first, so the first-at-max-weight
    tie-break keeps cluster `gf:debug_logic` (no existing cluster_key change), with
    devops_console additively in the chain."""
    a = _classify("/debug/pprof")
    assert a["cluster_key"] == "gf:debug_logic"
    assert "devops_console" in a["matched_buckets"]


def test_devops_console_negative_boundary() -> None:
    """`/grafana` is boundary-anchored: `/grafanaland` (next char `l`) MUST NOT
    match devops_console."""
    a = _classify("/grafanaland/page")
    assert "devops_console" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# nosqli (weight 35) -> nosqli (§A.8)
# ---------------------------------------------------------------------------


def test_nosqli_bare_operator_param() -> None:
    a = _classify("/search", query_params={"$ne": "1"})
    assert a["cluster_key"] == "gf:nosqli"
    assert a["priority_score"] == 35
    assert "nosqli" in a["matched_buckets"]


def test_nosqli_compound_operator_param_survives_expand() -> None:
    """A compound key `username[$ne]` is split by `expand_compound_key` (on `[`/`]`)
    into the `$ne` token, so nosqli fires even though the operator is nested. (auth
    also fires here via the `username` token; this test only pins that the operator
    survived into the matcher.)"""
    a = _classify("/account", query_params={"username[$ne]": ""})
    assert "nosqli" in a["matched_buckets"]


def test_nosqli_search_path_fragment() -> None:
    a = _classify("/_search")
    assert a["cluster_key"] == "gf:nosqli"
    assert a["priority_score"] == 35


def test_nosqli_aggregate_path_fragment() -> None:
    a = _classify("/aggregate")
    assert a["cluster_key"] == "gf:nosqli"
    assert a["priority_score"] == 35


def test_nosqli_negative_exact_key_not_substring() -> None:
    """Matching is exact-key, not substring: a benign `negotiate` param (which
    merely CONTAINS the letters of `$ne` ... it does not) MUST NOT fire nosqli, and
    neither does a plain `id`."""
    a = _classify("/products", query_params={"negotiate": "1", "id": "5"})
    assert "nosqli" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# cloud_metadata (weight 40, full-URL regex) -> ssrf (§B.10)
# ---------------------------------------------------------------------------


def test_cloud_metadata_imds_address_in_url() -> None:
    """The link-local IMDS address sitting in a proof-param VALUE (only visible in
    the full url, not url_path) fires cloud_metadata via the full-URL pass."""
    a = _classify(
        "/about",
        url="https://host/about?next=http://169.254.169.254/latest/meta-data",
    )
    assert a["cluster_key"] == "gf:cloud_metadata"
    assert a["priority_score"] == 40
    assert "cloud_metadata" in a["matched_buckets"]


def test_cloud_metadata_obfuscated_hex_form() -> None:
    """`0xA9FEA9FE` is the hex of 169.254.169.254 (case-insensitive via the
    lowercased haystack + dual-case alternation)."""
    a = _classify("/about", url="https://host/about?u=http://0xA9FEA9FE/")
    assert a["cluster_key"] == "gf:cloud_metadata"
    assert a["priority_score"] == 40


def test_cloud_metadata_obfuscated_decimal_form() -> None:
    a = _classify("/about", url="https://host/about?u=http://2852039166/")
    assert "cloud_metadata" in a["matched_buckets"]
    assert a["priority_score"] == 40


def test_cloud_metadata_path_form_without_url() -> None:
    """The IMDS PATH literal in the url_path fires cloud_metadata via the normal
    `bucket_matches` regex pass (no full `url` needed)."""
    a = _classify("/latest/meta-data")
    assert a["cluster_key"] == "gf:cloud_metadata"
    assert a["priority_score"] == 40
    assert "cloud_metadata" in a["matched_buckets"]


def test_cloud_metadata_gcp_internal_host() -> None:
    a = _classify("/proxy-thing", url="https://host/proxy-thing?u=http://metadata.google.internal/")
    assert "cloud_metadata" in a["matched_buckets"]


def test_cloud_metadata_negative_no_imds() -> None:
    """No IMDS literal anywhere -> cloud_metadata MUST NOT fire (incl. a benign
    number like `169` that is not the link-local address)."""
    a = _classify("/products/169-deals", url="https://host/products/169-deals")
    assert "cloud_metadata" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# sso += /federationmetadata (§C.12)
# ---------------------------------------------------------------------------


def test_sso_federationmetadata_fragment() -> None:
    a = _classify("/federationmetadata/2007-06/federationmetadata.xml")
    assert a["cluster_key"] == "gf:sso"
    assert a["priority_score"] == 35
    assert "sso" in a["matched_buckets"]


def test_sso_federationmetadata_negative_boundary() -> None:
    a = _classify("/federationmetadatax/foo")
    assert "sso" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# interestingext += VCS/IaC dotfiles (§C.13)
# ---------------------------------------------------------------------------


def test_interestingext_svn_dir() -> None:
    a = _classify("/.svn/entries")
    assert a["cluster_key"] == "gf:interestingext"
    assert a["priority_score"] == 10
    assert "interestingext" in a["matched_buckets"]


def test_interestingext_tfstate() -> None:
    a = _classify("/infra/terraform.tfstate")
    assert a["cluster_key"] == "gf:interestingext"
    assert a["priority_score"] == 10


def test_interestingext_svn_negative_boundary() -> None:
    """`.svn` is boundary-anchored: `/notes.svnx` (next char `x`) MUST NOT match."""
    a = _classify("/notes.svnx")
    assert "interestingext" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# debug_logic += build/dependency manifests (§C.13)
# ---------------------------------------------------------------------------


def test_debug_logic_composer_json() -> None:
    a = _classify("/composer.json")
    assert a["cluster_key"] == "gf:debug_logic"
    assert a["priority_score"] == 30
    assert "debug_logic" in a["matched_buckets"]


def test_debug_logic_web_inf_descriptor() -> None:
    """`/WEB-INF/web.xml` (lowercased) is the Java deployment descriptor."""
    a = _classify("/WEB-INF/web.xml")
    assert a["cluster_key"] == "gf:debug_logic"
    assert a["priority_score"] == 30


def test_debug_logic_composer_json_negative_boundary() -> None:
    """The leading-slash form keeps boundary precision: `/mycomposer.json` (no
    `/composer.json` substring) MUST NOT match."""
    a = _classify("/mycomposer.json")
    assert "debug_logic" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# object-storage += bucket-listing params + host markers (§C.14)
# ---------------------------------------------------------------------------


def test_object_storage_list_type_param() -> None:
    a = _classify("/files", query_params={"list-type": "2"})
    assert a["cluster_key"] == "gf:object-storage"
    assert a["priority_score"] == 25
    assert "object-storage" in a["matched_buckets"]


def test_object_storage_marker_param() -> None:
    a = _classify("/objects", query_params={"marker": "abc"})
    assert a["cluster_key"] == "gf:object-storage"
    assert a["priority_score"] == 25


def test_object_storage_s3_host_marker() -> None:
    """The `.s3.amazonaws.com` host marker (URL authority, not url_path) fires
    object-storage via the full-URL pass."""
    a = _classify("/list", url="https://mybucket.s3.amazonaws.com/list")
    assert a["cluster_key"] == "gf:object-storage"
    assert a["priority_score"] == 25
    assert "object-storage" in a["matched_buckets"]


def test_object_storage_azure_blob_host_marker() -> None:
    a = _classify("/c", url="https://acct.blob.core.windows.net/c")
    assert "object-storage" in a["matched_buckets"]


def test_object_storage_negative_ordinary_host() -> None:
    a = _classify("/about", url="https://example.com/about")
    assert "object-storage" not in a["matched_buckets"]


# ---------------------------------------------------------------------------
# _TYPE_FLOOR["privileged_write"] -> privileged_action / 30 (§D.16)
# ---------------------------------------------------------------------------


def test_privileged_write_floor_routes_to_privileged_action() -> None:
    """A row a producer typed `privileged_write` with no bucket match floors to
    `gf:privileged_action`/30 (specialist routing for bfla)."""
    a = _classify("/billing/run", case_type="privileged_write")
    assert a["cluster_key"] == "gf:privileged_action"
    assert a["priority_score"] == 30
    assert a["priority_reason"] == "gf:privileged_action"
    assert a["matched_buckets"] == ["privileged_action"]
