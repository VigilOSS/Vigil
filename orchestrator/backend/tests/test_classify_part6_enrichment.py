"""Contract tests for the Phase 2b upstream param/extension enrichment.

classify-context-and-surface 2026-06, Part 6 — widen the param-key / path-
fragment sets of buckets that ALREADY exist (no new buckets). One positive per
enriched row plus the named precision negatives:

  * ``redirect``          += goto, rt, to, domain, site            (weight 25)
  * ``lfi``               += folder, root, dir, inc, conf          (weight 40)
  * ``sqli``              += where, select, table, column, field,
                             from, row, sleep, fetch               (weight 40)
  * ``rce``               += ping, exe, func, function, cli, daemon (weight 50)
  * ``debug_logic`` (was path-only) param keys += debug, dbg, test  (weight 30)
  * ``privileged_action`` param-key form += grant, delete, create,
                             disable, enable, toggle, reset, rename,
                             modify, alter, clone                  (weight 30)
  * ``interestingext``    += .backup, .bkp, .cfg, .cnf, .crt, .csr,
                             .passwd, .pwd, .mdb, .rdp, .dat, .pac  (weight 10)

Negatives: ``?code=`` stays ``gf:oauth-oidc`` (NOT ``gf:rce`` — ``code`` is
deliberately NOT an rce key), and a ``.xml`` URL stays type ``data`` / never
enters ``interestingext``. The loader/fixture convention mirrors
``test_classify_high_value_buckets.py``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _classify_buckets():
    """Load the real ``assess.lib.classify_buckets`` module (sibling-suite loader)."""
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify_type():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify as classify

    return classify.classify_type


def _classify(
    url_path: str,
    *,
    case_type: str = "unknown",
    query_params: dict | None = None,
    body_params: dict | None = None,
):
    cb = _classify_buckets()
    return cb.classify_from_fields(
        case_type=case_type,
        url_path=url_path,
        query_params=json.dumps(query_params or {}),
        body_params=json.dumps(body_params or {}),
    )


# ---------------------------------------------------------------------------
# redirect (weight 25) — single-token open-redirect params
# ---------------------------------------------------------------------------


def test_redirect_goto_param() -> None:
    a = _classify("/go", query_params={"goto": "https://evil.example"})
    assert a["cluster_key"] == "gf:redirect"
    assert a["priority_score"] == 25
    assert "redirect" in a["matched_buckets"]


def test_redirect_site_param() -> None:
    a = _classify("/out", query_params={"site": "https://evil.example"})
    assert a["cluster_key"] == "gf:redirect"
    assert "redirect" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# lfi (weight 40) — directory/traversal params
# ---------------------------------------------------------------------------


def test_lfi_folder_param() -> None:
    a = _classify("/browse", query_params={"folder": "../../etc"})
    assert a["cluster_key"] == "gf:lfi"
    assert a["priority_score"] == 40
    assert "lfi" in a["matched_buckets"]


def test_lfi_inc_param() -> None:
    a = _classify("/page", query_params={"inc": "../../etc/passwd"})
    assert a["cluster_key"] == "gf:lfi"
    assert "lfi" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# sqli (weight 40) — SQL-keyword-flavored params
# ---------------------------------------------------------------------------


def test_sqli_where_param() -> None:
    a = _classify("/report", query_params={"where": "1=1"})
    assert a["cluster_key"] == "gf:sqli"
    assert a["priority_score"] == 40
    assert "sqli" in a["matched_buckets"]


def test_sqli_sleep_param() -> None:
    a = _classify("/report", query_params={"sleep": "5"})
    assert a["cluster_key"] == "gf:sqli"
    assert "sqli" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# rce (weight 50) — command-exec params
# ---------------------------------------------------------------------------


def test_rce_ping_param() -> None:
    a = _classify("/tools", query_params={"ping": "127.0.0.1"})
    assert a["cluster_key"] == "gf:rce"
    assert a["priority_score"] == 50
    assert "rce" in a["matched_buckets"]


def test_rce_daemon_param() -> None:
    a = _classify("/tools", query_params={"daemon": "restart"})
    assert a["cluster_key"] == "gf:rce"
    assert "rce" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# debug_logic (weight 30) — was path-only, now fires on debug-toggle params
# ---------------------------------------------------------------------------


def test_debug_logic_debug_param() -> None:
    a = _classify("/app/page", query_params={"debug": "1"})
    assert a["cluster_key"] == "gf:debug_logic"
    assert a["priority_score"] == 30
    assert "debug_logic" in a["matched_buckets"]


def test_debug_logic_test_param() -> None:
    a = _classify("/app/page", query_params={"test": "1"})
    assert a["cluster_key"] == "gf:debug_logic"
    assert "debug_logic" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# privileged_action (weight 30) — state-verb param NAMES
# ---------------------------------------------------------------------------


def test_privileged_action_delete_param() -> None:
    a = _classify("/account/settings", query_params={"delete": "1"})
    assert a["cluster_key"] == "gf:privileged_action"
    assert a["priority_score"] == 30
    assert "privileged_action" in a["matched_buckets"]
    # The path-predicate append must not double-list the bucket.
    assert a["priority_reason"].count("gf:privileged_action") == 1


def test_privileged_action_grant_param() -> None:
    a = _classify("/account/settings", query_params={"grant": "admin"})
    assert a["cluster_key"] == "gf:privileged_action"
    assert "privileged_action" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# interestingext (weight 10) — backup/cred/cert/db extensions
# ---------------------------------------------------------------------------


def test_interestingext_backup_extension() -> None:
    a = _classify("/db.backup")
    assert a["cluster_key"] == "gf:interestingext"
    assert a["priority_score"] == 10
    assert "interestingext" in a["matched_buckets"]


def test_interestingext_passwd_extension() -> None:
    a = _classify("/etc/shadow.passwd")
    assert a["cluster_key"] == "gf:interestingext"
    assert "interestingext" in a["matched_buckets"]


def test_interestingext_cfg_extension() -> None:
    a = _classify("/conf/app.cfg")
    assert a["cluster_key"] == "gf:interestingext"
    assert "interestingext" in a["matched_buckets"]


# ---------------------------------------------------------------------------
# Negatives (the named precision pins)
# ---------------------------------------------------------------------------


def test_code_param_stays_oauth_oidc_not_rce() -> None:
    """`?code=` is a high-frequency OAuth callback param; `code` was deliberately
    NOT added to rce, so the row clusters by its oauth-oidc PATH fragment."""
    a = _classify("/oauth2/authorize", query_params={"code": "abc123"})
    assert a["cluster_key"] == "gf:oauth-oidc"
    assert "rce" not in a["matched_buckets"]


def test_xml_url_stays_data_and_not_interestingext() -> None:
    """`.xml` is a legitimate data file (excluded from interestingext) and stays
    typed `data` by `classify_type`."""
    classify_type = _classify_type()
    assert classify_type("GET", "/exports/report.xml") == "data"
    a = _classify("/exports/report.xml", case_type="data")
    assert "interestingext" not in a["matched_buckets"]
    assert a["cluster_key"] != "gf:interestingext"
