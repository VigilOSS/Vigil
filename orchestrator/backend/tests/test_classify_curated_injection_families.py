"""Fix 4 curation extended to the injection/file families (rce/lfi/ssti).

The redirect/ssrf curation handled the families the weak inner-token rescue would
MISROUTE. These three families are about PRECISION OF PRIORITY: a compound param
like `?cmd_exec=` / `?file_path=` / `?render_template=` would otherwise reach its
bucket only via the capped weak tier (score 20). Curating the common compound
names as whole keys promotes them to the bucket's full weight (rce=50, lfi=40,
ssti=25), so a real command-exec / file-inclusion / template surface is triaged
at its true severity.

Mirrors the `_classify_buckets()` loader convention in test_classify_precision.py.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path


def _cb():
    scripts = Path(__file__).resolve().parents[3] / "agent" / "scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    import assess.lib.classify_buckets as cb

    return cb


def _classify(url_path="/x", *, query=None):
    cb = _cb()
    return cb.classify_from_fields(
        case_type="unknown", url_path=url_path,
        query_params=json.dumps(query or {}),
    )


# --- rce (weight 50) ----------------------------------------------------------

def test_cmd_exec_compound_is_full_weight_rce():
    a = _classify(query={"cmd_exec": "ls"})
    assert a["cluster_key"] == "gf:rce"
    assert a["priority_score"] == 50  # full rce weight, NOT the weak cap (20)


def test_camelcase_runcommand_is_rce():
    a = _classify(query={"runCommand": "whoami"})  # -> runcommand
    assert a["cluster_key"] == "gf:rce"
    assert a["priority_score"] == 50


# --- lfi (weight 40) ----------------------------------------------------------

def test_file_path_compound_is_full_weight_lfi():
    a = _classify(query={"file_path": "../../etc/passwd"})
    assert a["cluster_key"] == "gf:lfi"
    assert a["priority_score"] == 40


def test_download_path_and_include_path_are_lfi():
    assert _classify(query={"download_path": "x"})["cluster_key"] == "gf:lfi"
    assert _classify(query={"includePath": "x"})["cluster_key"] == "gf:lfi"  # -> includepath


def test_config_file_is_lfi_not_other():
    a = _classify(query={"config_file": "app.ini"})
    assert a["cluster_key"] == "gf:lfi"


# --- ssti (weight 25) ---------------------------------------------------------

def test_template_string_compound_is_ssti():
    a = _classify(query={"template_string": "{{7*7}}"})
    assert a["cluster_key"] == "gf:ssti"
    assert a["priority_score"] == 25


def test_camelcase_rendertemplate_is_ssti():
    a = _classify(query={"renderTemplate": "x"})  # -> rendertemplate
    assert a["cluster_key"] == "gf:ssti"
