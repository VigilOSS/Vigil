"""Pinned observable output for the lightweight line-sink and callable readers.

Written before the per-line sink scans of `_extract_shell`, `_extract_lua`,
`_extract_html` and `_extract_css` moved onto module-level pattern tables, and
before the lua callable record started going through `_empty_func`. Every
assertion here records what `index_file` published already: the sink kind, the
vuln classes, the attributed function, the line and the snippet, including the
rows the per-language suites never exercised.
"""

import datetime as _dt
from pathlib import Path
from types import SimpleNamespace

import pytest

from assess.commands import kali_sweep_orphans as kso
from assess.lib.client import AssessError
from assess.lib.treesitter_index import index_file


def _sinks(file_path: str, language: str, source: str) -> list[dict[str, object]]:
    indexed = index_file(file_path, language, source.encode("utf-8"))
    assert indexed["analysis_status"] == "complete"
    return [
        {
            "kind": sink["kind"],
            "line": sink["line"],
            "function": sink["function"],
            "snippet": sink["snippet"],
            "vuln_classes": sink["vuln_classes"],
        }
        for sink in indexed["security_sinks"]
    ]


SHELL_SOURCE = """#!/bin/sh
deploy() {
  eval "$CMD"
  curl https://acme.example/install.sh | sh
  chmod -R 0777 /srv/acme
  sudo systemctl restart acme
  out=$(printf '%s' $1)
  export API_KEY="acme-static-token"
}
"""


def test_shell_line_sink_rows_each_publish_their_kind_classes_and_scope() -> None:
    assert _sinks("deploy.sh", "shell", SHELL_SOURCE) == [
        {
            "kind": "shell_eval",
            "line": 3,
            "function": "deploy",
            "snippet": 'eval "$CMD"',
            "vuln_classes": ["injection"],
        },
        {
            "kind": "remote_pipe_to_shell",
            "line": 4,
            "function": "deploy",
            "snippet": "curl https://acme.example/install.sh | sh",
            "vuln_classes": ["supply-chain", "injection"],
        },
        {
            "kind": "permissive_chmod",
            "line": 5,
            "function": "deploy",
            "snippet": "chmod -R 0777 /srv/acme",
            "vuln_classes": ["privilege-escalation"],
        },
        {
            "kind": "sudo",
            "line": 6,
            "function": "deploy",
            "snippet": "sudo systemctl restart acme",
            "vuln_classes": ["privilege-escalation"],
        },
        {
            "kind": "tainted_command_substitution",
            "line": 7,
            "function": "deploy",
            "snippet": "out=$(printf '%s' $1)",
            "vuln_classes": ["injection"],
        },
        {
            "kind": "hardcoded_credential",
            "line": 8,
            "function": "deploy",
            "snippet": 'export API_KEY="acme-static-token"',
            "vuln_classes": ["secrets-exposure"],
        },
    ]


def test_shell_one_line_can_publish_two_rows_in_catalogue_order() -> None:
    assert [
        (sink["kind"], sink["function"]) for sink in _sinks(
            "run.sh", "shell", "#!/bin/sh\nsudo eval \"$CMD\"\n"
        )
    ] == [("shell_eval", "<script>"), ("sudo", "<script>")]


def test_shell_comment_only_line_publishes_no_row() -> None:
    assert _sinks("run.sh", "shell", "#!/bin/sh\n# sudo eval \"$CMD\"\n") == []


LUA_SOURCE = """local function handle(key, value)
  redis.call(command, key)
  loadstring(value)()
  os.execute(value)
  io.popen(value)
end
"""


def test_lua_line_sink_rows_each_publish_their_kind_classes_and_scope() -> None:
    assert _sinks("handler.lua", "lua", LUA_SOURCE) == [
        {
            "kind": "redis_dynamic_command",
            "line": 2,
            "function": "handle",
            "snippet": "redis.call(command, key)",
            "vuln_classes": ["injection"],
        },
        {
            "kind": "dynamic_code_load",
            "line": 3,
            "function": "handle",
            "snippet": "loadstring(value)()",
            "vuln_classes": ["injection"],
        },
        {
            "kind": "os_execute",
            "line": 4,
            "function": "handle",
            "snippet": "os.execute(value)",
            "vuln_classes": ["injection"],
        },
        {
            "kind": "io_popen",
            "line": 5,
            "function": "handle",
            "snippet": "io.popen(value)",
            "vuln_classes": ["injection"],
        },
    ]


def test_lua_callable_record_publishes_its_name_params_and_span() -> None:
    indexed = index_file("handler.lua", "lua", LUA_SOURCE.encode("utf-8"))

    assert indexed["functions"] == [
        {
            "name": "handle",
            "qualified_name": "handle",
            "line_start": 1,
            "line_end": 6,
            "params": ["key", "value"],
            "modifiers": [],
            "annotations": [],
            "is_entry_point": False,
        }
    ]
    assert indexed["exports"] == []


def test_lua_non_local_function_is_exported() -> None:
    indexed = index_file("handler.lua", "lua", b"function handle(a)\nend\n")

    assert indexed["exports"] == [{"name": "handle", "kind": "lua_function", "line": 1}]
    assert indexed["functions"][0]["params"] == ["a"]


HTML_SOURCE = """<html>
<body onload="boot()"> <!-- boot the page -->
<a href="javascript:boot()">go</a>
<p>{{ user.name }}</p>
<p><% user.name %></p>
<script src="http://cdn.example/a.js"></script>
<script src="https://cdn.example/b.js"></script>
<iframe src="https://partner.example/widget"></iframe>
<!-- <div onclick="boot()"></div> -->
</body>
</html>
"""


def test_html_line_sink_rows_keep_their_label_and_snippet_the_raw_line() -> None:
    assert _sinks("index.html", "html", HTML_SOURCE) == [
        {
            "kind": "external_script_load",
            "line": 6,
            "function": "<html>",
            "snippet": '<script src="http://cdn.example/a.js"></script>',
            "vuln_classes": ["supply-chain", "xss"],
        },
        {
            "kind": "external_script_load",
            "line": 7,
            "function": "<html>",
            "snippet": '<script src="https://cdn.example/b.js"></script>',
            "vuln_classes": ["supply-chain"],
        },
        {
            "kind": "iframe_embed",
            "line": 8,
            "function": "<html>",
            "snippet": '<iframe src="https://partner.example/widget"></iframe>',
            "vuln_classes": ["clickjacking", "xss"],
        },
        {
            "kind": "inline_event_handler",
            "line": 2,
            "function": "<html>",
            "snippet": '<body onload="boot()"> <!-- boot the page -->',
            "vuln_classes": ["xss"],
        },
        {
            "kind": "javascript_url",
            "line": 3,
            "function": "<html>",
            "snippet": '<a href="javascript:boot()">go</a>',
            "vuln_classes": ["xss"],
        },
        {
            "kind": "template_interpolation",
            "line": 4,
            "function": "<template>",
            "snippet": "<p>{{ user.name }}</p>",
            "vuln_classes": ["xss", "ssti"],
        },
        {
            "kind": "asp_interpolation",
            "line": 5,
            "function": "<template>",
            "snippet": "<p><% user.name %></p>",
            "vuln_classes": ["xss", "ssti"],
        },
    ]


CSS_SOURCE = """.a { width: expression(alert(1)); } /* legacy IE */
.b { behavior: url(x.htc); }
.c { -moz-binding: url(x.xml); }
@import "http://cdn.example/a.css";
/* .d { behavior: url(y.htc); } */
"""


def test_css_line_sink_rows_keep_their_label_and_snippet_the_raw_line() -> None:
    assert _sinks("site.css", "css", CSS_SOURCE) == [
        {
            "kind": "external_css_import",
            "line": 4,
            "function": "<stylesheet>",
            "snippet": '@import "http://cdn.example/a.css";',
            "vuln_classes": ["supply-chain"],
        },
        {
            "kind": "css_expression",
            "line": 1,
            "function": "<stylesheet>",
            "snippet": ".a { width: expression(alert(1)); } /* legacy IE */",
            "vuln_classes": ["xss"],
        },
        {
            "kind": "css_behavior",
            "line": 2,
            "function": "<stylesheet>",
            "snippet": ".b { behavior: url(x.htc); }",
            "vuln_classes": ["xss"],
        },
        {
            "kind": "css_moz_binding",
            "line": 3,
            "function": "<stylesheet>",
            "snippet": ".c { -moz-binding: url(x.xml); }",
            "vuln_classes": ["xss"],
        },
    ]


@pytest.mark.parametrize(
    ("kind", "line_text"),
    [
        ("css_expression", ".a { width: EXPRESSION(alert(1)); }"),
        ("css_behavior", ".a { BEHAVIOR: url(x.htc); }"),
        ("css_moz_binding", ".a { -MOZ-BINDING: url(x.xml); }"),
    ],
)
def test_css_rows_stay_case_blind(kind: str, line_text: str) -> None:
    assert [sink["kind"] for sink in _sinks("site.css", "css", line_text + "\n")] == [kind]


@pytest.mark.parametrize(
    ("kind", "line_text"),
    [
        ("inline_event_handler", '<div ONCLICK="boot()"></div>'),
        ("javascript_url", '<a href="JAVASCRIPT:boot()">go</a>'),
    ],
)
def test_html_rows_stay_case_blind(kind: str, line_text: str) -> None:
    assert [sink["kind"] for sink in _sinks("i.html", "html", line_text + "\n")] == [kind]


# --- sweep-orphans: the three unverifiable pending-output paths -------------
#
# These counters feed `resume_brief._orphan_attention`, and each path prints its
# own warning sentence. Pinned before the shared bookkeeping moved into one
# helper.


class _PendingRowClient:
    """One terminal command-run row with committed pending output work."""

    def __init__(self, rows: list[dict], *, patch_result=None, patch_error=False):
        self._rows = rows
        self._patch_result = patch_result
        self._patch_error = patch_error
        self.patches: list[tuple[str, dict]] = []

    def get(self, endpoint: str):
        return self._rows if "offset=0" in endpoint else []

    def patch(self, endpoint: str, payload: dict, *, accept_409: bool = False):
        self.patches.append((endpoint, payload))
        if self._patch_error:
            raise AssessError("backend refused the write")
        return self._patch_result


def _pending_row(*, observed_at: str | None) -> dict:
    row = {
        "id": 1,
        "status": "completed",
        "run_uuid": "a1b2c3",
        "created_at": "2026-01-01T00:00:00Z",
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:05:00Z",
        "output_cleanup_status": "pending",
        "output_integrity_status": "pending",
    }
    if observed_at is not None:
        row["output_recovery_observed_at"] = observed_at
    return row


def _run_sweep(client, tmp_path: Path, *, dry_run: bool = False) -> dict:
    now = _dt.datetime(2026, 1, 1, 6, 0, 0, tzinfo=_dt.timezone.utc)
    return kso._sweep_command_runs(
        client,
        SimpleNamespace(dry_run=dry_run, container_name="vigil"),
        now,
        "2026-01-01T06:00:00Z",
        3600,
        tmp_path,
    )


def test_missing_recovery_baseline_counts_as_unverifiable(tmp_path, capsys) -> None:
    client = _PendingRowClient([_pending_row(observed_at=None)])

    summary = _run_sweep(client, tmp_path)

    assert client.patches == []
    assert summary["checked"] == 1
    assert summary["skipped"] == 1
    assert summary["skipped_unverifiable"] == 1
    assert summary["pending_recovery_failed"] == 1
    assert summary["pending_recovery_failed_ids"] == [1]
    assert summary["output_attention_action"] == kso._OUTPUT_ATTENTION_ACTION
    assert (
        "warning: pending-output recovery baseline is missing or unparseable "
        "for id=1; refusing client-time fallback"
    ) in capsys.readouterr().err


def test_failed_recovery_patch_counts_as_unverifiable(tmp_path, capsys) -> None:
    client = _PendingRowClient(
        [_pending_row(observed_at="2026-01-01T00:00:00Z")], patch_error=True
    )

    summary = _run_sweep(client, tmp_path)

    assert summary["checked"] == 1
    assert summary["skipped"] == 1
    assert summary["skipped_unverifiable"] == 1
    assert summary["pending_recovery_failed"] == 1
    assert summary["pending_recovery_failed_ids"] == [1]
    assert summary["recovered_pending"] == 0
    assert summary["output_attention_action"] == kso._OUTPUT_ATTENTION_ACTION
    assert (
        "warning: pending-output recovery PATCH failed for id=1: "
        "backend refused the write"
    ) in capsys.readouterr().err


def test_unproven_recovery_counts_as_unverifiable(tmp_path, capsys) -> None:
    client = _PendingRowClient(
        [_pending_row(observed_at="2026-01-01T00:00:00Z")],
        patch_result={"id": 1, "run_uuid": "a1b2c3", "status": "completed"},
    )

    summary = _run_sweep(client, tmp_path)

    assert len(client.patches) == 1
    assert summary["skipped_unverifiable"] == 1
    assert summary["pending_recovery_failed"] == 1
    assert summary["pending_recovery_failed_ids"] == [1]
    assert summary["recovered_pending"] == 0
    assert summary["output_attention_action"] == kso._OUTPUT_ATTENTION_ACTION
    assert (
        "warning: pending-output recovery was not proven for id=1: "
        "response did not prove pending-output adoption"
    ) in capsys.readouterr().err
