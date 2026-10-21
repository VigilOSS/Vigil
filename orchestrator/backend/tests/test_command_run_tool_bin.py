"""``tool_bin`` names the tool a command run actually exercised.

The Commands view filters and colours runs by it, and phase readiness buckets
runs by it, so a shell script must resolve to the scanner or client it drives —
never to shell syntax (``;``, ``for``, ``}``), an option (``-sk``), a variable,
a fragment of a quoted string, or a print builtin that only labels output.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing

import pytest

from app import db as db_module
from app.services.state_manager import command_runs
from tests.test_command_runs_api import _base_payload, _post, _write_engagement


SCRIPT_CASES: list[tuple[str, str]] = [
    ("set -euo pipefail; curl -sk https://shop.acme.example/", "curl"),
    ("H=x; curl -s \"$H\"", "curl"),
    ("for h in a b; do curl -sk \"https://$h.acme.example/\"; done", "curl"),
    (
        "\nUA=\"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36\"\nD=/tmp/acme\nok=0; bad=0\n"
        "while read -r u; do b=$(basename \"$u\"); curl -s \"$u\" -o \"$D/$b\"; done < urls.txt\n",
        "curl",
    ),
    ("printf '=== HEAD /pls/ ===\\n'; curl -sI https://shop.acme.example/pls/", "curl"),
    (
        "printf '%s' '{\"a\":1}' > /tmp/p.json; curl -d @/tmp/p.json https://api.acme.example/v1",
        "curl",
    ),
    ("probe() { curl -sk \"$1\"; }\nprobe https://shop.acme.example/a", "curl"),
    ("p(){ c=$(curl -sk -m8 \"$1\"); echo \"$c\"; }\np /a", "curl"),
    (
        "H=(-H \"X-Acme-Platform: android\" -H \"Accept: */*\")\ncurl -sk \"${H[@]}\" https://api.acme.example/",
        "curl",
    ),
    ("TOKEN=$(sqlite3 $DB \"SELECT 1;\")\necho \"$TOKEN\"", "sqlite3"),
    ("# VA-007: retry the key\n# second note\ncurl -s https://api.acme.example/", "curl"),
    (
        "cat << 'EOF' > /tmp/t.html\n<script>; for x in y; do\nEOF\ncurl -sk https://shop.acme.example/",
        "curl",
    ),
    (
        "{ printf \"===== admin =====\\n\"; curl -sk -D- https://shop.acme.example/admin; } | tee out.txt",
        "curl",
    ),
    ("OUT=/tmp/acme.txt\n> \"$OUT\"\ncurl -sS https://shop.acme.example/ >> \"$OUT\"", "curl"),
    (
        "set -eu\nKEY=acme\nprintf '%s\\n' acme.example > scope.txt\nrm -f job.txt\n"
        "subfinder -dL scope.txt -o job.txt",
        "subfinder",
    ),
    (
        "RID=20260426; OUT=/tmp/$RID; cd \"$OUT\" && curl -s https://shop.acme.example/ -o a.txt && wc -c a.txt",
        "curl",
    ),
    ("JS=/tmp/index.js; grep -oE '.{30}segment' \"$JS\" | sort -u | head -10", "grep"),
    ("RID=1; setsid sh -c \"nmap -sS -Pn acme.example\" > /dev/null 2>&1 &", "nmap"),
    (
        "while IFS=\"$(printf \"\\t\")\" read -r name tok; do curl -sk \"https://$name/\"; done < tokens.txt",
        "curl",
    ),
    ("if curl -sf https://shop.acme.example/health; then echo up; fi", "curl"),
    (
        "for C in login 'id;whoami'; do ENC=$(python3 -c 'import sys; print(sys.argv[1])' \"$C\"); "
        "curl -sk \"https://shop.acme.example/?q=$ENC\"; done",
        "curl",
    ),
    ("IP=$(getent hosts acme.example | awk '{print $1}')\ncurl -sk --resolve acme.example:443:$IP https://acme.example/", "curl"),
    ("H=$(curl -sk -D /tmp/h.txt https://shop.acme.example/)\necho \"$H\" | grep -i server", "curl"),
    ("cat hosts.txt | xargs -I{} -P 4 curl -sk https://{}/", "curl"),
    ("case \"$code\" in\n  200|301) echo ok ;;\n  *) echo other ;;\nesac\nhttpx -l hosts.txt", "httpx"),
    ("case $m in a) nmap -sV acme.example;; b) curl -s https://acme.example/;; esac", "nmap"),
    ("case $m in a|b) nmap -sV acme.example;; esac", "nmap"),
    ("case $m in (a) nmap -sV acme.example;; esac", "nmap"),
    ("function g { nmap -sV acme.example; }; g", "nmap"),
    ("function g() { nmap -sV acme.example; }; g", "nmap"),
    ("function g {\n  nmap -sV acme.example\n}\ng", "nmap"),
    ("/usr/bin/curl -sk https://shop.acme.example/", "curl"),
    ("echo hello", "echo"),
    ("python3 -c 'import json'", "python3"),
]


@pytest.mark.parametrize(("script", "expected"), SCRIPT_CASES)
def test_shell_script_resolves_to_the_real_tool(script: str, expected: str) -> None:
    for argv in (["bash", "-lc", script], ["sh", "-c", script]):
        assert command_runs._derive_tool_bin(" ".join(argv), argv) == expected
    # Command text alone (no argv) resolves the same way.
    assert command_runs._derive_tool_bin(script, None) == expected


@pytest.mark.parametrize(
    ("command", "argv", "expected"),
    [
        ("curl -s https://acme.example/health", ["curl", "-s", "https://acme.example/health"], "curl"),
        ("FOO=bar sqlmap --batch -u https://acme.example", None, "sqlmap"),
        ("timeout 120 httpx -l targets.txt -json", None, "httpx"),
        ("sudo -u scanner nohup nuclei -l t.txt", None, "nuclei"),
        ("bash --rcfile /tmp/rc.sh script.sh", ["bash", "--rcfile", "/tmp/rc.sh", "script.sh"], "bash"),
        (
            "bash --norc -lc 'nuclei -l targets.txt'",
            ["bash", "--norc", "-lc", "nuclei -l targets.txt"],
            "nuclei",
        ),
        ("printf 'x\\n'", ["printf", "x\\n"], "printf"),
    ],
)
def test_argv_and_wrapper_shapes(command: str, argv: list[str] | None, expected: str) -> None:
    assert command_runs._derive_tool_bin(command, argv) == expected


_NEVER_A_TOOL = {";", "&&", "|", "for", "do", "while", "{", "}", "#", ">", "printf", "1"}


@pytest.mark.parametrize(("script", "_expected"), SCRIPT_CASES)
def test_derived_name_is_never_shell_syntax_or_an_option(script: str, _expected: str) -> None:
    derived = command_runs._derive_tool_bin(script, None)
    assert derived not in _NEVER_A_TOOL
    assert not derived.startswith(("-", "$", "\"", "'"))


def test_stale_tool_bins_are_rewritten_once() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.execute(
        "CREATE TABLE assessment_command_runs ("
        "id INTEGER PRIMARY KEY, command TEXT NOT NULL, argv_json TEXT NOT NULL, "
        "tool_bin TEXT NOT NULL DEFAULT '')"
    )
    rows = [
        (1, "bash -c 'set -e; curl -s https://acme.example/'", ["bash", "-c", "set -e; curl -s https://acme.example/"], ";"),
        (2, "for h in a b; do nmap $h; done", [], "for"),
        (3, "curl -s https://acme.example/", ["curl", "-s", "https://acme.example/"], "curl"),
    ]
    connection.executemany(
        "INSERT INTO assessment_command_runs (id, command, argv_json, tool_bin) VALUES (?, ?, ?, ?)",
        [(row_id, command, json.dumps(argv), tool_bin) for row_id, command, argv, tool_bin in rows],
    )

    stale = command_runs.stale_command_run_tool_bins(connection)
    assert sorted(stale) == [("curl", 1), ("nmap", 2)]
    assert command_runs.rewrite_command_run_tool_bins(connection, stale) == 2
    assert dict(
        connection.execute("SELECT id, tool_bin FROM assessment_command_runs").fetchall()
    ) == {1: "curl", 2: "nmap", 3: "curl"}
    # Already current: nothing left to rewrite.
    assert command_runs.stale_command_run_tool_bins(connection) == []


def _tool_bin_marker(connection: sqlite3.Connection):
    return connection.execute(
        "SELECT migrated_rows FROM schema_migrations WHERE migration_id = ?",
        (db_module.COMMAND_RUN_TOOL_BIN_MIGRATION_ID,),
    ).fetchone()


def test_startup_rewrites_legacy_tool_bins_once(client, isolate_settings):
    """Rows stored before the shell-aware derivation are rewritten by a one-time
    data migration on startup; the schema_migrations marker keeps later startups
    from re-scanning the ledger."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            command="bash -lc 'set -e; curl -s https://shop.acme.example/'",
            argv=["bash", "-lc", "set -e; curl -s https://shop.acme.example/"],
            tool_name="execute_command",
        ),
    )
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        assert _tool_bin_marker(connection) == (0,)  # fresh database: nothing to rewrite
        connection.execute("UPDATE assessment_command_runs SET tool_bin = ';' WHERE id = ?", (run_id,))
        connection.execute(
            "DELETE FROM schema_migrations WHERE migration_id = ?",
            (db_module.COMMAND_RUN_TOOL_BIN_MIGRATION_ID,),
        )
    db_module.close_thread_connection()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        assert connection.execute(
            "SELECT tool_bin FROM assessment_command_runs WHERE id = ?", (run_id,)
        ).fetchone() == ("curl",)
        assert _tool_bin_marker(connection) == (1,)
        # The marker makes the migration run once: a later startup leaves rows alone.
        connection.execute("UPDATE assessment_command_runs SET tool_bin = ';' WHERE id = ?", (run_id,))
    db_module.close_thread_connection()

    db_module.init_db()

    with sqlite3.connect(str(db_path)) as connection:
        assert connection.execute(
            "SELECT tool_bin FROM assessment_command_runs WHERE id = ?", (run_id,)
        ).fetchone() == (";",)
        assert _tool_bin_marker(connection) == (1,)


def test_concurrent_startup_workers_both_finish_the_tool_bin_migration(
    client, isolate_settings, monkeypatch
):
    """Two workers starting against an un-migrated database both pass the
    marker check before either records it. The worker that finishes second
    must start cleanly instead of failing on the marker's unique key, and the
    rewrite must be recorded once."""
    _write_engagement(isolate_settings["engagements_dir"])
    created = _post(
        client,
        _base_payload(
            command="bash -lc 'set -e; curl -s https://shop.acme.example/'",
            argv=["bash", "-lc", "set -e; curl -s https://shop.acme.example/"],
            tool_name="execute_command",
        ),
    )
    assert created.status_code == 201, created.text
    run_id = created.json()["id"]
    db_path = db_module.database_path()
    with sqlite3.connect(str(db_path)) as connection:
        connection.execute("UPDATE assessment_command_runs SET tool_bin = ';' WHERE id = ?", (run_id,))
        connection.execute(
            "DELETE FROM schema_migrations WHERE migration_id = ?",
            (db_module.COMMAND_RUN_TOOL_BIN_MIGRATION_ID,),
        )
    db_module.close_thread_connection()

    derive = command_runs._derive_tool_bin
    other_worker_ran = False

    def derive_while_other_worker_migrates(command, argv):
        # The first worker is mid-scan when the second worker runs the whole
        # migration and commits its marker.
        nonlocal other_worker_ran
        if not other_worker_ran:
            other_worker_ran = True
            with closing(sqlite3.connect(str(db_path), timeout=5)) as other:
                db_module._migrate_command_run_tool_bins(other)
                other.commit()
        return derive(command, argv)

    monkeypatch.setattr(command_runs, "_derive_tool_bin", derive_while_other_worker_migrates)
    with closing(sqlite3.connect(str(db_path), timeout=5)) as first:
        db_module._migrate_command_run_tool_bins(first)
        first.commit()

    assert other_worker_ran
    with closing(sqlite3.connect(str(db_path))) as connection:
        assert connection.execute(
            "SELECT tool_bin FROM assessment_command_runs WHERE id = ?", (run_id,)
        ).fetchone() == ("curl",)
        assert connection.execute(
            "SELECT migrated_rows FROM schema_migrations WHERE migration_id = ?",
            (db_module.COMMAND_RUN_TOOL_BIN_MIGRATION_ID,),
        ).fetchall() == [(1,)]
