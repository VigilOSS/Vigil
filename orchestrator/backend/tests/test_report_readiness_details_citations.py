"""Free-text ``details`` citations resolved against the sealed generation.

Every STRUCTURED citation a finding carries is already checked against the
generation its binding seals: ``canonical_location``, relocations, lead
bindings, cross-file trigger targets, and the symbols and spans on an analysis
receipt. The free-text keys whose own schema descriptions TEACH the
``<path>:<line>`` convention — ``details.sink``'s description is literally
``"memcpy(buf, scheme, schemelen) at lib/urlapi.c:342"`` — were never read, so a
finding could cite a line that does not exist and survive until a verifier
opened it.

Refusing the write would be wrong: prose legitimately names vendor files, build
outputs and library calls the sealed tree never held. So this is a report-time
gate that fires only on a citation the sealed tree can be shown to contradict.
"""
from __future__ import annotations

import argparse
import json
import re
import shlex

from app import db as db_module
from tests.test_finding_code_snapshot_provenance import (
    _ENGAGEMENT_KEY,
    _dispatch,
    _finding_payload,
    _record,
    _seed_repo,
)

BASE = f"/engagements/{_ENGAGEMENT_KEY}/assessment"

_CITATION_KIND = "finding_details_citation_unresolved"


def _engagement_id() -> int:
    with db_module.get_connection() as connection:
        return int(
            connection.execute(
                "SELECT id FROM engagements WHERE key = ?", (_ENGAGEMENT_KEY,)
            ).fetchone()["id"]
        )


def _recorded(
    client,
    isolate_settings,
    slug: str,
    details: dict[str, object],
    *,
    location: str = "file:src/parser.c:41",
    bind: bool = True,
) -> dict[str, object]:
    binding = _seed_repo(client, isolate_settings)
    author = f"hunter-{slug.lower()}"
    _dispatch(client, author)
    payload = _finding_payload(
        slug,
        binding if bind else None,
        location=location,
        author_agent_id=author,
    )
    payload["details"] = {**payload["details"], **details}
    payload["evidence_ref"] = "findings.md"
    recorded = _record(client, payload)
    assert recorded.status_code == 201, recorded.text
    return binding


def _citation_blockers(client) -> list[dict]:
    response = client.get(f"{BASE}/report-readiness")
    assert response.status_code == 200, response.text
    body = response.json()
    assert not any(
        item["kind"] == _CITATION_KIND for item in body["advisories"]
    ), "an unresolved code citation gates the report; it is not an advisory"
    return [item for item in body["blockers"] if item["kind"] == _CITATION_KIND]


def _declare_outside_snapshot(binding: dict[str, object], path: str) -> None:
    """Record ``path`` as a target the snapshot genuinely cannot hold."""
    with db_module.get_connection() as connection:
        connection.execute(
            """
            INSERT INTO code_analysis_triggers (
                engagement_id, source_file_id, target_file_id, target_file_path,
                vuln_class, reason, status, repo_id, repo_generation
            ) VALUES (?, NULL, NULL, ?, 'buffer-overflow',
                      'the dependency lives outside this checkout', 'pending', ?, ?)
            """,
            (
                _engagement_id(),
                path,
                binding["repo_id"],
                binding["repo_generation"],
            ),
        )


# ── A citation the sealed tree contradicts gates the report ──────────────────


def test_a_cited_line_past_the_end_of_a_sealed_file_blocks(client, isolate_settings):
    _recorded(
        client,
        isolate_settings,
        "VA-601",
        {"sink": "memcpy(buf, scheme, schemelen) at src/parser.c:4200"},
    )

    [blocker] = _citation_blockers(client)

    assert blocker["slug"] == "VA-601"
    assert blocker["detail_key"] == "sink"
    assert blocker["path"] == "src/parser.c"
    assert blocker["line"] == 4200
    assert blocker["closest_admitted_path"] == "src/parser.c"
    assert blocker["severity"] == "block"
    assert "src/parser.c" in blocker["detail"]


def test_a_cited_path_with_an_admitted_namesake_blocks(client, isolate_settings):
    """The wrong directory, not a vendor file: the sealed tree holds the name."""
    _recorded(
        client,
        isolate_settings,
        "VA-602",
        {"entry_point": "parse_packet() in lib/parser.c:41"},
    )

    [blocker] = _citation_blockers(client)

    assert blocker["path"] == "lib/parser.c"
    assert blocker["closest_admitted_path"] == "src/parser.c"
    assert blocker["detail_key"] == "entry_point"


def test_an_unresolved_citation_gates_report_readiness(client, isolate_settings):
    _recorded(
        client,
        isolate_settings,
        "VA-603",
        {"taint_path": ["curl_url_set -> parseurl() at src/parser.c:900"]},
    )

    body = client.get(f"{BASE}/report-readiness").json()

    assert body["ready"] is False
    assert [item["detail_key"] for item in _citation_blockers(client)] == ["taint_path"]


# ── What must never fire ─────────────────────────────────────────────────────


def test_a_resolvable_citation_is_silent(client, isolate_settings):
    _recorded(
        client,
        isolate_settings,
        "VA-604",
        {
            "sink": "memcpy(buf, scheme, schemelen) at src/parser.c:120",
            "evidence": "The copy at src/other.c:7-19 takes the attacker length.",
        },
    )

    assert _citation_blockers(client) == []


def test_prose_naming_a_file_the_sealed_tree_never_held_is_silent(
    client, isolate_settings
):
    """Refusing this would be wrong: a remediation legitimately names vendors."""
    _recorded(
        client,
        isolate_settings,
        "VA-605",
        {
            "remediation": (
                "Use strlcpy as vendor/third_party/libfoo/strings.c:88 does, and "
                "rebuild with build/out/release.mk:12."
            )
        },
    )

    assert _citation_blockers(client) == []


def test_tokens_that_are_not_path_shaped_are_silent(client, isolate_settings):
    _recorded(
        client,
        isolate_settings,
        "VA-606",
        {
            "guards_evaluated": (
                "Scored CVSS:3.1/AV:N/AC:H and replayed against "
                "https://acme.example:8443/parse?len=4200 at 12:30:05 on attempt 2:1."
            )
        },
    )

    assert _citation_blockers(client) == []


def test_a_path_declared_outside_the_snapshot_is_silent(client, isolate_settings):
    binding = _recorded(
        client,
        isolate_settings,
        "VA-607",
        {"sink": "memcpy(dst, src, len) at lib/parser.c:41"},
    )
    assert _citation_blockers(client), "fixture must start from a firing citation"

    _declare_outside_snapshot(binding, "lib/parser.c")

    assert _citation_blockers(client) == []


def test_a_qualified_symbol_name_in_prose_is_not_read_as_a_path(
    client, isolate_settings
):
    """A dotted callable name looks file-shaped and must still never fire.

    Naming a callable is not a claim about WHERE it lives, which is why a cited
    line is required before anything is resolved. Symbol names are never
    refused on their own: ``details.sink``'s taught examples are ``memcpy`` and
    ``sqlite3_exec``, which the sealed tree does not define.
    """
    _recorded(
        client,
        isolate_settings,
        "VA-608",
        {
            "entry_point": "Parser.parse receives the attacker length.",
            "sink": "memcpy(buf, scheme, schemelen) consumes it unchecked.",
        },
    )

    assert _citation_blockers(client) == []


def test_a_finding_with_no_sealed_binding_has_nothing_to_resolve_against(
    client, isolate_settings
):
    _recorded(
        client,
        isolate_settings,
        "VA-609",
        {"sink": "the handler at src/parser.c:9999"},
        location="https://acme.example/api/parse",
        bind=False,
    )

    assert _citation_blockers(client) == []


def test_the_citation_blocker_prints_a_command_that_parses(client, isolate_settings):
    """A refusal naming a verb spelling the CLI does not register is worse than
    silence: the reader runs it, argparse refuses, and the remedy is lost."""
    _recorded(
        client,
        isolate_settings,
        "VA-610",
        {"sink": "memcpy(buf, scheme, schemelen) at src/parser.c:4200"},
    )

    [blocker] = _citation_blockers(client)
    commands = re.findall(r"`vigil assess ([^`]+)`", blocker["detail"])

    assert commands, blocker["detail"]
    from assess import cli as assess_cli
    from assess.commands import update_finding

    parser = argparse.ArgumentParser(prog="vigil assess")
    sub = parser.add_subparsers(dest="command")
    assess_cli._register_subcommand_group(
        sub,
        name="finding",
        help_text="Finding lifecycle.",
        dest="finding_action",
        leaf_modules=(update_finding,),
    )
    for command in commands:
        parsed = parser.parse_args(shlex.split(command))
        assert parsed.command == "finding"
        assert parsed.finding_action == "update"
        assert json.loads(parsed.details_inline) == {"sink": "..."}
