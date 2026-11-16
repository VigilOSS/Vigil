"""Merged Activity feed: audit-log entries plus structured events.

Rows are inserted directly so each test controls the stored timestamp
spelling: ``events.created_at`` is SQLite ``YYYY-MM-DD HH:MM:SS`` while
``activity_entries.occurred_at`` holds both that spelling and ISO-8601.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from app import db
from app.services import activity_feed
from tests.test_engagements_api import write_engagement


ENGAGEMENT_KEY = "2026-04-17-120200-activity-feed"
FEED = f"/engagements/{ENGAGEMENT_KEY}/activity"


def _seed(client, isolate_settings) -> int:
    write_engagement(isolate_settings["engagements_dir"], key=ENGAGEMENT_KEY)
    response = client.get(f"/engagements/{ENGAGEMENT_KEY}")
    assert response.status_code == 200, response.text
    return int(response.json()["id"])


def _audit(
    engagement_id: int,
    occurred_at: str,
    title: str,
    *,
    actor_kind: str = "system",
    actor_name: str = "vigil-assess",
    action: str = "",
    result: str = "",
    body: str = "",
    metadata: dict | None = None,
) -> int:
    with db.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO activity_entries (
                engagement_id, occurred_at, actor_kind, actor_name, title,
                action, result, body_markdown, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                occurred_at,
                actor_kind,
                actor_name,
                title,
                action,
                result,
                body,
                json.dumps(metadata or {}),
            ),
        )
        return int(cursor.lastrowid)


def _event(
    engagement_id: int,
    created_at: str,
    event_type: str,
    *,
    task_name: str = "task",
    agent_name: str = "operator",
    summary: str = "",
    phase: str = "unknown",
) -> int:
    with db.get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO events (
                engagement_id, event_type, phase, task_name, agent_name, summary, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (engagement_id, event_type, phase, task_name, agent_name, summary or event_type, created_at),
        )
        return int(cursor.lastrowid)


def _feed(client, **params) -> dict:
    response = client.get(FEED, params=params)
    assert response.status_code == 200, response.text
    return response.json()


def test_feed_unions_audit_and_events_newest_first_without_activity_copies(
    client, isolate_settings
):
    engagement_id = _seed(client, isolate_settings)
    note = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "Scoped the Acme login flow",
        actor_kind="agent", actor_name="recon-specialist",
    )
    # `vigil assess log` writes the audit row and then mirrors its title as an
    # activity.recorded event; the feed must show that action once.
    _event(
        engagement_id, "2026-04-17 12:00:00", "activity.recorded",
        task_name="activity-entry", agent_name="recon-specialist",
        summary="Scoped the Acme login flow",
    )
    surface = _event(
        engagement_id, "2026-04-17 12:01:00", "surface.updated",
        task_name="auth_entry", agent_name="recon-specialist",
        summary="auth_entry discovered: https://app.example.com/login",
    )

    payload = _feed(client)

    assert [item["id"] for item in payload["items"]] == [f"event:{surface}", f"audit:{note}"]
    assert payload["total"] == 2
    assert payload["has_more"] is False
    assert all(item["detail"].get("event_type") != "activity.recorded" for item in payload["items"])
    surface_item = payload["items"][0]
    assert surface_item["category"] == "knowledge"
    assert surface_item["actor"] == {"name": "recon-specialist", "kind": "agent"}
    assert surface_item["entities"][0]["type"] == "surface"
    assert surface_item["entities"][0]["key"] == "https://app.example.com/login"


def test_feed_orders_mixed_timestamp_spellings_by_instant(client, isolate_settings):
    """Regression: SQLite and ISO spellings must not be ordered as strings.

    As text, every ``YYYY-MM-DDTHH…`` value sorts after every
    ``YYYY-MM-DD HH…`` value of the same day, so a plain string sort puts the
    12:00:03 ISO row above the 12:00:05 SQLite row.
    """
    engagement_id = _seed(client, isolate_settings)
    iso_early = _audit(engagement_id, "2026-04-17T12:00:03Z", "ISO early")
    sqlite_mid = _audit(engagement_id, "2026-04-17 12:00:05", "SQLite middle")
    event_late = _event(engagement_id, "2026-04-17 12:00:06", "chain.created", task_name="acme-chain")
    iso_late = _audit(engagement_id, "2026-04-17T12:00:07.250000Z", "ISO late")
    offset_latest = _audit(engagement_id, "2026-04-17T13:00:08+01:00", "Offset spelling")

    payload = _feed(client)

    assert [item["id"] for item in payload["items"]] == [
        f"audit:{offset_latest}",
        f"audit:{iso_late}",
        f"event:{event_late}",
        f"audit:{sqlite_mid}",
        f"audit:{iso_early}",
    ]
    assert [item["occurred_at"] for item in payload["items"]] == [
        "2026-04-17T12:00:08Z",
        "2026-04-17T12:00:07.250000Z",
        "2026-04-17T12:00:06Z",
        "2026-04-17T12:00:05Z",
        "2026-04-17T12:00:03Z",
    ]


def test_feed_cursor_pages_are_gap_free_in_both_directions(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    expected: list[str] = []
    for second in range(7):
        if second % 2:
            expected.append(f"event:{_event(engagement_id, f'2026-04-17 12:00:0{second}', 'chain.created', task_name=f'chain-{second}')}")
        else:
            expected.append(f"audit:{_audit(engagement_id, f'2026-04-17T12:00:0{second}Z', f'Note {second}', actor_kind='agent', actor_name='recon-specialist')}")
    # Same instant in both sources: the order must still be total.
    expected.append(f"event:{_event(engagement_id, '2026-04-17 12:00:09', 'chain.created', task_name='tie')}")
    expected.append(f"audit:{_audit(engagement_id, '2026-04-17T12:00:09Z', 'Tie note', actor_kind='agent', actor_name='recon-specialist')}")

    seen: list[str] = []
    cursor = None
    while True:
        params = {"limit": 3, **({"before": cursor} if cursor else {})}
        page = _feed(client, **params)
        seen.extend(item["id"] for item in page["items"])
        assert page["total"] == len(expected)
        if not page["has_more"]:
            break
        cursor = page["items"][-1]["cursor"]

    assert len(seen) == len(set(seen)) == len(expected)
    full = [item["id"] for item in _feed(client, limit=50)["items"]]
    assert seen == full
    assert set(full) == set(expected)

    # Catching up from an older cursor walks forward without skipping rows.
    anchor = _feed(client, limit=50)["items"][5]
    newer: list[str] = []
    cursor = anchor["cursor"]
    while True:
        page = _feed(client, limit=2, after=cursor)
        newer = [item["id"] for item in page["items"]] + newer
        if not page["has_more"]:
            break
        cursor = page["items"][0]["cursor"]
    assert newer == full[:5]


def _catch_up(client, head: str, **params) -> list[str]:
    """What a live refresh holding ``head`` receives: every page newer than it, newest first,
    each read continuing from the previous one's ``catch_up_cursor``."""
    newer: list[str] = []
    cursor = head
    for _ in range(10):
        page = _feed(client, after=cursor, **params)
        newer = [item["id"] for item in page["items"]] + newer
        cursor = page["catch_up_cursor"]
        if not page["has_more"]:
            return newer
    raise AssertionError("catch-up did not settle")


def test_feed_catch_up_delivers_a_row_recorded_after_its_instant(client, isolate_settings):
    """A queued logger dates a row by when its call finished, after newer rows were read.

    A live refresh still receives it once, beside the rows that arrived with it."""
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:00:00Z", "Note A", actor_kind="agent", actor_name="recon-specialist")
    _audit(engagement_id, "2026-04-17T12:00:40Z", "Note B", actor_kind="agent", actor_name="fuzzer")
    head = _feed(client)["items"][0]["cursor"]

    late = _audit(engagement_id, "2026-04-17T12:00:05Z", "Note late", actor_kind="agent", actor_name="recon-specialist")
    newer = _event(engagement_id, "2026-04-17 12:00:50", "chain.created", task_name="acme-chain")

    page = _feed(client, after=head)
    assert [item["id"] for item in page["items"]] == [f"event:{newer}", f"audit:{late}"]
    assert page["has_more"] is False
    assert page["catch_up_cursor"] == page["items"][0]["cursor"]
    assert _feed(client, after=page["catch_up_cursor"])["items"] == []
    # The full read lists it by its instant.
    assert [item["id"] for item in _feed(client)["items"]][-2] == f"audit:{late}"


def test_feed_catch_up_walks_many_late_rows_without_gaps(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:01:00Z", "Head", actor_kind="agent", actor_name="fuzzer")
    head = _feed(client)["items"][0]["cursor"]
    late = [
        f"audit:{_audit(engagement_id, f'2026-04-17T12:00:{second:02d}Z', f'Late {second}', actor_kind='agent', actor_name='fuzzer')}"
        for second in (30, 10, 50, 20, 40)
    ]

    received = _catch_up(client, head, limit=2)

    assert sorted(received) == sorted(late) and len(received) == len(late)
    assert _catch_up(client, _feed(client, after=head, limit=50)["catch_up_cursor"]) == []


def test_feed_catch_up_of_only_late_rows_continues_past_them(client, isolate_settings):
    """A refresh that gains only late rows lists no row newer than its head; the next
    refresh continues from the response's catch-up cursor and receives nothing again."""
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:00:00Z", "Note A", actor_kind="agent", actor_name="recon-specialist")
    _audit(engagement_id, "2026-04-17T12:00:40Z", "Note B", actor_kind="agent", actor_name="fuzzer")
    head = _feed(client)["items"][0]
    late = _audit(engagement_id, "2026-04-17T12:00:05Z", "Note late", actor_kind="agent", actor_name="recon-specialist")

    page = _feed(client, after=head["cursor"])

    assert [item["id"] for item in page["items"]] == [f"audit:{late}"]
    assert _feed(client, after=page["catch_up_cursor"])["items"] == []
    # Rows recorded after that refresh still arrive, once.
    newer = _audit(engagement_id, "2026-04-17T12:00:50Z", "Note C", actor_kind="agent", actor_name="fuzzer")
    assert _catch_up(client, page["catch_up_cursor"]) == [f"audit:{newer}"]


def test_feed_catch_up_cursor_moves_past_rows_the_view_hides(client, isolate_settings):
    """Tool calls hidden by the view still advance the catch-up cursor's watermark, so the
    next refresh reads only what was recorded since, not every hidden row again."""
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:01:00Z", "Head", actor_kind="agent", actor_name="fuzzer")
    first = _feed(client)
    for second in range(5):
        _audit(engagement_id, f"2026-04-17T12:00:{second:02d}Z", "Bash", actor_kind="hook", actor_name="fuzzer",
               action="bash: nmap acme.example")

    page = _feed(client, after=first["catch_up_cursor"])

    assert page["items"] == [] and page["has_more"] is False
    assert page["catch_up_cursor"] != first["catch_up_cursor"]
    assert _feed(client, after=page["catch_up_cursor"], category="tools")["items"] == []
    late = _audit(engagement_id, "2026-04-17T12:00:30Z", "Note late", actor_kind="agent", actor_name="fuzzer")
    assert _catch_up(client, page["catch_up_cursor"]) == [f"audit:{late}"]


def test_feed_catch_up_cursor_is_given_where_a_refresh_can_start(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    empty = _feed(client)
    assert (empty["items"], empty["catch_up_cursor"]) == ([], None)
    for second in range(3):
        _audit(engagement_id, f"2026-04-17T12:00:0{second}Z", f"Note {second}", actor_kind="agent", actor_name="fuzzer")
    top = _feed(client, limit=2)
    assert top["catch_up_cursor"] == top["items"][0]["cursor"]
    # An older page is no place to catch up from.
    assert _feed(client, before=top["items"][-1]["cursor"])["catch_up_cursor"] is None


def test_feed_items_carry_the_order_the_feed_sorts_by(client, isolate_settings):
    """``order`` is the feed's total order key, [instant, source rank, id]: rows sharing an
    instant list audit before event and newer ids first, and an undated row sorts as instant 0."""
    engagement_id = _seed(client, isolate_settings)
    _event(engagement_id, "2026-04-17 12:00:00", "chain.created", task_name="tie")
    _audit(engagement_id, "2026-04-17T12:00:00Z", "Tie note", actor_kind="agent", actor_name="fuzzer")
    _audit(engagement_id, "2026-04-17T12:00:00+00:00", "Tie note 2", actor_kind="agent", actor_name="fuzzer")
    _audit(engagement_id, "not a time", "Undated note", actor_kind="agent", actor_name="fuzzer")
    _audit(engagement_id, "2026-04-17T12:00:00.0004Z", "Sub-millisecond note", actor_kind="agent", actor_name="fuzzer")

    items = _feed(client)["items"]

    orders = [tuple(item["order"]) for item in items]
    assert orders == sorted(orders, reverse=True) and len(set(orders)) == len(orders)
    assert [(item["source"], item["source_id"]) == (["audit", "event"][1 - order[1]], order[2])
            for item, order in zip(items, orders)] == [True] * len(items)
    assert items[-1]["kind"] == "Undated note" and items[-1]["order"][0] == 0


def test_feed_catch_up_applies_the_page_filters_to_late_rows(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:01:00Z", "Head", actor_kind="agent", actor_name="fuzzer")
    head = _feed(client)["items"][0]["cursor"]
    tool = _audit(engagement_id, "2026-04-17T12:00:30Z", "Bash", actor_kind="hook", actor_name="fuzzer",
                  action="bash: nmap acme.example")

    # Tool calls are hidden by default, late or not.
    assert _feed(client, after=head)["items"] == []
    assert [item["id"] for item in _feed(client, after=head, category="tools")["items"]] == [f"audit:{tool}"]


def test_feed_shows_a_late_logged_call_once(client, isolate_settings):
    """`vigil assess log` mirrors its row as an activity.recorded event when it records it;
    a row dated by its call's finish, long before, is still listed once."""
    engagement_id = _seed(client, isolate_settings)
    row = _audit(engagement_id, "2026-04-17T12:00:00.250Z", "Bash", actor_kind="hook", actor_name="recon-specialist",
                 action="bash: nmap acme.example")
    _event(engagement_id, "2026-04-17 12:00:45", "activity.recorded", task_name="activity-entry",
           agent_name="recon-specialist", summary="Bash")

    payload = _feed(client, category="tools,notes")

    assert [item["id"] for item in payload["items"]] == [f"audit:{row}"]
    assert payload["total"] == 1


@pytest.mark.parametrize(
    "params",
    [{}, {"actor": "agent"}, {"category": "notes,tools"}],
    ids=["default", "actor", "categories"],
)
def test_feed_pages_older_rows_from_a_late_row_at_its_own_place(client, isolate_settings, params):
    """A row recorded late can become the oldest row a client holds, with older history
    unloaded or with all of it loaded. Paging older from its cursor lists the rows below
    it in feed order, never rows above it, under the client's filters."""
    engagement_id = _seed(client, isolate_settings)
    for second in range(10, 20):
        _audit(engagement_id, f"2026-04-17T12:00:{second}Z", f"Note {second}", actor_kind="agent", actor_name="recon-specialist")
        _audit(engagement_id, f"2026-04-17T12:00:{second}.500Z", "Bash", actor_kind="hook", actor_name="recon-specialist",
               action="bash: nmap acme.example")
    head = _feed(client, limit=3, **params)["items"][0]["cursor"]

    late = _audit(engagement_id, "2026-04-17T12:00:15.250Z", "Late note", actor_kind="agent", actor_name="recon-specialist")
    page = _feed(client, after=head, **params)
    assert [item["id"] for item in page["items"]] == [f"audit:{late}"]
    full = [item["id"] for item in _feed(client, limit=500, **params)["items"]]
    below = full[full.index(f"audit:{late}") + 1:]
    assert below
    older = _feed(client, before=page["items"][0]["cursor"], limit=500, **params)
    assert [item["id"] for item in older["items"]] == below
    assert older["has_more"] is False

    # Older than every row: nothing lies below it.
    oldest = _audit(engagement_id, "2026-04-17T11:00:00Z", "Oldest late note", actor_kind="agent", actor_name="recon-specialist")
    page = _feed(client, after=page["catch_up_cursor"], **params)
    assert [item["id"] for item in page["items"]] == [f"audit:{oldest}"]
    bottom = _feed(client, before=page["items"][0]["cursor"], **params)
    assert (bottom["items"], bottom["has_more"]) == ([], False)
    assert _feed(client, after=page["catch_up_cursor"], **params)["items"] == []


def test_feed_accepts_cursors_without_a_watermark(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    for second in range(5):
        _audit(engagement_id, f"2026-04-17T12:00:0{second}Z", f"Note {second}", actor_kind="agent", actor_name="recon-specialist")
    full = _feed(client)["items"]
    anchor = full[2]["cursor"]
    position = "~".join(anchor.split("~")[:3])

    for cursor in (anchor, position):
        assert [item["id"] for item in _feed(client, before=cursor)["items"]] == [item["id"] for item in full[3:]]
        assert [item["id"] for item in _feed(client, after=cursor)["items"]] == [item["id"] for item in full[:2]]
    for malformed in (
        f"{anchor}~1",
        f"{anchor}~{position.split('~')[0]}~audit",
        f"{position}~-1",
        f"{anchor}~{position}",
    ):
        response = client.get(FEED, params={"after": malformed})
        assert response.status_code == 422, malformed


def test_feed_read_is_one_snapshot_so_a_row_committed_meanwhile_is_delivered_once(
    client, isolate_settings, monkeypatch
):
    """Another lane's `vigil assess log` can commit while a refresh is mid-read; the
    read's watermark and its pages agree, so later refreshes deliver that row once."""
    engagement_id = _seed(client, isolate_settings)
    _audit(engagement_id, "2026-04-17T12:00:00Z", "Head", actor_kind="agent", actor_name="recon-specialist")
    head = _feed(client)["items"][0]["cursor"]
    concurrent: list[str] = []
    original = activity_feed._watermark

    def watermark_then_another_lane_writes(connection, *args):
        value = original(connection, *args)
        if not concurrent:
            other = sqlite3.connect(db.database_path())
            try:
                for stamp, title in (("2026-04-17T12:00:30Z", "Concurrent"), ("2026-04-17T12:00:40Z", "Concurrent 2")):
                    row = other.execute(
                        "INSERT INTO activity_entries (engagement_id, occurred_at, actor_kind, actor_name, title) "
                        "VALUES (?, ?, 'agent', 'fuzzer', ?)",
                        (engagement_id, stamp, title),
                    )
                    other.commit()
                    concurrent.append(f"audit:{row.lastrowid}")
            finally:
                other.close()
        return value

    monkeypatch.setattr(activity_feed, "_watermark", watermark_then_another_lane_writes)
    delivered: list[str] = []
    for _ in range(3):
        page = _feed(client, after=head)
        delivered += [item["id"] for item in page["items"]]
        head = page["catch_up_cursor"]

    assert sorted(delivered) == sorted(concurrent)


def test_feed_keeps_rows_with_unparseable_timestamps_as_oldest(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    undated = [
        _audit(engagement_id, "sometime on tuesday", "Undated note A", actor_kind="agent", actor_name="recon-specialist"),
        _audit(engagement_id, "", "Undated note B", actor_kind="agent", actor_name="recon-specialist"),
    ]
    dated = _audit(engagement_id, "2026-04-17T12:00:00Z", "Dated note", actor_kind="agent", actor_name="recon-specialist")
    undated_event = _event(engagement_id, "not a time", "chain.created", task_name="acme-chain")

    seen: list[dict] = []
    cursor = None
    while True:
        page = _feed(client, limit=1, **({"before": cursor} if cursor else {}))
        seen.extend(page["items"])
        if not page["has_more"]:
            break
        cursor = page["items"][-1]["cursor"]

    assert [item["id"] for item in seen] == [
        f"audit:{dated}", f"audit:{undated[1]}", f"audit:{undated[0]}", f"event:{undated_event}",
    ]
    assert seen[2]["occurred_at"] == "sometime on tuesday"
    assert _feed(client)["total"] == 4
    newer = _feed(client, after=seen[3]["cursor"])
    assert [item["id"] for item in newer["items"]] == [f"audit:{dated}", f"audit:{undated[1]}", f"audit:{undated[0]}"]


def test_feed_category_counts_and_tool_calls_hidden_by_default(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    for index in range(3):
        _audit(
            engagement_id, f"2026-04-17T12:00:0{index}Z", "Bash",
            actor_kind="hook", actor_name="operator", action=f"bash: curl https://app.example.com/{index}",
        )
    decision = _audit(
        engagement_id, "2026-04-17T12:01:00Z", "agent decision",
        action="kind=scope_decision", metadata={"kind": "scope_decision", "surfaced_to_user": True},
    )
    start = _audit(
        engagement_id, "2026-04-17T12:02:00Z", "agent start",
        actor_name="vulnerability-analyst",
        action="agent_id=va-acme-01 role=vulnerability-analyst", result="in-progress",
        metadata={"agent_id": "va-acme-01", "agent_role": "vulnerability-analyst"},
    )
    review = _audit(
        engagement_id, "2026-04-17T12:03:00Z", "code-record analysis",
        actor_name="code-vuln-hunter", result="clean",
        metadata={"file_id": 7, "disposition": "clean", "finding_slug": ""},
    )

    payload = _feed(client)
    counts = {category["key"]: category["count"] for category in payload["categories"]}
    defaults = {category["key"] for category in payload["categories"] if category["default"]}

    assert [item["id"] for item in payload["items"]] == [f"audit:{review}", f"audit:{start}", f"audit:{decision}"]
    assert counts["tools"] == 3
    assert counts["decisions"] == 1
    assert counts["lifecycle"] == 1
    assert counts["code"] == 1
    assert "tools" not in defaults
    assert payload["total"] == 3

    tools = _feed(client, category="tools")
    assert [item["category"] for item in tools["items"]] == ["tools"] * 3
    assert tools["total"] == 3
    assert tools["items"][0]["summary"] == "Ran: curl https://app.example.com/2"
    # Counts describe every category under the other filters, whatever is selected.
    assert {c["key"]: c["count"] for c in tools["categories"]} == counts

    rejected = client.get(FEED, params={"category": "not-a-category"})
    assert rejected.status_code == 422, rejected.text


def test_feed_derives_actor_kind_from_identity(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    agent_row = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "finding-update",
        actor_name="va-acme-01", action="finding=VA-001", metadata={"finding_slug": "VA-001"},
    )
    system_row = _audit(
        engagement_id, "2026-04-17T12:00:01Z", "operator checkpoint",
        action="checkpoint_version=3", result="consume-test", metadata={"checkpoint_version": 3},
    )
    operator_row = _audit(
        engagement_id, "2026-04-17T12:00:02Z", "artifact register",
        actor_name="operator", action="notes/acme.md", result="note",
        metadata={"relative_path": "notes/acme.md"},
    )

    payload = _feed(client)
    kinds = {item["id"]: item["actor"]["kind"] for item in payload["items"]}
    assert kinds == {
        f"audit:{agent_row}": "agent",
        f"audit:{system_row}": "system",
        f"audit:{operator_row}": "operator",
    }
    # The stored audit kind stays available verbatim for the disclosure.
    assert all(item["detail"]["actor_kind"] == "system" for item in payload["items"])

    agents_only = _feed(client, actor="agent")
    assert [item["id"] for item in agents_only["items"]] == [f"audit:{agent_row}"]
    assert agents_only["total"] == 1


def test_feed_resolves_entities_and_dispatch_runs(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    with db.get_connection() as connection:
        dispatch_id = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, dispatched_at, status
            ) VALUES (?, 'va-acme-01', 'vulnerability-analyst', '2026-04-17T11:59:00Z', 'completed')
            """,
            (engagement_id,),
        ).lastrowid
        run_id = connection.execute(
            """
            INSERT INTO assessment_runs (engagement_id, run_uuid, run_kind, producer_dispatch_id)
            VALUES (?, 'run-acme-1', 'web', ?)
            """,
            (engagement_id, dispatch_id),
        ).lastrowid
    done = _audit(
        engagement_id, "2026-04-17T12:05:00Z", "agent done",
        actor_name="va-acme-01", action="agent_id=va-acme-01", result="completed",
        metadata={"agent_id": "va-acme-01", "finding_slugs": ["VA-001", "VA-002"]},
    )
    record = _audit(
        engagement_id, "2026-04-17T12:04:00Z", "finding-record",
        actor_name="vulnerability-analyst", action="finding=VA-001 severity=high", result="active",
        metadata={"finding_slug": "VA-001", "source_name": "vulnerability-analyst"},
    )
    merged = _event(
        engagement_id, "2026-04-17 12:06:00", "finding.merged",
        task_name="VA-002", summary="Merged VA-002 into VA-001: duplicate root cause",
    )

    items = {item["id"]: item for item in _feed(client)["items"]}

    done_item = items[f"audit:{done}"]
    assert done_item["dispatch"] == {
        "agent_id": "va-acme-01", "role": "vulnerability-analyst", "run_id": run_id,
    }
    assert done_item["actor"]["kind"] == "agent"
    assert [(e["type"], e["key"]) for e in done_item["entities"]] == [
        ("finding", "VA-001"), ("finding", "VA-002"), ("run", str(run_id)),
    ]
    assert done_item["summary"] == "va-acme-01 finished (completed) · findings VA-001, VA-002"
    record_item = items[f"audit:{record}"]
    assert record_item["category"] == "findings"
    assert record_item["summary"] == "Recorded finding VA-001 (high, active)"
    assert [(e["type"], e["key"]) for e in record_item["entities"]] == [("finding", "VA-001")]
    merged_item = items[f"event:{merged}"]
    assert [(e["type"], e["key"]) for e in merged_item["entities"]] == [("finding", "VA-002")]


def test_feed_drops_event_that_mirrors_an_audit_row(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    record = _audit(
        engagement_id, "2026-04-17T12:00:00.500000Z", "finding-record",
        actor_name="vulnerability-analyst", action="finding=VA-001 severity=high", result="active",
        metadata={"finding_slug": "VA-001"},
    )
    _event(
        engagement_id, "2026-04-17 12:00:01", "finding.created",
        task_name="VA-001", agent_name="vulnerability-analyst", summary="Recorded VA-001",
    )
    # A structured event with no audit counterpart (older engagements) stays.
    legacy = _event(
        engagement_id, "2026-04-17 12:30:00", "finding.created",
        task_name="VA-002", agent_name="vulnerability-analyst", summary="Recorded VA-002",
    )

    payload = _feed(client)

    assert [item["id"] for item in payload["items"]] == [f"event:{legacy}", f"audit:{record}"]
    assert {c["key"]: c["count"] for c in payload["categories"]}["findings"] == 2


def test_feed_search_and_time_range(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    early_note = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "Mapped Acme billing exports",
        actor_kind="agent", actor_name="recon-specialist",
    )
    late_note = _audit(
        engagement_id, "2026-04-18T09:00:00Z", "Billing export replay blocked",
        actor_kind="agent", actor_name="exploit-developer",
    )
    surface = _event(
        engagement_id, "2026-04-18 10:00:00", "surface.updated",
        task_name="file_handling", agent_name="recon-specialist",
        summary="file_handling discovered: https://billing.example.com/export",
    )
    _event(
        engagement_id, "2026-04-18 11:00:00", "chain.created",
        task_name="unrelated-chain", summary="Attack chain recorded: unrelated-chain",
    )

    searched = _feed(client, q="billing")
    assert [item["id"] for item in searched["items"]] == [
        f"event:{surface}", f"audit:{late_note}", f"audit:{early_note}",
    ]
    assert searched["total"] == 3

    ranged = _feed(client, q="billing", since="2026-04-18T00:00:00Z", until="2026-04-18T09:30:00+00:00")
    assert [item["id"] for item in ranged["items"]] == [f"audit:{late_note}"]

    invalid = client.get(FEED, params={"since": "yesterday"})
    assert invalid.status_code == 422, invalid.text
    bad_cursor = client.get(FEED, params={"before": "not-a-cursor"})
    assert bad_cursor.status_code == 422, bad_cursor.text


def test_feed_unknown_engagement_returns_404(client, isolate_settings):
    response = client.get("/engagements/does-not-exist/activity")
    assert response.status_code == 404


def test_feed_summaries_read_as_sentences(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    rows = {
        "verify": _audit(
            engagement_id, "2026-04-17T12:00:00Z", "verify-finding",
            action="finding=VA-003 disposition=confirmed", result="Reproduced twice",
            metadata={"finding_slug": "VA-003", "disposition": "confirmed"},
        ),
        "refresh": _audit(
            engagement_id, "2026-04-17T12:00:01Z", "artifact refresh",
            actor_name="operator", action="refresh", result="refreshed=12 missing=1",
            metadata={"refreshed": 12, "present": 11, "missing": 1},
        ),
        "bash": _audit(
            engagement_id, "2026-04-17T12:00:02Z", "Bash",
            actor_kind="hook", actor_name="recon-specialist", action="bash: dig app.example.com",
        ),
    }
    rows["link"] = _audit(
        engagement_id, "2026-04-17T12:00:02.500000Z", "finding-link",
        actor_name="operator", action="finding=VA-004 root_cause=VA-003", result="eliminates_attack_path",
        metadata={"finding_slug": "VA-004", "root_cause_slug": "VA-003"},
    )
    intel = _event(
        engagement_id, "2026-04-17 12:00:03", "intel.recorded",
        task_name="tech-component", agent_name="recon-specialist", summary="nginx 1.25",
    )

    items = {item["id"]: item for item in _feed(client, category="findings,files,tools,knowledge")["items"]}

    assert items[f"audit:{rows['verify']}"]["summary"] == "Set VA-003 verification to confirmed: Reproduced twice"
    assert items[f"audit:{rows['refresh']}"]["summary"] == "Refreshed the file index: 11 present, 1 missing"
    assert items[f"audit:{rows['bash']}"]["summary"] == "Ran: dig app.example.com"
    assert items[f"audit:{rows['link']}"]["summary"] == "Linked VA-004 to root cause VA-003 (eliminates attack path)"
    intel_item = items[f"event:{intel}"]
    assert intel_item["summary"] == "Recorded tech component intel: nginx 1.25"
    assert [(entity["type"], entity["label"]) for entity in intel_item["entities"]] == [
        ("intel", "Tech component: nginx 1.25"),
    ]


def test_feed_search_matches_the_summary_the_operator_sees(client, isolate_settings):
    """Regression: the visible summary is built at read time, so search must
    match it as well as the stored fields."""
    engagement_id = _seed(client, isolate_settings)
    done = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "agent done",
        actor_name="va-acme-01", action="agent_id=va-acme-01", result="completed",
        metadata={"agent_id": "va-acme-01"},
    )
    review = _audit(
        engagement_id, "2026-04-17T12:01:00Z", "code-record analysis",
        actor_name="code-vuln-hunter", action="file_id=4711 receipt=file", result="clean",
        metadata={"file_id": 4711, "disposition": "clean", "finding_slug": ""},
    )
    # Prose that mentions every word of the summary but not the record itself.
    handoff = _audit(
        engagement_id, "2026-04-17T12:02:00Z", "agent handoff",
        actor_name="va-acme-02", result="Reviewed the code file list; va-acme-01 finished earlier",
        metadata={"agent_id": "va-acme-02"},
    )
    intel = _event(
        engagement_id, "2026-04-17 12:03:00", "intel.recorded",
        task_name="tech-component", agent_name="recon-specialist", summary="nginx 1.25",
    )
    body_note = _audit(
        engagement_id, "2026-04-17T12:04:00Z", "Mapped the Acme export",
        actor_kind="agent", actor_name="recon-specialist", body="Résumé of billing exports",
    )

    def ids(query: str) -> list[str]:
        return [item["id"] for item in _feed(client, q=query)["items"]]

    assert ids("va-acme-01 finished") == [f"audit:{handoff}", f"audit:{done}"]
    assert ids("Reviewed code file #4711") == [f"audit:{review}"]
    assert ids("tech component intel") == [f"event:{intel}"]
    # Stored verbatim fields keep matching, including word-level FTS matches.
    assert ids("receipt=file") == [f"audit:{review}"]
    assert ids("resume") == [f"audit:{body_note}"]
    searched = _feed(client, q="finished")
    assert searched["total"] == 2
    counts = {category["key"]: category["count"] for category in searched["categories"]}
    assert counts["lifecycle"] == 1 and counts["decisions"] == 1
    # Category selection and cursors still apply to the matched rows.
    lifecycle = _feed(client, q="finished", category="lifecycle")
    assert [item["id"] for item in lifecycle["items"]] == [f"audit:{done}"]
    first = _feed(client, q="finished", limit=1)
    assert first["has_more"] is True
    older = _feed(client, q="finished", limit=1, before=first["items"][0]["cursor"])
    assert [item["id"] for item in older["items"]] == [f"audit:{done}"]
    assert older["has_more"] is False


def test_feed_search_matches_the_dispatch_run_chip(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    with db.get_connection() as connection:
        dispatch_id = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, dispatched_at, status
            ) VALUES (?, 'va-acme-07', 'vulnerability-analyst', '2026-04-17T11:59:00Z', 'completed')
            """,
            (engagement_id,),
        ).lastrowid
        run_id = connection.execute(
            """
            INSERT INTO assessment_runs (engagement_id, run_uuid, run_kind, producer_dispatch_id)
            VALUES (?, 'run-acme-7', 'web', ?)
            """,
            (engagement_id, dispatch_id),
        ).lastrowid
    start = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "agent start",
        actor_name="vulnerability-analyst", action="agent_id=va-acme-07",
        metadata={"agent_id": "va-acme-07"},
    )
    _audit(engagement_id, "2026-04-17T12:01:00Z", "Unrelated note", actor_kind="agent", actor_name="recon-specialist")

    payload = _feed(client, q=f"Run #{run_id}")

    assert [item["id"] for item in payload["items"]] == [f"audit:{start}"]
    assert ("run", f"Run #{run_id}") in [(e["type"], e["label"]) for e in payload["items"][0]["entities"]]


def test_feed_entity_chips_resolve_concrete_records(client, isolate_settings):
    """Every chip names the record it opens, or says why it cannot."""
    engagement_id = _seed(client, isolate_settings)
    with db.get_connection() as connection:
        surface_id = connection.execute(
            """
            INSERT INTO assessment_surfaces (engagement_id, surface_type, target_descriptor, status)
            VALUES (?, 'auth_entry', 'https://app.example.com/login: sso', 'discovered')
            """,
            (engagement_id,),
        ).lastrowid
        note_id = connection.execute(
            "INSERT INTO intel_notes (engagement_id, title, created_at) VALUES (?, 'Acme login notes', '2026-04-17 11:59:00')",
            (engagement_id,),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO intel_tech_components (engagement_id, component, version, created_at)
            VALUES (?, 'nginx', '1.24', '2026-04-16 08:00:00')
            """,
            (engagement_id,),
        )
        nginx_id = connection.execute(
            """
            INSERT INTO intel_tech_components (engagement_id, component, version, created_at)
            VALUES (?, 'nginx', '1.25', '2026-04-17 11:59:30')
            """,
            (engagement_id,),
        ).lastrowid
        # Recorded after the event: not the record the event announced.
        connection.execute(
            """
            INSERT INTO intel_tech_components (engagement_id, component, version, created_at)
            VALUES (?, 'nginx', '1.26', '2026-04-18 08:00:00')
            """,
            (engagement_id,),
        )
        chain_id = connection.execute(
            """
            INSERT INTO assessment_attack_chains (engagement_id, chain_key, title)
            VALUES (?, ?, 'Acme login takeover')
            """,
            (engagement_id, "acme-login-takeover-" + "x" * 150),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_attack_chain_links (engagement_id, chain_id, relation, entity_kind, entity_ref)
            VALUES (?, ?, 'evidence', 'artifact', 'evidence/login.txt'),
                   (?, ?, 'step', 'finding', 'VA-002'),
                   (?, ?, 'outcome', 'finding', 'VA-001')
            """,
            (engagement_id, chain_id) * 3,
        )
        bare_chain = connection.execute(
            "INSERT INTO assessment_attack_chains (engagement_id, chain_key, title) VALUES (?, 'acme-bare-chain', 'Bare')",
            (engagement_id,),
        ).lastrowid
        assert bare_chain
    events = {
        "surface": _event(
            engagement_id, "2026-04-17 12:00:00", "surface.updated", task_name="auth_entry",
            summary="auth_entry discovered: https://app.example.com/login: sso",
        ),
        "gone_surface": _event(
            engagement_id, "2026-04-17 12:00:01", "surface.updated", task_name="auth_entry",
            summary="auth_entry covered: https://retired.example.com/",
        ),
        "note": _event(
            engagement_id, "2026-04-17 12:00:02", "intel.recorded", task_name="note", summary="Acme login notes",
        ),
        "tech": _event(
            engagement_id, "2026-04-17 12:00:03", "intel.recorded", task_name="tech-component", summary="nginx",
        ),
        "breach": _event(
            engagement_id, "2026-04-17 12:00:04", "intel.recorded", task_name="breach-record", summary="breach-record",
        ),
        # The CLI truncates the chain key to the event's 128-character task name.
        "chain": _event(
            engagement_id, "2026-04-17 12:00:05", "chain.created",
            task_name=("acme-login-takeover-" + "x" * 150)[:128],
        ),
        "bare_chain": _event(engagement_id, "2026-04-17 12:00:06", "chain.created", task_name="acme-bare-chain"),
    }
    audits = {
        "root_file": _audit(
            engagement_id, "2026-04-17T12:00:07Z", "artifact register", actor_name="operator",
            action="RESUME.md", result="handoff", metadata={"relative_path": "RESUME.md", "artifact_id": 3},
        ),
        "evidence_file": _audit(
            engagement_id, "2026-04-17T12:00:08Z", "artifact register", actor_name="operator",
            action="notes/acme.md", result="note", metadata={"relative_path": "notes/acme.md", "artifact_id": 4},
        ),
        "finding": _audit(
            engagement_id, "2026-04-17T12:00:09Z", "finding-update", actor_name="va-acme-01",
            action="finding=VA-001", metadata={"finding_slug": "VA-001", "request_variant_id": 12, "run_id": 5},
        ),
    }

    items = {item["id"]: item for item in _feed(client, category=",".join(
        ["findings", "knowledge", "files", "notes", "decisions", "lifecycle", "code"]
    ))["items"]}

    def chips(kind: str, row_id: int) -> list[dict]:
        return items[f"{kind}:{row_id}"]["entities"]

    assert [(e["type"], e["ref"], e["unlinked_reason"]) for e in chips("event", events["surface"])] == [
        ("surface", {"surface_id": surface_id}, ""),
    ]
    [gone] = chips("event", events["gone_surface"])
    assert gone["ref"] is None and gone["unlinked_reason"]
    [note] = chips("event", events["note"])
    assert note["ref"] == {"intel_type": "note", "intel_id": note_id}
    assert note["label"] == "Note: Acme login notes"
    [tech] = chips("event", events["tech"])
    assert tech["ref"] == {"intel_type": "tech_component", "intel_id": nginx_id}
    [breach] = chips("event", events["breach"])
    assert breach["ref"] is None and breach["unlinked_reason"]
    [chain] = chips("event", events["chain"])
    assert chain["ref"] == {"chain_key": "acme-login-takeover-" + "x" * 150, "finding_slug": "VA-002"}
    [bare] = chips("event", events["bare_chain"])
    assert bare["ref"] is None and bare["unlinked_reason"]
    [root_file] = chips("audit", audits["root_file"])
    assert root_file["ref"] == {"file_name": "RESUME.md"}
    [evidence_file] = chips("audit", audits["evidence_file"])
    assert evidence_file["ref"] is None and evidence_file["unlinked_reason"]
    assert [(e["type"], e["ref"]) for e in chips("audit", audits["finding"])] == [
        ("finding", {"finding_slug": "VA-001"}),
        ("http_variant", {"request_variant_id": 12}),
        ("run", {"run_id": 5}),
    ]


def test_feed_search_sees_rows_written_after_an_earlier_search(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    first = _audit(
        engagement_id, "2026-04-17T12:00:00Z", "agent done",
        actor_name="va-acme-01", result="completed", metadata={"agent_id": "va-acme-01"},
    )
    assert [item["id"] for item in _feed(client, q="finished")["items"]] == [f"audit:{first}"]
    later = _audit(
        engagement_id, "2026-04-17T12:05:00Z", "agent done",
        actor_name="va-acme-02", result="completed", metadata={"agent_id": "va-acme-02"},
    )
    event = _event(
        engagement_id, "2026-04-17 12:06:00", "intel.recorded", task_name="note", summary="Acme finished notes",
    )
    assert [item["id"] for item in _feed(client, q="finished")["items"]] == [
        f"event:{event}", f"audit:{later}", f"audit:{first}",
    ]


# ── One entry by id ─────────────────────────────────────────────────────


def _walk_feed(client, **params) -> list[dict]:
    seen: list[dict] = []
    cursor = None
    while True:
        page = _feed(client, limit=2, **params, **({"before": cursor} if cursor else {}))
        seen.extend(page["items"])
        if not page["has_more"]:
            return seen
        cursor = page["items"][-1]["cursor"]


def test_entry_lookup_returns_the_item_the_feed_returns(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    with db.get_connection() as connection:
        dispatch_id = connection.execute(
            """
            INSERT INTO assessment_dispatches (
                engagement_id, agent_id, agent_role, dispatched_at, status
            ) VALUES (?, 'va-acme-01', 'vulnerability-analyst', '2026-04-17T11:59:00Z', 'completed')
            """,
            (engagement_id,),
        ).lastrowid
        connection.execute(
            """
            INSERT INTO assessment_runs (engagement_id, run_uuid, run_kind, producer_dispatch_id)
            VALUES (?, 'run-acme-1', 'web', ?)
            """,
            (engagement_id, dispatch_id),
        )
    secret = "Authorization: Bearer acme-secret-" + "x" * 4000
    _audit(
        engagement_id, "2026-04-17T12:05:00Z", "agent done",
        actor_name="va-acme-01", action="agent_id=va-acme-01", result="completed",
        metadata={"agent_id": "va-acme-01", "finding_slugs": ["VA-001", "VA-002"]},
    )
    _audit(
        engagement_id, "2026-04-17T12:04:00Z", "Bash",
        actor_kind="hook", actor_name="va-acme-01", action=f"bash: curl -H '{secret}' https://app.example.com/",
        body=secret, metadata={"relative_path": "scans/acme.txt", "token": secret},
    )
    _audit(engagement_id, "sometime on tuesday", "Undated note", actor_kind="agent", actor_name="recon-specialist")
    _event(
        engagement_id, "2026-04-17 12:01:00", "surface.updated",
        task_name="auth_entry", agent_name="recon-specialist",
        summary="auth_entry discovered: https://app.example.com/login",
    )
    _event(engagement_id, "not a time", "chain.created", task_name="acme-chain")

    listed = _walk_feed(client, category="decisions,findings,knowledge,lifecycle,code,files,notes,tools")

    assert len(listed) == 5
    for item in listed:
        response = client.get(f"{FEED}/{item['id']}")
        assert response.status_code == 200, response.text
        assert response.json() == item
    tool_call = next(item for item in listed if item["kind"] == "Bash")
    assert tool_call["detail"]["body_markdown"] == secret
    assert tool_call["detail"]["metadata"]["token"] == secret


def test_entry_lookup_is_scoped_to_the_engagement(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    other_key = "2026-04-17-120300-activity-other"
    write_engagement(isolate_settings["engagements_dir"], key=other_key)
    other = client.get(f"/engagements/{other_key}")
    assert other.status_code == 200, other.text
    mine = _audit(engagement_id, "2026-04-17T12:00:00Z", "Acme note", actor_kind="agent", actor_name="recon-specialist")
    theirs = _audit(int(other.json()["id"]), "2026-04-17T12:00:00Z", "Other note", actor_kind="agent", actor_name="recon-specialist")
    their_event = _event(int(other.json()["id"]), "2026-04-17 12:01:00", "chain.created", task_name="other-chain")

    assert client.get(f"{FEED}/audit:{mine}").status_code == 200
    for entry_id in (f"audit:{theirs}", f"event:{their_event}"):
        response = client.get(f"{FEED}/{entry_id}")
        assert response.status_code == 404, response.text
        assert entry_id in response.json()["detail"]
    assert client.get(f"/engagements/{other_key}/activity/audit:{theirs}").json()["summary"] == "Other note"


def test_entry_lookup_unknown_entry_and_engagement_return_404(client, isolate_settings):
    engagement_id = _seed(client, isolate_settings)
    known = _audit(engagement_id, "2026-04-17T12:00:00Z", "Acme note", actor_kind="agent", actor_name="recon-specialist")
    # The feed never lists the event `vigil assess log` mirrors from its audit row.
    mirrored = _event(
        engagement_id, "2026-04-17 12:00:00", "activity.recorded",
        task_name="activity-entry", agent_name="recon-specialist", summary="Acme note",
    )

    for entry_id in (f"audit:{known + 1000}", f"event:{known}", f"event:{mirrored}", "audit:99999999999999999999999999"):
        response = client.get(f"{FEED}/{entry_id}")
        assert response.status_code == 404, f"{entry_id}: {response.text}"
        assert entry_id in response.json()["detail"]
    assert client.get(f"/engagements/does-not-exist/activity/audit:{known}").status_code == 404


def test_entry_lookup_refuses_a_malformed_id(client, isolate_settings):
    _seed(client, isolate_settings)

    for entry_id in ("audit", "audit:", "audit:0", "audit:-1", "audit:1.5", "audit:01", "audit:abc", "note:3", "AUDIT:3", "audit:3:4", "3", "audit:3%0A"):
        response = client.get(f"{FEED}/{entry_id}")
        assert response.status_code == 422, f"{entry_id}: {response.status_code} {response.text}"
        detail = response.json()["detail"]
        assert "audit:<id>" in detail and "event:<id>" in detail


def test_feed_category_counts_equal_the_categories_of_the_rows_listed(client, isolate_settings):
    """Every category count is the number of rows the feed lists in it, under every filter.

    The rows cover each category from both sources, hook lifecycle rows matched by
    title prefix and by exact title, actor identities of every derived kind, an
    undated row, a mirrored ``finding.created`` event and an ``activity.recorded``
    copy (both listed nowhere, so counted nowhere).
    """
    engagement_id = _seed(client, isolate_settings)
    stamp = iter(f"2026-04-17T12:{minute:02d}:00Z" for minute in range(60))
    for title, actor_kind, actor_name in (
        ("Bash", "hook", "HUNT-01"),
        ("Read", "hook", "HUNT-02"),
        ("Bash", "hook", "operator"),
        ("Bash", "hook", "acme-hook"),
        ("Dispatch: HUNT-01", "hook", "HUNT-01"),
        ("Client session ended", "hook", "HUNT-02"),
        ("agent decision", "system", "vigil-assess"),
        ("agent start", "system", "code-vuln-hunter"),
        ("update-finding", "system", "vulnerability-analyst"),
        ("code-dispatch done", "system", "HUNT-01"),
        ("code-record analysis", "system", ""),
        ("artifact register", "system", "web-ui"),
        ("Submission recorded", "system", "system"),
        ("Recon notes", "agent", "recon-specialist"),
        ("Operator note", "operator", "operator"),
        ("Unclassified system row", "system", "unknown"),
    ):
        _audit(engagement_id, next(stamp), title, actor_kind=actor_kind, actor_name=actor_name)
    _audit(engagement_id, "not a time", "Undated note", actor_kind="agent", actor_name="recon-specialist")
    _audit(
        engagement_id, "2026-04-17T13:00:00Z", "finding-record",
        actor_name="vulnerability-analyst", metadata={"finding_slug": "VA-001"},
    )
    for event_type, agent_name in (
        ("finding.created", "vulnerability-analyst"),
        ("chain.created", "operator"),
        ("surface.updated", "recon-specialist"),
        ("intel.recorded", "system"),
        ("phase.started", "operator"),
        ("verification_decision", "vigil-assess"),
        ("code_analysis.updated", "HUNT-01"),
        ("artifact.updated", "operator"),
        ("report.generated", ""),
        ("something.else", "recon-specialist"),
        ("activity.recorded", "HUNT-01"),
    ):
        _event(engagement_id, "2026-04-17 13:30:00", event_type, task_name="task", agent_name=agent_name)
    _event(engagement_id, "2026-04-17 13:30:01", "artifact.updated", task_name="log.md", agent_name="operator")
    _event(engagement_id, "2026-04-17 13:00:01", "finding.created", task_name="VA-001", agent_name="vulnerability-analyst")

    every = ",".join(sorted({c["key"] for c in _feed(client)["categories"]}))
    for filters in (
        {},
        {"actor": "agent"},
        {"actor": "system"},
        {"actor": "operator"},
        {"since": "2026-04-17T12:05:00Z", "until": "2026-04-17T13:00:00Z"},
        {"q": "HUNT-01"},
    ):
        listed = _feed(client, category=every, limit=500, **filters)
        assert not listed["has_more"]
        expected = {key: 0 for key in every.split(",")}
        for item in listed["items"]:
            expected[item["category"]] += 1
        assert {c["key"]: c["count"] for c in listed["categories"]} == expected, filters
        assert listed["total"] == len(listed["items"]), filters
        default_view = _feed(client, **filters)
        assert default_view["total"] == len(listed["items"]) - expected["tools"], filters
        assert default_view["categories"] == listed["categories"], filters
