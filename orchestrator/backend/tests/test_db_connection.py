from app import db


def test_get_connection_reuses_same_thread_connection(client):
    with db.get_connection() as first:
        with db.get_connection() as nested:
            assert nested is first

    with db.get_connection() as second:
        assert second is first


def test_get_connection_commits_at_outermost_context(client):
    with db.get_connection() as connection:
        connection.execute(
            "INSERT INTO engagements (key, target, status, engagement_root) VALUES (?, ?, ?, ?)",
            ("reuse-test", "example.com", "in_progress", "/tmp/reuse-test"),
        )
        with db.get_connection() as nested:
            assert nested.execute(
                "SELECT COUNT(*) FROM engagements WHERE key = ?",
                ("reuse-test",),
            ).fetchone()[0] == 1

    with db.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM engagements WHERE key = ?",
            ("reuse-test",),
        ).fetchone()[0] == 1


def test_get_connection_rolls_back_outermost_exception(client):
    try:
        with db.get_connection() as connection:
            connection.execute(
                "INSERT INTO engagements (key, target, status, engagement_root) VALUES (?, ?, ?, ?)",
                ("rollback-test", "example.com", "in_progress", "/tmp/rollback-test"),
            )
            with db.get_connection() as nested:
                assert nested is connection
            raise RuntimeError("rollback")
    except RuntimeError:
        pass

    with db.get_connection() as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM engagements WHERE key = ?",
            ("rollback-test",),
        ).fetchone()[0] == 0
