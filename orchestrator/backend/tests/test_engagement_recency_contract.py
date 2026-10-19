"""The offline CLI's declared work clocks match the executable backend schema."""
import sqlite3

from app import db
from vigil_cli.engagement_recency import ACTIVITY_SOURCES


def test_declared_recency_sources_have_real_clocks_and_engagement_ownership(isolate_settings):
    db.init_db()
    with sqlite3.connect(db.database_path()) as database:
        tables = {row[0] for row in database.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for source in ACTIVITY_SOURCES:
            assert source.table in tables
            columns = {row[1] for row in database.execute(f'PRAGMA table_info("{source.table}")')}
            assert {clock.partition(":")[0] for clock in source.timestamps} <= columns
            if source.parent:
                assert source.foreign_key in columns
                parent_columns = {row[1] for row in database.execute(f'PRAGMA table_info("{source.parent}")')}
                assert {"id", "engagement_id"} <= parent_columns
            else:
                assert "engagement_id" in columns
