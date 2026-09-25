"""SQLite schema for the code-analysis persistence subsystem."""

from __future__ import annotations



import sqlite3

def create_tables(connection: sqlite3.Connection) -> None:
    # ── Code Analysis Tables ──────────────────────────────────
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_repos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_key TEXT NOT NULL,
                name TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT '',
                repo_path TEXT NOT NULL,
                total_files INTEGER NOT NULL DEFAULT 0,
                analyzable_files INTEGER NOT NULL DEFAULT 0,
                total_loc INTEGER NOT NULL DEFAULT 0,
                commit_hash TEXT NOT NULL DEFAULT '',
                branch TEXT NOT NULL DEFAULT '',
                analysis_status TEXT NOT NULL DEFAULT 'ingested',
                repo_role TEXT NOT NULL DEFAULT 'analysis',
                threat_model_json TEXT NOT NULL DEFAULT '{}',
                git_churn_json TEXT NOT NULL DEFAULT '{}',
                lsp_config_json TEXT NOT NULL DEFAULT '{}',
                active_generation INTEGER NOT NULL DEFAULT 0,
                source_origin_path TEXT NOT NULL DEFAULT '',
                source_kind TEXT NOT NULL DEFAULT 'legacy',
                snapshot_manifest_path TEXT NOT NULL DEFAULT '',
                snapshot_digest TEXT NOT NULL DEFAULT '',
                source_review_identity_digest TEXT NOT NULL DEFAULT '',
                source_manifest_version TEXT NOT NULL DEFAULT 'v1',
                source_manifest_digest TEXT NOT NULL DEFAULT '',
                source_snapshot_quality TEXT NOT NULL DEFAULT 'legacy-unverified',
                worktree_dirty INTEGER,
                structural_index_schema TEXT NOT NULL DEFAULT '',
                structural_index_generation INTEGER,
                structural_index_manifest_path TEXT NOT NULL DEFAULT '',
                structural_degraded_files INTEGER NOT NULL DEFAULT 0,
                structural_degraded_file_paths_json TEXT NOT NULL DEFAULT '[]',
                structural_artifact_truncated_files INTEGER NOT NULL DEFAULT 0,
                structural_artifact_truncated_file_paths_json TEXT NOT NULL DEFAULT '[]',
                structural_analysis_status_counts_json TEXT NOT NULL DEFAULT '{}',
                threat_model_generation INTEGER,
                pending_refresh_token TEXT NOT NULL DEFAULT '',
                pending_refresh_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_modules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                module_key TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                trust_boundary TEXT NOT NULL DEFAULT '',
                file_count INTEGER NOT NULL DEFAULT 0,
                critical_file_count INTEGER NOT NULL DEFAULT 0,
                analysis_status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_id, module_key),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT '',
                loc INTEGER NOT NULL DEFAULT 0,
                file_hash TEXT NOT NULL DEFAULT '',
                classification TEXT NOT NULL DEFAULT 'unclassified',
                role TEXT NOT NULL DEFAULT '',
                slot_types_json TEXT NOT NULL DEFAULT '[]',
                analysis_priority INTEGER NOT NULL DEFAULT 0,
                analysis_status TEXT NOT NULL DEFAULT 'unclassified',
                analysis_depth TEXT NOT NULL DEFAULT 'none',
                skip_reason TEXT NOT NULL DEFAULT '',
                variant_check_status TEXT NOT NULL DEFAULT 'pending',
                module_id INTEGER,
                git_churn_score INTEGER NOT NULL DEFAULT 0,
                has_past_cve_fix INTEGER NOT NULL DEFAULT 0,
                header_snippet TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                structural_analysis_status TEXT NOT NULL DEFAULT 'pending',
                structural_analysis_mode TEXT NOT NULL DEFAULT '',
                structural_degradation_reason TEXT NOT NULL DEFAULT '',
                structural_source_size INTEGER NOT NULL DEFAULT 0,
                structural_bytes_scanned INTEGER NOT NULL DEFAULT 0,
                structural_unavailable_dimensions_json TEXT NOT NULL DEFAULT '[]',
                structural_artifact_truncated INTEGER NOT NULL DEFAULT 0,
                structural_truncated_dimensions_json TEXT NOT NULL DEFAULT '[]',
                structural_signal_counts_json TEXT NOT NULL DEFAULT '{}',
                retired_at TEXT,
                retirement_reason TEXT,
                replacement_repo_generation INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_id, file_path),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE,
                FOREIGN KEY(module_id) REFERENCES code_modules(id) ON DELETE SET NULL
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_source_generations (
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_version TEXT NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                source_review_identity_digest TEXT NOT NULL,
                snapshot_manifest_path TEXT NOT NULL DEFAULT '',
                snapshot_digest TEXT NOT NULL DEFAULT '',
                source_snapshot_quality TEXT NOT NULL,
                repo_path TEXT NOT NULL,
                source_origin_path TEXT NOT NULL DEFAULT '',
                source_kind TEXT NOT NULL DEFAULT 'legacy',
                commit_hash TEXT NOT NULL DEFAULT '',
                branch TEXT NOT NULL DEFAULT '',
                worktree_dirty INTEGER,
                promoted_at TEXT NOT NULL,
                source_superseded_at TEXT,
                source_supersession_reason TEXT NOT NULL DEFAULT '',
                replacement_repo_generation INTEGER,
                PRIMARY KEY(engagement_id, repo_id, repo_generation),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_source_generation_files (
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                file_path TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                language TEXT NOT NULL DEFAULT '',
                loc INTEGER NOT NULL DEFAULT 0,
                header_snippet TEXT NOT NULL DEFAULT '',
                git_churn_score INTEGER NOT NULL DEFAULT 0,
                has_past_cve_fix INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(engagement_id, repo_id, repo_generation, file_id),
                UNIQUE(engagement_id, repo_id, repo_generation, file_path),
                FOREIGN KEY(engagement_id, repo_id, repo_generation)
                    REFERENCES code_source_generations(
                        engagement_id, repo_id, repo_generation
                    ) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE RESTRICT
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_analysis_queue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                priority INTEGER NOT NULL DEFAULT 50,
                status TEXT NOT NULL DEFAULT 'pending',
                assigned_agent TEXT NOT NULL DEFAULT '',
                lease_token TEXT NOT NULL DEFAULT '',
                repo_generation INTEGER NOT NULL DEFAULT 0,
                last_heartbeat_at TEXT,
                adopted_leases_json TEXT NOT NULL DEFAULT '[]',
                disposition TEXT NOT NULL DEFAULT '',
                analysis_notes TEXT NOT NULL DEFAULT '',
                skip_reason TEXT NOT NULL DEFAULT '',
                expansion_request_json TEXT NOT NULL DEFAULT '{}',
                batch_theme TEXT NOT NULL DEFAULT '',
                slot_types_json TEXT NOT NULL DEFAULT '[]',
                guidance_hypotheses_json TEXT NOT NULL DEFAULT '[]',
                cwe_coverage_json TEXT NOT NULL DEFAULT '[]',
                cross_file_triggers_json TEXT NOT NULL DEFAULT '[]',
                queue_mode TEXT NOT NULL DEFAULT 'initial',
                reanalysis_reason TEXT NOT NULL DEFAULT '',
                reanalysis_of_queue_item_id INTEGER,
                consumed_at TEXT,
                completed_at TEXT,
                source_superseded_at TEXT,
                source_supersession_reason TEXT NOT NULL DEFAULT '',
                replacement_repo_generation INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                queue_item_id INTEGER,
                file_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL DEFAULT '',
                receipt_kind TEXT NOT NULL DEFAULT 'file',
                callable_refs_json TEXT NOT NULL DEFAULT '[]',
                reviewed_spans_json TEXT NOT NULL DEFAULT '[]',
                receipt_binding_status TEXT NOT NULL DEFAULT 'legacy_unbound',
                function_name TEXT NOT NULL DEFAULT '',
                hypothesis TEXT NOT NULL DEFAULT '',
                evidence TEXT NOT NULL DEFAULT '',
                evidence_ref TEXT NOT NULL DEFAULT '',
                disposition TEXT NOT NULL DEFAULT '',
                confidence TEXT NOT NULL DEFAULT 'medium',
                finding_slug TEXT NOT NULL DEFAULT '',
                cwe_id TEXT NOT NULL DEFAULT '',
                slot_type TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                audit_metadata_json TEXT NOT NULL DEFAULT '{}',
                cwe_coverage_json TEXT NOT NULL DEFAULT '[]',
                cross_file_triggers_json TEXT NOT NULL DEFAULT '[]',
                lease_token TEXT NOT NULL DEFAULT '',
                repo_generation INTEGER NOT NULL DEFAULT 0,
                result_fingerprint TEXT NOT NULL DEFAULT '',
                supersedes_result_id INTEGER UNIQUE REFERENCES code_analysis_results(id) ON DELETE RESTRICT,
                superseded_at TEXT,
                source_superseded_at TEXT,
                source_supersession_reason TEXT NOT NULL DEFAULT '',
                replacement_repo_generation INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_structural_callable_publications (
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                published_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(engagement_id, repo_id, repo_generation),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_structural_callables (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                file_id INTEGER NOT NULL,
                file_sha256 TEXT NOT NULL,
                callable_key TEXT NOT NULL,
                name TEXT NOT NULL,
                qualified_name TEXT NOT NULL,
                start_line INTEGER NOT NULL,
                end_line INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, repo_id, repo_generation, callable_key),
                UNIQUE(engagement_id, file_id, repo_generation, qualified_name, start_line, end_line),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_analysis_result_callables (
                result_id INTEGER NOT NULL,
                callable_id INTEGER NOT NULL,
                file_id INTEGER NOT NULL,
                ordinal INTEGER NOT NULL,
                PRIMARY KEY(result_id, callable_id),
                UNIQUE(result_id, ordinal),
                FOREIGN KEY(result_id) REFERENCES code_analysis_results(id) ON DELETE CASCADE,
                FOREIGN KEY(callable_id) REFERENCES code_structural_callables(id) ON DELETE RESTRICT,
                FOREIGN KEY(file_id) REFERENCES code_files(id) ON DELETE CASCADE
            )
            """
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_structural_callables_current_file "
        "ON code_structural_callables(engagement_id, file_id, repo_generation, qualified_name)"
    )
    connection.execute(
        "CREATE INDEX IF NOT EXISTS idx_code_analysis_result_callables_file "
        "ON code_analysis_result_callables(file_id, result_id)"
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_variant_check_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                dispatch_id INTEGER NOT NULL,
                dispatch_agent_id TEXT NOT NULL,
                dispatch_agent_role TEXT NOT NULL,
                current_file_id INTEGER,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                language TEXT NOT NULL,
                classification TEXT NOT NULL,
                role TEXT NOT NULL,
                slot_types_json TEXT NOT NULL,
                parent_finding_slugs_json TEXT NOT NULL,
                parent_finding_set_digest TEXT NOT NULL,
                variant_input_digest TEXT NOT NULL,
                status TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                rationale TEXT NOT NULL,
                receipt_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, receipt_fingerprint),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(dispatch_id) REFERENCES assessment_dispatches(id) ON DELETE RESTRICT
            )
            """
    )
    connection.execute(
        """
            CREATE INDEX IF NOT EXISTS idx_code_variant_receipts_current_lookup
            ON code_variant_check_receipts(
                engagement_id, repo_id, current_file_id, variant_input_digest
            )
            """
    )
    connection.execute(
        """
            CREATE INDEX IF NOT EXISTS idx_code_variant_receipts_latest_file
            ON code_variant_check_receipts(
                engagement_id, current_file_id, id DESC
            )
            WHERE current_file_id IS NOT NULL
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_fuzz_decisions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                decision TEXT NOT NULL CHECK(decision IN ('required', 'not_required')),
                target_ids_json TEXT NOT NULL DEFAULT '[]',
                evidence_ref TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                rationale TEXT NOT NULL,
                decision_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, decision_fingerprint),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE RESTRICT
            )
            """
    )
    connection.execute(
        """
            CREATE INDEX IF NOT EXISTS idx_code_fuzz_decisions_current
            ON code_fuzz_decisions(
                engagement_id, repo_id, repo_generation,
                source_manifest_digest, id DESC
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_fuzz_campaign_receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                dispatch_id INTEGER NOT NULL,
                dispatch_agent_id TEXT NOT NULL,
                repo_id INTEGER NOT NULL,
                repo_generation INTEGER NOT NULL,
                source_manifest_digest TEXT NOT NULL,
                target_id TEXT NOT NULL,
                covered_finding_slugs_json TEXT NOT NULL DEFAULT '[]',
                engine TEXT NOT NULL,
                sanitizers_json TEXT NOT NULL DEFAULT '[]',
                run_budget_seconds INTEGER NOT NULL,
                executions INTEGER NOT NULL,
                outcome TEXT NOT NULL CHECK(outcome IN (
                    'completed_no_crash', 'completed_crashes_triaged',
                    'build_failed', 'campaign_failed'
                )),
                crash_count INTEGER NOT NULL,
                triage_summary TEXT NOT NULL,
                evidence_ref TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                rationale TEXT NOT NULL,
                receipt_fingerprint TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(engagement_id, receipt_fingerprint),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(dispatch_id) REFERENCES assessment_dispatches(id) ON DELETE RESTRICT,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE RESTRICT
            )
            """
    )
    connection.execute(
        """
            CREATE INDEX IF NOT EXISTS idx_code_fuzz_campaign_receipts_current
            ON code_fuzz_campaign_receipts(
                engagement_id, repo_id, repo_generation,
                source_manifest_digest, target_id, id DESC
            )
            """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_ingest_staging (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                repo_id INTEGER NOT NULL,
                refresh_token TEXT NOT NULL,
                file_path TEXT NOT NULL,
                file_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(repo_id, refresh_token, file_path),
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(repo_id) REFERENCES code_repos(id) ON DELETE CASCADE
            )
        """
    )
    connection.execute(
        """
            CREATE TABLE IF NOT EXISTS code_analysis_triggers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement_id INTEGER NOT NULL,
                source_queue_item_id INTEGER,
                source_file_id INTEGER,
                target_file_id INTEGER,
                target_file_path TEXT NOT NULL DEFAULT '',
                vuln_class TEXT NOT NULL DEFAULT '',
                reason TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                resolved_queue_item_id INTEGER,
                resolution_note TEXT NOT NULL DEFAULT '',
                repo_id INTEGER NOT NULL DEFAULT 0,
                repo_generation INTEGER NOT NULL DEFAULT 0,
                source_manifest_digest TEXT NOT NULL DEFAULT '',
                source_superseded_at TEXT,
                source_supersession_reason TEXT NOT NULL DEFAULT '',
                replacement_repo_generation INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(engagement_id) REFERENCES engagements(id) ON DELETE CASCADE,
                FOREIGN KEY(source_queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE CASCADE,
                FOREIGN KEY(source_file_id) REFERENCES code_files(id) ON DELETE SET NULL,
                FOREIGN KEY(target_file_id) REFERENCES code_files(id) ON DELETE SET NULL,
                FOREIGN KEY(resolved_queue_item_id) REFERENCES code_analysis_queue(id) ON DELETE SET NULL
            )
            """
    )
    # ── End Code Analysis Tables ──────────────────────────────
