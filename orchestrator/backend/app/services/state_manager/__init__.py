"""State manager package.

Canonical home for the state-manager domain logic (formerly the 7411-line
``state_manager.py`` module). Every consumer accesses it via attribute access
(``state_manager.X``); this ``__init__`` re-exports the full public surface plus
the private/monkeypatched names that tests and internal callers depend on.
Private names are re-exported BY OBJECT REFERENCE so identity is preserved
(the ``lru_cache``-backed ``_retention_config`` and the monkeypatch targets).
"""

from __future__ import annotations

from ._common import (
    SEVERITY_RANK,
    WORKFLOW_STATUSES,
    WORKFLOW_STATUS_RANK,
    VERIFICATION_STATES,
    VERIFICATION_STATE_RANK,
    VERIFICATION_DISPOSITIONS,
    VERIFICATION_DISPOSITION_RANK,
    COMMAND_RUN_TERMINAL_STATUSES,
    ROOT_CAUSE_LINK_KIND,
    ROOT_CAUSE_EFFECTS,
    SLUG_RE,
)
from .links import (
    create_finding_link,
    set_root_cause_link,
    clear_root_cause_link,
    list_finding_links,
    list_finding_groups,
)
from .findings import (
    create_finding,
    update_finding,
    patch_finding,
    verify_finding,
    merge_findings,
    list_findings,
    get_finding,
    list_exploit_candidates,
    list_finding_transitions,
)
from .dispatches import (
    record_dispatch,
    update_dispatch,
    get_dispatch,
    list_dispatches,
    record_handoff,
    update_handoff,
    get_handoff,
    list_handoffs,
    record_decision,
    list_decisions,
    update_decision,
)
from .coverage import (
    COVERAGE_STATUSES,
    PROBE_RESULT_STATUSES,
    PROBE_RESULT_STATUSES_COVERING,
    PROBE_RESULT_STATUS_DEFAULT,
    record_target,
    list_targets,
    record_service,
    list_services,
    record_request_variant,
    list_request_variants,
    list_request_observations,
    ingest_request_observation,
    record_coverage_item,
    list_coverage_items,
    record_probe_run,
    list_probe_runs,
    record_surface,
    list_surfaces,
    update_surface,
    coverage_readiness,
    PER_HOST_OBJECTIVES,
    per_host_coverage,
    per_host_finding_verdicts,
    update_coverage_item_status,
    vendor_saas_hosts_pending_decision,
    egress_block_status,
    coverage_rollup,
)
from .app_units import (
    score_application_units,
    list_application_units,
    set_app_unit_override,
)
from .depth_ledger import (
    depth_ledger,
    terminal_depth_block,
)
from .phase_readiness import (
    phase_readiness,
    PHASES as PHASE_READINESS_PHASES,
    PHASE_REQUIRE_STAGE,
)
from .report_readiness import (
    report_readiness,
    list_report_findings,
    list_report_finding_groups,
)
from .chains import (
    create_attack_chain,
    create_attack_chain_link,
    list_attack_chains,
    list_attack_chain_links,
    record_credential,
    list_credentials,
    record_credential_test,
    list_credential_tests,
    record_access_record,
    list_access_records,
    record_pivot,
    list_pivots,
    record_tunnel,
    list_tunnels,
    record_blocked_technique,
    list_blocked_techniques,
)
from .command_runs import (
    record_command_run,
    finalize_command_run,
    record_job,
    update_job,
    list_jobs,
    get_job,
    list_command_runs,
    get_command_run,
    upsert_host_liveness,
    host_liveness,
)
from .oob import (
    record_oob_probe,
    list_oob_probes,
    get_oob_probe_by_nonce,
    correlate_oob_interaction,
)
from .assessment_summary import (
    assessment_summary,
)

# Private / monkeypatched names, re-exported by object reference so identity is
# preserved. Importing them here keeps ``state_manager.X`` working for legacy
# access. NOTE: this re-export is NOT the patch-effective location for
# ``_engagement_or_404``. Every submodule (and ``_common`` itself) binds the
# name locally via ``from ..events import _engagement_or_404``, so the only
# canonical patch target that all callers observe is
# ``app.services.events._engagement_or_404`` — patching the ``_common`` (or this
# package-level) alias would not affect those local bindings.
from ._common import (  # noqa: F401
    _append_notes,
    _engagement_or_404,
    get_connection,
)
from .command_runs import _retention_config  # noqa: F401

__all__ = [
    "SEVERITY_RANK",
    "WORKFLOW_STATUSES",
    "WORKFLOW_STATUS_RANK",
    "VERIFICATION_STATES",
    "VERIFICATION_STATE_RANK",
    "VERIFICATION_DISPOSITIONS",
    "VERIFICATION_DISPOSITION_RANK",
    "COMMAND_RUN_TERMINAL_STATUSES",
    "ROOT_CAUSE_LINK_KIND",
    "ROOT_CAUSE_EFFECTS",
    "SLUG_RE",
    "create_finding_link",
    "set_root_cause_link",
    "clear_root_cause_link",
    "list_finding_links",
    "list_finding_groups",
    "create_finding",
    "update_finding",
    "patch_finding",
    "verify_finding",
    "merge_findings",
    "list_findings",
    "get_finding",
    "list_exploit_candidates",
    "list_finding_transitions",
    "record_dispatch",
    "update_dispatch",
    "get_dispatch",
    "list_dispatches",
    "record_handoff",
    "update_handoff",
    "get_handoff",
    "list_handoffs",
    "record_decision",
    "list_decisions",
    "update_decision",
    "COVERAGE_STATUSES",
    "PROBE_RESULT_STATUSES",
    "PROBE_RESULT_STATUSES_COVERING",
    "PROBE_RESULT_STATUS_DEFAULT",
    "record_target",
    "list_targets",
    "record_service",
    "list_services",
    "record_request_variant",
    "list_request_variants",
    "list_request_observations",
    "ingest_request_observation",
    "record_coverage_item",
    "list_coverage_items",
    "record_probe_run",
    "list_probe_runs",
    "record_surface",
    "list_surfaces",
    "update_surface",
    "coverage_readiness",
    "PER_HOST_OBJECTIVES",
    "per_host_coverage",
    "per_host_finding_verdicts",
    "update_coverage_item_status",
    "vendor_saas_hosts_pending_decision",
    "egress_block_status",
    "coverage_rollup",
    "score_application_units",
    "list_application_units",
    "set_app_unit_override",
    "depth_ledger",
    "terminal_depth_block",
    "phase_readiness",
    "PHASE_READINESS_PHASES",
    "PHASE_REQUIRE_STAGE",
    "report_readiness",
    "list_report_findings",
    "list_report_finding_groups",
    "create_attack_chain",
    "create_attack_chain_link",
    "list_attack_chains",
    "list_attack_chain_links",
    "record_credential",
    "list_credentials",
    "record_credential_test",
    "list_credential_tests",
    "record_access_record",
    "list_access_records",
    "record_pivot",
    "list_pivots",
    "record_tunnel",
    "list_tunnels",
    "record_blocked_technique",
    "list_blocked_techniques",
    "record_command_run",
    "finalize_command_run",
    "record_job",
    "update_job",
    "list_jobs",
    "get_job",
    "list_command_runs",
    "get_command_run",
    "upsert_host_liveness",
    "host_liveness",
    "record_oob_probe",
    "list_oob_probes",
    "get_oob_probe_by_nonce",
    "correlate_oob_interaction",
    "assessment_summary",
]
