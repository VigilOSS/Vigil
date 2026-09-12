from __future__ import annotations

import functools
import os
from typing import Annotated, Any, Literal, TypeAlias

import anyio
from fastapi import APIRouter, Query, Response, status
from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from ..services import activity as activity_service
from ..services import code_analysis
from ..services import code_fuzz_completion
from ..services.engagements import get_engagement_or_404
from ..ws import broadcaster

router = APIRouter(
    prefix="/engagements/{engagement_key}/assessment/code",
    tags=["code-analysis"],
)


CodeSlotType: TypeAlias = Literal[
    "NETWORK-INPUT",
    "URL-COMPONENT",
    "CMD-ARGUMENT",
    "FILE-CONTENT",
    "ENV-VARIABLE",
    "CALLBACK-DATA",
    "PROTOCOL-FIELD",
    "SERIALIZED-DATA",
    "EXEC-POLICY",
]
StrictPositiveId: TypeAlias = Annotated[int, Field(strict=True, gt=0)]
StructuralAnalysisStatus: TypeAlias = Literal["complete", "degraded", "unsupported"]
StructuralAnalysisMode: TypeAlias = Literal[
    "tree_sitter",
    "lightweight_regex",
    "streaming_security_fallback",
    "none",
]
StructuralDimension: TypeAlias = Literal[
    "call_sites",
    "classes",
    "dataflow",
    "entry_points",
    "exports",
    "functions",
    "imports",
    "security_sinks",
    "security_sources",
]
_STREAMING_FALLBACK_UNAVAILABLE_BASELINE = frozenset(
    {"call_sites", "classes", "dataflow", "exports", "functions"}
)
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_MAX_REPO_KEY_BYTES = 255
_MAX_VARIANT_PARENT_FINDINGS = code_analysis.MAX_VARIANT_PARENT_FINDINGS


def _validate_repo_key(value: str) -> str:
    if (
        value in {".", ".."}
        or "/" in value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("repo_key must be one safe path component")
    try:
        encoded = os.fsencode(value)
    except UnicodeEncodeError:
        raise ValueError("repo_key must be filesystem-encodable") from None
    if len(encoded) > _MAX_REPO_KEY_BYTES:
        raise ValueError(
            f"repo_key must be at most {_MAX_REPO_KEY_BYTES} filesystem-encoded bytes"
        )
    return value


RepoKey: TypeAlias = Annotated[
    str,
    Field(min_length=1, max_length=_MAX_REPO_KEY_BYTES),
    AfterValidator(_validate_repo_key),
]


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------

class CodeRepoCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_key: RepoKey
    name: str = Field(min_length=1, max_length=256)
    language: str = Field(default="", max_length=64)
    repo_path: str = Field(min_length=1, max_length=4096)
    source_origin_path: str = Field(default="", max_length=4096)
    source_kind: Literal["git", "directory", "legacy"] = "legacy"
    snapshot_manifest_path: str = Field(default="", max_length=4096)
    snapshot_digest: str = Field(default="", max_length=128)
    source_manifest_version: Literal["v1"] = "v1"
    source_snapshot_quality: Literal["verified", "legacy-unverified"] = "legacy-unverified"
    worktree_dirty: bool | None = None
    total_files: int = Field(default=0, ge=0)
    analyzable_files: int = Field(default=0, ge=0)
    total_loc: int = Field(default=0, ge=0)
    commit_hash: str = Field(default="", max_length=64)
    branch: str = Field(default="", max_length=256)
    git_churn: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_verified_snapshot_identity(self) -> CodeRepoCreateRequest:
        if self.source_snapshot_quality != "verified":
            return self
        missing = [
            field_name
            for field_name in ("source_origin_path", "snapshot_manifest_path", "snapshot_digest")
            if not getattr(self, field_name)
        ]
        if self.source_kind == "legacy":
            missing.append("source_kind")
        if self.source_kind == "git" and self.worktree_dirty is None:
            missing.append("worktree_dirty")
        if missing:
            raise ValueError(
                "verified source snapshot is missing identity fields: "
                + ", ".join(sorted(missing))
            )
        if len(self.snapshot_digest) != 64 or any(
            character not in "0123456789abcdef" for character in self.snapshot_digest
        ):
            raise ValueError("snapshot_digest must be a lowercase SHA-256 digest")
        return self


class CodeFileRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_path: str = Field(min_length=1, max_length=4096)
    language: str = Field(default="", max_length=64)
    loc: int = Field(default=0, ge=0)
    file_hash: str = Field(pattern=_SHA256_PATTERN)
    header_snippet: str = Field(default="", max_length=8192)
    git_churn_score: int = Field(default=0, ge=0)
    has_past_cve_fix: bool = False


class CodeRepoRefreshFilesRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=128)
    files: list[CodeFileRecord] = Field(min_length=1)


class CodeRepoRefreshPreviewRequest(BaseModel):
    repo_key: RepoKey
    files: list[CodeFileRecord]


class CodeRepoRefreshCommitRequest(BaseModel):
    refresh_token: str = Field(min_length=1, max_length=128)
    manifest_complete: Literal[True]


class CodeRepoLspConfigPublishRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    lsp_config: dict[str, Any]


class CodeFileClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: StrictPositiveId
    classification: str = Field(min_length=1, max_length=32)  # critical/high/medium/low/skip
    role: str = Field(default="", max_length=128)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    language: str | None = Field(default=None, max_length=64)
    analysis_priority: int = Field(strict=True, ge=0, le=100)


class CodeFilesBulkClassifyRequest(BaseModel):
    classifications: list[CodeFileClassification]


class CodeModuleRecord(BaseModel):
    module_key: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    description: str = Field(default="", max_length=4096)
    trust_boundary: str = Field(default="", max_length=1024)
    files: list[str] = Field(default_factory=list)
    file_ids: list[StrictPositiveId] = Field(default_factory=list)


class CodeModulesBulkCreateRequest(BaseModel):
    repo_id: StrictPositiveId
    modules: list[CodeModuleRecord]


class QueueItemRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: StrictPositiveId
    priority: int = Field(strict=True, ge=0, le=100)
    batch_theme: str = Field(default="", max_length=256)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    guidance_hypotheses: list[str] = Field(default_factory=list)
    supersedes: StrictPositiveId | None = None


class QueueItemsBulkCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["initial", "reanalysis"] = "initial"
    reason: str = Field(default="", max_length=2000)
    items: list[QueueItemRecord] = Field(min_length=1, max_length=200)

    @model_validator(mode="after")
    def require_reanalysis_reason(self) -> QueueItemsBulkCreateRequest:
        self.reason = self.reason.strip()
        if self.mode == "reanalysis" and not self.reason:
            raise ValueError("reason is required when mode=reanalysis")
        if self.mode == "reanalysis" and any(
            item.supersedes is None for item in self.items
        ):
            raise ValueError(
                "every reanalysis item requires supersedes with the exact predecessor queue row ID"
            )
        if self.mode == "initial" and any(
            item.supersedes is not None for item in self.items
        ):
            raise ValueError("initial queue items must not set supersedes")
        return self


class QueueFetchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(default=10, ge=1, le=100)
    agent_name: str = Field(min_length=1, max_length=128)
    repo_id: StrictPositiveId | None = None
    classification: Literal["critical", "high", "medium", "low", "skip"] | None = None
    batch_theme: str | None = Field(default=None, max_length=256)
    item_ids: list[StrictPositiveId] | None = Field(default=None, min_length=1, max_length=1000)


class QueueCompleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    item_ids: list[StrictPositiveId] = Field(min_length=1, max_length=1)
    agent_name: str = Field(min_length=1, max_length=128)
    lease_token: str = Field(min_length=1, max_length=128)
    disposition: str = Field(min_length=1, max_length=64)
    notes: str = Field(default="", max_length=20000)
    cwe_coverage: list[dict[str, Any]] = Field(default_factory=list)
    # C50: structured reason when disposition='skipped'. Required at the
    # service layer when skipping; ignored for other dispositions.
    skip_reason: str = Field(default="", max_length=512)


class QueueErrorRequest(BaseModel):
    item_ids: list[StrictPositiveId] = Field(min_length=1, max_length=1)
    agent_name: str = Field(min_length=1, max_length=128)
    lease_token: str = Field(min_length=1, max_length=128)
    notes: str = Field(default="", max_length=20000)


class QueueNeedsContextRequest(BaseModel):
    item_ids: list[StrictPositiveId] = Field(min_length=1, max_length=1)
    agent_name: str = Field(min_length=1, max_length=128)
    lease_token: str = Field(min_length=1, max_length=128)
    expansion_request: dict[str, Any] = Field(default_factory=dict)


class QueueResetStaleRequest(BaseModel):
    minutes: int = Field(default=10, ge=1, le=1440)


class QueueRetryErrorRequest(BaseModel):
    """C5.1: recover status='error' queue items back to 'pending' by id."""

    item_ids: list[StrictPositiveId] = Field(min_length=1)
    reason: str = Field(default="", max_length=2000)


class QueueRetryNeedsContextRequest(BaseModel):
    item_ids: list[StrictPositiveId] = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2000)


class QueueHeartbeatRequest(BaseModel):
    item_id: StrictPositiveId
    agent_name: str = Field(min_length=1, max_length=128)
    lease_token: str = Field(min_length=1, max_length=128)


class SourceLineSpan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start_line: int = Field(strict=True, ge=1)
    end_line: int = Field(strict=True, ge=1)

    @model_validator(mode="after")
    def validate_order(self) -> SourceLineSpan:
        if self.end_line < self.start_line:
            raise ValueError("end_line cannot precede start_line")
        return self


class StructuralCallableRecord(SourceLineSpan):
    name: str = Field(min_length=1, max_length=512)
    qualified_name: str = Field(min_length=1, max_length=1024)


class StructuralCallableReference(SourceLineSpan):
    file_id: StrictPositiveId
    name: str = Field(min_length=1, max_length=512)
    qualified_name: str = Field(min_length=1, max_length=1024)


class ReviewedSourceSpan(SourceLineSpan):
    file_id: StrictPositiveId
    label: str = Field(default="", max_length=512)


class AnalysisResultRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    queue_item_id: StrictPositiveId
    file_id: StrictPositiveId | None = None
    agent_name: str = Field(min_length=1, max_length=128)
    lease_token: str = Field(min_length=1, max_length=128)
    receipt_kind: Literal["file", "call_chain"] = "file"
    callable_refs: list[StructuralCallableReference] = Field(
        default_factory=list,
        max_length=10000,
    )
    reviewed_spans: list[ReviewedSourceSpan] = Field(
        default_factory=list,
        max_length=10000,
    )
    function_name: str = Field(default="", max_length=512)
    hypothesis: str = Field(default="", max_length=20000)
    evidence: str = Field(default="", max_length=20000)
    evidence_ref: str = Field(default="", max_length=4096)
    disposition: str = Field(min_length=1, max_length=64)
    confidence: str = Field(default="medium", max_length=32)
    finding_slug: str = Field(default="", max_length=256)
    cwe_id: str = Field(default="", max_length=32)
    slot_type: str = Field(default="", max_length=128)
    notes: str = Field(default="", max_length=20000)
    audit_metadata: dict[str, Any] = Field(default_factory=dict)
    cwe_coverage: list[dict[str, Any]] = Field(default_factory=list)
    cross_file_triggers: list[dict[str, Any]] = Field(default_factory=list)
    assessment_run_id: StrictPositiveId | None = None
    assessment_source_id: StrictPositiveId | None = None
    supersedes: StrictPositiveId | None = None


class RequeueItemRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: StrictPositiveId | None = None
    file_path: str = Field(default="", max_length=4096)
    repo_id: StrictPositiveId | None = None
    priority: int | None = Field(default=None, strict=True, ge=0, le=100)
    batch_theme: str = Field(default="", max_length=256)
    slot_types: list[CodeSlotType] = Field(default_factory=list)
    guidance_hypotheses: list[str] = Field(default_factory=list)
    reason: str = Field(default="", max_length=20000)
    trigger_context: dict[str, Any] = Field(default_factory=dict)


class RequeueRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[RequeueItemRecord]


TriggerResolutionStatus: TypeAlias = Literal[
    "external_context_unavailable",
    "source_equivalent_analyzed",
    "not_applicable",
]


class TriggerResolutionItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trigger_id: StrictPositiveId | None = None
    id: StrictPositiveId | None = None
    file_path: str = Field(default="", max_length=4096)
    target_file_path: str = Field(default="", max_length=4096)
    repo_id: StrictPositiveId | None = None
    vuln_class: str = Field(default="", max_length=128)


class TriggerResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TriggerResolutionItem] = Field(min_length=1)
    resolution_status: TriggerResolutionStatus
    resolution_note: str = Field(min_length=1, max_length=20000)


class StructuralSignalCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    entry_points: int = Field(ge=0)
    imports: int = Field(ge=0)
    security_sinks: int = Field(ge=0)
    security_sources: int = Field(ge=0)


class StructuralAnalysisStatusCounts(BaseModel):
    model_config = ConfigDict(extra="forbid")

    complete: int = Field(ge=0)
    degraded: int = Field(ge=0)
    unsupported: int = Field(ge=0)


class StructuralMetadataItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    file_id: StrictPositiveId
    source_sha256: str = Field(pattern=_SHA256_PATTERN)
    indexed_language: str = Field(max_length=64)
    total_functions: int = Field(ge=0)
    total_entry_points: int = Field(ge=0)
    total_sinks: int = Field(ge=0)
    total_exports: int = Field(ge=0)
    structural_analysis_status: StructuralAnalysisStatus
    structural_analysis_mode: StructuralAnalysisMode
    structural_degradation_reason: str | None = Field(max_length=128)
    structural_source_size: int = Field(ge=0)
    structural_bytes_scanned: int = Field(ge=0)
    structural_unavailable_dimensions: list[StructuralDimension]
    structural_artifact_truncated: bool
    structural_truncated_dimensions: list[StructuralDimension]
    structural_signal_counts: StructuralSignalCounts
    callables: list[StructuralCallableRecord] = Field(
        default_factory=list,
        max_length=10000,
    )

    @model_validator(mode="after")
    def validate_structural_coverage_metadata(self) -> StructuralMetadataItem:
        for field_name in (
            "structural_unavailable_dimensions",
            "structural_truncated_dimensions",
        ):
            dimensions = getattr(self, field_name)
            if dimensions != sorted(set(dimensions)):
                raise ValueError(f"{field_name} must be sorted and unique")
        if self.structural_bytes_scanned > self.structural_source_size:
            raise ValueError("structural_bytes_scanned cannot exceed structural_source_size")
        if self.structural_bytes_scanned != self.structural_source_size:
            raise ValueError(
                "structural analysis must account for every source byte"
            )
        if self.structural_analysis_status == "complete":
            if self.structural_analysis_mode not in {"tree_sitter", "lightweight_regex"}:
                raise ValueError("complete structural analysis requires a full analysis mode")
            if self.structural_degradation_reason or self.structural_unavailable_dimensions:
                raise ValueError("complete structural analysis cannot claim unavailable dimensions")
        elif self.structural_analysis_status == "degraded":
            if self.structural_analysis_mode == "streaming_security_fallback":
                if not self.structural_degradation_reason:
                    raise ValueError("degraded structural analysis requires a degradation reason")
                if not self.structural_unavailable_dimensions:
                    raise ValueError(
                        "streaming fallback analysis must name unavailable dimensions"
                    )
                missing_baseline = sorted(
                    _STREAMING_FALLBACK_UNAVAILABLE_BASELINE
                    - set(self.structural_unavailable_dimensions)
                )
                if missing_baseline:
                    raise ValueError(
                        "streaming fallback analysis is missing baseline unavailable "
                        "dimensions: " + ", ".join(missing_baseline)
                    )
            elif self.structural_analysis_mode in {"tree_sitter", "lightweight_regex"}:
                if self.structural_degradation_reason != "artifact_signal_limit":
                    raise ValueError(
                        "bounded parser degradation requires reason=artifact_signal_limit"
                    )
                if self.structural_unavailable_dimensions:
                    raise ValueError(
                        "bounded parser degradation cannot claim unavailable dimensions"
                    )
                if not self.structural_artifact_truncated:
                    raise ValueError(
                        "bounded parser degradation requires a truncated artifact"
                    )
            else:
                raise ValueError("degraded structural analysis requires an explicit degraded mode")
        else:
            if self.structural_analysis_mode != "none":
                raise ValueError("unsupported structural analysis requires analysis_mode=none")
            if self.structural_degradation_reason != "unsupported_language":
                raise ValueError(
                    "unsupported structural analysis requires reason=unsupported_language"
                )
            if not self.structural_unavailable_dimensions:
                raise ValueError(
                    "unsupported structural analysis must name unavailable dimensions"
                )
            if any(
                (
                    self.total_functions,
                    self.total_entry_points,
                    self.total_sinks,
                    self.total_exports,
                    *self.structural_signal_counts.model_dump().values(),
                )
            ):
                raise ValueError(
                    "unsupported structural analysis requires zero structural totals and signals"
                )
        represented_dimension_values = {
            "functions": self.total_functions,
            "exports": self.total_exports,
            "entry_points": self.total_entry_points,
            "imports": self.structural_signal_counts.imports,
            "security_sinks": self.total_sinks,
            "security_sources": self.structural_signal_counts.security_sources,
        }
        unavailable_with_values = sorted(
            dimension
            for dimension in self.structural_unavailable_dimensions
            if represented_dimension_values.get(dimension, 0)
        )
        if unavailable_with_values:
            raise ValueError(
                "unavailable structural dimensions require zero totals/signals: "
                + ", ".join(unavailable_with_values)
            )
        if self.structural_artifact_truncated != bool(self.structural_truncated_dimensions):
            raise ValueError(
                "structural_artifact_truncated must match structural_truncated_dimensions"
            )
        if self.structural_artifact_truncated and self.structural_analysis_status != "degraded":
            raise ValueError("truncated structural artifacts must be marked degraded")
        if self.total_entry_points != self.structural_signal_counts.entry_points:
            raise ValueError("total_entry_points must match structural_signal_counts.entry_points")
        if self.total_sinks != self.structural_signal_counts.security_sinks:
            raise ValueError("total_sinks must match structural_signal_counts.security_sinks")
        if len(self.callables) > self.total_functions:
            raise ValueError("callables cannot exceed total_functions")
        identities = [
            (
                callable_record.qualified_name,
                callable_record.start_line,
                callable_record.end_line,
            )
            for callable_record in self.callables
        ]
        if len(identities) != len(set(identities)):
            raise ValueError("callables must have unique qualified-name/source-span identities")
        return self


class BulkStructuralMetadataRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: StrictPositiveId
    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    structural_index_schema: str = Field(min_length=1, max_length=128)
    structural_input_digest: str = Field(pattern=_SHA256_PATTERN)
    structural_index_manifest_path: str = Field(min_length=1, max_length=4096)
    degraded_files: int = Field(ge=0)
    degraded_file_paths: list[str]
    artifact_truncated_files: int = Field(ge=0)
    artifact_truncated_file_paths: list[str]
    analysis_status_counts: StructuralAnalysisStatusCounts
    updates: list[StructuralMetadataItem]

    @model_validator(mode="after")
    def validate_structural_aggregate_metadata(self) -> BulkStructuralMetadataRequest:
        for count_field, path_field in (
            ("degraded_files", "degraded_file_paths"),
            ("artifact_truncated_files", "artifact_truncated_file_paths"),
        ):
            paths = getattr(self, path_field)
            if paths != sorted(set(paths)):
                raise ValueError(f"{path_field} must be sorted and unique")
            if getattr(self, count_field) != len(paths):
                raise ValueError(f"{count_field} must match {path_field}")
        status_counts = self.analysis_status_counts
        if status_counts.degraded != self.degraded_files:
            raise ValueError("degraded_files must match analysis_status_counts.degraded")
        if status_counts.complete + status_counts.degraded + status_counts.unsupported != len(
            self.updates
        ):
            raise ValueError("analysis_status_counts must account for every structural update")
        return self


class ThreatModelRecordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: StrictPositiveId
    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    threat_model: dict[str, Any]


class VariantCheckReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dispatch_id: StrictPositiveId
    file_id: StrictPositiveId
    repo_id: StrictPositiveId
    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    file_sha256: str = Field(pattern=_SHA256_PATTERN)
    parent_finding_slugs: list[str] = Field(max_length=_MAX_VARIANT_PARENT_FINDINGS)
    status: Literal["completed"]
    evidence_ref: str = Field(min_length=1, max_length=4096)
    rationale: str = Field(min_length=1, max_length=20000)

    @model_validator(mode="after")
    def validate_parent_finding_slugs(self) -> VariantCheckReceiptRequest:
        if self.parent_finding_slugs != sorted(set(self.parent_finding_slugs)):
            raise ValueError("parent_finding_slugs must be sorted and unique")
        invalid = [
            slug
            for slug in self.parent_finding_slugs
            if (
                not isinstance(slug, str)
                or not 1 <= len(slug) <= 256
                or slug != slug.strip()
                or any(ord(character) < 32 or ord(character) == 127 for character in slug)
            )
        ]
        if invalid:
            raise ValueError(
                "parent_finding_slugs entries must be canonical, trimmed strings up to 256 characters"
            )
        for field_name in ("evidence_ref", "rationale"):
            value = getattr(self, field_name)
            if value != value.strip() or not value.strip():
                raise ValueError(
                    f"{field_name} must be nonempty and contain no surrounding whitespace"
                )
        return self


class FuzzDecisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repo_id: StrictPositiveId
    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    decision: Literal["required", "not_required"]
    target_ids: list[str] = Field(
        default_factory=list,
        max_length=code_fuzz_completion.MAX_FUZZ_TARGETS,
    )
    evidence_ref: str = Field(min_length=1, max_length=4096)
    rationale: str = Field(min_length=1, max_length=20000)

    @model_validator(mode="after")
    def validate_target_ids(self) -> FuzzDecisionRequest:
        if self.target_ids != sorted(set(self.target_ids)):
            raise ValueError("target_ids must be sorted and unique")
        if any(
            not target_id
            or target_id != target_id.strip()
            or len(target_id) > 256
            or any(ord(character) < 32 or ord(character) == 127 for character in target_id)
            for target_id in self.target_ids
        ):
            raise ValueError("target_ids entries must be canonical strings up to 256 characters")
        if self.decision == "not_required" and self.target_ids:
            raise ValueError("not_required fuzz decisions cannot declare target_ids")
        if self.decision == "required" and not self.target_ids:
            raise ValueError("required fuzz decisions must declare at least one target_id")
        for field_name in ("evidence_ref", "rationale"):
            value = getattr(self, field_name)
            if value != value.strip() or not value.strip():
                raise ValueError(
                    f"{field_name} must be nonempty and contain no surrounding whitespace"
                )
        return self


class FuzzCampaignReceiptRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    dispatch_id: StrictPositiveId
    repo_id: StrictPositiveId
    repo_generation: int = Field(ge=1)
    source_manifest_digest: str = Field(pattern=_SHA256_PATTERN)
    target_id: str = Field(min_length=1, max_length=256)
    covered_finding_slugs: list[str] = Field(
        default_factory=list,
        max_length=code_fuzz_completion.MAX_FUZZ_FINDINGS,
    )
    engine: str = Field(min_length=1, max_length=128)
    sanitizers: list[str] = Field(min_length=1, max_length=32)
    run_budget_seconds: int = Field(ge=1, le=31_536_000)
    executions: int = Field(ge=0)
    outcome: Literal[
        "completed_no_crash",
        "completed_crashes_triaged",
        "build_failed",
        "campaign_failed",
    ]
    crash_count: int = Field(ge=0)
    triage_summary: str = Field(min_length=1, max_length=20000)
    evidence_ref: str = Field(min_length=1, max_length=4096)
    rationale: str = Field(min_length=1, max_length=20000)

    @model_validator(mode="after")
    def validate_campaign_outcome(self) -> FuzzCampaignReceiptRequest:
        for field_name, values in (
            ("covered_finding_slugs", self.covered_finding_slugs),
            ("sanitizers", self.sanitizers),
        ):
            if values != sorted(set(values)):
                raise ValueError(f"{field_name} must be sorted and unique")
            if any(
                not value
                or value != value.strip()
                or len(value) > 256
                or any(ord(character) < 32 or ord(character) == 127 for character in value)
                for value in values
            ):
                raise ValueError(
                    f"{field_name} entries must be canonical strings up to 256 characters"
                )
        if self.target_id != self.target_id.strip() or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.target_id
        ):
            raise ValueError("target_id must be a canonical string")
        if self.engine != self.engine.strip() or any(
            ord(character) < 32 or ord(character) == 127
            for character in self.engine
        ):
            raise ValueError("engine must be a canonical string")
        for field_name in ("triage_summary", "evidence_ref", "rationale"):
            value = getattr(self, field_name)
            if value != value.strip() or not value.strip():
                raise ValueError(
                    f"{field_name} must be nonempty and contain no surrounding whitespace"
                )
        if self.outcome == "completed_no_crash" and self.crash_count != 0:
            raise ValueError("completed_no_crash requires crash_count=0")
        if self.outcome == "completed_crashes_triaged" and self.crash_count < 1:
            raise ValueError("completed_crashes_triaged requires crash_count>=1")
        if (
            self.outcome
            in code_fuzz_completion.COVERING_FUZZ_CAMPAIGN_OUTCOMES
            and self.executions < 1
        ):
            raise ValueError("completed fuzz campaigns require at least one execution")
        return self


# ---------------------------------------------------------------------------
# Broadcast helper
# ---------------------------------------------------------------------------

async def _broadcast(engagement_key: str, record_type: str, payload: dict[str, Any]) -> None:
    await broadcaster.publish(
        engagement_key,
        {
            "type": "code_analysis.updated",
            "engagement_key": engagement_key,
            "record_type": record_type,
            "payload": payload,
        },
    )


def _audit_code_mutation(
    engagement_id: int,
    *,
    title: str,
    action: str,
    actor_name: str = "vigil-assess",
    result: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    try:
        activity_service.record_activity_entry(
            engagement_id,
            actor_kind="system",
            actor_name=actor_name or "vigil-assess",
            title=title,
            action=action,
            result=result,
            metadata=metadata or {},
        )
    except Exception:
        return


# ---------------------------------------------------------------------------
# Repository endpoints
# ---------------------------------------------------------------------------

@router.post("/repos/refresh/start", status_code=status.HTTP_201_CREATED)
async def start_repo_refresh(engagement_key: str, request: CodeRepoCreateRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.start_code_repo_refresh,
            engagement.id,
            request.model_dump(exclude_unset=True),
        )
    )
    await _broadcast(engagement.key, "repo_refresh_started", record)
    return record


@router.post("/repos/refresh/preview")
async def preview_repo_refresh(
    engagement_key: str, request: CodeRepoRefreshPreviewRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    return await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.preview_code_repo_refresh,
            engagement.id,
            repo_key=request.repo_key,
            files=[item.model_dump() for item in request.files],
        )
    )


@router.post("/repos/{repo_id}/refresh/files")
async def stage_repo_refresh_files(
    engagement_key: str, repo_id: int, request: CodeRepoRefreshFilesRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.stage_code_repo_refresh_files,
            engagement.id,
            repo_id,
            refresh_token=request.refresh_token,
            files=[item.model_dump() for item in request.files],
        )
    )
    return record


@router.post("/repos/{repo_id}/refresh/commit")
async def commit_repo_refresh(
    engagement_key: str, repo_id: int, request: CodeRepoRefreshCommitRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.commit_code_repo_refresh,
            engagement.id,
            repo_id,
            refresh_token=request.refresh_token,
            manifest_complete=request.manifest_complete,
        )
    )
    await _broadcast(engagement.key, "repo_refresh_committed", record)
    return record


@router.get("/repos")
def list_repos(engagement_key: str) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_repos(engagement.id)


@router.get("/repos/{repo_id}")
def get_repo(engagement_key: str, repo_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_code_repo(engagement.id, repo_id)


@router.patch("/repos/{repo_id}")
async def update_repo(engagement_key: str, repo_id: int, request: dict[str, Any]) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(code_analysis.update_code_repo, engagement.id, repo_id, **request)
    )
    await _broadcast(engagement.key, "repo", record)
    return record


@router.post("/repos/{repo_id}/lsp-config")
async def publish_repo_lsp_config(
    engagement_key: str,
    repo_id: int,
    request: CodeRepoLspConfigPublishRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.publish_code_repo_lsp_config,
            engagement.id,
            repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            lsp_config=request.lsp_config,
        )
    )
    await _broadcast(engagement.key, "repo_lsp_config", record)
    return record


# ---------------------------------------------------------------------------
# File endpoints
# ---------------------------------------------------------------------------

@router.get("/files")
def list_files(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
    module_id: int | None = Query(default=None),
    classification: str | None = Query(default=None),
    analysis_status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
    include_header_snippet: bool = Query(default=False),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_files(
        engagement.id,
        repo_id=repo_id,
        module_id=module_id,
        classification=classification,
        analysis_status=analysis_status,
        search=search,
        limit=limit,
        offset=offset,
        include_header_snippet=include_header_snippet,
    )


@router.get("/files/{file_id}")
def get_file(engagement_key: str, file_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_code_file(engagement.id, file_id)


@router.post("/files/bulk-classify")
async def bulk_classify_files(engagement_key: str, request: CodeFilesBulkClassifyRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.bulk_classify_code_files,
            engagement.id,
            classifications=[c.model_dump() for c in request.classifications],
        )
    )
    await _broadcast(engagement.key, "file_classification", record)
    return record


@router.patch("/files/{file_id}")
async def update_file(engagement_key: str, file_id: int, request: dict[str, Any]) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(code_analysis.update_code_file, engagement.id, file_id, **request)
    )
    await _broadcast(engagement.key, "file", record)
    return record


@router.post("/files/bulk-structural-metadata")
async def bulk_structural_metadata(
    engagement_key: str,
    request: BulkStructuralMetadataRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.bulk_update_structural_metadata,
            engagement.id,
            repo_id=request.repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            structural_index_schema=request.structural_index_schema,
            structural_input_digest=request.structural_input_digest,
            structural_index_manifest_path=request.structural_index_manifest_path,
            degraded_files=request.degraded_files,
            degraded_file_paths=request.degraded_file_paths,
            artifact_truncated_files=request.artifact_truncated_files,
            artifact_truncated_file_paths=request.artifact_truncated_file_paths,
            analysis_status_counts=request.analysis_status_counts.model_dump(),
            updates=[u.model_dump(exclude_unset=True) for u in request.updates],
        )
    )
    await _broadcast(engagement.key, "structural_metadata", record)
    return record


# ---------------------------------------------------------------------------
# Module endpoints
# ---------------------------------------------------------------------------

@router.post("/modules", status_code=status.HTTP_201_CREATED)
async def bulk_create_modules(engagement_key: str, request: CodeModulesBulkCreateRequest) -> list[dict[str, Any]]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    records = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.bulk_create_code_modules,
            engagement.id,
            repo_id=request.repo_id,
            modules=[m.model_dump() for m in request.modules],
        )
    )
    await _broadcast(engagement.key, "modules", {"count": len(records)})
    return records


@router.get("/modules")
def list_modules(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_modules(engagement.id, repo_id=repo_id)


# ---------------------------------------------------------------------------
# Analysis queue endpoints
# ---------------------------------------------------------------------------

@router.post("/analysis-queue", status_code=status.HTTP_201_CREATED)
async def bulk_create_queue_items(engagement_key: str, request: QueueItemsBulkCreateRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.bulk_create_queue_items,
            engagement.id,
            items=[i.model_dump() for i in request.items],
            mode=request.mode,
            reason=request.reason,
        )
    )
    await _broadcast(engagement.key, "analysis_queue", record)
    return record


@router.get("/analysis-queue/stats")
def get_queue_stats(engagement_key: str) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.queue_stats(engagement.id)


@router.post("/analysis-queue/fetch")
async def fetch_queue_items(engagement_key: str, request: QueueFetchRequest) -> list[dict[str, Any]]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    records = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.fetch_queue_items,
            engagement.id,
            limit=request.limit,
            agent_name=request.agent_name,
            repo_id=request.repo_id,
            classification=request.classification,
            batch_theme=request.batch_theme,
            item_ids=request.item_ids,
        )
    )
    await _broadcast(engagement.key, "queue_fetch", {"count": len(records)})
    return records


@router.post("/analysis-queue/done")
async def complete_queue_items(engagement_key: str, request: QueueCompleteRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.complete_queue_items,
            engagement.id,
            item_ids=request.item_ids,
            agent_name=request.agent_name,
            lease_token=request.lease_token,
            disposition=request.disposition,
            notes=request.notes,
            cwe_coverage=request.cwe_coverage,
            skip_reason=request.skip_reason,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-dispatch done",
            action=f"item_ids={request.item_ids} disposition={request.disposition}",
            actor_name=request.agent_name,
            result=request.notes,
            metadata={
                "item_ids": request.item_ids,
                "disposition": request.disposition,
                "lease_token": request.lease_token,
            },
        )
    )
    await _broadcast(engagement.key, "queue_done", record)
    return record


@router.post("/analysis-queue/error")
async def error_queue_items(engagement_key: str, request: QueueErrorRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.error_queue_items,
            engagement.id,
            item_ids=request.item_ids,
            agent_name=request.agent_name,
            lease_token=request.lease_token,
            notes=request.notes,
        )
    )
    await _broadcast(engagement.key, "queue_error", record)
    return record


@router.post("/analysis-queue/needs-context")
async def needs_context_queue_items(engagement_key: str, request: QueueNeedsContextRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.needs_context_queue_items,
            engagement.id,
            item_ids=request.item_ids,
            agent_name=request.agent_name,
            lease_token=request.lease_token,
            expansion_request=request.expansion_request,
        )
    )
    await _broadcast(engagement.key, "queue_needs_context", record)
    return record


@router.post("/analysis-queue/reset-stale")
async def reset_stale_queue_items(engagement_key: str, request: QueueResetStaleRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.reset_stale_queue_items,
            engagement.id,
            minutes=request.minutes,
        )
    )
    await _broadcast(engagement.key, "queue_reset_stale", record)
    return record


@router.post("/analysis-queue/heartbeat")
async def heartbeat_queue_item(engagement_key: str, request: QueueHeartbeatRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.heartbeat_queue_item,
            engagement.id,
            item_id=request.item_id,
            agent_name=request.agent_name,
            lease_token=request.lease_token,
        )
    )
    await _broadcast(engagement.key, "queue_heartbeat", record)
    return record


@router.post("/analysis-queue/retry-error")
async def retry_error_queue_items(engagement_key: str, request: QueueRetryErrorRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.retry_error_queue_items,
            engagement.id,
            item_ids=request.item_ids,
            reason=request.reason,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-dispatch retry-error",
            action=f"item_ids={request.item_ids} reason={request.reason}",
            result="",
            metadata={"item_ids": request.item_ids, "reason": request.reason},
        )
    )
    await _broadcast(engagement.key, "queue_retry_error", record)
    return record


@router.post("/analysis-queue/retry-needs-context")
async def retry_needs_context_queue_items(
    engagement_key: str, request: QueueRetryNeedsContextRequest
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.retry_needs_context_queue_items,
            engagement.id,
            item_ids=request.item_ids,
            reason=request.reason,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-dispatch retry-needs-context",
            action=f"item_ids={request.item_ids} reason={request.reason}",
            metadata={"item_ids": request.item_ids, "reason": request.reason},
        )
    )
    await _broadcast(engagement.key, "queue_retry_needs_context", record)
    return record


@router.post("/analysis-queue/requeue", status_code=status.HTTP_201_CREATED)
async def requeue_triggered_files(engagement_key: str, request: RequeueRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.requeue_triggered_files,
            engagement.id,
            items=[item.model_dump() for item in request.items],
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-dispatch requeue-triggers",
            action=f"count={len(request.items)}",
            metadata={"count": len(request.items)},
        )
    )
    await _broadcast(engagement.key, "queue_requeue", record)
    return record


@router.get("/triggers")
def list_code_triggers(
    engagement_key: str,
    status_filter: str | None = Query(default=None, alias="status"),
    repo_id: int | None = Query(default=None),
    include_superseded: bool = Query(default=False),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_code_triggers(
        engagement.id,
        status_filter=status_filter,
        repo_id=repo_id,
        include_superseded=include_superseded,
    )


@router.post("/triggers/resolve")
async def resolve_code_triggers(engagement_key: str, request: TriggerResolveRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.resolve_code_triggers,
            engagement.id,
            items=[item.model_dump() for item in request.items],
            resolution_status=request.resolution_status,
            resolution_note=request.resolution_note,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-dispatch resolve-triggers",
            action=f"status={request.resolution_status} count={len(request.items)}",
            result=request.resolution_note,
            metadata={"count": len(request.items), "resolution_status": request.resolution_status},
        )
    )
    await _broadcast(engagement.key, "triggers_resolve", record)
    return record


# ---------------------------------------------------------------------------
# Analysis results endpoints
# ---------------------------------------------------------------------------

@router.post("/analysis-results", status_code=status.HTTP_201_CREATED)
async def create_analysis_result(engagement_key: str, request: AnalysisResultRecord) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(code_analysis.create_analysis_result, engagement.id, request.model_dump())
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-record-analysis",
            action=(
                f"file_id={record['file_id']} receipt={request.receipt_kind} "
                f"callables={len(request.callable_refs)} spans={len(request.reviewed_spans)}"
            ),
            actor_name=request.agent_name,
            result=request.disposition,
            metadata={
                "file_id": record["file_id"],
                "queue_item_id": request.queue_item_id,
                "finding_slug": request.finding_slug,
                "disposition": request.disposition,
                "receipt_kind": request.receipt_kind,
                "callable_count": len(request.callable_refs),
                "reviewed_span_count": len(request.reviewed_spans),
            },
        )
    )
    await _broadcast(engagement.key, "analysis_result", record)
    return record


@router.get("/analysis-results")
def list_analysis_results(
    engagement_key: str,
    file_id: int | None = Query(default=None),
    queue_item_id: int | None = Query(default=None, ge=1),
    lease_token: str | None = Query(default=None, min_length=1, max_length=128),
    function_name: str | None = Query(default=None, max_length=512),
    disposition: str | None = Query(default=None),
    include_superseded: bool = Query(default=False),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_analysis_results(
        engagement.id,
        file_id=file_id,
        queue_item_id=queue_item_id,
        lease_token=lease_token,
        function_name=function_name,
        disposition=disposition,
        include_superseded=include_superseded,
    )


@router.post("/variant-checks", status_code=status.HTTP_201_CREATED)
async def create_variant_check_receipt(
    engagement_key: str,
    request: VariantCheckReceiptRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.record_variant_check_receipt,
            engagement.id,
            dispatch_id=request.dispatch_id,
            file_id=request.file_id,
            repo_id=request.repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            file_sha256=request.file_sha256,
            parent_finding_slugs=request.parent_finding_slugs,
            status_value=request.status,
            evidence_ref=request.evidence_ref,
            rationale=request.rationale,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-record variant-check",
            action=(
                f"dispatch_id={request.dispatch_id} file_id={request.file_id} "
                f"receipt_id={record['id']}"
            ),
            actor_name=record["dispatch_agent_id"],
            result="current" if record["current"] else "historical",
            metadata={
                "dispatch_id": request.dispatch_id,
                "file_id": request.file_id,
                "receipt_id": record["id"],
                "receipt_fingerprint": record["receipt_fingerprint"],
                "agent_id": record["dispatch_agent_id"],
                "agent_role": record["dispatch_agent_role"],
            },
        )
    )
    await _broadcast(engagement.key, "variant_check_receipt", record)
    return record


@router.get("/variant-checks")
def list_variant_check_receipts(
    engagement_key: str,
    file_id: int | None = Query(default=None, gt=0),
    repo_id: int | None = Query(default=None, gt=0),
    include_stale: bool = Query(default=False),
    limit: int = Query(
        default=code_analysis.DEFAULT_VARIANT_RECEIPT_PAGE,
        ge=1,
        le=code_analysis.MAX_VARIANT_RECEIPT_PAGE,
    ),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.list_variant_check_receipts(
        engagement.id,
        file_id=file_id,
        repo_id=repo_id,
        include_stale=include_stale,
        limit=limit,
        offset=offset,
    )


@router.post("/fuzz/decision", status_code=status.HTTP_201_CREATED)
async def create_fuzz_decision(
    engagement_key: str,
    request: FuzzDecisionRequest,
    response: Response,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_fuzz_completion.record_fuzz_decision,
            engagement.id,
            repo_id=request.repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            decision=request.decision,
            target_ids=request.target_ids,
            evidence_ref=request.evidence_ref,
            rationale=request.rationale,
        )
    )
    if not record["created"]:
        response.status_code = status.HTTP_200_OK
    else:
        await anyio.to_thread.run_sync(
            functools.partial(
                _audit_code_mutation,
                engagement.id,
                title="code-record fuzz-decision",
                action=f"repo_id={request.repo_id} decision={request.decision}",
                metadata={
                    "repo_id": request.repo_id,
                    "repo_generation": request.repo_generation,
                    "decision_id": record["id"],
                    "decision_fingerprint": record["decision_fingerprint"],
                },
            )
        )
        await _broadcast(engagement.key, "fuzz_decision", record)
    return record


@router.get("/fuzz/decisions")
def list_fuzz_decisions(
    engagement_key: str,
    repo_id: int | None = Query(default=None, gt=0),
    include_stale: bool = Query(default=False),
    limit: int = Query(
        default=code_fuzz_completion.DEFAULT_FUZZ_HISTORY_PAGE,
        ge=1,
        le=code_fuzz_completion.MAX_FUZZ_HISTORY_PAGE,
    ),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_fuzz_completion.list_fuzz_decisions(
        engagement.id,
        repo_id=repo_id,
        include_stale=include_stale,
        limit=limit,
        offset=offset,
    )


@router.get("/fuzz/state")
def get_fuzz_state(
    engagement_key: str,
    repo_id: int = Query(gt=0),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_fuzz_completion.get_fuzz_state(engagement.id, repo_id)


@router.post("/fuzz/campaign-receipts", status_code=status.HTTP_201_CREATED)
async def create_fuzz_campaign_receipt(
    engagement_key: str,
    request: FuzzCampaignReceiptRequest,
) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(
        lambda: get_engagement_or_404(engagement_key)
    )
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_fuzz_completion.record_fuzz_campaign_receipt,
            engagement.id,
            dispatch_id=request.dispatch_id,
            repo_id=request.repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            target_id=request.target_id,
            covered_finding_slugs=request.covered_finding_slugs,
            engine=request.engine,
            sanitizers=request.sanitizers,
            run_budget_seconds=request.run_budget_seconds,
            executions=request.executions,
            outcome=request.outcome,
            crash_count=request.crash_count,
            triage_summary=request.triage_summary,
            evidence_ref=request.evidence_ref,
            rationale=request.rationale,
        )
    )
    await anyio.to_thread.run_sync(
        functools.partial(
            _audit_code_mutation,
            engagement.id,
            title="code-record fuzz-campaign",
            action=(
                f"dispatch_id={request.dispatch_id} repo_id={request.repo_id} "
                f"target_id={request.target_id} receipt_id={record['id']}"
            ),
            actor_name=record["dispatch_agent_id"],
            result="covering" if record["covering"] else "non-covering",
            metadata={
                "dispatch_id": request.dispatch_id,
                "repo_id": request.repo_id,
                "receipt_id": record["id"],
                "receipt_fingerprint": record["receipt_fingerprint"],
                "outcome": request.outcome,
            },
        )
    )
    await _broadcast(engagement.key, "fuzz_campaign_receipt", record)
    return record


@router.get("/fuzz/campaign-receipts")
def list_fuzz_campaign_receipts(
    engagement_key: str,
    repo_id: int | None = Query(default=None, gt=0),
    include_stale: bool = Query(default=False),
    limit: int = Query(
        default=code_fuzz_completion.DEFAULT_FUZZ_HISTORY_PAGE,
        ge=1,
        le=code_fuzz_completion.MAX_FUZZ_HISTORY_PAGE,
    ),
    offset: int = Query(default=0, ge=0),
) -> list[dict[str, Any]]:
    engagement = get_engagement_or_404(engagement_key)
    return code_fuzz_completion.list_fuzz_campaign_receipts(
        engagement.id,
        repo_id=repo_id,
        include_stale=include_stale,
        limit=limit,
        offset=offset,
    )


# ---------------------------------------------------------------------------
# Threat model endpoints
# ---------------------------------------------------------------------------

@router.post("/threat-model")
async def create_threat_model(engagement_key: str, request: ThreatModelRecordRequest) -> dict[str, Any]:
    engagement = await anyio.to_thread.run_sync(lambda: get_engagement_or_404(engagement_key))
    record = await anyio.to_thread.run_sync(
        functools.partial(
            code_analysis.record_threat_model,
            engagement.id,
            repo_id=request.repo_id,
            repo_generation=request.repo_generation,
            source_manifest_digest=request.source_manifest_digest,
            threat_model=request.threat_model,
        )
    )
    await _broadcast(engagement.key, "threat_model", record)
    return record


@router.get("/threat-model/{repo_id}")
def get_threat_model(engagement_key: str, repo_id: int) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.get_threat_model(engagement.id, repo_id)


@router.get("/readiness")
def get_readiness(
    engagement_key: str,
    target_phase: Literal["classify-map", "hunt", "verify-variant", "fuzz", "complete"] = Query(),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    return code_analysis.code_readiness(engagement.id, target_phase=target_phase)


# ---------------------------------------------------------------------------
# Coverage endpoint
# ---------------------------------------------------------------------------

@router.get("/coverage")
def get_coverage(
    engagement_key: str,
    repo_id: int | None = Query(default=None),
    detail: str | None = Query(default=None),
) -> dict[str, Any]:
    engagement = get_engagement_or_404(engagement_key)
    if detail == "cwe":
        return code_analysis.code_coverage_cwe_detail(engagement.id, repo_id=repo_id)
    return code_analysis.code_coverage_summary(engagement.id, repo_id=repo_id)
