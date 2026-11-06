"""Every bulk assessment write model declares the same item ceiling.

The cap is not a style rule: each of these requests is served inside ONE
``BEGIN IMMEDIATE`` transaction against a single-writer SQLite file, under one
HTTP response budget. An uncapped list lets a caller build a transaction that
outlives its own read timeout — and the caller then cannot tell whether the
write committed, which is the one outcome a durable write must never produce.

``CodeFilesBulkClassifyRequest`` was the sole uncapped one, and it was also the
one whose payload scales with the repository: a classification pass over a large
tree arrived as a single request. It is bounded here at the same ceiling its
siblings use, which is also the chunk size `code-classify` sends.
"""
from __future__ import annotations

import pytest
from pydantic import BaseModel, ValidationError

from app.api.assessment import (
    MAX_BULK_ASSESSMENT_WRITE_ITEMS,
    ArtifactRegisterBulkRequest,
    CoverageItemBulkRecordRequest,
    RequestObservationBulkIngestRequest,
    WorkItemBulkIngestRequest,
    WorkItemUpdateRequest,
)
from app.api.code_analysis import (
    CodeFilesBulkClassifyRequest,
    QueueItemsBulkCreateRequest,
)


_BULK_LIST_FIELDS: tuple[tuple[type[BaseModel], str], ...] = (
    (CodeFilesBulkClassifyRequest, "classifications"),
    (RequestObservationBulkIngestRequest, "items"),
    (WorkItemBulkIngestRequest, "items"),
    (WorkItemUpdateRequest, "updates"),
    (CoverageItemBulkRecordRequest, "items"),
    (ArtifactRegisterBulkRequest, "items"),
    (QueueItemsBulkCreateRequest, "items"),
)


@pytest.mark.parametrize(("model", "field"), _BULK_LIST_FIELDS)
def test_a_bulk_write_list_declares_a_ceiling(model, field) -> None:
    metadata = model.model_fields[field].metadata
    maximum = next(
        (getattr(entry, "max_length") for entry in metadata if hasattr(entry, "max_length")),
        None,
    )
    assert maximum is not None, f"{model.__name__}.{field} accepts an unbounded list"
    assert 1 <= maximum <= MAX_BULK_ASSESSMENT_WRITE_ITEMS


def _classification(file_id: int) -> dict:
    return {"file_id": file_id, "classification": "low", "analysis_priority": 5}


def test_a_full_classification_chunk_is_accepted() -> None:
    """The ceiling equals the chunk size the CLI sends, so the shipped path fits."""
    request = CodeFilesBulkClassifyRequest.model_validate(
        {
            "classifications": [
                _classification(index + 1)
                for index in range(MAX_BULK_ASSESSMENT_WRITE_ITEMS)
            ]
        }
    )

    assert len(request.classifications) == MAX_BULK_ASSESSMENT_WRITE_ITEMS


def test_an_unchunked_classification_pass_is_refused_before_the_transaction() -> None:
    with pytest.raises(ValidationError) as refusal:
        CodeFilesBulkClassifyRequest.model_validate(
            {
                "classifications": [
                    _classification(index + 1)
                    for index in range(MAX_BULK_ASSESSMENT_WRITE_ITEMS + 1)
                ]
            }
        )

    assert refusal.value.errors()[0]["type"] == "too_long"


def test_an_empty_classification_request_is_refused() -> None:
    """A write that classifies nothing reports success for work nobody did."""
    with pytest.raises(ValidationError) as refusal:
        CodeFilesBulkClassifyRequest.model_validate({"classifications": []})

    assert refusal.value.errors()[0]["type"] == "too_short"
