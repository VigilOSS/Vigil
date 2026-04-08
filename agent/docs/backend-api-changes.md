# Backend API Changes — CWE Coverage & Cross-File Triggers

This document describes the backend API changes required to support effort-based CWE coverage tracking and cross-file trigger requeuing in the code analysis pipeline.

## Endpoints

### `POST code/analysis-results`

**Changes:**
- `queue_item_id` is now optional (nullable integer). Omitting it or passing `null` is valid.
- Accepts optional `cwe_coverage` array — per-vulnerability-class effort records attached to the result.
- Accepts optional `cross_file_triggers` array — files connected via call graph that need re-analysis.

**New fields in request body:**

```json
{
  "queue_item_id": null,
  "file_id": 15,
  "disposition": "finding",
  "cwe_coverage": [
    {
      "family": "buffer-overflow",
      "effort": 85,
      "functions_analyzed": 12,
      "entry_chains_traced": 4,
      "total_entry_chains": 5,
      "notes": "Full taint tracing on all memcpy/memmove sinks."
    }
  ],
  "cross_file_triggers": [
    {
      "file_path": "src/url_helpers.c",
      "reason": "Delegates scheme validation without bounds check",
      "vuln_class": "buffer-overflow"
    }
  ]
}
```

### `POST code/analysis-queue/done`

**Changes:**
- Accepts optional `cwe_coverage` array in the payload alongside `item_ids`, `disposition`, and `notes`.
- When `cwe_coverage` is present, the backend accumulates it against the relevant file(s) using max-effort semantics (see Accumulation below).

**Updated request body:**

```json
{
  "item_ids": [1, 2, 3],
  "disposition": "analyzed",
  "notes": "Batch complete",
  "cwe_coverage": [
    {"family": "sql-injection", "effort": 60, "functions_analyzed": 8}
  ]
}
```

### `GET code/coverage`

**Changes:**
- Response includes per-file `cwe_coverage` accumulation with effort scores when available.
- Response includes per-file `applicable_families` list (derived from slot types and language).
- Includes a `files` array when CWE data exists, containing per-file effort summaries.

**Updated response shape (additions):**

```json
{
  "total_files": 25,
  "by_classification": { "...": "existing" },
  "files": [
    {
      "file_id": 15,
      "file_path": "src/RemotePrint.java",
      "file_name": "RemotePrint.java",
      "classification": "critical",
      "applicable_families": ["web-app-injection", "path-traversal", "ssrf"],
      "cwe_coverage": [
        {"family": "web-app-injection", "effort": 85},
        {"family": "path-traversal", "effort": 30}
      ]
    }
  ]
}
```

### `GET code/coverage?detail=cwe`

**New query parameter:** `detail=cwe`

Returns the full per-file effort matrix. Same shape as the `files` array above, but guaranteed to include all files (not just those with CWE data). Files without CWE data have an empty `cwe_coverage` array.

Can be combined with `repo_id`: `code/coverage?detail=cwe&repo_id=42`

### `POST code/analysis-queue`

**Changes:**
- Queue items can now include `batch_theme`, `guidance_hypotheses`, and `slot_types` fields alongside the existing format. These are passed through and stored for agent dispatch context.

**Extended item format:**

```json
{
  "items": [
    {
      "file_id": 15,
      "batch_theme": "Network input handlers",
      "slot_types": ["NETWORK-INPUT", "PROTOCOL-FIELD"],
      "guidance_hypotheses": [
        "Check memcpy bounds on protocol length fields",
        "Verify signed/unsigned comparison guards"
      ]
    }
  ]
}
```

### `POST code/analysis-queue/requeue`

**New endpoint.** Accepts cross-file triggers and creates new analysis queue items.

**Request body:**

```json
{
  "items": [
    {
      "file_path": "src/url_helpers.c",
      "reason": "Delegates scheme validation without bounds check",
      "trigger_context": {
        "vuln_class": "buffer-overflow",
        "source": "cross_file_trigger"
      }
    }
  ]
}
```

**Response:**

```json
{
  "queued": 1,
  "items": [{"id": 42, "file_path": "src/url_helpers.c", "status": "pending"}]
}
```

## Accumulation Semantics

Multiple `done` calls per file accumulate `cwe_coverage` using **max-effort** semantics:

- If file F already has `{"family": "sql-injection", "effort": 40}` and a new result reports `{"family": "sql-injection", "effort": 70}`, the stored effort becomes `70`.
- `functions_analyzed`, `entry_chains_traced`, and `total_entry_chains` use max semantics as well.
- `notes` from the higher-effort record replaces the previous notes for that family.
- Families not previously recorded are appended.

This allows multiple analysis passes (initial scan, deeper hunt, variant scan) to build up coverage incrementally without losing the high-water mark from any pass.
