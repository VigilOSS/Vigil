# Surface classification evidence contract

Research collection: `classify-surface-2026-06`.

Status: synthetic public evidence summary. ADR 0004 records the accepted design and
`IMPLEMENTATION-SPEC.md` records the executable classifier contract.

The June 2026 research used a synthetic corpus designed to exercise unrelated surface shapes. This
summary preserves the conclusions needed to maintain and review the classifier. The checked-in test
matrix supplies the reproducible regression evidence.

## Evidence shape

Four independent surface shapes were used:

- a large public-sector web estate with a deep priority-zero tail;
- a consumer application corpus used as an independent quantitative contrast;
- a modern SaaS corpus used for qualitative API and GraphQL validation; and
- a broad legacy estate used to stress archive, file-transfer, and older application paths.

The research progressed from a small stratified sample through two deep-tail passes and a targeted
pass over risky route families. A second-pass review corrected systematic over-classification of
ordinary content routes. Raw row counts are intentionally omitted because they are not part of the
runtime contract; the checked-in cases are the reproducible evidence.

## Cross-corpus conclusions

### GraphQL and API

GraphQL routes repeatedly fell through to the generic path bucket even though they represented an
important application surface in unrelated estates. The accepted `graphql` bucket therefore has a
high-value floor. Generic REST-like API paths were the largest missed class by volume, but were not
uniformly high-value; the lower `api` floor preserves coverage without treating every API route as
an urgent finding. The bare `/api/` fragment/type-floor reconciliation is specified in
`IMPLEMENTATION-SPEC.md` section 6.3.

### Deserialization

Encoded application-state routes remained security-relevant even when their suffix resembled a
static JavaScript asset. The accepted rule recognizes the narrow loader-state path family rather
than globally boosting encoded or `.js` paths.

### Object storage

Legacy document-library routes formed a material long-tail class. The rule is deliberately
product-shape-aware; a blanket `/files/` rule would misclassify ordinary static documents.

### Authentication and identity

Authentication entry points, SSO routes, and OIDC discovery documents were repeatedly under-ranked.
They have distinct buckets because their security value and false-positive profiles differ.

## Public reproducibility

The public evidence chain is:

1. `IMPLEMENTATION-SPEC.md` defines bucket order, weights, soundness overrides, normalization, and
   the complete synthetic case table.
2. `orchestrator/backend/tests/test_classify_*.py` pins those behaviors against fictional paths and
   values.
3. `agent/references/gf-patterns/` explains how the runtime patterns map to the same contract.
4. ADR 0004 records why this boundary is durable.

The research labels are not a shipped dependency or a source of runtime truth. A future classifier
change must add a minimized synthetic regression before changing code.

## Data handling

Only this summary, the implementation specification, and the minimized synthetic cases are needed
to maintain the behavior. Do not add real engagement data to fixtures or issue reports.
