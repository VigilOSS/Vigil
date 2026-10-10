# Surface classification evidence contract

Research collection: `classify-surface-2026-06`.

Status: synthetic public evidence summary. ADR 0004 records the accepted design and
`IMPLEMENTATION-SPEC.md` records the executable classifier contract.

This public summary explains the design rationale needed to maintain and review the classifier.
The checked-in synthetic test matrix supplies reproducible regression evidence; it does not
reproduce private engagement measurements.

## Evidence shape

The synthetic regressions cover four surface shapes:

- a large fictional Acme web estate with nested routes;
- a fictional consumer application with unrelated route shapes;
- a fictional SaaS application with API and GraphQL routes; and
- a fictional legacy estate with archive, file-transfer, and older application paths.

Raw engagement measurements are excluded from this public contract. The synthetic cases pin
runtime behavior without identifying targets or claiming to reproduce those measurements.

## Design rationale

### GraphQL and API

GraphQL routes need a distinct bucket because a generic path label loses the application shape. The accepted `graphql` bucket therefore has a
high-value floor. Generic REST-like API paths are not uniformly high-value; the lower `api` floor preserves coverage without treating every API route as
an urgent finding. The bare `/api/` fragment/type-floor reconciliation is specified in
`IMPLEMENTATION-SPEC.md` section 6.3.

### Deserialization

Encoded application-state routes can remain security-relevant even when their suffix resembled a
static JavaScript asset. The accepted rule recognizes the narrow loader-state path family rather
than globally boosting encoded or `.js` paths.

### Object storage

Legacy document-library routes need product-aware classification. The rule is deliberately
product-shape-aware; a blanket `/files/` rule would misclassify ordinary static documents.

### Authentication and identity

Authentication entry points, SSO routes, and OIDC discovery documents need distinct classification.
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
