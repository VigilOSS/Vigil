# ADR 0039 — One change policy decides finding verdict effects

- Status: Accepted — implemented
- Date: 2026-11-04

## Context

A proof receipt backs one verification event, so an invalidated verdict needs a fresh proof run.
[ADR 0038](0038-live-proof-approval-and-verification-history.md) kept a conservative review for
every edit outside narrow same-verifier enrichment, and
[ADR 0023](0023-source-and-live-proof-enrich-one-finding.md) makes the file location canonical
on a file/live merge. This ADR amends both for edits to a verified finding.

In practice the decision lived in five write paths (patch, re-record, merge, relocation and
root-cause links), each with its own status set and field list. Title edits, filling an empty
evidence reference and root-cause grouping after verification forced claim reviews or fresh proof
runs, while the paths disagreed on which statuses an edit could reset. A merge reset a confirmed
target whenever the source was further along or more severe. Reopening a confirmed finding to
draft, which every verifier prompt prescribes, did not withdraw its verdict.

## Decision

`finding_change_policy` is the single owner. It compares the resolved stored rows before and after
a write, never request arguments, and classifies each changed axis as `keep`, `claim_review` or
`invalidate`; the strongest axis is the change's effect. Every write path applies the same
classification, and every status except `unreviewed` carries a verdict an invalidation resets.

- **Keep:** title, notes, workflow, submission fields, provenance, source name, remediation,
  references and other presentation detail, filling an empty evidence reference or type, generic
  links, and root-cause set, retarget or clear.
- **Claim review:** summary and claim prose (impact, evidence, reproduction wording), replacing an
  evidence reference or type, CVSS impact metrics revised within the same band, and a root-cause
  link whose effect is `eliminates_finding`, because it claims the root fix retires the finding.
- **Invalidate:** severity, CWE, defect family, root-cause key, authentication context, location,
  CVSS exploitability metrics or a band crossing, removing a proof dependency (an evidence key,
  the evidence reference, or a recorded reproduction run), retraction, and reopening for
  re-triage.

A claim review keeps a confirmed or downgraded verdict and raises the report blocker until an
independent `claim_equivalence` decision or re-verification. An invalidating edit on a killed
(`false_positive`) finding is refused until the finding is reopened; a rediscovery that folds
into a killed finding keeps it killed. Location drift inside the same callable keeps a verdict
only when `finding verify` rebinds it to the current source snapshot.

Merge never changes the target's technical claim and never resets its verdict: severity, CVSS and
CWE stay the target's, and a stronger source value is returned as a warning naming the explicit
edit. A file/live merge still makes the file location canonical, but into a verified live target
that is a location change, so the merge is refused; the operator merges the live finding into the
file finding or reopens the target first. Same-verifier enrichment is decided on the same
classification: it may append reproduction steps and runs as exact prefixes.

Each transition records `metadata.change_policy` with the policy version, the effect and every
axis with its effect. Write responses carry `verification_effect`, `verification_invalidated` and
`changed_axes`, and the merge and link CLIs print the effect. The assess contract renders the
effect table from a mirror pinned to the policy.

The claim digest that equivalence decisions and proof-work bindings record is versioned. Version 2
covers the columns and detail keys whose effect is never `keep`, so a kept edit cannot stale a
recorded decision or binding. It omits the evidence reference and type: filling one is kept, and
replacing one records its own claim review. A record without a version was written at version 1 and is compared at version 1, so
it stays valid exactly as long as the claim it recorded is unchanged. Verdicts invalidated earlier
are not restored.

## Consequences

- Cosmetic and grouping work after verification no longer costs a proof run or a review.
- The same change has the same effect through every verb, and the audit names which axis decided.
- A merge can leave a weaker technical claim on the target than the source carried; the warning
  makes that an explicit, reviewed edit rather than a silent reset.
- A version-1 decision re-raises its review when a field it covered changes, even one whose effect
  is now `keep`; the new decision is recorded at version 2.

## Alternatives considered

- **Keep conservative review for every edit.** Rejected because it made a title edit as costly as
  a changed claim and taught operators to avoid documenting verified findings.
- **Let merge take the stronger technical claim and invalidate.** Rejected because consolidating a
  duplicate is not evidence that the stronger claim holds.
- **Recompute existing decisions at the new digest.** Rejected because the reviewed claim is not
  stored, so a recomputed digest would attest to content no verifier saw.
