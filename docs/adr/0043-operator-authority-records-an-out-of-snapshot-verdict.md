# ADR 0043 — Operator authority records an out-of-snapshot verdict

- Status: Accepted — implemented in the verification route, the CLI, report readiness, the
  operator frontend and the exported report
- Date: 2026-11-07
- Amends: [ADR 0028](0028-producer-provenance-binds-proof-to-work.md), whose
  terminal-verification rule assumed every verdict is reached by a dispatch.

## Context

Every terminal verification status (`confirmed`, `downgraded`, `false_positive`) requires at
least one proof receipt, and each receipt has to come from a `completed` run the verifying
dispatch produced, be evidence-healthy, carry a live `proof_run` link to the finding, and
come from a dispatch distinct from the finding's author. Those are four separate dispatch
conditions. An operator holds no dispatch.

That is the right shape while the fact that settles a finding lives inside the engagement.
It leaves no route when the fact lies outside the sealed snapshot by design. A deployment
configuration that disables the vulnerable path is not source under review, and
[ADR 0026](0026-sealed-source-generations-own-current-code-truth.md) makes a generation
own exactly the bytes the backend attested, so no receipt in this engagement can carry it.
The operator can read the configuration and cannot record what it settles.

The routes that exist are lossy or dishonest:

- `operator-checkpoint` is the operator's own durable row, and its free-text block is
  labelled unverified operator intent, never a finding and never evidence. It has no lever
  on a verdict, which is correct, because it resolves no citation.
- `finding retract-claim` replaces the summary and records correction history. The verdict
  and the band stay where they were.
- `finding update --severity` is an invalidating axis under
  [ADR 0039](0039-one-change-policy-decides-finding-verdict-effects.md), so re-banding
  strips the verdict and leaves the finding owing a receipt again.
- `details.related_intel_ids` is a kept axis, so the evidence attaches without invalidating
  anything, and it carries no authority over the verdict.

The finding therefore keeps a rating its own evidence contradicts, and the honest correction
has nowhere to land.

## Decision

A terminal verdict can be recorded on the operator's own out-of-snapshot evidence, with no
proof receipt:

    vigil assess finding verify <slug> --status <terminal> \
        --operator-authority --intel-id <id> --reason <text>

[ADR 0019](0019-vigil-does-not-defend-against-its-own-operator.md) makes the operator the
authority over their own engagement; what it does not permit is weakening a gate silently,
so the waiver is durable, attributable and visible.

- **Preconditions.** The status must be terminal, `--reason` must be non-blank and say what
  the evidence settles, and `--intel-id` must resolve to exactly one live intel row in this
  engagement. Intel tables allocate ids independently and an index row can outlive the
  record it points at, so a citation that resolves to nothing, or to several entity types,
  names no evidence and is refused before the write.
- **The stamp.** The verification stamps `provenance.operator_authority` on the finding and on
  the transition metadata as `{kind: "out_of_snapshot", intel_id, intel_type, at, reason}`, so
  neither the point read nor the history can show the verdict without the authority behind it.
  The type is part of the citation rather than decoration: intel tables allocate ids
  independently, so an id alone can send a reader to an unrelated row that happens to occupy
  it in another table. An authored stamp is refused: the key is the service's record that an
  intel row resolved and a reason was given, and accepting a caller's version would make the
  waiver forgeable by anything that can write provenance.
  The receipt requirement then reads the stamp back off the stored row in place of
  `proof_receipt_ids`, so the gate is waived only for a verdict whose waiver is already
  durable.
- **Nothing rides along.** The waiver cannot carry `--proof-receipt-id`, a confirm-check, a
  counter-check or a severity variance. Each of those is a receipt-bound record, so a
  verdict holding no receipts cannot hold one, and an empty shell would make the verdict
  read as partly proven. A kill still records its own kill annotations, because those are
  the verdict's rationale and not evidence.
- **Superseded rather than deleted.** When a later dispatch-verified verdict lands, the
  stamp moves to `provenance.superseded_operator_authority`. Deleting it would erase how the
  earlier verdict was reached, and leaving it in place would read as the authority behind
  the new one. Neither stamp is authorable: the live one is refused unless it is this
  verification's own, and the superseded record is refused outright, because a forged one
  fabricates a waiver that was never granted. A merge does not carry a source finding's
  stamp, because the waiver was recorded against that finding's verdict.

### Why an intel id

A reason string is an assertion, and nobody can open it. An intel row is a referenceable
record with its own type, content and audit trail, so a reader who distrusts the verdict can
read what the operator relied on and reach their own conclusion. The row is resolved before
the write, so a stamp never cites something that is absent, and the resolved type travels
with the id so every surface can name the table the reader has to open. The reason stays
required because the row holds what the evidence is and not what it settles.

### What this does not weaken

The receipt gate exists to stop a dispatch self-certifying. That gate is unchanged.

- A dispatch cannot skip a receipt. A dispatch-produced verdict still needs the completed
  run, the healthy evidence, the live `proof_run` link and the author-independent verifier.
- Author independence is untouched for every receipt-backed verdict.
- No out-of-snapshot bytes enter the sealed generation. The evidence stays an intel row, and
  the snapshot's admitted inventory, exclusions and digests are not touched.
- The finding's source citations stay bound to the active generation. ADR 0026 stands: a
  cited file, line span and callable resolve against the generation exactly as before, and
  operator authority does not admit a citation that fails to resolve.
- It is not a route past
  [ADR 0035](0035-unproven-findings-are-parked-or-blocked-never-dropped.md). A finding whose
  runtime proof is merely owed is parked, and a finding blocked on missing access stays
  blocked. This verb covers evidence the operator holds, and not evidence nobody has.
- Publication is unchanged. A report publishes only a reproduction an independent rehearsal
  confirmed, and the stamp waives nothing there.

### The visibility obligation

The risk this decision creates is a waiver that reads as proof. A terminal verdict with an
empty receipt list, rendered beside dispatch-verified ones with nothing to tell them apart,
turns an honest operator record into a laundered proof. The stamp therefore travels with the
verdict everywhere a verdict renders, and a surface that cannot show it is a defect to fix:

- **The finding read.** The verification-evidence payload carries `operator_authority`
  beside the receipt list, so an empty list never reads as "nobody recorded the evidence".
  The finding record projection and the exploit-candidate rows carry it as well, so an
  approval gate reading `candidate_reason: verified_<severity>` does not take it for proof.
- **Report readiness.** Every terminal verdict resting on a stamp raises the
  `finding_operator_authority_verdict` item, naming the slug, the status, the intel id and
  the reason, and stating that the report has to describe the verdict as operator-attested.
  It is an advisory, because the operator already decided and readiness reports rather than
  overrules.
- **The operator frontend.** The finding detail labels the verdict as operator authority and
  shows the intel id and the reason wherever it shows the verification status.
- **The exported report.** Wherever the report states how a verdict was reached, it states
  operator attestation and names the intel row. Rendering it as equivalent to a
  dispatch-verified verdict is the one presentation that is not available.
- **Every operator-facing listing that states a verdict.** The exploit-approval queue marks
  the verdict cell, because an operator authorising live exploitation is the reader with the
  most at stake in the difference. `findings.md` and `submission.md` carry it too: the first
  is the document handed over, and the second leaves for a recipient who has no other way to
  learn the verdict was not proven here.

## Consequences

- A fact outside the snapshot can correct a verdict while the finding keeps its evidence,
  band history and proof lineage instead of resetting them.
- The ledger now holds terminal verdicts whose backing is an operator assertion plus an
  intel pointer. A reader who ignores the provenance stamp will over-trust them, and the
  stamp is the only thing between an honest record and a laundered proof. That cost is
  accepted, and the visibility obligation is what bounds it.
- A `confirmed` verdict on operator authority reaches report readiness as an advisory, so an
  operator can carry one into a report. The independent reproduction rehearsal still gates
  publication, and that gate is a check on the authored steps rather than on this waiver.
- The waiver has no revocation verb. A later dispatch-verified verdict supersedes it;
  otherwise it stands for the rest of the engagement.
- Open: the rehearsal gate admits only specific verifier roles, so an operator who
  personally re-walked a reproduction still cannot clear it. Whether that gate should accept
  this stamp is a separate decision, and this ADR does not make it.

## Alternatives considered

- **Register an operator dispatch and carry an `artifact` receipt under it.** Rejected, and
  it is the alternative that needs no code change: the deployment configuration can be
  registered as an artifact, and a receipt under a dispatch the operator registered
  satisfies every condition the gate checks. It is the worst option for the ledger, because
  it records operator authority as dispatch verification. The audit trail would then state
  that a verifier proved the claim, with nothing in it to say otherwise. A visibly weaker
  stamp beats an invisibly false receipt.
- **Let `proof-run start` accept an external repository read, with repository plus commit as
  generation identity.** Rejected. It is a far larger change, and it blurs the boundary
  ADR 0026 draws: a generation is the bytes the backend attested, and a caller-supplied
  commit label is the exact identity that ADR refused, because dirty worktrees and admission
  rules move the reviewed source without moving the label. It also covers only the
  out-of-snapshot evidence that happens to live in another repository.
- **Do nothing and accept the contradicted rating.** Rejected. The operator's remaining
  choices are to leave the rating wrong or to destroy the verdict with a re-band, and both
  leave a worse record than a visible waiver.
