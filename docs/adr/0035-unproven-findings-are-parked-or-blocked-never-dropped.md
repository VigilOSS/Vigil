# ADR 0035 — Unproven findings are parked or blocked, never dropped

- Status: Accepted
- Date: 2026-10-13

## Context

Vigil requires a proven attacker outcome before a finding is reported. Applied bluntly, that rule
loses real work: a finding whose runtime proof is still owed was killed or ignored, a finding
whose last proof step the program's rules forbid was downgraded to what the tester was allowed to
show, and a finding waiting on an account nobody had provisioned vanished from view.

## Decision

An unproven finding takes one of three explicit states:

1. **Parked** (`verification_status=pending_runtime_proof`). Source or static evidence is solid
   and the runtime proof is owed. The finding stays out of exploit candidates and the report, and
   report readiness blocks until a runtime pass confirms or downgrades it. Inability to produce a
   PoC is not proof of falsehood; a finding is killed only when its primitive is disproven.
2. **ROE-blocked** (`details.roe_blocked`). The primitive is proven, and only the final
   demonstration is forbidden by the program's rules. The finding is graded at impact-if-true and
   records the single test that would confirm it.
3. **Blocked** (`verification_status=blocked`, with `details.block_reason` and
   `details.unblock_requirements`). The attempt cannot start without missing access, such as an
   account, device, or credential. It stays out of the report, and is linked to the finding or
   technique that would unblock it. Its premise is re-checked whenever a new identity or
   credential lands.

`vigil assess finding list --holding` shows parked and blocked findings, and the resume brief
surfaces blocked and ROE-blocked ones.

## Consequences

- A policy wall no longer reads as a low-severity verdict.
- Parked work cannot be quietly left behind at report time.
- A stale "not provisioned for this user" cannot hide a product's surface for the rest of the
  engagement.

## Alternatives considered

- **Drop anything without runtime proof.** Rejected: it discards structurally sound findings.
- **Report at the demonstrated severity only.** Rejected for ROE-blocked findings: it penalises
  the tester for following the program's rules.
