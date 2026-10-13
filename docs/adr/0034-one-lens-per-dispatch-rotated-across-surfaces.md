# ADR 0034 — One lens per dispatch, rotated across surfaces

- Status: Accepted
- Date: 2026-10-13
- Extends: [ADR 0009](0009-operator-specialist-division-of-labor.md)

## Context

ADR 0009 stopped the operator from naming the bug: the operator supplies the surface and rules,
and the specialist originates the hypothesis. Two gaps remained. Dispatches still carried menus
of lenses, which a specialist works through shallowly, and they carried self-imposed restraints
("don't enumerate", "use only data the app hands you") that cost real severity. In one recorded
case an idea list aimed at the wrong bug class produced twelve dispatches and one Low.

## Decision

1. **Each deep dispatch names exactly one mindset lens.** A lens describes how the developer was
   thinking (access control, injection surface, business logic, chain impact, or a finer
   qualifier such as caching or race conditions). The specialist derives its own hypotheses under
   it. Wide passes carry the developer lens and no family lens.
2. **Lenses rotate.** A lens that found something is re-run on new surfaces, because the same
   developer pattern recurs. A fresh lens is run on surfaces already worked, because a surface
   proven clean under one lens is still open under another.
3. **Only hard constraints bind a dispatch.** The engagement boundary, the program's rules of
   engagement, required headers, and the human-reach budget may constrain it. Methodological
   restraints may not.

## Consequences

- The lens is part of each dispatch's recorded prompt context.
- The operator hands the specialist the measured coverage for its surface and an open objective,
  so the specialist knows what is already covered without being told what to try.

## Alternatives considered

- **Give each specialist every lens.** Rejected: a menu gets sampled, not worked.
