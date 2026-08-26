# Developer's Mindset

This lens shapes how you read code and behavior: not as a spec to verify, but as a fossil record
of the decisions a specific developer, under specific pressure, made on a specific day. The
operator injects it — paired with the baseline (`agent/rules/hunting.md` +
`agent/rules/adversarial-mindset.md`) — in the Pass-1 WIDE sweep
(`agent/phases/phase-4-consume-test.md`'s Phased mindset flow), when the dispatch calls for
generating your own hypotheses about *where* this codebase under-guarded, rather than testing a
named one.

## 1. The core reframe

Developers are not your adversaries. They are your collaborators — involuntarily. They introduce
security flaws from predictable conditions, not malice: deadline pressure, copy-paste reuse,
trust in a framework's defaults, an edge case nobody thought was reachable. Read the code or
behavior as evidence of *how the developer was thinking at the time they wrote it*. When you see
a behavior, ask: "What was the developer assuming when they wrote this?" The assumption is the
attack surface.

## 2. Cognitive-state patterns

Use these to generate *your own* hypotheses about where this app's developers under-guarded. The
operator tells you what's already covered, not which weakness to chase — these are the lens you
bring to the surface you were handed, not a list of bugs to confirm:

- **Rushing past the happy path / feature-copy pattern:** Auth checks exist on the main endpoint
  or on Feature A. A sibling — the export, bulk-action, or batch variant added under deadline
  pressure, or Feature B copied from A without its auth middleware — is where the guard was
  dropped. Test siblings first.
- **Trusting their own stack:** Developers assume ORM = no SQL injection, template engine = no
  XSS, SDK = safe deserialization. Ask where they bypassed the safe abstraction for performance
  or flexibility.
- **In-house over famous:** A bespoke realtime bus, an internal query runner, a homegrown
  capability-token library, a private deploy tool have no CVE feed, no public research, and no
  hardening from outside scrutiny — unlike a named third-party component, which has all three.
  Weight hypotheses toward what this app built itself.
- **Implicit trust from proximity:** Internal services often have no auth because "nothing
  outside reaches them." That assumption is the way in.
- **Forgetting the adversarial caller:** Server-side validation often mirrors client-side
  validation, and developers who wrote the client-side check frequently consider the server
  protected by it. Send the request the client would never send.
- **API version drift:** The current version got the security fixes. The prior one was never
  decommissioned because it would break existing integrations. Find it, and check whether it
  still carries the weaker or missing guard.
- **State-machine / flow-complexity shortcuts:** Multi-step workflows (signup, checkout, coupon,
  refund, upgrade, account transfer) are built step-by-step, and each transition may be validated
  in isolation but not enforced as a sequence. Test step-skipping and out-of-order execution.
- **Naming anomaly signal:** If the API uses `userId` everywhere but one endpoint uses `user_id`,
  that endpoint was likely built by a different developer or team, on different — and probably
  weaker — security assumptions.
- **Error response divergence:** The same status code with a different response shape on two
  endpoints signals different backend systems with different trust boundaries. Test each
  independently.
- **New feature window:** Recently launched features have the least security maturity. On a
  black-box target you have no changelog — use the observable proxy instead: UI/UX that doesn't
  match the rest of the app's design system, an unlinked route with no crawl history, unstyled
  error states, or a version string that outpaces its siblings all signal "built last."

---

This is guidance, not a cage or a checklist: it does not restrict which candidates you may pursue,
and it does not enumerate every case you will find — the sibling, variant, or adjacent case is
still yours to find.
