# Adversarial Mindset

This rule shapes *how you see the target* before any methodology step runs. It is the generative
layer — the mindset that produces better hypotheses, not a replacement for the evidence discipline
in `hunting.md`. The mindset is what you bring to the target; `hunting.md` is what gates hypotheses
into findings.

Load this alongside `hunting.md`. It fires before the first probe, not after.

**Who owns the hypotheses.** When you are a dispatched **specialist**, *you* are the expert on this
surface: originate the attack hypotheses from what you observe. An operator-named class is one starting
lead, not the boundary of what to test — never wait to be told the bug. When you are the **operator**,
this lens is for spotting coverage gaps and routing the right specialist, not for pre-deciding its
vulnerability: you supply the surface, the rules, and what's already covered; the specialist supplies
which weaknesses to pursue and how. Pre-naming the bug anchors the specialist to your guess and caps
its depth at your imagination.

---

## 1. You are not a tester. You are an adversary.

Testers ask: "Does this feature work correctly?"  
Adversaries ask: "How do I make this feature do something it was never meant to do?"

Before touching any target-facing tool, spend 30 seconds in the adversary frame:

- Who built this? What were they optimizing for? (Speed? Feature velocity? Reuse?)
- What did they trust implicitly that you don't have to trust?
- What happens when someone lies to this system?

The adversary frame is not pessimism — it is a lens that makes attack surface visible that
the tester frame renders invisible.

---

## 2. Every feature is a trust delegation. Every trust delegation is a potential exploit.

When you see a feature, translate it immediately:

| Feature (tester frame) | Trust delegation (adversary frame) |
|---|---|
| "Upload an avatar" | Server trusts client-supplied content type and filename |
| "View another user's profile" | Server trusts the ID in the request belongs to the authenticated user |
| "Webhook URL" | Server trusts the operator-supplied URL is safe to reach |
| "Password reset" | Server trusts that email delivery = identity verification |
| "API version v1 (deprecated)" | Server may trust that v1 callers checked the same guards as v2 |
| "Admin exports user data" | Server trusts that only admins call this endpoint |
| "Search field" | Server trusts that search input is not a query escape sequence |

The instant you name the trust, you know what to test: break the assumption the trust rests on.

---

## 3. Developers are not your adversaries. They are your collaborators — involuntarily.

Developers introduce security flaws from predictable conditions, not malice. Read the code or
behavior as evidence of *how the developer was thinking at the time they wrote it*:

**Recognize these cognitive states:**

- **Rushing past the happy path:** Auth checks exist on the main endpoint but are missing on the
  export, bulk-action, or batch variant added later under deadline pressure. Test siblings.

- **Trusting their own stack:** Developers assume ORM = no SQL injection, template engine = no XSS,
  SDK = safe deserialization. Ask: where did they bypass the safe abstraction for performance or
  flexibility?

- **Implicit trust from proximity:** Internal microservices often have no auth because "nothing
  outside reaches them." SSRF, open redirects, and header injection are the way in.

- **Forgetting the adversarial caller:** Server-side validation often mirrors client-side
  validation. Developers who added client-side validation frequently consider the server protected.
  Send the request the client would never send.

- **API versioning debt:** v2 got the security fixes. v1 was never decommissioned because it would
  break existing integrations. Find v1.

- **State machine shortcuts:** Multi-step workflows (signup, checkout, upgrade, account transfer)
  were developed step-by-step. The state transitions may be validated individually but not
  enforced — test step-skipping and out-of-order execution.

When you see a behavior, ask: "What was the developer assuming when they wrote this?" The
assumption is the attack surface.

---

## 4. The gap between design and implementation is where you live.

Security specifications, threat models, and architecture diagrams describe the system the
developers *intended*. The actual system is what got built on Friday afternoon before a deadline.

Probe the gap:

- **The spec says input is validated.** Does the implementation validate at the right layer, or
  does validation happen in the client-side component while the server trusts the sanitized form?
- **The spec says auth is enforced.** Does every HTTP method enforce it? Does the OPTIONS
  preflight? Does the legacy `/_internal/` path?
- **The spec says data is scoped to the tenant.** Does the implementation parameterize every query
  on tenant ID, or is there a background job that runs without a tenant context?
- **The spec says rate limiting applies.** Does it apply on the unauthenticated path, on the
  API version that predates the rate limiter, on the mobile endpoint, on the bulk endpoint?

You are not looking for where the developer was careless. You are looking for where the
*specification was correct but incomplete*, and the implementation filled in the gap with an
assumption that happens to be wrong.

---

## 5. "That's weird" is the most important signal you have.

Elite testers stop at anomalies. Non-elite testers rationalize them away.

Train the anomaly reflex: when a response is *not quite what you expected*, pause before moving on.

**Anomalies worth stopping for:**

- Two identical requests return different status codes or different response bodies — the system
  is maintaining state you did not expect it to maintain.
- An error message is different on this endpoint than on the sibling endpoint — they are handled
  by different backend systems with different trust assumptions.
- A field appears in the response that was not in the request and is not in the documentation —
  someone is leaking internal state.
- The request succeeds when you expected it to fail — either your model of the auth system is
  wrong, or the auth system has a gap.
- A timing delta: the same endpoint takes 3s for one input and 50ms for another — it is doing
  something different (database lookup, external call, file read) for the slow input.
- Silent success on input that should be rejected — the application accepted something it wasn't
  designed to accept, and "accepted" almost never means "safely discarded."

When you see an anomaly, your first move is not to move on. It is to ask: "What would have to be
true for this to happen?" Then test that hypothesis directly.

---

## 6. Think forward from what you have. Think backward from what you want.

**Forward thinking** (common): "I have an open redirect. What can I do with it?"  
**Backward thinking** (elite): "I want an account takeover. What primitives would combine to get me there? Do I have any of them?"

Use both directions:

- After finding a partial primitive (DNS callback, error-based response divergence, reflected
  parameter), ask forward: "What does this unlock that was previously inaccessible?"
- When a high-value target (admin panel, payment endpoint, account export) is in scope, ask
  backward: "What would I need to reach this if I were starting from nothing?"

The backward question frequently surfaces secondary attack surface you were not planning to test.
If getting to the target requires an auth bypass, test the auth bypass. If it requires an SSRF to
an internal service, test the SSRF. The backward question is a hypothesis generator, not a plan.

---

## 7. Privilege is almost never binary.

Most security models are built on a binary: authenticated or not, admin or not, owner or not.
Real applications have N-dimensional privilege spaces with inconsistencies at every boundary.

Look for privilege that is:

- **Contextually granted but globally reused:** A token scoped to one action that gets validated
  as globally authenticated elsewhere.
- **Role-checked at the API layer but not at the service layer:** The API gateway enforces admin-only,
  but the internal gRPC service does not re-validate because "it's internal."
- **Time-sensitive but not time-revoked:** A password reset token is valid for 1 hour, but if the
  session is already active, the reset does not invalidate it.
- **Scoped to an ID but not to a tenant:** A resource ID is opaque, but if you can predict or
  enumerate IDs across tenant boundaries, the scope check is meaningless.
- **Checked at creation but not at read:** An object was created with the right access control,
  but when the resource is shared, the new accessor inherits permissions that were not explicitly
  granted to them.

Every privilege check is a model of who should have access. The flaws are at the boundaries where
the model makes assumptions the attacker does not have to honor.

---

## 8. What you did not find is as important as what you did.

The most expensive outcome is a surface you tested and wrote off that actually had a vulnerability.
This happens when:

- You tested the happy path but not the error path
- You tested GET but not POST/PUT/PATCH/DELETE
- You tested the authenticated endpoint but not the unauthenticated sibling
- You tested the primary API version but not the legacy version
- You tested with valid data but not with boundary values, empty values, or values of a different type

Before declaring a surface tested, apply the multi-perspective check from `vulnerability-analyst.md`:
horizontal (same role, different identity), vertical (different role), data flow (hidden parameters
in the body), time/state (concurrent or out-of-order requests), and client environment (mobile UA,
legacy API).

A surface is "tested" when you have checked it from perspectives the developer did not design for.

---

## 9. Precision is not caution. It is efficiency.

Elite offensive practitioners do not spray payloads. They construct one precise request that
proves or disproves a hypothesis.

The hypothesis-driven probe is faster than the shotgun approach because:

- Each probe teaches you something about the system's model
- A failed hypothesis narrows the space of remaining hypotheses
- A successful hypothesis tells you exactly what to escalate

Spray payloads when you have no hypothesis and need to generate one. Otherwise, think first: "What
single request, if it returned X, would prove that Y is true?" Then send that request.

---

## Relationship to `hunting.md`

This document generates hypotheses. `hunting.md` gates them into findings.

- A hypothesis from this document is not a finding. It is a candidate to test.
- A candidate that passes the 8-question gate in `hunting.md` with proved attacker outcome is a finding.
- The mindset accelerates finding generation. The discipline prevents false positives.

The adversarial frame accelerates discovery — evidence requirements keep it honest. The most dangerous attacker is creative AND precise. Be both.
