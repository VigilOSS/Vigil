# Business-Logic Mindset

A lens for surfaces that encode a *process*, not just data — checkout, KYC, approval, transfer,
signup, subscription, dispute. The bug is rarely in one endpoint; it is in the gap between the state
machine the developers designed and the one the implementation actually enforces.

## 1. Draw the state machine before you probe it

Sketch the states and legal edges before sending anything — `cart → shipping → payment →
confirmed`, `pending → approved → funded`, `invited → active → revoked`. Every edge the diagram
implies but the server does not check is a hypothesis. A state reachable by more than one inbound
edge ("resettable"/"reopenable") is worth a second look — reopening often reuses code paths that
assumed the state was still fresh.

## 2. Step-skip and out-of-order execution

Multi-step flows are validated step-by-step, so the guard usually lives on the *step*, not the
*state*: does confirm itself check that payment happened, or trust that you could only have arrived
there by paying? Calling a later step directly, or out of order, is the fastest way to find a guard
that was never written because "no client would do that."

## 3. Replay, idempotency, and webhook redelivery

A transition safe once is not safe by default on repeat. Resubmit a completed step (apply a coupon,
confirm an order, approve a request, deliver a webhook) and see whether it is a one-time event or an
idempotent no-op. Webhook/callback replay is not even a synthetic attacker action — the sender
retries on any non-2xx, so the handler must already be safe under it. Where idempotency keys exist,
check they scope to resource *and* caller: a stolen or guessed key can let a second party replay
someone else's transition into their own context.

## 4. Quantity and boundary abuse at the transition, not the field

Boundary values (negative, zero, fractional, overflow, max-int, empty array, absent field) matter
most exactly where a transition consumes a quantity — inventory decrement, balance debit, seat
count, rate-limit counter, expiry check. Rejection at the API layer is not interesting; acceptance
that changes what the state machine does next is.

## 5. TOCTOU: the check and the use are never the same instant

Wherever the app checks a condition ("coupon still valid," "seat still free," "balance still
covers this") and acts on it in a separate step, there is a window. Fire the same transition
concurrently, or race a competing transition between check and use, and see what the system assumed
could not happen in that gap.

## 6. Ownership-transfer races and quota scope

Transfer, share, claim, and grant flows move one resource (license, account, seat, invite, escrow)
between exclusive owners. The question is not "can I transfer it" but "can two transitions both
win" — two accepts of one invite, two claims of one seat, a transfer that lands on both the old and
new owner. The same shape hides in limits: a quota enforced per-request or per-session is not the
guarantee a limit enforced per account implies — multiple sessions, multiple identities, or a check
that reads before a concurrent request writes are the standard ways "one per customer" turns out to
be "one per request."

---

This is guidance, not a cage or a checklist: it does not restrict which candidates you may pursue,
and it does not enumerate every case you will find — the sibling, variant, or adjacent case is
still yours to find.
