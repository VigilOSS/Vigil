# Adversarial Mindset

The lens that generates hypotheses before the first probe. It gates nothing: a hypothesis is a
candidate to test, and it becomes a finding only by clearing the evidence bar (`agent/rules/hunting.md`
§2 on the red track, `agent/shared-constraints-code.md` §5 on the code track, `agent/rules/triage.md` on
the blue track).

As a dispatched specialist you are the expert on your surface: originate hypotheses from what you
observe. A class named in the dispatch is one starting lead, not the boundary of the work.

## 1. Ask how the feature can be made to do what it was never meant to do

Who built it, what were they optimizing for, and what did they trust that you don't have to?

## 2. Every feature is a trust delegation

Name the trust, then break the assumption it rests on: an upload trusts the client's content type
and filename, a profile view trusts that the ID belongs to the caller, a webhook trusts the URL is
safe to reach, a password reset trusts that email delivery proves identity, a deprecated API
version trusts that its callers passed the same guards as the current one.

## 3. Live in the gap between design and implementation

The spec says input is validated, auth is enforced, data is tenant-scoped, rate limits apply. Check
whether that holds on every method, the legacy path, the background job, the bulk endpoint.

## 4. "That's weird" is the signal

When a response is not quite what you expected, ask what would have to be true for it to happen and
test that directly (red-track signal catalogue: `hunting.md` §4).

## 5. Think forward from what you have and backward from what you want

Forward: what does this primitive unlock? Backward: what would reach the admin panel, the payment
flow, the account export from nothing? The backward question surfaces surface you had not planned
to test.

## 6. Privilege is rarely binary

Look for a scoped token accepted globally, a role checked at the gateway but not the service, a
reset that leaves live sessions valid, an ID scoped to the object but not the tenant, a permission
checked at creation but not on share.

## 7. Untested perspectives hide the miss

The expensive outcome is a surface written off too early: the error path, the other HTTP methods, the
unauthenticated sibling, the legacy version, boundary and wrong-type values.
