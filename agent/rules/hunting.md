# Hunting Rules

The evidence bar for red-track live/deployed work. Web specialists that hunt or adjudicate load it
from their Load First list; collection and enrichment roles load it before their first finding,
negative, or probe verdict; the web operator loads it when judging a negative, closing a surface,
probing inline, or recovering a stalled loop. Operator-only phase-exit, aggregate-rate, and
app-unit rules live in `agent/rules/hunting-operator.md`. Code-track reachability and impact are
owned by `agent/shared-constraints-code.md` §5, not by this file.

## 1. Resolve the engagement boundary before target work

`agent/shared-constraints.md` §1 owns the engagement boundary and the state that must be resolved
before target-facing decisions. Trigger-gated skill loading is owned by §3 of the same file.

## 2. Prove the attacker outcome, not just the vulnerability

For a live/deployed attack claim, if the answer to "can an attacker do this right now with real
harm?" is no, that claimed attacker outcome is not established yet. Proving a vulnerability exists
is not enough: demonstrate what the attacker **gains** from it. The gap between "vulnerability
confirmed" and "attacker outcome proved" is where most severity inflation happens.

| Existence proof (insufficient alone) | Exploitation proof (required) |
|---|---|
| "TLS validation is disabled" | "TLS bypass lets attacker extract session token X from intercepted traffic → replaying X against /api/vault returns the victim's vault records" |
| "IDOR returns a different user's ID" | "IDOR on /api/users/{id} returns full name, email, phone, and billing address for any user ID" |
| "SSRF reaches internal host" | "SSRF to 169.254.169.254 returns IAM credentials → credentials grant s3:ListBucket on production bucket" |
| "Session token is in the response" | "Session token replayed from a different IP returns 200 with authenticated user data — no IP binding" |

The pattern applies to every vulnerability class: confirm the primitive, then demonstrate the
attacker outcome it enables. An OOB or DNS callback alone proves a primitive, not SSRF impact.

Credentials, tokens, keys, and leaked config matter only when you show what they grant — **use
them**. Replay the token and show what it unlocks. If replay fails, say why (expiry, IP binding,
CSRF token required) and mark the finding CHAIN REQUIRED with the specific gap.

A strong-but-unproven finding is parked, not dropped: `evidence_type=theoretical` +
`chain_required=true` at `verification_status=pending_runtime_proof`, with a next test naming what
would confirm and what would falsify it (`vigil assess contract finding record`; review the holding
area with `vigil assess finding list --holding`). It stays out of the report until a runtime pass
proves it.

**Recording a finding is not grading it.** A finding at `verification_status=unreviewed` is an open
question, not a graded N/A. Do not assert "no P2 here" or "this surface is clean" while any unauth or
medium-plus finding on it is still `unreviewed`; drive it to a verifier decision first.

Withdrawing your own claim: `false_positive` when you have the counter-evidence (it needs the
completed counter-check that falsified the claim), `disputed` when you do not. Both survive a later sweep; leaving the
finding `unreviewed` reads as never looked at and gets the claim re-filed. A kill whose experiment
could not be run is `blocked`, not a kill. Field shapes: `vigil assess contract finding verify`.

### ROE-blocked: a candidate, not a severity downgrade

When you cannot safely complete the final proof step because the rules of engagement forbid it
(touching real customer data, pivoting into production, exfiltrating a record you have already shown
you can reach), that is a constraint on *you*, not a weakness in the finding. Do not lower the
severity to match what you were permitted to demonstrate. Grade the **candidate at impact-if-true**
and record the single unblocking test that would convert it (`details.roe_blocked` +
`details.required_followup`; `vigil assess contract finding record`). This differs from the
theoretical/`chain_required` park, which needs another *bug* to land: here the primitive is proved
and only the demonstration is walled off by policy. An ROE wall never masquerades as a low-severity
verdict.

### Blocked-for-provisioning

The attempt cannot even start because a precondition is missing: no test account in the required
group, no access to the device, no additional credential or grant. Record the wall on the finding
(`details.block_reason`, `details.unblock_requirements`, `details.attempts_summary`; `vigil assess
contract finding record`) and the technique-level wall with `vigil assess block-technique`. A
`blocked` finding stays out of the report — unlike an ROE-blocked candidate, the primitive was never
reached — but the unblock path is first-class: when a later finding or chain would satisfy the block,
link them (`vigil assess contract finding link` and `contract block-technique` carry both
directions).

### Re-derive a blocked record before accepting it

A `blocked` record encodes a premise that was true when written — an identity that did not exist
yet, a role that could not be granted, a product "not provisioned for this user." Premises expire;
the record does not. Re-read the standing block list (`vigil assess list-blocked-techniques`,
`vigil assess finding list --verification-status blocked`) whenever a new identity, credential, or
access grant lands, and at phase entry, then re-derive each premise. One stale "not provisioned"
sentence can hide a whole product's surface once a second identity gains access to it.

## 3. Precondition equivalence check

Before rating severity, identify the precondition required to trigger the vulnerability. If that
precondition already grants the attacker equivalent or greater access than the vulnerability itself
provides, the finding is defense-in-depth (Low), not an independent exploit. Score on incremental
impact over the precondition, not total impact of the chain.

- **Redundant**: "Unvalidated redirect captures auth verifier" — but triggering the redirect requires
  breaking the same TLS connection that already exposes the auth verifier. Incremental impact: zero.
- **Not redundant**: "App disables TLS validation process-wide" — no precondition beyond network
  proximity. The app removes its own protection. Incremental impact: full credential capture from any
  shared network.
- **Chain test**: if exploiting B requires condition A, ask "what can the attacker already do with
  just A?" If the answer is "everything B provides," B is defense-in-depth.
- **Attacker controls the whole processed input**: run the chain test with A = "the victim processes
  the attacker's artifact" (a repo, PR, template, project path, archive, config, or build). A build or
  dev tool that executes the attacker's own source by design already grants code execution, so a flaw
  that only reproduces that outcome is defense-in-depth — zero incremental capability — unless it
  reaches a genuinely different trust context (a victim's deployment, tenant, or credentials, or a
  control the attacker's visible source could not evade). A fully reproduced injection can still be
  no-impact under this test. The verifier FP catalog's "Redundant with the attacker's own controlled
  input" trigger (`agent/references/finding-fp-and-severity-gate.md`) applies it on both tracks.

## 4. Kill weak leads fast; push harder on strong ones

Kill signals — validate quickly, chain, or drop:

- Theory without a real request, response, or replayable action
- More than two fragile preconditions stacked together
- "Might be chainable" used instead of a proved chain
- Static or generic surface with no meaningful attack paths after a short pass

Push-harder signals — stay until you have the attacker outcome or a concrete reason the path fails:

- A response field, timing delta, or status diverges between two otherwise-identical requests
  (different account, header, or encoding): the application is keeping state, and that state is
  usually where the finding lives
- An error, stack trace, or redirect leaks framework internals, file paths, or internal hostnames
- Repeating the same request produces different behavior
- Partial signal (OOB DNS fires but no body leak, time delta without error, 5xx on malformed input):
  the primitive exists; the next work is shaping the payload to complete it
- A sibling route, method, or content-type behaves differently from the one you tested
- The response silently accepts an input shape it shouldn't (alternate protocol, unexpected encoding,
  out-of-range value)

## 5. Depth over breadth; rotate only when genuinely dry

Thoroughness is what earns confidence that nothing was left undiscovered, so time is not the
constraint — confidence is. Stay on one target long enough to understand what it values (its
money-moving flow, admin surface, trust boundary); a sweep that touches everything once and nothing
twice is how the deep bug on the third surface gets missed. Use bug A as a signal for B and C nearby
and follow the cluster until it is dry.

Rotate off a lead or surface only when repeated *varied* attempts produce no new information — not on
a timer, and not because it is slow. A confirmed lead (a host that answers but blocks, a gate that
rejects, a partial primitive) is either driven to its attacker outcome or dispositioned "dead because
X" before you declare stuck or fall back to brute-force discovery; anything proven on one confirmed
surface gets tried on every other confirmed surface of the same shape first.

The dry signal: when your last several varied attempts all returned the same response class (same
status family, same error shape, no new state), stop issuing that shape and go to §14. A probe you
repeat on purpose to detect state divergence (§4) is new information, not a stall.

## 6. The sibling rule

When one route, method, content-type, or controller path is vulnerable, its siblings sharing the same
code path are the highest-probability next test. Walk every sibling before moving to a new surface;
the Verify → Exploit variant/sibling pass checks this at phase exit.

## 7. Impact first

Weight attention toward surfaces where broken auth, object-reference drift, privileged writes, or
trust-boundary confusion would matter. These are the families (`access-control`, `auth`, `injection`,
`ssrf`, `file`) the app-unit depth ledger treats as block-high at the report edge, so the judgment is
cheaper to act on now.

## 8. A human-reach unknown stays open

An endpoint whose human-reach status is still unknown — the `agent/shared-constraints.md` §2d
preflight did not resolve it and no `human_reach_decision` is recorded — is an open question, not a
silent skip. Do not close a surface as exhausted while a notify-shaped endpoint on it is undetermined;
run it through the procedure `vigil assess contract agent decision` owns. A name such as
`send-notification` is a hypothesis about behavior: the recorded determination, not the name, decides
how you treat the endpoint.

## 9. Validate before writing

Do not draft a finding, chain step, or remediation note from a lead that hasn't been pushed to a
`tested`/`signal` probe-run verdict (§12) with recorded evidence. Prose written ahead of the evidence
backfills confidence the testing never earned, and the verifier inherits the gap. A live lead earns
report space only after it clears §2.

## 10. Evidence beats volume; send the smallest probe that answers the question

A handful of decisive, exact requests is stronger evidence than broad repetitive testing; once the
first proof lands, reissuing it is noise. Once access to a data set is proven, one minimal sample is
the whole of the evidence — pulling more records is itself the harm
(`agent/references/runtime-guides/web-finding-recording.md` "Proof-not-collection").

If you already know what to test (a path from robots.txt, sitemap, or JS; a parameter from source),
`curl` it through `vigil assess kali exec`. Reach for a fan-out tool only when you need discovery and
brute-force is in scope. Before brute-forcing a format (parameter names, ID shapes, path segments),
re-read the recon you already captured: API descriptions, schema endpoints, `.well-known/`, sitemaps,
and routes in served source hand you the format. A tool's candidate is followed by a surgical `curl`
that captures the evidence — that is the capture step, not noise.

The program's VDP overrides efficiency: when it forbids brute-force or rejects scanner-only evidence,
do not run `ffuf` / `arjun` / `puredns` / generic-template `nuclei`; fall back to surgical requests
against specifically discovered targets. A long or high-volume run that will not fit one
synchronous call (`agent/shared-constraints.md` §2) is an operator-owned `kali job`, so it can be
stopped cleanly; a specialist names it in `next_steps`. The operator budgets the aggregate rate
across lanes (`agent/rules/hunting-operator.md` §2).

Headers a proxy or CDN trusts (`X-Forwarded-*`, `X-Original-URL`, method overrides) are ordinary
injected inputs: probe the ones plausible for the architecture and record them like any other input,
`vigil assess record-probe --input-slot header:<name>` (`vigil assess contract record-probe`).

## 11. A self-imposed discovery restriction is not a target fact

"I won't enumerate because it might violate the rules" is a conservative interpretation, not a
target fact. Light, low-rate, curated discovery of resources you already have evidence for (a path in
JS, a parameter in a form, a directory in a redirect) is compliant under a "minimal testing"
commitment; the honest line is rate + wordlist size + stop on sensitive data. Before accepting a
restriction as a severity cap, re-read the program's exact language, and if it forbids high-volume
scanning but not targeted discovery, continue (or ask the operator to re-dispatch) under the correct
reading.

## 12. A non-conclusive response is a lead, not a verdict

A response only becomes a verdict when it answers the question. A status code on its own, a non-401
error on a protected op, and a transport failure are non-conclusive — each is a lead to push, never a
"tested / clean / patched / not-present" closure.

**(a) A raw status code is not a disposition for a body-dependent class.** For uploads, injection,
IDOR reads, reflection, auth-skip, and stored XSS (including SVG), capture and inspect the body and
headers: a `200` on an upload can be the bypass, a `403` can carry a leaked body, and the serving
`Content-Type` + CSP decide whether an SVG executes. `curl -o /dev/null` is for pure liveness or
timing probes only.

**(b) A 401/403 means the auth gate fired; any other outcome on a protected op did not.** A
validation error (`400`/`422`), a `500`/parse error, a `missing required argument` / `did you mean`
message, or silent acceptance proves the request reached the resolver or handler without being
auth-rejected — the surface is anonymously reachable up to validation. Re-send with valid-shape
arguments to reach the real authorization decision. Class-specific instances live in the
`ssrf-testing` (denylist 400/403) and `graphql-testing` skills.

**(c) `http=000` / connection-failed / DNS failure is a runtime error, not a target verdict.** The
kali path reports `status=transport_error` (exit 6) and retries once host-pinned; if it persists,
re-run with `--runtime host` and let a real HTTP response, or a clean connection-refused, decide.

**(d) A WAF or bot-challenge interstitial is pending in both directions until a browser proves the
origin.** Re-render with `vigil assess kali browser <url>`; only the rendered origin response is a
verdict. The kali path reports `status=waf_challenge` for this; do not override it with the
challenge's status code. A signature/fingerprint block returns the same 403 to the browser and stays
pending until routed WAF-clean (`agent/references/web/waf-bypass-and-safe-testing.md`).

**(e) An auth-gate redirect is a bypass-test lead, not a "covered/gated" closure.** A `302` to login
proves the gate fired, not that it holds. Run the bypass sweep (static-extension exemption,
path-normalization confusion, routing-header injection, verb tampering; `auth-bypass` skill) before
dispositioning.

**(f) Verify the bytes on the wire before treating a `406` / content-negotiation response as target
behavior.** An unquoted header value in curl argv shell-splits into separate tokens; the resulting
error is a Kali-side artifact. Replay with `--verbose` and confirm the header went out as one token.

An OOB callback from a private or Kali-runtime address is self-resolution, not a target callback
(`ssrf-testing` skill, "OOB self-resolution").

**Re-derive inherited dispositions from raw evidence.** A prior agent's "tested / clean / disproven"
note is a view to re-verify, not ground truth. Before accepting a negative on a protected op, re-open
the raw rows (`vigil assess command-run get <id>`, `vigil assess command-run list --tool-bin <bin>
--show-matches`) and re-derive it from the request/response bytes: a recorded `403` may have been a
validation error (b), a "patched" a transport error (c), a "clean" a status-only probe (a), a "gated"
an unrendered WAF challenge (d).

## 13. A negative needs its tier, lens, run id, and a positive control

A "fails-closed" / "covered" / "no-params" negative is valid only for the exact **tier + lens** it
was proven on, and only when the run **completed** (not timed out or partial). A sibling tier
(different auth level, role, or trust context) or a new lens on a worked surface is a fresh test.
Before recording a negative, state "proven fails-closed at [tier] / [lens] / [run-id]"; anything
shorter is a disposition you cannot defend. Never extend a conclusion to untested hosts or surfaces
from a non-representative sample ("every subdomain is the same SPA").

**Bracket every negative with a live positive control** on the same route, verb, identity, and
gateway, in the same window. Without one you cannot tell "denied" from "blocked," "not found," "not
provisioned," or "not reached." Before a failed replay becomes a negative, prove the identity is
live: `vigil assess auth status --probe --identity <name> --probe-url <known-authed-url>`.

**An empty result from your own tooling is not a measurement of the target.** A refusal, zero-byte
result, parse error, or empty match set is a fact about the run until you show the probe reached the
target and did what you asked. Before running a probe, ask what a false result would look like (a
pattern that assumes wording the target may not use cannot answer the question); confirm the same
query returns hits for something known-present before believing the empty result. The same holds for
writes: verify the effect by re-reading the state, not the acknowledgement.

## 14. Stuck-state recovery

When the dry signal fires, change an axis instead of repeating the shape: another host or API
version, another identity, another vuln class, or another feature area (exhaust a duplicate
cluster first, §6). A bug that will not escalate goes to its vuln-class skill and the A→B chain
table in `agent/agents/exploit-developer.md`. When tools return nothing useful, read the JS and map
the API by hand.
