# Hunting Rules

These rules are always active across the engagement. They are intentionally compact, but they are
strict: breaking them lowers finding quality.

## 1. Resolve the engagement boundary before target work

Apply `agent/shared-constraints.md` §1; it owns the engagement boundary and the
state that must be resolved before target-facing decisions.

## 2. No theoretical findings — prove the attacker outcome, not just the vulnerability

For a live/deployed attack claim, if the answer to "can an attacker do this right now with real
harm?" is no, that claimed attacker outcome is not established yet.

**Code-mode reachability is not this file's.** Product path versus deployment-specific attacker
reachability, the net-new-capability test, and how far a library/framework defect may claim impact
without an embedding consumer are owned end-to-end by `agent/shared-constraints-code.md` §5 — the
code track's own bundle. Everything below governs live/deployed claims.

For live/deployed claims, proving a vulnerability exists is not enough: demonstrate what the
attacker **gains** from it. The gap between "vulnerability confirmed" and "attacker outcome
proved" is where most severity inflation happens.

**Existence proof (insufficient alone) — examples, not exhaustive:**
- "TLS validation is disabled" — so what?
- "IDOR returns a different user's ID" — what data?
- "SSRF reaches internal host" — what's on it?
- "Session token is in the response" — can you use it?

**Exploitation proof (required) — same examples, completed:**
- "TLS bypass lets attacker extract session token X from intercepted traffic → replaying X against /api/vault returns the victim's vault records"
- "IDOR on /api/users/{id} returns full name, email, phone, and billing address for any user ID"
- "SSRF to 169.254.169.254 returns IAM credentials → credentials grant s3:ListBucket on production bucket"
- "Session token replayed from a different IP returns 200 with authenticated user data — no IP binding"

For live/deployed claims, the pattern applies to every vulnerability class: confirm the primitive,
then demonstrate the attacker outcome it enables.

When you capture credentials, tokens, or keys — **use them**. Extract the token, replay it, show what it unlocks. If replay fails, say why (expiry, IP binding, CSRF token required) and mark the finding CHAIN REQUIRED with the specific gap.

A strong-but-unproven finding is parked, not dropped: hold it with `evidence_type=theoretical` + `chain_required=true` at `verification_status=pending_runtime_proof` (`vigil assess contract finding record`), and review the holding area with `vigil assess finding list --holding`. It stays out of the report until a runtime pass proves it.

**Recording a finding is not grading it.** A finding at `verification_status=unreviewed` is an **open question**, not a graded N/A — the lifecycle default means "not yet judged," not "judged harmless." Do not assert "no P2 here" / "this surface is clean" while any unauth or medium-plus finding is still `unreviewed`: an unreviewed finding is exactly what a clean-bill-of-health claim is supposed to have already resolved. Drive it to a verifier decision before you grade the surface.

### ROE-blocked: a candidate, not a severity downgrade

This rule demands the attacker outcome — but when you cannot safely complete the final
proof step because the program's rules of engagement forbid it (touching real customer
data, pivoting into production, exfiltrating a record you have already shown you can
reach), that is a constraint on *you*, not a weakness in the finding. Do not lower the
severity to match what you were permitted to demonstrate. Grade the **candidate at
impact-if-true** — the severity it carries if the blocked step succeeds, which the
surrounding evidence already makes likely — and record the single unblocking test that
would convert it, as `details.roe_blocked` plus a `details.required_followup` naming the exact
next action (`vigil assess contract finding record`).

This is distinct from the theoretical/`chain_required` park above (which needs another
*bug* to land): here the primitive is proved and only the demonstration is walled off by
policy. An ROE wall must never masquerade as a low-severity verdict.

### Blocked-for-provisioning: a third category

Distinct from both `roe_blocked` and theoretical/`chain_required`: `roe_blocked` means
the primitive is proved and only the final demonstration is walled off by policy;
theoretical/`chain_required` means the finding needs another *bug* to complete. A third
case is neither — the attempt cannot even start because a precondition is missing: no
test account in the required group, no access to the physical line/device, no
additional credential or access grant. The wall may be permanent for this engagement.
Record it on the finding as `details.block_reason` + `details.unblock_requirements` +
`details.attempts_summary` (field shapes and the `kind` vocabulary:
`vigil assess contract finding record`), and record the technique-level wall itself with
`vigil assess block-technique`.

A `blocked` finding stays OUT of the report — unlike an `roe_blocked` candidate, it is
not gradeable at impact-if-true, because the primitive itself was never reached. But the
unblock path is first-class, not a dead end: when a later finding or chain lands that
would satisfy the block (the missing account gets provisioned, the missing device turns
up, the missing credential surfaces elsewhere), link the two so the operator, and the
next engagement against this target, see the connection instead of re-discovering it from
scratch. Which side is the subject of that link depends on whether the wall is a finding
or a technique — `vigil assess contract finding link` and `contract block-technique` carry
both directions and why they differ.

### Re-derive a blocked record before accepting it

A `blocked` record encodes a premise that was true when it was written — an identity
that did not exist yet, a fixture nobody had built, a role that could not be granted, a
product "not provisioned for this user." Premises expire; the record does not.
Re-derive the premise before accepting the block, and re-read the standing block list
(`vigil assess list-blocked-techniques`, plus `vigil assess finding list
--verification-status blocked`) whenever a new identity, credential, or access
grant lands — tie the re-check to that state change, or to phase entry, never to a
feeling that the block is probably still good. A single stale "not provisioned for this
user" sentence can hide an entire product's surface for the rest of the engagement once
a second identity gains access to it.

## 3. Precondition equivalence check

Before rating severity, identify the precondition required to trigger the vulnerability. If that precondition already grants the attacker equivalent or greater access than the vulnerability itself provides, the finding is defense-in-depth (Low), not an independent exploit. Score on incremental impact over the precondition, not total impact of the chain.

Examples:
- **Redundant**: "Unvalidated redirect captures auth verifier" — but triggering the redirect requires breaking the same TLS connection that already exposes the auth verifier. Incremental impact: zero.
- **Not redundant**: "App disables TLS validation process-wide" — no precondition beyond network proximity. The app removes its own protection. Incremental impact: full credential capture from any shared network.
- **Chain test**: If exploiting B requires condition A, ask: "What can the attacker already do with just A?" If the answer is "everything B provides," then B is defense-in-depth.
- **Attacker controls the whole processed input**: the same test applies when the "precondition" is that the victim runs the tool on an artifact the attacker wholly controls — a repo, PR, template, project path, archive, config, or build. Run the chain test with A = "the victim processes the attacker's artifact": a build/dev tool that compiles or executes the attacker's own source *by design* already grants code execution, so a flaw that only reproduces that outcome (e.g. a crafted directory name that injects an import the attacker could have written into their own source) is defense-in-depth — zero incremental capability — **unless** it reaches a genuinely different trust context (a victim's deployment/tenant/credentials, or a control the attacker's visible source could not evade). A fully-reproduced injection can still be no-impact under this test. The verifier's FP catalog echoes this as the "Redundant with the attacker's own controlled input" trigger (`agent/references/finding-fp-and-severity-gate.md`), run by both the web and code verifiers.

## 4. Kill weak leads fast — and push harder on strong ones

Kill low-confidence signals fast — validate quickly, chain them, or drop them. The inverse matters equally: when a signal is live, push through ambiguous responses until you have either the attacker outcome or a concrete reason the path fails.

Kill signals include:

- Theory without a real request, response, or replayable action
- More than two fragile preconditions stacked together
- "Might be chainable" used instead of a proved chain
- Static or generic surface with no meaningful attack paths after a short pass

Push-harder signals include:

- A response field, timing delta, or status code diverges between two otherwise-identical requests (different account, different header, different payload encoding) — divergence is evidence of state the application is keeping, and that state is usually where the finding lives
- An error message, stack trace, or redirect leaks framework internals, file paths, or infrastructure hostnames
- Repeating the exact same request produces different behavior — the target is carrying state across requests
- A probe produces partial signal (OOB DNS fires but no body leak, time delta without error, 5xx on malformed input) — partial signal means the primitive exists; the next work is shaping the payload to complete it
- A sibling route, method, or content-type behaves differently than the one you just tested — siblings are the fastest way to confirm or widen the finding
- The response silently accepts an input shape the application shouldn't (alternate protocol, unexpected encoding, out-of-range value) without erroring — silent acceptance is almost never benign

## 5. Exhaust the surface — depth over breadth, rotate only when genuinely dry

Leave a surface only when it is genuinely dry: no meaningful routes, no privileged features, no object references, and no useful source intelligence after a *thorough* pass. "Slow" is not "dry" — do not rotate on a timer; rotate when you have actually exhausted the surface.

One well-understood target is worth more than shallow passes over many: stay on it long enough to
understand what the application actually values (its money-moving flow, its admin surface, its
trust boundary) before moving to the next. A breadth-first sweep that touches everything once and
nothing twice is exactly how the deep bug on the third surface gets missed.

## 5a. A human-reach determination is part of exhausting a surface

An endpoint whose human-reach status is still **unknown** — the `agent/shared-constraints.md`
§2d preflight did not resolve it, and no `human_reach_decision` has been recorded —
is an **open question, not a silent skip**. Do not close a surface as exhausted
while a notify-shaped endpoint on it sits undetermined; run it through the procedure
`vigil assess contract agent decision` owns (static characterization, then the bounded
live-fire budget if still ambiguous) so it lands in the same recorded-verdict system
as every other lead. A name alone — `send-notification`, `alert-approver`, `ticket-create` — is a
hypothesis about behavior, not proof it reaches anyone: an endpoint that only
*looks* notify-shaped may resolve NEGATIVE under the reaches-a-real-third-party
test and become ordinary surface, and one that looks harmless may resolve
POSITIVE. The recorded determination — not the name — decides how you treat it.

## 6. Evidence beats volume

A handful of decisive, exact requests that prove the primitive is stronger evidence than broad,
repetitive testing across many inputs — once the first proof lands, reissuing it is noise, not
rigor. This holds at the collection boundary too: once access to a data set is proven, one minimal
sample is the whole of the evidence a finding needs. Pulling more records is not more proof, and
the extra pull is itself the harm (`agent/shared-constraints.md` §4, "Proof-not-collection").

## 7. Reach for the skill when the signal calls for it

Trigger-gated skill loading is owned by `agent/shared-constraints.md` §3 (code track:
`agent/shared-constraints-code.md` §8) — read it there.

## 8. Automation for recon, judgment for validation

Use automation to enumerate and classify. Use deliberate human-guided validation for auth, logic, chaining, and impact.

## 9. The sibling rule

When one route, method, content-type, or controller path is vulnerable, its siblings sharing the
same code path are the highest-probability next test — a vulnerable pattern is rarely unique to
the one instance you happened to test first. Walk every sibling before moving to a new surface;
this is what the Verify → Exploit variant/sibling pass (`agent/operator-core.md` Mandatory
Phase-Exit Passes) checks for at phase exit.

## 10. Think in chains

Use bug A as a signal for B and C nearby; follow the cluster until it is genuinely dry.

## 11. Impact first

Prioritize surfaces where broken auth, object reference drift, privileged writes, or trust-boundary
confusion would matter over surfaces where they wouldn't. This is not a style preference — these
are the same families (`access-control`, `auth`, `injection`, `ssrf`, `file`) the depth ledger
treats as BLOCK_HIGH (rule 25, below); weighting your own attention toward them here is the same
judgment the terminal gate applies later, applied earlier when it's cheaper to act on.

## 13. Validate before writing — a report entry costs the same evidence bar as a finding

Do not draft a finding, chain step, or remediation note from a lead that hasn't been pushed to a
`tested`/`signal` probe-run verdict (§23) with recorded evidence. Writing the prose ahead of the
evidence backfills confidence the testing never earned, and Phase 5's reviewer inherits the gap
instead of catching it. A live/deployed lead earns report space only after it clears rule 2's
proved-attacker-outcome bar. A code-mode finding clears the corresponding bar with a supported
product path, concrete invariant failure, feasible harmful outcome, and bounded consumer-impact
claim under `shared-constraints-code.md` §5.

## 14. Credentials require proof

Leaked tokens, keys, or config only matter when you show what they actually grant.

## 15. Rotate only when genuinely dry, not when slow

Rule 5 applied to a single lead: switch endpoint, method, surface, or hypothesis only once
repeated *varied* attempts (not repeats of the same probe) produce **no new information**.

## 16. Time is not the constraint — confidence is

Being thorough and refusing to rush is what earns high confidence that no vulnerability was left undiscovered; a pass that finishes fast but shallow has not done the job. Do not trade coverage or validation depth for speed, and do not abandon a live lead because it is taking time. This is not license to grind genuinely dead surface — rules 5 and 15 govern that: rotate only when a surface is truly exhausted, then spend the reclaimed time going deep on live surface.

## 16a. Exhaust confirmed leads first; break the same-response-class loop

A *confirmed* lead — a host that answers but blocks, a gate that rejects (any
auth/permission wall), a partial primitive that half-works — must be either
driven to its attacker outcome or explicitly dispositioned ("dead because X")
before you declare stuck or fall back to brute-force discovery. Confirmed-but-
unexploited is not a stopping point; it is the highest-value work on the board.

Anything proven on one confirmed surface gets tried on every other confirmed
surface of the same shape before you rotate away — the sibling rule (rule 9)
applied to leads, not just bugs.

Circuit-breaker (a cue, not a counter): if your last several *varied* attempts
on a lead all returned the same response CLASS — same status family, same
error shape, no new state (rule 15's "no new information") — STOP issuing more
of that shape and go to rule 17. Re-issuing the same response class is the dry
signal. This does NOT apply to a probe you are repeating on purpose to detect
state divergence (rule 4's push-harder signals) — that is new information, not
a stall.

## 16b. Phase-exhausted means every flagged host has a recorded verdict — not a feeling of completion

Rule 16 measures the *job* by confidence; this rule operationalizes when a
*phase* is actually done. A phase is **exhausted** only when every real-app
host above the route threshold carries a **recorded verdict** — a finding, or
an evidence-backed negative (the coverage ledger's `recorded-verdict?`). A
*feeling* of completion after working the highest-route hosts is not a verdict:
the sense that "I have seen what this surface is" is exactly the head-sampling
bias that buries findings on the hosts you never opened.

**Never generalize a surface-wide conclusion from a non-representative
sample.** "Everything funnels to one account system," "every subdomain is the
same SPA," "the whole estate is one vendor platform" — a conclusion that
retires *untested* hosts has to be earned host-by-host, not extrapolated from
the few you happened to test first. A hypothesis whose payoff is that it ends
the hunt is the one to distrust most.

**Ledger-green is a FLOOR, not proof of exhaustion.** A passing coverage
ledger means every *flagged* host has a verdict — it does **not** mean the
surface is fully explored. A high-value API that sits below the route
threshold may never have been flagged at all, so a green ledger can co-exist
with an entire untested application (rule 25, "A URL can be a whole application,"
below, is the companion check). Treat ledger-green as the minimum bar you
cleared, then keep looking for the surface the ledger could not see.

**A negative verdict on one tier or lens does not cover siblings.** A
"fails-closed" / "covered" / "no-params" negative is only valid when it names the exact
**tier + lens** it was proven on and the run **completed** (not timed-out or partial). A
sibling tier — different auth level, different role, different trust context — or a new
lens on an already-worked surface is a fresh test, not a redundant one. Before recording
a negative and closing the work item, state "proven fails-closed at [tier] / [lens] /
[run-id]" — anything shorter than that is a disposition you cannot defend.

**Bracket every negative with a live positive control.** Prove a positive on the same
route, verb, identity, and gateway, in the same window, before you record the negative.
Without one you cannot distinguish "denied" from "blocked," "not found," "not
provisioned," or "not reached" — the response bytes alone don't carry that distinction.
This generalizes a case already enforced narrowly: before a failed replay becomes a
negative disposition, `agent/agents/vulnerability-analyst.md` requires proving the
identity is actually live — `vigil assess auth status --probe --identity <name>
--probe-url <known-authed-url>` — the identity-specific instance of this general rule.

**Pull the next uncovered host; do not sample.** The default loop is
structural, not intuitive: take the next `uncovered` real-app host straight off
`vigil assess coverage` and give it a lane, rather than choosing what to test
next by feel. Pulling from the ledger is what prevents head-sampling
mechanically — you cannot quietly skip a host the ledger keeps handing you.

## 17. Stuck-state recovery

When progress stalls, use this table to pick a concrete next action instead of grinding:

| I'm stuck because... | Go to |
|---|---|
| All endpoints return 403/401 | Rotate to a different subdomain or look for unauthenticated API versions (`/api/v1/`, `/api/public/`) |
| I found a bug but can't escalate impact | Load the matching vuln-class skill and check the A->B chain table in `exploit-developer.md` |
| Recon is huge but I don't know where to start testing | Rank by signal density: API endpoints with object IDs > authenticated-only routes > static pages |
| Every parameter seems filtered | Try encoding bypass (double-URL, unicode, null bytes), then switch to a different vuln class entirely |
| I keep finding duplicates of the same bug pattern | Apply the sibling rule (rule 9) to exhaust the cluster, then rotate to a different feature area |
| The app is simple with few endpoints | Go deeper: test business logic, race conditions, multi-step workflow abuse, parameter pollution |
| I confirmed a low-severity bug but can't chain it | Check if it enables a higher-impact primitive (open redirect -> OAuth theft, SSRF -> metadata, XSS -> admin panel) |
| Tools are returning nothing useful | Stop automation, test manually. Read the JS source, map the API by hand, test one request at a time |

## 22. Smallest probe that answers the question

Prefer the smallest probe that gets you the answer. If you already know what
to test — a discovered path from `robots.txt` / sitemap / JS, a known
parameter pulled from source analysis, a specific endpoint — `curl` that
thing directly via `vigil assess kali exec -- curl ...`. If you have NO
knowledge and need to discover from scratch, AND brute-force is in scope per
the engagement VDP, then use the appropriate Kali verb — the verb menu is in
`vigil assess kali --help` and `agent/skills/kali-exec/SKILL.md`.

Before you brute-force a *format* — guessing parameter names, ID shapes, path
segments, or value encodings — re-read the recon output you already captured,
verbatim, for the exact shape. Self-describing surfaces hand you the format for
free: machine-readable API descriptions, queryable type/field-definition endpoints,
`.well-known/` resources, sitemaps, and routes embedded in served source. Mine
and ingest those first; a guessed variant you could have read off a captured
artifact is wasted traffic and lower-quality evidence.

Both modes are valid. The failure modes are symmetrical: a fan-out tool
fired when you have specific targets wastes traffic, may trip WAFs, and
loses the surgical evidence quality triagers want; a hand-built `curl` loop
fired when you genuinely need wordlist fan-out wastes context-window and
produces lower-quality evidence than the equivalent tool run.

**The VDP overrides this.** Bug-bounty programs frequently mark
brute-force, automated-scanner-only, and excessive-traffic findings as
out-of-scope. When a VDP forbids brute-force (as many financial programs do)
or rejects scanner-only evidence ("Reports based only on
automated tool/scanner results... will not be accepted"), do not run
`ffuf` / `arjun` / `puredns` / generic-template `nuclei` regardless of
what's "more efficient" — fall back to surgical `curl` against
specifically-discovered targets. Read scope before reaching for any
fan-out tool.

**Evidence-capture follow-ups are surgical.** When a tool surfaces a
candidate (arjun flags `?debug=` as reflected, ffuf finds `/admin/users`,
nuclei flags a CVE), the next step is almost always a `curl` against the
specific endpoint to capture the request/response that becomes the finding
evidence. That follow-up `curl` is not "noisy curl that should have been a
tool" — it is the surgical capture step the tool cannot perform. Keep
doing them.

## 22a. A self-imposed discovery restriction is not a target fact

A self-imposed "I won't enumerate because it might violate RoB" is a conservative
interpretation, not a target fact. Light, targeted, low-rate **curated** content-discovery
of *known* protected resources — a path already found in JS, a parameter visible in a
form, a directory referenced in a redirect — counts as "identifying an indicator" and IS
compliant under a "minimal testing" commitment. The honest RoB line is **rate +
wordlist-size + stop-on-sensitive-data**, not "never enumerate."

Before accepting a self-imposed restriction as a severity cap, re-read the program's
exact language. If the policy forbids high-volume automated scanning but not targeted
discovery of paths you already have evidence for, re-dispatch with the restriction relaxed
to the correct reading — treating an over-restriction as a finding boundary is exactly
where depth is lost.

## 23. A non-conclusive response is a LEAD, not a verdict

A response only becomes a verdict when it actually answers the question. A status
code on its own, a non-401 error on a protected op, and a transport failure are all
**non-conclusive** — each is a lead to push, never a "tested / clean / patched / not-present"
closure. Recording a closure from any of them buries a real finding behind a wrong disposition.

**(a) A raw status code is not a disposition for a body-dependent class.** For any class
where the proof lives in the response — file uploads, injection, IDOR reads, reflection,
auth-skip, stored-XSS (including SVG payloads), the *serving* `Content-Type`/CSP — a `200`/`403`/`404` status
alone decides nothing. Capture and inspect the response **body and headers**, not just the
code: a `200` on an upload can be the bypass; a `403` can carry a leaked body; the serving
`Content-Type` + CSP, not the upload status, decide whether an SVG executes. `curl -o /dev/null`
(status/timing only) is for **pure liveness or timing probes** — never for a candidate whose
verdict depends on what came back. A re-pass that only added body inspection is exactly how
missed upload and stored-XSS findings get recovered.

**(b) A 401/403 means the auth gate fired; any other outcome on a protected op did NOT.**
A `401`/`403` from the gateway is the auth gate rejecting you — that, and only that, is an
auth-rejection verdict. **Any other outcome** on a protected operation — a field/schema
**validation error** (`400`/`422`), a `500`/parse error, a `missing required argument` /
`did you mean` message, or silent acceptance — proves the request was parsed and reached the
**resolver / business-logic / handler layer WITHOUT being auth-rejected**, i.e. the surface is
**anonymously reachable up to validation**. That is a **LEAD**, not a closure: re-send with
**valid-shape arguments** (correct types, all required fields, a syntactically valid body) to
drive past validation to the *real* authorization decision. Treating a validation error as
"tested / clean / not-vulnerable" closes a surface that was never actually auth-tested. (The
narrow worked instances — a denylist `400`/`403` documented in the relevant request-forgery skill,
and resolver-authz notes in `agent/skills/graphql-testing/SKILL.md` — are this rule applied to
one class; this is the general form. Use `vigil assess list-skills` to find the matching skill.)

**(c) An `http=000` / connection-failed / DNS-failure response is a RUNTIME ERROR, not a
target verdict.** A failed connection tells you nothing about the target, so never record
"404 / patched / gated / not-present" from one. The kali path surfaces it as
`status=transport_error` (exit 6) and auto-retries once host-pinned; if it persists, re-run via
the host route (`--runtime host`) and let a *real* HTTP response — or a clean, fast
connection-refused — be the verdict.

**(d) A WAF / bot-challenge interstitial is PENDING — never a verdict in either direction —
until a browser proves the origin.** When the bytes are the edge's challenge page rather than
the origin app's, the response belongs to the WAF, not the application behind it, and decides
nothing about the surface. Re-render with `vigil assess kali browser <url>`: headless Chromium
executes the challenge JS and returns the **real origin** status + DOM, and only that rendered
origin response is a verdict. The kali path surfaces this as `status=waf_challenge` precisely so
it cannot close a surface as `404`/`patched`/`gated`/`not-present`; do not override it with the
challenge's status code. Vendor challenge signatures, and the fingerprint-block case a re-render
will NOT clear, are in `agent/references/web/waf-bypass-and-safe-testing.md`.

**(e) An auth-gate redirect is a bypass-test LEAD, not a "covered/gated" closure.**
A `302` to a login or policy page proves the gate *fired* — it says nothing about whether
the gate is bypassable. Classifying a redirected endpoint as "covered/gated" and closing
it consumes the signal without doing the work. Record the redirect as a lead and run a
bypass-technique sweep (static-extension exemption, path-normalization confusion,
routing-header injection, verb tampering) before the surface is dispositioned — the
auth-bypass skill carries the sweep methodology.

**(f) Verify the exact bytes on the wire before treating a `406` / content-negotiation
response as target behavior.** An unquoted header value in curl argv shell-splits into
separate tokens, producing a malformed request that the connection layer rejects before it
reaches the application. The resulting `406` or error is a **Kali-side artifact**, not a
target response. Before closing a content-negotiation probe, confirm the request was sent
with the header intact: replay with `--verbose` and inspect the `>` request lines to
verify the `Accept:`/`Content-Type:` value was transmitted as a single token. An artifact
from a malformed argv is not evidence the handler was reached.

**Re-derive un-pushed signals from RAW evidence.** A prior agent's stopping point — a
"tested / clean / disproven" note, a `notes/PHASE-3-REMAINING-WORK.md` line, an inherited
disposition — is a **view to re-verify, not ground truth**. Before accepting any negative
disposition on a protected op, re-open the raw `command-run get` rows behind that signal
(`vigil assess command-run get <id>`, `vigil assess command-run list --tool-bin <bin> --show-matches`)
and re-derive the disposition from the actual request/response bytes. A `403` recorded by a
prior pass may have been a downstream validation error mistaken for an auth gate (b); a "patched"
may have been an `http=000` transport error (c); a "clean" may have been a status-only probe that
never read the body (a); a "gated"/"not-present" may have been a WAF challenge page never
re-rendered in a browser (d).

## 23a. Aggregate-rate discipline — a shared egress IP sees the SUM of every concurrent dispatch

A WAF-fronted estate rate-limits (or hard-blocks) the shared runtime egress IP, not any single
dispatch — four agents each issuing a "safe" 5 r/s look like one client doing 20 r/s at the
edge, and that sum, not any one agent's rate, is what trips the rule.

- **Budget the AGGREGATE request rate across ALL concurrent dispatches, not per-dispatch.**
  Before adding another concurrent agent against a WAF-fronted estate, sum the rates already
  in flight and confirm the total still fits the tier's ceiling
  (`agent/references/recon/rate-calibration.md`).
- **Do not run an inherently high-volume tool** (`arjun`, `ffuf`, a large `nuclei` sweep)
  **concurrently with multiple deep specialist agents** on the same WAF-fronted estate over the
  shared egress IP — serialize it, or run it alone at a low rate scoped to a few endpoints.
- **Run long or high-volume tools as an operator-owned `kali job`, not a stretched synchronous
  `kali exec`.** `vigil assess kali job stop` cleanly SIGTERMs the in-container PID it owns. A
  synchronous call killed by the external agent-harness ceiling (exit 144/SIGUSR1,
  `agent/shared-constraints.md` §2) orphans the in-container process instead — an orphaned
  scanner keeps sending traffic to the target with nobody watching it or able to stop it.
- **A WAF/CloudFront 403 block is PENDING, never a clean negative.** A *challenge interstitial*
  resolves via a browser re-render (rule 23(d) above); a *signature/fingerprint block*
  (AWS-WAF/CloudFront) returns the same 403 to headless Chromium, so a re-render will not clear
  it — it stays PENDING until routed WAF-clean. Detection signatures, the
  per-request-vs-estate-block disambiguation, and WAF-clean routing intel:
  `agent/references/web/waf-bypass-and-safe-testing.md`.

## 24. OOB self-resolution caveat — confirm on a public egress source

Blind SSRF is confirmed only when the callback arrives at a **publicly routable** listener
from a **public egress source IP**, or when the callback includes a real HTTP interaction
(status line, headers) originating from the target's egress path. A DNS hit that
originates from a container-bridge or private subnet address — 172.x.x.x, 10.x.x.x, or
the Kali runtime's own IP — is **self-resolution**: the Kali container resolved the OOB
host itself, not the target server. Self-resolution is infrastructure noise, not a
finding.

To avoid fabricating self-resolution hits:
- Place OOB callback hosts in **request bodies**, not in curl header argv. Curl resolves
  header values before the request reaches the wire; a host in
  `-H "X-Forwarded-For: http://<oob>"` may be resolved by the Kali container, not the
  target.
- Use `vigil oob mint` to get a nonce-tagged callback URL; correlate with
  `vigil oob poll`, which matches probe-to-callback and shows the source IP. A hit whose
  source IP falls in RFC-1918 space is self-resolution regardless of the DNS name.
- Confirm public egress on the OOB hit before recording a SSRF finding.

## 25. A URL can be a whole application — go deep on app units

A single host often carries several distinct applications under different
path-prefixes — `host/giving` (a donations app), `host/admin` (tenant
admin), `host/api/v2` (a REST surface). Each is its own **app unit**
`(host, port-class, path-prefix)` with its own auth model and attack
surface. A shallow pass over many hosts that glances at each prefix hides
that an entire application went untested — exactly the failure this harness
exists to catch.

The backend scores each app unit (structure × risk − suppressors) and marks
the ones worth a dedicated deep campaign as `deep_required`. Mid-engagement
this scoring is **advisory and EV-ranked** — it tells you where to dig next,
and nothing in Phases 1–6 refuses a transition or exits non-zero on it. But
that advisory posture does not hold all the way to report: app-unit depth is
where depth is *measured*, at two grains, and a **decisive-surface or
high-confidence** `deep_required` unit that fails either one is a
**deferred-terminal obligation**, not advisory:

- **Family grain** (`kind=depth_unsatisfied_units`) — the unit was never
  touched at all for a BLOCK_HIGH family (`access-control`, `auth`,
  `injection`, `ssrf`, `file`).
- **Class grain** (`kind=depth_uncovered_classes`) — the family LOOKS covered
  or touched, but a specific class its gf coverage_items flagged
  (`signal_classes_uncovered`) was never class-specifically probed — a
  sibling class (e.g. `ssti`) can satisfy the whole `injection` family while
  `sqli` has no class-specific probe. The class gate applies even when the
  unit is otherwise family-satisfied or touched.

Both block the terminal `report`/`complete` edge unless you deep-test the
gap or clear it with a recorded `depth_deferral` decision (exact escape
command, the touched-but-unfinished WARN downgrade, and the non-decisive/
low-confidence exemption: `agent/phases/phase-8-report.md` Definition of Done
and `agent/operator-core.md` Mandatory Phase-Exit Passes).
`check-phase-readiness --phase report` previews the same ledger every phase
from Phase 4 on, so the hold is legible the whole way and never a surprise at
report time.

Treat a `deep_required` unit as a whole application: a dedicated dispatch
across every applicable vuln class and auth context, not a single surface
glance. `vigil assess app-unit list` shows the ledger, `app-unit score`
re-runs discovery, and `app-unit mark-deep` / `clear-deep` pin a manual
override that always beats the scorer (`vigil assess contract app-unit`);
claim a unit's next coherent queue batch with `vigil assess work-buffer
fetch-by-unit` (`vigil assess contract work-buffer`).

## 26. Attack headers are ordinary injected inputs, not special-cased

A header the application (or a fronting proxy/CDN) trusts as authoritative is an
injected-at-test-time input like any query param or body field — you choose which
ones are plausible for the observed architecture, probe them, and record the
result exactly like any other named input. The standard set worth trying wherever
a proxy, CDN, or load balancer sits in front of the target:

| Header | What it typically confuses |
|---|---|
| `X-Forwarded-Host` | Origin routing, password-reset/link-generation host, cache-key host |
| `X-Original-URL` / `X-Rewrite-URL` | Reverse-proxy path rewriting — path-based auth bypass |
| `X-Http-Method-Override` / `X-HTTP-Method` | Verb-based access control (a blocked `DELETE`/`PUT` re-sent as `GET` + override) |
| `X-Forwarded-For` / `X-Real-IP` | IP-allowlist / rate-limit / geofence bypass, log/audit poisoning |

This is a starting menu, not a checklist to exhaust mechanically — the same
"surface what exists, LLM chooses, evidence lands in the grid" principle that
governs every other input applies here uniformly; headers are not special. Inject
the ones plausible for the architecture you observed (a CDN-fronted host →
`X-Forwarded-*`; a path-rewriting reverse proxy → `X-Original-URL`/`X-Rewrite-URL`),
then record the attempt the same way you would a query or body probe — as
`vigil assess record-probe --input-slot header:<name> ...`, whose verdict decides
covering vs. touched-but-inconclusive (full flag set: `vigil assess contract
record-probe`). Observed security-relevant routing,
identity, and method-override names can arrive as first-class `header:<name>`
coverage items; manual probes still land in the same per-input grid when no item
was derived. For exploitation depth once a header vector shows signal, see
`agent/skills/host-header-injection/SKILL.md`.

---

## 27. An empty result from your own tooling is not a measurement of the target

Rule 23 governs what the *target* returned. This one governs what *your own tooling* returned. A
refusal, a zero-byte result, a parse error, or an empty match set is a fact about the run, not a
fact about the target — and it arrives looking exactly like a clean negative. Before recording any
"nothing there," establish that the probe reached the target and did the thing you asked.

The failure is expensive because it is confident and it compounds: a rate-limited API that silently
drops your request returns zero bytes, and "nothing exposed on their GitHub" enters the record as a
finding-grade negative that later work inherits without re-deriving.

Two habits catch it:

- **Ask what a false result would look like, before you run the probe.** If your grep would match a
  string you introduced yourself, or your search pattern assumes wording the file may not use, the
  probe cannot answer the question — and you know that in advance, not afterwards.
- **Bracket a negative with a positive control.** Confirm the same query returns hits for something
  known-present before believing the empty result for your target. An archive index that is empty
  for every host is broken; one that is empty only for yours is evidence.

The same rule applies to writes: **verify the effect, not the acknowledgement.** An operation can
succeed structurally while being empty of the thing you needed — a write that returns 200 and
changes nothing, a self-check that renders a stale row, a 200 whose body carries no data because a
cache had not filled. Re-read the state you intended to change rather than trusting the response
that says you changed it.
