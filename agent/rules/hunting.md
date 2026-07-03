# Hunting Rules

These rules are always active across the engagement. They are intentionally compact, but they are
strict: breaking them lowers finding quality.

## 1. Read scope before target work

Confirm the exact in-scope hosts, scope mode, exploit policy, and auth state before making target-facing decisions.

## 2. No theoretical findings — prove the attacker outcome, not just the vulnerability

If the answer to "can an attacker do this right now with real harm?" is no, it is not a finding yet.

Proving a vulnerability exists is not enough. You must demonstrate what the attacker **gains** from it. The gap between "vulnerability confirmed" and "attacker outcome proved" is where most severity underrating happens.

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

The pattern applies to every vulnerability class: confirm the primitive exists, then demonstrate the attacker outcome it enables.

When you capture credentials, tokens, or keys — **use them**. Extract the token, replay it, show what it unlocks. If replay fails, say why (expiry, IP binding, CSRF token required) and mark the finding CHAIN REQUIRED with the specific gap.

A strong-but-unproven finding is parked, not dropped: hold it with `evidence_type=theoretical` + `chain_required=true` at `verification_disposition=pending_runtime_proof` (see `agent/operator-core.md`), and review the holding area with `vigil assess list-findings --holding`. It stays out of the report until a runtime pass proves it.

**Recording a finding is not grading it.** A finding at `verification_state=unreviewed` is an **open question**, not a graded N/A — the lifecycle default means "not yet judged," not "judged harmless." Do not assert "no P2 here" / "this surface is clean" while any unauth or medium-plus finding is still `unreviewed`: an unreviewed finding is exactly what a clean-bill-of-health claim is supposed to have already resolved. Drive it to a verifier disposition before you grade the surface.

**ROE-blocked proof is a CANDIDATE, not a severity downgrade.** This rule demands the attacker outcome — but when you cannot safely complete the final proof step because the program's rules of engagement forbid it (touching real customer data, pivoting into production, exfiltrating a record you have already shown you can reach), that is a constraint on *you*, not a weakness in the finding. Do not lower the severity to match what you were permitted to demonstrate. Grade the **candidate at impact-if-true** — the severity it carries if the blocked step succeeds, which the surrounding evidence already makes likely — and record the single unblocking test that would convert it: set `details.roe_blocked=true` and put the exact next action in `details.required_followup`. This is distinct from the theoretical/`chain_required` park above (which needs another *bug* to land): here the primitive is proved and only the demonstration is walled off by policy. An ROE wall must never masquerade as a low-severity verdict.

**Blocked-for-provisioning is a THIRD category — distinct from both `roe_blocked` and theoretical/`chain_required`.** `roe_blocked` means the primitive is proved and only the final demonstration is walled off by policy; theoretical/`chain_required` means the finding needs another *bug* to complete. A third case is neither: the attempt cannot even start because a precondition is missing — no test account in the required group, no access to the physical line/device, no additional credential or access grant — and the wall may be permanent for this engagement. Record this with `details.block_reason` (why the attempt could not proceed) and `details.unblock_requirements` (`{kind: account|line|device|credential|access, description, requested_from}` — what is missing and who/what would need to provision it); roll repeated attempts up into `details.attempts_summary` instead of scattering them across free-text notes. A `blocked` finding stays OUT of the report — unlike an `roe_blocked` candidate, it is not gradeable at impact-if-true, because the primitive itself was never reached. But the unblock path is first-class, not a dead end: when a later finding or chain lands that would satisfy the block (the missing account gets provisioned, the missing device turns up, the missing credential surfaces elsewhere), link the two — `vigil assess link-finding <blocked-finding-slug> --link-kind unblocked_by --target-kind finding --target-ref <finding-that-unblocks-it>` — so the operator, and the next engagement against this target, see the connection instead of re-discovering it from scratch.

## 3. Precondition equivalence check

Before rating severity, identify the precondition required to trigger the vulnerability. If that precondition already grants the attacker equivalent or greater access than the vulnerability itself provides, the finding is defense-in-depth (Low), not an independent exploit. Score on incremental impact over the precondition, not total impact of the chain.

Examples:
- **Redundant**: "Unvalidated redirect captures auth verifier" — but triggering the redirect requires breaking the same TLS connection that already exposes the auth verifier. Incremental impact: zero.
- **Not redundant**: "App disables TLS validation process-wide" — no precondition beyond network proximity. The app removes its own protection. Incremental impact: full credential capture from any shared network.
- **Chain test**: If exploiting B requires condition A, ask: "What can the attacker already do with just A?" If the answer is "everything B provides," then B is defense-in-depth.

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

## 5. Exhaust the surface — rotate only when genuinely dry

Leave a surface only when it is genuinely dry: no meaningful routes, no privileged features, no object references, and no useful source intelligence after a *thorough* pass. "Slow" is not "dry" — do not rotate on a timer; rotate when you have actually exhausted the surface.

## 5a. A human-reach determination is part of exhausting a surface

An endpoint whose human-reach status is still **unknown** — the `agent/shared-constraints.md`
§2d preflight did not resolve it, and no `human_reach_decision` has been recorded —
is an **open question, not a silent skip**. Do not close a surface as exhausted
while a notify-shaped endpoint on it sits undetermined; run it through the §2d
procedure (static characterization, then the bounded live-fire budget if still
ambiguous) so it lands in the same recorded-verdict system as every other lead.
A name alone — `send-notification`, `alert-approver`, `ticket-create` — is a
hypothesis about behavior, not proof it reaches anyone: an endpoint that only
*looks* notify-shaped may resolve NEGATIVE under §2d and become ordinary surface,
and one that looks harmless may resolve POSITIVE. The recorded determination —
not the name — decides how you treat it.

## 6. Evidence beats volume

Prefer a few decisive requests and exact proofs over broad noisy testing.

## 7. Use skills before improvising

Load the most relevant skill first. Only improvise when the existing skill/reference set is genuinely insufficient.

## 8. Automation for recon, judgment for validation

Use automation to enumerate and classify. Use deliberate human-guided validation for auth, logic, chaining, and impact.

## 9. The sibling rule

When one route, method, or controller path is vulnerable, inspect its siblings before moving on.

## 10. Think in chains

Use bug A as a signal for B and C nearby; follow the cluster until it is genuinely dry.

## 11. Impact first

Prioritize surfaces where broken auth, object reference drift, privileged writes, or trust-boundary confusion would matter.

## 12. Depth over breadth

One well-understood target or feature is worth more than shallow passes over many. Stay long enough to understand what the application actually values.

## 13. Validate before writing

Validate leads to reproducible, evidence-backed state before report drafting — a finding earns report space only when it is worth a human reader's time.

## 14. Credentials require proof

Leaked tokens, keys, or config only matter when you show what they actually grant.

## 15. Rotate only when genuinely dry, not when slow

Switch endpoint, method, surface, or hypothesis when a lead is genuinely exhausted — when repeated *varied* attempts (not repeats of the same probe) produce no new information. Slow or difficult is not the same as dry: push through ambiguous responses on a live lead before rotating.

## 16. Time is not the constraint — confidence is

Being thorough and refusing to rush is what earns high confidence that no vulnerability was left undiscovered; a pass that finishes fast but shallow has not done the job. Do not trade coverage or validation depth for speed, and do not abandon a live lead because it is taking time. This is not license to grind genuinely dead surface — rules 5 and 15 govern that: rotate only when a surface is truly exhausted, then spend the reclaimed time going deep on live surface.

## 16b. Exhaust confirmed leads first; break the same-response-class loop

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

## 16c. Phase-exhausted means every flagged host has a recorded verdict — not a feeling of completion

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
with an entire untested application (the "a URL can be a whole application"
rule below is the companion check). Treat ledger-green as the minimum bar you
cleared, then keep looking for the surface the ledger could not see.

**A negative verdict on one tier or lens does not cover siblings.** A
"fails-closed" / "covered" / "no-params" negative is only valid when it names the exact
**tier + lens** it was proven on and the run **completed** (not timed-out or partial). A
sibling tier — different auth level, different role, different trust context — or a new
lens on an already-worked surface is a fresh test, not a redundant one. Before recording
a negative and closing the work item, state "proven fails-closed at [tier] / [lens] /
[run-id]" — anything shorter than that is a disposition you cannot defend.

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

## 18. Sub-Agent Dispatch Discipline

> **Sub-agent dispatch discipline** (default-to-dispatch, inline only for
> operator-scoped work, one-specialist/one-objective/one-skill-set): moved to
> `agent/operator-core.md`'s dispatch doctrine — operator-only content, not a
> specialist read.

## 19. Developer psychology heuristics

> **Developer psychology heuristics** (feature-copy, flow-complexity, API
> version drift, naming anomaly, error-response divergence, new-feature
> window): moved to `agent/rules/mindsets/developer.md` — load it as your
> generative lens for hypothesis generation.

## 20. Severity-CVSS alignment audit before report

> **Severity-CVSS alignment audit before report:** moved to
> `agent/operator-core.md`'s dispatch doctrine — operator-only content, not a
> specialist read.

## 21. Stale-text scrub before publishing

> **Stale-text scrub before publishing:** moved to `agent/operator-core.md`'s
> dispatch doctrine — operator-only content, not a specialist read.

## 22. Smallest probe that answers the question

Prefer the smallest probe that gets you the answer. If you already know what
to test — a discovered path from `robots.txt` / sitemap / JS, a known
parameter pulled from source analysis, a specific endpoint — `curl` that
thing directly via `vigil assess kali exec -- curl ...`. If you have NO
knowledge and need to discover from scratch, AND brute-force is in scope per
the engagement VDP, then use the appropriate Kali verb (`ffuf` for paths,
`arjun` for params, `puredns` for DNS, `sqlmap` for SQLi, `dalfox` for XSS,
`nuclei` for template-based CVE/misconfig, `httpx`/`whatweb`/`wafw00f` for
fingerprinting).

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
out-of-scope. When the VDP forbids brute-force (Acme Bank, many financial
programs) or rejects scanner-only evidence ("Reports based only on
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
target verdict.** A failed connection tells you nothing about the target. On the kali path
this now surfaces as `status=transport_error` (never a target verdict like `404`/`patched`/
`gated`/`not-present`) and auto-retries once on a **host-pinned IP** (`--resolve <host>:443:<IP>`).
Never record "404 / patched / gated / not-present" from a transport failure: re-run host-pinned
(or via the host route — `--runtime host` / `VIGIL_RECON_RUNTIME=host`) and let a *real* HTTP
response — or a clean, fast connection-refused — be the verdict. See
`agent/references/runtime-guides/docker-desktop-network-hazards.md`.

**(d) A WAF / bot-challenge interstitial is PENDING — never a verdict in either direction —
until a browser proves the origin.** When the bytes are the edge's challenge page rather than
the origin app's — Imperva (`reese84` cookie / *"Pardon Our Interruption"*), Akamai (`_abck`
cookie / `AkamaiGHost` / *"Access Denied"*), or Cloudflare (`cf-chl` / *"Just a moment"*) —
the response belongs to the WAF, not the application behind it. A `200`/`403` (or any
status/body) that `curl`/`httpx` returns from a WAF-fronted host is a **challenge artifact**:
it proves neither presence nor absence of a finding and decides nothing about the surface.
Re-render with `vigil assess kali browser <url>` — headless Chromium executes the challenge JS
and returns the **real origin** status + DOM; only that rendered origin response is a verdict.
The kali path surfaces this as `status=waf_challenge` precisely so it cannot close a surface as
`404`/`patched`/`gated`/`not-present`; do not override it with the challenge's status code.

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
disposition on a protected op, re-open the raw `get-command-run` rows behind that signal
(`vigil assess get-command-run <id>`, `vigil assess list-command-runs --tool-bin <bin> --show-matches`)
and re-derive the disposition from the actual request/response bytes. A `403` recorded by a
prior pass may have been a downstream validation error mistaken for an auth gate (b); a "patched"
may have been an `http=000` transport error (c); a "clean" may have been a status-only probe that
never read the body (a); a "gated"/"not-present" may have been a WAF challenge page never
re-rendered in a browser (d).

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

## A URL can be a whole application — go deep on app units

A single host often carries several distinct applications under different
path-prefixes — `host/giving` (a donations app), `host/admin` (tenant
admin), `host/api/v2` (a REST surface). Each is its own **app unit**
`(host, port-class, path-prefix)` with its own auth model and attack
surface. A shallow pass over many hosts that glances at each prefix hides
that an entire application went untested — exactly the failure this harness
exists to catch.

The backend scores each app unit (structure × risk − suppressors) and marks
the ones worth a dedicated deep campaign as `deep_required`. The score is an
**advisory** signal, not a wall — it tells you where to dig, it does not
block you. Inspect it with `vigil assess app-unit list`; re-run discovery
after more collection with `vigil assess app-unit score`. When you know a
unit deserves (or does not deserve) a deep pass regardless of the score, set
a durable manual override with `vigil assess app-unit mark-deep <id>
--reason ...` or `vigil assess app-unit clear-deep <id> --reason ...` — a
manual mark always wins over the scorer. Treat a `deep_required` unit as a
whole application: a dedicated dispatch across every applicable vuln class
and auth context, not a single surface glance.
