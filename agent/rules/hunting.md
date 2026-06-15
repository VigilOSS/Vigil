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

The operator's value is *not* doing the testing — it is choosing the right
specialist, framing the dispatch tightly, and judging the returned evidence.
When the operator does the hunting itself, two things break: the operator's
context window fills with low-level transcripts that should have stayed in a
specialist subagent, and the audit trail loses the per-role provenance that
report-writer and later operators rely on.

- **Default to dispatch.** When a task fits a named role (`recon-specialist`,
  `vulnerability-analyst`, `exploit-developer`, `fuzzer`, `osint-analyst`,
  `surface-collector`, `source-analyzer`, `report-writer`, or any
  `code-*` role), launch that specialist instead of running the underlying
  tools yourself. Specialists carry the role prompt, the matching skill
  context, and the handoff schema the operator does not.
- **Inline only for genuinely operator-scoped work.** A handful of actions
  belong on the operator: scope and authorization decisions, dispatch
  authoring, recording specialist handoffs, reviewing evidence, and the
  occasional one-shot lookup that informs the next dispatch (a single
  `vigil assess fetch ...` query, a `list-skills` call, a contract render).
  Anything that walks a target, parses output, or iterates over a work-buffer
  cluster is specialist work.
- **One specialist, one objective, one skill set.** Each dispatch names the
  role, the dispatch mode, and the explicit skill list (`--skills` on
  `vigil assess agent start`). Bundling multiple objectives into one
  dispatch defeats the role boundary and produces handoffs that report-writer
  cannot map back to a coherent finding line.
- **When in doubt, dispatch.** If the operator is about to run a Kali tool,
  parse its output, and decide what to do next, that loop belongs in a
  specialist. The cost of an extra dispatch is small; the cost of a polluted
  operator context is large because it reduces the operator's ability to
  judge the next dispatch.

## 19. Developer psychology heuristics

Use these to generate testable hypotheses about where developers introduced flaws:

- **Feature-copy pattern**: Feature A has auth checks. Newly added Feature B was likely copied from A without the auth middleware — test B's auth boundary first.
- **Flow-complexity pattern**: Multi-step workflows (checkout + coupon + refund + credits) have edge cases at every step boundary. Test step-skipping and out-of-order execution.
- **API version drift**: `/api/v2/user` exists — does `/api/v1/user` still work with weaker or no auth? Old versions are rarely decommissioned properly.
- **Naming anomaly signal**: If the API uses `userId` everywhere but one endpoint uses `user_id`, that endpoint was built by a different developer or team — it likely has different (weaker) security assumptions.
- **Error response divergence**: Same 403 status code but different JSON structure on two endpoints = different backend systems with different trust boundaries. Test each independently.
- **New feature window**: Features launched in the last 30 days have the lowest security maturity. Check changelogs and release notes for recent additions.

## 20. Severity-CVSS alignment audit before report

Before any report-writer dispatch, query `vigil assess list-findings` and verify
each finding's `severity` matches its `details.cvss_score` band:

- `high` requires `cvss_score >= 7.0`
- `medium` requires `4.0 <= cvss_score <= 6.9`
- `low` requires `cvss_score < 4.0`

Fix mismatches via `vigil assess update-finding --inline '{"details":
{"cvss_score": <n>, "cvss_vector": "..."}}'`. The JSON field is `details`,
not `details_json`. A finding whose severity contradicts its CVSS makes the
entire report look unverified to the triager, and mismatches are the single
most common cleanup-time defect in this codebase. Run the audit before
calling report-writer so the dispatch sees coherent state.

## 21. Stale-text scrub before publishing

Read each active finding's `summary` and `details` text fields and strip
phrases that contradict the current state:

- "severity adjusted from X to Y" when the severity is no longer Y
- "originally rated as Z" when the rating has shifted twice since
- "merged from W" when W has since been split off
- "downgraded to medium" / "upgraded to high" / "previously low" against
  the current severity field

Stale narrative is invisible to backend status fields and ends up in
report.md verbatim. The `vigil assess list-findings --json | jq -r .[].slug`
loop in `agent/skills/report-generation/SKILL.md` (Review-and-Fix QA Mode)
provides the executable recipe; this rule is the reason to run it.

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

**Re-derive un-pushed signals from RAW evidence.** A prior agent's stopping point — a
"tested / clean / disproven" note, a `notes/PHASE-3-REMAINING-WORK.md` line, an inherited
disposition — is a **view to re-verify, not ground truth**. Before accepting any negative
disposition on a protected op, re-open the raw `get-command-run` rows behind that signal
(`vigil assess get-command-run <id>`, `vigil assess list-command-runs --tool-bin <bin> --show-matches`)
and re-derive the disposition from the actual request/response bytes. A `403` recorded by a
prior pass may have been a downstream validation error mistaken for an auth gate (b); a "patched"
may have been an `http=000` transport error (c); a "clean" may have been a status-only probe that
never read the body (a).

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
