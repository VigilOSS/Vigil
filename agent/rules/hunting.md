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

## 3. Precondition equivalence check

Before rating severity, identify the precondition required to trigger the vulnerability. If that precondition already grants the attacker equivalent or greater access than the vulnerability itself provides, the finding is defense-in-depth (Low), not an independent exploit. Score on incremental impact over the precondition, not total impact of the chain.

Examples:
- **Redundant**: "Unvalidated redirect captures auth verifier" — but triggering the redirect requires breaking the same TLS connection that already exposes the auth verifier. Incremental impact: zero.
- **Not redundant**: "App disables TLS validation process-wide" — no precondition beyond network proximity. The app removes its own protection. Incremental impact: full credential capture from any shared network.
- **Chain test**: If exploiting B requires condition A, ask: "What can the attacker already do with just A?" If the answer is "everything B provides," then B is defense-in-depth.

## 4. Kill weak leads fast — and push harder on strong ones

Do not spend long stretches polishing low-confidence signals. Either validate quickly, chain them, or drop them. The inverse matters equally: when a signal is live, do not abandon it at the first ambiguous response — dig in until you have either the attacker outcome or a concrete reason the path fails.

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

## 5. Five-minute rule for dead surface

If a surface yields no meaningful routes, no privileged features, no object references, and no useful source intelligence after a short focused pass, rotate instead of grinding.

## 6. Evidence beats volume

Prefer a few decisive requests and exact proofs over broad noisy testing.

## 7. Use skills before improvising

Load the most relevant skill first. Only improvise when the existing skill/reference set is genuinely insufficient.

## 8. Automation for recon, judgment for validation

Use automation to enumerate and classify. Use deliberate human-guided validation for auth, logic, chaining, and impact.

## 9. The sibling rule

When one route, method, or controller path is vulnerable, inspect its siblings before moving on.

## 10. Think in chains

Use bug A as a signal for B and C nearby, but time-box chain exploration and stop when the cluster is dry.

## 11. Impact first

Prioritize surfaces where broken auth, object reference drift, privileged writes, or trust-boundary confusion would matter.

## 12. Depth over breadth

One well-understood target or feature is worth more than shallow passes over many. Stay long enough to understand what the application actually values.

## 13. Validate before writing

Do not start report drafting before the lead is validated, reproducible, and worth a human reader's time.

## 14. Credentials require proof

Leaked tokens, keys, or config only matter when you show what they actually grant.

## 15. Rotate when progress stalls

If repeated attempts produce no new information, switch endpoint, method, surface, or hypothesis instead of grinding.

## 16. Time-box caps

Three tiers prevent rabbit-holing:

- **5 minutes** — dead surface with no routes, no features, no object references (rule 5)
- **20 minutes** — a single endpoint producing no new signals. Rotate to a different endpoint, vuln class, or subdomain.
- **45 minutes** — absolute cap on a single parameter or feature before forced rotation. If 45 minutes of focused testing yields nothing, the lead is dry.

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
  `aith assess fetch ...` query, a `list-skills` call, a contract render).
  Anything that walks a target, parses output, or iterates over a work-buffer
  cluster is specialist work.
- **One specialist, one objective, one skill set.** Each dispatch names the
  role, the dispatch mode, and the explicit skill list (`--skills` on
  `aith assess agent start`). Bundling multiple objectives into one
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

Before any report-writer dispatch, query `aith assess list-findings` and verify
each finding's `severity` matches its `details.cvss_score` band:

- `high` requires `cvss_score >= 7.0`
- `medium` requires `4.0 <= cvss_score <= 6.9`
- `low` requires `cvss_score < 4.0`

Fix mismatches via `aith assess update-finding --inline '{"details":
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
report.md verbatim. The `aith assess list-findings --json | jq -r .[].slug`
loop in `agent/skills/report-generation/SKILL.md` (Review-and-Fix QA Mode)
provides the executable recipe; this rule is the reason to run it.

## 22. Smallest probe that answers the question

Prefer the smallest probe that gets you the answer. If you already know what
to test — a discovered path from `robots.txt` / sitemap / JS, a known
parameter pulled from source analysis, a specific endpoint — `curl` that
thing directly via `aith assess kali exec -- curl ...`. If you have NO
knowledge and need to discover from scratch, AND brute-force is in scope per
the engagement VDP, then use the appropriate Kali verb (`ffuf` for paths,
`arjun` for params, `puredns` for DNS, `sqlmap` for SQLi, `dalfox` for XSS,
`nuclei` for template-based CVE/misconfig, `httpx`/`whatweb`/`wafw00f` for
fingerprinting).

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
