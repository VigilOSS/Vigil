# Hunting Rules

These rules are always active across the engagement. They are intentionally compact, but they are
strict: breaking them wastes time and lowers finding quality.

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

## 4. Kill weak leads fast

Do not spend long stretches polishing low-confidence signals. Either validate quickly, chain them, or drop them.

Kill signals include:

- Theory without a real request, response, or replayable action
- More than two fragile preconditions stacked together
- "Might be chainable" used instead of a proved chain
- Static or generic surface with no meaningful attack paths after a short pass

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

## 18. Developer psychology heuristics

Use these to generate testable hypotheses about where developers introduced flaws:

- **Feature-copy pattern**: Feature A has auth checks. Newly added Feature B was likely copied from A without the auth middleware — test B's auth boundary first.
- **Flow-complexity pattern**: Multi-step workflows (checkout + coupon + refund + credits) have edge cases at every step boundary. Test step-skipping and out-of-order execution.
- **API version drift**: `/api/v2/user` exists — does `/api/v1/user` still work with weaker or no auth? Old versions are rarely decommissioned properly.
- **Naming anomaly signal**: If the API uses `userId` everywhere but one endpoint uses `user_id`, that endpoint was built by a different developer or team — it likely has different (weaker) security assumptions.
- **Error response divergence**: Same 403 status code but different JSON structure on two endpoints = different backend systems with different trust boundaries. Test each independently.
- **New feature window**: Features launched in the last 30 days have the lowest security maturity. Check changelogs and release notes for recent additions.
