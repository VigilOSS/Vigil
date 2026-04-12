# Hunting Rules

These rules are always active across the engagement. They are intentionally compact, but they are
strict: breaking them wastes time and lowers finding quality.

## 1. Read scope before target work

Confirm the exact in-scope hosts, scope mode, exploit policy, and auth state before making target-facing decisions.

## 2. No theoretical findings

If the answer to "can an attacker do this right now with real harm?" is no, it is not a finding yet.

## 3. Kill weak leads fast

Do not spend long stretches polishing low-confidence signals. Either validate quickly, chain them, or drop them.

Kill signals include:

- Theory without a real request, response, or replayable action
- More than two fragile preconditions stacked together
- "Might be chainable" used instead of a proved chain
- Static or generic surface with no meaningful attack paths after a short pass

## 4. Five-minute rule for dead surface

If a surface yields no meaningful routes, no privileged features, no object references, and no useful source intelligence after a short focused pass, rotate instead of grinding.

## 5. Evidence beats volume

Prefer a few decisive requests and exact proofs over broad noisy testing.

## 6. Use skills before improvising

Load the most relevant skill first. Only improvise when the existing skill/reference set is genuinely insufficient.

## 7. Automation for recon, judgment for validation

Use automation to enumerate and classify. Use deliberate human-guided validation for auth, logic, chaining, and impact.

## 8. The sibling rule

When one route, method, or controller path is vulnerable, inspect its siblings before moving on.

## 9. Think in chains

Use bug A as a signal for B and C nearby, but time-box chain exploration and stop when the cluster is dry.

## 10. Impact first

Prioritize surfaces where broken auth, object reference drift, privileged writes, or trust-boundary confusion would matter.

## 11. Depth over breadth

One well-understood target or feature is worth more than shallow passes over many. Stay long enough to understand what the application actually values.

## 12. Validate before writing

Do not start report drafting before the lead is validated, reproducible, and worth a human reader's time.

## 13. Credentials require proof

Leaked tokens, keys, or config only matter when you show what they actually grant.

## 14. Rotate when progress stalls

If repeated attempts produce no new information, switch endpoint, method, surface, or hypothesis instead of grinding.

## 15. Time-box caps

Three tiers prevent rabbit-holing:

- **5 minutes** — dead surface with no routes, no features, no object references (rule 4)
- **20 minutes** — a single endpoint producing no new signals. Rotate to a different endpoint, vuln class, or subdomain.
- **45 minutes** — absolute cap on a single parameter or feature before forced rotation. If 45 minutes of focused testing yields nothing, the lead is dry.

## 16. Stuck-state recovery

When progress stalls, use this table to pick a concrete next action instead of grinding:

| I'm stuck because... | Go to |
|---|---|
| All endpoints return 403/401 | Rotate to a different subdomain or look for unauthenticated API versions (`/api/v1/`, `/api/public/`) |
| I found a bug but can't escalate impact | Load the matching vuln-class skill and check the A->B chain table in `exploit-developer.md` |
| Recon is huge but I don't know where to start testing | Rank by signal density: API endpoints with object IDs > authenticated-only routes > static pages |
| Every parameter seems filtered | Try encoding bypass (double-URL, unicode, null bytes), then switch to a different vuln class entirely |
| I keep finding duplicates of the same bug pattern | Apply the sibling rule (rule 8) to exhaust the cluster, then rotate to a different feature area |
| The app is simple with few endpoints | Go deeper: test business logic, race conditions, multi-step workflow abuse, parameter pollution |
| I confirmed a low-severity bug but can't chain it | Check if it enables a higher-impact primitive (open redirect -> OAuth theft, SSRF -> metadata, XSS -> admin panel) |
| Tools are returning nothing useful | Stop automation, test manually. Read the JS source, map the API by hand, test one request at a time |

## 17. Developer psychology heuristics

Use these to generate testable hypotheses about where developers introduced flaws:

- **Feature-copy pattern**: Feature A has auth checks. Newly added Feature B was likely copied from A without the auth middleware — test B's auth boundary first.
- **Flow-complexity pattern**: Multi-step workflows (checkout + coupon + refund + credits) have edge cases at every step boundary. Test step-skipping and out-of-order execution.
- **API version drift**: `/api/v2/user` exists — does `/api/v1/user` still work with weaker or no auth? Old versions are rarely decommissioned properly.
- **Naming anomaly signal**: If the API uses `userId` everywhere but one endpoint uses `user_id`, that endpoint was built by a different developer or team — it likely has different (weaker) security assumptions.
- **Error response divergence**: Same 403 status code but different JSON structure on two endpoints = different backend systems with different trust boundaries. Test each independently.
- **New feature window**: Features launched in the last 30 days have the lowest security maturity. Check changelogs and release notes for recent additions.
