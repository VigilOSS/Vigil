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
