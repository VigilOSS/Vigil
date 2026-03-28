# Threat Hunt — Depth & Escalation Reference

This reference defines the investigative mindset, escalation techniques, and user coaching patterns for driving a threat hunt engagement toward deeper, higher-severity findings. Read this reference when the engagement reaches Phase 5+ or when the user asks to dig deeper, raise CVE scores, find more findings, or prove exploitability.

---

## Depth Mindset

These principles reflect how experienced red teamers think. They apply continuously throughout an engagement.

### Never Stop at Surface Findings

When a vulnerability is discovered, the immediate question is: "Can I raise this severity?" A Medium finding might chain into a Critical. An info-disclosure finding might enable auth bypass. Spend at least one follow-up test attempting escalation before moving on to the next finding.

### Auth-Required Findings Are Still Real

Engagements may be unauthenticated, authenticated, or both — the user decides during intake. Regardless of the current scan mode:

**During unauthenticated scans**: You will encounter endpoints and behaviors that require authentication to fully exploit. Do NOT ignore or dismiss these. An authenticated SSRF, SSTI, IDOR, or privilege escalation is still a real vulnerability — it just means the attacker needs a valid session first, which is often trivial (phishing, credential stuffing, insider threat, or chaining with another finding that leaks tokens). Mark these as `BLOCKED (requires auth)` and document:
- What credentials or session tokens are needed
- What the impact would be with access
- The specific endpoints and test cases you'd run with a session
- Whether the finding is exploitable even after proper auth is added (e.g., an IDOR behind a login is still an IDOR)

**During authenticated scans**: Test everything the unauthenticated scan found, plus the full authenticated attack surface. Re-test `BLOCKED` findings from prior unauthenticated runs.

**Key principle**: The scan mode defines your *starting position*, not your *scope of findings*. An unauthenticated scan that only reports unauthenticated findings is incomplete. The user may provide credentials mid-engagement, turning every blocked finding into an active test case.

### Prove It or It Didn't Happen

Every finding needs tangible proof a stakeholder can act on. Not "this endpoint appears vulnerable" — show the exact curl command, the response body, the data exposed. Where possible, provide something the user can paste into a browser or demo to leadership.

The standard: **"Would a VP reading this say 'holy shit' or 'so what?'"**

### Completeness Self-Audit

At the end of each phase, before marking it complete, re-read state.md and assets.json and ask:
- Did I miss anything?
- Are there findings I mentioned but never verified?
- Are there endpoints I discovered but never tested?
- Are there raw output files with interesting results I didn't follow up on?

Document gaps explicitly. Unverified findings are liabilities — they may be the most critical issues in the engagement.

### Think Laterally About Impact

For every finding, ask:
- What else can I reach from here?
- Can I pivot to other internal services?
- Can I combine this with another finding to escalate severity?
- What's the worst-case scenario if an attacker chains this with something else?
- What would a motivated attacker do next?

---

## Severity Escalation Protocol

Use this protocol after completing attack chains (Phase 5), whenever the user asks to "dig deeper" or "raise the CVE", or whenever findings plateau at Medium/Low severity and Critical/High paths likely exist.

### Step 1: Triage for Escalation Potential

Review all current findings and score each on escalation potential:

| Finding | Current Severity | Escalation Path | Target Severity | Effort |
|---------|-----------------|-----------------|-----------------|--------|
| #1 | Medium | Chain with #3 for auth bypass | High | Low |
| #2 | Low | Combined with SSRF reaches internal services | Critical | Medium |
| #4 | Info | Version has known CVEs in NVD | High | Low |

Pick the **top 3 by impact-to-effort ratio** and investigate them deeply.

### Step 2: Escalation Techniques by Finding Type

**Information Disclosure:**
- Can disclosed versions, paths, or internal IPs enable a targeted exploit?
- Does the version have known CVEs? Check with `searchsploit` or NVD lookup
- Can internal paths/IPs be reached via SSRF or proxy?
- Does technology disclosure narrow down framework-specific attack vectors?

**Missing Authentication:**
- What's the worst data reachable? Find the highest-PII endpoint
- Can all records be enumerated (sequential IDs, pagination abuse)?
- Can write operations be performed (create, update, delete)?
- What does the API spec/swagger reveal about adjacent unprotected endpoints?
- Can unauthenticated access be combined with other findings (format injection, verb tampering)?

**XSS / Injection:**
- Can reflected XSS be escalated to stored?
- Can session tokens or credentials be stolen via the injection?
- Can it chain with CSRF for account takeover?
- Can admin functionality be reached through the injection point?
- For SSTI: can you achieve RCE or file read?

**Header / Configuration Weaknesses:**
- Can missing HSTS + weak cookie flags enable session hijacking via MITM?
- Can missing CSP enable exploitation of discovered XSS vectors?
- Can CORS misconfiguration + credential reflection enable cross-origin data theft?
- Can permissive CORS + API endpoints enable full account takeover from attacker domain?

**Auth Bypass:**
- What's the full blast radius? Test ALL endpoints, not just the first one found
- Can admin/config endpoints be reached?
- Can other users' data be accessed (horizontal privilege escalation)?
- Can write operations be performed (vertical privilege escalation)?
- What is the total count of affected endpoints — scope matters for severity

**Rate Limiting Gaps:**
- Can the gap enable credential brute-force on login endpoints?
- Can it enable MFA code brute-force?
- Can it enable data scraping at scale on IDOR endpoints?
- Combine with user enumeration for a full credential stuffing chain

### Step 3: Document Escalation Results

For each attempt, document in `<WORKDIR>/escalation-notes.md`:

```markdown
## Escalation Attempt: Finding #X -> Target Severity
- **Hypothesis**: [specific, testable claim]
- **Technique**: [what was tested and how]
- **Result**: ESCALATED to [severity] / PARTIAL (achieved [X]) / NOT ESCALATABLE
- **Evidence**: [exact command + response snippet]
- **New finding created**: Yes/No (Finding #Y if yes)
```

### Step 4: Iterate in Rounds of 3

After each round of 3 escalation attempts, summarize results and present options before continuing. This keeps the user informed and allows them to redirect focus. Typically 2-4 rounds cover the full escalation surface.

---

## Engagement Coaching

At key moments during an engagement, guide the user toward interactions that improve depth and coverage. Present specific, actionable options rather than waiting for the user to know what to ask.

### After Initial Findings (End of Phase 3)

Present findings AND offer paths to go deeper:

```
I found [N] findings so far. Before moving to attack chains, here are ways to go deeper:

1. **Escalation targets**: [2-3 findings] could chain into higher severity.
   Should I try to raise their CVE score?

2. **Proof gaps**: [findings] are likely real but not yet proven exploitable.
   Want browser-verifiable evidence for these?

3. **Auth boundary**: [N findings] are blocked — require authentication.
   If you provide credentials, I could test:
   - [specific endpoint] for [specific vuln type]
   - [specific endpoint] for [specific vuln type]

4. **Source code**: With codebase access, I can cross-reference findings
   and likely find [types of additional vulns].

Pick any combination, or say "continue" to proceed to attack chains.
```

### After Attack Chains (End of Phase 5)

Present chain results AND offer next moves:

```
Attack chain results: [N confirmed, N partial, N not exploitable]

To go deeper:
1. **More chains**: [N] untested combinations remain. Try the next 3?
2. **Scope expansion**: [services/endpoints] not fully tested yet.
3. **Credential escalation**: With auth, findings [X, Y, Z] could reach Critical.
4. **Purple team**: Source code would confirm [finding] and reveal adjacent vulns.
5. **Different angle**: Shift to [business logic / race conditions / deserialization / etc.]
```

### When the User Says "Continue" or "What's Next"

Present choices with context rather than just moving to the next phase:

```
Current status: [N Critical, N High, N Medium, N Low, N Info]

I recommend:
- **Higher severity**: Dig into [specific finding] — provable escalation via [technique]
- **Breadth**: [areas not yet tested]
- **Stakeholder proof**: Browser-verifiable evidence for the top [N] findings

What matters most right now?
```

### Before Declaring the Engagement Complete

Run a completeness audit and share it transparently:

```
Completeness audit before wrap-up:

- Verified findings: [N] (proof captured)
- Unverified findings: [N] (mentioned but not proven — these are risk)
- Auth-blocked findings: [N] (need credentials to test)
- Untested areas: [list endpoints/services discovered but not assessed]
- Dismissed findings: [N] (ruled out — reason for each)

The [N] unverified and [N] auth-blocked findings could include Critical issues.
Want me to verify them, list what credentials would unlock, or generate the report as-is?
```

### When the User Redirects Scope

When told to ignore certain findings or shift focus, acknowledge the redirect, preserve existing work in the report, and immediately suggest the most promising alternative paths:

```
Parking [finding/area] — marked as "known, fix in progress" in report.

Redirecting to:
1. [New focus area] — potential for [impact]
2. [New focus area] — potential for [impact]
3. [New focus area] — potential for [impact]

These are the strongest paths to new Critical/High findings. Proceeding.
```

---

## User Prompting Guide

These are high-value prompts users can give at any point during an engagement to drive better results. Share relevant ones with the user when the engagement stalls or when they ask what they can do to help.

### Severity Escalation
- "Dig deeper into finding #X — can you raise the CVE score?"
- "How can this [XSS/IDOR/etc.] be made more dangerous?"
- "Pick 3 findings and try to escalate each to Critical"
- "What would a real attacker do with this finding?"

### Attack Chaining
- "Choose 3 attack chains and go deep on each"
- "Can this finding be combined with others to achieve higher impact?"
- "Determine if this could reach internal services or other APIs"
- "What's the worst-case chain from what you've found?"

### Proving Impact
- "For each finding, prove it's real — give me something I can show in a browser"
- "Test several different ways for each finding and provide proof"
- "Show me the highest-PII endpoint that's exposed"
- "Give me the exact curl command that demonstrates the issue"

### Completeness
- "Did you miss anything? Review all raw output files"
- "Are there findings you mentioned but never verified?"
- "What endpoints did you discover but never test?"
- "Is there any more exploitation or discovery left?"

### Scope Expansion
- "Ignore [known issue] — what OTHER attack vectors exist?"
- "Here are credentials: [creds] — find more vulns with authenticated access"
- "Here's the source code at [path] — cross-reference your findings and find more"
- "What could you find if you had [access/credentials/source code]?"

### Keeping Momentum
- "Don't rule out auth-required findings — document what you'd need and what the impact would be"
- "Continue with the next round of attack chains"
- "Is there not any more exploitation or discovery left?"
- "Review the report — is anything duplicated or missing proof?"
