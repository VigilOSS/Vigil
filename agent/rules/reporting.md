# Reporting Rules

These rules keep reports human-first, evidence-backed, and severity-disciplined.

## 1. State proven attacker outcomes directly

State what the attacker can do — hedge language like "could potentially" or "may allow" signals that the finding has not been validated to the point of actionable certainty. If certainty is missing, validate further before reporting.

Banned phrases:

- `could potentially`
- `may allow`
- `might be possible`
- `could lead to`
- `could be chained with ...`

Preferred pattern:

- `An attacker can [exact action] by [exact method].`

## 2. Proof is mandatory

Show exact impact, not just status codes or tool noise. The report should make the failure obvious to a reviewer.

## 3. Severity follows proven impact

Do not let recon hints, CVEs, or intuition inflate severity beyond what the evidence proves.

If you use CVSS, make it match the proved attack path, not the imagined best case for the attacker.

For resource-limit and protocol-wrapper issues, prove the limit is a security
boundary before using High/Critical language. A named cap being bypassed is not
enough when the cap only protects a local buffer, spool, or compatibility path.
Compare equivalent default transports and protocol modes. If the same logical input
can already be sent through another supported path and the downstream component does
only bounded, linear work, report it as Medium/hardening or documentation rather
than a High vulnerability.

High/Critical requires a proved second-order outcome: service-level denial of
service, unbounded retained memory/disk, superlinear CPU, output amplification,
crash, memory corruption, privilege-boundary crossing, or another concrete impact
that ordinary protocol access cannot already produce.

## 4. Verify the data is actually non-public

Before calling something exposure or disclosure, confirm the same information is not already intentionally public.

## 5. Use distinct identities when ownership matters

For cross-user access issues, show attacker context and victim context clearly enough that the unauthorized boundary crossing is undeniable.

## 6. Lead with attacker outcome

Sentence one should explain what the attacker gains, not what category label the bug belongs to.

## 7. Keep it concise and human-readable

A strong report should be fast to scan without losing exact technical proof.

## 8. Title quality matters

Prefer: `[Bug Class] in [exact endpoint or feature] allows [attacker role] to [impact] [scope]`

Avoid vague titles like:

- `IDOR vulnerability found`
- `Security issue in API`
- `XSS in user input`

## 9. Use durable finding state as the source

Do not invent details that are not present in recorded findings, backend state, or confirmed evidence references.

## 10. Section length limits

Reports are for humans who scan fast. Enforce these ceilings per finding:

| Section | Maximum |
|---------|---------|
| Description | 2-4 sentences |
| Steps to Reproduce | Numbered steps, one action per step, no narrative between steps |
| Evidence | One request/response pair per proof point, response truncated to relevant 5-15 lines |
| Impact | 1-2 sentences |
| Remediation | 1-2 sentences |

If you need more space, the finding is probably two findings. Split it.

The executive summary is one page maximum. If it does not fit on one page, cut words.

## 11. Expanded banned language

In addition to Rule 1 hedge phrases, these patterns are banned:

**Filler transitions:**
- `Furthermore` · `Additionally` · `Moreover`
- `It is worth noting that` · `It should be noted that`
- `As demonstrated above` · `As mentioned earlier`
- `During the course of our assessment` · `Upon further investigation`
- `In conclusion` · `To summarize` . `with a one-minute proof-of-concept`

Preferred alternatives:
- Start with the proof or outcome sentence immediately
- Use a short transition only when it adds meaning: `The same request also`, `The response then`, `A second request confirms`

**Redundant structure:**
- Restating the finding title in the first sentence of the description
- Opening with `This finding describes...` or `This vulnerability allows...` — the finding *is* the description
- Explaining what the vulnerability class is to the reader — the audience knows XSS, SQLi, IDOR, SSRF, and other standard classes; definitions waste space and patronize the reader
- Closing paragraphs that restate what was just said

Preferred alternatives:
- Let the first sentence add the new proof, victim scope, or attacker outcome that the title does not carry
- Move background that materially matters into `Vulnerability Details`, not the opener

**Passive voice that hides the actor:**
- `It was discovered that...` → name the endpoint and what it does
- `The application was found to be vulnerable to...` → state what is vulnerable and how
- `Testing revealed that...` → state the fact directly

Preferred pattern: subject-verb-object. The endpoint does X. The attacker sends Y. The response contains Z.

**Baseline-conduct disclaimers (external submissions):**
- Scope assertions enumerating what was *not* touched
- Request-volume or rate pledges (`10 calls at ~3 req/s`, `We limited testing to...`)
- Future-conduct pledges (`Researcher will not contact customers`, `will not be used to...`)
- "I respected the program rules" framing

External submissions are about the finding, not the researcher. Program rules already require in-scope, rate-limited, non-impersonating testing — restating compliance implies you might have violated it. Write as if professional conduct is assumed.

## 12. Active voice by default

Write in active voice. The subject acts.

- Bad: `It was observed that session tokens are returned in the response body.`
- Good: `The /api/login endpoint returns session tokens in the response body.`
- Bad: `The parameter was found to be injectable.`
- Good: ``The `search` parameter on /api/products accepts unescaped SQL syntax.``

Passive voice is acceptable only when the actor is genuinely unknown or irrelevant.

## 13. Evidence formatting standard

Evidence must show the exact proof, not raw tool dumps.

**Request block:** Full HTTP request in a fenced code block. Annotate injected payloads or manipulated parameters with inline comments if the critical part is not obvious.

**Response block:** Truncate to the 5-15 lines that prove the finding. Bold or annotate the specific data that constitutes the proof — the leaked PII field, the unauthorized record, the injected output. Never paste a full response when 10 lines suffice.

**Highlighting:** Use `**bold**` or `← proof` annotations to draw the eye to the critical line in evidence blocks. A reviewer should find the proof in under 3 seconds.

**Raw tool output is not evidence.** Do not paste Nmap scans, Nuclei JSON, or sqlmap logs as evidence. Extract the specific proof from tool output and present it as a request/response pair or a targeted excerpt.

## 14. Remediation must be specific

Generic advice is not remediation.

Banned remediation patterns:
- `Implement proper input validation`
- `Use appropriate access controls`
- `Follow security best practices`
- `Sanitize user input`
- `Implement proper authentication`

Remediation must name the technology, the control, and the fix:
- `Use parameterized queries via PDO::prepare() for all SQL queries in the search controller.`
- `Add server-side ownership check on /api/orders/{id}: verify order.user_id matches the authenticated session before returning data.`
- `Set HttpOnly and Secure flags on the PHPSESSID cookie in php.ini or via session_set_cookie_params().`

If you do not know the server-side technology, state the control that failed and the class of fix required, not a platitude.

## 15. Keep every sentence load-bearing

Every sentence in a finding must contribute new information. If removing a sentence does not reduce the reader's understanding, remove it.

Common padding to avoid:
- Background paragraphs explaining the technology stack before getting to the bug
- "This is significant because..." followed by restating the impact that was already in the impact section
- Listing theoretical secondary impacts that were not proved
- Adding "defense in depth" remediation items beyond the primary fix

## 16. No severity labels in titles

Finding titles communicate the bug class, location, attacker role, and impact. Severity belongs in the CVSS metadata line, not the title.

Banned patterns: `[CRITICAL] Unauthenticated RCE in /api/upload` · `IDOR in /api/orders/{id} [HIGH]`

Correct pattern: the title carries no severity badge. The CVSS line carries score and vector.

## 17. No internal identifiers or tooling references in external deliverables

External-facing reports must not include:
- Internal backend tracking IDs (slugs such as `VA-003`, `EX-032`, `RE-010`) in any field
- References to internal tooling, scan file paths, or orchestrator state
- Operational status annotations: "Reported to X on date", "Duplicative", "Already sent"

These are internal-only metadata with no meaning to the client. Remove Slug/Slugs fields from all finding sections before external delivery.

## 18. Consolidate findings to root cause

When two findings share the same vulnerable component or configuration and one is a direct consequence of the other, write one finding covering the root cause and all demonstrated impacts.

Separate findings for the same root cause inflate the finding count, split remediation, and fragment the attack story. Apply the same judgment a BugCrowd/HackerOne triager would: one root cause, one submission.

Common patterns that require consolidation:
- Credential exposure as a direct consequence of an auth bypass on the same system
- Multiple unauthenticated routes on the same API when the root cause is a single missing-auth control

## 19. No internal-only sections in external reports

The following are internal-only and must not appear in client-facing deliverables:

- **Coverage Summary** — operational metrics (targets, services, probe counts) are engagement-internal and have no meaning to the client
- **Finding Cross-Reference** — maps report IDs to backend slugs; internal traceability only, exclude from external reports
- **Tested by / tester attribution** — not required in client deliverables
