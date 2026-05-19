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

### Precondition analysis

Before assigning severity, answer: **what does the attacker need to already have?** Every precondition
that is not freely available to an anonymous internet attacker reduces severity. Stack enough
preconditions and even a technically impressive bug becomes low-impact.

**Defense-in-depth:** If exploiting the finding requires already possessing the secret or credential it
bypasses, the finding is defense-in-depth — it adds a layer but its failure alone does not grant access.
An API-key bypass that requires knowing the API key is not critical; the key is the auth mechanism, and
obtaining it is a separate vulnerability. Rate the bypass relative to how hard the precondition is to
satisfy independently.

**Preconditions that reduce severity:**
- Requires a valid authenticated session (not anonymous)
- Requires knowing a non-iterable identifier (UUID, GUID, random token) — the attacker cannot enumerate, they must already have it from somewhere
- Requires a second vulnerability to supply the input (chain-dependent primitive)
- Requires access to source code, CI config, or internal systems to extract a secret
- Requires attacker-controlled infrastructure (subdomain, DNS, upstream service)
- Requires specific file upload + specific serving conditions to trigger
- Reproduces only in dev/staging, not production

**Preconditions that do NOT reduce severity:**
- Requires an iterable integer ID (1, 2, 3...) — the attacker can enumerate trivially
- Requires only a free/low-privilege account on a self-registration platform
- Requires sending a single crafted HTTP request with no prior knowledge

**Identifier complexity matters for IDOR:** An IDOR on `/api/records/{uuid}` where the UUID is not leaked anywhere is materially less exploitable than `/api/records/{id}` where id is a sequential integer. The former requires the attacker to already know the target; the latter lets them sweep every record. Rate accordingly.

**Code-only without runtime proof:** A vulnerability pattern confirmed in source code but never demonstrated against a running instance is less certain than one with a captured request/response. Code paths may be dead, gated by middleware not visible in the snippet, or patched at deploy time. Drop severity at least one tier from what a dynamically-proved equivalent would earn.

**Missing headers, stack traces, error messages, schema exposure, and configuration observations** are informational unless they directly enable a higher-impact attack. Do not inflate these to medium or above on the theory that they "could help an attacker" — that is speculative chaining, not proved impact.

**Timing side-channels** are real but low-impact in practice. Rate as low unless the timing oracle directly leaks a high-value secret (e.g., full API key byte-by-byte extraction proved in evidence).

**DoS severity depends on access:** Unauthenticated DoS against a production endpoint with no rate limiting is higher than auth-required DoS that crashes a background worker.

For resource-limit and protocol-wrapper issues, prove the limit is a security boundary before using
High/Critical language. A named cap being bypassed is not enough when the cap only protects a local
buffer, spool, or compatibility path. Compare equivalent default transports and protocol modes. If the
same logical input can already be sent through another supported path and the downstream component does
only bounded, linear work, report it as Medium/hardening or documentation rather than a High vulnerability.

High/Critical requires a proved second-order outcome: service-level denial of service, unbounded
retained memory/disk, superlinear CPU, output amplification, crash, memory corruption,
privilege-boundary crossing, or another concrete impact that ordinary protocol access cannot already
produce.

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

## 20. Do not write like an AI in external submissions

Bug bounty submissions and vendor disclosure emails are read by humans who triage hundreds of reports. The patterns below signal AI authorship and undermine credibility. Avoid all of them.

### Do not document what you ruled out

Bug bounty submissions are about the finding, not the research methodology. Do not include sections (or sub-sections) cataloguing failed attack variants: XXE attempts, SSRF probes, injection sweeps, oracle enumeration runs, or any other dead-end investigation. The triage reviewer does not need a log of what did not work.

Banned constructs:
- Any section titled or labelled "Defender-positive", "Dead ends", "Negative findings", "Ruled out", "What was probed"
- Inline sentences of the form: "XXE is dead. 144 probes across 6 URI schemes returned…"
- Parenthetical probe-count annotations anywhere in the submission body: `(20-probe sweep, 2026-05-19)`, `(111 candidates across 7 families)`

If a negative result is genuinely material — e.g., confirming that JPQL injection is closed on the same surface you are reporting — state it in one sentence, plain English, without a probe count. One sentence. Then move on.

### Probe counts and precise telemetry are internal state

Request volumes, per-phase timing ranges, percentile latencies, and per-node load-balancer distribution are internal operational data. They do not belong in submissions.

Banned patterns:
- `~270 SOAP POST requests distributed across gmwp-app1 and gmwp-app2`
- `p50=257 ms, p95=564 ms`
- `Rate held below 6 SOAP/min during the oracle sweep`
- `144 probes across 6 URI schemes`

If the reviewer needs a time window for incident response, one UTC date range suffices: `Testing occurred 2026-05-18 20:49 – 2026-05-19 11:03 UTC`.

### Deconfliction is three lines, not a section

When a program or policy requires deconfliction data, provide exactly:
1. Researcher identifier (handle or email the program knows you by)
2. Source IP address
3. UTC time window for all testing (single range, not per-phase)

Nothing else. Do not enumerate marker strings, do not break the time window into per-phase sub-ranges, do not state request volumes, do not describe rate limiting, do not make cleanup assertions. These additions signal automated tooling, not a human researcher.

If the program does not require deconfliction data, omit the section entirely.

### Attack scenarios must sound like real threat models

The attack scenario should describe a plausible adversary with a realistic motivation. It is 2-3 sentences.

Banned patterns:
- Cartoonish personas: "a first-year computer science student in a dorm room", "a script kiddie on public Wi-Fi", "any curious teenager with a browser"
- Romantic framing: "from a public Wi-Fi network", "with a copy of curl"
- The phrase "with a one-minute proof-of-concept" — banned by Rule 11 and doubly banned here

Preferred pattern: name the adversary class (external unauthenticated attacker, low-privilege authenticated user, malicious insider), the access they start with, the action they take, and the impact they achieve. A real triager reading this should think "yes, this is who would do this" — not roll their eyes.

### Do not instruct the triage reviewer

Do not tell the reviewer how to interpret, score, weight, or act on your finding. They are experienced security professionals. Phrases like the following are condescending and read as AI-generated:

Banned patterns:
- `please do not treat it as one in triage`
- `this is the finding; the escalation paths describe where it goes`
- `do not conflate this with the other finding above`
- `recorded so triage does not re-investigate`
- `triage can prioritize remediation correctly`

State what you found and what it means. Stop there. Let the reviewer decide.

### CVSS scores must match proved impact, not structural potential

If write operations returned HTTP 200 but the payload was rejected by application-layer validation and zero state was mutated, the integrity impact is not `I:H`. Score the impact that was demonstrated, not the impact that would occur if a secondary condition (valid template name, valid actor ID) were satisfied.

If you believe the structural gap warrants a higher score than the demonstrated impact justifies, explain in one sentence why, then score the demonstrated impact. Do not assign `I:H` and then hedge it in the body prose.

### Titles are one clause, not a paragraph

A submission title is the shortest possible description that distinguishes this finding from all others. It maps to a single platform field that displays in list views.

Maximum 12 words. No parenthetical product aliases. No sub-clauses beginning with "bypasses", "on the federal", "on the production". No architectural context that belongs in the summary.

Bad: `Unauthenticated SOAP execution on production CA Identity Governance (Eurekify) bypasses the portal.cms.gov SSN/Experian RIDP gate on the federal role-request workflow plane`
Good: `Unauthenticated SOAP access to CA IGA workflow engine bypasses EUA RIDP gate`

### Remediation is a fix, not a project plan

Remediation is 1-3 items. Item 1 is the primary fix (the control that must be bound or enforced). Item 2, if present, is defense-in-depth (an additional layer worth adding). Item 3, if present, is an audit/cleanup step.

Do not include:
- A "validate the fix" step telling the team to re-run your PoC curls — that is implied by any competent engineering process
- More than one defense-in-depth item
- Documentation or change-management recommendations
- Security-review gate recommendations for future changes

### Do not re-explain your metadata in the body

If CWE, CVSS, VRT, or OWASP mapping fields appear at the top of the submission, do not restate or justify them inside the prose. `"The CWE here is CWE-306"` in the Impact section, after CWE-306 is already declared in the header, wastes a sentence and reads as AI filling space.

### "This submission" is banned

Say "this finding" or "this report". The word "submission" is platform jargon that makes prose sound like a form being completed, not a human describing a bug.

### Related findings: one sentence each

Cross-references to other findings in the same program belong at the end of the submission. Each cross-reference is one sentence: what the other finding is, and why it is related. No multi-paragraph descriptions of sibling findings. The reviewer can read that submission separately.

If the finding genuinely depends on another (chain), describe the dependency in plain English in the Summary, not in a dedicated Related Findings section.
