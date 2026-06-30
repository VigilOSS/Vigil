# Reporting Rules

These rules keep reports human-first, evidence-backed, and severity-disciplined.

## 1. State proven attacker outcomes directly

State what the attacker can do — hedge language like "could potentially" or "may allow" signals that the finding has not been validated to the point of actionable certainty. If certainty is missing, validate further before reporting.

Preferred pattern:

- `An attacker can [exact action] by [exact method].`

Phrases that signal unvalidated findings (replace with the pattern above):

- `could potentially`
- `may allow`
- `might be possible`
- `could lead to`
- `could be chained with ...`

## 2. Proof is mandatory

Show exact impact, not just status codes or tool noise. The report should make the failure obvious to a reviewer.

## 3. Severity follows proven impact

Severity reflects what the evidence proves — recon hints, CVEs, and intuition are signals to investigate, not grounds for inflation.

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

**Missing headers, stack traces, error messages, schema exposure, and configuration observations** are informational unless they directly enable a higher-impact attack. Rate these as informational — the theory that they "could help an attacker" is speculative chaining, not proved impact.

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

Vague titles that fail this formula:

- `IDOR vulnerability found` — missing endpoint, role, and impact
- `Security issue in API` — missing bug class, endpoint, and impact
- `XSS in user input` — missing exact feature and attacker outcome

## 9. Use durable finding state as the source

Every claim in the report traces back to a recorded finding, backend state, or confirmed evidence reference — the report reflects proved state, not memory or inference.

## 10. Section length limits

Reports are for humans who scan fast. Enforce these ceilings per finding:

| Section | Maximum |
|---------|---------|
| Description | 2-4 sentences |
| Steps to Reproduce | Numbered steps, one action per step, no narrative between steps. Each step that sends a request includes the request block and the relevant response excerpt (truncated to 5-15 lines) inline — proof lives inside the step that produces it. |
| Impact | 1-2 sentences |
| Remediation | 1-2 sentences |

If you need more space, the finding is probably two findings. Split it.

The executive summary is one page maximum. If it does not fit on one page, cut words.

## 11. Language that signals confidence and precision

In addition to Rule 1 hedge phrases, replace these filler patterns with their tighter alternatives:

**Transitions → lead with proof.**

| Instead of | Write |
|---|---|
| `Furthermore` · `Additionally` · `Moreover` | Start with the proof or outcome sentence immediately |
| `It is worth noting that` · `It should be noted that` | State the fact |
| `As demonstrated above` · `As mentioned earlier` | `The same request also` · `The response then` · `A second request confirms` |
| `During the course of our assessment` · `Upon further investigation` | (delete — add nothing) |
| `In conclusion` · `To summarize` · `with a one-minute proof-of-concept` | (delete — add nothing) |

**Descriptions → add new information per sentence.**

| Instead of | Write |
|---|---|
| Restating the finding title in the first sentence | First sentence adds the proof, victim scope, or attacker outcome the title does not carry |
| `This finding describes...` · `This vulnerability allows...` | The finding *is* the description — open with the new fact |
| Defining the vulnerability class for the reader | The audience knows XSS, SQLi, IDOR, SSRF — jump to the specifics |
| Closing paragraphs that restate prior sentences | (delete — the reader just read it) |

Background that materially matters goes into `Vulnerability Details`, not the opener.

**Voice → name the actor and the action.**

| Instead of | Write |
|---|---|
| `It was discovered that...` | Name the endpoint and what it does |
| `The application was found to be vulnerable to...` | State what is vulnerable and how |
| `Testing revealed that...` | State the fact directly |

Preferred pattern: subject-verb-object. The endpoint does X. The attacker sends Y. The response contains Z.

**Descriptors → name what the thing does.**

| Instead of | Write |
|---|---|
| `robust` · `comprehensive` · `seamless` · `crucial` · `admirably honest` · `the crux of the matter` | Name what the thing does instead of rating it |

**External submissions → focus on the finding, not the researcher.**

Compliance is assumed. Restating it implies uncertainty:
- Scope assertions enumerating what was *not* touched → (omit)
- Request-volume or rate pledges (`10 calls at ~3 req/s`, `We limited testing to...`) → (omit)
- Future-conduct pledges (`Researcher will not contact customers`) → (omit)
- "I respected the program rules" framing → (omit)

Program rules already require in-scope, rate-limited, non-impersonating testing. Write as if professional conduct is the baseline.

## 12. Active voice by default

Write in active voice. The subject acts.

- Bad: `It was observed that session tokens are returned in the response body.`
- Good: `The /api/login endpoint returns session tokens in the response body.`
- Bad: `The parameter was found to be injectable.`
- Good: ``The `search` parameter on /api/products accepts unescaped SQL syntax.``

Passive voice is acceptable only when the actor is genuinely unknown or irrelevant.

## 13. Inline evidence formatting

Evidence lives inside the Steps to Reproduce step that produces it — not in a separate section. Format proof inline with each reproduction step.

**Request block:** Full HTTP request in a fenced code block immediately after the step instruction. Annotate injected payloads or manipulated parameters with inline comments if the critical part is not obvious.

**Response block:** Immediately below the request, truncate to the 5-15 lines that prove the finding. Bold or annotate the specific data that constitutes the proof — the leaked PII field, the unauthorized record, the injected output. 10 lines that show the proof beat 200 lines that bury it.

**Highlighting:** Use `**bold**` or `← proof` annotations to draw the eye to the critical line in response blocks. A reviewer should find the proof in under 3 seconds.

**Raw tool output is not evidence.** Extract the specific proof from tool output and present it as a request/response pair or a targeted excerpt — the reader needs the proof line, not the full Nmap scan, Nuclei JSON, or sqlmap log.

## 14. Remediation must be specific

Remediation names the technology, the control, and the fix:
- `Use parameterized queries via PDO::prepare() for all SQL queries in the search controller.`
- `Add server-side ownership check on /api/orders/{id}: verify order.user_id matches the authenticated session before returning data.`
- `Set HttpOnly and Secure flags on the PHPSESSID cookie in php.ini or via session_set_cookie_params().`

Generic advice fails this bar because it tells the developer nothing actionable:
- `Implement proper input validation`
- `Use appropriate access controls`
- `Follow security best practices`
- `Sanitize user input`
- `Implement proper authentication`

When the server-side technology is unknown, state the control that failed and the class of fix required.

## 15. Keep every sentence load-bearing

Every sentence in a finding must contribute new information. If removing a sentence does not reduce the reader's understanding, remove it.

Common padding to avoid:
- Background paragraphs explaining the technology stack before getting to the bug
- "This is significant because..." followed by restating the impact that was already in the impact section
- Listing theoretical secondary impacts that were not proved
- Adding "defense in depth" remediation items beyond the primary fix

## 16. Severity lives in the CVSS line, not the title

Finding titles communicate the bug class, location, attacker role, and impact. The CVSS metadata line carries score and vector.

`[CRITICAL] Unauthenticated RCE in /api/upload` → `Unauthenticated RCE in /api/upload`
`IDOR in /api/orders/{id} [HIGH]` → `IDOR in /api/orders/{id} allows authenticated user to read other users' orders`

## 17. External deliverables contain only client-meaningful content

Strip before external delivery:
- Internal backend tracking IDs (slugs such as `VA-003`, `EX-032`, `RE-010`) in any field
- References to internal tooling, scan file paths, or orchestrator state
- Operational status annotations: "Reported to X on date", "Duplicative", "Already sent"

These are internal-only metadata with no meaning to the client — the reader sees noise where they expect findings.

## 18. Consolidate findings to root cause

When two findings share the same vulnerable component or configuration and one is a direct consequence of the other, write one finding covering the root cause and all demonstrated impacts.

Separate findings for the same root cause inflate the finding count, split remediation, and fragment the attack story. Apply the same judgment a BugCrowd/HackerOne triager would: one root cause, one submission.

Common patterns that require consolidation:
- Credential exposure as a direct consequence of an auth bypass on the same system
- Multiple unauthenticated routes on the same API when the root cause is a single missing-auth control

## 19. Keep internal sections out of external reports

These sections are engagement-internal — strip them from client-facing deliverables:

- **Coverage Summary** — operational metrics (targets, services, probe counts) have no meaning to the client
- **Finding Cross-Reference** — maps report IDs to backend slugs; internal traceability only
- **Tested by / tester attribution** — operational, not part of the deliverable

## 20. Write like a human in external submissions

External submissions (bug bounty, disclosure email) are read by humans. The patterns below signal automated authorship and undermine credibility. The full gate checklist lives in `agent/references/bugbounty-submission-format.md`.

**Report what you found, not what you ruled out.** The submission covers the vulnerability. If a negative result is genuinely material, state it in one sentence without a probe count — sections cataloguing failed attack variants ("Defender-positive", "Dead ends", "Negative findings") signal automated enumeration.

**Keep telemetry internal.** Request volumes, per-phase timing, percentile latencies, and per-node distribution are operational state. One UTC date range covers the time window if the reviewer needs it.

**Deconfliction: three lines only.** Researcher ID, source IP, UTC time window (single range, not per-phase). Omit if the program does not require it.

**Attack scenarios: realistic adversary, not a character.** Name the adversary class, starting access, action, and outcome in 2-3 sentences — cartoonish personas ("a first-year student in a dorm room") and romantic framing ("from a public Wi-Fi network with a copy of curl") undermine credibility.

**State the finding, let the reviewer draw conclusions.** Phrases like `please do not treat it as one in triage` or `recorded so triage does not re-investigate` assume the reviewer needs instruction — present the evidence and stop.

**CVSS must match proved impact.** If writes returned HTTP 200 but were rejected at the application layer with zero state mutated, `I` is not `H`. Score from the proved outcome, then let the body prose support it — hedging a score in body text is Rule 3 applied to external submissions.

**Titles: ≤12 words, one clause.** Bad: `Unauthenticated SOAP execution on production CA Identity Governance (Eurekify) bypasses the portal.cms.gov SSN/Experian RIDP gate on the federal role-request workflow plane`. Good: `Unauthenticated SOAP access to CA IGA workflow engine bypasses EUA RIDP gate`.

**Remediation: ≤3 items.** Primary fix, optional defense-in-depth, optional audit step.

**Header metadata lives in the header.** CWE, CVSS, and VRT declared in header fields need no in-body explanation. One field, one place.

**Preferred phrase:** `this finding` (not `this submission`).

**If flagged as AI-generated:** the correction is shorter, rougher, and more specific — never longer and more polished. Uniform polish is itself the tell.
