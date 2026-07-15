# Reporting Rules

Report-authoring rules: load these when authoring or finalizing a finding's
report-ready details, in review mode, or drafting an external submission. They
keep reports human-first, evidence-backed, and severity-disciplined. Hunters do
not need this file at hunt time — the severity/precondition essence they need is
carried by `agent/shared-constraints.md` §7 and `agent/rules/hunting.md` §2–§3.

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

## 13. Evidence formatting — proof quality and placement

**Proof quality applies wherever evidence lives, regardless of format:**

**Request block:** Full HTTP request in a fenced code block immediately after the step instruction. Annotate injected payloads or manipulated parameters with inline comments if the critical part is not obvious.

**Response block:** Immediately below the request (or, for external submissions, in the Evidence section — see "Placement" below), truncate to the 5-15 lines that prove the finding. Bold or annotate the specific data that constitutes the proof — the leaked PII field, the unauthorized record, the injected output. 10 lines that show the proof beat 200 lines that bury it.

**Highlighting:** Use `**bold**` or `← proof` / `<-- proof` annotations to draw the eye to the critical line in response blocks. A reviewer should find the proof in under 3 seconds.

**Raw tool output is not evidence.** Extract the specific proof from tool output and present it as a request/response pair or a targeted excerpt — the reader needs the proof line, not the full Nmap scan, Nuclei JSON, or sqlmap log.

**Placement differs by format — do not mix them:**

- **Internal `report.md` (legacy):** evidence lives inside the Steps to Reproduce step that produces it — no separate Evidence section. See "Report Structure (Legacy Internal Report)" in the report-generation skill.
- **External submissions:** evidence lives in its own `### Evidence` section, separate from Steps to Reproduce — see `agent/references/submission-format.md` "Structure" and "Steps to Reproduce vs Evidence." Reference the producing step ("the response to step 3") rather than re-pasting its request a second time — see Rule 21.

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

### Cross-finding dedup pass — pick a lead, flag dup-risk siblings

Consolidation (above) collapses findings into one. The other axis is **which findings a program
will treat as duplicates of each other even when you file them separately.** Blind pre-submission
triage cannot catch this: it judges one finding's bytes in isolation and never sees the cluster.
The vulnerability hunt is per-surface and never sees it either. So before submitting two-or-more
findings that share a root cause, run an explicit **cross-finding pass** over the whole submittable
set:

1. **Cluster by root cause** — group findings that share the same vulnerable control, component, or
   endpoint family (not merely the same host). A shared *selector* — e.g. every handler trusting the
   same client-supplied `userId`/`id`/`eps_sirp_id` — is a cluster signal.
2. **Pick the lead** — the highest-impact finding in the cluster is the canonical submission and
   carries the cluster's severity. A cross-user *write* leads a cross-user *read*; an RCE leads the
   info-leak that enabled it.
3. **Decide consolidate vs separate-with-framing** using the dup-risk heuristic:
   - **Same endpoint family + same selector/object class → high dup risk.** Consolidate into the lead
     as "root cause + all demonstrated impacts", or — if filing separately — expect a merge and frame
     each sibling by its *distinct primitive* (the read is the *discovery/harvest* primitive; the
     write is the *tampering* primitive) so the incremental value is explicit.
   - **Different endpoint + different object + different authority/impact axis → low dup risk.** File
     separately; a one-line cross-reference to the shared root is enough.
4. **Record the decision** so it is not re-litigated: `link-finding <sibling> --root-cause <lead>`
   for the backend cluster, and state the lead-vs-sibling framing in each submission's dedup notes.

The failure mode this prevents: filing a P3 read and a P2 write on the same broken endpoint family as
two independent tickets, then having the read dup-closed into the write — burning triage goodwill and
a submission slot. One root cause, one lead; siblings either merge in or carry an explicit
distinct-primitive justification.

## 19. Keep internal sections out of external reports

These sections are engagement-internal — strip them from client-facing deliverables:

- **Coverage Summary** — operational metrics (targets, services, probe counts) have no meaning to the client
- **Finding Cross-Reference** — maps report IDs to backend slugs; internal traceability only
- **Tested by / tester attribution** — operational, not part of the deliverable

## 20. Write like a human in external submissions

External submissions (bug bounty, disclosure email) are read by humans. The patterns below signal automated authorship and undermine credibility. The full gate checklist lives in `agent/references/submission-format.md`.

**Report what you found, not what you ruled out.** The submission covers the vulnerability. If a negative result is genuinely material, state it in one sentence without a probe count — sections cataloguing failed attack variants ("Defender-positive", "Dead ends", "Negative findings") signal automated enumeration.

**Keep telemetry internal.** Request volumes, per-phase timing, percentile latencies, and per-node distribution are operational state. One UTC date range covers the time window if the reviewer needs it.

**State safety framing once; keep it separate from mechanism.** Say why the PoC is safe to run (offline / localhost-only / FAKE credentials) exactly once, in the setup — never re-asserted at every step. That test-safety fact answers "why can I trust this didn't touch the real target," which is a different question from the vulnerability's mechanism ("why does the sink fire," "what triggers it," "what order things happen in"). Restating the safety framing at each step in place of explaining the mechanism is padding: it dilutes the finding's actual proof and is one of the most recognizable tells of agent-authored output. A PoC that says "offline" or "FAKE" a dozen times reads as a script defending itself, not a script proving a bug.

**Deconfliction: three lines only.** Researcher ID, source IP, UTC time window (single range, not per-phase). Omit if the program does not require it.

**Attack scenarios: realistic adversary, not a character.** Name the adversary class, starting access, action, and outcome in 2-3 sentences — cartoonish personas ("a first-year student in a dorm room") and romantic framing ("from a public Wi-Fi network with a copy of curl") undermine credibility.

**State the finding, let the reviewer draw conclusions.** Phrases like `please do not treat it as one in triage` or `recorded so triage does not re-investigate` assume the reviewer needs instruction — present the evidence and stop.

**CVSS must match proved impact.** If writes returned HTTP 200 but were rejected at the application layer with zero state mutated, `I` is not `H`. Score from the proved outcome, then let the body prose support it — hedging a score in body text is Rule 3 applied to external submissions.

**Titles: ≤12 words, one clause.** Bad: `Unauthenticated SOAP execution on production CA Identity Governance (Eurekify) bypasses the portal.cms.gov SSN/Experian RIDP gate on the federal role-request workflow plane`. Good: `Unauthenticated SOAP access to CA IGA workflow engine bypasses EUA RIDP gate`.

**Remediation: ≤3 items.** Primary fix, optional defense-in-depth, optional audit step.

**Header metadata lives in the header.** CWE, CVSS, and VRT declared in header fields need no in-body explanation. One field, one place. Resolve the exact VRT leaf or CWE weakness offline via `agent/references/reporting/` (`bugcrowd-vrt.md` / `hackerone-weaknesses.md`) rather than guessing the category.

**Preferred phrase:** `this finding` (not `this submission`).

**Write your own actions in first person.** `I submitted the form and the request was rejected`, not `a human filed one such submission` or `it was observed that the request was rejected` — third-person or passive framing of what you personally did during testing is an agent tell.

**Name what you haven't established, in your own voice — but stay accurate.** `I haven't worked out the outbound beacon on Excel-for-Mac (WEBSERVICE is unsupported there), though the local cross-row read still surfaces the neighbor's email` reads human; a matrix where every cell is solved reads generated. Don't over-concede past what you actually found: if a lesser impact still holds where the primary one doesn't, say so instead of writing off the whole environment.

**If flagged as AI-generated:** the correction is shorter, rougher, and more specific — never longer and more polished. Uniform polish is itself the tell.

## 21. Establish each fact once — don't re-prove it every section

State and prove each load-bearing fact in exactly one place, then let the rest of the finding rely on it. Re-asserting the same claim in the Summary, again in a step's preamble, and again in the Attack Scenario — or re-pasting a step's request/response verbatim under a separate Evidence heading — is one of the most recognizable agent-authored tells: the model re-establishes a claim wherever a section could carry it, where a human states it once and trusts the reader to carry it forward. Give each fact one home — usually the step whose request/response proves it — and let everything else reference that home instead of restating it.

- **Sections:** don't re-paste bytes a step already showed. Evidence exists to carry the annotated proof pulled from a step's response, not to retype the request a second time (see submission-format.md "Steps to Reproduce vs Evidence") — reference the step instead of repeating it. If the Attack Scenario just re-narrates the Summary and Steps, cut it or reduce it to the one sentence that adds a new adversary or starting-access detail (submission-format.md already allows dropping Attack Scenario entirely for this reason).
- **Qualifiers:** state each precondition once, where it's proven — don't repeat the same adjective phrase on every actor mention. `an anonymous visitor holding no account, session, or token, in a logged-out browser, clearing only Turnstile` → `an anonymous visitor` on every mention after the first.
- **Annotations:** gloss a response line once. `login_identifier:null` — the field name carries the rest; never repeat the same gloss in a second section.

**This is not a license to cut corroborating proof.** A second environment, engine, or code path that independently confirms the same conclusion through a different mechanism — e.g., an offline replay that rules out network dependence, or a second browser engine that rules out a client-side quirk — is a new primitive, not a restatement of the same fact. Cutting it trades a rebuttal-proof anchor for concision; keep it.

Test: if a sentence's fact is already stated or proven earlier by the *same* mechanism, it must add something new (a different identity, endpoint, or primitive) — or it's cut.
