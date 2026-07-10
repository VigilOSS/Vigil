---
description: "Per-engagement program brief template — the canonical home for all engagement-specific ROE (scope, headers, rate cap, no-fire endpoints, side-effect limits, ban-risk rules). Fill in one copy per engagement. Stays OUT of global prompts; loaded by specialists via the engagement's ENGAGEMENT.md or scope.json references."
category: Engagement Setup
---

# Engagement Program Brief — \[ENGAGEMENT NAME / KEY\]

> **Usage:** Copy this file to `$ENGAGEMENT_DIR/ENGAGEMENT.md` and fill in every section
> before dispatching specialists. Specialists load this file at the start of each dispatch
> to read the engagement-specific ROE. The operator edits it as the program evolves
> (new OOS carve-outs, updated rate caps, newly-discovered no-fire endpoints).
>
> **Authoring rule:** every slot below receives the *engagement-specific instance*. The
> capability-neutral judgment (why these constraints exist and how to reason about edge
> cases) lives in `agent/shared-constraints.md` and `agent/rules/hunting.md`; this file
> carries only the per-program values.
>
> **Applicability:** every ROE constraint below (scope headers, rate caps, no-fire
> endpoints, deconfliction markers, exfiltration limits) governs LIVE target-facing
> testing — the web/network operator (`agent/operator-core.md`) and any Kali-runtime
> probing. The static CODE operator (`agent/operator-core-code.md`), doing pure
> whitebox source review with no traffic to the target, is NOT bound by the header/
> rate/no-fire/deconfliction/exfil rules below while reading source. BUT every one of
> them RE-APPLIES the instant the code track runs any live probe — a Phase-4 fuzz
> campaign (`agent/phases/code-phase-4-fuzz.md`) against a running target, or web
> testing running alongside the code review (`operator-core-code.md` "Integration
> with Web Engagement").

---

## 1. Scope

### In-Scope Hosts and Assets

```
# List every in-scope apex domain, wildcard, IP range, or asset class.
# Mirror what is registered in scope.json — this section is human-readable context;
# scope.json is the machine-enforced gate.

*.example.com
api.example.com
10.0.0.0/24   # internal range — only when VPN/tunneled access is granted
```

Scope notes (cloud regions, mobile apps, API versions, etc.):

> [FILL: any scope nuances not captured by the host list — e.g., "Android app v3.x+
> only", "EU region only", "does not include payment microservice"]

### Out-of-Scope Hosts and Paths

```
# List every explicit OOS carve-out. These are registered with:
#   vigil engagement add-oos <key> <host-or-path>
# and enforced automatically by filter-scope, dispatch scope_host gate, and proxy.

appointments.example.com       # third-party scheduling SaaS
*.cdn-vendor.net               # CDN infrastructure — not in scope
/api/internal/billing          # billing service — separate program
```

OOS notes:

> [FILL: rationale for unusual carve-outs; whether any OOS paths were recently moved in-scope]

---

## 2. Required Request Headers and Deconfliction Marker

> **Why this section is here:** programs require specific headers on all in-scope traffic
> so they can attribute and deconflict researcher probes. This is the durable slot for
> the per-program header set. The `vigil engagement set-header` command registers the
> header so `kali_exec` injects it automatically into every in-scope HTTP probe
> (curl/httpx/nuclei/ffuf/katana/arjun). Fill in all program-mandated headers here.

### Program-Mandated Headers

```bash
# Register these before any probing. set-header takes the engagement key plus a
# single "Name: Value" string (NOT separate name and value arguments):
vigil engagement set-header <engagement-key> "X-Bug-Bounty-Researcher: <handle>"
vigil engagement set-header <engagement-key> "User-Agent: BugBountyResearcher/<handle>"
```

| Header | Value | Injection method |
|--------|-------|-----------------|
| `[FILL: header name]` | `[FILL: value]` | `set-header` (auto-injected) |

### Deconfliction Marker

The program uses `[FILL: header name OR User-Agent OR request body field]` as the
deconfliction marker. Registered value: `[FILL: exact value]`.

Placement decision (fill in one):

- [ ] **Header** — registered via `vigil engagement set-header` and auto-injected
- [ ] **User-Agent** — must be set explicitly on tools that override UA by default (nikto, whatweb, hydra)
- [ ] **Request body field** — inject manually into POST/PUT payloads; note which tools cannot carry it

> [FILL: any tool-specific exceptions where the marker cannot be auto-injected and must be handled manually]

---

## 3. Rate Cap

> Exceeding the program's rate cap risks a ban or invalidation of findings.
> The per-target rate table in `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy"
> provides per-trait defaults; the values below OVERRIDE those defaults for this engagement.

| Surface | Max requests/sec | Max concurrency | Notes |
|---------|-----------------|-----------------|-------|
| All in-scope hosts (default) | `[FILL: e.g., 20]` | `[FILL: e.g., 5]` | — |
| API endpoints | `[FILL]` | `[FILL]` | [FILL: e.g., "strict — returns 429 at > 10 req/s"] |
| Authenticated flows | `[FILL]` | `[FILL]` | [FILL: e.g., "session invalidates on rapid reuse"] |

Back-off rule: on a 429, pause `[FILL: e.g., 60]` seconds before retrying. Do not bypass
the rate limit — `agent/references/runtime-guides/dispatch-resource-policy.md` "Recon Dispatch Resource Policy" makes this explicit;
the program may revoke scope on violation.

---

## 4. No-Fire Endpoints

> These endpoints MUST NOT be probed. They either reach real end-user inboxes/queues/state
> or are explicitly excluded by the program. Record a `scope_decision` for any lead that
> touches one — do not fire the request to characterize the behavior.

```
# Absolute no-fire list for this engagement (add paths or full URLs):
/api/send-email
/api/sms
/api/create-account         # could create real accounts visible to real users
/admin/delete               # destructive operation on production data
[FILL: additional no-fire paths]
```

Mirror the finalized list into `scope.json` as `off_limits_paths` (a JSON array
of `/path`, globbed `/path/*`, or absolute URL patterns). That machine-owned
field is what direct/list execution admission, Katana crawl exclusions, and the
shared proxy enforce; this prose section remains the human-readable ROE.

If a test path you want to probe is adjacent to one of the above (e.g., testing
`/api/send-notification` vs. `/api/send-email`), raise a `scope_decision` before proceeding
so the operator can confirm the boundary.

---

## 5. Irreversible and Notifying Flows

> Any flow that on success OR failure could land in a real inbox, create a persistent
> record visible to real users, or send a notification must be characterized statically —
> not proved by triggering it. See `agent/shared-constraints.md` §2d for the doctrine
> (static-first characterization, the reaches-a-real-third-party test, and the capped
> 1-3 live-fire budget for genuine unknowns).

Known irreversible / notifying flows in this engagement:

| Endpoint / action | Side effect | Real recipient? (yes\|no\|unknown) | Approved for probing? | Condition |
|-------------------|-------------|----------------------------------|----------------------|-----------|
| `[FILL: e.g., POST /api/support/ticket]` | Creates a real support ticket visible to the vendor | Yes | No | Record a `human_reach_decision`; do not fire |
| `[FILL: e.g., POST /api/password-reset]` | Sends a reset email to the account address | Unknown | Conditional | Only with a researcher-owned email address (see Known-Safe Test Destinations below) |
| `[FILL: add rows]` | | | | |

Static characterization procedure: describe the likely behavior from source / spec /
documentation and record a `scope_decision`. Do not trigger to confirm beyond the
capped live-fire budget in `agent/shared-constraints.md` §2d when the recipient is
genuinely unknown.

### Known-Safe Test Destinations

> Pre-declare test identities and destinations here that are proven NEGATIVE under
> the `agent/shared-constraints.md` §2d "reaches-a-real-third-party" test — a
> researcher-owned mailbox/phone, a documented sandbox with no live inbox, or a
> self-directed test account. A destination listed here is ordinary surface — hunt
> it fully; sending to it does not consume the §2d live-fire budget and does not
> need a `human_reach_decision` record.

| Destination | Type | Owner / control | Notes |
|-------------|------|-----------------|-------|
| `[FILL: e.g., pentest+vigil@researcher.example]` | Email | Researcher-owned mailbox | Safe for password-reset / notification testing |
| `[FILL: e.g., +1-555-0100]` | Phone / SMS | Researcher-owned test number | Safe for SMS-notification testing |
| `[FILL: e.g., staging.example.com sandbox tenant]` | Sandbox account | Provisioned by the program, no live inbox | Confirmed no delivery to real users |
| `[FILL: add rows]` | | | |

---

## 6. Exfiltration Limits

> Proof-of-access requires a minimal redacted sample — never bulk-pull real user records.
> Volume is not stronger evidence and only increases harm. See `agent/shared-constraints.md §4`.

Per-finding exfiltration limit: **one minimal redacted sample** (enough to identify the
record class and one non-PII field). Specific limits for this engagement:

| Data class | Limit | Notes |
|------------|-------|-------|
| PII / user records | 1 redacted row | Do not include real names, emails, or IDs in the finding |
| Payment / financial data | 1 masked row (last 4 / stars) | Stop immediately on first confirmed access |
| Credentials / tokens | Record the format proof only | Do not capture or store the value |
| `[FILL: engagement-specific class]` | `[FILL]` | `[FILL]` |

Evidence-not-collection principle: if a single record proves access, stop. The finding's
`details.evidence` carries the proof format and the redacted sample; it does not carry
a downloaded table.

---

## 7. Parked and Non-Submittable Findings

> Some in-scope findings cannot be submitted (duplicate, not-applicable by program policy,
> informational-only, already-known). Park them rather than discarding — they may become
> submittable after a disclosure window or serve as chain primitives.

Known non-submittable classes for this program:

- [ ] Missing security headers (informational per program policy)
- [ ] Self-XSS (requires victim interaction not achievable by attacker)
- [ ] `[FILL: any program-specific not-applicable class]`

Finding lifecycle for parked findings (there is no `parked` status — use the real
holding-area mechanism):
1. Record normally via `vigil assess record-finding`. For informational / not-applicable-by-policy
   classes, set `evidence_type=informational`; for a strong-but-unproven finding or chain primitive,
   set `evidence_type=theoretical` and `details.chain_required=true` (with `details.chain_rationale`).
2. Move it into the holding area so it stays OUT of the report until proven, rather than leaving it
   report-ready: `vigil assess verify-finding <slug> --disposition pending_runtime_proof --reason "parked: <why not yet submittable>"`.
   The park reason lives in that verification reason / `details.chain_rationale`, not a non-existent `parked_reason`.
3. Review the holding area with `vigil assess list-findings --holding` and re-evaluate after each
   engagement phase — a chain may promote it to submittable.

---

## 8. Ban-Risk Rules

> Violating these risks account suspension, revocation of scope, or CNA action.

- **Do not bypass the rate cap** (§3 above). The program monitors request volume by IP and
  researcher handle.
- **Do not probe OOS hosts** even if they share infrastructure with in-scope hosts.
- **Do not use destructive operations** (`DELETE`, `PATCH` on production data) without
  explicit written approval from the program.
- **Deconfliction header is mandatory** on all in-scope HTTP traffic (§2 above). Missing
  headers on a probe that triggers an alert is treated as unauthorized access.
- `[FILL: any program-specific ban-risk rule — e.g., "account creation via the standard
  flow is not permitted; researcher accounts are pre-provisioned"]`

If you are unsure whether a probe is in-scope, record a `scope_decision` and surface it
to the operator before probing.

---

## 9. Passive DNS Coverage — Free Key Uplift

> Supply these environment variables before running dns-discovery to unlock free tier
> access to Chaos (ProjectDiscovery) and GitHub subdomain corpora. Missing keys mean
> subfinder silently skips those sources and the recon coverage is lower.

```bash
# Set in the engagement environment or ~/.vigil/.env:
export SUBFINDER_CHAOS_API_KEY="[FILL: get from https://chaos.projectdiscovery.io]"
export SUBFINDER_GITHUB_TOKEN="[FILL: personal token, read:packages scope]"
```

After setting the keys, re-run the dns-discovery stage:

```bash
vigil assess dns-discovery <apex-domain> --engagement-dir <engagement-dir>
# OR if already ran subfinder:
vigil assess kali subfinder -d <apex-domain> -all -recursive \
  -o /engagements/<key>/scans/subs_passive_refresh.txt \
  --technique RECON --intent "subfinder rerun with Chaos+GitHub keys" \
  --probe-kind fingerprint --phase recon --timeout 1800
```

A re-run with keys typically surfaces 15–40% more subdomains on enterprise targets versus
the keyless run, which directly affects the attack surface available in Phase 2.
