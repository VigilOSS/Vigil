---
description: Code finding authoring, source access assumptions, evidence and credential recording
skill: code-vulnerability-analysis
---

# Code finding recording

Code findings record in the same `assessment_findings` table as web findings, through
`vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>`; the
contract (`vigil assess contract finding record`) owns fields, enums, CVSS consistency, and
dedup keys. `--agent-id` is the dispatch id from your Runtime Identity block (e.g. `HUNT-RUN-1`),
not the role name. It becomes the finding's immutable `provenance.agent_id`, and without it no code
finding can reach `confirmed`, `downgraded`, or `false_positive`, because terminal verification is
refused when the backend cannot show the verifier was a different dispatch from the author. The
verifier normally updates existing findings; a spot-check discovery creates a new one through the
same helper.

**Title:** `[Bug Class] in [file:line or component] allows [attacker or supported caller/consumer
role] to [impact] [victim/scope]`. Name a supported caller or consumer only for an intrinsic product
defect; unknown deployment reach is never a remote-attacker claim.

**White-box source access is not attacker access.** You can read the repository because the
customer provided it for review, which is not a public exposure path. When a finding's impact
depends on reading non-public source, deployment, or configuration files (committed secrets,
`conn.php`, `Web.config`, XML config, private keys, service credentials), populate
`details.attacker_access_path` (enum in the contract) and `details.exposure_prerequisite`, the
concrete condition that gives a real attacker the bytes ("file is served from public S3 path",
"confirmed LFI reads this path", "separate repo/backup disclosure required"). Severity follows
that path:

- `critical` only when an unauthenticated or low-privilege attacker obtains the contents through a
  confirmed live exposure or read primitive, or the secret is already public and its validated use
  grants full production compromise.
- `high` only when the secret or config is production-grade and immediately useful but the access
  path is a plausible repo, backup, or deploy-artifact disclosure rather than a confirmed live read.
- `medium` or lower when it is mainly defense-in-depth or source hygiene, needs privileged
  repository or filesystem access, or has no realistic attacker read path.

Use `AV:N` only when the attacker's access path is genuinely network-direct; "attacker must first
read a private repository or server path" is a prerequisite to model honestly or downgrade.

**Code finding conventions:**
- `canonical_location` is `file:<relative-path>:<line-number>` (e.g. `file:lib/url.c:547`); only
  `file:` locations count in code-analysis coverage and queue accounting.
- `provenance.code_snapshot` binds the finding to the exact source reviewed. `finding record` and
  `finding verify` derive it from the active repository, so do not transcribe it
  (`vigil assess contract finding record --field canonical_location`). Verification carries the
  binding on every `file:` finding and is the only path that rebinds a stale finding after a fresh
  review of the current sealed bytes; generic finding updates cannot edit it.
- `defect_family` uses CWE-based names (`buffer-overflow`, `integer-overflow`, `use-after-free`,
  `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`), and
  `details.cwe_id` the most specific CWE (`CWE-122`, not `CWE-119`).
- `details.evidence` holds the vulnerable code plus either the untrusted-input-to-sink taint path
  or the exact supported operation/state/lifetime sequence that breaks the invariant, and why the
  existing guards are insufficient. Taint findings fill `details.entry_point`, `details.sink`, and
  `details.taint_path`; state and lifetime findings name the public operation and failing use and
  bind the sequence in `details.steps_to_reproduce`, `details.caller_feasibility`, and
  `details.precondition_analysis` without inventing attacker bytes.
- `details.references` lists CVE, advisory, or CWE links; `details.poc_code` holds a PoC script.

**Deduplication:** before recording, query `vigil assess finding list --search <file path>` (a
filtered listing returns every match). The same root cause at the same canonical location is an
update or merge, not a new finding; variant instances in other files or materially different sink
sites are new findings.

**Independent re-derivation:** when your lane reached an already-recorded finding on its own and
adds no new evidence, record `vigil assess finding corroborate <slug> --dispatch <your agent_id>
--reason '<how you reached it>'` instead of a duplicate. A corroboration is an audited link, not
proof: it never changes verification status, and a verifier still needs its own receipts.

**`notes` holds replayable proof commands:** the exact build flags, PoC input generation,
sanitizer invocation, unit-test repro, or debugger invocation that confirmed the bug, so another
analyst can rerun the proof from `notes` and the referenced source files without rediscovery.

**Committed secrets with live-target reach are also credentials.** A session cookie value, API
key, JWT signing secret, or DB/service credential usable against the in-scope deployed app is also
recorded with `vigil assess post credentials <credential-json-file>` (its `status` defaults to
`discovered`), beside the `finding record` call. That flags a candidate finding and, for a session
artifact (a session-hint cookie or a bearer/JWT), mints a usable identity and cross-links the two,
so on a mixed code and web engagement the web track can use it.
