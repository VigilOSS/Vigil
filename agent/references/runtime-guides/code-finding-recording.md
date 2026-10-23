---
description: Code finding authoring, source access assumptions, evidence and credential recording
skill: code-vulnerability-analysis
---

# Code finding recording

Code analysis findings record in the **same** `assessment_findings` table as web findings.
Use `vigil assess finding record <agent-name> <finding-json-file> --agent-id <your-agent_id>` to
record. `--agent-id` is the dispatch id from your Runtime Identity block (e.g. `HUNT-RUN-1`), not
the role name in `<agent-name>`; it becomes the finding's immutable `provenance.agent_id`, and
without it no code finding can ever reach `confirmed`, `downgraded`, or `false_positive` — terminal
verification is refused when the backend cannot show the verifier was a different dispatch from the
author.
For new findings, omit `slug` from the JSON payload — `finding record` allocates the next
canonical slug under a lock and prints it on stdout. Use that returned slug in handoffs,
analysis rows, and follow-up commands. Hand-authoring `CH-001` / `CV-001` style slugs in
parallel dispatches risks collisions.

Finding prefixes are allocated by the finding-record helper; read its contract and use the
returned slug. The verifier normally updates existing findings; a spot-check discovery may
create a new one through the same helper.

**Title:** name the code location, supported actor, failed boundary and outcome:
`[Bug Class] in [file:line or component] allows [attacker or supported caller/consumer role] to
[impact] [victim/scope]`. Use a supported caller/consumer only for an intrinsic product defect;
do not turn unknown deployment reach into a remote-attacker claim.

The finding-record contract owns CVSS base-vector/score and severity consistency. A memory corruption primitive with
attacker-controlled reachability needs the same severity discipline as a web auth bug because the
report pipeline consumes one shared finding table.

**White-box source access is not attacker access.** The operator and code agents can read the
repository because the customer provided it for review; do not treat that reviewer capability as
a public exposure path. For any finding whose impact depends on reading non-public source,
deployment, or configuration files (committed secrets, `conn.php`, `Web.config`, XML config,
private keys, service credentials), explicitly populate:

- `details.attacker_access_path`: one of `public_web_exposure`, `runtime_file_read_lfi`,
  `exposed_build_artifact`, `repository_or_backup_disclosure`, `privileged_insider`,
  or `unknown`
- `details.exposure_prerequisite`: the concrete condition that gives a real attacker the bytes
  (for example: "file is served from public S3 path", "confirmed LFI reads this path",
  "separate repo/backup disclosure required")

Severity must follow that access path:

- `critical` only when an unauthenticated or low-privilege attacker can obtain the file contents
  through a confirmed live exposure/read primitive, or when the secret is already public and its
  validated use grants full production compromise.
- `high` only when the secret/config is production-grade and immediately useful, but the access
  path is a plausible repo/backup/deploy-artifact disclosure rather than a confirmed live web read.
- `medium` or lower when the finding is primarily defense-in-depth/source hygiene, requires
  privileged repository/filesystem access, or cannot be tied to a realistic attacker read path.

Use `AV:N` only when the attacker's access path is genuinely network-direct. If the missing step is "attacker must first read a private repository or server filesystem path", model that prerequisite honestly or downgrade.

**Code finding conventions:**
- `canonical_location` format: `file:<relative-path>:<line-number>` (e.g., `file:lib/url.c:547`)
- `provenance.code_snapshot` binds the finding to the exact source reviewed, which is what makes
  the evidence reproducible. `finding record` and `finding verify` derive it from the active
  repository, so do not transcribe it; what you supply is `--agent-id`, the dispatch the backend
  resolves into that binding's attestation. Verification carries the binding on EVERY `file:`
  finding — the author's binding cannot attest that you read the bytes — and is the only path that
  may rebind a legacy/stale finding after a fresh review of the current sealed bytes, while generic
  finding updates cannot edit it. Run `vigil assess contract finding verify` for the shape
- `defect_family` uses CWE-based names: `buffer-overflow`, `integer-overflow`, `use-after-free`, `injection`, `race-condition`, `crypto-misuse`, `auth-bypass`, `format-string`
- `details.cwe_id` must be a specific CWE ID (e.g., `CWE-122`, not generic `CWE-119`)
- `source_name` is your agent name (e.g., `code-vuln-hunter`)
- `details.evidence` includes the vulnerable code plus either the untrusted-input-to-sink taint path or the exact supported operation/state/lifetime sequence that breaks the invariant, and explains why existing guards are insufficient
- For taint-driven findings populate `details.entry_point`, `details.sink`, and `details.taint_path`; for non-taint state/lifetime findings identify the public operation and failing use, then bind the sequence in `details.steps_to_reproduce`, `details.caller_feasibility`, and `details.precondition_analysis` without inventing attacker bytes
- `details.references` is an array of CVE links, advisory URLs, or CWE documentation links
- `details.poc_code` holds a PoC exploit script; for web findings use `details.poc_request` / `details.poc_response` for structured HTTP pairs

**Deduplication:** Before recording, query existing findings via `vigil assess fetch findings`.
If the same root cause at the same canonical location already exists, update or merge that finding
instead of creating a duplicate. Variant instances in different files or materially different sink
sites are new findings; repeated commentary on the same `file:path:line` is not.

**The `notes` field must contain replayable proof commands** such as the exact build flags, PoC
input file generation, sanitizer invocation, unit-test repro command, or debugger invocation used
to confirm the bug. The goal is reproduction without rediscovery: another analyst should be able to
rerun the proof from `notes` plus the referenced source files alone.

Coverage finding counts (`vigil assess finding list` with a count flag or equivalent)
intentionally include only findings whose `canonical_location` starts with `file:` — web
findings with URL-based locations are excluded from code-analysis queue accounting.

**Committed secrets with live-target reach also get recorded as credentials.** A committed secret
found in source that has live-target reach against the in-scope web app — a session cookie value,
an API key, a JWT signing secret, or a DB/service credential usable against the deployed app —
should ALSO be recorded via `vigil assess post credentials <credential-json-file>` (the payload's
`status` field carries the validity state and already defaults to `discovered`), alongside the normal
`finding record` call for the code finding itself. Recording a
discovered credential automatically flags a candidate finding and, when the secret is a session
artifact (a session-hint cookie or a bearer/JWT), mints a usable identity from it and cross-links
the two — so on a mixed code+web engagement the secret auto-surfaces as a usable identity for the
parallel web track instead of sitting inert in a code finding's `details`.

---

