# Changelog

Notable changes to Vigil. Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file starts at the changes below. Earlier history lives in `jj log` / `git log` and was not
back-filled, because reconstructing it after the fact would invent a precision the record does not
have.

## [Unreleased]

## [0.3.0] - 2026-09-12

### Added

- **A continuous, explicit source-to-live workflow.** Structural index v6 records stable callable
  identities and spans for bundled JavaScript, coverage distinguishes facts/advice/blockers, leases
  and corrected results name their superseded rows, code-file listings are paginated envelopes, and
  each dispatch receives an engagement-contained scratch directory. Web/code track activation,
  legacy phase repair, host/rate mutations, and ambiguous proxy ownership are explicit and audited.
- **Repairable provenance and truthful client identity.** New findings require a valid author;
  legacy authorless records have a one-time audited binding command. Dispatches keep requested,
  launcher-effective, and provider-observed client facts separate, with the unavailable provider
  observation represented as `unknown` rather than guessed from model variables.
- **Public-source release foundations.** Apache-2.0 licensing, security/contribution/community
  policy, package metadata, synthetic methodology/fixtures, and dependency-license evidence are in
  place. Destructive history rewriting and public cutover remain owner-only gates.
- **Bounded parser and million-file qualification.** Exact structural parsers now run in a
  resource-capped child process with typed failure outcomes and complete streaming fallback. A
  virtual million-file regression drives production listing through interrupted and complete
  paginated scans, composes 200 exact selectors distributed across the inventory, and proves one
  maximum-size queue commit plus idempotent cancellation retry without allocating a million-file
  tree.
- **Prompt census and canonical blind-triage packets.** `vigil assess prompt-census` measures
  expected prompt structure and bytes without pinning authored wording. `vigil assess export
  triage-packet` assembles exact canonical inputs into a content-addressed, symlink-safe packet with
  a digest manifest and an explicit no-process-isolation declaration.
- **Executable benchmark reliability controls.** Timeout reconciliation closes paginated live
  state while preserving partial evidence; a focused profile preflights offline Nuclei, reuses
  collection, and accepts evidence-linked deadlines; typed payload transport verifies and streams
  the exact bytes that are sent.

### Changed

- **Benchmark outcome and contamination are independent axes.** `clean`, `answer_key_exposed`,
  `confirmed_read`, and `telemetry_incomplete` are typed states; every non-clean attempt receives
  zero qualifying credit while retaining its diagnostic progress and execution outcome. Requested,
  launcher-effective, and provider-observed model/reasoning identities are also separate; pricing
  fallbacks never become provider evidence.
- **Sent replies are append-only.** Drafts remain editable, but a sent reply's bytes are immutable;
  a correction creates a linked version. Resume/list/note/artifact commands now report totals,
  truncation, replacement, refresh, and unlink behavior explicitly instead of requiring inference.
- **New engagement scope stops writing legacy repository fields.** Repository intent remains in the
  engagement manifest and code-ingest contract; existing `scope.json` `repos`/`source_repos` values
  remain readable for compatibility.

### Fixed

- **Fresh installs no longer inherit owner-specific OOB defaults.** `oob.frp_host` and
  `oob.domain` must be configured explicitly. Starting without either value now fails with the
  exact `vigil config set oob.frp_host <host>` and `vigil config set oob.domain <domain>` commands
  needed to finish setup.
- **A CLI-recorded finding could never reach `confirmed`.** The backend refuses every terminal
  verification it cannot attribute to an author dispatch distinct from the verifier's, but the
  generated finding schema forbade `provenance.agent_id` — the only field that carries that
  attribution — so `finding record` could not supply it and every CLI-authored finding was stuck at
  `unreviewed`. The schema now admits the key and `finding record` requires `--agent-id`; the backend
  refuses missing or invalid authors. The independence check itself is unchanged: an unresolvable
  author and an author that is the verifier are both still refused.
- **An unknown finding filter value returned an empty list instead of an error.**
  `finding list --verification-status verified` (the retired two-axis spelling) answered `[]` with
  exit 0, which reads as "no confirmed findings" while confirmed findings sit in the table.
  `severity`, `workflow_status`, and `verification_status` filters are now validated against their
  enums and answer an unknown value with a 400 naming the vocabulary. The dead `verified` /
  `escalated` / `pending` disposition words were swept out of the prompt corpus in the same change.
- **A resumed run inherited proof it could not stand behind.** The resume proof repair covered run
  candidates only; obligations and source reads still copied their parent's receipt bindings
  verbatim, so a child inherited decayed proof, raised a `proof_*` blocker it could not clear, and
  held at `partial` forever. One predicate now governs all three: a resumed run inherits only
  receipts that are healthy at resume time, a closed obligation or terminal candidate whose proof
  was dropped reopens, and the child's own event row records the dropped receipt ids plus the
  parent conclusion they supported. Parent records stay immutable. Two parent source reads that
  differed only by a proof binding now collapse to one row in the child instead of aborting the
  whole resume on the read-fingerprint unique index.
- **Documented `vigil assess` flags that no parser registered.** `--verification-state`,
  `--verification-disposition`, `finding link --root`, `agent list --json`, `kali nikto --ssl`,
  `kali wafw00f --input-list`, and `post credentials --status` were written across the prompt
  corpus and died at argparse exit 2. A new lint in `orchestrator/backend/tests/test_skill_cli_sync.py`
  resolves every literal `vigil assess` invocation in the corpus against the live argparse tree, so
  a flag that no verb registers now fails the build.

### Removed

- **Credential and secret masking from Vigil's own operator surfaces.** The Runs tab rendered the
  audit trail through a secret-shaped regex pass behind a "Reveal values" toggle; `auth list --json`
  projected the credential store to names only; `auth status` reported `Bearer (length=40)` and
  20-character prefixes; `runtime resources` stripped proxy userinfo; and `vigil auth status`
  reduced cookies and headers to a count. All of it is gone, along with every constant, helper,
  reveal control, and call site. Vigil runs on the operator's machine, against authorized targets,
  with the engagement's own credentials — a control that withholds that data from the operator has
  no adversary to exclude, so only its false positives are observable, and one of them silently
  truncated whole command lines out of the audit view. See
  [ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md), which also names the
  four controls that keep a real adversary and are untouched: benchmark anti-cheat, scope/ROE
  enforcement, proof and evidence integrity, and the untrusted-target-text boundary.
- **The remaining operator-data suppression controls.** HTTP capture no longer exposes a redaction
  profile or status; proof receipts no longer create transformed derivatives; artifact registration
  no longer carries a sensitivity switch; and submission, reply, CLI, API, and frontend surfaces keep
  exact captured values. Legacy database columns remain read-only migration history, with historical
  proof-derivative relationships still enforced by integrity checks rather than silently discarded.

## [0.2.0] - 2026-08-26

### Added

- **Findings carry their own reproduction.** `details.repro_runs` records the `command-run` id
  behind each step of `details.steps_to_reproduce`, so a reproduction can be diffed against what was
  actually executed. Submission export reports missing or unresolvable run ids, and report readiness
  blocks on an empty reproduction.
- **Exploit-flow block.** An optional three-to-five step plain-prose flow inside the finding
  `summary`, carrying no commands, so a triager understands the mechanism before reaching the
  reproduction.
- **Per-step actor labels.** Each step names the acting identity, derived from the recorded run's
  auth context.
- **Step ceiling.** Ten steps per reproduction, one action per step. Controls, edge cases, alternate
  endpoints, and source-code analysis do not belong in the steps; cleanup does, but only when the
  reproduction mutates state the triager will also mutate.
- **Sentence-length ceiling.** 25 words, 20 inside Steps to Reproduce, prose only. The cap limits
  how much a sentence says, not how much a submission says; long walk-throughs split rather than
  shrink.
- **Meta-commentary is a banned phrasing class.** The writer narrating its own reporting decisions
  ("read this as", "that bounds", "I would rather report", "to be clear about what I am not
  claiming") is deleted rather than reworded, and an anticipated objection is answered with evidence
  or not at all — never pre-rebutted in the body.
- **Four non-blocking submission advisories:** longest prose sentence, step count, section sentence
  budgets, and evidence block length. They read as suggestions and are surfaced in
  `submission-context.json`, on stderr, and in the operator reference section of a rendered
  submission.
- **`--identity-target <tool>` on `vigil assess kali`.** When Vigil cannot derive an injectable
  argv shape from the wrapped command, this names the tool whose shape to use, so an identity still
  rides a `bash -c 'curl ...'` or a wrapped invocation. It resolves before injection rather than as
  a retry, and is refused for `bash /path/poc.sh` — extending `-H` onto the *bash* argv makes the
  header the script's `$1`, stamping `auth_context` on a run that carried nothing. `kali job start`
  registers it too, so the argv-shape refusal has the same remedy on the async lane as on the
  synchronous one instead of dead-ending the operator's long-running job.
- **`kali browser` wait controls that compose.** `--wait-selector` and `--settle` now run in
  sequence instead of one silently replacing the other, `--wait-state` (`attached`/`visible`/
  `hidden`/`detached`) and `--wait-until` (`domcontentloaded`/`load`/`networkidle`) cover the
  initial navigation, and a `wait` step takes an optional `state`. The attached-only default
  resolved on elements that were not yet rendered, so a capture ran against a half-built page. A
  pre-flight budget check WARNs on stderr — and still runs — when `--timeout` cannot outlast the
  page timeouts plus settle, naming both numbers. It warns rather than refuses because that budget
  is a *ceiling, not a cost*: a page that renders in three seconds finishes well inside a 45s
  `--page-timeout`, so the tight pairing usually completes and a refusal would dead-end a run that
  was going to work. The warning is worth printing anyway, because the DOM and screenshot are
  written at the end and the HAR flushes at context close — a run that does reach the wrapper kill
  yields zero artifacts and is indistinguishable from a clean negative.
- **Install staleness is visible.** `vigil install`/`update`/`up` all stamp the source commit they
  synced (the write moved into `install_from_source`, so the three paths cannot diverge),
  `vigil status`/`vigil doctor` report an `install_staleness` verdict, and `vigil assess` emits a
  non-fatal stderr WARN when the working root is behind source. A lagging working root silently
  exposes an older verb and skill set, so a documented flag returns argparse's "invalid choice" and
  a documented skill is simply absent — the operator prompt now names that WARN as the first
  hypothesis when something the prompt describes "does not exist".
- **`vigil oob poll` verifies the channel on a zero-match result.** Marker, DNS, HTTP, and the
  callback log are checked and reported as `channel_verified` in `--json` and a
  `channel UNVERIFIED` line in text. A silent channel and a target that never called back produced
  the identical empty result, which reads as a negative finding. The verification runs only when
  nothing matched, so a successful correlation stays fast, and it reports rather than refuses.
  Because waiting for a blind callback *is* a poll loop, the proof runs on a cadence rather than on
  every empty poll: a verdict is reused for five minutes, or sixty seconds when it failed, because
  a broken channel is the one the operator is actively repairing and a stale "unverified" that
  outlives the repair is its own lie. Worst case for a broken channel drops from a ten-second probe
  per poll to ten seconds per minute. The guarantee is unchanged — a zero match is still qualified
  by a real end-to-end round trip — and a reused answer says so: `channel_check.cached` and
  `age_seconds` in `--json`, `checked=cached(42s ago)` in text. `vigil oob test` still proves the
  channel fresh every time; that verb means "prove it now". The proof's own callbacks land in the
  same client log the poller reads, so they are dropped from the report rather than counted as
  unclaimed callbacks — otherwise the check would manufacture the evidence it exists to qualify.
- **`scaffold-probe` emits a scope guard.** The generated skeleton ships `scoped_host()`, which
  normalizes a caller-supplied host and resolves it against `scope.json` (`hosts` +
  `discovered_hosts`, wildcard-aware) before it reaches `evidence.host`. Argv is untrusted input,
  never an authorization; the refusal says how to widen scope legitimately.
- **`command-run list` shows an `out/err` preview-size column.** It carries the character count of
  the preview the backend holds for each stream (`stdout_preview_chars`/`stderr_preview_chars`).
  The withheld `stdout_preview` is deliberate bandwidth control, but with nothing in its place a
  reader could not tell a silent run from a suppressed preview.
- **`vigil assess agent start` names the spawn command.** It prints `@<role>` or
  `spawn_agent <role>` based on which per-role wrapper the engagement actually has on disk, beside
  the standing statement that the command records a dispatch and does not launch anything.

### Changed

- **Submissions are restructured for followability.** Step-verification outcomes now live inline in
  the step that produces them, and the Evidence section carries only what the steps cannot show:
  the decisive artifact (the bytes proving what a step's expected-result line can only assert), root
  cause, negative controls, post-exploitation boundaries, minimum required privilege, and
  environment facts that are load-bearing for Impact or Remediation. Evidence takes one block when a
  finding has one thing to prove and a labelled block per category when it has several — the shape
  follows the proof obligations, not a template. The previous split — steps own
  the action, Evidence owns the result — forced every outcome into a separate section downstream of
  the request that produced it, so the writer re-established request context to make results
  legible. That re-telling was the structural cause of duplicated, over-long submissions.
- **The report-writer may now edit a reproduction, not merely reformat it.** It can renumber,
  reword, merge, label, and drop steps. The boundary is fabrication, not editing: every command,
  argv, and response value must trace to a recorded `command-run` id in `details.repro_runs`.
  Dropping a step re-triggers the reproduction rehearsal, so a trimmed path is never shipped
  unexecuted. Specialists are unchanged — they continue to record the full executed sequence, and
  no probe or command run is deleted when a step is dropped from the narrative.
- **Attack Scenario is omitted whenever an exploit-flow block is present.** The two carry the same
  sequence, once mechanical and once narrative.
- **`--attribution-scope` takes `scope` (default) or `all`.** `document-origin` is removed: under
  scope routing its stated purpose — not poisoning cross-origin SPA preflights — is already covered,
  and keeping it would preserve the deconfliction violation being fixed. `all` attributes every
  origin and prints one loud stderr line naming the leaked header names. A program that mandates a
  header with no resolvable in-scope host refuses before navigation; that is the only fail-closed
  case on the attribution axis, and `--attribution-scope all` is the documented way past it. (The
  browser's other refusal is the shared `--identity` one — see the refusal budget under Notes.)
- **A CVSS score and vector that disagree are rejected at write time**, on `finding record`, on
  `finding update`, and at the verify checkpoint, naming both values instead of silently
  recomputing. Validation runs only when the write itself authors one of the pair, so a legacy
  mismatched row is not stranded — every later edit to it, including the one that fixes it, still
  goes through. "Authors" is computed the way each write shape actually stores details: a
  merge-mode patch discards empty incoming values, so a payload file that spells out
  `"cvss_score": null` changes nothing and is not treated as authoring — it used to be judged
  against the stored legacy pair and rejected over a write that was a no-op. On merge the pair
  moves atomically: once the severity winner declares either half, its absences win too, which
  stops a merge from manufacturing a mismatch neither input had. **Merge reports rather than
  refuses.** Because the pair moves whole, a contradictory merged pair always arrived whole on one
  of the two inputs — so refusing there would dead-end a correct duplicate consolidation over a
  data defect the merging agent did not author, and leave both duplicates in the report. The merge
  completes and the merge response carries a `warnings` list (always present, empty when clean)
  naming the contradiction, the values, and the verb that repairs it. `vigil assess finding merge`
  relays each warning to stderr beside its confirmation line, so the CLI caller learns about the
  defect at merge time rather than much later from a blocked readiness check. The readiness
  blockers stay as the backstop, for rows that predate the gate and for the merged row itself.
- **`agent start` and `agent handoff` name their ids.** The JSON payload key `id` became
  `dispatch_id` and `handoff_id`; a bare `id` beside `agent_id` did not say which of the two
  identifiers it was.
- **The specialist constraints state what the runtime container is not.** Three gaps that fail
  silently or mid-run are now settled facts rather than things each engagement rediscovers: there
  is no `vigil` executable inside the container, so a helper script that shells out to
  `vigil assess ...` passes a host test and dies with exit 127 on the only approved
  target-execution route (a script that runs in the runtime must be self-contained — argv in,
  manifests and `scope.json` read straight off the bind mount, recording calls made from the host
  afterwards); the `aws` binary is installed but no credentials are injected, so signed calls
  belong on `vigil assess host-exec` — an audited route, not a §2 bypass; and `/data`, unlike
  `/tmp`, is a real bind mount, but a shared engagement-agnostic one, so an artifact written there
  is detached from the engagement and never appears at `$DIR`. A skill's tool list is also not
  proof of installation — check with `command -v` before planning a step around an unused tool.
- **The operator prompt names install drift as a first hypothesis.** The working root (`~/vigil`)
  and the `vigil` binary upgrade through different commands, so a documented verb, flag, or skill
  can be genuinely absent from a lagging root. The prompt now says to read the stale-install WARN
  and re-run `vigil install` before concluding a feature was never built.

### Fixed

- The five canonical example submissions now satisfy the rules they are meant to exemplify.
- A control that proves the causal claim — a safe branch escaping the same bytes, a pre-exploitation
  capability baseline — is corroborating proof, not a banned "ruled out" section.
- **`vigil assess kali <verb>` exits non-zero when there is no complete output to interpret.**
  `failed`=3, `timed_out`=4, `killed`=5, `transport_error`=6; 1 and 2 stay reserved for a
  Vigil-side refusal (`AssessError`) and argparse, so a target verdict is still distinguishable
  from a tooling failure. Every terminal status previously exited 0, so a `cmd && next-step` chain
  and every scripted caller treated a killed scan as a clean empty result. `waf_challenge` stays 0
  on purpose: the exchange completed, the caveat is whose body came back, and its remedy is
  re-rendering through `kali browser`, not aborting. **The fan-out verbs are in the contract too,
  with no carve-out.** `kali sweep` and `arjun-sweep` print their own results instead of going
  through the shared `emit_result` funnel, so they were silently exempt — a sweep whose every arm
  died still exited 0. They now aggregate *worst-arm-when-all-failed* from the same table: non-zero
  only when EVERY arm produced no usable output, carrying the shared status's own code (all
  timed out → 4, all transport errors → 6, so the diagnosis survives aggregation) or `failed` for a
  mixed set. One dead arm out of fifty is still a useful sweep, and failing there would train
  callers to ignore `$?` on the verb most likely to run unattended — so a partial failure exits 0
  and is made unmissable instead: a "N with NO usable output" count in the table
  header, `failed`/`failed_by_status` (sweep) and `failed_methods` (arjun) in the JSON, and a
  stderr line saying those arms are holes, not negatives.
- **Browser attribution follows the scope boundary, not the document origin.** Program-mandated
  headers now reach every `scope.json`-admitted host — in-scope siblings like `api.<target>` and
  `people.<target>` included — through the same `host_admitted` matcher the rest of the CLI uses,
  and never reach a third party such as an analytics or telemetry origin. The old document-origin
  rule did both halves wrong: it withheld the mandated header from in-scope subdomains the SPA
  actually calls, and attributed same-origin requests regardless of scope. Scope data still never
  aborts or filters a request — it decides attribution only.
- **Command-run byte counts and retention status are recorded for kali routes.** Every kali row
  previously reported `stdout_bytes=0`, an empty digest and a constant `output_retention_status`
  of `empty`, so an auditor reading the history could not tell a genuinely silent tool from output
  sitting on disk. The two lanes that own their own spill files — the synchronous `kali <verb>`
  exec path and the async-job finalize — now pass the run's output paths into `finalize`, which chunk-hashes
  each file and sends `stdout_bytes`/`stderr_bytes`/`stdout_sha256`/`stderr_sha256`; the backend
  writes those plus a real `retained`/`empty` status on non-`host_exec` routes (`host_exec` spills
  through the backend's own retention machinery and is untouched). The wrapper has to do the
  measuring: the finalize previews are head+tail truncations and would undercount. A caller that
  reports nothing — a wrapper that cannot read its spill, or the orphan sweeper finalizing a run
  whose process was never proven quiesced — leaves the row's byte columns untouched rather than
  claiming a count it cannot stand behind.
- **A retried kali run and its audit row now name the same file.** The CR-36 false-negative retry
  used to re-run into a second filename, leaving the row's `stdout_path` — and the artifact-index
  entry derived from it — pointing at the abandoned first attempt while every other field on the
  row (preview, return code, duration, evidence ref) described the second. The retry now re-runs
  into the run's canonical `<run_uuid>.{out,err}` and rotates the losing attempt aside to
  `<run_uuid>.attempt1.{out,err}`, so both attempts survive on disk and the row, its index entry,
  its digest and its verdict all describe one attempt. This is also what makes the byte truth above
  honest: `finalize` hashes exactly the file the row points at.
- **`cvss_score: 0` is representable.** The generated finding schema used `exclusiveMinimum: 0`, so
  an informational finding scored `0.0` with an all-`N` vector could not be recorded at all — the
  one score CVSS defines for no impact was the one score the schema rejected.
- **`finding verify --new-severity` no longer silently no-ops.** Outside `--disposition downgraded`
  the field was accepted, stored nowhere, and reported success; the caller believed it had re-banded
  a finding. Both the backend and the client now refuse it and name the verb that owns that axis
  (`finding update <slug> --severity <band>`). The client-side message names *every* slug in a
  batch: it used to name only the first, so `finding verify A B C --new-severity low` sent the
  caller off to re-band A and leave B and C at the old band.
- **`vigil auth import` refuses an import that would store nothing.** A wrapped export
  (`{"material": {...}}`) reached the backend intact, landed inert in `raw_json`, and left the
  identity `state="missing"` while the CLI printed success — the failure only surfaced later as an
  unexplained dead session. The refusal names the wrapper key it found and the shape that works.
- **Auth liveness returns `unknown` rather than `dead` without positive evidence.** `dead` now
  requires a configured `dead_marker` hit or a response that is itself an authentication challenge
  (401/407, or a redirect to a login endpoint). A missing `authed_marker`, an unexplained status
  mismatch, and a 403 all classify as `unknown`. A 403 is an *authorization* verdict — on another
  principal's object it is the healthy IDOR/BOLA signal — and treating it as death killed the very
  identity doing the testing. A liveness signature stays ONE flat rule per identity
  (`{expect_status, authed_marker, dead_marker}`), deliberately origin-agnostic. Per-host modelling
  already has two owners — the probe-scope key that scopes the recorded observation, and
  `--identity-scope` for an identity that genuinely differs per host — so a per-origin signature
  map would be a third way to say the same thing, and the extra argument is exactly what let the
  two CLI surfaces drift into calling the classifier differently. Both now call it with identical
  arguments, so they cannot disagree; an unrecognized signature shape carries none of the three
  keys and reports `unknown` with the fix named, never a verdict borrowed from another host's
  rule.
- **`auth list` stopped showing a dead verdict a newer probe had already disproved.** The typed
  `liveness_verdict`/`last_probed_at` columns predate origin-scoped observations and are a global
  projection, so a stale global `dead` kept rendering beside an identity a fresh scoped probe had
  just proved `live` — and an operator reading the listing would skip the one session that worked.
  The listing now reconciles the two: a fresh scoped observation wins when the listing has a
  defensible host (an explicit `--host`, or exactly one usable cookie host), and with no such host
  a scoped verdict is *not* promoted to a global one — the row reads `unknown` rather than
  borrowing another origin's answer. An unqualified legacy `dead` on an identity whose stored state
  is not `dead` is dropped for the same reason. This is a read projection: it mutates no lifecycle
  state, never crosses identity rows, and expired observations never win.
- **`vigil email` scans Spam, Junk, and Archive.** The relevant-mailbox test was a fixed
  inbox/all-mail/important list, so a verification mail filtered to `[Gmail]/Spam` was reported as
  simply absent. Coverage accounting stays honest: an unauthoritative empty result now carries the
  folders actually scanned, `--json` emits that coverage instead of plain text on stderr, and the
  incomplete-scan message names `--limit` as the lever that widens the candidate window. Three
  properties the folder set makes load-bearing are now pinned by tests, because each one silently
  reintroduces the original bug: the scan walks a *bounded window* rather than stopping at the
  first message older than the cutoff (provider date ordering is a hint, not a guarantee, so an
  out-of-order old message must not end the scan); folders are paged *round-robin*, so a
  200-message Inbox cannot consume the whole candidate budget before Spam gets a page; and
  duplicate folder views of one message are collapsed by Message-ID. Truncation is reported rather
  than hidden — the folder that ran out of window is named, and the aggregate-Inbox fallback marks
  the result non-authoritative.
- **Every state-writing `vigil assess` verb has a discoverable contract.** Nineteen mutating verbs —
  `emit-event`, `log`, `post`, `record-chain`, `record-reply`, `app-unit`, `approve-proposal`,
  `scaffold-probe`, `recon`, `egress-check`, `dns-discovery`, `web-discovery`, `arjun-select`,
  `arjun-sweep`, `js-mining`, `ingest`, `gau`, `exploit`, `scope filter` — answered "Unknown
  contract" and were invisible to `list-commands`, so an agent could not learn their shape without
  reading source. Namespaced children (`finding merge`, `export findings|reply|surfaces`) resolve
  through a longest-prefix rule instead of two hand-rolled shims, and a parity test now walks the
  real parser and fails when a new mutating leaf ships without one. A schema rejection now points
  at the contract that would have prevented it: `intel record` names
  `vigil assess contract intel record <type>` on stderr (and in its own `--help`), and
  `finding update` names `vigil assess contract finding update`. An error that says only which keys
  failed leaves the caller guessing which keys were allowed. `kali --help` likewise renders the
  exit-code table from `KALI_EXIT_CODES` itself, so the help and the contract cannot drift.
- **Superseded intel rows are visibly superseded.** `intel list` renders
  `[SUPERSEDED -> <id>]` on a row carrying `superseded_by_id`, on both the identifying-key and
  JSON-fallback paths. The rows are included by design (the list is an audit record) but were
  indistinguishable from live intel.
- **The AWS skills route signed calls to the host, not the container.** `aws-iam-privesc` told
  agents to run authenticated `aws`/boto3 through `kali exec`, where the binary exists but no
  credentials do — every signed call died with `NoCredentials`. Signed calls now go through
  `vigil assess host-exec`; `kali exec` is reserved for unsigned calls (`--no-sign-request`,
  unauthenticated Cognito) and target-facing HTTP. `cloud-exposure` and `ssrf-testing` carried the
  same inversion. Four tools the skills presented as available (`pacu`, `enumerate-iam`,
  `cloudsplaining`, `pmapper`) and two more (`gsutil`, `az`) are in neither the image nor the host,
  and are now described as such.
- **`command-run get --include-output` is accepted.** It was already the endpoint's behaviour but
  the flag did not exist, so a caller copying the sibling `command-run list` invocation hit an
  argparse error. `command-run list --include-output`'s help text was also inverted, describing the
  opposite of what it does.
- **Docker image freshness is a content manifest, not a timestamp.** `vigil up` rebuilt
  `vigil-proxy` on every single run: the freshness check took an mtime high-water mark over
  `agent/scripts/assess`, and every ordinary `vigil assess` invocation rewrites `__pycache__/*.pyc`
  under the install root, so a build input was "newer than the image" within minutes of each build.
  The same walk could not express the opposite failure either — it stat'd only files that still
  exist, so an upgrade that DELETED an input left the stale image reading as current. Freshness is
  now a sha256 over `(relative path, content)` for every declared input, stamped on the image at
  build time as the `com.vigil.runtime-inputs-sha256` label and re-derived on each check, which
  answers both questions with one mechanism. The runtime image already worked this way; the fix
  generalised that into `image_freshness.py` and routed the proxy image, `vigil up`, and
  `vigil mitmproxy build|start` through it, so there is one owner of the proxy `docker build` argv
  and the label it stamps — `vigil up` no longer assembles its own unstamped copy, which was a
  second, independent way back into the rebuild-forever loop. Build artifacts and caches are
  excluded from the walk by the same set `vigil install` uses to decide what a source file is, so
  the copier and the digest cannot disagree. **One-time cost:** an existing `vigil-proxy:latest`
  carries no label and cannot be *proven* current, so it rebuilds once and is stamped; an
  unprovable image is treated as outdated rather than as an error, so nothing dead-ends. An
  already-built `vigil:latest` is unaffected — it already carries a matching label.
- **A first in-place `vigil install` is no longer misread as an upgrade.** "Is this an upgrade?"
  was answered by looking for directory names in the SOURCE tree, which a fresh clone has by
  definition, so the first install into a root Vigil had never touched took the upgrade path — and
  the upgrade path pins legacy shared-domain OOB routing that a genuinely new install must not
  inherit. The question is now answered by state Vigil itself created in the install root
  (`.vigil-install-meta.json`, `.runtime-data`, or an engagement directory), which is the only
  evidence that distinguishes the two.
- **Work-item claims apply scope exclusion before the candidate limit.** `work-buffer fetch-by-priority`
  and `fetch-by-unit` selected the top-N pending rows and *then* dropped the out-of-scope ones in
  Python, so a co-tenant host that ranks above the in-scope work returned an empty claim — every
  time, deterministically, with in-scope work sitting untouched underneath it. Both paths now push
  the exclusion into the candidate `SELECT` ahead of `ORDER BY … LIMIT`, and `fetch-by-unit` also
  applies it inside unit selection so a unit whose only pending work is out-of-scope is not
  selectable at all. The predicate is unchanged and still fails OPEN — no scope file, or a row with
  no host, stays claimable — and the exclusion is keyed on the handful of foreign hosts an
  engagement has observed rather than on a row-id list, so a large pending backlog cannot overflow
  SQLite's variable limit and turn a claim into a 500. With no foreign host the emitted SQL is
  byte-identical to before.
- **Retired finding links are no longer exported as current evidence.**
  `assessment_finding_links.retired_at` exists precisely so a superseded link is preserved rather
  than deleted, but submission export and vendor-reply export fetched every linked command run
  regardless, so a retired link shipped to a triager as live proof. The filter runs before the
  `command-run` fetch, so a retired link costs nothing to skip, and both renders share it.
  `finding link list` still shows retired rows — it is the audit surface, and hiding them there
  would be the opposite bug.
- **`auth status` without `--probe` no longer refreshes the credential's last-seen clock.** Looking
  at a session counted as using it, so the 8-hour staleness backstop was reset by inspection and an
  identity nobody had actually replayed for a day could still read as fresh. Resolve is now
  explicit about intent — `record_use` (default true, since a resolve normally *is* a replay) is
  false on the three no-probe read paths and threaded through the client, the
  `GET /credentials/resolve` query parameter, and all three service branches including alias
  resolution, which used to touch unconditionally. `record_use` is part of the client's resolve
  cache key, so a read-only answer can never be handed to a caller that is about to replay it. A
  real probe still records a use, and the stale sweep still fires.
- **Minute-based rate flags are parsed and converted.** Rate-lease reservation read only
  `-rl`/`--rate-limit` (per second), so `httpx -rlm 600` — a per-minute limiter that *replaces* the
  per-second one on httpx and nuclei — reserved nothing and ran at its real rate outside the
  engagement-wide budget, which is an ROE breach rather than an inconvenience. Both families are
  now parsed in spaced and attached forms, per-minute is converted to rps, and the reservation
  takes the `max()` of what is configured: under-reserving breaks ROE, while over-reserving costs
  only a refusal the caller can re-issue. The precedence was measured against the tools in the
  running image rather than inferred — `katana` ignores `-rlm` entirely, so the documented example
  uses `httpx`, where it is real.
- **`vigil auth keepalive` reads the origin status, not the proxy's CONNECT status.** Through an
  HTTPS proxy the probe's response blob begins `HTTP/1.1 200 Connection established`, and the
  status regex matched that first — so a dead session looked alive and the keepalive loop kept
  refreshing nothing. The probe now passes `curl --suppress-connect-headers` so the tunnel preamble
  never enters the blob, and the parser independently skips 1xx and tunnel-2xx preamble and takes
  the first real status. Both, because the flag alone leaves the parser wrong for any other
  preamble, and the parser deliberately takes the *first* non-preamble match rather than the last:
  with `curl -i` the body shares the blob, and a status line quoted inside an HTML body is not the
  response's status. `auth status`'s probe already read its code from `-w %{http_code}`, so it was
  never mis-parsing — but its marker matching ran against the same polluted blob, so it gets the
  suppression too.

### Removed

- **Severity-defence phrasing from the report-writer prompt.** Its canned phrases justified CVSS
  metrics in body prose, which the submission checklist already bans; the header carries required
  privileges, victim interaction, and demonstrated impact.
- **The report-writer pre-work checkpoint**, which restated checks the closing sequence and the
  report-generation skill already own.
- **The credential-containment and output-redaction layer.** A prior working-copy effort taught
  `kali exec` to detect credential material and rewrite what it recorded — redacted `resolved_argv`,
  sanitized spill files, refusals on unmanaged shell redirects. It is gone in full, along with every
  constant, helper, and call site. Vigil is single-operator and local: the credential store, the
  `command-run` audit rows, and the artifacts are the operator's own working state, and the audit
  trail exists to reproduce exactly what ran. Rewriting an argv on the way into that trail broke the
  one property it has. **Credentials and local state remain self-owned** — `--identity` still
  expands into a literal `Cookie:`/`Authorization` header that `command-run` stores and returns,
  and that is
  the intended inject-and-audit mechanism, not a leak. **Redaction is the report-writer's job at
  submission time**, performed once while authoring and stored in the finding, because only the
  author can tell the operator's own session cookie (mask) from a credential the target disclosed
  (that IS the proof).
- **The browser `safe-facts-v1` mode and its `--fact` reducer.** The mode suppressed the final URL,
  page title, DOM dump, and screenshot in favour of a bounded fact list. Authenticated browser runs
  keep **full artifact capture**: an authenticated screenshot and DOM are frequently the only proof
  a rendered-JS finding has, and a reducer that decides in advance which facts matter cannot know
  what the reviewer will need. The `--fact` flag, its selector grammar, and its validators are
  deleted rather than deprecated.

### Notes

Nothing here changes what blocks a submission publish. The blocking set remains the four
internal-identifier hygiene checks; every new submission signal is advisory.

**The refusal budget, in full.** Callers here are agents mid-engagement, and a refusal they cannot
get past ends the work rather than correcting it — so a refusal has to earn its place by rejecting
a request that is *incoherent*, never one that is merely risky. Finding writes gained two: a CVSS
score that contradicts its own vector, and `--new-severity` outside `--disposition downgraded`
(which was silently dropped before, and whose remedy is a real verb the message names).
`kali browser` gained one on the attribution axis: a program mandates an attribution header and no
in-scope host resolves, with `--attribution-scope all` named as the way past — the only fail-closed
case in the browser's *attribution* path. `--identity` gained one, shared by `kali browser` and
every `kali` verb through `kali_exec`: a requested identity that is absent from the store, that the
store has marked non-replayable (`dead`, quarantined, `use_for_requests: false`), or that carries
nothing this tool can inject for this request host now refuses instead of running anonymously and
stamping `auth_context` on a run that carried no credentials — which is exactly what destroys
cross-identity evidence. An advisory `stale` identity is still replayed, so the 8-hour age flag
never dead-ends anyone, and `auth status --probe` is exempt even for `dead` (the probe is how that
flag gets re-tested). Each message names the state, the age, and the recovery command. Raw nuclei
gained two, both about OOB-correlation integrity: an argv that sets `-interactsh-url`/`-iserver`
itself, and a shell-wrapped `nuclei` that does not disable callbacks — either would route blind
callbacks somewhere Vigil cannot correlate, and both name the typed wrapper plus `--oob-mode
none|public|vigil` as the way through. A bare `nuclei` argv is not refused at all: `-ni` is appended
for it. `vigil auth import` gained one: an import whose every identity carries no
cookies/headers/tokens, which used to report success and store an inert record. (Outside the CLI,
the probe skeleton `scaffold-probe` emits refuses a target host `scope.json` does not declare —
that is ROE, and the message says how to widen scope.) Two candidate refusals were deliberately
*not* taken, and both became visible truth instead — the browser timeout budget, which is a
ceiling rather than a cost, now warns; and a contradictory CVSS pair inherited through a merge now
warns, because refusing would strand two duplicates in the report over a defect the caller did not
write. Where the code stopped refusing, it started measuring: real byte counts and digests on kali
audit rows, a `failed` count on every fan-out, a `cached`/`age_seconds` field on the OOB channel
proof, and named truncated mailboxes on an incomplete mail scan.
