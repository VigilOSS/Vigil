# Changelog

Notable changes to Vigil. Format follows [Keep a Changelog][keepachangelog]; versioning follows
[Semantic Versioning][semver].

1.0.0 is the first public release. Pre-1.0 development happened in this repository's version
control, and `jj log` remains the record of it; this file starts at the release rather than
summarizing that history.

## [Unreleased]

### Added

- **Nine operator session commands now share one rendered source contract.** `vigil-start` and
  `vigil-encapsulate-win` join the resume, handoff, compaction, depth, escalation, verification, and
  triage commands rendered for Claude and Codex.
- **Operator checkpoints and richer resume hydration.** The assessment CLI records a bounded pointer
  to durable engagement state, and `resume-brief` returns the current checkpoint plus honest totals
  for recent decisions, dispatches, and handoffs.
- **Engagement launch preflight.** Client availability and provider credentials fail before launch;
  unavailable services and stale installs warn with an explicit bypass for deliberate recovery.

### Changed

- **`consume-test` is the canonical phase spelling.** `consume` and `consume_test` remain accepted
  input aliases; readiness responses return `consume-test`.
- **Client launchers are interactive engagement entrypoints.** Unknown client flags forward with a
  typo guard, while benchmark validation for all clients remains explicitly deferred in `TODO.md`.

### Fixed

- **Maintainer and user documentation now follows executable contracts.** Extension recipes name the
  real registries and test suites, session docs list all nine commands, eval instructions use the
  backend dev environment, and a structural guard rejects dead paths or an oversized `CODE-MAP.md`.
- **Session end no longer replaces the operator's place marker.** The automatic hook records an
  activity receipt; the explicit operator checkpoint remains current for the next session.
- **Checkpoint identity and rendering stay truthful.** Create requests cannot self-assert a client
  or writer source, supersession displays engagement-local checkpoint versions, and every Markdown
  line ending is contained without hiding the operator's text.
- **Client entrypoints resolve the intended environment.** Codex hook commands are materialized to
  installed paths, post-subcommand `--root` remains a Vigil option, provider-key precedence matches
  generated launchers, and malformed env/config input fails with a controlled explanation.

## [1.0.0] - 2026-09-12

First public release. Vigil is operator-run offensive-security and incident-response tooling: a
`vigil` CLI, an orchestrator backend that owns durable engagement state, a containerized recon
runtime, and a prompt corpus that drives an agent through an engagement. See the
[README](README.md) for setup and [`docs/adr/`](docs/adr/) for the decisions behind the behavior
described here.

### Breaking

- **`oob.frp_host` and `oob.domain` have no default.** Out-of-band callback handling requires
  operator-provided relay infrastructure. Vigil ships no fallback host, and OOB startup fails with
  the exact `vigil config set` commands needed. Everything else installs and runs without it.
- **Engagement credentials live in the backend, not on disk.** The `engagement_credentials` table
  holds one record per `(engagement, identity)`, managed through `vigil auth`. There is no
  `auth.json` file to read, edit, or back up separately. See the
  [README runtime model](README.md#authentication).
- **The durable work buffer is a backend table.** `assessment_work_items` replaces the former
  per-engagement `cases.db`, with the same engagement scoping and inline classification applied
  server-side in the ingest transaction. See
  [ADR 0013](docs/adr/0013-work-buffer-folded-into-backend-ledger.md).
- **New engagement scope stops writing legacy repository fields.** Repository intent belongs to the
  engagement manifest and the code-ingest contract. Existing `scope.json` `repos` / `source_repos`
  values stay readable.
- **`--attribution-scope` takes `scope` or `all`.** The `document-origin` value is removed; scope
  routing already covers its stated purpose, and keeping it would preserve the cross-origin
  deconfliction defect it caused.

### Added

- **A continuous source-to-live workflow.** Web and code are independent durable tracks; a
  structural index records stable callable identities and spans; coverage separates facts, advice,
  and blockers. See [ADR 0022](docs/adr/0022-web-and-code-tracks-advance-independently.md).
- **One defect stays one finding across source and live validation.** Live proof enriches the
  source-anchored finding rather than forking a duplicate; materially different behavior is a
  variant. See [ADR 0023](docs/adr/0023-source-and-live-proof-enrich-one-finding.md).
- **Sealed, generation-bound source snapshots.** Analysis binds to the exact snapshot it read.
  Historical analysis is retained as history and is never reused as coverage for a newer
  generation. See [ADR 0026](docs/adr/0026-sealed-source-generations-own-current-code-truth.md).
- **File-level analysis leases.** A lease coordinates writes and recovery. It never limits which
  files a model may read or how far it may trace. See
  [ADR 0027](docs/adr/0027-code-analysis-leases-coordinate-files-not-reasoning.md).
- **Findings carry their own reproduction.** `details.repro_runs` binds each reproduction step to
  the `command-run` id that produced it, so a written repro can be diffed against what actually
  executed. Report readiness blocks on an empty reproduction.
- **Three-layer model identity.** Requested, launcher-effective, and provider-observed model and
  reasoning are separate fields. Disagreement between them is data, not an error to hide. See
  [ADR 0030](docs/adr/0030-model-identity-signals-remain-distinct.md).
- **Bounded structural parsing.** Exact parsers run in a resource-capped child process with typed
  failure outcomes and a complete streaming fallback, so a hostile or oversized file degrades
  visibly instead of taking the run down. See
  [ADR 0029](docs/adr/0029-structural-parsers-are-contained-with-honest-fallback.md).
- **`vigil assess prompt-census` and `vigil assess export triage-packet`.** The census measures
  expected prompt structure and bytes without pinning authored wording. The packet assembles
  canonical inputs into a content-addressed, symlink-safe bundle with a digest manifest.
- **Benchmark participants run in fresh mountless Lima clones.** Judge, oracle, family, and solver
  material stays on the host, with no host-manual launcher. See
  [ADR 0020](docs/adr/0020-benchmark-participants-run-in-mountless-lima-clones.md).

### Changed

- **Sent replies are bound to immutable renderer bytes.** At the sent transition Vigil stores the
  exact reply body, byte length, SHA-256, renderer identity, and reply sequence, and verifies the
  digest on every read. A correction creates a new linked version; drafts stay editable. See
  [ADR 0025](docs/adr/0025-final-external-communications-are-versioned-and-immutable.md).
- **A CVSS score that contradicts its own vector is rejected at write time.** `finding record`,
  `finding update`, and the verify checkpoint all name both values instead of silently
  recomputing. Merge reports the contradiction as a warning rather than stranding two duplicates.
- **`vigil assess kali <verb>` exits non-zero on a terminal failure status.** `failed` is 3,
  `timed_out` 4, `killed` 5, `transport_error` 6 — distinct from Vigil's own 1 and argparse's 2. A
  run that produced output, `waf_challenge` included, still exits 0, and the JSON is always
  emitted in full before the exit.
- **Benchmark outcome and contamination are independent axes.** `clean`, `answer_key_exposed`,
  `confirmed_read`, and `telemetry_incomplete` are typed states. Any non-clean attempt scores zero
  qualifying credit while keeping its diagnostic progress. See
  [ADR 0003](docs/adr/0003-benchmark-decoy-scoring-decoupled-from-competence.md).
- **Unavailable measurements are typed, never relabelled clean.** Parser failure, missing provider
  telemetry, and unresolvable identity render as incomplete or `unknown`. See
  [ADR 0015](docs/adr/0015-honest-instruments-distinguish-no-measurement-from-clean.md).
- **Install freshness compares the managed bytes actually copied.** A recorded revision is
  provenance, not proof that unsnapshotted source bytes reached the working root. See
  [ADR 0024](docs/adr/0024-installed-freshness-follows-managed-content.md).
- **CODE-track network access is advisory, not a sandbox.** Ordinary code work keeps normal network
  access; recognized declared-target contact warns and proceeds. Absence of a warning does not
  prove no target was reached. See
  [ADR 0021](docs/adr/0021-code-network-access-is-advisory-not-a-sandbox.md).

### Fixed

- **Terminal verification requires an attributable author.** `finding record` takes `--agent-id`,
  the generated schema admits `provenance.agent_id`, and the backend refuses a missing or invalid
  author. The independence check stands: the author dispatch must differ from the verifier's.
- **Finding filters validate their vocabulary.** An unknown `severity`, `workflow_status`, or
  `verification_status` value answers 400 naming the accepted words, so a typo cannot read as "no
  matching findings" while matching findings sit in the table.
- **A resume inherits only proof it can stand behind.** Run candidates, obligations, and source
  reads share one predicate: only receipts healthy at resume time carry over, an obligation whose
  proof was dropped reopens, and the child's event row names the dropped receipt ids. Parent
  records stay immutable.
- **Documented CLI flags are linted against the live parser.**
  `orchestrator/backend/tests/test_skill_cli_sync.py` resolves every literal `vigil assess`
  invocation in the prompt corpus against the argparse tree, so a documented flag no verb registers
  fails the build instead of dying at argparse exit 2.
- **`vigil oob poll` qualifies a zero-match result.** Marker, DNS, HTTP, and callback-log checks run
  when nothing matched and report `channel_verified`, so a silent channel is distinguishable from a
  target that never called back. The verdict is cached on a cadence and says when it was reused.

### Removed

- **Credential and secret masking from every operator-facing surface.** The run-audit regex pass and
  its reveal toggle, name-only `auth list --json`, `Bearer (length=40)` projections, proxy-userinfo
  stripping, and cookie/header counts are gone with their constants, helpers, and call sites. See
  [ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md).
- **The remaining operator-data suppression controls.** HTTP capture no longer exposes a redaction
  profile, proof receipts no longer create transformed derivatives, and artifact registration no
  longer carries a sensitivity switch. Legacy columns remain read-only migration history.
- **The browser `safe-facts-v1` mode and its `--fact` reducer.** Authenticated browser runs keep
  full artifact capture; a screenshot and DOM are frequently the only proof a rendered-JS finding
  has. The flag, its selector grammar, and its validators are deleted rather than deprecated.

### Security

- **Vigil does not defend against its own operator, by design.** Credentials, tokens, cookies,
  `Authorization` headers, and raw argv render verbatim in the CLI, the API, `--json`, exports, and
  the frontend. This is expected behavior on the operator's own machine and is not a vulnerability.
  See [ADR 0019](docs/adr/0019-vigil-does-not-defend-against-its-own-operator.md) and
  [SECURITY.md](SECURITY.md#operator-data-boundary).
- **Four controls have a real adversary and are enforced.** Benchmark anti-cheat (the benchmarked
  model), scope and ROE enforcement (non-consenting third parties), proof and evidence integrity,
  and the untrusted-target-text boundary. ADR 0019 may not be cited to weaken any of them.
- **Target-derived text is untrusted data.** Text captured from a target is labelled and delimited
  before an agent reads it, never deleted or rewritten. See
  [ADR 0018](docs/adr/0018-target-derived-text-is-untrusted-data.md).
- **Scope and ROE are enforced before target-facing work.** In-scope host validation, the
  `exploit_policy` gate, and destructive-command blocks protect parties who did not consent.
  Authorization remains the operator's responsibility; see [SECURITY.md](SECURITY.md#authorized-use).
- **Proof integrity is additive.** Artifact digest revalidation, receipt health, immutable producer
  attribution, and terminal-state immutability add information rather than removing it. See
  [ADR 0028](docs/adr/0028-producer-provenance-binds-proof-to-work.md).

### Upgrade notes

There is no supported upgrade path from a pre-1.0 working tree; 1.0.0 is the first release intended
for use outside this repository. Install it fresh:

1. Follow the [README quick start](README.md#quick-start) to install the CLI and workspace.
2. Run `vigil doctor` for host prerequisites and `vigil status` for live service state.
3. Add credentials with `vigil auth` — nothing is read from an `auth.json` on disk.
4. Configure OOB only if you need it: `vigil config set oob.frp_host <host>` and
   `vigil config set oob.domain <domain>` against relay infrastructure you control.
5. Expect operator-owned credentials and evidence to render verbatim. Treat a Vigil screen the way
   you treat a terminal with live credentials in it.

[keepachangelog]: https://keepachangelog.com/en/1.1.0/
[semver]: https://semver.org/spec/v2.0.0.html
[unreleased]: https://github.com/vigil-oss/vigil/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/vigil-oss/vigil/releases/tag/v1.0.0
