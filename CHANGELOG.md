# Changelog

Notable changes to Vigil. Format follows [Keep a Changelog][keepachangelog];
versioning follows [Semantic Versioning][semver].

Durable design decisions live in [`docs/adr/`](docs/adr/).

## [Unreleased]

### Removed

- **`vigil update` is gone.** It was a verbatim duplicate of `vigil install` with no behavior of
  its own. Use `vigil install` — it upgrades a working root in place.
- **The `PreToolUse` command-filtering hook is gone.** `scope-check.sh` matched every shell command
  against four destructive shapes. It could not do the job: `rm -rf /tmp/x` was blocked but
  `bash -c "rm -rf /tmp/x"` was not, `git clean -fd` was blocked but `eval`, `sh -c`, `$(echo git)`
  and a `subprocess.run` list all sailed through, and `find . -delete` and `git reset --hard` were
  never covered at all — the same wrapped-shell blind spot that condemned the masking layer in
  ADR 0019. It also cost two silent failures: one spelling of the flags missed four of six orderings,
  and matching an option value as a run of non-space characters disabled the guard entirely for any
  repository path containing a space. A guard that fails silently is worse than none, because it is
  trusted. ADR 0019 records why it is not coming back in that form, and `TODO.md` scopes what a
  guardrail that acts where commands execute — rather than where they are spelled — would have to
  answer. Activity logging, compaction and session-end hooks are unaffected, as is the benchmark
  anti-cheat `PreToolUse` guard, which has a real adversary in the benchmarked model.
- **Two session commands are gone.** `vigil-escalate-honestly` paraphrased the FP/severity gate a
  session already runs; `vigil-encapsulate-win` told the model to write its own conclusions into
  the shared methodology mid-engagement, which is a human review decision.

### Added

- **`vigil --version`** reports the CLI binary's version (`vigil status` still reports the working
  root's).
- **`vigil doctor --json`**, and `doctor` now exits non-zero on a `FAIL` row or on a missing
  required prerequisite — the Docker CLI, the install root, or the agent tree. It previously
  reported `"ok": true` on a host with no Docker at all, because an absent CLI reads as
  `MISSING` and skips the daemon probe that would have produced a `FAIL`. Optional rows such
  as OOB configuration stay advisory, the gating rows are named on stderr, and `--json` rows
  carry `required`.
- **Operator checkpoints record both track phases.** A `both` engagement advances its web and code
  tracks independently; the checkpoint and the resume brief now report each by name.
- **`vigil assess code-dispatch list`** pages the code-analysis queue read-only, with stable IDs and
  filters for status, repository, classification, theme, and queue mode. `--ids-only` writes the
  ids file `code-dispatch fetch --ids-file` consumes, so exact-ID batching no longer depends on
  scraping insertion output that caps at 200 rows and scrolls away. A page that stopped at the
  limit says so on stderr.
- **`vigil assess fetch --list-routes`** prints the declared catalog of backend read routes, so a
  route no longer has to be guessed. `fetch` still reaches any route the backend serves.
- **`vigil install` says what actually needs restarting.** It used to print the same "restart
  everything" list every time, including after the ordinary install that changes only prompt text
  and needs no restart. The summary is now derived per consumer, with the exact command for each.
- **Reference repositories.** `vigil assess code-ingest --role reference` ingests host or framework
  source for lookup without taking on responsibility for reviewing it. Reference files stay sealed,
  indexed, searchable and citable with full source identity, and are excluded from queue population,
  receipts, variants, fuzz completion and phase readiness. A plugin review no longer has to choose
  between reading the host's code and owning a second large codebase's coverage debt.
- **`vigil assess code-lead`** binds a tracked intel lead to a repository, file and line range, turns
  bound files into analysis queue rows (`code-lead queue`), and reports each lead's obligation and
  staleness state (`code-lead list`). Prior art that was previously a note nobody could act on now
  reaches the queue and shows up in code completeness as `code_leads_unresolved`. A lead's
  disposition is still closed on the note itself, so there is one lead primitive, not two.
- **`vigil assess code-dependencies`** derives what a sealed repository actually ships and what the
  reviewed code reaches, from its own manifests, lockfiles, build configuration and build output.
  Readers cover Maven, Gradle, npm, Go and Python (`requirements*.txt`, `pyproject.toml`,
  `poetry.lock`, `Pipfile.lock`). Composer, Bundler, Cargo, pnpm and `Pipfile` are on the recognized
  roster with no reader, so each is reported as an `unparsed_ecosystem` gap — that ecosystem is present
  and NOT analyzed, which never collapses into "no dependencies here". Container base images are not
  read at all. Every value is an `unverified_*` observation with a named origin (`source_manifest` or
  `build_output`); there is deliberately no vocabulary member that reads as "not shipped", because
  build files do not settle what a built artifact contains. `--structural-index` correlates against
  the import index, and a missing index reports `unverified_reachability_unindexed` rather than
  claiming a component is unreferenced. `--scan-report` correlates an existing Trivy/Grype report
  against the derived picture without letting a scan row change a shipment observation. Paired with
  a new `dependency-analysis` skill rather than stretching the mobile or OSINT skills.
- **Framework registration is recorded separately from surface type.**
  `vigil assess record-surface --framework-registration <kind>` names how a host framework registers
  a plugin — service provider, HTTP endpoint, request interceptor, event listener, template
  override, scheduled task, CLI command, data-model extension, or configuration binding. These are
  architecture facts, orthogonal to security semantics, so the shared cross-engagement surface
  taxonomy is unchanged.
- **`vigil assess agent bind-client-handle`** records which client session a dispatch is actually
  running as, after launch, when the handle exists. Bindings are append-only and superseding, and
  render in `agent list` and the resume brief, so mid-flight messaging no longer depends on a
  hand-maintained mapping the operator keeps in their head.
- **Orphaned analysis leases are visible and recoverable.** `code-dispatch list` reports item-level
  heartbeat age and `--stale-minutes`; `code-dispatch adopt-lease` performs an audited
  compare-and-swap handover that keeps the dead attempt's accumulated receipts and refuses a lease
  that is still live; `code-dispatch progress` reports one item's accumulated state; and
  `code-coverage` lists open leases oldest-first with how long each has been silent and how many
  receipts a reset would discard. `reset-stale` remains, but it is no longer the only option, so
  recovering a died-mid-file dispatch does not mean redoing durable work.
- **FreeMarker templates are structurally indexed.** `.ftl`, `.ftlh` and `.ftlx` now reach language
  detection and a FreeMarker-aware lightweight extraction covering interpolation sites, escape
  directives, output contexts, attribute and form-field positions. The extension decides the
  auto-escaping ambient, because FreeMarker's own output-format-by-extension rule makes `.ftlh`
  HTML and `.ftlx` XML; a bare `.ftl` inherits an application default this repository cannot see,
  so it stays reported as unescaped until a directive says otherwise, and an explicit `<#ftl>`
  header wins over the extension either way. Results are degraded advisory signals by construction
  and never read as proof that a site is safe. `.kts`, `Pipfile`, `Pipfile.lock` and `poetry.lock`
  also reach detection, so they stop landing in the unknown-language bucket that made them invisible
  at ingest.
- **PowerShell is structurally analysed, not merely detected.** `.ps1`, `.psm1` and `.psd1` reached
  language detection but had no extractor, so every one of them fell through to the streaming
  scanner. An extractor now reads `function`, `filter` and `workflow` declarations with either
  signature form PowerShell accepts — a C-style parameter list after the name, or a `param()` block
  as the body's first statement — treats a script-level `param()` as the script's own argument
  surface, and follows `Import-Module`, `using module`/`using namespace` and dot-sourced
  `.ps1`/`.psm1` as import edges, because dot-sourcing is how most PowerShell codebases share
  helpers. Comment-based help (`<# ... #>`) is skipped: its `.EXAMPLE` sections quote the very
  cmdlets the sink table flags, so a documented script was reading as a vulnerable one. One sink
  table — dynamic evaluation, process execution, URL fetch, download-piped-to-execution, hardcoded
  credentials — serves both the structural extractor and the bounded streaming scanner, so the two
  paths cannot report the same file differently.
- **PHP 8 attributes are captured on both index paths.** Attributes are the route and authorization
  table of every modern PHP framework, and `_ENTRY_ANNOTATIONS["php"]` is matched against a
  function's `annotations` — so with them dropped, a controller action could never become an entry
  point. The structural indexer now reads each `attribute_list` verbatim as `#[...]`, and the
  streaming scanner stops reading a leading `#[` as a PHP line comment, which had removed the whole
  line from every detector below it.
- **`vigil doctor` and the engagement preflight check for ripgrep.** The row is advisory
  (`required=False`), like `fzf`: useful, not universally installed, and irrelevant to a web
  engagement. It matters on the code track — `agent/shared-constraints-code.md` ranks `rg` second
  only to the ctags index and uses the ripgrep-only `--type` flag, and the Codex and Goose hunters
  have shell only, so on a host without it every search exits 127, which a specialist reads as "no
  results" rather than "tool missing". That is the failure shape that makes a coverage tool report
  clean coverage of code it never read. Nothing else checked: ripgrep is in no dependency manifest
  and ships only in the runtime image, which code analysis does not use. The row says what is lost
  rather than leaving a bare `MISSING`.
- **Blade templates are structurally indexed.** `.blade.php` resolves to a new `blade` language
  through the first compound-suffix lookup in the language table; `Path.suffix` returns only `.php`,
  so every Laravel view was handed to the PHP grammar, which reads `{{ }}` and `{!! !!}` as inline
  text and reported nothing. The extractor runs the HTML pass for forms, scripts and inline handlers,
  then reads Blade's own constructs: `{!! !!}` is an `unescaped_output` sink, `{{ }}` a
  `template_interpolation` one, `{{-- --}}` is skipped, and `@{{ }}` is excluded because it is
  Blade's escape for a client framework. Each sink records `unverified_escape_observed` or
  `unverified_no_escape_observed` — an observation, never a clearance, because `e()` escapes for HTML
  text and not for an attribute or a script body. `@extends`/`@include*`/`@component`/`@each` build
  the view graph and `@section`/`@yield` export slot names. The backend counts `blade` as
  structurally analyzed, and `.mts`/`.cts` now reach TypeScript.
- **PHP closures, route files and magic methods reach the index.** `_CALLABLE_NODE_TYPES["php"]`
  named anonymous and arrow functions but nothing extracted them, so a
  `Route::get('/x', function () {...})` handler and every line of its body were read by no detector
  at all; and top-level `Route::` / `$app->` / `$router->` in `routes/*.php` never reached the
  entry-point pass, which ran only inside function bodies. Closures now extract under the name of
  whatever binds them, file-scope route patterns are matched with the duplicate suppressed when a
  named handler already covers the line, and eight more magic methods (`__unserialize`, `__serialize`,
  `__sleep`, `__toString`, `__invoke`, `__call`, `__get`, `__set`) register as entry points, because
  an attacker-controlled `unserialize()` lands there and the runtime, not the application, is the
  caller. Request-input detection widened past the superglobals to the request object (`$request->`,
  `Input::`, `Request::`), which is what idiomatic Laravel, Symfony and CodeIgniter write.
- **A file whose index found no callable now reports what it could not measure.** A `routes/web.php`,
  a Blade view or a module-level script parsed cleanly, bounded no scan span, and reported
  `security_sinks: []` — an unmade measurement rendered as a clean negative, which ADR 0015 forbids.
  Such a file now reports `analysis_status: degraded`, `degradation_reason: unscanned_function_scope`
  and `unavailable_dimensions: [call_sites, dataflow, security_sinks]`, adding `entry_points` when it
  found none of those either. A file with no scannable line at all is excluded, because there the
  empty result genuinely is the measurement. Truncation still owns the reason when both apply. The
  backend rejects a tree-sitter file claiming complete function-scoped coverage with zero callables
  but non-zero sinks or entry points, requires a whole-file span to prove manual review of one, and
  stops counting them as "nothing to verify" — which is what let a zero-callable critical file close
  with no review proof at all. `code-coverage`'s structural verification names them per file.
- **LLM and agent API endpoints route to a skill of their own.** A new `llm_api` URL bucket (weight
  40, 20 parameter keys, five path fragments including `/completions`, `/v1/messages` and
  `/embeddings`) maps to `prompt-injection`, and a new `agent/skills/llm-api-testing/SKILL.md` covers
  dialect fingerprinting, system-prompt disclosure, direct and indirect injection, tool-calling
  actions, tenancy boundaries and cost abuse. The taxonomy declared the `ai-ml` family from the
  start, but no bucket mapped to it: `/v1/chat/completions` scored only `25 gf:api-versioning` and a
  bare `?prompt=` scored zero. The skill had to ship with the bucket, because both `ai-ml` classes
  previously resolved to the mobile `ai-ml-on-device-security` skill alone. The bucket is declared
  last in the weight-40 run, so no pre-existing row re-clusters; the classifier revision is stamped
  `2`, so re-score an existing engagement with
  `vigil assess work-buffer reclassify --reclassify-stale`.
- **An `infrastructure` vuln-class family.** `privilege-escalation`, `network-exposure` and
  `supply-chain` were emitted by the Dockerfile and shell extractors with no canonical home, held in
  a test exception so the "no invented class" invariant could stay enforced for everything else.
  Each remap was wrong one level up: `injection` presumes untrusted input reaching an interpreter and
  an `ADD https://…` has none, `access-control` presumes a principal and a routed function and a
  `USER`-less Dockerfile has neither, `debug-exposure` means an HTTP endpoint and `EXPOSE 5432` is a
  declared port. `NETWORK-EXPOSURE` joins the Kali technique enum; the other two are probe-exempt,
  because they are read out of a Dockerfile or CI config and a real breakout is `EXPLOIT-CHAIN`.
- **A finding can be parked as owed a runtime proof.** `finding verify --status
  pending_runtime_proof` marks a source-bound finding whose static evidence holds but whose live PoC
  has not been run. It stays out of exploit candidates — proof owed is not proof — which is exactly
  why it used to be invisible to the phase that would prove it. `vigil assess exploit review` now
  prints a `Runtime proof owed` section beside the candidates, with the attach sequence
  (`proof-run start` → `proof-receipt create` → `finding verify --proof-receipt-id`) and, when any
  owed row is `file:`-bound, the `engagement add-track web` / `add-host` prerequisite — the host
  comes from the program authorization, never from the finding's own target-derived text. Proof
  attaches to the same finding as a receipt: `finding relocate` would reset the marker and drop the
  row out of `finding list --holding`, and `contract finding relocate` now says so.
- **The delivered report renders the recorded attack path, not just its narrative.** Appendix A
  carried each chain's prose only; the `assessment_attack_chain_links` rows existed but never reached
  the export. Steps now render as a numbered list, re-sorted by insertion order because the schema
  carries no step-order column, with each `finding` step linking to that finding's own section by
  severity, report ID and title. Links with any other `relation` render as labelled supporting
  context rather than being dropped, since `relation` and `entity_kind` are free-form text. A step
  whose finding is not in the report is named verbatim, which can only happen in a draft — readiness
  blocks it in a final. Link notes render as plain text, never Markdown (ADR 0018). A chain with no
  recorded links renders exactly as before.
- **`vigil engagement add-host` works on a `code` engagement.** A code engagement may legitimately
  declare the hosts its source talks to (ADR 0021), and declaring a root is the authorization event
  itself (ADR 0018), so it cannot be gated on already having one. It prints a notice that this does
  not activate the web track and names `vigil engagement add-track <key> web` (ADR 0022). `blue` is
  still refused.
- **Contracts say what the caller may actually set.** `vigil assess contract finding update` renders
  the 24 patchable top-level fields; it previously set `details_schema_name`, so the one section a
  patch author needs rendered empty while 15 KB of `details` keys that `finding record` already owns
  rendered in full — and the model forbids extra keys, so a name missing there was a name no agent
  could discover. A new backend test pins the roster to `FindingPatchRequest`. The required-fields
  section now lists only what the author supplies, subtracting the helper defaults: `finding record`
  fills ten of its twelve required names itself, and named `verification_status` as required two
  sections below the default that calls `unreviewed` the only record-time value it accepts.
  `vigil assess contract code-dependencies` documents all 18 gap codes, where a prose note named
  eight.

### Changed

- **The stale working-root warning fires once, at engagement start.** It used to repeat on every
  `vigil assess` passthrough, which trains an operator to ignore it and says nothing new each time.
  Per-dispatch instruction identity — installed revision plus exact operator and specialist hashes —
  already records staleness durably for every dispatch, so the repetition added noise, not evidence.
- **`total_assigned_input_local_tokens` was redefined under a stable name.** It used to be standing
  prompt tokens plus emitted source tokens; it is now emitted source alone, because a role's
  standing prompt load is authored markdown this workflow does not decide and `vigil assess
  prompt-census` measures it advisorily instead. The calibration baseline therefore moves from
  252,884 to 2,354 — roughly 99% of the old figure was standing prompt prose, not a hundredfold
  efficiency gain. Any baseline compared across this release is comparing two different quantities.
- **A delivered report carries only the fields its template renders.** The exported HTML is the one
  Vigil artifact whose reader is the client rather than the operator, and its data node embedded
  whole SQL rows: `SELECT *` on `assessment_findings` carried `notes`, `provenance`, the raw
  `details` object and the `submission_*` columns into every delivered report, none of which the
  template renders and all of which a reader sees with View Source. Five field rosters in
  `report_export.py` now project each record, and a field is copied verbatim or dropped outright —
  nothing is masked, truncated or reduced to a shape, so this is not the masking ADR 0019 forbids.
  The narrowing lives at the delivery boundary and never inside the projections, which also back
  `GET report-findings` and `vigil assess finding report --json`, where the operator must keep every
  column. `report_readiness` is draft-only for the same reason: a final export cannot be produced
  while blockers stand, and its advisories quote internal QA doubt about the engagement's own
  evidence.
- **Traffic-shaping ROE commands are gated on declared hosts, not engagement type.** Required
  headers, out-of-scope carve-outs and the rate limit now refuse until the engagement declares an
  in-scope host, and accept once it does — so a `web` engagement with no hosts no longer takes them,
  and a `code` engagement that declared one does. The predicate reads `backend_hosts` as well as
  `hosts`, because an Android engagement keeps its live API roots there while `hosts` stays empty for
  the artifact-only surface.

### Fixed

- **A live command proof can now actually back a terminal verification.** Three defects in the
  runtime-proof path compounded, and between them no `vigil assess kali` run could ever produce a
  healthy proof receipt. The audit row is opened *before* the command runs, so the artifact rows for
  its stdout/stderr files were minted while those files did not exist yet and stayed indexed as
  absent; finalize — the first moment the bytes exist and have been hashed — never re-read them, so
  every receipt citing an audited run was born `missing` until someone ran `artifact refresh` by
  hand. Past that, a stream measured at zero bytes records no digest, and the empty digest was read
  as "not measured" rather than as the measurement it is, which left almost every successful run
  permanently `stale` on its empty stderr. And `proof-receipt create` asserted the response echoed
  the requested `evidence_health`, so an honest backend downgrade surfaced as "the write may have
  committed" on a write that had committed correctly. Finalize now indexes the files the run wrote
  (host-exec keeps its own verified-descriptor path), a zero-byte stream is healthy when the
  retained file is also zero bytes and stale when bytes appeared after the fact, and the CLI holds
  only a caller-*declared* health to the echo — reporting a measured downgrade as a WARN naming the
  consequence.
- **`vigil assess contract finding verify` now states the code-snapshot requirement it actually
  has.** The contract described `provenance.code_snapshot` as needed "only when a code verifier
  binds/rebinds", but the backend requires it on *every* verification of a `file:` finding: the
  author's stored binding attests that the author read those bytes and cannot also attest that the
  verifier did. Omitting it is a 400 and the write does not land. The verb now says so, with the
  failure mode and its remedy.

- **A Codex specialist starts from its dispatch message, not the operator's transcript.**
  `agent/.codex/config.toml` now pins `multi_agent_v2 = false`. Codex's default spawn path
  (`multi_agent`) starts a child from the dispatch message alone when `fork_context` is omitted;
  `multi_agent_v2` replaces that field with `fork_turns`, which defaults to `all` — the parent's
  entire history. Vigil passes neither field, so the flag alone decided what a specialist inherited,
  and an operator whose own `~/.codex/config.toml` enabled v2 silently forked the operator
  transcript into every dispatch. That is exactly the anchoring `agent/phases/code-phase-2-hunt.md`
  forbids between the Phase 2A pass and the 2C dispatch that re-derives it independently. Codex
  ships the flag off; pinning it here also overrides a global that turns it on.
- **`vigil assess prompt-census` measures what you think it measures.** It reported a single
  standing-load figure for `exploit-developer` and `source-analyzer`, both of which declare two
  mutually-exclusive constraint bundles and load exactly one — so the number it gave was never any
  real dispatch's load. It now reports one variant per track and leaves the single figure null,
  because a single figure is the bug. Detection is structural (a MANDATORY bullet naming no file of
  its own, followed by sub-bullets that each name one), so it survives a prompt rewrite rather than
  keying off a particular phrasing. The operator cores are measured too, as their own category —
  `agent/operator-core.md` is the largest prompt in the repo and was invisible to the tool that
  exists to size prompts. The output now names the tree it measured and says so on stderr when that
  is not the checkout you are standing in, which is the default whenever `vigil` runs from an
  installed working root.
- **`vigil oob start` refuses an install that never reserved a relay slot**, instead of warning and
  then starting on the shared route. Starting was what created the `frpc.toml` and route marker that
  made the next `vigil install` pin the legacy route rather than allocate — so following the
  warning's own remedy, in the order it gave it, was exactly what stopped the remedy working. The
  refusal is narrow: it fires only when there is no routing record **and** no prior OOB state. An
  install whose callbacks are already live on the shared route is unaffected and still starts, which
  is the population that route exists for. `vigil up` skips OOB in the same case rather than failing
  the whole bring-up.
- **Checkpoint references cannot forge a heading.** `operator-checkpoint show` joined finding slugs,
  dispatch agent ids, command-run ids and artifact ids straight into the render, so a newline inside
  an `agent_id` — which the backend accepts — reached column zero and could impersonate a section in
  a document agents read as instructions. The containment the resume brief already used is now a
  shared helper applied to both, and the same audit closed 29 further rows in the resume brief
  carrying persisted, length-bounded columns. Containment is lossless: every original character is
  preserved and only the rendering indent is inserted, so clean data renders exactly as before.
- **A resolved decision says what was decided.** The resume brief reported `[resolved]` and then
  printed the original payload, never the resolution the backend already carried — so an operator
  rehydrating after compaction knew a question had been settled but not how, and could contradict it.
- **The latest handoff is found before the scan cap, not after.** `latest_handoffs` sorted by
  checkpoint time over a set already limited to 1,000 rows ordered by immutable creation time, so
  past that depth an older specialist that had just checkpointed could not appear in the section
  named "latest". The ordering now happens in the query. No schema or index change was needed, and
  the default ordering every other consumer relies on is untouched.
- **A reference repository can no longer be handed analysis work.** Three paths let it happen:
  the queue-claim query never filtered on `repo_role`, so re-ingesting a repository with
  `--role reference` left its existing pending rows claimable (the role change does not advance
  the generation, by design); `queue_stats` counted those rows, so the "is the queue drained"
  signal the dispatch loop reads could never reach zero once they were excluded from claiming;
  and a metadata refresh reopened file review on a reference repository with no demotion involved
  at all, manufacturing fresh claimable rows. The role is now read live at every claim site rather
  than written onto rows, so promoting a repository back to `analysis` restores its obligations
  with nothing to undo. `code-dispatch list` still shows every row and now carries `repo_role`:
  a listing that silently dropped rows would hide the exact IDs an operator needs, and there is no
  adversary here to hide them from.
- **Dependency reachability is scoped to the module that declared the dependency.** It scanned
  every indexed file in the ecosystem, so in a multi-module repository a dependency declared in
  `a/package.json` but imported only by `b/` was reported as referenced from `a` — and, worse, a
  module with no index of its own was reported `unverified_no_reference_observed` because a
  *different* module happened to have one. That is a negative manufactured from absent evidence,
  which this vocabulary exists to make impossible. A declaration now reaches its own module and
  everything beneath it (an aggregator POM, a workspace root), never a sibling; build-output
  records still search the whole tree, because their bytes are in the artifact regardless of which
  module ships them.
- **A malformed structural-index artifact counts as unindexed, not as unreferenced.** An artifact
  that existed and parsed as JSON but was not an object with an `imports` list — `{}`, a truncated
  write, an older record shape — kept its `complete` status and silently supplied no imports, so
  every component came back `unverified_no_reference_observed`. It now degrades to a gap naming
  what was wrong, like the missing-artifact case beside it. A corrupt *per-file* artifact also no
  longer kills the whole command: that is a hole in one file. An unreadable *manifest* still exits
  non-zero, because an inventory you cannot read means nothing is known about what was indexed.
- **The operator prompt stops pre-explaining gates that already explain themselves.** An operator
  cannot skip a phase-exit gate — `transition-phase` refuses and its refusal carries the reasoning —
  so `agent/operator-core.md` no longer restates the variant-pass, chain-construction, depth,
  intel-closure and severity gates ahead of time, nor the dispatch, handoff and checkpoint semantics
  that `vigil assess contract` renders from the code. Each cut leaves a pointer naming the command
  that teaches it, one hop, not a paraphrase. 4,454 bytes off every operator session. Less than
  hoped: several passages that looked like duplication turned out to be the canonical source that
  other files cite, and the reference guide for dispatch fields explicitly names the operator core
  as its own source of truth.
- **Blue standing prompts stop restating rules they do not own.** `agent/rules/triage.md` and
  `agent/shared-constraints-blue.md` carried duplicate copies of writing discipline, the
  resume-hydration command block, confidence labels, UTC discipline and the reference block — in
  several places character-for-character identical to the file that owns them. Each now points at
  its owner and keeps only the blue-specific delta: `shared-constraints-blue.md` is 3,029 bytes
  smaller and `triage.md` 316 bytes larger, a net 2,713 bytes off the standing load of every blue
  dispatch.
- **The operator prompt no longer misstates the CVSS severity bands.** It gave them as
  `high >= 7.0`, `medium 4.0-6.9`, `low < 4.0` — omitting `critical` and `info` entirely, so an
  operator following it banded a CVSS 9.5 finding as `high`. `report_readiness.py` has always
  computed `critical >= 9.0` and `info >= 0.1`, and its blocker states the expected band per
  finding. The prose also named the wrong verb for correcting a mismatch. Found while removing
  prose that restates what a gate already refuses.
- **A pointer return type no longer hides a whole C function.** `char *copy_name(...)` parses as
  `pointer_declarator(function_declarator(...))`, and the C branch read only the direct children of
  the declarator field — finding neither the name nor the parameters, so the function was dropped
  from the index entirely, and because sinks are attributed by scanning function bodies, every sink
  inside it went with it. The byte-identical `.cpp` indexed correctly the whole time, because the
  C++ branch already walked the declarator chain. `array_declarator` and `parenthesized_declarator`
  are covered on the same walk, and a function returning a function pointer resolves to the
  innermost named declarator. This was the commonest shape of allocation helper, in the most
  memory-unsafe language Vigil supports.
- **PHP's inclusion constructs are `lfi`/`rfi`, not path traversal.** `include`, `require`,
  `include_once` and `require_once` sat in the `file_path` sink kind, which carries
  `path-traversal`. They load and *execute* the named file, so a caller-controlled path is `lfi` —
  and `rfi` wherever `allow_url_include` is on — and those route to a different skill. They are now
  their own `file_inclusion` kind carrying `["lfi", "rfi"]`. The patterns moved verbatim, so the
  audited slice is still 89: `file_path` went from 38 to 34 and `file_inclusion` holds the four. It
  was the coarser answer for the commonest PHP RCE shape there is.
- **A PowerShell file no longer fails the whole structural index.** `code-index` has emitted
  `powershell` for `.ps1`/`.psm1`/`.psd1` since the language table was written, but the backend's
  canonical language set never listed it, so `code-index sync` rejected the entire submission with
  `unsupported structural index language` for any repository containing one. A drift test now
  fails if the agent side can emit a language the backend will not accept. Acceptance was only half
  of it — those files still had no extractor, and reached the streaming scanner rather than a
  structural one; see the PowerShell extractor under Added.
- **Cold image builds no longer die at 20s.** `vigil up` and `vigil install` threaded one bounded
  runner through both fast metadata queries and image builds, so the bound that makes a wedged
  daemon fail fast killed every first-run Kali build and swallowed its progress output.
- **Codex hooks stay live.** Codex gates project-local hooks behind a per-hash trust review;
  declining it started a normal-looking session with Vigil's hooks disabled and no indication
  anywhere in the UI — so the activity log an engagement's audit trail depends on, and the
  session-end receipt, were silently absent. Generated Codex launchers now vouch for the hooks Vigil
  itself wrote.
- **`vigil quickstart` no longer reports `[ok] docker`** on a host with the client binary and no
  running daemon; it shares `vigil doctor`'s daemon probe.
- **A relay slot is allocated whenever OOB is configured**, not only by the install that first
  creates the root. Configuring `oob.domain` after installing and re-running `vigil install` now
  reserves a dedicated slot instead of pinning the globally shared legacy route.
- **A quoted-empty provider key (`KEY=""`) reads as unset** in the launch preflight and the
  generated launchers, and a real quoted key no longer exports its quote characters.
- **`vigil up` no longer kills the proxy it just started.** Starting a stopped mitmproxy passed the
  streaming build runner as `start_proxy`'s only runner, and that runner returns empty stdout by
  design — so a current image read back unstamped and was rebuilt, and the post-start `docker ps`
  check saw no container and ended the command claiming the proxy had exited.
- **`vigil oob start` warns when no relay slot was ever reserved**, instead of silently resolving
  the shared 53/8443 route that another install in the same state also resolves. The documented
  setup sequences now include the `vigil install` that reserves the slot.
- **`code-ingest` churn rankings cover analyzed files only.** The "highest-churn files" block
  ranked over full git history, so it listed files the same run had just reported as skipped —
  minified bundles, font assets, lockfiles — and the same contamination reached the `git_churn`
  metadata stored in the backend.
- **`code-index build` repair hints name a usable path.** The `structural_index_stale` blocker
  printed a `<snapshot-path>` placeholder, but the command binds to that snapshot's `source/`
  directory and refused anything else without saying which path it wanted.
- **A blank operator-checkpoint intent is refused.** `--intent "   "` was stored and superseded the
  previous checkpoint, so resume hydration lost the operator's real save-my-place note.
- **Two rebuilds that were never needed are gone.** `vigil install` rewrites every managed file
  regardless of content, and two checks read those fresh timestamps as work: `/readyz` reported
  `restart_required` for a byte-identical backend, and `vigil up` ran a full `npm run build` for a
  byte-identical frontend. Both now compare contents.
- **`root=$(vigil install ~/vigil)` captures only the path.** The post-install summary shared stdout
  with the install root; it now goes to stderr.
- **The OOB "no relay route" notice no longer misinforms.** It told every install, including a fresh
  one, that the root keeps a shared legacy route — state a new root does not have. That sentence now
  appears only for a root actually running OOB on the shared 53/8443 route.
- **CLI output wraps on a terminal without changing what a pipe sees.** Piped output stays one
  record per line, no escape codes, no more bytes than before.
- **A live but unreachable backend is no longer reported as stopped.** Every failed `/readyz` probe
  read as `not-running`, the one verdict the install summary drops entirely — so a wedged or
  slow-to-answer orchestrator could vanish from the summary right after an install replaced the code
  it is running. A refusal, a timeout, and an unreadable answer are now separate, and only local
  process evidence (the pidfile, and the port the probe actually used) can establish `not-running`.
- **The post-install verdict compares against the source it installed from, and its remedies name
  that source.** `vigil install --source X` resolved X, copied its bytes, and then let the freshness
  check rediscover a source through environment, config, the running package, and the current
  directory. With two checkouts on the box the just-installed root could be reported stale against a
  tree it was never installed from. Every consumer that compares against a checkout — the CLI binary
  AND the working root — now receives the one resolved source, and the commands they print are
  pinned to it (`vigil --source X install`, shell-quoted) instead of a bare `vigil install` that
  re-runs the same discovery. An operator who does exactly what the summary says can no longer
  overwrite a just-synchronised working root from the wrong checkout.
- **The clean install summary no longer asserts a cause it did not measure.** It said the install
  had changed only files that are read live; nothing recorded which files the install changed, and a
  backend-source upgrade performed while the backend is stopped reaches the same branch.
- **Backend freshness sees modules imported after startup.** A cross-tree module first imported
  lazily was in neither the startup snapshot nor the declared input set, so a later install could
  replace it on disk while the process kept running the old loaded code — invisibly, for the life of
  the process. A `sys.meta_path` recorder now digests each install-root source file as it is
  imported, so the comparison uses the bytes the import actually read.
- **The correlation wording lint sees negation, not proximity.** Any negation within 60 characters
  cleared the guard, so "should not be overlooked because it correlates callbacks" and "is not
  preferred, but it correlates each hit" both passed while asserting exactly what the contract
  forbids. The negation now has to govern the correlation verb.
- **`/vigil-resume` stops probing optional files with a failing command.** The Codex branch ran
  `ls -l RESUME.md COMPACT.md`, which exits non-zero whenever either optional file is absent — next
  to instructions that make command failure meaningful. It now reports present/absent per file, as
  the Claude branch already did.
- **Structural Coverage Debt scales past a handful of files.** One exact line per degraded,
  unsupported, or truncated file put more metadata than source in front of a specialist on a
  repository with hundreds of unindexed files, and contradicted Phase 2's own compression rule.
  Above 25 files the exact lines move to a generation-bound ledger the dispatch cites by path and
  digest, with counts, an extension breakdown, and security-relevant files still inline.
- **Hunt readiness requires a populated queue.** Phase 1 recorded classifications and copied the
  file-analysis artifact but never loaded the backend queue, and hunt readiness returned before any
  queue accounting — so an operator could enter hunt with every admitted file classified and zero
  queue rows. The artifact is planning input; the backend queue is the durable ledger, and the gate
  no longer conflates them. Phase 1 now loads the queue on return.
- **`code-dispatch requeue-triggers` applies per target and accounts exactly.** One blocked target
  used to roll back every other valid target in the same transaction, and `total` counted trigger
  inputs while the outcome buckets counted target files, so they could not sum. Each target now
  commits inside its own savepoint, blocked targets are reported with reasons and exit nonzero, and
  `input_trigger_count` is separate from `target_count` whose buckets sum exactly.
- **`requeue-triggers` accepts the rows `list-triggers` prints.** It read only `file_path`, so the
  `id`/`target_file_path` objects that `list-triggers` emits became empty selectors the backend
  silently skipped, and a scalar ID raised `AttributeError`. One strict selector model now covers
  both, rejects scalars and selector-less objects before any write, and emits one outcome per input.
- **A requeued file keeps its batch theme.** Trigger requeue defaulted the target to
  `cross-file-trigger` and rewrote pending rows to it, so requeued work vanished from its lane's
  filters. Provenance stays in `queue_mode`, which is now a first-class filter on list and fetch.
- **`artifact register` no longer reports failure after a committed write.** The response validator
  compared the backend's canonical path against the original spelling, so `./tools/a.md` or an
  absolute alias was rejected after a valid committed response — the dangerous
  write-succeeded/report-failed mode. Paths are canonicalized once before the POST, and a response
  that names the canonical artifact without a usable id now reports `committed but response
  invalid` instead of inviting a blind retry.
- **`vigil assess contract` renders enum domains and nested object keys.** Intel contracts listed
  top-level field names only, so the accepted values for fields like `validation_status` and the
  legal keys inside objects like `provenance` were unreadable from the one surface that is supposed
  to be the canonical authoring shape. One schema-aware renderer now covers every schema-backed
  contract, including a populated `reviewed_spans` example that shows `file_id`, not `file_path`.
- **Dispatch model/reasoning warnings stopped drowning real failures.** Three warnings fired per
  dispatch, one of them on every dispatch regardless of input; the caller-fixable case is now one
  warning and the permanent fact is stated once in the `agent start` contract.
- **The code pre-dispatch checklist covers model and reasoning.** They are required by the shared
  operator core and were missing from the code-specific checklist, so the omission surfaced only as
  repeated warnings on the stderr channel that real failures use.
- **Three classifier call sites scored rows with half the classifier disabled.** `ingest_arjun.py`,
  the `work-buffer` retype pass and the `coverage_checks.py` fallback each called the classifier
  without the `url` / `source` / `live_status` context the boost layer and the full-URL regex pass
  need. Arjun-discovered parameters were under-scored by up to 30 and could never reach
  `cloud_metadata` or `object-storage` at all, whose markers live in the URL authority and query; the
  retype pass disagreed with the classification it was replacing.
- **A bare `?query=` no longer clusters as GraphQL.** `query` is a graphql key and outranks `sqli`,
  so `/api/v2/products/search?query=shoes` read as `45 gf:graphql`. The match is now suppressed
  unless something corroborates it — a graphql path fragment, a second unambiguous key
  (`mutation`, `subscription`, `operationName`, `variables`), or a typed graphql body. It is a
  re-rank and not a drop: the row keeps its `sqli` and `xss` matches and becomes `40 gf:sqli`.
- **An image upload no longer clusters as path traversal.** `img_traversal` shares `image`, `photo`,
  `thumb` and `thumbnail` with `upload_fields` and outranks it 35 to 30, so an avatar upload — the
  exact shape the upload shadow exists for — clustered `gf:img_traversal` while the byte-identical
  `file`-keyed row clustered `gf:upload_fields`. Only the cluster pick moves; `img_traversal` stays
  in the reason chain.
- **A PHP session check was detected by a pattern that could never match.** The auth signal was
  `\b\$_SESSION\b`, and the leading `\b` demanded a word character immediately before the sigil,
  which valid PHP never writes — so it matched only `a$_SESSION` and every `$_SESSION` guard read as
  no auth signal at all.
- **`resume-brief` finds every stale dispatch and invents no handoff gaps.** Both scans stopped at
  1,000 rows. The dispatch scan was newest-first, so the cap cut the oldest rows — precisely what
  stale means — and past 1,000 in-progress dispatches the brief reported zero stale while
  `reconcile-stale` flagged them. The handoff map was a top-1,000 page, so a live specialist whose
  handoff sank below the cut was reported as a gap that did not exist: an instrument reporting a
  measurement it never made. Both now read exhaustively in one connection, so the `*_count` totals
  are real, and the displayed lists are ordered oldest-first — the ten longest-overdue dispatches
  rather than the ten that just crossed the threshold.
- **The `code_leads_unresolved` blocker names a command that shows the rows.** Its remediation
  pointed at `code-lead list --lead-status open`, but the blocker counts bindings noted `open` or
  `in_progress` and does not exclude superseded ones, so the narrower read dead-ended the operator on
  a gate that was still firing.
- **A copied reproduction is the request the finding recorded, byte for byte.** Three edits had crept
  between the record and the `curl` a reader pastes. The synthesized command carried curl's own
  `User-Agent` and `Accept`, plus `Content-Type: application/x-www-form-urlencoded` whenever a body
  was attached — three headers the recorded request never sent, each able to change which parser,
  body binder, router or WAF rule the request meets (a GET-with-body parser differential turns on
  whether a `Content-Type` arrives at all). Each is now suppressed with `-H 'Name:'` unless the
  record supplies it, matched case-insensitively and untrimmed, so a recorded ` User-Agent` — the
  leading space IS the smuggling probe — does not travel beside curl's default. The method is
  emitted as recorded rather than upper-cased, because a case-sensitive-routing probe records `get`
  on purpose. And the observed response is emitted with its trailing bytes intact: stripping them
  left a report asserting a whitespace-sensitive differential while deleting the difference, and a
  response body that is nothing but whitespace is now a recorded body rather than an absent one.
  `Host` and `Content-Length` are untouched — curl derives those from the URL and the recorded body,
  so they reproduce the record rather than adding to it.
- **Copy as Markdown carries the two fields that set a finding's severity.** `auth_context` and
  `evidence_type` render in the Full Report and in the frontend drawer but were dropped from the
  copy, so a high-severity claim read as unauthenticated and wire-observed when it may have been
  neither: the reader who copied a finding got a stronger report than the reader who read one. Both
  are labelled and formatted exactly as the report labels them, so the two cannot drift.

### Security

- **A target's response body can no longer break out of the evidence block of a delivered report.**
  Every fenced block in the Markdown export and in Copy as Markdown opened with a fixed ` ``` `, and
  CommonMark closes a fenced block at the first line whose fence is at least as long. The content
  inside is target-derived — `evidence_detail`, a recorded `body_excerpt`, `poc_code` — so a response
  body containing a ` ``` ` line escaped the block, and every byte after it became live Markdown in a
  document the operator was about to paste into a submission form: the target writes headings, links
  and plausible report prose beside the operator's own words, and the reader cannot tell which is
  which. That is the untrusted-target-text boundary ([ADR 0018](docs/adr/0018-target-derived-text-is-untrusted-data.md))
  failing in exactly the direction it exists to prevent, in the one Vigil artifact whose reader is
  the client. Nothing is escaped, trimmed or removed to fix it — ADR 0019 rules that out and the
  evidence has to stay byte-exact — the delimiter outgrows the content instead: one backtick longer
  than the longest run present, which by construction no run inside can match.

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
  [authentication reference](docs/authentication.md).
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
