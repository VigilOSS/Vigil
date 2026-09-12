# Assessment CLI reference

`vigil assess` is the assessment surface. Most of it is **agent-facing**: the
operator prompt and the specialist roles call these verbs to record and read
canonical engagement state. This page is the reference for that surface, plus the
handful of verbs an operator drives by hand.

`vigil assess` delegates to `agent/scripts/assess.py`, a `uv run --script`
entrypoint with inline `tree-sitter` dependencies, so the first invocation
installs the bundled parser packages automatically. No separate
`pip install tree-sitter ...` step is required, but `uv` must be on `PATH`.

Run `vigil assess --help`, or `vigil assess <verb> --help`, for the full flag set
on any verb.

---

## Resuming an engagement

```bash
vigil assess resume-brief [--finding <slug>] [--q <text>] [--agent-id <id>] \
                          [--since <iso>] [--max-age-hours N]
```

One bounded JSON + markdown operating picture: your current operator checkpoint,
finding queues, a recent-decisions ledger, surface and work-buffer rollups, stale
dispatches, handoff gaps, the newest dispatch and handoff rows, command-history
matches, indexed artifacts, and an intel section. Capped lists print
`… showing N of M` — read the M before assuming the list is complete.

The JSON includes `operator_checkpoint`, `recent_decisions_count`,
`dispatches.recent_dispatches_count`, and `dispatches.latest_handoffs_count`. Each
count is the total represented by its corresponding capped list after any
applicable query filter, not merely the number of rows rendered.

`resume-brief` is a **read**. It observes abandoned command runs, jobs, and owned
host processes without writing, and when it finds any it prints a WARN naming the
reconciling command:

```bash
vigil assess kali sweep-orphans --scope all
```

The full resume contract is in [`agent/rules/resume.md`](../agent/rules/resume.md).

### Operator checkpoints

```bash
vigil assess operator-checkpoint record --intent "what I was about to do and why" \
    [--finding <slug>] [--agent-id <id>]
vigil assess operator-checkpoint show --all
```

A checkpoint stores only **references** to rows the backend already holds —
unknown finding, agent, command-run, or artifact ids refuse the write and name
them. `--intent` is the single free-text field, recorded and rendered as
**UNVERIFIED operator intent**, never as a finding and never as evidence.

It is append-only. Correct a wrong checkpoint by recording a new one; the
superseded entry stays readable. Displayed checkpoint numbers and supersede
pointers use the per-engagement `checkpoint_version`, so `show --all` resolves
them within the current engagement.

---

## The artifact index

```bash
vigil assess artifact search|get|register|refresh|mark-scratch
```

An engagement-local file index. Register a heavy raw file explicitly:

```bash
vigil assess artifact register <path> [--finding <slug>] [--agent-id <id>] [--command-run-id <n>]
```

The backend computes SHA-256 and links the file to a finding, chain, surface,
request variant, or command run.

**What gets indexed.** Ordinary registered text is hashed and indexed in full,
with a 4 KiB preview. Verified command-output rows are different: they index the
retention owner's bounded 16 KiB sample and report `index_status=partial` when
that sample is shorter than the retained output. A miss in a partial row does not
prove the full output lacks the text.

**Scratch.** `mark-scratch <path-or-id>` dismisses a registered note as scratch,
so `check-phase-readiness --phase report` stops flagging it. This is the escape
valve for operator or specialist working notes that are not durable engagement
memory. The corresponding `unlinked_markdown_note` signal is an **advisory**, not
a blocker: report readiness stays `true` and the exit code is unchanged. It is
printed loudly, with the exact `mark-scratch` fix in its detail line.

---

## Run accounting and proof

```bash
vigil assess proof-run start|begin|finish|list|get
vigil assess run-audit sources|source-read|obligation|candidate|tool-signal|discovery-pass|code-receipt|compare
```

Shared run accounting for the code, web, and blue tracks. In outline:

- A scan run starts **queued**, recording the exact target plus the
  source-generation and exclusion identity it will work against, then moves to
  **running**.
- The trusted source-read command streams inventoried bytes and records the exact
  ranges it delivered.
- Typed sanitizer, crash, and OOB signals create deterministic candidates.
- Discovery passes retain attributed workflow evidence without claiming the model
  understood anything. A code scan cannot complete until its latest pass records
  an evidence-backed terminal frontier outcome.
- Exact generation-bound variant and fuzz receipts resolve their matching
  obligations only when a healthy artifact proof matches the receipt's evidence
  path and digest — the receipt cannot vouch for itself.
- If hard debt is open or proof is missing, a requested completion is sealed as a
  **`partial`** result rather than reported as success.

The orchestrator's Runs tab shows the same lifecycle, provenance, evidence health,
paged work records, and deterministic baseline comparisons, with every recorded
value rendered verbatim.

---

## Exporting a submission

```bash
vigil assess export submission <slug> --platform <bugcrowd|hackerone|direct>
vigil assess export submission --recover
```

Renders the finding-backed `submission.md`. In final mode it creates a staged,
hash-verified immutable version through the backend.

Attachments are opt-in via repeatable `--attachment-id`. With none, the exact
Markdown is preserved; with selected registered, hash-valid artifacts, the export
produces a deterministic ZIP and a manifest.

`--recover` reconciles interrupted exports, retains the caller surface in the
activity ledger, and consumes every bounded failed-version and orphan-diagnostic
page.

The orchestrator's Submissions tab offers the same review, attachment, export,
recovery, paged finding/history, and download workflow for humans. **Neither path
changes external submission status or sends anything to a platform.**

---

## Closing dispatches

```bash
vigil assess agent close <agent-id>
vigil assess agent reconcile-stale [--dry-run] [--max-age-hours N]
```

`close` closes an in-progress dispatch whose handoff is `ready` or `blocked`, and
records a `dispatch_closed_from_handoff` decision row.

`reconcile-stale` lists in-progress dispatches older than the threshold and closes
the ones whose handoff is `ready`/`blocked`. It always prints every candidate with
`closed=true|false` and a `skip_reason`.

Blue and code dispatch both go through the same surface:

```bash
vigil assess agent start --role <role> --tier <L1|L2|L3|L4> \
  --skills <names> --rate-budget '<authored tenant query budget>' \
  --prompt-context-json dispatch-context.json --emit-prompt
```

Use `--no-target-traffic` instead of `--rate-budget` for a genuinely offline lane.
For a blue engagement the emitter reads `customer`, `platforms`, and
`tenant_reference_paths` from `scope.json`, validates every tenant reference, and
prints the complete prompt. The prompt-context JSON shape is documented in
[`dispatch-template.md`](../agent/references/runtime-guides/dispatch-template.md).

---

## Discovery and recording verbs

| Group | Verbs |
|---|---|
| Discovery | `recon`, `recon-status`, `dns-discovery`, `web-discovery`, `js-mining`, `gau`, `arjun-select`, `arjun-sweep` |
| HTTP | `http`, `post`, `fetch`, `resolve`, `scaffold-probe`, `classify-payload`, `anomaly-score` |
| Recording | `record-probe`, `record-surface`, `record-chain`, `record-reply`, `emit-event`, `log`, `block-technique`, `list-blocked-techniques` |
| State | `coverage`, `work-buffer`, `command-run`, `scope`, `app-unit`, `contract`, `fixture`, `finding`, `intel`, `exploit` |
| Phases | `transition-phase`, `check-phase-readiness` |
| Discovery of docs | `list-skills`, `list-references`, `list-commands`, `list-mindsets`, `prompt-census` |
| Blue | `host-exec`, `approve-proposal` |
| Code track | `code-ingest`, `code-index`, `code-coverage`, `code-record`, `code-dispatch`, `code-size-summary`, `code-sourcemap-extract` |
| Runtime tools | `kali` (see below), `egress-check` |

`vigil assess check-phase-readiness --phase consume-test` also accepts `consume`
or `consume_test` as input aliases. Its JSON response always returns the canonical
`phase: "consume-test"` value. `vigil assess check-phase-readiness --strict`
turns any open advisory item into a non-zero exit;
`vigil assess check-phase-readiness --strict-deep` independently gates
unsatisfied deep-required app units. Neither flag changes the terminal
report/complete transition gate.

`vigil assess fixture observe` records rotation-safe IDs from a JSON response in
a local manifest; `vigil assess fixture resolve` reads a concrete
`<fixture>.<field>` back for a PoC. See
[`dynamic-fixture-identity.md`](dynamic-fixture-identity.md).

### Kali tool verbs

`vigil assess kali <tool>` runs a tool inside the shared runtime container via
`docker exec`:

`alterx`, `arjun`, `asnmap`, `bbot`, `browser`, `cero`, `dalfox`, `dnsx`, `exec`,
`ffuf`, `gau`, `gf`, `httpx`, `katana`, `nikto`, `nmap-scan`, `nuclei`, `puredns`,
`robots`, `sqlmap`, `subfinder`, `tlsx`, `tool-help`, `wafw00f`, `whatweb`, plus
`sweep` and `sweep-orphans`.

Long-running scans go through the `dtach` job supervisor so workers survive
operator session exit:

```bash
vigil assess kali job start|status|tail|list|stop
```

---

## Agent-facing top-level commands

These `vigil` verbs are called by agents during an engagement rather than driven
by an operator:

| Command | Purpose |
|---|---|
| `vigil oob mint` | Mint a unique OAST nonce callback URL and record a probe row. |
| `vigil oob poll --client <name>` | Parse the interactsh log and correlate callbacks to recorded probes. |
| `vigil auth quarantine --identity <name>` | Quarantine a specific stored identity. |
| `vigil auth keepalive --anchor-cookie <name>` | Fire one read-only authed GET per identity per interval to defeat an enterprise **idle** timeout, teeing a LIVE/DEAD verdict to a log. Anchor cookie names are engagement-specific and required. |
| `vigil email <mailbox>` | Read recent messages from a local Mail.app mailbox — primarily to retrieve a short-lived email-verification code during authenticated testing. |
| `vigil use <key>` | Set the persisted engagement for global services and non-`assess` verbs. (`vigil assess` binds to its launched session, CWD, or an explicit flag instead.) |
| `vigil bench ...` | The generated-suite benchmark harness — see [`benchmarking.md`](benchmarking.md). |
