# Resume Rule

Resume hydration runs before new work in an existing engagement because backend state is the
operator's durable memory for findings, intel, dispatch handoffs, null results, and raw command
coverage. Skipping it causes duplicate dispatches, repeated probes, lost kill rationale, and
stale phase decisions.

Apply this rule after locating the engagement directory when any of these are
true:
- The engagement is in progress
- The current phase is past initialization
- Findings, dispatch rows, activity entries, or command runs may already exist
- You are unsure whether the engagement is fresh
- The session was compacted, truncated, or restarted

**Compaction is a context boundary, so hydration is required before continuing.**
Automatic delivery of recovery instructions depends on the client.
Claude's `PreCompact` hook steers its summarizer. Codex receives the same contract
through `compact_prompt`, then its `SessionStart(compact)` hook re-hydrates the
immediate continuation. Follow the injected recovery instructions; do not invoke
`vigil-resume` manually when that recovery is delivered.

**ZCode:** native manual or automatic compaction does not establish Vigil recovery.
When a context boundary is recognized, restore the selected instructions and apply
this hydration procedure through the task's original context-bound helper before
dependent work. The human can invoke `/vigil-resume` explicitly to request that
restoration. A startup receipt, compacted summary, or successful native compression
is not evidence of fresh recovery context or completed backend hydration. Without
a verified compact callback, recovery before an unattended continuation is not
guaranteed; explain that limitation rather than promising automatic recovery or
inferring that compaction was detected.

Still record `vigil assess operator-checkpoint` before a long dispatch wave:
the checkpoint is durable backend state, while the client's summary remains only
a bridge to it.

Run the core resume hydration before target-facing commands, specialist dispatch, phase
transitions, finding writes, or report work:

```bash
vigil assess resume-brief
```

For targeted continuation, narrow the brief instead of manually reconstructing state:

```bash
vigil assess resume-brief --finding <finding-slug-or-alias>
vigil assess resume-brief --q "<scope-host-or-keyword>"
vigil assess resume-brief --agent-id <agent-id>
vigil assess resume-brief --since <iso-datetime>   # what's new since the last brief
vigil assess resume-brief --max-age-hours <N>      # override the per-role stale threshold
```

The brief includes your own **Operator Checkpoint** (the last thing you recorded
you were about to do), finding queues, a **Recent Decisions** ledger, a
**Surfaces** rollup (counts by status×type plus the top still-uncovered
surfaces), a **Work Buffer** rollup (pending coverage obligations counted by
gf-bucket), stale dispatches, handoff gaps, the newest dispatch and handoff rows,
relevant command-history matches, indexed artifacts, and an **Intel** section
(open high-severity CVEs, open leads that still need a disposition, and any notes
you tagged `coverage` / `read-first`). Capped lists print `… showing N of M`, so
read the M before assuming the list is the whole picture. Use the drill-down
commands it prints for exact evidence:

```bash
vigil assess command-run get <id>
vigil assess artifact search --q <query>
vigil assess artifact get <id>
vigil assess agent render-handoff <agent-id>
vigil assess check-phase-readiness --phase report   # advisory (red engagements): open CVEs/leads + dangling finding links + report blockers
vigil assess operator-checkpoint show --all        # your own checkpoint chain, including superseded (corrected) entries
```

`resume-brief` is a READ. It OBSERVES abandoned command runs, jobs, and owned
host processes without writing; when it finds any it prints a WARN naming the
exact reconciling command. Run that command before new target-facing work so the
audit trail stops claiming a dead run is still going:

```bash
vigil assess kali sweep-orphans --scope all
```

For outstanding runtime proof, inspect `vigil assess proof-work list` and the relevant
`proof-work get <id>` before dispatching. The list also exposes owed but unprepared findings;
each entry's `queue_state` names what it needs next and `next_test` carries the planned test.
Also inspect `reverification_required`: it names material invalidations of prior runtime proof,
separate from parked findings. Preserve terminal history and obtain a fresh independent verdict.
Use the explicit `proof-work reconcile <id>` write when ownership or source/scope currentness
needs reconciliation; the read brief never changes it. A chat exit or old checkpoint is not
proof that a supervised command stopped. Preserve a live owner/run, recover a genuinely stopped
assignment through the contract, and keep blocked work visible while other investigation continues.
Read the complete handoff with `agent render-handoff <agent-id> --max-lines 0` when its excerpt
omits a material clue or recommended next test; do not treat a short summary as the whole result.

Close the loop at the other end: before a phase transition, before a long
dispatch wave, and at session end, record your own checkpoint so the next
session resumes from a row instead of a guess.

```bash
vigil assess operator-checkpoint record --intent "what I was about to do and why" --finding <slug> --agent-id <agent-id>
```

The checkpoint stores only REFERENCES to rows the backend already holds (unknown
finding / agent / command-run / artifact ids refuse the write, naming them), and
`--intent` is the single free-text field — recorded and rendered as **UNVERIFIED
operator intent**, never as a finding or as evidence. It is append-only: correct
a wrong checkpoint by recording a new one, and the superseded entry stays
readable.

Use command history as a coverage map, not as a reuse gate. If you cite a prior run
instead of re-running, fetch it with `vigil assess command-run get <id>` first because
a successful return code does not prove the preview answers the current question.

Treat unlinked markdown notes as scratch, not engagement memory. State that must
survive resume goes into backend rows or into an indexed artifact linked to a
finding, chain, dispatch/agent, surface, request variant, or command run.

### Keep resume bounded

- Drill down by id (`command-run get`, `artifact get`, `fetch findings/<slug>`) — the brief already names the surfaces and command runs you need. The brief carries only the **aggregate** Surfaces (status×type + top uncovered) and Work Buffer (pending counts by gf-bucket) rollups; the per-item `coverage-items`, `request-variants`, and full `work-buffer` dumps stay out of the resume picture as operational detail — reach for them only after the rollup flags a bucket worth opening.
- Treat `artifact search` as the engagement memory index — `.md` files under the engagement directory that are not in the index are scratch.
- Use `vigil assess agent render-handoff <agent-id>` for prior dispatch context — it stays bounded where raw transcripts grow linearly.
- Read command history before re-running probes — the history is canonical, and rerunning is warranted only when the variant differs.
- Read the brief's **Per-Input Coverage** grid before re-probing a surface — it shows which specific input was tested for which attack family as which identity, and any wall code, so a covered (host × input × identity × class) cell is not blindly re-tested.

After hydration, summarize the resume state in one compact operator note:
- confirmed, suspicious, killed, and open findings
- intel that changes targeting or exploitability — and any open high CVEs or open leads from the brief's Intel section that still need to be tested or ruled out (before report, `vigil assess check-phase-readiness --phase report` lists these plus any exploited-but-unlinked CVE or dangling finding link)
- your last operator checkpoint's intent, and whether it still describes the right next action
- recent operator decisions and null results
- last dispatch owner, skills, result, and handoff gaps
- command-run coverage already performed against the host or keyword
- still-open attack surfaces from the brief's **Surfaces** rollup, and which gf-buckets still carry pending coverage in the **Work Buffer** rollup
- indexed artifacts that matter to the next action

Only then decide the next action.
