# Resume Rule

Backend state is the durable memory of an engagement: findings, intel, dispatch handoffs, null
results, decisions and command coverage. Hydrate from it before new work, because skipping it causes
duplicate dispatches, repeated probes, lost kill rationale and stale phase decisions.

Apply this rule when the engagement is in progress or past initialization, when backend rows may
already exist, when you are unsure it is fresh, and after any compaction, truncation or restart.
Compaction is a context boundary: Claude's `PreCompact` hook and Codex's `compact_prompt` steer the
summary, and both clients' `SessionStart(compact)` hook delivers recovery instructions that name this
file before the continuation; follow them rather
than invoking `vigil-resume` yourself. ZCode delivers none, so on a recognized boundary run this
hydration before dependent work (`/vigil-resume` carries the ZCode procedure).

## Hydrate

Before target-facing commands, dispatch, phase transitions, finding writes or report work:

```bash
vigil assess resume-brief
```

Narrow it instead of reconstructing state by hand: `--finding <slug-or-alias>`, `--q "<host-or-keyword>"`,
`--agent-id <agent-id>`, `--since <iso-datetime>` (what is new since the last brief),
`--max-age-hours <N>` (override the per-role stale threshold). `resume-brief --help` lists them.

The brief carries your last checkpoint, finding queues, decisions, surface and work-buffer rollups,
stale dispatches, handoffs, command history, artifacts, a Per-Input Coverage grid and open intel.
Capped lists print `… showing N of M`; read M before treating a list as complete. Drill down by id with the commands it prints: `vigil assess command-run get <id>`,
`vigil assess artifact search --q <query>` / `artifact get <id>`,
`vigil assess agent render-handoff <agent-id>` (`--max-lines 0` when an excerpt omits a clue or next
test), `vigil assess operator-checkpoint show --all`, and
`vigil assess check-phase-readiness --phase report` for open CVEs, leads, dangling links and report
blockers. Open the per-item coverage, request-variant or work-buffer dumps only after a rollup flags a
bucket worth opening.

`resume-brief` is a read. When it finds abandoned command runs, jobs or owned host processes it prints
a WARN naming the reconciling command; run it before new target-facing work, typically
`vigil assess kali sweep-orphans --scope all`.

For outstanding runtime proof, read `vigil assess proof-work list` and `proof-work get <id>` before
dispatching: each entry's `queue_state` names its next step, and `reverification_required` names
proof an edit made historical, which needs a fresh independent verdict. Reconcile ownership with the
explicit `proof-work reconcile <id>` write. A chat exit or an old checkpoint does not prove a
supervised command stopped; keep live owners, recover only stopped assignments through the contract.

Fetch a prior run with `command-run get <id>` before citing it instead of re-running: a zero exit does
not prove its preview answers the current question. Unlinked markdown notes are scratch; state that must survive lives in backend rows or an
indexed artifact linked to a finding, chain, dispatch, surface, request variant or command run.

## Summarize, then act

Write one compact note covering: confirmed, suspicious, killed and open findings; intel that changes
targeting, including open high CVEs and leads; your last checkpoint's intent and whether it is still
right; recent decisions and null results; the last dispatch's owner, result and handoff gaps; command
coverage on the host or keyword; open surfaces and work-buffer buckets; artifacts that matter next.
Only then decide the next action.

Record a checkpoint before a phase transition, before a long dispatch wave and at session end, so the
next session resumes from a row instead of a guess: `vigil assess operator-checkpoint record --intent
"what I was about to do and why" --finding <slug> --agent-id <agent-id>`. `vigil assess contract
operator-checkpoint` owns what it may reference; `--intent` renders as unverified intent, never
evidence.
