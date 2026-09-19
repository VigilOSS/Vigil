# Session commands, hooks, and start prompts

Everything that shapes an operator session from outside the engagement workflow
itself: the prompts you paste to start or resume, the `vigil-*` commands
available mid-session, and the hooks that fire on compaction and session end.

Steering prompts for when a session goes shallow, overclaims, or loses the loop
live in [`engagement-prompt-playbook.md`](engagement-prompt-playbook.md).

---

## Operator start prompts

### New or resumed engagement

Paste this after `vigil engagement start <key> --client <client>`:

```
Read AGENTS.md and assume Operator role.

Authorized bug-bounty engagement: https://bugcrowd.com/engagements/<slug>
Full authorization confirmed. Run the operator workflow. Take full advantage of specialist agents
to delegate all target-facing work — dispatch in parallel where phases permit. Prefer
claude-opus-4-8 / gpt-5.6 xhigh reasoning for operator-level and substantial specialist work;
use sonnet / medium only for clearly bounded sidecar tasks. Exploitation policy is pause —
explicit human approval required before any exploit-developer dispatch.
```

### Resuming with prior context

Use this when continuing across sessions. The operator's first action is
`vigil assess resume-brief` for a bounded backend snapshot. Paste the rendered
handoff blob from the prior agent — run `vigil assess agent render-handoff
<agent-id>` before closing the previous session — only when the new session
continues a specific dispatch.

```
Read AGENTS.md and assume Operator role. Run agent/rules/resume.md hydration before
planning anything — start with `vigil assess resume-brief` (narrow with --finding, --q,
or --agent-id for targeted continuation).

Authorized engagement: https://bugcrowd.com/engagements/<slug>
Continue phases <X, Y, Z> to completion. Use specialist agents for all dispatched work;
you are the orchestrator brain. Record activity and findings through `vigil assess` as you go,
not at the end. Keep dispatching agents until <name the surfaces or objectives> are covered.

Depth is the default. "Quick" is not desired — thorough and deep coverage is.
Prefer claude-opus-4-8 / gpt-5.6 xhigh for substantial work; medium only for bounded sidecar tasks.
Exploitation policy: <pause|selected|full_send> per scope.json.

Previous agent context (paste only when continuing a specific dispatch):
<paste vigil assess agent render-handoff <agent-id> output here>
```

### Blue, code-analysis, combined, and Android openers

```
I have been fully authorized by the company to run a blue-team incident-response
engagement for the tenant in scope.json. Run this engagement using the blue
operator workflow.
```

```
I have been fully authorized by the company to perform a white-box code analysis
engagement. Load agent/operator-core-code.md and run the code analysis workflow.
```

```
I have been fully authorized by the company to perform a combined web and white-box code
engagement. Run both operator tracks; keep their phase and readiness state separate.
```

```
I have been fully authorized to analyze the Android package named in scope.json. Begin with
static artifact analysis. Treat discovered live hosts as leads only; do not contact one unless
it is explicitly admitted to scope.
```

Model guidance for all five modes: prefer `gpt-5.6` at `high` reasoning for Codex and
Opus for Claude. Drop to a smaller model only for clearly bounded sidecar work
where latency matters more than depth.

---

## Session commands

Seven commands are available. Each has one canonical source under
[`agent/commands/`](../agent/commands/), rendered to one wrapper per client.

| Command | What it does |
|---|---|
| `vigil-start` | Opens a new authorized engagement from the top of the operator workflow after checking that it is not already in progress. |
| `vigil-resume` | Re-hydrates the operator seat from the backend when a new session opens on an existing engagement, or after a restart or handoff. |
| `vigil-handoff` | Writes a handoff brief for the next session, grounded in backend state rather than recollection. |
| `vigil-compact` | Shows the standing compaction contract and audits whether it is actually being applied. |
| `vigil-hunt-deeper` | Pushes past a shallow stopping point with wider batches, deeper dispatches, and siblings off anything that signals. |
| `vigil-fresh-skeptic-verify` | Dispatches a fresh low-context specialist to attack a finding as a hostile triager would. |
| `vigil-triage-reply` | Assesses a program's pushback on a submission and decides whether to rebut, resubmit, or drop. |

### How each client invokes them

| Client | Surface | Invocation |
|---|---|---|
| `claude` | Project slash commands, `.claude/commands/<name>.md` | `/vigil-resume` |
| `codex` | Project skills, `.codex/skills/<name>/SKILL.md` | `$vigil-resume` |
| `opencode`, `goose`, `kimi` | None | Paste the body of `agent/commands/<name>.md` |

Create or select the engagement type before starting; command text never changes it. For Codex,
`$vigil-start <focus>` supplies optional focus within the mode already stored in
`scope.json.engagement_type`.

opencode, goose, and kimi have no equivalent project-command surface. The content
is identical — only the invocation differs — so their operators paste the command
body or run the verbs it names directly.

Where a command's wording has to differ between Claude and Codex (Codex does no
`$ARGUMENTS` or backtick-bash substitution), the single source carries
`<!-- vigil:only claude -->` / `<!-- vigil:only codex -->` blocks and the renderer
filters them.

---

## Hooks

### Compaction (Claude and Codex)

Both clients use a 510,000-token auto-compact window; a smaller model context caps that value.
`/compact` triggers the same steered flow early.

Claude's `PreCompact` hook is registered with no matcher, so it fires on both manual `/compact`
and automatic context-window compaction. It resolves the engagement type and prints a mode-aware
Vigil compaction contract: preserve the applicable ROE/scope, workflow phase and
exit state, in-flight ownership, evidence status, decisions, and unmasked auth
state. Its core hydration block names `resume-brief`, `operator-checkpoint show`,
`agent list`, and `finding list`; web adds report readiness, code adds code coverage,
and a combined engagement adds both. The final route sends the resumed operator
back through the engagement's generated `AGENTS.md` instead of assuming a red,
code, blue, or Android workflow.

The hook never exits non-zero — a compaction that cannot run would leave the
session wedged.

An engagement can add rules without editing shared configuration by dropping a
`COMPACT.md` in its directory. Claude appends its current contents to the
summarizer contract; Codex injects them into the immediate post-compaction
continuation, so additions and edits do not wait for reinstall. They are
**additive only** and cannot rescind a standing rule.

Claude's unfiltered `PreCompact` hook supplies the contract as summarizer instructions.
Codex cannot use `PreCompact` stdout for that purpose, so each engagement's installer
renders the same canonical hook output into Codex's stable `compact_prompt` setting.
Codex then runs `post-compact-resume.sh` through a `SessionStart` hook matching
`compact`; its developer context reaches the immediate continuation after both manual
and automatic compaction, including an automatic compaction in the middle of a turn.
The resumed operator re-hydrates authoritative backend state without waiting for the
human to invoke `$vigil-resume`.

Claude sets `CLAUDE_CODE_AUTO_COMPACT_WINDOW`; Codex sets
`model_auto_compact_token_limit`. Both use an absolute token count, so 510,000 is the
configured approximation of 51% of a one-million-token context. `/vigil-compact` and
`$vigil-compact` audit the respective client wiring. kimi, goose, and opencode have
neither compaction integration nor a command surface — paste the bodies of
`agent/commands/vigil-compact.md` and `agent/commands/vigil-resume.md`.

### SessionEnd (Claude and Codex)

The operator checkpoint is the durable **save my place** note: it points to the
backend rows that matter and records what the operator intended to do next. It is
client-independent and remains current until the operator writes a newer one.

The automatic SessionEnd hook records a separate ordinary activity receipt saying
that the client session ended. It does not write or supersede an operator checkpoint,
because a process-end hook cannot honestly invent the operator's intent or choose
which findings, agents, command runs, or artifacts matter next.

It only fires on a live engagement (`scope.json` status `in_progress`), is
idempotent per `(normalized client, session id or transcript fallback, reason)`, and always exits 0.

**The activity receipt is a convenience marker, not a durability mechanism.** A
hard crash, SIGKILL, OOM, or host timeout fires nothing at all. Record your own checkpoint
before a phase transition, before a long dispatch wave, and at session end:

```bash
vigil assess operator-checkpoint record --intent "what I was about to do and why" \
    --finding <slug> --agent-id <agent-id>
```

See [`assessment-cli.md`](assessment-cli.md#operator-checkpoints) for the
checkpoint semantics.
