# Session commands, hooks, and start prompts

Everything that shapes an operator session from outside the engagement workflow
itself: the prompts you paste to start or resume, the `vigil-*` commands
available mid-session, and the hooks that fire on compaction and session end.

Steering prompts for when a session goes shallow, overclaims, or loses the loop
live in [`engagement-prompt-playbook.md`](engagement-prompt-playbook.md).

---

## Operator start prompts

### New or resumed engagement

Paste this after `vigil engagement start <key> --mode web --client <client>`
(or the corresponding selected mode):

```
Read AGENTS.md and assume Operator role.

Authorized bug-bounty engagement: https://bugcrowd.com/engagements/<slug>
Full authorization confirmed. Run the operator workflow. Take full advantage of specialist agents
to delegate all target-facing work — dispatch in parallel where phases permit. Prefer
claude-opus-5 / gpt-5.6-sol xhigh reasoning for operator-level and substantial specialist work;
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
Prefer claude-opus-5 / gpt-5.6-sol xhigh for substantial work; medium only for bounded sidecar tasks.
Exploitation policy: <pause|selected|full_send> per scope.json.

Previous agent context (paste only when continuing a specific dispatch):
<paste vigil assess agent render-handoff <agent-id> output here>
```

### Blue, code-analysis, and Android openers

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
I have been fully authorized to analyze the Android package named in scope.json. Begin with
static artifact analysis. Treat discovered live hosts as leads only; do not contact one unless
it is explicitly admitted to scope.
```

For an engagement with web and code enabled, start one `--mode web` client and a separate
`--mode code` client. Each loads only its selected operator core, and both use the same
backend findings and independent phase state. The enabled tracks do not select a combined
operator role. Use `vigil engagement mode` inside a client to verify `mode:` and the
canonical `prompt:` before work or after compaction.

Model guidance for these modes: prefer `gpt-5.6-sol` at `high` reasoning for Codex and
Opus for Claude. Drop to a smaller model only for clearly bounded sidecar work
where latency matters more than depth.

### Remediation developer sessions

Start repository context with `vigil remediation -k <key> start`, then supply ticket IDs or URLs
in Claude:

```text
/vigil-remediate SEC-123
/vigil-remediate SEC-123 https://jira.example.com/browse/SEC-124
```

The command reads the selected repository `PROJECT.md` and task-specific guidance. One normalized
bug keeps this conversation as its developer; several select a coordinator that launches separate
full developer sessions through Vigil. The command announces the choice. Ticket retrieval uses
profile-selected source readers/MCPs and skills; unavailable retrieval stays pending. The developer
validates the report and presents a fix plan before editing.

Vigil's native Claude session host records the conversation UUID and job identity. The session runs
in the repository root so existing settings, MCPs, ignored skills, and private runbooks remain
available; code edits belong only in the registered case workspace. `vigil remediation -k <key>
join <case-id>` attaches to the exact recorded conversation rather than launching another copy.
Native launch/join requires Claude Code 2.1.257 or newer and is currently Claude-specific.

The launch overlay exposes only `/vigil-remediate` and case artifact access. It does not import the
assessment operator or hunting command context. The generated Codex `$vigil-remediate` skill retains
generic command guidance without promising native batch session hosting.

The profile controls hook policy. With `hook_policy = "disabled"`, non-managed hooks are disabled
only for this session, announced before launch and in developer context. Managed hooks remain active.
Vigil/Claude runs configured formatting, analysis, and tests at verification and before publication;
case recording and session continuity do not depend on hooks. Repository hook files are unchanged.
The assessment hook descriptions below apply to ordinary engagement sessions, not a remediation
session whose profile disables them. See [Remediation workspace](remediation.md) for intake,
generated handoffs, shared testing, approval, and deployment.

---

## Session commands

Eight commands are available across the supported workflows. Each has one canonical source under
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
| `vigil-remediate` | Routes ticket IDs or URLs to one developer or a coordinator using the selected repository remediation profile. |

### How each client invokes them

| Client | Surface | Invocation |
|---|---|---|
| `claude` | Project slash commands, `.claude/commands/<name>.md` | `/vigil-resume` |
| `codex` | Project skills, `.codex/skills/<name>/SKILL.md` | `$vigil-resume` |
| `opencode`, `zcode` | Native assessment command files or enabled ZCode plugin commands | `/vigil-resume` in a prepared web/code session; `/vigil-remediate` in repository-context remediation |
| `goose`, `kimi`, `pi` | None | Paste the body of `agent/commands/<name>.md` |

Select the operator mode at `vigil engagement start`; command text never changes it. For
Codex, `$vigil-start <focus>` supplies optional focus within the launched session's mode.
Use `vigil remediation start` for the focused remediation command instead of selecting an
assessment mode. Its repository-context overlay does not expose the hunting commands.

OpenCode and ZCode expose the seven assessment commands from a separate generated
web/code asset tree. Start, resume, handoff, and compact support both tracks. The
three web-specific commands explain their limitation in code mode rather than
changing workflows. Repository-context remediation exposes only `vigil-remediate`.
Follow [ZCode setup](zcode-setup.md) to open the generated workspace, enable the
native plugin, and start a fresh task. Command discovery is not runtime proof of
specialist execution or hooks.
Goose, Kimi, and Pi have no installed project commands; run the applicable verbs or
use the canonical command guidance within the active workflow.

Client-specific command instructions live in capability blocks in the canonical
source; the renderer selects the appropriate body. Native OpenCode/ZCode command
arguments use `$ARGUMENTS`; they do not execute Claude's inline shell substitutions.

---

## Hooks

### Compaction (Claude and Codex)

Both clients use a 510,000-token auto-compact window; a smaller model context caps that value.
`/compact` triggers the same steered flow early.

Claude's `PreCompact` hook is registered with no matcher, so it fires on both manual `/compact`
and automatic context-window compaction. It reads `VIGIL_OPERATOR_MODE` and prints a mode-aware
Vigil compaction contract: preserve the applicable ROE/scope, workflow phase and
exit state, in-flight ownership, evidence status, decisions, and unmasked auth
state. Its core hydration block names `resume-brief`, `operator-checkpoint show`,
`agent list`, and `finding list`; web adds report readiness and code adds code coverage.
It never asks one session to load both cores. The final route sends the resumed operator
through the engagement's `AGENTS.md` and the selected canonical prompt.
Remediation sessions rehydrate with `vigil remediation -k <key> list` and
`vigil remediation -k <key> show <case-id>`; their case gates do not use
offensive phase readiness.

The hook never exits non-zero — a compaction that cannot run would leave the
session wedged.

An engagement can add rules without editing shared configuration by dropping a
`COMPACT.md` in its directory. Claude appends its current contents to the
summarizer contract; Codex injects them into the immediate post-compaction
continuation, so additions and edits do not wait for reinstall. They are
**additive only** and cannot rescind a standing rule.

Claude's unfiltered `PreCompact` hook supplies the contract as summarizer instructions.
Codex cannot use `PreCompact` stdout for that purpose, so each engagement's installer
renders a mode-neutral copy of the canonical hook output into Codex's stable
`compact_prompt` setting. This remains valid if another session selects a different mode.
Codex then runs `post-compact-resume.sh` through a `SessionStart` hook matching
`compact`; its developer context reaches the immediate continuation after both manual
and automatic compaction, including an automatic compaction in the middle of a turn.
The hook verifies the session-selected mode through `vigil engagement mode` and directs
the operator to only that mode's canonical prompt. If mode selection is unavailable,
it stops target-facing work. The resumed operator re-hydrates authoritative backend
state without waiting for the human to invoke `$vigil-resume`.

Claude sets `CLAUDE_CODE_AUTO_COMPACT_WINDOW`; Codex sets
`model_auto_compact_token_limit`. Both use an absolute token count, so 510,000 is the
configured approximation of 51% of a one-million-token context. `/vigil-compact` and
`$vigil-compact` audit the respective client wiring. kimi, pi, goose, and opencode have
neither compaction integration nor a command surface — paste the bodies of
`agent/commands/vigil-compact.md` and `agent/commands/vigil-resume.md`.

### ZCode compaction and explicit recovery

Native manual or automatic compaction and Vigil recovery are separate capabilities.
Successful compression, an enabled plugin, or a startup receipt does not prove that
fresh recovery context reached the continuation. Vigil leaves ZCode's native
compaction settings unchanged.

After compaction, pause ongoing work and invoke `/vigil-resume` explicitly when
fresh recovery has not been verified. The command restores the selected workflow
instructions, engagement constraints, and current backend state through that task's
original bound helper. It keeps the task's binding rather than selecting the
project's context for new tasks. If hydration fails, dependent work waits for repair.

This explicit recovery does not guarantee that an unattended mid-turn continuation
waited for hydration, or establish that work already performed used fresh state.
See [ZCode capability boundaries](zcode-setup.md#capability-boundaries) for native
acceptance evidence and limitations.

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
