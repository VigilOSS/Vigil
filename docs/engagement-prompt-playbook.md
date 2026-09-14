# Operator Steering Playbook

> A library of **human-side prompts** for driving a Vigil engagement — the things you type to keep the
> model honest, deep, and on-method when it drifts.
>
> This is not a restatement of `operator-core.md` / `hunting.md` / `shared-constraints.md`. Those tell the
> *model* how to run an engagement. This tells *you* how to **push** one: how to re-anchor a model that has
> gone shallow, started overclaiming, forgotten the core loop, or quietly started doing the work itself
> instead of dispatching. Prompts here are reworded toward best practice — short, specific, and tied to the
> rule they reinforce — not transcribed verbatim from past sessions.
>
> **Why a steering library at all?** Long engagements degrade the model in predictable ways. It gets lazy,
> it forgets the operator role, it inflates severity to look productive, it stops at the first win. The
> value of a human in the loop is catching each of those the moment it starts and saying the one sentence
> that corrects it. Those sentences are below.
>
> **Where the rest lives.** This file is *mid-session* steering. The prompts you paste to start or resume a
> session, the nine `vigil-*` client commands, and the compaction / session-end hooks are in
> [`session-commands.md`](session-commands.md).

---

## How to use this

1. Skim [§1 Failure modes](#1-the-models-failure-modes-and-the-one-line-fix) — it maps each way the model
   drifts to the nudge that fixes it and the rule that nudge reinforces.
2. Keep [§2 Re-anchoring nudges](#2-re-anchoring-nudges) within reach — these are the everyday one-liners.
3. Use [§3 Phase steering](#3-phase-steering) for the longer prompts that move a phase forward.
4. Read [§4 High-leverage techniques](#4-high-leverage-techniques-the-gold) once — these are the moves that
   find what the model would otherwise miss.
5. [§5 Duplicative-but-worth-it vs. drop](#5-what-the-docs-already-say) is the honest audit: which of your
   habitual prompts are already enforced by the docs (so saying them is reinforcement, not instruction) and
   which are noise to drop.
6. [§6 Templates](#6-copy-paste-templates) are fill-in-the-blank starting points.
7. [§7 Client commands](#7-the-same-prompts-as-client-commands) is where most of §6 already
   lives as a command you can invoke instead of paste — plus what runs automatically.

---

## 1. The model's failure modes (and the one-line fix)

The whole playbook reduces to this table. Everything after it is detail.

| The model is… | You say… | Reinforces |
|---|---|---|
| **Doing the probing itself** (running curl/nmap, parsing output) | "You're the operator — dispatch a specialist for this; don't run target tools yourself." | operator-core *"You are the orchestrator brain"*; hunting §18 |
| **Stopping shallow** / "no findings" too fast | "Slow isn't dry. Exhaust the surface before rotating — confidence, not time, is the bar." | hunting §5, §15, §16 |
| **Forgetting the core loop / phases** after many batches | "Re-read operator-core.md, confirm the phase, then continue." | operator-core Resume Gate |
| **Overclaiming severity / impact** | "What can an attacker do *right now*? Score the incremental impact, not the theoretical ceiling." | hunting §2, §3 |
| **Tunnel-visioned on the first win** | "Don't stop at the first bug — hunt its siblings and the cluster around it before moving on." | hunting §9, §10 |
| **Wasting shallow dispatches** (20–30s agents) | "Give each specialist enough scope to run deep; don't burn a dispatch on a 30-second task." | operator-core Iteration-mode (dispatch_mode) Declaration |
| **Calling theory a finding** | "No theory. If you can't show the attacker outcome with a real request/response, park it `chain_required`, don't report it." | hunting §2; shared-constraints §7 |
| **Thrashing** when another agent changed state | "Another agent is working — review what changed and decide; don't reflexively revert." | (net-new — §4) |
| **About to ship a self-graded finding** | "Dispatch a fresh, low-context specialist to review this as a skeptical triager." | operator-core Phase 4; adversarial-mindset |
| **Padding the report** with slop/theory | "Cut filler and speculation. Write the exact action and exact method, nothing else." | reporting §11/§15; shared-constraints §7 |

---

## 2. Re-anchoring nudges

Short prompts, grouped by what they correct. These are reinforcement of rules the model already has — say
them when you see drift, not on every turn.

### Stay the brain
- "You're the operator. Dispatch a specialist for this — don't run the tools yourself."
- "Delegate in parallel where the phases allow; your job is selection and judgment, not execution."
- "Don't over-constrain the specialist — give it the hypothesis and the gap, and let it work." *(matches the
  model's own guidance that too many guardrails choke a subagent)*

### Go deeper, don't rotate early
- "Slow isn't dry. Exhaust this surface — routes, privileged features, object references, source intel —
  before moving on."
- "Leave no stone unturned. Confidence that nothing was missed is the bar, not elapsed time."
- "Don't drain the queue quickly — depth per item over breadth across items."
- "Keep dispatching until the surface is genuinely exhausted; if you hit a stopping point, push past it and
  tell me what's left, don't stop and ask."

### Prove impact, score honestly
- "What can an attacker do right now? If the answer is 'nothing yet,' it's not a finding."
- "Does the precondition already grant equivalent access? If so it's defense-in-depth, not a high."
- "You're overstating this. Score the incremental impact over what the attacker already has."
- "Be honest about severity — I'd rather a defensible medium than a high the triager downgrades on sight."

### Remember the core
- "Re-read operator-core.md, confirm the current phase, then continue." *(works as a periodic reset — every
  few batches on a long run)*
- "Re-read adversarial-mindset.md before this pass."

### Find more off what you have
- "Don't stop at the first bug — check its siblings (sibling routes, methods, content-types, auth contexts)
  and the cluster around it."
- "Try non-trivial, creative paths, not just the obvious one — think about how a developer would have cut a
  corner here."
- "Look for chains across the confirmed set before reporting — A→B even where it looks unlikely."

---

## 3. Phase steering

Longer prompts that advance a phase. Anonymized; swap the bracketed parts.

### Kickoff
```
Read AGENTS.md → assume Operator role (operator-core.md). Authorized engagement: [program/scope URL].
Apply the active `agent/rules/*.md`. In-scope: [hosts]. Out-of-scope: [hosts]. Update scope.json.
Exploitation policy: [pause | selected | full_send]. Rate budget: [N req/s].
Delegate all target-facing work to specialists, in parallel where phases permit. Depth over speed.
Start the engagement.
```
For an unfamiliar program, prepend a research step: *"Before starting, research the program's VDP/scope
across sources — don't rely on a single page — and summarize what is actually in scope before updating
scope.json."*

### Recon & coverage
```
Phase 1 is the goal this session — don't advance early. Dispatch recon/OSINT specialists to enumerate every
subdomain and surface; depth over speed, and throttle DNS/UDP so the runtime stays healthy.
Then dispatch a review pass: did the commands that should have run actually run? katana? gau? are all hosts
liveness-checked, results bucketed and triaged? Fill the gaps and report coverage % per host before exiting.
```
Recon-QA checklist worth naming explicitly: *katana ran? gau ran? results bucketed? all hosts liveness-checked?
blackholed hosts dropped? coverage % per host?* (Backstops the operator-core Phase-1 exit gates.)

### Hunt
```
Dispatch specialists in batches across all surfaces. Don't over-constrain them — hand each a hypothesis and
the specific gap, and let it run deep. Try non-trivial, creative exploitation paths and look for sibling
routes and clusters off anything that signals. Load adversarial-mindset.md. Record everything to the backend
as you go so nothing is re-run. Don't stop until the surface is exhausted; if a lead stalls, change the
approach or research similar techniques — don't abandon a live lead because it's slow.
```

### Escalate & chain
```
For [finding]: state the real-world entrypoint, how it works, and the attacker outcome. Can it go higher?
Dispatch a specialist to find chains across confirmed findings (siblings share a root cause) and one to push
severity via the matching exploit path. Stop at the point that proves attacker impact — don't over-exploit,
especially on production.
```

### Verify (do this before every submission)
```
Dispatch a fresh specialist with minimal context to review [finding] as a skeptical triager:
- What can an attacker do right now — real-world impact, or just a CVSS band fit?
- Did local testing cheat, or are there guards in the code that kill it? (Trust the code over the docs.)
- Is any of it "expected" — internal-only, requires existing access, public-by-design?
- Hunt downgrades and missing evidence; bullet what's off.
Then tell me whether a downgrade is warranted and whether the program would push back.
```

### Report
```
Dispatch report-writer (draft) for [findings] per the report rules: standalone, no internal IDs or tool names,
no theory, working PoC (inline where possible), a VRT category that actually exists, no filler, written for
the triager. Then a fresh report-writer in QA mode to fix structure, then normalize across reports.
Give me the file path and attacker entrypoint for each so I can submit.
```

### Triage defense (after submitting)
```
[Program] [closed/pushed back on] [finding] saying [reason]. Dispatch a fresh, low-context specialist to read
the finding, our submission text, and their response, and decide whether the pushback is fair.
If we should push back, give me a concise, professional reply (here, don't edit the submission) that proves
real-world impact with evidence — only if you genuinely think they'll stop pushing back after it.
If they're right, say so and tell me whether to resubmit under a different VRT or drop it.
```

### Resume
```
Read AGENTS.md → operator-core.md → resume exactly where it left off. Confirm running specialists are alive
and writing files; re-dispatch any that died. Treat any handoff doc as a lead, not gospel. Keep the backend
authoritative as you go.
```

---

## 4. High-leverage techniques (the gold)

These are the moves that find what the model would otherwise miss. Most are **not** fully spelled out in the
core docs — they're the operator-craft on top.

### A. The fresh, low-context skeptic
The single highest-yield move. Before anything ships — and again whenever a finding "feels too clean" — spawn a
**deliberately context-starved** specialist and tell it to act as a skeptical program/vendor reviewer (or, for
code, a maintainer). Low context is the point: a reviewer that didn't watch the finding get built doesn't
inherit its confirmation bias.
> "Dispatch a fresh specialist with little context/bias to review the finding, the evidence, and the
> submission text, and decide if we should push back — and what to say."

It catches the model's most common failure: **overclaiming**. In practice the model inflates severity to look
productive, and this pass is what walks it back to a defensible, triager-proof claim. (Reinforces operator-core
Phase 4 + the FP/severity gate, but the *low-context* twist is the part worth doing deliberately.)

### B. Anchor on the highest-impact archetype, then hunt its variants everywhere
Don't just enumerate bugs — name the worst realistic archetype for this target (a Log4j-style unauth log-ingestion
RCE, the SSRF that already worked, a blank-credential auth bypass) and hunt for siblings and variants of *that
pattern* across the whole surface/codebase.
> "Pick the 10 files/surfaces most likely to hide something like [archetype]; dispatch hunters for variants of
> that exact pattern, plus the unsuspecting ones."

### C. For code targets: trust the code over the docs
A recurring, embarrassing failure is submitting against documented behavior that the actual code contradicts.
> "Ignore what the finding/submission claims and read the code itself. Verify against the source, not the docs —
> docs are often wrong where the code is right, and that's what makes a submission look amateur."

Pair it with a prior-art check: *"Research similar CVEs and prior reports — confirm this is real and not already
known or fixed in a later commit."*

### D. Calibrate dispatch depth — don't burn shallow agents
A swarm of 20–30s dispatches is wasted tokens. Push the model to give each specialist enough scope to run for
minutes and actually go deep.
> "Each specialist should have enough scope to run for several minutes and go deep — don't burn a dispatch on a
> 30-second task. Token spend is fine; shallow dispatches aren't."

(The dispatch-mode table governs item counts; this governs *depth per dispatch*, which it doesn't.)

### E. Defeat tunnel vision after the first win
The model tends to declare victory at the first confirmed bug and forget the surrounding cluster.
> "Don't stop at the [SSRF] and forget how you found it — there may be variants or other findings clustered
> here. Keep going."

### F. Concurrency discipline
On multi-agent runs, state changes you didn't initiate are normal. Tell the model not to thrash.
> "Another agent is working this — if something changes unexpectedly, review and decide what's best; don't
> reflexively revert it."

### G. Human gates for risk and money
On production, `.gov`/regulated, or destructive-capable steps, keep an explicit approval gate — and use it to
force a pause for review, not just safety.
> "Prove the attacker impact but stop at proof — don't over-exploit. Present numbered options and wait for my
> approval before the destructive/exploit step."

### H. Periodic core re-read as an anti-laziness mechanism
The most reliable cure for mid-engagement drift. Bake it into a long run (a Stop-hook goal, or just say it every
few batches).
> "Read operator-core.md every few batches so the phases and method stay loaded, and keep dispatching until all
> surfaces are worked through."

---

## 5. What the docs already say

Per the request to separate signal from noise: many habitual session-prompts restate rules the model already
has. Restating a rule is **reinforcement when the model is drifting from it** and **noise when it isn't.** Here's
the honest split.

### Worth repeating (the model genuinely drifts from these)
| Habitual prompt | Already enforced by | Why still worth saying |
|---|---|---|
| "You're the operator, delegate / don't do it yourself" | operator-core *orchestrator brain*; hunting §18 | The model slides back into running tools itself on long runs. |
| "Leave no stone unturned / depth over speed / slow isn't dry" | hunting §5, §12, §16 | The strongest counter to shallow "no findings." |
| "What can an attacker do right now / no theory" | hunting §2; shared-constraints §7 | Counters overclaiming and theory-as-finding. |
| "Is this expected / already-admin / defense-in-depth" | hunting §3 | The model forgets precondition-equivalence under pressure to find Highs. |
| "Check siblings / chains" | hunting §9, §10; operator-core variant + chain passes | Tunnel vision after the first win. |
| "Re-read operator-core / confirm the phase" | operator-core Resume Gate | The single best drift reset. |
| "Severity must match real impact, not CVSS band" | hunting §20; shared-constraints §4 | The model inflates; this forces honesty. |

### Drop or downgrade (noise / not best practice)
- **Re-pasting the full program policy every message.** Put stable scope/policy facts in `scope.json`
  or one operator activity note; reference that state instead.
- **Anxious status pings** ("stuck or still working?", "status?") as a *technique*. Fine occasionally; not a
  method. Prefer a concrete check: "confirm running specialists are alive and writing files."
- **Micromanaging report formatting mid-stream.** The report rules + QA pass own this; let them run, then
  review once.
- **Heavy per-dispatch guardrails.** The model's own guidance (and yours) is that over-constraining chokes a
  subagent — hand it the hypothesis and the gap, not a checklist.
- **Stream-of-consciousness multi-topic prompts.** One dispatch, one objective reads better and dedups cleaner
  (shared-constraints §16; hunting §18).

---

## 6. Copy-paste templates

### Hunt-deeper (anti-laziness)
```
Keep dispatching specialists across all surfaces — batches, in parallel, each with enough scope to run deep
(not 30-second dispatches). Try non-trivial, creative paths and hunt siblings/clusters off anything that
signals. Slow isn't dry: exhaust each surface before rotating. Record to the backend as you go. Don't stop at
a stopping point — push past it and tell me what's left. Re-read operator-core.md every few batches.
```

### Escalate honestly
```
For [finding]: real-world entrypoint, mechanism, attacker outcome. Can it go higher via a sibling or chain?
Score the incremental impact over what the attacker already has — don't inflate. Stop at proof of impact.
```

### Fresh-skeptic verify
```
Dispatch a fresh, low-context specialist as a skeptical triager/maintainer on [finding]:
real-world impact or just a band fit? guards in the code that kill it (trust code over docs)? anything
"expected" / already-privileged / public-by-design? Hunt downgrades and missing evidence. Bullet what's off,
then recommend confirm / downgrade / kill.
```

### Triage reply
```
[Program] said [reason]. Fresh low-context specialist: read the finding, our submission, and their reply;
is the pushback fair? If we should push back, a concise professional reply (here, not in the submission) that
proves impact with evidence — only if it'll actually end the pushback. If they're right, say so and recommend
resubmit-under-different-VRT or drop.
```

---

## 7. The same prompts as client commands

Three of the §6 templates, plus four session-lifecycle prompts, ship as **client commands** so
you do not have to paste them. They live in one canonical source per command under
`agent/commands/<name>.md` and are rendered per client by
`agent/scripts/render-operator-prompts.sh`; `render-operator-prompts.sh check` fails on drift,
including on a missing rendered file. Never edit the rendered copies.

| Command | What it is |
|---|---|
| `vigil-start` | Open a new authorized engagement from the top of the operator workflow |
| `vigil-resume` | Re-hydrate the operator seat from the backend after a compaction, restart or handoff |
| `vigil-handoff` | Write the next operator a brief grounded in backend state, not recollection |
| `vigil-compact` | Show the standing compaction contract and audit whether it is being applied |
| `vigil-hunt-deeper` | §6 Hunt-deeper |
| `vigil-fresh-skeptic-verify` | §6 Fresh-skeptic verify |
| `vigil-triage-reply` | §6 Triage reply |

The `vigil-` prefix is mandatory: bare `resume` and `compact` collide with built-ins in both
clients.

- **Claude Code** — `/vigil-resume`, `/vigil-hunt-deeper`, … Arguments are passed inline
  (`/vigil-fresh-skeptic-verify idor-on-tenant-export`), and the commands run backend queries for
  you before you read them.
- **Codex** — `$vigil-resume`, `$vigil-hunt-deeper`, … Codex skills perform no argument or
  command substitution, so the Codex rendering states the commands for the agent to run and
  reads your intent from the message you send alongside the skill name.
- **opencode, goose and kimi get no commands.** Those clients have no equivalent
  project-command surface. Paste the §6 template, or the body of the matching
  `agent/commands/<name>.md`, into the session by hand — the content is identical, only the
  invocation differs.

Commands reach an engagement as pointers, not copies: `<engagement>/.claude/commands/<name>.md`
and `<engagement>/.codex/skills/<name>/` are per-entry symlinks into the install root, so an
engagement never carries a stale copy. A command you write yourself in an engagement's
`.claude/commands/` is preserved and wins over the shipped one of the same name.

### Compaction and session end are also automatic

- `agent/scripts/hooks/pre-compact.sh` is registered as a Claude Code `PreCompact` hook with no
  matcher, so it fires on manual `/compact` **and** on automatic context-window compaction. Its
  stdout becomes the summarizer's custom instructions, merged with any text you typed after
  `/compact`. An engagement adds its own rules by dropping a `COMPACT.md` in the engagement
  directory; it is appended to the standing contract, never a replacement. Vigil does not wire
  Codex's supported compaction events, so Codex operators run `$vigil-compact` and apply the
  contract by hand.
- `agent/scripts/hooks/session-end.sh` is registered as a `SessionEnd` hook on **both** Claude
  and Codex. It records an ordinary activity receipt that the client ended; it never replaces the
  operator's separate **save my place** checkpoint. Treat the receipt as best-effort: a crash,
  `SIGKILL` or host timeout fires no hook at all. The durable checkpoint is the one the operator
  writes with `vigil assess operator-checkpoint record`.

---

*A steering library, not a methodology spec. The methodology lives in `agent/operator-core.md`,
`agent/rules/hunting.md`, `agent/rules/adversarial-mindset.md`, and `agent/shared-constraints.md`; this is the
human's side of the keyboard — what to say when the model drifts away from them.*
