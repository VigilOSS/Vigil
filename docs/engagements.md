# Engagements

Detail behind the README [Quick start](../README.md#quick-start) and
[Workflows and controls](../README.md#workflows-and-controls):
creation flags, tracks and modes, the start preflight, and how phases advance. Client setup
and flag forwarding: [`agent-clients.md`](agent-clients.md). Start and resume prompts:
[`session-commands.md`](session-commands.md).

## Creating an engagement

```bash
vigil engagement create                                  # follow the interactive questions
vigil engagement list --json                              # find the key
```

`create` starts the exploit policy at `pause` — explicit human approval before live exploit
work — and leaves authentication unset. Local sandbox proof uses the code route. When `--type` is omitted it is inferred from the inputs
(URL/host → `web`, APK or `--package-name` → `android`) and
echoed on stderr so it can be overridden; ambiguous inputs prompt on a terminal and fail fast
under `--no-prompt`. Repository selection requires explicit `--type remediation`.
Code creation accepts `--source-dir ./acme` to register an original directory, or prepares a
manual `source/` folder when omitted. The operator asks you to confirm the source, and that you
trust its build and test code to run inside the Vigil runtime, before first ingest or refresh. It
then creates one sealed audit copy directly from the selected directory.
Ordinary source folders and loose files work without Git. See [`code-analysis.md`](code-analysis.md).

Scope hosts can be given as `--hosts a,b`, repeated `--host` flags, a
`--hosts-file`, or any mix. `--dry-run` validates without writing; `--json` emits an object
instead of the bare path. The path goes to stdout and everything else to stderr, so
`eng=$(vigil engagement create ...)` works even when the wizard engages. Start
`vigil mitmproxy start` / `vigil oob start` first if the target needs authenticated coverage or
out-of-band callbacks.

## Tracks and modes

The creation type (`--type web` or `--type code`) selects the first durable track.
Offensive engagements persist enabled tracks and their independent phases in
`scope.json.tracks`; the stored engagement type is `offensive`. Starting a web or code
session initializes that track when needed, recording the transition and preserving
existing phases. `vigil engagement add-track <key> web|code` also initializes a track
without launching a session.

A session mode selects one operator prompt for one client process. Every offensive
engagement offers both web and code. Interactive `start` asks for a mode whenever
`--mode` is omitted, even with one initialized track. Noninteractive starts infer the
sole initialized track and require `--mode` when there are two. Change mode by starting
a new client process. Mode selection preserves target scope and exploit policy.

`vigil engagement mode <key>` inspects enabled tracks, phases, and prompt paths.
Inside a generated OpenCode or ZCode Project folder (including subfolders), Vigil
verifies the project binding and supplies the selected engagement, workflow, and client.
The same discovery supports `vigil assess` and `vigil engagement client-check`.
This identifies the project; native plugin execution and backend hydration have separate checks.

Outside a bound session, a dual-track engagement reports that this command has no
session binding. Source files describe available inputs, not the selected workflow.
Use `--client <client>` to request matching terminal start commands; a bound session
uses its own client by default. `--json` returns `client`, `selection_source`, a
`tracks` object and nullable `mode`, `prompt`, and per-track `start_command` fields.
An inherited mode from another engagement is ignored. Conflicting project and
environment identities are reported for operator review.

## Starting a session

Interactive `start` asks for engagement, client, then mode, skipping choices supplied
as flags. With no explicit key, starts always show the shared picker, even inside an
engagement or with a persisted selection. Choose an
existing engagement or **Create new engagement**. Rows show status, tracks and recent
activity; ordering uses meaningful recorded work and official client launch/open history,
falling back to creation. Missing history is labeled. Both engagement and remediation
startup use fzf search and workspace previews when fzf is installed; otherwise the
terminal picker supports typing to filter. Questions use shared Rich presentation.
Noninteractive engagement starts require a key and `--client`.

Legacy CLI clients start from the engagement root with their engagement environment
([what the launcher exports](agent-clients.md#what-the-launcher-exports)). OpenCode and
ZCode web/code sessions use their generated bound client workspace; ZCode opens that
folder as a project rather than becoming an owned CLI conversation. Flags Vigil does
not own follow the client's [forwarding rules](agent-clients.md#forwarding-flags-to-the-client).
Other commands keep their existing current-directory and active-pointer resolution.

A preflight runs first. It **hard-fails** when the client binary is not on `PATH`, or when Goose or
OpenCode's Blue integration has no `DEEPSEEK_API_KEY` in the environment, the engagement's `.orchestrator.env`, or the
workspace's env files. It recovers the default managed local backend when needed and refuses
launch when that managed backend remains unavailable or when any reachable backend belongs to
another workspace. A configured remote backend that cannot be reached at the transport level
produces a warning and launches against local engagement files only; backend-dependent commands
fail until that endpoint returns. A reachable backend that answers engagement synchronization
with a non-2xx response, or fails with a TLS or certificate error, refuses launch as a protocol
error. An older backend that cannot report its install root still receives the synchronization,
with a warning that workspace ownership is unverified. When the synchronization request itself
drops at the transport level after the backend answered, preflight warns and launches, and the
next backend request retries synchronization. Preflight never substitutes
localhost for a configured remote endpoint. Static code startup does not query
Docker. The first audited execution starts the managed Kali runtime if stopped; it never
recreates a running service. Application freshness remains a warning. `--skip-preflight`
bypasses these checks.

For a client session without Vigil's automatic opening message, pass `--no-autoprompt`:

```bash
vigil engagement start <engagement-key> --client codex --no-autoprompt
```

Explicit client messages are still forwarded. In code mode, source confirmation remains
required before first ingest or refresh. Existing sealed work resumes without repeating consent.
Claude's `-r`/`--resume` and Codex's `resume` requests start without an automatic opening message.

Startup refreshes generated client files only for the selected engagement. After an
application upgrade, an older official session on that same engagement must be ended
before the new release can refresh those shared files. The older process keeps its
matched assets and helpers available; startup never kills it automatically.

**Start engagements with `vigil engagement start` and nothing else.** An engagement directory
also holds a generated `start_<client>.sh`, and a bare `claude` or `codex` run from inside it
will start too — both are implementation detail, not supported entrypoints. Only the CLI verb
runs the preflight, refreshes the active-engagement pointer, and exports `ENGAGEMENT_KEY` and
`VIGIL_CLIENT_NAME`. Without the first, tool calls build malformed `/engagements/<key>/...`
container paths; without the second, the session-end receipt records the client as `unknown`.

For a human shell that jumps into a selected engagement directory, install the `athcd` helper
with `vigil engagement cd-init zsh >> ~/.zshrc`; non-interactive agents should pass an explicit
key instead.

## Proof work and continuation

Reopen the same engagement to retrieve its recorded investigation. In an existing native
conversation, `vigil-resume` retrieves current backend state; native chat history is separate.
Read existing work ownership before launching a specialist. Shared services and detached jobs
continue when a client exits. Nothing here restarts native clients unattended.

The current operator prepares proof for `pending_runtime_proof` candidates and claims the
work before launching a fresh specialist. A candidate carries the next test its verifier
recorded: hypothesis, confirming and falsifying observations, and a local or live route hint.
The explicit code route covers local library/API reproduction in audited Kali; the web route
covers admitted live targets under the applicable exploit approval. Neither requires a second
operator or both operator cores.

The UI's **Proof work** view shows owed candidates, their next tests, targets, owners, blockers,
approval and linked proof runs. Each entry shows a readiness state derived by the backend:
unprepared, ready, needs approval, in progress, blocked, stale, or done. It can prepare work,
record exact-work approval, reconcile state, and release ended ownership only after backend
liveness checks. Preparing or finishing a task never confirms the finding. Run evidence and the existing finding-verification requirements still apply.
Each entry links to its finding and its proof runs, a run links back to the proof work it served,
and a finding that awaits runtime proof shows the same entry in its own view.
A revised next test makes earlier work for that finding history: it keeps its runs and evidence,
reads stale or done, and the finding reads unprepared until work is prepared for the new plan.
New work reads blocked while an earlier owner of the same finding and route has not ended and
been released, because one worker owns a finding and route at a time.
A merged finding owes no proof work.

Manual inspection and recovery are available without launching a session:

```bash
vigil engagement prove <key>
vigil engagement prove <key> --finding VA-001 --mode code --objective "Challenge the supported API claim"
vigil engagement prove <key> --work 9 --reconcile
vigil engagement prove <key> --work 9 --release --reason "Ended worker and terminal jobs inspected"
```

Live approval is recorded in the UI or through the assess CLI:

```bash
vigil assess proof-work approve 9 --human-confirmation "Yes, run the bounded Acme test."
vigil assess proof-work revoke 9 --reason "Stop this test while access is reviewed."
```

The operator asks once and records the answer; the specialist checks the current work and
proceeds under that decision. `full_send` permits live proof without an additional per-work
grant, but an explicit revoke blocks that work until it is re-approved. Selected exploit
candidates do not authorize parked proof. New roots require explicit admission. Changes to
source, claim or admitted scope require current preparation; approval changes alone retain
ownership and context. Revocation does not terminate an already running command: use the
canonical run/job controls and inspect the result. Evidence remains in its original ledger.
The audit history records actor, confirmation or revocation reason verbatim. These fields
record the operator's assertion; they do not authenticate a separate human principal.

Finished work retains its lifecycle history after a material finding edit. The proof view's
separate verification-required list names the invalidating transition and next action.
Use `vigil assess contract proof-work` and `vigil assess contract finding update` for the
executable lifecycle and narrow same-verifier reproduction-enrichment contracts.

## Phases

The web, code, and blue phase rosters are pinned in
[`agent/scripts/assess/lib/phases.py`](../agent/scripts/assess/lib/phases.py). Each enabled
track's current phase is stored at `scope.json.tracks.<track>.phase`. The README
[phase table](../README.md#workflows-and-controls) lists web and code; blue phases are in
[`blue-engagements.md`](blue-engagements.md).

`complete` is a terminal state, not a working phase: no readiness gate, no audit tag, no
per-phase operator doc. The code vocabulary is deliberately distinct from the web one, and a
dual-track offensive engagement advances web and code independently. Older scopes with
`engagement_type=web|code|both` and scalar phase fields remain readable; new scopes use
`engagement_type=offensive` and the `tracks` map. Phase values are persisted, so
`consume` and `consume_test` are accepted as input aliases resolving to the canonical
`consume-test` at the boundary; the UI labels it "Consume & Test". Optional Athena log
investigation is a numbered step inside the exploit phase, not a phase of its own.

The specialist roster is shared across tracks and shipped with every engagement: `operator`,
`recon-specialist`, `surface-collector`, `source-analyzer`, `vulnerability-analyst`,
`exploit-developer`, `fuzzer`, `osint-analyst`, `report-writer`, the code roles
(`code-architect`, `code-vuln-hunter`, `code-vuln-verifier`, `code-variant-hunter`,
`code-fuzz-engineer`), and the blue roles (`alert-triage-specialist`, `investigator`,
`incident-verifier`, `ir-lead`). Validator-, chain-, and ranker-style behaviours are folded into
those roles rather than adding roster surface.

Transitions are gated on every track by `transition-phase`, which resolves the track from the
engagement (`--track web|code|blue` overrides). `--force` records a durable override decision, and
some integrity blockers cannot be forced at all.

```bash
vigil assess transition-phase <phase> [--track code] [--force --reason "<why>"]
```

Previewing readiness before a transition is per-track, because the tracks measure different
things. `check-phase-readiness` is the **web** gate and accepts only web phases; the code track
reads its readiness out of the coverage ledger; the blue gate runs inside `transition-phase`
itself and has no separate preview command.

```bash
vigil assess check-phase-readiness --phase <web-phase>                 # web
vigil assess code-coverage --require-transition-ready <code-phase>     # code
```
