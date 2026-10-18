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
manual `source/` folder when omitted. The operator asks for source confirmation before first
ingest or refresh, then creates one sealed audit copy directly from the selected directory.
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
`scope.json.tracks`; the stored engagement type is `offensive`. Use
`vigil engagement add-track <key> web|code` to enable the second explicitly.

A session mode selects one enabled track's operator prompt for one client process. A single
enabled track is selected automatically; with two tracks, `start` requires `--mode web` or
`--mode code`. Change mode by starting a new client process. Selecting a session mode does
not enable a track, reset its phase, or change scope.

`vigil engagement mode <key>` inspects enabled tracks, their phases, prompt paths, and complete
start commands without requiring a session selection. `--json` returns a `tracks` object and
nullable `mode` and `prompt` fields. In a session bound to that engagement, the selected mode
and prompt are reported too; an inherited mode from another engagement is ignored.

## Starting a session

`start` requires `--client`. Before launching, it prints the workspace, engagement, client,
selected mode, and track phase to stderr. It changes into the engagement directory, exports the engagement
environment ([what the launcher exports](agent-clients.md#what-the-launcher-exports)), then execs
the client. Flags it does not own are forwarded to the client
([forwarding rules](agent-clients.md#forwarding-flags-to-the-client)). The key may be omitted when
the current directory, active pointer, or `--select` resolves the engagement.

A preflight runs first. It **hard-fails** when the client binary is not on `PATH`, or when Goose or
OpenCode has no `DEEPSEEK_API_KEY` in the environment, the engagement's `.orchestrator.env`, or the
workspace's env files. It recovers the default managed local backend when needed and refuses
launch when that managed backend remains unavailable or when any reachable backend belongs to
another workspace. A configured remote backend that is temporarily unreachable produces a
warning and launches against local engagement files only; backend-dependent commands fail until
that endpoint returns. A matching backend whose immediate synchronization races also warns and
continues because the next backend request retries synchronization. Preflight never substitutes
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
work before launching a fresh specialist. The explicit code route covers local library/API
reproduction in audited Kali; the web route covers admitted live targets under the applicable
exploit approval. Neither requires a second operator or both operator cores.

The UI's **Proof work** view shows owed candidates, targets, owners, blockers, approval and
linked proof runs. It can prepare work, record exact-work approval, reconcile state, and release
ended ownership only after backend liveness checks. Preparing or finishing a task never
confirms the finding. Run evidence and the existing finding-verification requirements still apply.

Manual inspection and recovery are available without launching a session:

```bash
vigil engagement prove <key>
vigil engagement prove <key> --finding VA-001 --mode code --objective "Challenge the supported API claim"
vigil engagement prove <key> --work 9 --reconcile
vigil engagement prove <key> --work 9 --release --reason "Ended worker and terminal jobs inspected"
```

For a selected live proof, `--work 9 --approve` records approval for that prepared objective,
source, finding and admitted targets; `--revoke` removes that work's explicit approval. A
broader existing policy can still authorize it. New roots require explicit admission. Changed
source, claim or scope requires current preparation before further execution. Owner updates
can still preserve the result of work that already ran; they do not authorize new testing.
Agents use `vigil assess contract proof-work` for the executable payload/lifecycle contract.

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
