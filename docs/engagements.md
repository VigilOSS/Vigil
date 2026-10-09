# Engagements

Detail behind the README [Running an engagement](../README.md#running-an-engagement):
creation flags, tracks and modes, the start preflight, and how phases advance. Client setup
and flag forwarding: [`agent-clients.md`](agent-clients.md). Start and resume prompts:
[`session-commands.md`](session-commands.md).

## Creating an engagement

```bash
vigil engagement create https://target.example --hosts target.example
vigil engagement list --json                              # find the key
```

`create` starts the exploit policy at `pause` — explicit human approval before any exploit work
— and leaves authentication unset. When `--type` is omitted it is inferred from the inputs
(URL/host → `web`, `--repo` → `code`, APK or `--package-name` → `android`) and
echoed on stderr so it can be overridden; ambiguous inputs prompt on a terminal and fail fast
under `--no-prompt`. Combined source and web target inputs are rejected at creation so the
first track is explicit.

Scope hosts can be given as `--hosts a,b`, repeated `--host` flags, a
`--hosts-file`, or any mix. `--dry-run` validates without writing; `--json` emits an object
instead of the bare path. The path goes to stdout and everything else to stderr, so
`eng=$(vigil engagement create ...)` works even when the wizard engages. Start
`vigil mitmproxy start` / `vigil oob start` first if the target needs authenticated coverage or
out-of-band callbacks.

## Tracks and modes

Offensive engagements store enabled capabilities in `scope.json.tracks`. Creation enables one
track. Use `vigil engagement add-track <key> web|code` to enable the second explicitly. Then
start each operator session with `--mode web` or `--mode code`; each session reads only that
mode's operator prompt. `vigil engagement mode` reports the selected mode and prompt path from
inside a session. Selecting a mode does not add a track or change scope.

## Starting a session

`start` requires `--client`. It changes into the engagement directory, exports the engagement
environment ([what the launcher exports](agent-clients.md#what-the-launcher-exports)), then execs
the client. Flags it does not own are forwarded to the client
([forwarding rules](agent-clients.md#forwarding-flags-to-the-client)). The key may be omitted when
the current directory, active pointer, or `--select` resolves the engagement.

A preflight runs first. It **hard-fails** when the client binary is not on `PATH`, or when Goose or
OpenCode has no `DEEPSEEK_API_KEY` in the environment, the engagement's `.orchestrator.env`, or the
install root's env files. It **warns and continues** when the orchestrator is not running, the
Kali runtime container is not running, or the install root is stale. `--skip-preflight` bypasses
all five.

**Start engagements with `vigil engagement start` and nothing else.** An engagement directory
also holds a generated `start_<client>.sh`, and a bare `claude` or `codex` run from inside it
will start too — both are implementation detail, not supported entrypoints. Only the CLI verb
runs the preflight, refreshes the active-engagement pointer, and exports `ENGAGEMENT_KEY` and
`VIGIL_CLIENT_NAME`. Without the first, tool calls build malformed `/engagements/<key>/...`
container paths; without the second, the session-end receipt records the client as `unknown`.

For a human shell that jumps into a selected engagement directory, install the `athcd` helper
with `vigil engagement cd-init zsh >> ~/.zshrc`; non-interactive agents should pass an explicit
key instead.

## Phases

The three track rosters (see the README
[tracks table](../README.md#engagement-tracks-and-phases)) are pinned in
[`agent/scripts/assess/lib/phases.py`](../agent/scripts/assess/lib/phases.py).

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
