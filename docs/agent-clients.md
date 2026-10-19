# Agent clients

`--client` on `vigil engagement start` selects the engagement's agent client.
Clients read the selected workflow's operator prompt; they differ in the model behind
them, in whether they can dispatch specialists headlessly, and in whether they
expose the `vigil-*` session commands.

For every client, `vigil engagement start --client <client>` opens the shared
recent-engagement picker with a **Create new engagement** action. An explicit
engagement key skips that picker. If the selected engagement has two enabled
tracks, an interactive start asks for one mode unless `--mode` is supplied;
noninteractive starts require an explicit key and any ambiguous mode.

| Client | Model / runtime | Headless dispatch | Session commands |
|--------|-----------------|-------------------|------------------|
| `claude` | Claude Code (Anthropic) | Yes (`Agent` with registered `subagent_type`) | Yes (`/vigil-*`) |
| `codex` | Codex CLI (OpenAI) | Yes (registered roster) | Yes (`$vigil-*`) |
| `kimi` | Kimi Code (Moonshot K3, the CLI default) | No — runs inline | No |
| `pi` | Pi with your configured provider/model (remediation only) | No | No Vigil commands |
| `goose` | goose on direct DeepSeek | Yes — headless (`delegate`) | No |
| `opencode` | Native selected provider/model for web/code | Native assessment roles; verify actual dispatch | Yes (`/vigil-*`) for web/code |
| `zcode` | ZCode desktop with native selected provider/model (macOS web/code) | Native plugin roles; verify actual dispatch | Yes (`/vigil-*`) through enabled plugin |

Claude and Codex compact automatically
([compaction hooks](session-commands.md#compaction-claude-and-codex)) and run with their
cross-session memory disabled, so the orchestrator ledger stays the engagement's single record.

Run one lead operator per engagement at a time unless you are deliberately coordinating a
dual-client run: both clients share durable orchestrator state, but filesystem artifacts under
an engagement directory are still ordinary files.

## Closed-model clients

`claude`, `codex`, and `kimi` need only the vendor CLI installed and
authenticated; they carry their own vendor auth, so the start preflight does not
check for a provider key.

- **claude** — execs `claude`, with `--dangerously-skip-permissions` when the
  engagement was created with `--skip-permissions`. The engagement's
  `.claude/settings.json` pins `"autoMemoryEnabled": false`, and the launcher
  also exports `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1`; because the setting lives in
  the engagement's own settings file, it holds however the client was started.
  Vigil does not broker or replace Claude's native authentication. For
  subscription use, remember that Claude gives inherited
  `ANTHROPIC_AUTH_TOKEN` / `ANTHROPIC_API_KEY` and cloud-provider routing variables
  precedence over `/login`; remove unintended overrides and use `/status` to confirm
  the active credential ([Claude authentication precedence](https://code.claude.com/docs/en/team#authentication-precedence)).
- **codex** — execs `codex`, with `--dangerously-bypass-approvals-and-sandbox`
  under `--skip-permissions`, and always with `--dangerously-bypass-hook-trust`.
  The second flag is not an autonomy setting: Codex treats a project-local
  `[hooks]` block as untrusted until it is reviewed per hook hash, so a session
  opens on "Hooks need review" and an operator who presses esc, or picks
  "Continue without trusting", runs with Vigil's activity-log and session-end
  receipt hooks disabled and no indication anywhere in the UI. Vigil generates
  that hooks file itself, from its own installed agent root, so the launcher
  vouches for it rather than leaving the engagement record to a startup
  keystroke; Codex shows a standing "hooks may run without review" warning for
  the whole session in exchange.
  This sets a floor on the Codex version: `--dangerously-bypass-hook-trust`
  arrived with the hook-trust gate, and an older `codex` rejects the flag and
  refuses to start. Verified against 0.154.0; upgrade if a launch fails on an
  unexpected-argument error.
  The engagement's `.codex/config.toml` sets
  `[features] memories = false`, the Codex counterpart to Claude's
  `autoMemoryEnabled`. Codex ships memories off by default; Vigil pins it so an
  operator whose global `~/.codex/config.toml` enables the feature does not get
  a second cross-session store inside an engagement. The same block pins
  `multi_agent_v2 = false`. Independently of this preference, the operator explicitly
  selects fresh child context in the available spawn schema (`fork_turns: none` when
  exposed). Native role selection is used when available; otherwise the child's first
  instruction names its canonical `agent/agents/<role>.md`, saved packet and Load First
  files. Installed `.codex/agents/*.toml` files do not prove that a particular child loaded them.

Hook trust and project trust are separate prerequisites; a successful launch does not
establish that activity hooks fired. Check actual activity/session receipts for the client
version in use. Headless hook delivery on Codex 0.163.0 remains unverified; an absent
hook receipt is not evidence that no work ran. See the [Codex hook contract](https://learn.chatgpt.com/docs/hooks).

Claude Code selects a registered specialist through its native `Agent` tool with that
role as `subagent_type`, supplying the saved dispatch packet. The selected wrapper
provides the specialist instructions; see [custom subagents](https://code.claude.com/docs/en/sub-agents).

Dispatch fingerprints use `instruction_identity_status=installed` when the expected installed
instruction files were hashed. They identify disk contents, not observed child execution or
model identity. Unobserved launch properties remain unknown. The same distinction applies to
all supported clients. Bind an exposed native client handle and inspect the handoff and actual
runtime state before closing a dispatch or releasing its proof ownership.

- **kimi** — execs `kimi`, with `--auto` under `--skip-permissions`. Runs the
  operator inline from the same prompt; it has no generated specialist roster or
  activity hooks. Its model is
  deliberately not pinned.

## Pi

Install [Pi](https://github.com/earendil-works/pi/tree/main/packages/coding-agent)
and configure a provider with `/login` inside Pi, or Pi's supported environment
variables. Vigil uses Pi's own model and authentication settings.

```bash
vigil engagement start <remediation-key> --client pi
vigil engagement start <remediation-key> --client pi -- --provider anthropic --model <model-id> --thinking medium
```

The launcher execs `pi` and forwards client arguments unchanged. Pi loads the
engagement's `AGENTS.md` natively. Use `--` before Pi's `--thinking` or `--mode`
flags because Vigil also owns flags with those names.

Pi supports remediation engagements only. Other engagement modes require a
specialist roster that Vigil does not install for Pi; start those engagements with
`--client codex` or `--client claude`. Vigil installs no Pi activity hooks
or `vigil-*` session commands. `--skip-permissions`
does not change the Pi launcher: Pi has no per-tool approval prompts by default.
Its project-trust settings remain under Pi's control. See
[Pi configuration](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/configuration.md)
and [Pi permissions](https://github.com/earendil-works/pi/blob/main/packages/coding-agent/docs/security.md).

New engagements receive `start_pi.sh` automatically. For an existing engagement,
run `vigil install` after updating the CLI; the existing entrypoint repair adds it
when the engagement's primary launcher configuration can be recognized.

## Open-model clients

`goose` and OpenCode's Blue integration run direct DeepSeek and require `DEEPSEEK_API_KEY` in
Vigil's environment. Set it once in the install root; the launcher exports it to
the client:

```bash
echo 'DEEPSEEK_API_KEY=sk-...' >> ~/vigil/.env
```

The key is resolved from the process environment, then the engagement's
`.orchestrator.env`, then the install root's `.orchestrator.env`, then the install
root's `.env` — first hit wins. The start preflight requires this key for Goose
and the OpenCode modes using that integration, not native web/code model selection.
The launcher derives Goose's required
`OPENAI_API_KEY` from that DeepSeek credential so an unrelated ambient OpenAI key
cannot be sent to Vigil's DeepSeek endpoint. The Goose provider and upstream are
likewise pinned to the OpenAI-compatible adapter and `https://api.deepseek.com`, so
ambient Goose/OpenAI endpoint settings cannot redirect that credential.

### goose — the recommended open-model client

Unlike opencode it dispatches custom specialist subagents headlessly.

```bash
brew install block-goose-cli
vigil engagement start <key> --client goose
```

`vigil engagement create` writes the engagement's `.goosehints` (the operator
prompt), the recipe roster, and the hooks, so no `.goose` folder setup is
required. goose has no operator wrapper agent: the prompt reaches it through
`.goosehints`, and specialist dispatch goes through the `delegate` tool.

A bare start opens an interactive `goose session`. Seeded with an operator message
it opens `goose run --interactive` instead, because `goose run` refuses to start
without an instruction.

The launcher pins the default model to `deepseek-v4-pro` (thinking), its
engagement-local recipe roster, and unattended safety/session settings. An explicit
`--model` client argument overrides the pinned default.

**The thinking path depends on a stopgap.** Thinking-mode DeepSeek-V4 on goose's
direct provider works around
[aaif-goose#9397](https://github.com/aaif-goose/goose/issues/9397) with a local
reasoning-content repair proxy (`src/vigil_cli/goose_reasoning_proxy.py`),
started by the launcher. goose splits a parallel-tool-call assistant turn into N
messages but keeps `reasoning_content` only on the first, and DeepSeek 400s on the
rest; the proxy re-attaches it. `parallel_tool_calls:false` does not help —
DeepSeek ignores the flag. Remove the proxy when #9397 is fixed upstream. Opt out
with `VIGIL_GOOSE_REASONING_PROXY=0`, and thinking then regresses to the #9397 400
on any batched-tool turn.

### opencode

```bash
vigil engagement start <key> --client opencode
```

The launcher execs opencode's **default TUI** as `--agent operator`, not the
one-shot `opencode run`. The operator message is passed with `--prompt`.

For web/code, select the provider and model natively; Vigil does not require a
DeepSeek key or force assessment specialist models. To use Z.AI Coding Plan,
connect the corresponding provider through `/connect` and choose an entitled
model through `/models`. See [OpenCode providers](https://opencode.ai/docs/providers/#zai).
Generated assessment roles inherit the selected model. Installed role files do
not prove that a particular specialist was dispatched successfully.

Blue's existing provider/model routing is unchanged. OpenCode native GUI/desktop
is not the tested Vigil surface; this integration targets stable 1.x CLI/TUI.

### ZCode desktop

```bash
vigil engagement start <key> --mode code --client zcode
```

Use `--mode web` for an admitted web track. Open the exact generated **Project folder**
path printed by Vigil, not the canonical engagement storage folder. Add the
workspace's printed local marketplace, install and enable its matched plugin,
then start a new ZCode task and use the printed opening instructions. A reused
desktop app is not a newly owned CLI session and may not inherit terminal variables.
The generated router provides explicit matched helper and engagement paths.

Native authentication, the selected Coding Plan model, and approvals remain
under ZCode's control. Specialists form a flat roster and opt out of automatic
operator `AGENTS.md` injection. ZCode support here is web/code only; Blue is not
enabled by this integration. Full setup and verification: [ZCode setup](zcode-setup.md).

## Repository-context remediation clients

`vigil remediation -k <key> start --client opencode` opens OpenCode's native TUI
with a defensive `/vigil-remediate` command. It retains native authentication,
models, approvals, and project plugins; choose Z.AI Coding Plan with `/connect`
and an entitled model with `/models`.

`vigil remediation -k <key> start --client zcode` opens a ZCode desktop workspace
on macOS and prepares a local defensive command/context plugin. The operator
installs and enables that plugin in ZCode, then starts a new task. This is a
workspace-open operation, not a recorded native conversation attachment.

Both entrypoints support one case per conversation and inherited hooks.
Vigil-native background workers, binding, exact join/recovery, and a verified
session-wide hook-disable mapping remain Claude-only. ZCode's post-compaction
hook restores pointers to authoritative remediation state; pre-compaction
steering and terminal session-end receipts are not claimed. Native end-to-end
acceptance steps are in [remediation](remediation.md#opencode-and-zcode-repository-context).

The dedicated [ZCode setup guide](zcode-setup.md) explains native Coding Plan
selection, workspace selection, local marketplace installation, plugin enablement,
fresh tasks, and verification. Read-only prerequisite checks are available without
opening a client or starting services:

```bash
vigil engagement client-check --client zcode
vigil engagement client-check --client opencode --json
```

These checks do not inspect credentials or test model access. Startup hooks,
compact hooks, and backend hydration remain separately reported as unverified
by this prerequisite command; verify their actual delivery separately in a
native session. It does not consume a runtime health receipt or certify readiness.

## What the launcher exports

CLI launchers export `ENGAGEMENT_DIR`, `VIGIL_SESSION_ENGAGEMENT_DIR`,
`ENGAGEMENT_KEY`, `VIGIL_AGENT_ROOT`, `VIGIL_INSTALL_DIR`, `VIGIL_APPLICATION_DIR`,
`VIGIL_CLIENT_NAME`,
and — only when not already set — `ORCHESTRATOR_BASE_URL`, resolved from the
engagement's `.orchestrator.env`, then the workspace's `.orchestrator.env`, then
its `.env`. `vigil engagement start` also exports `VIGIL_OPERATOR_MODE` for the selected
`--mode`. `VIGIL_INSTALL_DIR` identifies private workspace state;
`VIGIL_APPLICATION_DIR` and `VIGIL_AGENT_ROOT` identify this session's release assets.
The launcher pins its helper CLI to the same release so package upgrades do not
silently change an active session's contracts.

Claude/Codex/Goose and the Blue OpenCode roster links are created at
**engagement-create** time. OpenCode/ZCode web/code starts instead stage their
assessment assets in a separate immutable client workspace. ZCode's absolute
`bin/vigil` helper exports the bound context for its own process; it does not
change the environment of the already running desktop app or arbitrary shell
commands. Operators and specialists use the literal paths in that context.

## Forwarding flags to the client

`vigil engagement start` is the one verb parsed leniently: any flag it does not own
is forwarded to the client verbatim and echoed on stderr as
`[vigil] forwarding to the client: <args>`.
ZCode desktop is the exception: forwarded CLI flags are rejected, because its
model and approvals must be selected natively. Plain opening-prompt text is supported.

A `--`-prefixed token that closely resembles a real Vigil flag is refused with a
suggestion rather than forwarded:

```
vigil: error: unrecognized argument --thinkng; did you mean --thinking?
Pass it to the client verbatim with `-- --thinkng`.
```

A bare `--` declares everything after it as passthrough, exempt from that
typo check. Two consequences worth knowing: argparse abbreviation is on, so an
unambiguous prefix of a Vigil flag is consumed by Vigil rather than forwarded; and when
the optional engagement key is omitted, Vigil resolves the current engagement without
consuming the first client flag value or post-`--` message.

`vigil engagement start` owns exactly `key`, `--select`, `--client`, `--mode`, `--thinking`,
`--no-autoprompt`, and `--skip-preflight`. There is no `--model` flag — `--model` is forwarded to the
client like any other unknown flag.
