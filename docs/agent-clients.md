# Agent clients

`--client` on `vigil engagement start` (and on `vigil bench run` for every client
except `kimi`) selects which agent CLI drives the engagement. All five read the
same operator prompt and run the same methodology; they differ in the model behind
them, in whether they can dispatch specialists headlessly, and in whether they
expose the `vigil-*` session commands.

| Client | Model / runtime | Headless dispatch | Session commands |
|--------|-----------------|-------------------|------------------|
| `claude` | Claude Code (Anthropic) | Yes (`@agent`) | Yes (`/vigil-*`) |
| `codex` | Codex CLI (OpenAI) | Yes (registered roster) | Yes (`$vigil-*`) |
| `kimi` | Kimi Code (Moonshot K3, the CLI default) | No — runs inline | No |
| `goose` | goose on direct DeepSeek | Yes — headless (`delegate`) | No |
| `opencode` | opencode on direct DeepSeek | No — runs inline | No |

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
  under `--skip-permissions`. The engagement's `.codex/config.toml` sets
  `[features] memories = false`, the Codex counterpart to Claude's
  `autoMemoryEnabled`. Codex ships memories off by default; Vigil pins it so an
  operator whose global `~/.codex/config.toml` enables the feature does not get
  a second cross-session store inside an engagement.
- **kimi** — execs `kimi`, with `--auto` under `--skip-permissions`. Runs the
  operator inline from the same prompt; it has no generated specialist roster or
  scope-guard hooks, and is not a `vigil bench run --client` option. Its model is
  deliberately not pinned.

## Open-model clients

`goose` and `opencode` run direct DeepSeek and require `DEEPSEEK_API_KEY` in
Vigil's environment. Set it once in the install root; the launcher exports it to
the client:

```bash
echo 'DEEPSEEK_API_KEY=sk-...' >> ~/vigil/.env
```

The key is resolved from the process environment, then the engagement's
`.orchestrator.env`, then the install root's `.orchestrator.env`, then the install
root's `.env` — first hit wins. The start preflight hard-fails for either open-model
client if none of them has `DEEPSEEK_API_KEY`. The launcher derives Goose's required
`OPENAI_API_KEY` from that DeepSeek credential so an unrelated ambient OpenAI key
cannot be sent to Vigil's DeepSeek endpoint. The Goose provider and upstream are
likewise pinned to the OpenAI-compatible adapter and `https://api.deepseek.com`, so
ambient Goose/OpenAI endpoint settings cannot redirect that credential.

### goose — the recommended open-model client

Unlike opencode it dispatches custom specialist subagents headlessly, *and* its
anti-cheat hook fires inside them.

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
reasoning-content repair proxy (`src/vigil_cli/bench/goose_reasoning_proxy.py`),
started by the launcher. goose splits a parallel-tool-call assistant turn into N
messages but keeps `reasoning_content` only on the first, and DeepSeek 400s on the
rest; the proxy re-attaches it. `parallel_tool_calls:false` does not help —
DeepSeek ignores the flag. Remove the proxy when #9397 is fixed upstream. Opt out
with `VIGIL_GOOSE_REASONING_PROXY=0`, and thinking then regresses to the #9397 400
on any batched-tool turn. Full detail: [`goose-bench.md`](goose-bench.md).

### opencode

```bash
vigil engagement start <key> --client opencode --thinking high
```

The launcher execs opencode's **default TUI** as `--agent operator`, not the
one-shot `opencode run`. The operator message is passed with `--prompt`.

`--thinking off|high|max` sets the DeepSeek reasoning level; it is optional here
and required only on `vigil bench run --client opencode`. opencode runs the
operator inline — it cannot dispatch custom specialists headlessly
(opencode#29616).

OpenRouter is not a supported launcher path; future evaluation is tracked in
[`TODO.md`](../TODO.md).

## What the launcher exports

Every client's launcher exports `ENGAGEMENT_DIR`, `VIGIL_SESSION_ENGAGEMENT_DIR`,
`ENGAGEMENT_KEY`, `VIGIL_AGENT_ROOT`, `VIGIL_INSTALL_DIR`, `VIGIL_CLIENT_NAME`,
and — only when not already set — `ORCHESTRATOR_BASE_URL`, resolved from the
engagement's `.orchestrator.env`, then the install root's `.orchestrator.env`, then
its `.env`.

The specialist roster links (`.codex/agents`, `.claude/agents`, both opencode
roster spellings, `.goose/recipes`) and the command surfaces (`.claude/commands`,
`.codex/skills`) are created at **engagement-create** time, not by the launcher.

## Forwarding flags to the client

`vigil engagement start` is the one verb parsed leniently: any flag it does not own
is forwarded to the client verbatim and echoed on stderr as
`[vigil] forwarding to the client: <args>`.

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

`vigil engagement start` owns exactly `key`, `--select`, `--client`, `--thinking`,
and `--skip-preflight`. There is no `--model` flag — `--model` is forwarded to the
client like any other unknown flag.
