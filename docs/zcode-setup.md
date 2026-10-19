# ZCode setup

ZCode is the Z.AI desktop coding client. Vigil does not replace its login,
provider selection, model selection, or native approvals. Install and sign in
using the [official setup guide](https://zcode.z.ai/en/docs/install).

## Check the installed client

Run this independently of an engagement:

```bash
vigil engagement client-check --client zcode
vigil engagement client-check --client zcode --json
```

The standalone check reads application metadata on macOS, reports the supported
release range, and checks the required `uv`, Bash, jq, and Node executables. It
does not open ZCode, inspect credentials, contact a provider or backend, install
plugins, change configuration, prepare a workspace, or start services. A required
prerequisite failure produces a nonzero exit status.

An optional engagement key and `--mode web|code` inspect existing matching client
contexts: recorded executable paths and helper permissions, managed agent/scope
pointers, workspace and plugin file digests, and plugin release identity. This
does not repair files or establish that the plugin is enabled in ZCode. Without
an explicit application pin, release matching remains `UNVERIFIED`.

When invoked through the generated bound helper without an engagement key, the
check uses that helper's explicit context and engagement binding. It does not
guess from the current directory or a global active-engagement pointer.

`OBSERVED` means an exact-context historical receipt records startup, compaction,
or context injection; it does not certify the currently installed desktop/engine
build or conversation readiness. `UNVERIFIED` means proof was not established.
Native-build acceptance, authentication/model requests, and completed backend
hydration still require separate verification.

## Select a model

Click the model name in ZCode's chat box, choose **Manage Models**, and open the
**Z.ai** provider in **Settings → Model Settings**. Connect your account, select
**Coding Plan**, enable the provider, and choose an entitled model in the chat's
model selector. Vigil uses the client selection;
an installed application alone does not establish that a model request succeeds.
Keep authentication inside the client rather than placing credentials in a Vigil
prompt or engagement file. See [ZCode model connection](https://zcode.z.ai/en/docs/configuration).

## Open the workspace and enable the plugin

**Open the generated ZCode workspace, not the canonical engagement folder or the
Vigil source repository.** Start the selected engagement and mode from a terminal:

```bash
vigil engagement start <engagement-key> --mode code --client zcode
# For an admitted web track, select --mode web instead.
```

The launcher prints `workspace:` and prepares a release/context-bound folder at
`<engagement>/client-context/<binding-digest>/zcode`. Open that exact printed path
as the ZCode project. Its `AGENTS.md` router supplies absolute paths to the matched
helper, selected operator prompt, and canonical engagement state. Its `plugin/`
directory contains the local marketplace. Keep the generated binding intact;
another engagement, mode, or application release can have a different path.
The `plugin/` entry points to a private immutable plugin shared by matching
release/tool bindings; keep that managed link intact too. The context file is
`.vigil-client-context.json`, and the absolute bound helper is `bin/vigil` within
the printed workspace. Workspace preparation requires `uv`, Bash, jq, and Node
on the launching terminal's PATH so their executable paths can be bound explicitly.

An already running ZCode app does not reliably inherit the launcher's shell
environment. Use the explicit helper and literal paths in the generated router
and opening instructions rather than relying on terminal environment variables.
Opening this workspace is not evidence that a fresh task has started.

For an entrypoint that supplies a local marketplace:

1. Open its printed workspace in ZCode. Plugin management requires an open workspace.
2. Open **Plugin Marketplace** in the sidebar, then **Add → Add plugin
   marketplace** and enter the printed local marketplace file or directory.
   This path was checked in ZCode 3.15.3. Builds using the settings layout expose
   the equivalent **Settings → Plugins → Create → Add marketplace** action.
3. Find the matching Vigil plugin under **Personal**, inspect its components and
   hook scripts, install it, and confirm that it is enabled.
4. Disable any other Vigil context plugin bound to a different engagement or
   mode in that workspace, so competing hooks cannot inject another context.
5. Start a **new task** after enabling the plugin, then paste the complete
   opening prompt printed by Vigil. A task that predates plugin enablement is not
   a hook-delivery test.

The printed opening prompt supplies startup guidance independently of enabled
hooks. The workspace router also names this setup guide and requires the agent
to report missing plugin/hook setup before dependent work. If the plugin is not
enabled, its hooks cannot diagnose their own absence; use the printed prompt and
the read-only client check to bootstrap setup.

The [ZCode plugin guide](https://zcode.z.ai/en/docs/plugin) documents local
marketplaces and native components. Enabling a hook-bearing plugin grants local
code-execution trust; review it before enabling it. Project hook JSON by itself
does not establish active hook execution.

## Verify the running task

Check these as separate facts:

- The expected plugin is enabled and its commands are visible in the `/` picker.
- A new task received the expected startup context for the selected engagement.
- The task can execute the exact matched Vigil helper named in its opening
  instructions and read the correct engagement's backend state.
- A real compaction event delivered recovery context on this exact desktop and
  engine build, before relying on automatic recovery.

A workspace opening successfully does not prove that a new conversation exists.
Visible command files do not prove hooks ran, and hook context does not prove
that the agent completed backend hydration. If setup is missing, stop the
dependent work, report the failed check, repair the native setup, and begin a new
task with the printed opening instructions.

## Capability boundaries

ZCode documents `SessionStart` sources including `compact`, but native acceptance
must establish delivery on the installed desktop and engine version. An
[upstream report](https://github.com/zai-org/feedback/issues/357) describes missing
compact dispatch on an older engine. If recovery is unverified or fails, restore
context explicitly rather than treating a summary as current backend state.

The documented hook surface does not establish `PreCompact` summary steering,
a terminal `SessionEnd` event, or exact attachment to a native conversation.
`Stop` ends a model turn, not necessarily a task. Vigil does not treat a transient
macOS `open` process as ownership of a live conversation. See the
[native hook reference](https://zcode.z.ai/en/docs/hooks).

Blue and remediation behavior are unchanged. Existing repository-context
remediation setup is documented separately in
[remediation](remediation.md#opencode-and-zcode-repository-context): that entrypoint
opens the source repository configured in `PROJECT.md`, not the generated web/code
workspace described above.
