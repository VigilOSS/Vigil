# ZCode setup

ZCode is the Z.AI desktop coding client. Vigil does not replace its login,
provider selection, model selection, or native approvals. Install and sign in
using the [official setup guide](https://zcode.z.ai/en/docs/install).

## Create or resume your first engagement

After installing Vigil, use its terminal picker:

```bash
vigil install
vigil engagement start --client zcode
```

Choose an existing engagement or **Create new engagement**. The shared creation
questions ask for the workflow and its required inputs; for ZCode select web or
code. Existing rows show their status, tracks and recent activity. The ordering
uses recorded work and official client launches/openings, with creation as a
fallback; it does not infer work from file modification times. An incomplete
history is labeled rather than presented as complete.

You can also create explicitly, using an authorized source directory:

```bash
vigil engagement create --type code --name acme --source-dir ./acme --no-prompt
vigil engagement start <printed-engagement-key> --mode code --client zcode
```

For web, use `vigil engagement create https://app.example.com --hosts app.example.com`
and then start the printed key with `--mode web --client zcode`. Use only targets
you are authorized to test. Creation preserves the source-trust and approval
boundaries of the selected workflow.

An explicit key skips engagement selection. If both web and code are enabled
and `--mode` is omitted, the terminal asks which one operator mode to launch.
Noninteractive calls must provide the key and any ambiguous mode explicitly.
Starting a client without a key always asks rather than silently using a current
directory or persisted selection. Other Vigil commands retain their own binding
rules.

Vigil then opens the exact generated project described below. Opening ZCode
alone, or using an unrelated project, does not install Vigil onboarding.

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
check uses that helper's explicit context and engagement binding. The installed
`vigil` discovers the same binding in a generated Project folder or its subfolders.
In either case, `vigil engagement client-check --json` uses the bound client when
`--client` is omitted. Outside a bound project, supply `--client zcode` explicitly;
the global active-engagement pointer does not select a client context.

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

The launcher shows **Project folder** (or `workspace:` in redirected output) and prepares a release/context-bound folder at
`<engagement>/client-context/<binding-digest>/zcode`. Open that exact printed path
as the ZCode project. Its `AGENTS.md` router supplies absolute paths to the matched
helper, selected operator prompt, and canonical engagement state. Its `plugin/`
directory contains the local marketplace. Keep the generated binding intact;
another engagement, mode, or application release can have a different path.
`<binding-digest>` is a generated fingerprint, not a value to invent or enter.
The compact setup instructions call the printed folder `<PATH>`. Replace that
shorthand with the full folder path before pasting into ZCode; for the marketplace
file, append `/plugin/marketplace.json`. The task prompt uses project-relative
files and commands rather than placeholders.
The same `client-context` mechanism is used by OpenCode web/code starts. Claude
and Codex retain their existing engagement-root layouts. The context folder is
not another checkout: scope, evidence and backend records remain canonical.
The `plugin/` entry points to a private immutable plugin shared by matching
release/tool bindings; keep that managed link intact too. The context file is
`.vigil-client-context.json`, and the absolute bound helper is `bin/vigil` within
the printed workspace. Workspace preparation requires `uv`, Bash, jq, and Node
on the launching terminal's PATH so their executable paths can be bound explicitly.

In the **Projects** sidebar, click **Add project (+) → Open folder**. In the macOS
folder chooser, press **Cmd+Shift+G**, paste the complete printed **Project folder**
path, press Return, and click **Open**. Vigil has already created that folder;
you are opening an existing folder as a project, not creating an empty directory.
The path ends in `/client-context/<binding-digest>/zcode`. The canonical engagement
folder, its `source` folder, and the `plugin` folder are not the project to select.
If the project is already listed, select its matching workspace before creating a task.

An already running ZCode app does not reliably inherit the launcher's shell
environment. The generated `bin/vigil` helper supplies `VIGIL_CLIENT_NAME=zcode`,
the selected workflow, engagement, and exact context-file path explicitly.
The installed `vigil` also discovers that identity for mode inspection, client checks,
and assessment commands run from the Project folder or its subfolders. It validates
the binding and managed-file digests before supplying session identity; it keeps
application code and backend selection independent of project metadata.
Use the helper and literal paths in the generated router for explicit session commands.
Opening this workspace is not evidence that a fresh task has started.

For an entrypoint that supplies a local marketplace:

1. Open its printed workspace in ZCode. Plugin management requires an open workspace.
2. Open **Plugin Marketplace** in the sidebar, then **Add → Add plugin
   marketplace**. In **GitHub repo, git URL, file, or directory**, paste the Project
   folder path with `/plugin/marketplace.json` appended. This is a
   separate field from the project-folder chooser above.
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

The opening prompt names the project-relative instruction file, context binding,
and Vigil helper. It checks the engagement, client, and workflow before proceeding. A successful mode check
identifies the Code or Web workflow and its operator prompt. If project identity
needs attention, the agent explains the check's recovery action and waits for you
to confirm setup is ready. Project selection and client startup are terminal
onboarding steps; source inventory and durable resume are separate workflow steps.

The generated root `AGENTS.md` puts session identity and absolute commands first,
then the plugin/model/new-task checklist, workflow entry and recovery, and
specialist boundaries. Its writing follows the practical, verifiable guidance in
[OpenAI's agent practices](https://learn.chatgpt.com/guides/best-practices),
[Anthropic's instruction-file guidance](https://code.claude.com/docs/en/memory),
and [ZCode's project-instruction rules](https://zcode.z.ai/en/docs/agents).
It explicitly directs the agent to read the selected canonical prompt rather
than embedding a second workflow or relying on automatic Markdown imports.
Instructions guide behavior; native approvals and executable contracts enforce
their respective boundaries.

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
