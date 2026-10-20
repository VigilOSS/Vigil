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

The absolute helper injected into a native task checks that task's exact retained
context. From the stable Project folder, `./bin/vigil engagement client-check
--json` checks the selection for NEW tasks only. The installed `vigil` also
discovers this setup identity for mode inspection and client checks, but a folder
alone cannot identify an existing conversation. Workflow commands use the native
task's absolute context-bound helper. Outside a bound project, supply
`--client zcode` explicitly; the global active-engagement pointer does not select
a client context.

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

The launcher shows **Project folder** (or `workspace:` in redirected output):
`<engagement>/clients/zcode/code` (or `web`). Open this folder once as the ZCode
project and reuse it. Starting the same engagement/client/mode keeps this address
even when Vigil or ZCode is updated. Its root `AGENTS.md` explains setup and routes
each task into the immutable context delivered by the native hook. Its `plugin/`
entry contains the local dispatcher marketplace.
The compact setup instructions call the printed folder `<PATH>`. Replace that
shorthand with the full folder path before pasting into ZCode; for the marketplace
file, append `/plugin/marketplace.json`. The task prompt uses project-relative
files and commands rather than placeholders.
OpenCode uses the same stable per-engagement/client/mode entry. Claude and Codex
retain their existing engagement-root layouts. These project entries are not
checkouts: scope, evidence and backend records remain canonical.
Keep all managed files and the `plugin/` link intact. Preparation requires `uv`,
Bash, jq and Node on the launching terminal's PATH. The project bootstrap and
dispatcher retain a known Node launcher path so a desktop shell need not inherit
your terminal's PATH; relocating that executable requires explicit repair.

In the **Projects** sidebar, click **Add project (+) → Open folder**. In the macOS
folder chooser, press **Cmd+Shift+G**, paste the complete printed **Project folder**
path, press Return, and click **Open**. Vigil has already created that folder;
you are opening an existing folder as a project, not creating an empty directory.
The path ends in `/clients/zcode/code` or `/clients/zcode/web`. The canonical engagement
folder, its `source` folder, and the `plugin` folder are not the project to select.
If the project is already listed, select its matching workspace before creating a task.

An already running ZCode app does not reliably inherit the launcher's environment.
The native dispatcher binds a new task to the project's current selection and
injects its absolute context path and helper. The helper supplies the client,
mode, engagement, matching application, executable paths and backend explicitly.
Existing tasks keep their recorded binding after another start or compaction.
Vigil retains the versioned contexts under `client-context`; they are internal
task snapshots, not additional projects to add. No automatic cleanup infers that
an old native task has ended.

`./bin/vigil` in the stable project is setup-only, accepting `engagement mode` and
`engagement client-check`. An ordinary shell has no native conversation ID, so it
cannot safely choose an old task's helper from the current folder. Use the
absolute helper in that task's injected context for workflow commands. Opening
this workspace is not evidence that a fresh task has started.

For an entrypoint that supplies a local marketplace:

1. Open its printed workspace in ZCode. Plugin management requires an open workspace.
2. Open **Plugin Marketplace** in the sidebar, then **Add → Add plugin
   marketplace**. In **GitHub repo, git URL, file, or directory**, paste the Project
   folder path with `/plugin/marketplace.json` appended. This is a
   separate field from the project-folder chooser above.
   This path was checked in ZCode 3.15.3. Builds using the settings layout expose
   the equivalent **Settings → Plugins → Create → Add marketplace** action.
3. Find **vigil-project-v1** under **Personal**, inspect its components and
   hook scripts, install it, and confirm that it is enabled.
4. Keep this dispatcher enabled. It resolves each task separately; preparing a
   new retained application context does not require adding another marketplace.
5. Start a **new task** after enabling the plugin, then paste the complete
   opening prompt printed by Vigil. A task that predates plugin enablement is not
   a hook-delivery test.

The printed opening prompt supplies startup guidance independently of enabled
hooks. The workspace router also names this setup guide and requires the agent
to report missing plugin/hook setup before dependent work. If the plugin is not
enabled, its hooks cannot diagnose their own absence; use the printed prompt and
the read-only client check to bootstrap setup.

The opening prompt names the project-relative instruction file and project
identity. Native context supplies the task-specific binding and helper. It checks
the engagement, client, and workflow before proceeding. A successful mode check
identifies the Code or Web workflow and its operator prompt. If project identity
needs attention, the agent explains the check's recovery action and waits for you
to confirm setup is ready. Project selection and client startup are terminal
onboarding steps; source inventory and durable resume are separate workflow steps.

The root `AGENTS.md` describes the stable project and setup, then delegates to
the task's retained workflow router. Its writing follows the practical, verifiable guidance in
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

Native acceptance on ZCode Desktop 3.15.3 confirmed startup injection and bound
helper access to backend state. A real `/compact` completed, but produced no new
Vigil compact receipt or fresh compact context in the task. Do not interpret
successful native compression as verified automatic Vigil recovery on this build.

The documented hook surface does not establish `PreCompact` summary steering,
a terminal `SessionEnd` event, or exact attachment to a native conversation.
`Stop` ends a model turn, not necessarily a task. Vigil does not treat a transient
macOS `open` process as ownership of a live conversation. See the
[native hook reference](https://zcode.z.ai/en/docs/hooks).

Vigil leaves ZCode's native compaction settings unchanged. Its hook restores
workflow instructions only if a `compact` event actually reaches it; it does not
choose the native compaction threshold or certify completed hydration. Native
manual or automatic compression alone does not establish Vigil recovery.

After compaction, pause ongoing work and invoke `/vigil-resume` in the same task
when fresh recovery has not been verified. This reloads the selected workflow
instructions, engagement constraints, and current backend state using the task's
original immutable context and absolute helper. If the binding or hydration cannot
be verified, wait for repair before dependent work; the project's new-task
selection cannot identify or replace an existing task's context.

Explicit resume does not guarantee that an unattended mid-turn continuation waited
for hydration, or establish that earlier work used fresh state. Startup observations
and compacted summaries cannot supply that guarantee. Verify actual compact-event
delivery separately before relying on automatic recovery.

Existing tasks stay pinned while their verified binding receipts remain intact.
Missing receipts on `compact`/`clear`, or malformed receipts, produce a recovery
diagnostic rather than selecting a new context. If ALL receipt copies are lost,
an unknown `startup` event cannot distinguish an old conversation from a new
task; create a new task rather than continuing old history in that condition.
A specialist requires its parent's explicit Runtime Identity. When the native
event identifies a specialist but provides no retained binding, the dispatcher
reports the missing parent correlation instead of choosing another context.
An event without an actor identity cannot establish native parent ownership.
Dispatcher protocol assets are immutable; an asset collision or relocated Node
launcher requires maintainer-assisted inspection and repair before new starts,
rather than a live rewrite or automatic deletion of retained task assets.

Blue and remediation behavior are unchanged. Existing repository-context
remediation setup is documented separately in
[remediation](remediation.md#opencode-and-zcode-repository-context): that entrypoint
opens the source repository configured in `PROJECT.md`, not the generated web/code
workspace described above.
