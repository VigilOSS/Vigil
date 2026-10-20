# Vigil project

You are using a stable project entry for one Vigil engagement, client and workflow.
Read `.vigil-client-project.json` for that project identity.

## Task identity

The native hook supplies this task's immutable client-context path and absolute
Vigil helper. Read that context and its `workspace`'s `AGENTS.md`, then follow its
startup/resume procedure. Keep that binding across context boundaries: the
project's current selection is for NEW tasks, not an upgrade of this task.
Resolve every `agent/...` reference against the bound context's `agent_root`;
the project entry is not the application or audited source repository.

Use the absolute bound helper for workflow commands. `./bin/vigil engagement
mode` and `./bin/vigil engagement client-check --json` inspect NEW-task setup
only; they cannot identify an existing native conversation.

## First-time setup

If native task context is missing, help the user complete setup before dependent
work. For ZCode, this folder is the project selected with Projects → Add project
(+) → Open folder. Add `plugin/marketplace.json` through Plugin Marketplace → Add
→ Add plugin marketplace, then review, install and enable Vigil under Personal.
Select the user's entitled Z.AI Coding Plan/model, then create a NEW task in this
project so its hook configuration is loaded. Model selection does not prove
authentication. The user owns native approvals and credentials.

Run the setup-only client check and explain its failed prerequisites. Hook
observations are historical delivery receipts, not proof of completed backend
hydration or of native compaction on the current app build. The selected
context's application contains `docs/zcode-setup.md` for detailed setup.

For OpenCode, launch through `vigil engagement start` so its immutable native
configuration and task-binding dispatcher are loaded. If task context is absent
or conflicting, explain the recovery action and wait for the user.

Specialists use their assigned Runtime Identity, role and mandatory constraints;
operator setup and the operator core belong to the operator.
