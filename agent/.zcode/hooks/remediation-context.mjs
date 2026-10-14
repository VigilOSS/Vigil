// Native SessionStart adapter. Only the prepared remediation plugin has context.
// This supplies pointers to authoritative case state, not a session receipt.
import { readFileSync, realpathSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const quote = value => "'" + value.replaceAll("'", "'\"'\"'") + "'"

async function restore() {
  let raw = ""
  for await (const chunk of process.stdin) raw += chunk
  const input = JSON.parse(raw)
  if (!input || typeof input !== "object" || Array.isArray(input)) return
  if (input.hook_event_name !== "SessionStart"
      || !["startup", "resume", "clear", "compact"].includes(input.source)) return

  // Resolve beside the script, including after ZCode copies an installed plugin.
  const plugin = dirname(dirname(fileURLToPath(import.meta.url)))
  const context = JSON.parse(readFileSync(join(plugin, "vigil-context.json"), "utf8"))
  if (!context || typeof context !== "object" || Array.isArray(context)) return
  for (const field of ["install_root", "engagement_dir", "engagement_key", "repository", "profile", "agent_root"]) {
    if (typeof context[field] !== "string" || !context[field]) return
  }
  if (typeof input.cwd !== "string"
      || realpathSync(input.cwd) !== realpathSync(context.repository)) return
  const scope = JSON.parse(readFileSync(join(context.engagement_dir, "scope.json"), "utf8"))
  if (scope.engagement_type !== "remediation" || scope.status !== "in_progress") return

  const cli = typeof context.helper_path === "string" && context.helper_path
    ? quote(join(context.helper_path, "vigil")) : "vigil"
  const command = `${cli} --root ${quote(context.install_root)} remediation -k ${quote(context.engagement_key)}`
  const text = [
    "Restore Vigil defensive remediation context before continuing. Case records are authoritative; the summary is an index.",
    `Engagement directory: ${JSON.stringify(context.engagement_dir)}`,
    `Repository context: ${JSON.stringify(context.repository)}`,
    `Read the selected profile: ${JSON.stringify(context.profile)} and applicable repository instructions.`,
    `Read remediation essentials: ${JSON.stringify(join(context.agent_root, "operator-core-remediation.md"))}.`,
    `Run ${command} list, then ${command} show <case-id> for the selected case.`,
    `Use the same explicit executable, --root, and engagement-key prefix for all subsequent remediation commands, including route --client zcode.`,
    "Reconcile case identity, registered code workspace and revision, owner-approved fix scope, structured verification requirements, evidence, and current review state before edits or conclusions.",
    "Edits and checks exercise the case workspace; the session repository is not proof of the tested revision. If the selected case or approval is uncertain, ask the owner before dependent work.",
    "Use explicit remediation commands for durable recording. This hook does not establish native conversation binding, exact join/recovery, or session termination.",
  ].join("\n")
  process.stdout.write(JSON.stringify({hookSpecificOutput: {
    hookEventName: "SessionStart", additionalContext: text,
  }}) + "\n")
}

try {
  await restore()
} catch {
  // A missing context or malformed event must not block native compaction.
  process.stderr.write("[vigil] Remediation context unavailable; verify the enabled plugin and selected engagement.\n")
}
