// Native plugin protocol. Never depend on Finder inheriting a terminal's env.
import {readFileSync, realpathSync, lstatSync, existsSync, writeFileSync, renameSync, mkdirSync, openSync, closeSync, unlinkSync} from "node:fs"
import {dirname, join} from "node:path"
import {fileURLToPath} from "node:url"
import {createHash, randomUUID} from "node:crypto"
import {execFileSync} from "node:child_process"

const hash = value => createHash("sha256").update(value).digest("hex")
const plugin = dirname(dirname(fileURLToPath(import.meta.url)))
let nativeEvent
const atomic = (path, object) => {
  if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error("Unsafe native receipt path")
  const temporary = path + "." + process.pid + "." + randomUUID() + ".tmp"
  let fd
  let created = false
  try {
    fd = openSync(temporary, "wx", 0o600)
    created = true
    writeFileSync(fd, JSON.stringify(object))
    closeSync(fd)
    fd = undefined
    renameSync(temporary, path)
  } finally {
    if (fd !== undefined) closeSync(fd)
    if (created) {
      try { unlinkSync(temporary) } catch (error) {
        if (error.code !== "ENOENT") process.stderr.write(`[vigil] Native temporary cleanup failed: ${error.message}\n`)
      }
    }
  }
}
const restore = async () => {
  let raw = ""
  for await (const chunk of process.stdin) raw += chunk
  const input = JSON.parse(raw)
  const event = input.hook_event_name || input.hookEventName
  if (!["SessionStart", "PostToolUse", "PostToolUseFailure"].includes(event)) return
  nativeEvent = event
  const session = input.session_id || input.sessionId
  if (typeof session !== "string" || !session) throw new Error("Native session identity is unavailable")
  const release = JSON.parse(readFileSync(join(plugin, "vigil-release.json"), "utf8")).release_id
  const registry = process.env.ZCODE_PLUGIN_DATA
  const receiptName = "session-" + hash(session) + ".json"
  let bindingPath = process.env.VIGIL_NATIVE_DISPATCH_CONTEXT
  if (!bindingPath && registry && existsSync(join(registry, receiptName))) {
    if (lstatSync(join(registry, receiptName)).isSymbolicLink()) throw new Error("Unsafe native binding receipt")
    const row = JSON.parse(readFileSync(join(registry, receiptName), "utf8"))
    if (row.session_id === session && row.release_id === release) bindingPath = row.binding_path
  }
  if (!bindingPath && typeof input.cwd === "string") {
    const candidate = join(input.cwd, ".vigil-client-context.json")
    if (existsSync(candidate) && !lstatSync(candidate).isSymbolicLink()) bindingPath = candidate
  }
  // Globally enabled plugins must stay silent in unrelated workspaces.
  if (!bindingPath) return
  if (lstatSync(bindingPath).isSymbolicLink()) throw new Error("Unsafe client binding")
  const binding = readFileSync(bindingPath)
  const context = JSON.parse(binding.toString("utf8"))
  const bindingDigest = createHash("sha256").update(binding).digest("hex")
  if (context.schema_version !== 1 || context.client !== "zcode" || context.release_id !== release) return
  if (!["web", "code"].includes(context.mode)) throw new Error("Invalid client mode")
  for (const key of ["workspace", "engagement_dir", "install_root", "agent_root", "vigil_cli"])
    if (typeof context[key] !== "string" || !context[key]) throw new Error(`Missing context ${key}`)
  if (realpathSync(dirname(bindingPath)) !== realpathSync(context.workspace)) throw new Error("Workspace binding mismatch")
  const scope = JSON.parse(readFileSync(join(context.engagement_dir, "scope.json"), "utf8"))
  if (scope.status !== "in_progress") return
  if (registry) {
    if (existsSync(registry) && lstatSync(registry).isSymbolicLink()) throw new Error("Unsafe plugin data directory")
    mkdirSync(registry, {recursive: true, mode: 0o700})
    atomic(join(registry, receiptName), {session_id: session, release_id: release, binding_path: bindingPath})
  }
  const env = {...process.env, ENGAGEMENT_DIR: context.engagement_dir,
    VIGIL_SESSION_ENGAGEMENT_DIR: context.engagement_dir, VIGIL_AGENT_ROOT: context.agent_root,
    VIGIL_INSTALL_DIR: context.install_root, VIGIL_OPERATOR_MODE: context.mode,
    VIGIL_CLIENT_NAME: "zcode", VIGIL_REQUESTED_CLIENT: "zcode",
    VIGIL_CLIENT_CONTEXT: bindingPath, VIGIL_APPLICATION_DIR: dirname(context.agent_root),
    ENGAGEMENT_KEY: context.engagement_key || context.engagement_dir.split("/").at(-1),
    ORCHESTRATOR_BASE_URL: context.backend_url,
    PATH: [join(context.workspace, "bin"), ...Object.values(context.tools || {}).map(value => dirname(value)), "/usr/bin", "/bin"].join(":")}
  // Legacy scalar scopes are admitted by Vigil's canonical mode owner too.
  // Ask the bound helper instead of growing a second legacy-track schema here.
  if (scope.tracks == null) {
    const modes = JSON.parse(execFileSync(context.vigil_cli, ["engagement", "mode", "--json"],
      {env, timeout: 4000, encoding: "utf8", maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"]}))
    if (modes.mode !== context.mode || !modes.enabled_tracks?.includes(context.mode))
      throw new Error("Bound mode is not enabled by the canonical engagement contract")
  } else if (!scope.tracks?.[context.mode]) {
    throw new Error("Bound mode is not enabled for this engagement")
  }
  const call = (name, payload) => execFileSync(context.tools?.bash || "bash",
    [join(context.agent_root, "scripts/hooks", name)], {input: JSON.stringify({...payload, cwd: context.engagement_dir}),
      env, timeout: 4000, encoding: "utf8", maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"]})
  if (event !== "SessionStart") {
    const failed = event === "PostToolUseFailure"
    call("post-tool-log.sh", {hook_event_name: "PostToolUse", client_name: "zcode", session_id: session,
      tool_use_id: input.tool_use_id || input.toolUseId, agent_type: input.agent_type || input.agentType || "unknown",
      tool_name: input.tool_name || input.toolName, tool_input: input.tool_input || input.toolInput || {},
      tool_response: failed ? {stderr: input.error || "Native tool failed", exit_code: 1}
        : input.tool_response ?? input.toolResponse ?? {}})
    return
  }
  if (!["startup", "clear", "compact"].includes(input.source)) return
  const actor = input.agent_type || input.agentType
  const specialist = typeof actor === "string" && actor && actor !== "operator"
  let text = specialist ? [
    "Restore only this specialist's assigned role, mandatory constraints, active ownership, and Runtime Identity; never load an operator core.",
    `Use ${JSON.stringify(context.vigil_cli)} for every Vigil command and read client context ${JSON.stringify(bindingPath)} for literal artifact paths.`,
  ].join("\n") : [
    `Restore the session-selected ${context.mode} Vigil operator. Engagement: ${JSON.stringify(context.engagement_dir)}.`,
    `Use ${JSON.stringify(context.vigil_cli)} instead of bare vigil for every command.`,
    `Read client context ${JSON.stringify(bindingPath)} for literal artifact paths; do not rely on GUI environment variables.`,
    `Read ${JSON.stringify(join(context.workspace, "AGENTS.md"))} for this task's immutable workflow router. Resolve every agent/... path against ${JSON.stringify(context.agent_root)}.`,
    `Run the bound helper's engagement mode command and read only its selected canonical prompt.`,
    `Read the engagement's ENGAGEMENT.md when present and apply agent/rules/resume.md before dependent work.`,
    "Every specialist assignment includes this client-context path, absolute helper, literal artifact paths, and its normal Runtime Identity. Specialists load their role/constraints, not the operator core.",
  ].join("\n")
  if (input.source === "compact" && !specialist) {
    const recovery = call("post-compact-resume.sh", {hook_event_name: "SessionStart", source: "compact"})
    if (!recovery.trim()) throw new Error("Compaction recovery is unavailable")
    text += "\n" + recovery
  }
  // This records delivery of context, never completion of the model's hydration.
  const health = join(context.workspace, ".vigil-health-" + hash(session) + ".json")
  let previous = {}
  if (existsSync(health) && !lstatSync(health).isSymbolicLink()) {
    const row = JSON.parse(readFileSync(health, "utf8"))
    if (row.schema_version === 1 && row.client === "zcode" && row.session_id === session
        && row.release_id === release && row.binding_sha256 === bindingDigest) previous = row
  }
  atomic(health, {...previous, schema_version: 1, client: "zcode", session_id: session,
    release_id: release, binding_sha256: bindingDigest, [input.source + "_observed"]: true, context_injected: true})
  process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: "SessionStart", additionalContext: text}}) + "\n")
}
try { await restore() } catch (error) {
  // Native compaction must never be wedged by an unavailable backend/helper.
  process.stderr.write(`[vigil] Native context unavailable: ${error.message}\n`)
  if (nativeEvent) process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: nativeEvent,
    additionalContext: "Vigil context could not be verified. STOP dependent work, read this workspace AGENTS.md, check the enabled plugin, and restore the selected workflow through its bound helper."}}) + "\n")
}
