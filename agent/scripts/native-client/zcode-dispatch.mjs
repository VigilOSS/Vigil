// Frozen dispatcher-v1: enabled once; every task executes its own retained hooks.
import {findProject, projectInfo, readSession, bindSession, currentBinding, digest, regular, attest} from "./project-binding.mjs"
import {join, dirname} from "node:path"
import {fileURLToPath} from "node:url"
import {execFileSync} from "node:child_process"
let event
try {
  let raw = ""
  for await (const chunk of process.stdin) raw += chunk
  const input = JSON.parse(raw)
  event = input.hook_event_name || input.hookEventName
  if (!["SessionStart", "PostToolUse", "PostToolUseFailure"].includes(event)) process.exit(0)
  const session = input.session_id || input.sessionId
  if (typeof session !== "string" || !session) throw new Error("Native session identity is unavailable")
  let project = findProject(input.cwd)
  const registry = process.env.ZCODE_PLUGIN_DATA
  const globalReceipt = registry ? join(registry, "vigil-project-v1-" + digest(session) + ".json") : null
  if (!project && globalReceipt) {
    try { project = JSON.parse(regular(globalReceipt)).project }
    catch (error) { if (error.code !== "ENOENT") throw error }
  }
  if (!project) process.exit(0) // Globally enabled plugin stays silent elsewhere.
  const info = projectInfo(project)
  if (info.client !== "zcode") process.exit(0)
  const approvedPlugin = dirname(dirname(fileURLToPath(import.meta.url)))
  const owner = JSON.parse(regular(join(approvedPlugin, "vigil-owner.json")))
  const inventory = attest(approvedPlugin)
  if (!inventory["vigil-owner.json"] || owner.schema_version !== 1
      || info.install_root !== owner.install_root || info.engagements_root !== owner.engagements_root)
    throw new Error("Project does not belong to this user-approved dispatcher installation")
  let binding = globalReceipt ? readSession(project, "zcode", session, globalReceipt) : null
  binding ||= readSession(project, "zcode", session)
  if (!binding) {
    if (event !== "SessionStart" || input.source !== "startup")
      throw new Error("No retained binding for this conversation. Start a NEW task in this project.")
    const actor = input.agent_type || input.agentType
    if (typeof actor === "string" && actor && actor !== "operator")
      throw new Error("An unbound specialist needs its parent's explicit Runtime Identity; native parent correlation is unavailable")
    binding = bindSession(project, "zcode", session, currentBinding(project))
  }
  if (globalReceipt) binding = bindSession(project, "zcode", session, binding, globalReceipt)
  const plugin = join(binding.install_root, "client-plugins", binding.release_id.slice(0, 24), "zcode")
  const files = attest(plugin)
  if (!files["hooks/context.mjs"] || JSON.parse(regular(join(plugin, "vigil-release.json"))).release_id !== binding.release_id)
    throw new Error("Retained native hooks do not match this task")
  const output = execFileSync(binding.tools.node, [join(plugin, "hooks/context.mjs")], {
    input: raw, encoding: "utf8", timeout: 4500, maxBuffer: 1024 * 1024,
    env: {...process.env, VIGIL_NATIVE_DISPATCH_CONTEXT: binding.binding_path, ZCODE_PLUGIN_DATA: ""},
    stdio: ["pipe", "pipe", "pipe"]})
  process.stdout.write(output)
} catch (error) {
  process.stderr.write(`[vigil] Task context unavailable: ${error.message}\n`)
  if (event) process.stdout.write(JSON.stringify({hookSpecificOutput: {hookEventName: event,
    additionalContext: "Vigil could not verify this task's retained context. Explain the error and wait for the user before dependent work; the project's new-task selection cannot replace an existing conversation binding."}}) + "\n")
}
