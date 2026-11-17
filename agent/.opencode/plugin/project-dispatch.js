// Stable project protocol v1. Native session identity wins over launch selection.
import {readFileSync} from "node:fs"
import {join, dirname} from "node:path"
import {pathToFileURL, fileURLToPath} from "node:url"

const directory = dirname(dirname(fileURLToPath(import.meta.url)))
// The launch this staged copy belongs to; the plugin refuses to load for any other.
const launchProject = async () => {
  const project = await import(pathToFileURL(join(directory, "vigil-project.mjs")))
  const path = process.env.VIGIL_CLIENT_CONTEXT
  if (!path) throw new Error("No native Vigil launch context")
  const launch = JSON.parse(readFileSync(path, "utf8"))
  if (launch.workspace !== dirname(directory)) throw new Error("Native plugin does not belong to its launch context")
  if (launch.install_root !== process.env.VIGIL_INSTALL_DIR) throw new Error("Native context differs from its official launch installation")
  project.bindingInfo(path, launch.project)
  return {...project, project: launch.project}
}
const unavailable = error => `Vigil task binding unavailable: ${error.message}. Explain the recovery action and wait before dependent work.`

// A session's task binding follows its native lineage, read through the plugin context's session domain.
const setup = async ctx => {
  const {readSession, bindSession, currentBinding, project} = await launchProject()
  const {registerV2Hooks} = await import(pathToFileURL(join(directory, "vigil-assessment-runtime.mjs")))
  const resolveBinding = async (session, seen = new Set()) => {
    if (typeof session !== "string" || !session || seen.has(session) || seen.size >= 16)
      throw new Error("Invalid native session lineage")
    const previous = readSession(project, "opencode", session)
    if (previous) return previous
    seen.add(session)
    const info = await ctx.session.get({sessionID: session})
    if (info?.id !== session) throw new Error("Native session unavailable")
    let selected
    if (info.parentID) {
      selected = await resolveBinding(info.parentID, seen)
    } else {
      // Messages from the latest compaction on: a compaction is itself old history.
      const messages = await ctx.session.context({sessionID: session})
      if (!Array.isArray(messages)) throw new Error("Native task history unavailable")
      if (messages.some(message => message?.type === "compaction" || (message?.type === "assistant" && message.finish)))
        throw new Error("Existing conversation has no retained Vigil binding; create a NEW task rather than selecting a new context for old history")
      selected = currentBinding(project)
    }
    return bindSession(project, "opencode", session, selected)
  }
  const adapters = new Map()
  // An event never binds a session; it reaches only a session already bound to a task.
  const adapter = async (session, bind) => {
    const binding = bind ? await resolveBinding(session) : readSession(project, "opencode", session)
    if (!binding) return null
    if (!adapters.has(binding.binding_path)) {
      const loading = (async () => {
        const module = await import(pathToFileURL(join(binding.workspace, ".opencode/vigil-assessment-runtime.mjs")))
        if (typeof module.VigilAssessmentHooksV2 !== "function")
          throw new Error("This task's retained Vigil runtime has no OpenCode 2 adapter; start a NEW task")
        return module.VigilAssessmentHooksV2({ctx, bindingPath: binding.binding_path})
      })()
      adapters.set(binding.binding_path, loading)
      loading.catch(() => adapters.delete(binding.binding_path))
    }
    return adapters.get(binding.binding_path)
  }
  return registerV2Hooks(ctx, async (key, event) => {
    const fromEvent = key === "session.revert.committed"
    const session = fromEvent ? event.data?.sessionID : event.sessionID
    try {
      if (fromEvent && typeof session !== "string") return
      const handlers = await adapter(session, !fromEvent)
      if (handlers) await handlers[key](event)
    } catch (error) {
      const message = unavailable(error)
      if (key === "session.context" || key === "session.compaction") event.system.push({type: "text", text: message})
      else console.error(message)
    }
  })
}

export default {id: "vigil-assessment", setup}
