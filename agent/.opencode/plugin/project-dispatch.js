// Stable project protocol v1. Native session identity wins over launch selection.
import {readFileSync} from "node:fs"
import {join, dirname} from "node:path"
import {pathToFileURL, fileURLToPath} from "node:url"

export const VigilAssessmentHooks = async ({client}) => {
  const directory = dirname(dirname(fileURLToPath(import.meta.url)))
  const {bindingInfo, readSession, bindSession, currentBinding} = await import(pathToFileURL(join(directory, "vigil-project.mjs")))
  const path = process.env.VIGIL_CLIENT_CONTEXT
  if (!path) throw new Error("No native Vigil launch context")
  const launch = JSON.parse(readFileSync(path, "utf8"))
  if (launch.workspace !== dirname(directory)) throw new Error("Native plugin does not belong to its launch context")
  if (launch.install_root !== process.env.VIGIL_INSTALL_DIR) throw new Error("Native context differs from its official launch installation")
  const project = launch.project
  bindingInfo(path, project)
  const adapters = new Map()
  const resolveBinding = async (session, seen = new Set()) => {
    if (typeof session !== "string" || !session || seen.has(session) || seen.size >= 16)
      throw new Error("Invalid native session lineage")
    const previous = readSession(project, "opencode", session)
    if (previous) return previous
    seen.add(session)
    const response = await client.session.get({path: {id: session}})
    if (response.error || response.data?.id !== session) throw new Error("Native session unavailable")
    let selected
    if (response.data.parentID) {
      selected = await resolveBinding(response.data.parentID, seen)
    } else {
      const messages = await client.session.messages({path: {id: session}})
      if (messages.error || !Array.isArray(messages.data)) throw new Error("Native task history unavailable")
      if (messages.data.some(message => message.info?.role === "assistant" && message.info?.finish))
        throw new Error("Existing conversation has no retained Vigil binding; create a NEW task rather than selecting a new context for old history")
      selected = currentBinding(project)
    }
    return bindSession(project, "opencode", session, selected)
  }
  const adapter = async session => {
    const binding = await resolveBinding(session)
    if (!adapters.has(binding.binding_path)) {
      const source = join(binding.workspace, ".opencode/vigil-assessment-runtime.mjs")
      const module = await import(pathToFileURL(source))
      adapters.set(binding.binding_path, await module.VigilAssessmentHooks({client, bindingPath: binding.binding_path}))
    }
    return adapters.get(binding.binding_path)
  }
  const invoke = async (name, input, output) => {
    try { await (await adapter(input.sessionID))[name](input, output) }
    catch (error) {
      const message = `Vigil task binding unavailable: ${error.message}. Explain the recovery action and wait before dependent work.`
      if (name === "experimental.chat.system.transform") output.system.push(message)
      else if (name === "experimental.session.compacting") output.context.push(message)
      else console.error(message)
    }
  }
  return {
    "tool.execute.after": async (input, output) => invoke("tool.execute.after", input, output),
    "experimental.chat.system.transform": async (input, output) => invoke("experimental.chat.system.transform", input, output),
    "experimental.session.compacting": async (input, output) => invoke("experimental.session.compacting", input, output),
    event: async ({event}) => {
      const part = event.properties?.part
      if (event.type !== "message.part.updated" || part?.type !== "tool" || part.state?.status !== "error") return
      try { await (await adapter(part.sessionID)).event({event}) }
      catch (error) { console.error(`[vigil] Native activity unavailable: ${error.message}`) }
    },
  }
}
