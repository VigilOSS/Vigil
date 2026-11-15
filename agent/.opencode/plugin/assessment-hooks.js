// Native web/code adapter. The legacy standard plugin remains Blue-owned.
import {execFile, execFileSync} from "node:child_process"
import {readFileSync, realpathSync, writeFileSync, renameSync, existsSync, lstatSync, openSync, closeSync, unlinkSync} from "node:fs"
import {join, dirname} from "node:path"
import {createHash, randomUUID} from "node:crypto"
import {promisify} from "node:util"

const execFileAsync = promisify(execFile)
const PACKET_REFERENCE = /tools\/dispatch-packets\/(\d+)\/([0-9a-f]{64})\.md/g
const BIND_ATTEMPTS = 3

export const VigilAssessmentHooks = async ({client, bindingPath = process.env.VIGIL_CLIENT_CONTEXT}) => {
  const states = new Map()
  const readContext = () => {
    if (!bindingPath) throw new Error("No native Vigil context binding")
    const binding = readFileSync(bindingPath)
    const context = JSON.parse(binding.toString("utf8"))
    if (context.schema_version !== 1 || context.client !== "opencode" || !["web", "code"].includes(context.mode))
      throw new Error("Invalid native Vigil context")
    for (const key of ["workspace", "engagement_dir", "agent_root", "vigil_cli", "install_root", "release_id"])
      if (typeof context[key] !== "string" || !context[key]) throw new Error(`Missing context ${key}`)
    const scope = JSON.parse(readFileSync(join(context.engagement_dir, "scope.json"), "utf8"))
    if (scope.status !== "in_progress") throw new Error("Engagement is not in progress")
    realpathSync(context.workspace)
    return {...context, binding_sha256: createHash("sha256").update(binding).digest("hex")}
  }
  const env = context => ({...process.env, ENGAGEMENT_DIR: context.engagement_dir,
    VIGIL_SESSION_ENGAGEMENT_DIR: context.engagement_dir, VIGIL_AGENT_ROOT: context.agent_root,
    VIGIL_INSTALL_DIR: context.install_root, VIGIL_OPERATOR_MODE: context.mode,
    VIGIL_CLIENT_CONTEXT: bindingPath, VIGIL_APPLICATION_DIR: dirname(context.agent_root),
    VIGIL_REQUESTED_CLIENT: "opencode", ENGAGEMENT_KEY: context.engagement_key || context.engagement_dir.split("/").at(-1),
    VIGIL_CLIENT_NAME: "opencode", ORCHESTRATOR_BASE_URL: context.backend_url || process.env.ORCHESTRATOR_BASE_URL,
    PATH: [join(context.workspace, "bin"), ...Object.values(context.tools || {}).map(value => dirname(value)),
      process.env.PATH || "/usr/bin:/bin"].join(":")})
  const hook = (context, name, payload) => execFileSync(context.tools?.bash || "bash",
    [join(context.agent_root, "scripts/hooks", name)], {input: JSON.stringify({...payload, cwd: context.engagement_dir}),
      env: env(context), encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024, stdio: ["pipe", "pipe", "pipe"]})
  const statePath = (context, session) => join(context.workspace,
    ".vigil-health-" + createHash("sha256").update(String(session)).digest("hex") + ".json")
  const state = (context, session) => {
    if (states.get(session)?.binding_sha256 !== context.binding_sha256) {
      let existing = {schema_version: 1, release_id: context.release_id,
        binding_sha256: context.binding_sha256, client: "opencode", session_id: session}
      const path = statePath(context, session)
      if (existsSync(path)) {
        if (lstatSync(path).isSymbolicLink()) throw new Error("Unsafe health path")
        const row = JSON.parse(readFileSync(path, "utf8"))
        if (row.schema_version === 1 && row.client === "opencode"
            && row.release_id === context.release_id && row.session_id === session
            && row.binding_sha256 === context.binding_sha256) existing = row
      }
      states.set(session, existing)
    }
    return states.get(session)
  }
  const observe = (context, session, fields) => {
    const row = Object.assign(state(context, session), {schema_version: 1,
      release_id: context.release_id, binding_sha256: context.binding_sha256,
      client: "opencode", session_id: session}, fields)
    const path = statePath(context, session)
    const temp = path + "." + process.pid + "." + randomUUID() + ".tmp"
    let fd
    let created = false
    try {
      fd = openSync(temp, "wx", 0o600)
      created = true
      writeFileSync(fd, JSON.stringify(row))
      closeSync(fd)
      fd = undefined
      renameSync(temp, path)
    } finally {
      if (fd !== undefined) closeSync(fd)
      if (created) {
        try { unlinkSync(temp) } catch (error) {
          if (error.code !== "ENOENT") console.error(`[vigil] Health temporary cleanup failed: ${error.message}`)
        }
      }
    }
  }
  const pointers = context => [
    `Vigil mode: ${context.mode}. Canonical engagement: ${JSON.stringify(context.engagement_dir)}.`,
    `Use the absolute bound helper ${JSON.stringify(context.vigil_cli)} for every Vigil command.`,
    `Client context: ${JSON.stringify(bindingPath)}. Treat environment-variable artifact paths as literal paths from this binding.`,
    `Read ${JSON.stringify(join(context.workspace, "AGENTS.md"))} for this task's immutable workflow router. Resolve every agent/... path against ${JSON.stringify(context.agent_root)}.`,
  ].join("\n")
  const request = async sessionID => {
    const response = await client.session.messages({path: {id: sessionID}})
    if (response.error || !Array.isArray(response.data)) throw new Error("Native messages unavailable")
    const session = await client.session.get({path: {id: sessionID}})
    if (session.error || !session.data || session.data.id !== sessionID) throw new Error("Native session unavailable")
    let messages = response.data.slice().sort((a, b) =>
      (a.info?.time?.created ?? 0) - (b.info?.time?.created ?? 0) || String(a.info?.id).localeCompare(String(b.info?.id)))
    const boundary = session.data.revert?.messageID
    if (boundary) {
      const index = messages.findIndex(message => message.info?.id === boundary)
      if (index < 0) throw new Error("Native revert boundary unavailable")
      // The current unfinished request is created after the active revert and is
      // still needed for attribution. Historical summaries beyond it are not.
      const current = messages.filter(message => message.info?.role === "assistant" && !message.info?.finish && !message.info?.error)
      messages = [...messages.slice(0, index), ...current]
    }
    const assistants = messages.filter(message => message.info?.role === "assistant")
    const pending = [...new Map(assistants.filter(message => !message.info.finish && !message.info.error)
      .map(message => [message.info.id, message.info])).values()]
    const current = pending.length === 1 ? pending[0] : null
    if (!current || current.sessionID !== sessionID)
      throw new Error("Current unfinished assistant cannot be correlated")
    return {current, messages, boundary: boundary || null, parentID: session.data.parentID,
      directory: session.data.directory}
  }
  // A native task child names its dispatch only through the launch message's
  // content-addressed packet path. The packet's leading Runtime Identity names
  // the dispatch, and the backend row must agree before the handle is bound.
  const dispatches = new Map()
  const helper = async (context, args) => {
    const {stdout} = await execFileAsync(context.vigil_cli, args, {cwd: context.workspace, env: env(context),
      encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024})
    return JSON.parse(stdout.trim().split("\n").at(-1))
  }
  const failure = error => String(error.stderr || error.message || error).trim().slice(-500)
  const packetIdentity = (context, id, sha256) => {
    const path = join(realpathSync(context.engagement_dir), "tools/dispatch-packets", id, sha256 + ".md")
    const metadata = lstatSync(path)
    if (realpathSync(path) !== path || !metadata.isFile() || metadata.size > 1024 * 1024)
      throw new Error("Dispatch packet is not a bounded regular file")
    const bytes = readFileSync(path)
    if (createHash("sha256").update(bytes).digest("hex") !== sha256) throw new Error("Dispatch packet differs from its SHA-256")
    const [heading, ...lines] = bytes.toString("utf8").split("\n")
    const fields = {}
    if (heading === "## Runtime Identity")
      for (const line of lines) {
        if (!line.trim()) break
        const match = /^([a-z_]+): (.+)$/.exec(line)
        if (match) fields[match[1]] = match[2].trim()
      }
    if (!fields.agent_id || !/^[a-z0-9][a-z0-9-]*$/.test(fields.agent_role || ""))
      throw new Error("Dispatch packet has no Runtime Identity")
    return fields
  }
  const resolveDispatch = async (context, session, native, attempts) => {
    const launch = native.messages.find(message => message.info?.role === "user")
    const text = (launch?.parts || []).filter(part => part?.type === "text").map(part => String(part.text)).join("\n")
    const packets = [...new Set([...text.matchAll(PACKET_REFERENCE)].map(match => `${match[1]}/${match[2]}`))]
    if (packets.length !== 1)
      return packets.length ? {status: "unresolved", reason: "ambiguous_dispatch_packets", packets, advisories: []}
        : {status: "unresolved", reason: "no_dispatch_packet", advisories: []}
    const [id, sha256] = packets[0].split("/")
    const info = native.current
    const record = {dispatch_id: Number(id), packet_sha256: sha256, handle: session,
      session_namespace: native.directory || context.project || context.workspace,
      native_agent: info.agent || "unknown", model: `${info.providerID}/${info.modelID}`,
      variant: info.variant || "default"}
    let identity
    try { identity = packetIdentity(context, id, sha256) } catch (error) {
      return {...record, status: "unresolved", reason: "packet_unverified", detail: error.message, advisories: []}
    }
    Object.assign(record, {agent_id: identity.agent_id, registered_role: identity.agent_role})
    const reference = {agent_id: record.agent_id, dispatch_id: record.dispatch_id}
    const mismatch = record.native_agent === record.registered_role ? [] : [{advisory: "native_agent_role_mismatch",
      ...reference, registered_role: record.registered_role, native_agent: record.native_agent, handle: session}]
    const outcome = ({advisories = [], ...fields}) => ({...record, ...fields, advisories: [...mismatch, ...advisories]})
    let row
    try { row = await helper(context, ["assess", "agent", "get", record.agent_id]) } catch (error) {
      if (error.code === 2) return outcome({status: "unresolved", reason: "dispatch_not_found"})
      return outcome({status: "failed", reason: "helper_failed", detail: failure(error), attempts: attempts + 1})
    }
    if (row?.id !== record.dispatch_id || row.agent_id !== record.agent_id || row.agent_role !== record.registered_role)
      return outcome({status: "unresolved", reason: "dispatch_identity_mismatch"})
    if (row.status !== "in-progress")
      return outcome({status: "unresolved", reason: "dispatch_not_in_progress", dispatch_status: row.status})
    const current = row.client_binding
    if (current?.asserted_client_handle === session)
      return outcome({status: "already_bound", binding_version: current.binding_version})
    // A second live session for one packet is a duplicate launch, not a correction.
    if (current) return outcome({status: "unresolved", reason: "dispatch_bound_elsewhere",
      advisories: [{advisory: "dispatch_already_bound", ...reference, handle: session,
        bound_client: current.asserted_client, bound_handle: current.asserted_client_handle}]})
    const note = `Recorded by the Vigil OpenCode plugin at native task session ${session}'s first request `
      + `(dispatch packet ${sha256}). Observed native agent ${record.native_agent}, model ${record.model}, `
      + `variant ${record.variant}.` + (mismatch.length ? ` The native agent differs from registered role ${record.registered_role}.` : "")
    try {
      const bound = await helper(context, ["assess", "agent", "bind-client-handle", record.agent_id, "--client", "opencode",
        "--session-namespace", record.session_namespace, "--handle", session, "--note", note])
      return outcome({status: bound?.already_bound ? "already_bound" : "bound", binding_version: bound?.binding?.binding_version})
    } catch (error) {
      return outcome({status: "failed", reason: "helper_failed", detail: failure(error), attempts: attempts + 1})
    }
  }
  const dispatchFor = async (context, session, native) => {
    const previous = await dispatches.get(session)
    if (previous && !(previous.status === "failed" && previous.attempts < BIND_ATTEMPTS)) return previous
    const pending = resolveDispatch(context, session, native, previous?.attempts || 0).catch(error =>
      ({status: "failed", reason: "plugin_error", detail: failure(error), attempts: (previous?.attempts || 0) + 1, advisories: []}))
    dispatches.set(session, pending)
    const record = await pending
    if (record.status === "failed") console.error(`[vigil] Dispatch binding for ${session} failed: ${record.detail}`)
    return record
  }
  // The operator sees the task result, never the child's system prompt.
  const reportDispatch = async output => {
    const session = output?.metadata?.sessionId
    if (typeof session !== "string" || !dispatches.has(session)) return
    const record = await dispatches.get(session)
    if (record.reason === "no_dispatch_packet" || record.reported) return
    record.reported = true
    const {reported, attempts, ...shown} = record
    output.output = `${output.output ?? ""}\n\nVigil dispatch binding: ${JSON.stringify(shown)}`
      + (["bound", "already_bound"].includes(record.status)
        ? "\nThis handle is recorded; run `agent bind-client-handle` only to correct it." : "")
  }
  const toolName = tool => ({bash: "Bash", read: "Read", write: "Write", edit: "Edit",
    task: "Agent", webfetch: "WebFetch", websearch: "WebSearch", skill: "Skill"}[tool] || tool)
  const nativeToolName = async tool => {
    if (toolName(tool) !== tool) return toolName(tool)
    // The public SDK exposes connected MCP servers and the built-in/custom
    // registry separately. Do not classify arbitrary underscore names as MCP.
    let timer
    try {
      const [servers, local] = await Promise.race([
        Promise.all([client.mcp.status(), client.tool.ids()]),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Native tool catalog timeout")), 1000) }),
      ])
      if (servers.error || local.error || !servers.data || !Array.isArray(local.data))
        throw new Error("Native tool catalog unavailable")
      if (!local.data.includes(tool) && Object.entries(servers.data).some(([server, status]) =>
        status.status === "connected" && tool.startsWith(server.replace(/[^a-zA-Z0-9_-]/g, "_") + "_")))
        return "mcp__" + tool
    } catch (error) {
      console.error(`[vigil] Native MCP identity could not be verified: ${error.message}`)
    } finally { clearTimeout(timer) }
    return tool
  }
  const log = async (input, output, failed = false) => {
    try {
      const context = readContext()
      let actor = "unknown"
      try { actor = (await request(input.sessionID)).current.agent || "unknown" } catch {}
      const name = await nativeToolName(input.tool)
      const response = failed ? {...output, stderr: String(output.error || "Native tool failed"), exit_code: 1}
        : {...output, ...output.metadata,
          ...(input.tool === "bash" && output.metadata?.exit !== undefined ? {exit_code: output.metadata.exit} : {})}
      // The shared logger retains its existing bounded projection. Keep all
      // original native data available to that projection, including mixed MCP
      // content and structured-only results; never stringify undefined output.
      if (name.startsWith("mcp__")) response.output = JSON.stringify(response)
      hook(context, "post-tool-log.sh", {hook_event_name: "PostToolUse", client_name: "opencode",
        session_id: input.sessionID, tool_use_id: input.callID, agent_type: actor,
        tool_name: name, native_tool_name: input.tool, tool_input: ["write", "edit"].includes(input.tool)
          ? {...(input.args || {}), file_path: input.args?.file_path ?? input.args?.filePath}
          : input.args || {},
        tool_response: response})
    } catch (error) { console.error(`[vigil] Native activity was not recorded: ${error.message}`) }
  }
  return {
    "tool.execute.after": async (input, output) => {
      if (input.tool === "task") await reportDispatch(output)
      return log(input, output)
    },
    event: async ({event}) => {
      const part = event.properties?.part
      if (event.type === "message.part.updated" && part?.type === "tool" && part.state?.status === "error")
        await log({tool: part.tool, sessionID: part.sessionID, callID: part.callID, args: part.state.input},
          {error: part.state.error}, true)
    },
    "experimental.session.compacting": async (input, output) => {
      try {
        const context = readContext()
        const contract = hook(context, "pre-compact.sh", {hook_event_name: "PreCompact", trigger: "native"})
        if (!contract.trim()) throw new Error("Empty compaction contract")
        output.context.push(contract)
        observe(context, input.sessionID, {compacting_observed: true, recovery_pending: true})
      } catch (error) {
        output.context.push(`Vigil preservation unavailable: ${error.message}. Restore canonical backend state before continuing.`)
      }
    },
    "experimental.chat.system.transform": async (input, output) => {
      let context
      try {
        context = readContext()
        const native = await request(input.sessionID)
        const info = native.current
        // This callback also runs for the summarizer with the same sessionID.
        if (info.agent === "compaction" || info.mode === "compaction" || info.summary) return
        if (input.model && (info.providerID !== input.model.providerID || info.modelID !== input.model.id))
          throw new Error("Native request model correlation is ambiguous")
        output.system.push(pointers(context))
        const row = state(context, input.sessionID)
        if (Object.hasOwn(row, "revert_boundary") && row.revert_boundary !== native.boundary) {
          row.last_summary_id = null
          row.recovery_pending = false
          row.revert_boundary = native.boundary
        }
        row.revert_boundary = native.boundary
        const summary = native.messages.filter(message => message.info?.summary && message.info?.finish && !message.info?.error).at(-1)?.info
        if (info.agent !== "operator" || native.parentID) {
          output.system.push("Restore only this specialist's assigned role, mandatory constraints, and active ownership after a context boundary; never load an operator core.")
          if (native.parentID) {
            const dispatch = await dispatchFor(context, input.sessionID, native)
            for (const advisory of dispatch.advisories.filter(item => item.advisory === "native_agent_role_mismatch"))
              output.system.push(`Vigil advisory: ${JSON.stringify(advisory)}\nThis task runs as native agent `
                + `${JSON.stringify(advisory.native_agent)}, but its dispatch packet registers ${advisory.registered_role}. `
                + `Follow the packet's Runtime Identity: read ${JSON.stringify(join(context.agent_root, "agents", advisory.registered_role + ".md"))} `
                + "and its required references; the native agent's own instructions do not change your role.")
          }
          return
        }
        if (summary) {
          const resume = hook(context, "post-compact-resume.sh", {hook_event_name: "SessionStart", source: "compact"})
          if (!resume.trim()) throw new Error("Recovery context is unavailable")
          output.system.push(`Standing recovery contract for native summary ${summary.id}: apply the following once if hydration for this exact summary is not already completed in the current native tool history. Do not restart hydration already completed in this continuation.\n` + resume)
          observe(context, input.sessionID, {last_summary_id: summary.id, context_injected: true,
            recovery_pending: false, revert_boundary: native.boundary})
        } else if (row.recovery_pending) {
          throw new Error("Compaction is pending but its successful summary is not visible")
        } else {
          observe(context, input.sessionID, {request_observed: true, revert_boundary: native.boundary})
        }
      } catch (error) {
        output.system.push(`Vigil context could not be verified: ${error.message}. STOP dependent work and use the bound helper to restore the selected workflow; do not infer state from a summary.`)
      }
    },
  }
}
