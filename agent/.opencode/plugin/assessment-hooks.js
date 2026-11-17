// Native web/code adapter. The legacy standard plugin remains Blue-owned.
import {execFile, spawn} from "node:child_process"
import {readFileSync, realpathSync, writeFileSync, renameSync, existsSync, lstatSync, openSync, closeSync, unlinkSync, appendFileSync, mkdtempSync} from "node:fs"
import {join, dirname} from "node:path"
import {tmpdir} from "node:os"
import {createHash, randomUUID} from "node:crypto"
import {promisify} from "node:util"

const execFileAsync = promisify(execFile)
const PACKET_REFERENCE = /tools\/dispatch-packets\/(\d+)\/([0-9a-f]{64})\.md/g
const BIND_ATTEMPTS = 3
// The queue-adoption window `code-dispatch adopt-lease` applies by default.
const ADOPTION_STALE_MINUTES = 10
const LEASE_PAGE = 50
const ACTIVITY_BACKLOG = 200
// Hooks writing activity at once, across sessions.
const ACTIVITY_LOGGERS = 4
const FINAL_HANDOFF = new Set(["ready", "blocked"])
const shellWord = value => /^[A-Za-z0-9_./:=@%+,-]+$/.test(String(value)) ? String(value)
  : `'${String(value).replace(/'/g, `'\\''`)}'`

// Everything below is independent of the native host API; the adapter
// (VigilAssessmentHooksV2) supplies the native session, message and tool-catalog reads.
const runtime = ({bindingPath, activityTimeoutMs}) => {
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
  // A context hook's output joins the request; it runs off the event loop so other sessions keep working.
  const hook = (context, name, payload) => new Promise((resolve, reject) => {
    const child = execFile(context.tools?.bash || "bash", [join(context.agent_root, "scripts/hooks", name)],
      {env: env(context), encoding: "utf8", timeout: 5000, maxBuffer: 1024 * 1024},
      (error, stdout) => error ? reject(error) : resolve(stdout))
    child.stdin.on("error", () => {})
    child.stdin.end(JSON.stringify({...payload, cwd: context.engagement_dir}))
  })
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
  // A native task child names its dispatch only through the launch message's
  // content-addressed packet path. The packet's leading Runtime Identity names
  // the dispatch, and the backend row must agree before the handle is bound.
  const dispatches = new Map()
  // Most verbs end with one JSON line; `whole` reads a document printed with indentation.
  const helper = async (context, args, {whole = false} = {}) => {
    const {stdout} = await execFileAsync(context.vigil_cli, args, {cwd: context.workspace, env: env(context),
      encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024})
    return JSON.parse(whole ? stdout : stdout.trim().split("\n").at(-1))
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
  // `launch` is the task's launch text plus the native agent/model observed `at` it.
  const resolveDispatch = async (context, session, launch, attempts) => {
    const packets = [...new Set([...launch.text.matchAll(PACKET_REFERENCE)].map(match => `${match[1]}/${match[2]}`))]
    if (packets.length !== 1)
      return packets.length ? {status: "unresolved", reason: "ambiguous_dispatch_packets", packets, advisories: []}
        : {status: "unresolved", reason: "no_dispatch_packet", advisories: []}
    const [id, sha256] = packets[0].split("/")
    const record = {dispatch_id: Number(id), packet_sha256: sha256, handle: session,
      session_namespace: launch.directory || context.project || context.workspace,
      native_agent: launch.agent || "unknown", model: launch.model, variant: launch.variant || "default"}
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
    const note = `Recorded by the Vigil OpenCode plugin at native task session ${session}'s ${launch.at} `
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
  const dispatchFor = async (context, session, launch) => {
    const previous = await dispatches.get(session)
    if (previous && !(previous.status === "failed" && previous.attempts < BIND_ATTEMPTS)) return previous
    const pending = resolveDispatch(context, session, launch, previous?.attempts || 0).catch(error =>
      ({status: "failed", reason: "plugin_error", detail: failure(error), attempts: (previous?.attempts || 0) + 1, advisories: []}))
    dispatches.set(session, pending)
    const record = await pending
    if (record.status === "failed") console.error(`[vigil] Dispatch binding for ${session} failed: ${record.detail}`)
    return record
  }
  // The operator sees the task's return, never the child's system prompt. The
  // caller marks the record reported once the line has been delivered.
  const bindingReport = record => {
    if (record.reason === "no_dispatch_packet" || record.reported) return null
    const {reported, attempts, ...shown} = record
    return `Vigil dispatch binding: ${JSON.stringify(shown)}`
      + (["bound", "already_bound"].includes(record.status)
        ? "\nThis handle is recorded; run `agent bind-client-handle` only to correct it." : "")
  }
  const vigilCommand = (context, ...args) => [context.vigil_cli, "assess", ...args].map(shellWord).join(" ")
  // A missing handoff is a failed point read that `render-handoff` confirms with
  // its documented exit 2; any other failure leaves the handoff unverified.
  const readHandoff = async (context, agentId) => {
    try {
      const row = await helper(context, ["assess", "fetch", `dispatch-handoffs/${encodeURIComponent(agentId)}`, "--compact"])
      if (row?.agent_id !== agentId) throw new Error("Handoff read names another dispatch")
      return row
    } catch (error) {
      try {
        await execFileAsync(context.vigil_cli, ["assess", "agent", "render-handoff", agentId, "--max-lines", "1"],
          {cwd: context.workspace, env: env(context), encoding: "utf8", timeout: 15000, maxBuffer: 4 * 1024 * 1024})
      } catch (probe) { if (probe.code === 2) return null }
      throw error
    }
  }
  const leaseRead = agentId => ["code-dispatch", "list", "--status", "processing", "--agent-id", agentId, "--json"]
  const readLeases = async (context, agentId) => {
    const page = await helper(context, ["assess", ...leaseRead(agentId), "--limit", String(LEASE_PAGE)], {whole: true})
    if (!Array.isArray(page?.items) || !Number.isInteger(page.total)) throw new Error("Lease listing has no items/total")
    return page
  }
  // A native task can end with no error and no text (an empty provider stream),
  // and the native loop treats that as completion. One bounded read per return
  // says what the dispatch still owes; a failed read says how to check by hand.
  const dispatchStatus = async (context, record, empty) => {
    const agentId = record.agent_id
    const reference = {agent_id: agentId, dispatch_id: record.dispatch_id, empty_result: empty}
    const code = context.mode === "code"
    let handoff, page
    try {
      [handoff, page] = await Promise.all([readHandoff(context, agentId), code ? readLeases(context, agentId) : null])
    } catch (error) {
      return {...reference, verified: false, detail: failure(error), check: [
        vigilCommand(context, "agent", "render-handoff", agentId),
        ...(code ? [vigilCommand(context, ...leaseRead(agentId))] : [])]}
    }
    const handoffStatus = handoff ? String(handoff.handoff_status || "checkpointed") : null
    const final = FINAL_HANDOFF.has(handoffStatus)
    const leases = (page?.items || []).map(item => ({item_id: item.id, repo_id: item.repo_id, file_path: item.file_path,
      receipts: Number(item.current_result_count || 0), heartbeat_age_seconds: item.heartbeat_age_seconds,
      lease_token: item.lease_token}))
    const held = page ? page.total : 0
    if (final && !held && !empty) return null
    const next = []
    if (final && empty) next.push(vigilCommand(context, "agent", "render-handoff", agentId, "--max-lines", "0"))
    if (!final) {
      // Durable work on incomplete scope is a blocked return; nothing usable is a failed one.
      const durable = Boolean(handoff) || leases.some(lease => lease.receipts > 0)
      next.push(vigilCommand(context, "agent", "close", agentId, "--status", durable ? "blocked" : "failed",
        "--reason", "<observed return and execution state>"))
      next.push(vigilCommand(context, "agent", "continue", agentId, "--task", "<restated objective>"))
    }
    for (const lease of leases)
      next.push(lease.receipts > 0
        ? vigilCommand(context, "code-dispatch", "adopt-lease", lease.item_id, "<replacement-agent-id>",
          "--from-agent", agentId, "--from-lease", lease.lease_token, "--reason", "<why>")
        : vigilCommand(context, "code-dispatch", "reset-stale", ADOPTION_STALE_MINUTES,
          "--repo-id", lease.repo_id, "--path-prefix", lease.file_path))
    if (held > leases.length)
      next.push(vigilCommand(context, ...leaseRead(agentId), "--offset", leases.length))
    if (final) next.push(vigilCommand(context, "agent", "close", agentId))
    return {...reference, handoff: Boolean(handoff), handoff_status: handoffStatus,
      ...(page ? {held_leases: held, leases, ...(held > leases.length ? {leases_omitted: held - leases.length} : {})} : {}),
      next}
  }
  // Only a packet-verified dispatch is checked: its agent_id came from the digest-checked packet.
  const statusReport = async (record, empty) => {
    if (!record.agent_id || !(["bound", "already_bound", "failed"].includes(record.status) || empty)) return null
    let status
    try { status = await dispatchStatus(readContext(), record, empty) } catch (error) {
      status = {agent_id: record.agent_id, dispatch_id: record.dispatch_id, empty_result: empty,
        verified: false, detail: failure(error), check: [
          ["vigil", "assess", "agent", "render-handoff", record.agent_id],
          ["vigil", "assess", ...leaseRead(record.agent_id)]].map(words => words.map(shellWord).join(" "))}
    }
    return status ? `Vigil dispatch status: ${JSON.stringify(status)}` : null
  }
  // Activity rows are written off the tool's path. Each session's rows are written
  // one at a time in call order, and sessions side by side, at most
  // ACTIVITY_LOGGERS hooks at once, so a loaded host neither stalls the native
  // event loop, falls behind one hook, nor fans out shell hooks. A row names its
  // native call, which the hook claims before it posts, so a write that timed out
  // is never retried (the retry would no-op on that claim); only a spawn that
  // never started is. A row without that identity falls back to the hook's
  // command-text duplicate window, so such rows never run together. An
  // unconfirmed row is counted and kept beside the health receipts.
  //
  // A queued row is a private spool file from the moment it is queued, so no row
  // depends on OpenCode running code as it ends: SIGHUP (which `opencode serve`
  // without a terminal leaves to its default action), any other signal OpenCode
  // does not handle, and SIGKILL end the process without an exit event. A hook
  // claims its row as it starts, with an exclusive marker naming its pid, and
  // reads the file itself, so a started hook has its whole input. One
  // detached drainer per spool holds a pipe from this process, which closes however
  // the process ends; the drainer then waits for the running hooks and writes every
  // unclaimed row in call order. The claim lets exactly one of them write each row.
  // Rows still queued when an exit event does fire are also kept as unconfirmed.
  let unconfirmed = 0
  let sequence = 0
  const queued = new Set()
  const lanes = new Map()
  const ready = []
  const running = new Map()
  const spools = new Map()
  process.once("exit", () => {
    const writes = [...queued].filter(write => !write.failed).sort((left, right) => left.sequence - right.sequence)
    for (const write of writes) keepUnconfirmed(write.context, write.payload, write.body,
      new Error("OpenCode exited before the queued write was confirmed; a detached hook still writes it"))
  })
  const shell = context => context.tools?.bash || "bash"
  const logHook = context => join(context.agent_root, "scripts/hooks/post-tool-log.sh")
  // The same two shell programs, and UNSPOOLED, are in standard-hooks.js.
  // CLAIM <bash> <row file> <hook>: runs the hook on the row unless it is already claimed;
  // exits UNSPOOLED when the row's file is gone, before or after its claim.
  const UNSPOOLED = 75
  const CLAIM = 'set -C; { printf %s "$$" > "$2.claim"; } 2>/dev/null || { [ -e "$2.claim" ] && exit 0; exit 75; }; '
    + '{ exec 3< "$2"; } 2>/dev/null || exit 75; exec "$1" "$3" <&3 3<&-'
  // DRAIN <spool> <bash> <hook>: once this process ends, waits for each claimed row's
  // hook (as long as a hook may run), then writes the unclaimed rows in order.
  const DRAIN = 'w() { p=; read -r p < "$1"; [ -n "$p" ] || { sleep 0.05; read -r p < "$1"; }; n=0; '
    + 'while [ -n "$p" ] && kill -0 "$p" 2>/dev/null && [ "$n" -lt 1200 ]; do sleep 0.05; n=$((n + 1)); done; }; '
    + 'while read -r line; do :; done; set -C; for c in "$1"/*.claim; do [ -e "$c" ] && w "$c"; done; '
    + 'for f in "$1"/*.json; do [ -e "$f" ] || continue; if { printf %s "$$" > "$f.claim"; } 2>/dev/null; '
    + 'then "$2" "$3" < "$f" >/dev/null 2>&1; else w "$f.claim"; fi; rm -f "$f" "$f.claim"; done; '
    + 'rm -f "$1"/*; rmdir "$1"'
  // The spool a context's rows are queued in, with a drainer answering for it. A spool
  // whose directory is gone starts over: its drainer, which can no longer write
  // anything, is let go, and the rows still queued in it are spooled again.
  const spoolKey = context => [context.binding_sha256, shell(context), logHook(context)].join("\0")
  const spoolFor = context => {
    const key = spoolKey(context)
    let spool = spools.get(key)
    const lost = spool && !existsSync(spool.dir)
    if (!spool || lost) {
      try { spool?.drainer?.stdin.destroy() } catch {}
      spool = {dir: mkdtempSync(join(tmpdir(), "vigil-activity-")), drainer: null}
      spools.set(key, spool)
    }
    if (!spool.drainer) {
      try {
        const drainer = spawn(shell(context), ["-c", DRAIN, "vigil-activity", spool.dir, shell(context), logHook(context)],
          {env: env(context), stdio: ["pipe", "ignore", "ignore"], detached: true})
        spool.drainer = drainer
        // A drainer that ends while OpenCode runs is replaced by the next row.
        drainer.once("exit", () => { if (spool.drainer === drainer) spool.drainer = null })
        drainer.once("error", () => { if (spool.drainer === drainer) spool.drainer = null })
        drainer.stdin.on("error", () => {})
        drainer.unref()
        drainer.stdin.unref?.()
      } catch (error) {
        console.error(`[vigil] Native activity still queued when OpenCode ends may not be written: ${error.message}`)
      }
    }
    if (lost) for (const item of [...lanes.values()].flat().sort((left, right) => left.sequence - right.sequence))
      if (spoolKey(item.context) === key && item.file && !existsSync(item.file)) try { place(item) } catch {}
    return spool
  }
  // A written (or abandoned) row leaves the spool.
  const unspool = item => {
    for (const path of [item.file, item.file + ".claim"]) try { unlinkSync(path) } catch {}
  }
  // Writes the row into its context's spool.
  const place = item => {
    item.file = join(spoolFor(item.context).dir, String(item.sequence).padStart(12, "0") + ".json")
    writeFileSync(item.file, item.body, {mode: 0o600, flag: "wx"})
  }
  // The spooled row takes its final payload; a rename, so the file is never half written.
  // A row whose file is gone is spooled again.
  const respool = item => {
    if (!existsSync(item.file)) return place(item)
    const next = item.file + ".next"
    writeFileSync(next, item.body, {mode: 0o600})
    renameSync(next, item.file)
  }
  const runHook = item => new Promise((resolve, reject) => {
    let settled = false
    const settle = (error, started) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(Object.assign(error, {started})); else resolve()
    }
    const child = spawn(shell(item.context), ["-c", CLAIM, "vigil-activity", shell(item.context), item.file, logHook(item.context)],
      {env: env(item.context), stdio: "ignore", detached: true})
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, "SIGKILL") } catch { child.kill("SIGKILL") }
      settle(new Error(`post-tool-log.sh did not finish within ${activityTimeoutMs} ms`), true)
    }, activityTimeoutMs)
    child.once("spawn", () => { child.started = true })
    child.once("error", error => settle(error, Boolean(child.started)))
    child.once("exit", (code, signal) => settle(code === 0 ? null
      : code === UNSPOOLED && !existsSync(item.file) ? Object.assign(new Error("its spool file is gone"), {unspooled: true})
      : new Error(`post-tool-log.sh exited ${signal ? "on " + signal : code}`), true))
  })
  const keepUnconfirmed = (context, payload, body, error) => {
    unconfirmed += 1
    const path = join(context.workspace, ".vigil-activity-unrecorded.jsonl")
    let kept = `its hook payload is kept in ${path}`
    try {
      if (existsSync(path) && lstatSync(path).isSymbolicLink()) throw new Error("Unsafe activity spool path")
      appendFileSync(path, JSON.stringify({recorded_at: new Date().toISOString(), error: error.message,
        unconfirmed_this_session: unconfirmed}).slice(0, -1) + `,"payload":${body}}\n`, {mode: 0o600})
    } catch (spool) { kept = `its hook payload could not be kept (${spool.message})` }
    console.error(`[vigil] Native activity for ${payload.tool_name} call ${payload.tool_use_id} in session `
      + `${payload.session_id} was not confirmed recorded: ${error.message}. ${unconfirmed} unconfirmed this session; `
      + `${kept}. Compare with \`vigil assess fetch activity-entries\`.`)
  }
  const write = async item => {
    await item.ready
    if (item.failed) return console.error(`[vigil] Native activity was not recorded: ${item.failed.message}`)
    if (!existsSync(item.file)) place(item)
    try { await runHook(item) } catch (error) {
      // A row whose file went before its hook read it is spooled again (its claim with it) and written once more.
      if (error.unspooled) {
        unspool(item)
        place(item)
        return await runHook(item)
      }
      if (error.started) throw error
      await new Promise(resolve => setTimeout(resolve, 250))
      await runHook(item)
    }
  }
  const pump = () => {
    for (let index = 0; index < ready.length && running.size < ACTIVITY_LOGGERS;) {
      const lane = ready[index]
      const item = lanes.get(lane)[0]
      if (!item.named && [...running.values()].some(other => !other.named)) {
        index += 1
        continue
      }
      ready.splice(index, 1)
      lanes.get(lane).shift()
      running.set(lane, item)
      write(item).catch(error => keepUnconfirmed(item.context, item.payload, item.body, error))
        .catch(error => console.error(`[vigil] Native activity accounting failed: ${error.message}`))
        .finally(() => {
          unspool(item)
          queued.delete(item)
          running.delete(lane)
          if (lanes.get(lane)?.length) ready.push(lane); else lanes.delete(lane)
          pump()
        })
    }
  }
  // Rows whose own catalog read has not answered, each with the payload the latest catalog gives it.
  const resolving = new Set()
  // A catalog read answered: a row still waiting on its own read is spooled under that catalog's name.
  const catalogRead = () => {
    for (const item of resolving) {
      const value = item.guess()
      if (!value) continue
      item.payload = value
      item.body = item.serialize(value)
      try { respool(item) } catch {}
    }
  }
  // `named`, when given, settles to the final payload (a catalog-resolved tool name);
  // the row keeps its place in its session's queue meanwhile, so the tool result is not held for it.
  // Until then its spool file holds `payload`, or what `guess` gives once a catalog is read.
  const writeActivity = (context, payload, named, guess = () => null) => {
    // Serialized now: the write runs after the tool result has moved on.
    const serialize = value => JSON.stringify({...value, cwd: context.engagement_dir})
    const item = {context, payload, body: serialize(payload), sequence: sequence += 1, serialize, guess,
      named: typeof payload.tool_use_id === "string" && payload.tool_use_id !== ""}
    if (queued.size >= ACTIVITY_BACKLOG) {
      const overflow = new Error(`${ACTIVITY_BACKLOG} activity writes already queued`)
      if (!named) return keepUnconfirmed(context, payload, item.body, overflow)
      return void named.then(value => [value, serialize(value)], () => [payload, item.body])
        .then(([value, body]) => keepUnconfirmed(context, value, body, overflow))
        .catch(error => console.error(`[vigil] Native activity accounting failed: ${error.message}`))
    }
    place(item)
    queued.add(item)
    // A payload that cannot be completed is not recorded, as when it fails before queueing.
    if (named) resolving.add(item)
    item.ready = named?.then(value => {
      resolving.delete(item)
      item.payload = value
      item.body = serialize(value)
      try { respool(item) } catch (error) { item.failed = error }
    }, error => { resolving.delete(item); item.failed = error })
    const lane = typeof payload.session_id === "string" ? payload.session_id : ""
    if (!lanes.has(lane)) lanes.set(lane, [])
    lanes.get(lane).push(item)
    if (lanes.get(lane).length === 1 && !running.has(lane)) ready.push(lane)
    pump()
  }
  // Extends a native summary request with the preservation contract.
  const compacting = async (session, push) => {
    try {
      const context = readContext()
      const contract = await hook(context, "pre-compact.sh", {hook_event_name: "PreCompact", trigger: "native"})
      if (!contract.trim()) throw new Error("Empty compaction contract")
      push(contract)
      observe(context, session, {compacting_observed: true, recovery_pending: true})
    } catch (error) {
      push(`Vigil preservation unavailable: ${error.message}. Restore canonical backend state before continuing.`)
    }
  }
  // One request's context. `native` names the request's agent, its parent, an active
  // revert boundary, the latest visible native summary, and how to read the task's launch.
  const restore = async (context, session, native, push) => {
    push(pointers(context))
    const row = state(context, session)
    if (Object.hasOwn(row, "revert_boundary") && row.revert_boundary !== native.boundary) {
      row.last_summary_id = null
      row.recovery_pending = false
      row.revert_boundary = native.boundary
    }
    row.revert_boundary = native.boundary
    if (native.agent !== "operator" || native.parentID) {
      push("Restore only this specialist's assigned role, mandatory constraints, and active ownership after a context boundary; never load an operator core.")
      if (native.parentID) {
        const dispatch = await dispatchFor(context, session, native.launch())
        for (const advisory of dispatch.advisories.filter(item => item.advisory === "native_agent_role_mismatch"))
          push(`Vigil advisory: ${JSON.stringify(advisory)}\nThis task runs as native agent `
            + `${JSON.stringify(advisory.native_agent)}, but its dispatch packet registers ${advisory.registered_role}. `
            + `Follow the packet's Runtime Identity: read ${JSON.stringify(join(context.agent_root, "agents", advisory.registered_role + ".md"))} `
            + "and its required references; the native agent's own instructions do not change your role.")
      }
      return
    }
    if (native.summary) {
      const resume = await hook(context, "post-compact-resume.sh", {hook_event_name: "SessionStart", source: "compact"})
      if (!resume.trim()) throw new Error("Recovery context is unavailable")
      push(`Standing recovery contract for native summary ${native.summary}: apply the following once if hydration for this exact summary is not already completed in the current native tool history. Do not restart hydration already completed in this continuation.\n` + resume)
      observe(context, session, {last_summary_id: native.summary, context_injected: true,
        recovery_pending: false, revert_boundary: native.boundary})
    } else if (row.recovery_pending) {
      throw new Error("Compaction is pending but its successful summary is not visible")
    } else {
      observe(context, session, {request_observed: true, revert_boundary: native.boundary})
    }
  }
  const unverified = error => `Vigil context could not be verified: ${error.message}. STOP dependent work and use the bound helper to restore the selected workflow; do not infer state from a summary.`
  return {readContext, state, observe, dispatches, dispatchFor, bindingReport, statusReport, writeActivity,
    catalogRead, compacting, restore, unverified}
}

// The row under its catalog-resolved name. The shared logger retains its existing bounded
// projection; an MCP row keeps all original native data available to that projection,
// including mixed content and structured-only results, and never stringifies undefined output.
const withToolName = (payload, name) => ({...payload, tool_name: name, ...(name.startsWith("mcp__")
  ? {tool_response: {...payload.tool_response, output: JSON.stringify(payload.tool_response)}} : {})})

// Hooks registered through the OpenCode 2 plugin context. Names follow its plugin
// API (ToolHooks, SessionHooks); an unknown name would register and never fire.
const V2_HOOKS = [["tool", "execute.after"], ["session", "prompt"], ["session", "context"],
  ["session", "compaction"], ["session", "experimental.idle"]]
const V2_EVENTS = ["session.revert.committed"]
const V2_TOOL_NAMES = {shell: "Bash", read: "Read", write: "Write", edit: "Edit", patch: "apply_patch",
  subagent: "Agent", webfetch: "WebFetch", websearch: "WebSearch", skill: "Skill"}
// Message kinds that show a child has already started its conversation.
const CONVERSATION = new Set(["user", "synthetic", "assistant", "compaction", "shell", "skill"])
const isObject = value => typeof value === "object" && value !== null && !Array.isArray(value)

// Registers the hooks, routing each to `invoke(key, event)`; every callback contains its
// own failure, because a rejected hook fails the native operation it belongs to.
export const registerV2Hooks = async (ctx, invoke) => {
  // OpenCode does not read the launch's default shell budget itself; give a call that names
  // no timeout that budget. Shell timeouts are milliseconds; background commands keep none.
  const budget = Number(process.env.OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS)
  if (Number.isSafeInteger(budget) && budget > 0)
    await ctx.tool.hook("execute.before", event => {
      try {
        if (event.tool !== "shell" || !isObject(event.input) || event.input.timeout !== undefined
            || event.input.background === true) return
        event.input = {...event.input, timeout: budget}
      } catch (error) { console.error(`[vigil] Default shell timeout was not applied: ${error.message}`) }
    })
  for (const [domain, name] of V2_HOOKS)
    await ctx[domain].hook(name, async event => {
      try { await invoke(`${domain}.${name}`, event) }
      catch (error) { console.error(`[vigil] ${domain}.${name} hook failed: ${error.message}`) }
    })
  const stop = new AbortController()
  ;(async () => {
    for await (const event of ctx.event.subscribe({types: V2_EVENTS, signal: stop.signal})) {
      if (!V2_EVENTS.includes(event?.type)) continue
      try { await invoke(event.type, event) }
      catch (error) { console.error(`[vigil] ${event.type} handling failed: ${error.message}`) }
    }
  })().catch(error => { if (!stop.signal.aborted) console.error(`[vigil] Native event stream ended: ${error.message}`) })
  return () => stop.abort()
}

export const VigilAssessmentHooksV2 = async ({ctx, bindingPath = process.env.VIGIL_CLIENT_CONTEXT,
  activityTimeoutMs = 60000}) => {
  const {readContext, state, observe, dispatches, dispatchFor, bindingReport, statusReport, writeActivity,
    catalogRead, compacting, restore, unverified} = runtime({bindingPath, activityTimeoutMs})
  const system = event => text => event.system.push({type: "text", text})
  const session = async sessionID => {
    const info = await ctx.session.get({sessionID})
    if (info?.id !== sessionID) throw new Error("Native session unavailable")
    return info
  }
  // The session's messages from its latest completed compaction on.
  const history = async sessionID => {
    const messages = await ctx.session.context({sessionID})
    if (!Array.isArray(messages)) throw new Error("Native messages unavailable")
    return messages
  }
  const launches = new Map()
  const launchOf = (info, text, model, at) => ({text: String(text ?? ""), directory: info.location?.directory,
    agent: info.agent, model: model ? `${model.providerID}/${model.id}` : "unknown", variant: model?.variant, at})
  // An MCP tool is registered under its server's normalized name as namespace.
  const classify = (tool, {servers, tools}) => {
    const namespace = tools.find(entry => entry?.id === tool)?.options?.namespace
    return namespace && servers.some(server => server?.status?.status === "connected"
      && String(server.name).replace(/[^a-zA-Z0-9_-]/g, "_") === namespace) ? "mcp__" + tool : tool
  }
  // The last catalog this process read names a row whose own read has not answered when OpenCode ends.
  let catalog = null
  let prefetched = false
  const readCatalog = async () => {
    let timer
    try {
      const [servers, tools] = await Promise.race([
        Promise.all([ctx.mcp.list(), ctx.tool.list()]),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("Native tool catalog timeout")), 1000) }),
      ])
      if (!Array.isArray(servers?.data) || !Array.isArray(tools)) throw new Error("Native tool catalog unavailable")
      catalog = {servers: servers.data, tools}
      catalogRead()
      return catalog
    } finally { clearTimeout(timer) }
  }
  const nativeToolName = async tool => {
    if (V2_TOOL_NAMES[tool]) return V2_TOOL_NAMES[tool]
    try { return classify(tool, await readCatalog()) } catch (error) {
      console.error(`[vigil] Native MCP identity could not be verified: ${error.message}`)
    }
    return tool
  }
  // The catalog's name for a tool, or null before any catalog read has answered.
  const knownToolName = tool => V2_TOOL_NAMES[tool] || catalog && classify(tool, catalog)
  const toolInput = (tool, input) => ["write", "edit"].includes(tool) ? {...input, file_path: input.file_path ?? input.path}
    : tool === "subagent" ? {...input, subagent_type: input.agent}
      : tool === "patch" ? {...input, command: input.patchText} : input
  const resultText = result => typeof result.output === "string" ? result.output
    : typeof result.output?.output === "string" ? result.output.output
      : (Array.isArray(result.content) ? result.content : []).filter(part => part?.type === "text")
        .map(part => String(part.text)).join("\n")
  const log = async event => {
    const occurredAt = new Date().toISOString()
    try {
      const context = readContext()
      // A catalog read finishes in the row's queue slot, after the call has returned.
      const named = V2_TOOL_NAMES[event.tool] ? null : nativeToolName(event.tool)
      // The first call reads the catalog, so a later row has one to fall back on.
      if (!prefetched && !named) readCatalog().catch(() => {})
      prefetched = true
      let response
      if (event.status === "error") {
        const error = isObject(event.error) ? {...event.error, message: event.error.message} : event.error
        response = {error, stderr: String(event.error?.message || event.error || "Native tool failed"), exit_code: 1}
      } else {
        const result = isObject(event.result) ? event.result : {}
        const structured = isObject(result.output) ? result.output : {}
        response = {...result, ...structured, ...(isObject(result.metadata) ? result.metadata : {}), output: resultText(result)}
        const exit = structured.exitCode ?? result.metadata?.exit
        if (event.tool === "shell" && exit !== undefined && exit !== null) response.exit_code = exit
      }
      // A call id is unique within its message, so the message names the call too.
      const call = typeof event.messageID === "string" && event.messageID && typeof event.id === "string" && event.id
        ? `${event.messageID}/${event.id}` : event.id
      const payload = {hook_event_name: "PostToolUse", client_name: "opencode",
        session_id: event.sessionID, tool_use_id: call, agent_type: event.agent || "unknown",
        tool_name: V2_TOOL_NAMES[event.tool] || event.tool, native_tool_name: event.tool,
        tool_input: toolInput(event.tool, isObject(event.input) ? event.input : {}), tool_response: response,
        occurred_at: occurredAt}
      const guess = () => { const known = knownToolName(event.tool); return known && withToolName(payload, known) }
      writeActivity(context, (named && guess()) || payload, named?.then(name => withToolName(payload, name)), guess)
    } catch (error) { console.error(`[vigil] Native activity was not recorded: ${error.message}`) }
  }
  return {
    "tool.execute.after": log,
    // A child's launch prompt names its dispatch packet before the child runs. The
    // subagent call is not held for the backend; the child's first request awaits it.
    "session.prompt": async event => {
      try {
        if (dispatches.has(event.sessionID)) return
        const info = await session(event.sessionID)
        if (!info.parentID) return
        if ((await history(event.sessionID)).some(message => CONVERSATION.has(message?.type))) return
        const context = readContext()
        const launch = launchOf(info, event.prompt?.text, info.model, "launch prompt")
        launches.set(event.sessionID, launch)
        dispatchFor(context, event.sessionID, launch).catch(() => {})
      } catch (error) { console.error(`[vigil] Dispatch launch of ${event.sessionID} was not observed: ${error.message}`) }
    },
    "session.context": async event => {
      try {
        const context = readContext()
        const info = await session(event.sessionID)
        let messages = await history(event.sessionID)
        // A staged revert hides its boundary and everything after it; a boundary before
        // the latest compaction hides that compaction too.
        const boundary = info.revert?.messageID || null
        if (boundary) {
          const index = messages.findIndex(message => message?.id === boundary)
          messages = index < 0 ? [] : messages.slice(0, index)
        }
        const compacted = messages.filter(message => message?.type === "compaction")
        await restore(context, event.sessionID, {agent: event.agent, parentID: info.parentID, boundary,
          summary: compacted.filter(message => message.status === "completed").at(-1)?.id,
          // A launch observed in an earlier process is still the child's first message until it compacts.
          launch: () => launches.get(event.sessionID) ?? launchOf(info,
            compacted.length ? "" : messages.find(message => message?.type === "user")?.text, event.model, "first request"),
        }, system(event))
      } catch (error) {
        system(event)(unverified(error))
      }
    },
    "session.compaction": async event => compacting(event.sessionID, system(event)),
    // The subagent tool returns at once, so the dispatch report goes to the operator's
    // session as a note that does not wake it: it is read with the <subagent> report
    // that follows this child going idle.
    "session.experimental.idle": async event => {
      try {
        const pending = dispatches.get(event.sessionID)
        if (!pending) return
        // The child's own shell or subagent wakes it again; report once that work is done.
        if ((event.background || []).some(item => item?.sessionID === event.sessionID)) return
        const record = await pending
        const info = await session(event.sessionID)
        if (!info.parentID) return
        const last = (await history(event.sessionID)).filter(message => message?.type === "assistant").at(-1)
        const empty = !(last?.content || []).some(part => part?.type === "text" && String(part.text ?? "").trim())
        const binding = bindingReport(record)
        const lines = [binding, await statusReport(record, empty)].filter(Boolean)
        if (!lines.length) return
        await ctx.session.synthetic({sessionID: info.parentID, text: lines.join("\n\n"),
          description: "Vigil dispatch report", metadata: {source: "vigil", childID: event.sessionID},
          resume: false})
        if (binding) record.reported = true
      } catch (error) {
        console.error(`[vigil] Vigil dispatch report for ${event.sessionID} was not delivered: ${error.message}`)
      }
    },
    // A committed revert removes the messages after its boundary, a pending summary included.
    "session.revert.committed": async event => {
      try {
        const sessionID = event.data?.sessionID
        if (typeof sessionID !== "string") return
        const context = readContext()
        const row = state(context, sessionID)
        if (row.recovery_pending || row.last_summary_id)
          observe(context, sessionID, {last_summary_id: null, recovery_pending: false})
      } catch (error) { console.error(`[vigil] Revert was not applied to recovery state: ${error.message}`) }
    },
  }
}

export default {
  id: "vigil-assessment-hooks",
  setup: async ctx => {
    const adapter = await VigilAssessmentHooksV2({ctx})
    return registerV2Hooks(ctx, (key, event) => adapter[key](event))
  },
}
