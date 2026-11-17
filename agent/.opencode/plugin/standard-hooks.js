// GENERATED-EQUIVALENT source-of-truth — edited here, copied verbatim into each
// engagement by `vigil engagement create` (_write_opencode_config). Do not add
// engagement-specific values; the CLI ships this file unchanged.
//
// Vigil standard OpenCode hooks. Mirrors the Claude `.claude/settings.json` and
// Codex `.codex/config.toml` standard hooks for the OpenCode runtime, which reads
// neither of those — it loads plugins from `.opencode/plugin/` and calls the
// default export's `setup` with its plugin context.
//   - tool execute.after  -> scripts/hooks/post-tool-log.sh (PostToolUse logger).
//       records the command into the backend activity log (`vigil assess log`)
//       so OpenCode's host commands, which never pass through
//       assessment_command_runs, remain visible in the activity trail.
//       Best-effort and off the tool's path: a logging failure never fails or
//       delays the call (see the logger queue below).
//
// There is deliberately NO execute.before hook here. Vigil does not filter
// its own operator's shell commands (ADR 0019): a command-string filter cannot
// see through the shell, and the only party it acted against was the operator.
import { spawn } from "node:child_process"
import { existsSync, mkdtempSync, unlinkSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

// Resolve a hook script under the agent root. start_opencode.sh exports
// $VIGIL_AGENT_ROOT; without it, fall back to a relative path so a
// launcher-less run still finds the hooks when cwd is under the agent root.
// A copied project plugin runs with the engagement as cwd, normally
// <agent-root>/engagements/<key>, so ../../scripts/hooks is the standard bare
// session fallback. The other candidates cover running from agent/ or the repo
// root. If none exists, say so: silently dropping the activity trail makes the
// operator believe evidence was recorded when it was not.
function resolveHook(name) {
  const root = process.env.VIGIL_AGENT_ROOT
  if (root) return root.replace(/\/+$/, "") + "/scripts/hooks/" + name
  const candidates = [
    resolve(process.cwd(), "../../scripts/hooks", name),
    resolve(process.cwd(), "scripts/hooks", name),
    resolve(process.cwd(), "agent/scripts/hooks", name),
  ]
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  console.error(`[vigil] OpenCode could not resolve ${name} from cwd ${process.cwd()}`)
  return ""
}

// The logger runs off the tool's path. One OpenCode process serves every session
// (each subagent child included), so a synchronous logger would stall them all for
// each call. Each session's rows are written one at a time in call order, and
// sessions are written side by side, at most LOGGERS loggers at once, so many
// lanes neither fall behind one logger nor fan out into many. A row names its
// native call, which the logger claims exactly, and when the call finished, which
// dates it. A row without a native identity falls back to the logger's
// command-text duplicate window, so such rows never run together. Past BACKLOG
// queued rows a call waits for room rather than dropping its row.
//
// A queued row is a private spool file from the moment it is queued, so no row
// depends on OpenCode running code as it ends: SIGHUP (which `opencode serve`
// without a terminal leaves to its default action), any other signal OpenCode
// does not handle, and SIGKILL end the process without an exit event. A logger
// claims its row as it starts, with an exclusive marker naming its pid, and
// reads the file itself, so a started logger has its whole input. One detached
// drainer per spool holds a pipe from this process, which
// closes however the process ends; the drainer then waits for the running loggers
// and writes every unclaimed row in call order. The claim lets exactly one of
// them write each row.
const LOGGERS = 4
const BACKLOG = 256
const LOGGER_TIMEOUT_MS = 60000
const lanes = new Map()
const ready = []
const running = new Map()
const room = []
const spools = new Map()
let queued = 0
let sequence = 0

// The same two shell programs, and UNSPOOLED, are in assessment-hooks.js.
// CLAIM <bash> <row file> <hook>: runs the hook on the row unless it is already claimed;
// exits UNSPOOLED when the row's file is gone.
const UNSPOOLED = 75
const CLAIM = 'set -C; { printf %s "$$" > "$2.claim"; } 2>/dev/null || { [ -e "$2.claim" ] && exit 0; exit 75; }; '
  + 'exec "$1" "$3" < "$2"'
// DRAIN <spool> <bash> <hook>: once this process ends, waits for each claimed row's
// logger (as long as a logger may run), then writes the unclaimed rows in order.
const DRAIN = 'w() { p=; read -r p < "$1"; [ -n "$p" ] || { sleep 0.05; read -r p < "$1"; }; n=0; '
  + 'while [ -n "$p" ] && kill -0 "$p" 2>/dev/null && [ "$n" -lt 1200 ]; do sleep 0.05; n=$((n + 1)); done; }; '
  + 'while read -r line; do :; done; set -C; for c in "$1"/*.claim; do [ -e "$c" ] && w "$c"; done; '
  + 'for f in "$1"/*.json; do [ -e "$f" ] || continue; if { printf %s "$$" > "$f.claim"; } 2>/dev/null; '
  + 'then "$2" "$3" < "$f" >/dev/null 2>&1; else w "$f.claim"; fi; rm -f "$f" "$f.claim"; done; '
  + 'rm -f "$1"/*; rmdir "$1"'

// The spool rows for `hook` are queued in, with a drainer answering for it. A spool
// whose directory is gone starts over: its drainer, which can no longer write
// anything, is let go, and the rows still queued in it are spooled again.
function spoolFor(hook) {
  let spool = spools.get(hook)
  const lost = spool && !existsSync(spool.dir)
  if (!spool || lost) {
    try { spool?.drainer?.stdin.destroy() } catch (e) { /* already ended */ }
    spool = {dir: mkdtempSync(join(tmpdir(), "vigil-activity-")), drainer: null}
    spools.set(hook, spool)
  }
  if (!spool.drainer) {
    try {
      const drainer = spawn("bash", ["-c", DRAIN, "vigil-activity", spool.dir, "bash", hook],
        {env: process.env, stdio: ["pipe", "ignore", "ignore"], detached: true})
      spool.drainer = drainer
      // A drainer that ends while OpenCode runs is replaced by the next row.
      drainer.once("exit", () => { if (spool.drainer === drainer) spool.drainer = null })
      drainer.once("error", () => { if (spool.drainer === drainer) spool.drainer = null })
      drainer.stdin.on("error", () => {})
      drainer.unref()
      drainer.stdin.unref?.()
    } catch (e) {
      console.error(`[vigil] OpenCode shell activity still queued when OpenCode ends may not be written: ${e.message}`)
    }
  }
  if (lost) for (const write of [...lanes.values()].flat().sort((left, right) => left.sequence - right.sequence))
    if (write.hook === hook && write.file && !existsSync(write.file)) try { place(write) } catch (e) { /* dropped */ }
  return spool
}

// Writes the row into its hook's spool.
function place(write) {
  write.file = join(spoolFor(write.hook).dir, String(write.sequence).padStart(12, "0") + ".json")
  writeFileSync(write.file, write.body, { mode: 0o600, flag: "wx" })
}

function startLogger(write) {
  return spawn("bash", ["-c", CLAIM, "vigil-activity", "bash", write.file, write.hook],
    {env: process.env, stdio: "ignore", detached: true})
}

// A written (or abandoned) row leaves the spool.
function unspool(write) {
  for (const path of [write.file, write.file + ".claim"]) try { unlinkSync(path) } catch (e) { /* already gone */ }
}

function pump() {
  const anonymousRunning = () => [...running.values()].some((entry) => !entry.write.named)
  for (let index = 0; index < ready.length && running.size < LOGGERS;) {
    const lane = ready[index]
    const write = lanes.get(lane)[0]
    if (!write.named && anonymousRunning()) {
      index += 1
      continue
    }
    ready.splice(index, 1)
    lanes.get(lane).shift()
    queued -= 1
    let child
    try {
      if (!existsSync(write.file)) place(write)
      child = startLogger(write)
    } catch (e) {
      // best-effort; never block the run on a logging failure
      unspool(write)
      settle(lane)
      continue
    }
    const entry = { write, child, timer: null }
    running.set(lane, entry)
    let settled = false
    const finish = (code) => {
      if (settled) return
      settled = true
      clearTimeout(entry.timer)
      running.delete(lane)
      // A row whose file went before its logger claimed it is queued again, at its place.
      let again = false
      try { again = code === UNSPOOLED && !write.replaced && !existsSync(write.file) && (place(write), write.replaced = true) }
      catch (e) { /* dropped, as a row that cannot be spooled */ }
      if (again) {
        if (!lanes.has(lane)) lanes.set(lane, [])
        lanes.get(lane).unshift(write)
        queued += 1
      } else unspool(write)
      settle(lane)
      pump()
    }
    entry.timer = setTimeout(() => {
      try { process.kill(-child.pid, "SIGKILL") } catch (e) { finish() }
    }, LOGGER_TIMEOUT_MS)
    child.once("error", () => finish())
    child.once("exit", (code) => finish(code))
  }
  while (room.length && queued < BACKLOG) room.shift()()
}

// A lane whose logger ended (or never started) is ready again while it holds rows.
function settle(lane) {
  if (lanes.get(lane)?.length) ready.push(lane)
  else lanes.delete(lane)
}

const text = (value) => typeof value === "string" && value !== ""

// PostToolUse-equivalent. Best-effort; never fails the call on a logging failure.
// `call` is the native {session, id} when the host names one.
async function logCommand(command, agent = "operator", call = {}) {
  if (!command) return
  const occurredAt = new Date().toISOString()
  const logHook = resolveHook("post-tool-log.sh")
  if (!logHook) return
  const named = text(call.session) && text(call.id)
  const lane = text(call.session) ? call.session : ""
  const write = {
    hook: logHook,
    named,
    sequence: sequence += 1,
    body: JSON.stringify({
      hook_event_name: "PostToolUse",
      ...(named ? { client_name: "opencode", session_id: call.session, tool_use_id: call.id } : {}),
      tool_name: "Bash",
      tool_input: { command },
      tool_response: {},
      agent_type: agent,
      cwd: process.env.ENGAGEMENT_DIR || "",
      occurred_at: occurredAt,
    }),
  }
  place(write)
  if (!lanes.has(lane)) lanes.set(lane, [])
  lanes.get(lane).push(write)
  queued += 1
  if (lanes.get(lane).length === 1 && !running.has(lane)) ready.push(lane)
  pump()
  while (queued >= BACKLOG) await new Promise((resolve) => room.push(resolve))
}

export default {
  id: "vigil-standard-hooks",
  // OpenCode names the tool `shell`, passes the executed input on the event, and
  // runs this hook for child sessions too, so the event names the agent.
  setup: async (ctx) => {
    await ctx.tool.hook("execute.after", async (event) => {
      try {
        // A call id is unique within its message, so the message names the call too.
        if (event && event.tool === "shell") await logCommand(event.input && event.input.command,
          typeof event.agent === "string" && event.agent ? event.agent : "operator",
          { session: event.sessionID, id: text(event.messageID) && text(event.id) ? `${event.messageID}/${event.id}` : event.id })
      } catch (e) {
        console.error(`[vigil] OpenCode shell activity was not logged: ${e.message}`)
      }
    })
  },
}
