// GENERATED-EQUIVALENT source-of-truth — edited here, copied verbatim into each
// engagement by `vigil engagement create` (_write_opencode_config). Do not add
// engagement-specific values; the CLI ships this file unchanged.
//
// Vigil standard OpenCode hooks. Mirrors the Claude `.claude/settings.json` and
// Codex `.codex/config.toml` standard hooks for the OpenCode runtime, which reads
// neither of those — it loads plugins from `.opencode/plugin/`:
//   - tool.execute.after  -> scripts/hooks/post-tool-log.sh (PostToolUse logger).
//       records the command into the backend activity log (`vigil assess log`)
//       so OpenCode's host commands, which never pass through
//       assessment_command_runs, remain visible in the activity trail.
//       Best-effort: a logging failure never blocks the run.
//
//   - tool.execute.before -> scripts/hooks/application-read-only.sh (PreToolUse).
//       the Vigil application tree is read-only from an engagement session
//       (ADR 0048): a bash, write, edit or patch call aimed at it is refused with
//       the hook's message, which names the directory. Any other hook failure
//       lets the call run.
// KNOWN LIMITATION (opencode#5894): tool.execute.before/after do NOT fire for
// subagent (`task`) or MCP tool calls — only for the inline operator's own bash
// calls. A dispatched specialist's host commands are therefore not activity-logged
// here; network isolation still constrains all target traffic.
import { execFileSync } from "node:child_process"
import { existsSync } from "node:fs"
import { resolve } from "node:path"

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

// The OpenCode tool call reshaped onto the Claude PreToolUse contract the shared
// hook reads, or null for a tool that cannot write.
function preToolPayload(tool, args) {
  const cwd = process.env.ENGAGEMENT_DIR || process.cwd()
  if (tool === "bash" && args.command) {
    return { tool_name: "Bash", tool_input: { command: args.command }, cwd }
  }
  if ((tool === "write" || tool === "edit" || tool === "multiedit") && args.filePath) {
    return { tool_name: "Write", tool_input: { file_path: args.filePath }, cwd }
  }
  if (tool === "patch" && (args.patchText || args.patch)) {
    return { tool_name: "apply_patch", tool_input: { command: args.patchText || args.patch }, cwd }
  }
  return null
}

export const VigilStandardHooks = async () => ({
  // PreToolUse-equivalent. Throwing refuses the call; OpenCode returns the message.
  "tool.execute.before": async (input, output) => {
    const tool = String((input && input.tool) || "").toLowerCase()
    const payload = preToolPayload(tool, (output && output.args) || {})
    if (!payload) return
    const guardHook = resolveHook("application-read-only.sh")
    if (!guardHook) return
    try {
      execFileSync("bash", [guardHook], {
        input: JSON.stringify({ hook_event_name: "PreToolUse", ...payload }),
        env: process.env,
        stdio: ["pipe", "ignore", "pipe"],
      })
    } catch (e) {
      if (e && e.status === 2) {
        throw new Error(String(e.stderr || "").trim() || "refused: the Vigil application tree is read-only")
      }
      // any other failure lets the call run
    }
  },
  // PostToolUse-equivalent. Best-effort.
  "tool.execute.after": async (input, output) => {
    const tool = String((input && input.tool) || "").toLowerCase()
    if (tool !== "bash") return
    // tool.execute.after places the tool args in `input.args` (a BEFORE hook
    // puts them in `output.args`, where `output` here is {title,output,metadata}).
    // Reading output.args in the after-hook yields undefined — which silently
    // disabled activity logging. Prefer input.args, fall back to output.args.
    const command = (input && input.args && input.args.command)
      || (output && output.args && output.args.command)
    if (!command) return
    const logHook = resolveHook("post-tool-log.sh")
    if (!logHook) return
    try {
      execFileSync("bash", [logHook], {
        input: JSON.stringify({
          hook_event_name: "PostToolUse",
          tool_name: "Bash",
          tool_input: { command },
          tool_response: {},
          agent_type: "operator",
          cwd: process.env.ENGAGEMENT_DIR || "",
        }),
        env: process.env,
        stdio: ["pipe", "ignore", "ignore"],
      })
    } catch (e) {
      // best-effort; never block the run on a logging failure
    }
  },
})
