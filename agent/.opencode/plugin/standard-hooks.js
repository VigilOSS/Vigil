// GENERATED-EQUIVALENT source-of-truth — edited here, copied verbatim into each
// engagement by `vigil engagement create` (_write_opencode_config). Do not add
// engagement-specific values; the CLI ships this file unchanged.
//
// Vigil standard OpenCode hooks. Mirrors the Claude `.claude/settings.json` and
// Codex `.codex/config.toml` standard hooks for the OpenCode runtime, which reads
// neither of those — it loads plugins from `.opencode/plugin/`:
//   - tool.execute.after  -> scripts/hooks/post-tool-log.sh (PostToolUse logger).
//       records the command into the backend activity log (`vigil assess log`)
//       so activity_entries — and the bench taint audit that scans it — covers
//       OpenCode's host commands, which never pass through assessment_command_runs.
//       Best-effort: a logging failure never blocks the run.
//
// There is deliberately NO tool.execute.before hook here. Vigil does not filter
// its own operator's shell commands (ADR 0019): a command-string filter cannot
// see through the shell, and the only party it acted against was the operator.
// On the bench, a GUARD-ONLY `bench-guard.js` plugin is layered BESIDE this one
// (different filename) and owns tool.execute.before — its adversary is the
// benchmarked model, not the operator.
//
// KNOWN LIMITATION (opencode#5894): tool.execute.before/after do NOT fire for
// subagent (`task`) or MCP tool calls — only for the inline operator's own bash
// calls. A dispatched specialist's host commands are therefore not activity-logged
// here; network isolation still constrains all target traffic. See
// docs/deepseek-openrouter.md.
import { execFileSync } from "node:child_process"

// Resolve a hook script under the agent root. start_opencode.sh exports
// $VIGIL_AGENT_ROOT; without it, fall back to a relative path so a
// launcher-less run still finds the hooks when cwd is under the agent root.
// Returns "" when the root is unknown, making the hook a no-op.
function resolveHook(name) {
  const root = process.env.VIGIL_AGENT_ROOT
  if (root) return root.replace(/\/+$/, "") + "/scripts/hooks/" + name
  return ""
}

export const VigilStandardHooks = async () => ({
  // PostToolUse-equivalent, feeding the taint audit's activity_entries scan.
  // Best-effort.
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
