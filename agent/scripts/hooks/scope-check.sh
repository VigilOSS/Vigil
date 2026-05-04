#!/bin/bash
# scope-check.sh — Claude Code / Codex PreToolUse hook
# Reads hook JSON from stdin and blocks obviously destructive host commands.
# Target-facing routing is taught by the prompts/skills and audited by the CLI;
# the hook stays limited to commands that could destroy local state before the
# operator has a chance to recover.
# Hook format: {"tool_name":"Bash","tool_input":{"command":"..."}}
#
# Exit codes: 0 = allow, 2 = block

# No set -e: grep returning no matches (exit 1) is expected, not an error.

INPUT=$(cat)

# Only check Bash tool calls
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)
[ "$TOOL_NAME" != "Bash" ] && exit 0

# Extract command
COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null || true)
[ -z "$COMMAND" ] && exit 0

if printf '%s\n' "$COMMAND" | grep -Eq '(^|[[:space:];|&(])(sudo[[:space:]]+)?rm[[:space:]][^;&|]*-[^;&|[:space:]]*[rR][^;&|[:space:]]*[fF]|(^|[[:space:];|&(])(sudo[[:space:]]+)?rm[[:space:]][^;&|]*-[^;&|[:space:]]*[fF][^;&|[:space:]]*[rR]'; then
  echo "BLOCKED: Destructive recursive delete detected. Review the path and run a narrower command." >&2
  exit 2
fi

if printf '%s\n' "$COMMAND" | grep -Eq '(^|[[:space:];|&(])(sudo[[:space:]]+)?(mkfs|newfs|diskutil[[:space:]]+erase|dd[[:space:]][^;&|]*of=/dev/)'; then
  echo "BLOCKED: Destructive disk operation detected." >&2
  exit 2
fi

if printf '%s\n' "$COMMAND" | grep -Eq '(^|[[:space:];|&(])(sudo[[:space:]]+)?(chmod|chown)[[:space:]][^;&|]*-[^;&|[:space:]]*[rR][^;&|]*(/[[:space:]]*|/[;&|]|$)'; then
  echo "BLOCKED: Recursive ownership/permission change against a root path detected." >&2
  exit 2
fi

if printf '%s\n' "$COMMAND" | grep -Eq '(^|[[:space:];|&(])git[[:space:]]+clean[[:space:]][^;&|]*-[^;&|[:space:]]*f[^;&|[:space:]]*d[^;&|[:space:]]*x|(^|[[:space:];|&(])git[[:space:]]+clean[[:space:]][^;&|]*-[^;&|[:space:]]*d[^;&|[:space:]]*f[^;&|[:space:]]*x'; then
  echo "BLOCKED: Destructive git clean detected. Use an explicit path list or ask the user." >&2
  exit 2
fi

exit 0
