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

# Only check shell tool calls. "Bash" is Claude/Codex/OpenCode; Goose's raw shell tool is
# bare "shell" (v1.38.0) or "developer__shell" (older/doc-form builds). It is normally
# reshaped to "Bash" by goose-hook-adapter.sh, but accepting the raw names means a reshape
# failure cannot silently skip the scope check.
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)
case "$TOOL_NAME" in Bash|shell|developer__shell) ;; *) exit 0 ;; esac

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

# Destructive `git clean`: a forced recursive clean (-f together with -d) deletes
# untracked DIRECTORIES — including the operator's un-committed engagement notes.
# Match on flag PRESENCE within the git-clean segment, order-independent and
# whether combined (-fdx/-dfx/-xfd/...) or separate (-f -d), instead of a fixed
# -fdx/-dfx spelling that missed 4 of the 6 orderings (L7-1). A dry-run (-n) or
# interactive (-i) clean deletes nothing, so it is exempt.
# `git` accepts global options BEFORE the subcommand (-C <path>, -c k=v,
# --git-dir=, --no-pager, …), so `git clean` is not the only spelling: an agent
# that cannot cd rewrites `cd X && git clean -fd` as `git -C X clean -fd`, which
# a `git[[:space:]]+clean` pattern lets straight through. Allow a run of
# option-shaped tokens between the two words — option-shaped specifically, so an
# unrelated subcommand that merely mentions clean (`git log --grep clean`) still
# does not match.
GIT_GLOBAL_OPT='([[:space:]]+(-[Cc][[:space:]]+[^[:space:]]+|--[[:alnum:]-]+=[^[:space:]]*|-[[:alpha:]]+|--[[:alnum:]-]+))*'
CLEAN_SEG=$(printf '%s\n' "$COMMAND" | grep -Eo "(^|[[:space:];|&(])git${GIT_GLOBAL_OPT}[[:space:]]+clean[^;&|]*" | head -1)
if [ -n "$CLEAN_SEG" ]; then
  if ! printf '%s' "$CLEAN_SEG" | grep -Eq '([[:space:]]-[[:alpha:]]*[ni]|[[:space:]]--dry-run|[[:space:]]--interactive)'; then
    if printf '%s' "$CLEAN_SEG" | grep -Eq '([[:space:]]--force|[[:space:]]-[[:alpha:]]*f)' \
       && printf '%s' "$CLEAN_SEG" | grep -Eq '[[:space:]]-[[:alpha:]]*d'; then
      echo "BLOCKED: Destructive git clean (-f with -d) detected. Use an explicit path list or ask the user." >&2
      exit 2
    fi
  fi
fi

exit 0
