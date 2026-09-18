#!/usr/bin/env bash
# goose-hook-adapter.sh <target-hook-script>
# Goose hook payload adapter (the Goose analog of OpenCode's standard-hooks.js reshape).
#
# Goose's `developer` builtin exposes a shell tool plus file tools. In goose v1.38.0 the
# tool names are BARE — `shell`, `write`, `edit`, `tree`, `read_image` — NOT `developer__*`
# (goose's docs are wrong; verified by a live run). The SHARED hook scripts
# (post-tool-log.sh / bench-guard.sh) key on the Claude contract
# {tool_name:"Bash", tool_input:{command}}. This adapter reshapes Goose's payload to that
# contract and runs <target> with the reshaped JSON on stdin, PROPAGATING the target's exit
# code (2 => block a PreToolUse tool call):
#   - the shell tool (name CONTAINS "shell": bare `shell` or `developer__shell`)
#     -> the real command at .tool_input.command.
#   - any OTHER tool that carries a PATH field -> a synthetic `fileop <path>` command
#     carrying the tool's PATH arg, so the guard's answer-key (block 3) / cross-attempt
#     (block 4) PATH checks fire on a tree/write/edit/read of an off-limits file. The branch
#     is NAME-AGNOSTIC (keyed on path PRESENCE, not the tool name) because the bare file
#     tools `write`/`edit`/`tree`/`read_image` do NOT contain `developer__` — a name-based
#     branch would be dead for them. ONLY explicit path fields are scanned (never file
#     CONTENT) so a legitimate write whose body mentions a path is not false-blocked.
#     (A tool with no path field — e.g. a future no-arg tool — falls through to passthrough.)
#
# Fail-CLOSED-ish: if jq is missing/the payload is malformed, emit a payload the guard can
# still evaluate (the original tool_name with the original command), because
# bench-guard.sh ALSO accepts the raw shell tool names (`shell`/`developer__shell`) — so a
# reshape failure no longer silently allows a shell cheat. (Goose hooks themselves fail open
# on a crashing hook; the load-bearing controls remain ADR 0020's attested guest/bundle
# boundary; the host-side audit is defense in depth.)
set -uo pipefail

target="${1:-}"
[ -z "$target" ] && exit 0

payload="$(cat)"

reshaped="$(printf '%s' "$payload" | jq -c '
  (.tool_name // "") as $tn
  | (.working_dir // .cwd // "") as $cwd
  | (.event // .hook_event_name // "") as $evt
  | ( (.tool_input.path // .tool_input.file_path // .tool_input.file
       // .tool_input.directory // .tool_input.dir // "") | tostring ) as $p
  | if ($tn | ascii_downcase | test("shell")) then
      { tool_name: "Bash",
        tool_input: { command: (.tool_input.command // "") },
        tool_response: (.tool_response // .tool_output // .output // {}),
        cwd: $cwd, hook_event_name: $evt,
        tool_use_id: (.tool_use_id // .call_id // "") }
    elif ($p != "") then
      # NAME-AGNOSTIC file-tool branch: any non-shell tool that carries a path field
      # (write/edit/tree/read_image — bare names in goose v1.38.0, which do NOT contain
      # "developer__") becomes `fileop <path>` so the guard checks the PATH (block 3/4).
      { tool_name: "Bash",
        tool_input: { command: ("fileop " + $p) },
        cwd: $cwd, hook_event_name: $evt, tool_use_id: "" }
    else
      { tool_name: $tn, tool_input: (.tool_input // {}),
        cwd: $cwd, hook_event_name: $evt, tool_use_id: "" }
    end' 2>/dev/null || true)"

# Reshape failed (jq absent / malformed payload): pass a payload the guard still evaluates.
# bench-guard.sh accepts the raw shell tool names ("shell"/"developer__shell") and reads
# .tool_input.command, so a forbidden SHELL command is still caught — NOT silently
# allowed.
[ -z "$reshaped" ] && reshaped="$payload"

printf '%s' "$reshaped" | bash "$target"
