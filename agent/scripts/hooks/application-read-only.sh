#!/bin/bash
# application-read-only.sh — PreToolUse hook: the Vigil application tree is read-only
# for an engagement session (ADR 0048).
#
# The application directory is the tree this hook is installed in (the parent of the
# agent root that holds scripts/hooks/), plus $VIGIL_APPLICATION_DIR when the launcher
# exported a different one. The hook refuses, with exit 2 and the reason on stderr, a
# tool call that would modify a path under it:
#   - file tools: Write, Edit, MultiEdit, NotebookEdit, Codex apply_patch, and the file
#     tools the OpenCode plugin and Goose adapter reshape onto this contract. The target
#     path is the tool's own path field, resolved through symlinks, so an engagement
#     symlink into the application (for example `.claude/agents/`) counts as the
#     application.
#   - shell commands (application-read-only.jq): redirection targets, the operands of
#     rm/mv/touch/mkdir/chmod/tee/..., the destination of cp/install/ln/rsync, sed or
#     perl -i, dd of=, patch, find -delete/-exec, and a git or jj subcommand that changes
#     a work tree (checkout, restore, reset, stash, apply, commit, ...) when its work tree
#     or pathspec is under the application. `bash -c` and `eval` bodies are read one level
#     deep; commands inside if/for/while/case/{ } and after sudo/env/nice/timeout/xargs
#     are read like any other; relative paths follow cd, cd -, pushd and popd, and a
#     subshell's directory change ends with the subshell. Reads are never refused.
# The engagement directory is exempt even when it lies under the application directory.
#
# This catches the ordinary spellings of a write; it is not a sandbox. A script file,
# an interpreter's inline code, or a variable the hook cannot expand can still write
# there, which is why the operator and specialist cores carry the rule itself.
# Outside an engagement session, or without jq, the hook allows the call (exit 0).

INPUT=$(cat 2>/dev/null || true)
command -v jq >/dev/null 2>&1 || exit 0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=/dev/null
. "$SCRIPT_DIR/../lib/engagement.sh" 2>/dev/null || true

HOOK_CWD=$(printf '%s' "$INPUT" | jq -r '.cwd // empty' 2>/dev/null || true)
[ -z "$HOOK_CWD" ] && HOOK_CWD="$(pwd)"

ENG_DIR=""
if command -v resolve_engagement_dir >/dev/null 2>&1; then
  ENG_DIR=$(resolve_engagement_dir "$HOOK_CWD" 2>/dev/null || true)
fi
[ -z "$ENG_DIR" ] && exit 0

# physical_path <path> <base>: absolute, lexically normalised, with the deepest existing
# ancestor (and a symlinked final component) resolved physically. The path need not exist.
physical_path() {
  local path="$1" base="$2" part joined head tail target hops=0
  case "$path" in /*) ;; *) path="$base/$path" ;; esac
  while :; do
    local -a parts=() out=()
    set -f
    IFS='/' read -r -a parts <<< "$path"
    set +f
    for part in "${parts[@]}"; do
      case "$part" in
        ''|.) ;;
        ..) [ "${#out[@]}" -gt 0 ] && out=("${out[@]:0:$((${#out[@]} - 1))}") ;;
        *) out+=("$part") ;;
      esac
    done
    joined=""
    for part in "${out[@]}"; do joined="$joined/$part"; done
    [ -z "$joined" ] && joined="/"
    if [ -L "$joined" ] && [ "$hops" -lt 8 ]; then
      target=$(readlink "$joined")
      case "$target" in /*) path="$target" ;; *) path="$(dirname "$joined")/$target" ;; esac
      hops=$((hops + 1))
      continue
    fi
    break
  done
  head="$joined"
  tail=""
  while [ "$head" != "/" ] && [ ! -d "$head" ]; do
    tail="/$(basename "$head")$tail"
    head=$(dirname "$head")
  done
  head=$(cd "$head" 2>/dev/null && pwd -P) || head="/"
  [ "$head" = "/" ] && head=""
  printf '%s%s\n' "$head" "$tail"
}

is_under() {
  [ -n "$2" ] && { [ "$1" = "$2" ] || case "$1" in "$2"/*) true ;; *) false ;; esac; }
}

APP_ROOTS=()
for candidate in "$SCRIPT_DIR/../../.." "${VIGIL_APPLICATION_DIR:-}"; do
  [ -n "$candidate" ] && [ -d "$candidate" ] || continue
  resolved=$(cd "$candidate" && pwd -P) || continue
  [ "$resolved" = "/" ] && continue
  duplicate=0
  for root in "${APP_ROOTS[@]}"; do [ "$root" = "$resolved" ] && duplicate=1; done
  [ "$duplicate" -eq 0 ] && APP_ROOTS+=("$resolved")
done
[ "${#APP_ROOTS[@]}" -eq 0 ] && exit 0
ENG_PHYSICAL=$(cd "$ENG_DIR" 2>/dev/null && pwd -P) || ENG_PHYSICAL=""
CWD_PHYSICAL=$(physical_path "$HOOK_CWD" /)
TOOL_NAME=$(printf '%s' "$INPUT" | jq -r '.tool_name // empty' 2>/dev/null || true)
# goose-hook-adapter.sh reshapes a Goose file tool into `fileop <path>` and keeps the
# original tool beside it; only its writing tools are file writes.
SOURCE_TOOL=$(printf '%s' "$INPUT" | jq -r '
  (.source_tool_name // empty) as $name
  | if ($name | test("(^|__)(write|edit)$")) then "Write"
    elif ($name | test("text_editor$")) then
      (if ((.source_tool_input.command // "view") | IN("view")) then "read" else "Write" end)
    else "read" end' 2>/dev/null || true)
case "$SOURCE_TOOL" in
  Write) TOOL_NAME="Write" ;;
  read) exit 0 ;;
esac

# refuse_if_application <path> <description>: exit 2 when the physical path is under an
# application root and outside the engagement directory.
refuse_if_application() {
  local resolved="$1" what="$2" root
  [ -n "$resolved" ] || return 0
  is_under "$resolved" "$ENG_PHYSICAL" && return 0
  for root in "${APP_ROOTS[@]}"; do
    if is_under "$resolved" "$root"; then
      cat >&2 <<MESSAGE
Refused: the Vigil application directory $root is read-only from an engagement session.
$what would modify $resolved.
Do not edit, revert, format or check out files there, even to fix a harness defect you have
diagnosed. Record the defect with the failing command, the error and your per-run workaround
(operator: the engagement's ISSUES-AND-ENHANCEMENTS.md; specialist: the handoff's
runtime_issues), tell the user, and continue with the workaround. Reading the tree is allowed.
MESSAGE
      exit 2
    fi
  done
  return 0
}

file_targets() {
  printf '%s' "$INPUT" | jq -r '
    (.source_tool_input // .tool_input // {}) as $in
    | ($in.file_path // $in.notebook_path // $in.filePath // $in.path // empty | strings),
      (if (.tool_name // "") == "apply_patch" then
         ($in.command // $in.patch // $in.input // "") | strings
         | split("\n")[] | capture("^\\*\\*\\* (?:(?:Add|Update|Delete) File|Move to): (?<p>.+)$")
         | .p
       else empty end)' 2>/dev/null || true
}

case "$TOOL_NAME" in
  Write|Edit|MultiEdit|NotebookEdit|apply_patch)
    while IFS= read -r target; do
      [ -n "$target" ] || continue
      case "$target" in "~") target="$HOME" ;; "~/"*) target="$HOME/${target#\~/}" ;; esac
      refuse_if_application "$(physical_path "$target" "$CWD_PHYSICAL")" "$TOOL_NAME"
    done <<< "$(file_targets)"
    ;;
  Bash)
    VARS=$(jq -cn \
      --arg HOME "${HOME:-}" \
      --arg VIGIL_APPLICATION_DIR "${VIGIL_APPLICATION_DIR:-${APP_ROOTS[0]}}" \
      --arg VIGIL_AGENT_ROOT "${VIGIL_AGENT_ROOT:-${APP_ROOTS[0]}/agent}" \
      --arg ENGAGEMENT_DIR "${ENGAGEMENT_DIR:-$ENG_DIR}" \
      --arg PWD "$HOOK_CWD" \
      '$ARGS.named | with_entries(select(.value != ""))')
    ACTIONS=$(printf '%s' "$INPUT" \
      | jq -r --argjson vars "$VARS" -f "$SCRIPT_DIR/application-read-only.jq" 2>/dev/null || true)
    # The working directory follows cd/pushd/popd; a subshell saves it (with the
    # previous directory and the pushd stack) on push and restores it on pop.
    cwd="$CWD_PHYSICAL"
    repo="$CWD_PHYSICAL"
    oldcwd=""
    dirstack=()
    saved_cwd=()
    saved_old=()
    saved_stack=()
    while IFS=$'\t' read -r action operand; do
      case "$action" in
        cd)
          if [ "$operand" = "-" ]; then
            if [ -n "$oldcwd" ]; then swap="$cwd"; cwd="$oldcwd"; oldcwd="$swap"; fi
          elif [ -n "$operand" ]; then
            oldcwd="$cwd"; cwd=$(physical_path "$operand" "$cwd")
          fi
          ;;
        pushd)
          if [ -n "$operand" ]; then
            dirstack+=("$cwd"); oldcwd="$cwd"; cwd=$(physical_path "$operand" "$cwd")
          elif [ "${#dirstack[@]}" -gt 0 ]; then
            top=$((${#dirstack[@]} - 1)); swap="$cwd"; oldcwd="$cwd"; cwd="${dirstack[$top]}"; dirstack[top]="$swap"
          fi
          ;;
        popd)
          if [ "${#dirstack[@]}" -gt 0 ]; then
            top=$((${#dirstack[@]} - 1)); oldcwd="$cwd"; cwd="${dirstack[$top]}"; unset 'dirstack[top]'
          fi
          ;;
        push)
          saved_cwd+=("$cwd"); saved_old+=("$oldcwd")
          saved_stack+=("$(printf '%s\n' "${dirstack[@]+"${dirstack[@]}"}")")
          ;;
        pop)
          if [ "${#saved_cwd[@]}" -gt 0 ]; then
            top=$((${#saved_cwd[@]} - 1))
            cwd="${saved_cwd[$top]}"; oldcwd="${saved_old[$top]}"
            dirstack=()
            while IFS= read -r entry; do [ -n "$entry" ] && dirstack+=("$entry"); done <<< "${saved_stack[$top]}"
            unset 'saved_cwd[top]' 'saved_old[top]' 'saved_stack[top]'
          fi
          ;;
        w) [ -n "$operand" ] && refuse_if_application "$(physical_path "$operand" "$cwd")" "This shell command" ;;
        r)
          if [ -n "$operand" ]; then repo=$(physical_path "$operand" "$cwd"); else repo="$cwd"; fi
          refuse_if_application "$repo" "This version-control command"
          ;;
        ra) [ -n "$operand" ] && refuse_if_application "$(physical_path "$operand" "$repo")" "This version-control command" ;;
      esac
    done <<< "$ACTIONS"
    ;;
esac

exit 0
