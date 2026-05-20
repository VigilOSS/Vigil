#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

# -----------------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------------
# Usage:
#   render-operator-prompts.sh [MODE] [OUTPUT_DIR] [--type red|blue]
#
# MODE: repo | claude-install | codex-install | check | render-check
#   - `check` and `render-check` are aliases (CI/tests historically pass `check`).
#
# --type: red (default) | blue
#   - red  → uses agent/operator-core.md + injected red roster (unchanged
#            legacy behavior; back-compat byte-identical).
#   - blue → uses agent/operator-core-blue.md, which already embeds its own
#            prompt-locality and roster sections (no injection).
#
# Special cases:
#   - `check` (or `render-check`) with NO --type runs BOTH red and blue
#     checks. Blue is skipped (with stderr warning) if any of its required
#     specialist source files are missing (e.g. Unit 6 not yet run).
#   - `repo --type blue` against the agent/ SOURCE_DIR refuses to overwrite
#     agent/AGENTS.md (which is the canonical red rendering checked into the
#     repo). Blue is rendered per-engagement only.
# -----------------------------------------------------------------------------

MODE=""
OUTPUT_DIR=""
TYPE=""
TYPE_EXPLICIT=0

usage() {
  echo "Usage: $0 [repo|claude-install|codex-install|check|render-check] [output-dir] [--type red|blue]" >&2
  echo "" >&2
  echo "  check/render-check  Render to a temp dir and diff against existing files. Exits 1 if any drift." >&2
  echo "                      With no --type, runs BOTH red and blue checks." >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type)
      if [[ $# -lt 2 ]]; then
        echo "--type requires an argument (red|blue)" >&2
        usage
        exit 1
      fi
      TYPE="$2"
      TYPE_EXPLICIT=1
      shift 2
      ;;
    --type=*)
      TYPE="${1#--type=}"
      TYPE_EXPLICIT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -z "$MODE" ]]; then
        MODE="$1"
      elif [[ -z "$OUTPUT_DIR" ]]; then
        OUTPUT_DIR="$1"
      else
        echo "Unexpected positional argument: $1" >&2
        usage
        exit 1
      fi
      shift
      ;;
  esac
done

MODE="${MODE:-repo}"
OUTPUT_DIR="${OUTPUT_DIR:-$SOURCE_DIR}"
TYPE="${TYPE:-red}"

case "$TYPE" in
  red|blue) ;;
  *)
    echo "Invalid --type '$TYPE' (expected red or blue)" >&2
    exit 1
    ;;
esac

# -----------------------------------------------------------------------------
# Paths (mutable — check_render() resets OUTPUT_DIR and derived paths into a
# temp dir; set_output_paths() recomputes the derived paths in one place.)
# -----------------------------------------------------------------------------
CORE_FILE="$SOURCE_DIR/operator-core.md"
CORE_BLUE_FILE="$SOURCE_DIR/operator-core-blue.md"

set_output_paths() {
  CLAUDE_OUT="$OUTPUT_DIR/CLAUDE.md"
  AGENTS_OUT="$OUTPUT_DIR/AGENTS.md"
  CLAUDE_AGENTS_DIR="$OUTPUT_DIR/.claude/agents"
  CODEX_AGENTS_DIR="$OUTPUT_DIR/.codex/agents"
}
set_output_paths

# -----------------------------------------------------------------------------
# Agent rosters
# -----------------------------------------------------------------------------
AGENT_NAMES=(
  operator
  recon-specialist
  source-analyzer
  surface-collector
  vulnerability-analyst
  exploit-developer
  fuzzer
  osint-analyst
  report-writer
  code-architect
  code-vuln-hunter
  code-variant-hunter
  code-vuln-verifier
  code-fuzz-engineer
)

# Blue specialist roster. Note that `operator`, `osint-analyst`, and
# `report-writer` are shared with red and their source files live under
# agent/agents/<name>.md exactly as before. The other four are blue-only and
# are created by Unit 6 of the Blue Team Engagement plan.
BLUE_AGENT_NAMES=(
  operator
  alert-triage-specialist
  investigator
  incident-verifier
  ir-lead
  osint-analyst
  report-writer
)

agent_description() {
  case "$1" in
    operator) printf '%s\n' "Lead red team operator. Drives methodology, coordinates phases, and manages state." ;;
    recon-specialist) printf '%s\n' "Initial web and service reconnaissance specialist." ;;
    source-analyzer) printf '%s\n' "Frontend and client-source analysis specialist." ;;
    surface-collector) printf '%s\n' "URL collection, deduplication, and intelligent triage specialist for Phase 2." ;;
    vulnerability-analyst) printf '%s\n' "Validation-focused analyst for attackability and evidence quality." ;;
    exploit-developer) printf '%s\n' "Exploitation and chain-building specialist." ;;
    fuzzer) printf '%s\n' "High-volume fuzzing specialist for bounded payload families." ;;
    osint-analyst) printf '%s\n' "External intelligence specialist for CVEs, disclosures, and context." ;;
    report-writer) printf '%s\n' "Human-first reporting specialist for concise, evidence-backed reporting." ;;
    code-architect) printf '%s\n' "Architecture reconnaissance, threat modeling, and file classification for source code repositories." ;;
    code-vuln-hunter) printf '%s\n' "Deep vulnerability analysis specialist for function-level code review and exploitability assessment." ;;
    code-variant-hunter) printf '%s\n' "Systematic variant scanner for confirmed code vulnerability patterns." ;;
    code-vuln-verifier) printf '%s\n' "False-positive elimination specialist for code findings using full entry-to-sink validation." ;;
    code-fuzz-engineer) printf '%s\n' "AI-driven fuzz campaign orchestration for memory-safety vulnerability discovery." ;;
    alert-triage-specialist) printf '%s\n' "L1 alert triage. Normalize, classify, auto-close mechanical noise with cited tenant-ref pattern, dispatch to L2 with platform skill named." ;;
    investigator) printf '%s\n' "L2 platform investigator. Pulls telemetry, builds evidence ladder, drafts findings with timeline + IOCs + MITRE techniques. Loads one platform skill per dispatch." ;;
    incident-verifier) printf '%s\n' "L3 false-positive verifier. Five-check protocol with symmetric evidence bar. Only role that flips verification_state away from unreviewed." ;;
    ir-lead) printf '%s\n' "L4 incident response lead. Containment / eradication / recovery proposals via propose-contain → operator approval → host-exec → contain. No automated WRITE actions." ;;
  esac
}

agent_prompt_body() {
  local agent_name="$1"
  local source="$SOURCE_DIR/agents/$agent_name.md"
  if [[ ! -f "$source" ]]; then
    echo "Missing agent prompt source: $source" >&2
    exit 1
  fi
  awk '
    NR == 1 && $0 == "---" { frontmatter = 1; next }
    frontmatter && $0 == "---" { frontmatter = 0; body_started = 0; next }
    !frontmatter {
      if (!body_started && $0 == "") {
        next
      }
      body_started = 1
      print
    }
  ' "$source"
}

render_prompt_locality() {
  cat <<'EOF'
## Prompt Locality

- Operator instructions: `AGENTS.md` (canonical). `CLAUDE.md` is a pointer.
- Specialist prompt sources: `agent/agents/*.md`
- Generated specialist definitions: `.codex/agents/*.toml` / `.claude/agents/*.md`
- Always-active rules: `agent/rules/resume.md`, `agent/rules/hunting.md`, `agent/rules/reporting.md`, `agent/rules/adversarial-mindset.md`
- Skill discovery: `aith assess list-skills` (compact name + one-line "Use when").
- Detailed skills: `agent/skills/*/SKILL.md`
- References: `agent/references/INDEX.md`

EOF
}

render_agent_roster() {
  cat <<'EOF'
## Agent Roster

| Agent | Role | Dispatched When |
|---|---|---|
| `operator` | Lead red team operator. Drives methodology, coordinates phases, manages state. | Always active. Entry point. |
| `recon-specialist` | Network recon: fingerprinting, directory fuzzing, tech stack, port scanning. | Phase 1. |
| `source-analyzer` | Deep static analysis of HTML/JS/CSS for hidden routes, API endpoints, secrets. | Phase 1 (parallel with recon). |
| `surface-collector` | URL collection, dedup, intelligent triage, work-buffer population. | Phase 2. |
| `vulnerability-analyst` | Validates endpoints with targeted probes, produces durable evidence, reviews findings in Phase 4. | Phase 3 + Phase 4 verification. |
| `exploit-developer` | Crafts exploits, confirms impact, and builds realistic attack chains. | Phase 5. |
| `fuzzer` | High-volume parameter/directory/protocol fuzzing with bounded objectives. | When FUZZER_NEEDED. |
| `osint-analyst` | External intelligence gathering, CVE/disclosure research, and prioritization support. | Phase 5 (parallel with exploit). |
| `report-writer` | Generates structured engagement report from durable backend finding state. | Phase 7 or on-demand. |

EOF
}

render_code_agent_roster() {
  cat <<'EOF'
### Code Analysis Agents (operator-core-code.md mode)

| Agent | Role | Dispatched When |
|---|---|---|
| `code-architect` | Architecture recon, threat modeling, call graph, attack hypotheses for source repos. | Code Phase 1 (Classify+Map). |
| `code-vuln-hunter` | Deep vulnerability analysis using TOB-style methodology on actual source code. | Code Phase 2 (Hunt), batched. |
| `code-variant-hunter` | Systematic scanning for variant instances of confirmed bug patterns. | Code Phase 3 (Verify+Variant), parallel per finding. |
| `code-vuln-verifier` | FP elimination via five-check protocol with devil's advocate verification. | Code Phase 3 (Verify+Variant), parallel. |
| `code-fuzz-engineer` | AI-driven fuzz campaigns: target selection, harness construction, crash triage. | Code Phase 4 (conditional, C/C++ only). |

EOF
}

render_operator_prompt() {
  local out="$1"
  {
    cat <<'EOF'
<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/operator-core.md (+ agent/agents/*.md for embedded specialist text) -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

# AI Threat Hunting — Operator Instructions

When a session starts, display:
"[operator] AI Threat Hunting ready. Ensure `aith runtime start` is running, then use `aith engagement create <target_url>` to start a new engagement."

EOF
    render_prompt_locality
    render_agent_roster
    render_code_agent_roster
    cat "$CORE_FILE"
    cat <<'EOF'

## macOS/zsh Compatibility

- Use absolute paths: `/usr/bin/curl`, `/bin/cat`, `/usr/bin/grep`, etc.
- Do NOT use `grep -P` (Perl regex). Use `grep -E` (extended) or `rg` instead.
- HEREDOC: Use unquoted delimiter (`<< EOF`), NOT single-quoted (`<< 'EOF'`).
- New files: use bash commands (mkdir, cat >, echo >). Existing files: use Edit tool.

## Tool Promotion Workflow

After an engagement, review generated tools in `agent/engagements/<...>/tools/`:
1. Identify reusable tools -> create a skill in `agent/skills/<name>/SKILL.md`
2. Add the new skill to `agent/references/INDEX.md` and note it in the relevant Claude/Codex instructions
EOF
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

# Blue rendering. The blue source (`operator-core-blue.md`) already embeds its
# own banner (line 1), Prompt Locality section, and Agent Roster section, so
# we transclude it as-is and only prepend the generated-file header. No
# roster injection.
render_operator_prompt_blue() {
  local out="$1"
  {
    cat <<'EOF'
<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/operator-core-blue.md (+ agent/agents/*.md for embedded specialist text) -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo --type blue -->

# AI Threat Hunting — Blue Operator Instructions

EOF
    cat "$CORE_BLUE_FILE"
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

render_claude() {
  # CLAUDE.md is intentionally a thin pointer — AGENTS.md is the single
  # canonical full prompt. Rendering both as full copies caused Cursor /
  # Claude Code to load ~16.5k tokens 2-4x per turn (engagement wrapper +
  # agent/CLAUDE.md + agent/AGENTS.md). Keeping CLAUDE.md as a pointer
  # collapses that to a single load.
  cat > "$CLAUDE_OUT" <<'EOF'
<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- This file is intentionally a thin pointer to AGENTS.md so Claude Code -->
<!-- does not load the same operator prompt twice. -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

# AI Threat Hunting — Operator Instructions

Read `AGENTS.md` (in this same directory) for the complete operator prompt.

Do not load this file AND `AGENTS.md` — they would otherwise be identical.
`AGENTS.md` is canonical.
EOF
}

render_agents() {
  # NOTE: red and blue both write to $OUTPUT_DIR/AGENTS.md. A single
  # engagement is either red or blue, never both, so they cannot collide in
  # an engagement directory. Against the agent/ SOURCE_DIR, the checked-in
  # AGENTS.md is the red rendering — blue rendering there is refused below
  # in main().
  if [[ "$TYPE" == "blue" ]]; then
    render_operator_prompt_blue "$AGENTS_OUT"
  else
    render_operator_prompt "$AGENTS_OUT"
  fi
}

render_claude_wrapper() {
  local agent_name="$1"
  local description
  description=$(agent_description "$agent_name")
  local out="$CLAUDE_AGENTS_DIR/$agent_name.md"
  mkdir -p "$(dirname "$out")"

  if [[ "$agent_name" == "operator" ]]; then
    cat > "$out" <<'EOF'
---
name: operator
description: Lead red team operator. Drives pentest methodology, coordinates phases, and manages state.
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/operator.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

You are the lead red team operator.

Load and follow the complete operator instructions from `AGENTS.md` in the project root.
This wrapper exists only so Claude Code can expose an `operator` agent entrypoint without duplicating prompt text.
EOF
    return
  fi

  {
    cat <<EOF
---
name: $agent_name
description: $description
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/$agent_name.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

EOF
    agent_prompt_body "$agent_name"
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

toml_literal_prompt_body() {
  local agent_name="$1"
  agent_prompt_body "$agent_name" | perl -0pe "s/'''/''\\\\''/g"
}

render_codex_wrapper() {
  local agent_name="$1"
  local description
  description=$(agent_description "$agent_name")
  local out="$CODEX_AGENTS_DIR/$agent_name.toml"
  mkdir -p "$(dirname "$out")"

  if [[ "$agent_name" == "operator" ]]; then
    cat > "$out" <<'EOF'
# GENERATED FILE — DO NOT EDIT.
# Source: agent/agents/operator.md
# Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo

name = "operator"
description = "Lead red team operator. Drives methodology, coordinates phases, and manages state."

developer_instructions = """
Load and follow the complete operator instructions from AGENTS.md in the project root.
This wrapper exists only so Codex can expose an operator agent entrypoint without duplicating prompt text.
"""
EOF
    return
  fi

  {
    cat <<EOF
# GENERATED FILE — DO NOT EDIT.
# Source: agent/agents/$agent_name.md
# Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo

name = "$agent_name"
description = "$description"

developer_instructions = '''
EOF
    toml_literal_prompt_body "$agent_name"
    cat <<'EOF'
'''
EOF
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

# Render the active roster's wrappers (red or blue) selected by $TYPE.
render_all_wrappers() {
  local agent_name
  local roster=()
  if [[ "$TYPE" == "blue" ]]; then
    roster=("${BLUE_AGENT_NAMES[@]}")
  else
    roster=("${AGENT_NAMES[@]}")
  fi
  for agent_name in "${roster[@]}"; do
    render_claude_wrapper "$agent_name"
    render_codex_wrapper "$agent_name"
  done
}

# Return 0 if all blue specialist sources exist on disk, 1 otherwise. Used by
# render-check to skip the blue check gracefully before Unit 6 has run.
# Note: `operator` is rendered from a hardcoded template inside
# render_claude_wrapper/render_codex_wrapper, so it does not need a source
# file under agent/agents/.
blue_sources_ready() {
  local agent_name
  for agent_name in "${BLUE_AGENT_NAMES[@]}"; do
    if [[ "$agent_name" == "operator" ]]; then
      continue
    fi
    if [[ ! -f "$SOURCE_DIR/agents/$agent_name.md" ]]; then
      return 1
    fi
  done
  if [[ ! -f "$CORE_BLUE_FILE" ]]; then
    return 1
  fi
  return 0
}

# Inner render-check for a single type. Renders into a fresh temp dir, diffs
# against the committed files under $source_output_dir, and returns 0 if
# clean / 1 if drift. Resets OUTPUT_DIR-derived paths back to the caller's
# values before returning.
check_render_one() {
  local check_type="$1"
  local source_output_dir="$OUTPUT_DIR"
  local saved_type="$TYPE"
  local saved_output_dir="$OUTPUT_DIR"
  local tmp_dir
  tmp_dir=$(mktemp -d)

  TYPE="$check_type"
  OUTPUT_DIR="$tmp_dir"
  set_output_paths

  local roster=()
  if [[ "$check_type" == "blue" ]]; then
    roster=("${BLUE_AGENT_NAMES[@]}")
  else
    roster=("${AGENT_NAMES[@]}")
  fi

  render_claude
  render_agents
  render_all_wrappers

  local drift=0
  local f
  local check_files=()
  if [[ "$check_type" == "blue" ]]; then
    # Blue renders to engagement dirs, not the agent/ source tree, so do not
    # compare CLAUDE.md/AGENTS.md at the source tree. Only the specialist
    # wrappers belong under agent/.claude/.codex.
    check_files=()
  else
    check_files=(CLAUDE.md AGENTS.md)
  fi
  for f in ${check_files[@]+"${check_files[@]}"}; do
    if ! diff -q "$source_output_dir/$f" "$tmp_dir/$f" >/dev/null 2>&1; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$f" >&2
      diff -u "$source_output_dir/$f" "$tmp_dir/$f" >&2 || true
      drift=1
    fi
  done

  local agent_name
  for agent_name in "${roster[@]}"; do
    local claude_rel=".claude/agents/$agent_name.md"
    local codex_rel=".codex/agents/$agent_name.toml"
    local target_claude="$source_output_dir/$claude_rel"
    local target_codex="$source_output_dir/$codex_rel"
    # Missing wrapper IS drift — the render produced it but the checked-in
    # copy is absent. Operators reading from .claude/.codex hit nothing.
    if [[ ! -f "$target_claude" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$claude_rel" >&2
      drift=1
    elif ! diff -q "$target_claude" "$tmp_dir/$claude_rel" >/dev/null 2>&1; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$claude_rel" >&2
      diff -u "$target_claude" "$tmp_dir/$claude_rel" >&2 || true
      drift=1
    fi
    if [[ ! -f "$target_codex" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$codex_rel" >&2
      drift=1
    elif ! diff -q "$target_codex" "$tmp_dir/$codex_rel" >/dev/null 2>&1; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$codex_rel" >&2
      diff -u "$target_codex" "$tmp_dir/$codex_rel" >&2 || true
      drift=1
    fi
  done

  rm -rf "$tmp_dir"
  TYPE="$saved_type"
  OUTPUT_DIR="$saved_output_dir"
  set_output_paths

  if [[ "$drift" -ne 0 ]]; then
    if [[ "$check_type" == "blue" ]]; then
      printf 'render-check (%s): drift detected. Re-run from repo root:\n  cd agent && ./scripts/render-operator-prompts.sh repo --type blue\n' "$check_type" >&2
    else
      printf 'render-check (%s): drift detected. Re-run from repo root:\n  cd agent && ./scripts/render-operator-prompts.sh repo\n' "$check_type" >&2
    fi
    return 1
  fi
  echo "render-check (${check_type}): clean (${#roster[@]} specialist wrappers match source)"
  return 0
}

# Outer render-check dispatcher. Runs red and/or blue based on $TYPE and
# whether the caller passed --type explicitly.
check_render() {
  local any_failed=0
  if [[ "$TYPE_EXPLICIT" -eq 1 ]]; then
    if [[ "$TYPE" == "blue" ]]; then
      if ! blue_sources_ready; then
        echo "render-check (blue): SKIPPED — blue specialist source files not yet present (Unit 6 not yet run)." >&2
        return 0
      fi
      check_render_one blue || any_failed=1
    else
      check_render_one red || any_failed=1
    fi
  else
    # No --type → run both. Red is always available. Blue is skipped with a
    # stderr warning if its source files are not yet present.
    check_render_one red || any_failed=1
    if blue_sources_ready; then
      check_render_one blue || any_failed=1
    else
      echo "render-check (blue): SKIPPED — blue specialist source files not yet present (Unit 6 not yet run)." >&2
    fi
  fi
  if [[ "$any_failed" -ne 0 ]]; then
    exit 1
  fi
}

# -----------------------------------------------------------------------------
# Main dispatch
# -----------------------------------------------------------------------------
case "$MODE" in
  repo)
    # In source-tree-blue mode (TYPE=blue against the canonical agent/
    # source dir), agent/AGENTS.md and agent/CLAUDE.md are the checked-in red
    # canonical files and MUST NOT be overwritten. We still render the blue
    # specialist wrappers under agent/.claude/agents/ and agent/.codex/agents/
    # so the blue roster is dispatchable from the source tree. Per-engagement
    # blue renders (OUTPUT_DIR != SOURCE_DIR) write everything including
    # AGENTS.md.
    SOURCE_TREE_BLUE=0
    if [[ "$TYPE" == "blue" && "$(cd "$OUTPUT_DIR" && pwd)" == "$SOURCE_DIR" ]]; then
      SOURCE_TREE_BLUE=1
    fi
    if [[ "$TYPE" == "blue" ]] && ! blue_sources_ready; then
      echo "Cannot render blue: required source files missing under agent/." >&2
      echo "Unit 6 of the Blue Team Engagement plan has not yet run." >&2
      exit 1
    fi
    if [[ "$SOURCE_TREE_BLUE" -eq 1 ]]; then
      echo "render (blue, source-tree): skipping AGENTS.md and CLAUDE.md to preserve the red canonical files; writing specialist wrappers only." >&2
    else
      render_claude
      render_agents
    fi
    render_all_wrappers
    ;;
  claude-install)
    if [[ "$TYPE" == "blue" ]] && ! blue_sources_ready; then
      echo "Cannot render blue: required source files missing under agent/." >&2
      exit 1
    fi
    render_claude
    render_all_wrappers
    ;;
  codex-install)
    if [[ "$TYPE" == "blue" ]] && ! blue_sources_ready; then
      echo "Cannot render blue: required source files missing under agent/." >&2
      exit 1
    fi
    render_agents
    render_all_wrappers
    ;;
  check|render-check)
    check_render
    ;;
  *)
    usage
    exit 1
    ;;
esac
