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
  OPENCODE_AGENTS_DIR="$OUTPUT_DIR/.opencode/agent"
  # Goose specialist roster: one recipe .yaml per role. Unlike OpenCode/Claude/Codex,
  # Goose has NO operator wrapper — the operator prompt is carried via the engagement's
  # `.goosehints` and the default `goose run` agent dispatches specialists via the
  # `delegate` tool by recipe name. See docs/goose-bench.md.
  GOOSE_RECIPES_DIR="$OUTPUT_DIR/.goose/recipes"
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
    recon-specialist) printf '%s\n' "Recon completeness assessor + bounded web fingerprinting over the supervised recon pipeline." ;;
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

# -----------------------------------------------------------------------------
# OpenCode per-role model routing (workstream E).
#
# OpenCode subagents INHERIT the invoking primary's model unless they set `model`
# explicitly, so every generated `.opencode/agent/<name>.md` pins a model. The
# classification below splits the roster on task shape, not on red/blue:
#
#   deepseek-v4-pro   — the operator/primary and HARD multi-step reasoning roles:
#       exploit chaining, auth/access-control reasoning, deep taint analysis,
#       false-positive verification, and full-state synthesis. Pro is also the
#       safe default for anything ambiguous (Terminal-Bench agentic: Pro 67.9%).
#   deepseek-v4-flash — BOUNDED recon / parsing / enumeration / high-fan-out
#       sweep roles where the work is mechanical and cheap (Flash 56.9%; only
#       used where the task is simple and bounded).
#
# When adding a role, default it to Pro unless it is clearly a bounded,
# high-fan-out, mechanical sweep.
#
# Fast+deep variant pairs (OpenCode ONLY): OpenCode subagents inherit the
# invoking primary's model unless the wrapper pins `model:`, and OpenCode's
# task/dispatch has no per-call model override — the model is strictly the
# wrapper file's frontmatter `model:` at dispatch time. So for OpenCode we emit,
# for every role, the canonical tier (from agent_model below) AND an
# opposite-tier sibling so the operator can dispatch either a fast (Flash) or a
# deep (Pro) variant of any specialist by name (`<role>` + `<role>-pro` or
# `<role>-flash`). The sibling shares the canonical's prompt body verbatim; only
# the `model:` frontmatter and a short description suffix differ. This is
# OpenCode-only: `.claude`/`.codex` wrappers do NOT consume wrapper `model:`
# frontmatter, so no variants are emitted there (pure clutter). See
# render_opencode_wrapper / opencode_variant_suffix below.
OPENCODE_PRO_MODEL="deepseek/deepseek-v4-pro"
OPENCODE_FLASH_MODEL="deepseek/deepseek-v4-flash"

agent_model() {
  case "$1" in
    # Flash — bounded recon/parsing/enumeration/high-fan-out sweeps.
    recon-specialist|source-analyzer|surface-collector|fuzzer|code-variant-hunter|alert-triage-specialist)
      printf '%s\n' "$OPENCODE_FLASH_MODEL" ;;
    # Pro — operator + hard multi-step exploit/analysis/verification/synthesis.
    # (operator, vulnerability-analyst, exploit-developer, osint-analyst,
    #  report-writer, code-architect, code-vuln-hunter, code-vuln-verifier,
    #  code-fuzz-engineer, investigator, incident-verifier, ir-lead, + default.)
    *)
      printf '%s\n' "$OPENCODE_PRO_MODEL" ;;
  esac
}

# The OpenCode opposite-tier sibling: given a role's canonical model, return the
# OTHER tier's model. Used to emit the fast+deep variant pair (OpenCode only).
agent_opposite_model() {
  if [[ "$(agent_model "$1")" == "$OPENCODE_PRO_MODEL" ]]; then
    printf '%s\n' "$OPENCODE_FLASH_MODEL"
  else
    printf '%s\n' "$OPENCODE_PRO_MODEL"
  fi
}

# The dispatchable name suffix + description suffix for a variant pinned to
# $model. Pro siblings get `-pro`; Flash siblings get `-flash`.
opencode_variant_name_suffix() {
  if [[ "$1" == "$OPENCODE_PRO_MODEL" ]]; then
    printf '%s\n' "-pro"
  else
    printf '%s\n' "-flash"
  fi
}

opencode_variant_desc_suffix() {
  if [[ "$1" == "$OPENCODE_PRO_MODEL" ]]; then
    printf '%s\n' " — deep (Pro) variant"
  else
    printf '%s\n' " — fast (Flash) variant"
  fi
}

# -----------------------------------------------------------------------------
# Goose per-role model routing.
#
# Goose specialists pin their model in each recipe's `settings.goose_model` (the
# verified per-subagent override path — NOT the GOOSE_SUBAGENT_* env vars, which
# aaif-goose#9644 lets the orchestrator confabulate/override).
#
# #9397 (verified live 2026-06-19): goose v1.38.0's openai-compat provider drops
# DeepSeek-V4 thinking-mode `reasoning_content` from the 2nd..Nth assistant messages it
# emits when it splits a parallel-tool-call turn, so DeepSeek 400s. The bench's
# reasoning-content repair proxy (goose_reasoning_proxy.py, launched by start_goose.sh)
# re-attaches it, so thinking-mode V4 now works on the DIRECT path — per-role pro/flash
# routing is restored. Goose addresses DeepSeek by the BARE id (no `deepseek/` prefix).
# See docs/goose-bench.md.
GOOSE_PRO_MODEL="deepseek-v4-pro"
GOOSE_FLASH_MODEL="deepseek-v4-flash"

goose_model_for() {
  # Mirror the OpenCode per-role tiering (agent_model) but with goose's BARE ids:
  # Flash for bounded recon/parsing roles, Pro for the operator + hard reasoning roles.
  case "$(agent_model "$1")" in
    "$OPENCODE_FLASH_MODEL") printf '%s\n' "$GOOSE_FLASH_MODEL" ;;
    *)                       printf '%s\n' "$GOOSE_PRO_MODEL" ;;
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
- Generated specialist definitions: `.codex/agents/*.toml` / `.claude/agents/*.md` / `.opencode/agent/*.md` / `.goose/recipes/*.yaml`
- Always-active rules: `agent/rules/resume.md`, `agent/rules/hunting.md`, `agent/rules/reporting.md`, `agent/rules/adversarial-mindset.md`
- Skill discovery: `vigil assess list-skills` (compact name + one-line "Use when").
- Detailed skills: `agent/skills/*/SKILL.md`
- Reference discovery: `vigil assess list-references` (compact name + one-line description + paired skill; `--skill <name>` for a skill's paired refs).
- Detailed references: `agent/references/**/*.md`

EOF
}

render_agent_roster() {
  cat <<'EOF'
## Agent Roster

| Agent | Role | Dispatched When |
|---|---|---|
| `operator` | Lead red team operator. Drives methodology, coordinates phases, manages state. | Always active. Entry point. |
| `recon-specialist` | Recon-completeness assessment over the `vigil assess recon` job + bounded per-host web fingerprinting. | Phase 1 (after the recon job). |
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

# Vigil — Operator Instructions

When a session starts, display:
"[operator] Vigil ready. Ensure `vigil runtime start` is running, then use `vigil engagement create <target_url>` to start a new engagement."

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
- Make file edits through the active coding environment's patch/edit tool. Avoid shell
  redirection (`cat >`, `echo >`) for manual file creation or modification because it
  bypasses reviewable patch diffs and is easy to quote incorrectly in zsh.

## Tool Promotion Workflow

After an engagement, review generated tools in `agent/engagements/<...>/tools/`:
1. Identify reusable tools -> create a skill in `agent/skills/<name>/SKILL.md`
2. Skills and references self-register — `vigil assess list-skills` / `list-references` discover new files from their frontmatter, so there is no index to update; just note the new skill in the relevant Claude/Codex instructions if it needs workflow wiring
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

# Vigil — Blue Operator Instructions

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

# Vigil — Operator Instructions

Read `AGENTS.md` (in this same directory) for the complete operator prompt.

Load `AGENTS.md` OR this file, not both — they would otherwise be identical.
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

# Write a single OpenCode wrapper for $agent_name pinned to $model. The optional
# $name_suffix/$desc_suffix produce an opposite-tier VARIANT sibling
# (`<role>-pro.md` / `<role>-flash.md`); empty suffixes produce the canonical
# `<role>.md` (kept byte-identical to legacy output). Both the canonical and the
# variant share ONE code path here; only the filename, `model:`, and the
# description suffix differ. The GENERATED-FILE banner still points at the
# canonical source (`agent/agents/<role>.md`) so the variant's provenance and
# "DO NOT EDIT / Regenerate with" guidance stay intact.
render_one_opencode_wrapper() {
  local agent_name="$1"
  local model="$2"
  local name_suffix="${3:-}"
  local desc_suffix="${4:-}"
  local description
  description=$(agent_description "$agent_name")
  local out="$OPENCODE_AGENTS_DIR/$agent_name$name_suffix.md"
  mkdir -p "$(dirname "$out")"

  # OpenCode agent frontmatter: description + mode + model. Specialists are
  # `mode: subagent` so they are dispatchable only via the operator's
  # `task`/@mention (never a primary entrypoint). The OPERATOR is `mode: primary`
  # because `opencode run --agent operator` (written by engagements._write_launchers)
  # must be able to launch it AS the top-level brain: OpenCode 1.17.5 refuses to
  # run a `mode: subagent` agent as the entrypoint — it prints "agent X is a
  # subagent, not a primary agent. Falling back to default agent" and silently
  # runs the built-in `build` primary instead, which reads AGENTS.md as mere
  # context and does the work inline (0 specialist dispatches). A primary operator
  # still has the `task` tool and dispatches the subagent roster normally.
  # `model` is pinned on EVERY role because OpenCode subagents otherwise inherit
  # the invoking primary's model, defeating routing.
  if [[ "$agent_name" == "operator" ]]; then
    cat > "$out" <<EOF
---
description: Lead red team operator. Drives pentest methodology, coordinates phases, and manages state.$desc_suffix
mode: primary
model: $model
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/operator.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

You are the lead red team operator.

Load and follow the complete operator instructions from \`AGENTS.md\` in the project root.
This wrapper exists only so OpenCode can expose an \`operator\` agent entrypoint without duplicating prompt text.
EOF
    return
  fi

  {
    cat <<EOF
---
description: $description$desc_suffix
mode: subagent
model: $model
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/$agent_name.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->

EOF
    agent_prompt_body "$agent_name"
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

# Emit the OpenCode wrappers for a role: the canonical tier AND the opposite-tier
# sibling. OpenCode-only fast+deep pairing (see the routing block above). The
# canonical (empty suffixes) stays byte-identical to legacy; the sibling pins the
# opposite model with a `-pro`/`-flash` name + description suffix.
render_opencode_wrapper() {
  local agent_name="$1"
  local canonical_model opposite_model variant_name_suffix variant_desc_suffix
  canonical_model=$(agent_model "$agent_name")
  opposite_model=$(agent_opposite_model "$agent_name")
  variant_name_suffix=$(opencode_variant_name_suffix "$opposite_model")
  variant_desc_suffix=$(opencode_variant_desc_suffix "$opposite_model")

  # Canonical (byte-identical to legacy).
  render_one_opencode_wrapper "$agent_name" "$canonical_model"
  # Opposite-tier sibling (OpenCode-only fast+deep pair).
  render_one_opencode_wrapper "$agent_name" "$opposite_model" "$variant_name_suffix" "$variant_desc_suffix"
}

# Write the Goose specialist recipe for $agent_name to .goose/recipes/<name>.yaml.
# The operator has NO recipe (its prompt is the engagement `.goosehints`; the default
# goose agent dispatches via `delegate source <role>`), so this is a no-op for
# `operator`. Each specialist recipe carries: the role prompt body as a YAML literal
# block with an EXPLICIT indent indicator (`|2`) so a body whose first line is itself
# indented cannot mis-set the block indent; the `developer` builtin (shell + editor);
# and a per-role `goose_model` pin. Empty body lines are emitted truly empty (no
# trailing whitespace); content lines are indented 2 to sit inside the block.
render_goose_recipe() {
  local agent_name="$1"
  [[ "$agent_name" == "operator" ]] && return 0
  local description model out description_yaml
  description=$(agent_description "$agent_name")
  model=$(goose_model_for "$agent_name")
  out="$GOOSE_RECIPES_DIR/$agent_name.yaml"
  mkdir -p "$(dirname "$out")"
  # Escape for a YAML double-quoted scalar so any description renders valid YAML:
  # backslashes first (so we don't double-escape), then double quotes. All current
  # descriptions are quote/backslash-free, so this is a no-op for today's roster.
  description_yaml="${description//\\/\\\\}"
  description_yaml="${description_yaml//\"/\\\"}"
  {
    cat <<EOF
# GENERATED FILE — DO NOT EDIT.
# Source: agent/agents/$agent_name.md
# Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo
version: "1.0.0"
title: $agent_name
description: "$description_yaml"
instructions: |2
EOF
    agent_prompt_body "$agent_name" | awk '{ if ($0 == "") print ""; else print "  " $0 }'
    cat <<'EOF'
extensions:
  - type: builtin
    name: developer
settings:
EOF
    printf '  goose_model: %s\n' "$model"
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
    render_opencode_wrapper "$agent_name"
    render_goose_recipe "$agent_name"
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
    local opencode_rel=".opencode/agent/$agent_name.md"
    local target_claude="$source_output_dir/$claude_rel"
    local target_codex="$source_output_dir/$codex_rel"
    local target_opencode="$source_output_dir/$opencode_rel"
    # Missing wrapper IS drift — the render produced it but the checked-in
    # copy is absent. Operators reading from .claude/.codex/.opencode hit nothing.
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
    if [[ ! -f "$target_opencode" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$opencode_rel" >&2
      drift=1
    elif ! diff -q "$target_opencode" "$tmp_dir/$opencode_rel" >/dev/null 2>&1; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$opencode_rel" >&2
      diff -u "$target_opencode" "$tmp_dir/$opencode_rel" >&2 || true
      drift=1
    fi
    # OpenCode-only opposite-tier variant sibling (fast+deep pair). No
    # corresponding .claude/.codex variant exists by design, so this is checked
    # only for the opencode path.
    local opp_model variant_suffix opencode_variant_rel target_opencode_variant
    opp_model=$(agent_opposite_model "$agent_name")
    variant_suffix=$(opencode_variant_name_suffix "$opp_model")
    opencode_variant_rel=".opencode/agent/$agent_name$variant_suffix.md"
    target_opencode_variant="$source_output_dir/$opencode_variant_rel"
    if [[ ! -f "$target_opencode_variant" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$opencode_variant_rel" >&2
      drift=1
    elif ! diff -q "$target_opencode_variant" "$tmp_dir/$opencode_variant_rel" >/dev/null 2>&1; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$opencode_variant_rel" >&2
      diff -u "$target_opencode_variant" "$tmp_dir/$opencode_variant_rel" >&2 || true
      drift=1
    fi
    # Goose specialist recipe. No operator recipe exists by design (operator prompt
    # is the engagement .goosehints), so the recipe check is skipped for operator.
    if [[ "$agent_name" != "operator" ]]; then
      local goose_rel=".goose/recipes/$agent_name.yaml"
      local target_goose="$source_output_dir/$goose_rel"
      if [[ ! -f "$target_goose" ]]; then
        printf 'DRIFT (%s): %s missing — expected rendered recipe not present in repo\n' "$check_type" "$goose_rel" >&2
        drift=1
      elif ! diff -q "$target_goose" "$tmp_dir/$goose_rel" >/dev/null 2>&1; then
        printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$goose_rel" >&2
        diff -u "$target_goose" "$tmp_dir/$goose_rel" >&2 || true
        drift=1
      fi
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
