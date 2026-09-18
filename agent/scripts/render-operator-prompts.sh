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
# MODE: repo | claude-install | codex-install | check | render-check | source-sha
#   - `check` and `render-check` are aliases (CI/tests historically pass `check`).
#   - `source-sha` prints the current prompt-source digest for --type and exits;
#     it is the value a consumer compares an already-rendered copy's stamp
#     against (see "Prompt stamp" below).
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
#     specialist source files are missing.
#   - `repo --type blue` against the agent/ SOURCE_DIR writes the canonical
#     agent/AGENTS-blue.md without overwriting agent/AGENTS.md (the canonical
#     red rendering). Engagements point at these canonical installed files.
# -----------------------------------------------------------------------------

MODE=""
OUTPUT_DIR=""
TYPE=""
TYPE_EXPLICIT=0

usage() {
  echo "Usage: $0 [repo|claude-install|codex-install|check|render-check|source-sha] [output-dir] [--type red|blue]" >&2
  echo "" >&2
  echo "  check/render-check  Render to a temp dir and diff against existing files. Exits 1 if any drift." >&2
  echo "                      With no --type, runs BOTH red and blue checks." >&2
  echo "  source-sha          Print the current prompt-source digest for --type and exit." >&2
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
  # Operator commands. ONE canonical source per command under agent/commands/,
  # rendered to one wrapper path per client (ADR 0017). Claude reads project
  # slash commands from .claude/commands/<name>.md; Codex reads project skills
  # from .codex/skills/<name>/SKILL.md (verified empirically against Codex
  # 0.154.0 with `codex debug prompt-input`; a bare `skills/` is NOT discovered).
  # opencode/goose/kimi get no commands — those clients have no equivalent
  # project-command surface, and their operators run the verbs directly.
  CLAUDE_COMMANDS_DIR="$OUTPUT_DIR/.claude/commands"
  CODEX_SKILLS_DIR="$OUTPUT_DIR/.codex/skills"
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
# agent/agents/<name>.md exactly as before. The other four are blue-only.
BLUE_AGENT_NAMES=(
  operator
  alert-triage-specialist
  investigator
  incident-verifier
  ir-lead
  osint-analyst
  report-writer
)

# -----------------------------------------------------------------------------
# Operator command roster
# -----------------------------------------------------------------------------
# CANONICAL COMMAND FORMAT (agent/commands/<name>.md)
#
#   ---
#   name: vigil-resume
#   description: one line, shown in the client's command picker
#   ---
#   <shared markdown body>
#
# Commands are client-agnostic by default. Where a client capability differs,
# wrap the divergent text in a capability block — one canonical file, no forked
# content:
#
#   <!-- vigil:only claude -->
#   ...text using $ARGUMENTS, !`bash` command substitution, or @file...
#   <!-- vigil:end -->
#   <!-- vigil:only codex -->
#   ...the same instruction, degraded honestly: state the command for the agent
#      to RUN, because Codex skills have no substitution...
#   <!-- vigil:end -->
#
# Blocks whose client is not the render target are dropped along with their
# markers. Everything outside a block is emitted for every client. Commands are
# NOT split red/blue: the roster below is rendered once per invocation.
#
# The roster is explicit rather than a glob so a forgotten file is caught: a
# canonical source that is not listed here is reported as drift by render-check.
COMMAND_NAMES=(
  vigil-start
  vigil-resume
  vigil-handoff
  vigil-compact
  vigil-hunt-deeper
  vigil-fresh-skeptic-verify
  vigil-triage-reply
)

COMMANDS_SRC_DIR="$SOURCE_DIR/commands"

# Value of a frontmatter field in a canonical command source.
command_field() {
  local src="$1" field="$2"
  awk -v field="$field" '
    NR == 1 && $0 == "---" { inside = 1; next }
    inside && $0 == "---" { exit }
    inside {
      key = field ":"
      if (index($0, key) == 1) { print substr($0, length(key) + 2); exit }
    }
  ' "$src"
}

# Canonical body for one client: frontmatter stripped, capability blocks for
# other clients dropped, leading blank lines trimmed.
command_body() {
  local src="$1" client="$2"
  awk -v want="$client" -v src="$src" '
    function fail(reason) {
      printf "%s:%d: %s\n", src, NR, reason > "/dev/stderr"
      failed = 1
      exit 2
    }
    NR == 1 && $0 == "---" { fm = 1; next }
    fm && $0 == "---" { fm = 0; next }
    fm { next }
    /^<!-- vigil:only/ {
      if ($0 !~ /^<!-- vigil:only [^ ]+ -->$/) {
        fail("malformed capability block marker")
      }
      split($0, part, " ")
      if (part[3] != "claude" && part[3] != "codex") {
        fail("unknown capability client \047" part[3] "\047")
      }
      if (in_block) {
        fail("nested capability block")
      }
      in_block = 1
      block_start = NR
      skip = (part[3] == want) ? 0 : 1
      next
    }
    /^<!-- vigil:end -->$/ {
      if (!in_block) {
        fail("unmatched <!-- vigil:end -->")
      }
      in_block = 0
      skip = 0
      next
    }
    skip { next }
    !emitted && $0 == "" { next }
    { emitted = 1; print }
    END {
      if (!failed && in_block) {
        printf "%s:%d: missing <!-- vigil:end --> for capability block\n", src, block_start > "/dev/stderr"
        exit 2
      }
    }
  ' "$src"
}

# Claude project slash command: .claude/commands/<name>.md. Claude supports only
# `description` in this frontmatter (`name` comes from the filename), and the
# body keeps the $ARGUMENTS / !`bash` / @file substitutions.
render_claude_command() {
  local name="$1"
  local src="$COMMANDS_SRC_DIR/$name.md"
  [[ -f "$src" ]] || return 0
  local description out
  description=$(command_field "$src" description)
  out="$CLAUDE_COMMANDS_DIR/$name.md"
  mkdir -p "$(dirname "$out")"
  {
    cat <<EOF
---
description: $description
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/$name.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
EOF
    render_stamp md
    printf '\n'
    command_body "$src" claude
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

# Codex project skill: .codex/skills/<name>/SKILL.md, invoked as `$<name>`.
# Codex skill frontmatter carries `name` and `description`. Codex performs NO
# argument or command substitution in a skill body, so the codex capability
# blocks state the commands for the agent to run instead of pre-substituting
# their output.
render_codex_skill() {
  local name="$1"
  local src="$COMMANDS_SRC_DIR/$name.md"
  [[ -f "$src" ]] || return 0
  local description out
  description=$(command_field "$src" description)
  out="$CODEX_SKILLS_DIR/$name/SKILL.md"
  mkdir -p "$(dirname "$out")"
  {
    cat <<EOF
---
name: $name
description: $description
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/commands/$name.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
EOF
    render_stamp md
    printf '\n'
    command_body "$src" codex
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

render_all_commands() {
  local name
  for name in "${COMMAND_NAMES[@]}"; do
    render_claude_command "$name"
    render_codex_skill "$name"
  done
}

# -----------------------------------------------------------------------------
# Prompt stamp
# -----------------------------------------------------------------------------
# A render written OUTSIDE the source tree (an engagement directory, an install
# root) is a copy nothing ever re-renders: the operator reading it has no way to
# tell it is weeks behind the prompt it should be reading. Every such mirror
# therefore carries
#
#   <!-- vigil-prompt-stamp: <source-sha> <iso8601> -->      (md/html files)
#   # vigil-prompt-stamp: <source-sha> <iso8601>             (toml/yaml files)
#
# right below the GENERATED-FILE header. `<source-sha>` is the digest this
# script prints for `source-sha` mode, so a consumer compares
# `<copy>` stamp vs `render-operator-prompts.sh source-sha --type <t>` and warns
# on a mismatch — no second copy of the digest rule anywhere.
#
# Renders INTO the source tree are deliberately NOT stamped: those artifacts are
# committed and already guarded byte-for-byte by render-check, so a wall-clock
# line would churn every tracked wrapper on every render while adding nothing.
# render-check itself compares modulo the stamp (it renders into a temp dir), so
# a stamped copy never registers as prompt drift.
STAMP_MARKER="vigil-prompt-stamp"
STAMP_ENABLED=1
if [[ "$(cd "$OUTPUT_DIR" 2>/dev/null && pwd)" == "$SOURCE_DIR" ]]; then
  STAMP_ENABLED=0
fi
# One timestamp for the whole render, so every mirror written by one invocation
# agrees on when it was produced.
RENDER_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)
# Cached per $TYPE — render-check flips $TYPE between the red and blue passes.
SOURCE_SHA_CACHE=""
SOURCE_SHA_CACHE_TYPE=""

sha256_stdin() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum
  else
    shasum -a 256
  fi | awk '{ print $1 }'
}

# Digest of everything that determines the render for the current $TYPE: the
# renderer itself (rosters, descriptions, boilerplate), the operator core, and
# every role source in roster order. Content-addressed rather than git-derived
# so it also works from an install root (not a checkout) and still moves when a
# prompt is edited but not yet committed.
source_stamp_sha() {
  if [[ "$SOURCE_SHA_CACHE_TYPE" != "$TYPE" ]]; then
    local roster=() core agent_name
    if [[ "$TYPE" == "blue" ]]; then
      roster=("${BLUE_AGENT_NAMES[@]}")
      core="$CORE_BLUE_FILE"
    else
      roster=("${AGENT_NAMES[@]}")
      core="$CORE_FILE"
    fi
    SOURCE_SHA_CACHE=$(
      {
        cat "$SCRIPT_DIR/${BASH_SOURCE[0]##*/}"
        cat "$core"
        for agent_name in "${roster[@]}"; do
          if [[ -f "$SOURCE_DIR/agents/$agent_name.md" ]]; then
            cat "$SOURCE_DIR/agents/$agent_name.md"
          fi
        done
        # Commands are part of what this renderer produces, so an edit to one
        # must move the digest that engagement mirrors compare themselves to.
        local command_name
        for command_name in "${COMMAND_NAMES[@]}"; do
          if [[ -f "$SOURCE_DIR/commands/$command_name.md" ]]; then
            cat "$SOURCE_DIR/commands/$command_name.md"
          fi
        done
      } | sha256_stdin
    )
    SOURCE_SHA_CACHE_TYPE="$TYPE"
  fi
  printf '%s\n' "$SOURCE_SHA_CACHE"
}

# Emit the stamp line in $1 comment syntax ("md" or "hash"), or nothing at all
# when this render targets the source tree.
render_stamp() {
  [[ "$STAMP_ENABLED" -eq 1 ]] || return 0
  local sha
  sha=$(source_stamp_sha)
  if [[ "$1" == "hash" ]]; then
    printf '# %s: %s %s\n' "$STAMP_MARKER" "$sha" "$RENDER_TIMESTAMP"
  else
    printf '<!-- %s: %s %s -->\n' "$STAMP_MARKER" "$sha" "$RENDER_TIMESTAMP"
  fi
}

agent_description() {
  case "$1" in
    operator) printf '%s\n' "Lead red team operator. Drives methodology, coordinates phases, and manages state." ;;
    recon-specialist) printf '%s\n' "Recon completeness assessor + bounded web fingerprinting over the supervised recon pipeline." ;;
    source-analyzer) printf '%s\n' "Frontend and client-source analysis specialist." ;;
    surface-collector) printf '%s\n' "URL collection, deduplication, and intelligent triage specialist for Phase 2." ;;
    vulnerability-analyst) printf '%s\n' "Primary vulnerability hunter — surveys wide, goes deep where signal is, adjudicates with evidence-first rigor." ;;
    exploit-developer) printf '%s\n' "Exploitation and chain-building specialist." ;;
    fuzzer) printf '%s\n' "High-volume fuzzing specialist for bounded payload families." ;;
    osint-analyst) printf '%s\n' "External intelligence specialist for CVEs, disclosures, and context." ;;
    report-writer) printf '%s\n' "Human-first reporting specialist for concise, evidence-backed reporting." ;;
    code-architect) printf '%s\n' "Architecture reconnaissance, threat modeling, and file classification for source code repositories." ;;
    code-vuln-hunter) printf '%s\n' "Deep vulnerability analysis specialist for function-level code review and exploitability assessment." ;;
    code-variant-hunter) printf '%s\n' "Systematic scanner for historical bug shapes and variants of current code findings." ;;
    code-vuln-verifier) printf '%s\n' "False-positive elimination specialist for code findings using full entry-to-sink validation." ;;
    code-fuzz-engineer) printf '%s\n' "AI-driven fuzz campaign orchestration for memory-safety vulnerability discovery." ;;
    alert-triage-specialist) printf '%s\n' "L1 alert triage. Normalize, classify, auto-close mechanical noise with cited tenant-ref pattern, dispatch to L2 with platform skill named." ;;
    investigator) printf '%s\n' "L2 platform investigator. Pulls telemetry, builds evidence ladder, drafts findings with timeline + IOCs + MITRE techniques. Loads one platform skill per dispatch." ;;
    incident-verifier) printf '%s\n' "L3 false-positive verifier. Five-check protocol with symmetric evidence bar. Only role that records terminal verification_status decisions." ;;
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

# Specialist auto-load stop-sign. Claude Code (and other harnesses) auto-load
# CLAUDE.md/AGENTS.md walking up the dir tree, so a DISPATCHED SPECIALIST subagent
# inherits these operator pointers before it reaches its own Specialist-Context-Isolation
# rule. This banner is the harness-injection stop-sign: authored ONCE here and reused
# by every operator-prompt + pointer render below (DRY). See agent/shared-specialist-core.md
# ("Specialist Context Isolation") for why.
render_specialist_stop_sign() {
  cat <<'EOF'
<!-- STOP — DISPATCHED SPECIALIST: if you are a specialist subagent (recon, source,
     surface, vuln, exploit, fuzzer, osint, report, or any code-* role), do NOT load
     this file. It is the OPERATOR prompt and its startup/runtime banner must not bleed
     into your context. Load ONLY your own role file and every entry in its `Load First`.
     Auto-loaded CLAUDE.md/AGENTS.md pointers up the directory tree do not apply to you.
     See agent/shared-specialist-core.md ("Specialist Context Isolation") for why. -->
EOF
}

render_prompt_locality() {
  cat <<'EOF'
## Prompt Locality

- Operator instructions: `AGENTS.md` (canonical). `CLAUDE.md` is a pointer.
- Specialist prompt sources: `agent/agents/*.md`
- Generated specialist definitions: `.codex/agents/*.toml` / `.claude/agents/*.md` / `.opencode/agent/*.md` / `.goose/recipes/*.yaml`
- Always-active rules: `agent/rules/resume.md`, `agent/rules/hunting.md`, `agent/rules/adversarial-mindset.md`. `agent/rules/reporting.md` is specialist/Report-phase-loaded (named in report-writer dispatch Load lists, not loaded into operator context before Phase 8).
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
| `vulnerability-analyst` | Primary hunter — surveys wide then deep, confirms leads with targeted probes, produces durable evidence, reviews findings in Phase 5. | Phase 4 + Phase 5 verification. |
| `exploit-developer` | Crafts exploits, confirms impact, and builds realistic attack chains. | Phase 6. |
| `fuzzer` | High-volume parameter/directory/protocol fuzzing with bounded objectives. | When FUZZER_NEEDED. |
| `osint-analyst` | External intelligence gathering, CVE/disclosure research, and prioritization support. | Phase 6 (parallel with exploit). |
| `report-writer` | Generates structured engagement report from durable backend finding state. | Phase 8 or on-demand. |

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
EOF
    render_stamp md
    printf '\n'
    render_specialist_stop_sign
    cat <<'EOF'

# Vigil — Operator Instructions

When a session starts, display:
"[operator] Vigil ready. Ensure `vigil runtime start` is running, then use `vigil engagement create <target_url>` to start a new engagement."

EOF
    render_prompt_locality
    render_agent_roster
    render_code_agent_roster
    cat "$CORE_FILE"
    cat <<'EOF'

## macOS Shell Note

- `grep -P` (Perl regex) is unavailable on macOS: BSD grep has no `-P`. Use `grep -E` or `rg`.
- Make file edits through the coding environment's patch/edit tool rather than shell redirection
  (`cat >`, `echo >`), so every change lands as a reviewable diff.

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
EOF
    render_stamp md
    printf '\n'
    render_specialist_stop_sign
    cat <<'EOF'

# Vigil — Blue Operator Instructions

EOF
    cat "$CORE_BLUE_FILE"
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

render_claude() {
  # CLAUDE.md is intentionally a thin pointer — AGENTS.md is the single
  # canonical full prompt. Rendering both as full copies caused Cursor /
  # Claude Code to load the whole operator prompt 2-4x per turn (engagement
  # wrapper + agent/CLAUDE.md + agent/AGENTS.md). Keeping CLAUDE.md as a
  # pointer collapses that to a single load. `vigil assess prompt-census`
  # reports what one load currently costs; a size named here would go stale.
  {
    cat <<'EOF'
<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- This file is intentionally a thin pointer to AGENTS.md so Claude Code -->
<!-- does not load the same operator prompt twice. -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
EOF
    render_stamp md
    printf '\n'
    render_specialist_stop_sign
    cat <<'EOF'

# Vigil — Operator Instructions

Read `AGENTS.md` (in this same directory) for the complete operator prompt.

Load `AGENTS.md` OR this file, not both — they would otherwise be identical.
`AGENTS.md` is canonical.
EOF
  } > "$CLAUDE_OUT"
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
    {
      cat <<'EOF'
---
name: operator
description: Lead red team operator. Drives pentest methodology, coordinates phases, and manages state.
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/operator.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
EOF
      render_stamp md
      cat <<'EOF'

You are the lead red team operator.

Load and follow the complete operator instructions from `AGENTS.md` in the project root.
This wrapper exists only so Claude Code can expose an `operator` agent entrypoint without duplicating prompt text.
EOF
    } > "$out"
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
    render_stamp md
    printf '\n'
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
    {
      cat <<'EOF'
# GENERATED FILE — DO NOT EDIT.
# Source: agent/agents/operator.md
# Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo
EOF
      render_stamp hash
      cat <<'EOF'

name = "operator"
description = "Lead red team operator. Drives methodology, coordinates phases, and manages state."

developer_instructions = """
Load and follow the complete operator instructions from AGENTS.md in the project root.
This wrapper exists only so Codex can expose an operator agent entrypoint without duplicating prompt text.
"""
EOF
    } > "$out"
    return
  fi

  {
    cat <<EOF
# GENERATED FILE — DO NOT EDIT.
# Source: agent/agents/$agent_name.md
# Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo
EOF
    render_stamp hash
    cat <<EOF

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
    {
      cat <<EOF
---
description: Lead red team operator. Drives pentest methodology, coordinates phases, and manages state.$desc_suffix
mode: primary
model: $model
---

<!-- GENERATED FILE — DO NOT EDIT. -->
<!-- Source: agent/agents/operator.md -->
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
EOF
      render_stamp md
      cat <<EOF

You are the lead red team operator.

Load and follow the complete operator instructions from \`AGENTS.md\` in the project root.
This wrapper exists only so OpenCode can expose an \`operator\` agent entrypoint without duplicating prompt text.
EOF
    } > "$out"
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
    render_stamp md
    printf '\n'
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
EOF
    render_stamp hash
    cat <<EOF
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
  # Commands are roster-independent (identical for red and blue), so this is
  # idempotent when both types are rendered in one run.
  render_all_commands
}

# Return 0 if all blue specialist sources exist on disk, 1 otherwise. Used by
# render-check to skip the blue check gracefully when a source is unavailable.
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

# Drift comparison ignores the prompt stamp: it is provenance metadata (source
# digest + render time), not prompt content, so a differing or absent stamp must
# never read as prompt drift. Everything else is still compared byte-for-byte.
strip_stamp() {
  grep -v "$STAMP_MARKER" "$1" || true
}

# 0 (true) when the two rendered files differ in prompt content, or either is
# missing — the caller reports that as drift, matching the old `diff -q` contract.
prompt_files_differ() {
  [[ -f "$1" && -f "$2" ]] || return 0
  ! diff -q <(strip_stamp "$1") <(strip_stamp "$2") >/dev/null 2>&1
}

# Print the content diff for a drifting pair (stamp lines excluded, as above).
print_prompt_diff() {
  diff -u <(strip_stamp "$1") <(strip_stamp "$2") >&2 || true
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
    if prompt_files_differ "$source_output_dir/AGENTS-blue.md" "$tmp_dir/AGENTS.md"; then
      printf 'DRIFT (%s): AGENTS-blue.md differs from source render\n' "$check_type" >&2
      print_prompt_diff "$source_output_dir/AGENTS-blue.md" "$tmp_dir/AGENTS.md"
      drift=1
    fi
    check_files=()
  else
    check_files=(CLAUDE.md AGENTS.md)
  fi
  for f in ${check_files[@]+"${check_files[@]}"}; do
    if prompt_files_differ "$source_output_dir/$f" "$tmp_dir/$f"; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$f" >&2
      print_prompt_diff "$source_output_dir/$f" "$tmp_dir/$f"
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
    elif prompt_files_differ "$target_claude" "$tmp_dir/$claude_rel"; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$claude_rel" >&2
      print_prompt_diff "$target_claude" "$tmp_dir/$claude_rel"
      drift=1
    fi
    if [[ ! -f "$target_codex" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$codex_rel" >&2
      drift=1
    elif prompt_files_differ "$target_codex" "$tmp_dir/$codex_rel"; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$codex_rel" >&2
      print_prompt_diff "$target_codex" "$tmp_dir/$codex_rel"
      drift=1
    fi
    if [[ ! -f "$target_opencode" ]]; then
      printf 'DRIFT (%s): %s missing — expected rendered wrapper not present in repo\n' "$check_type" "$opencode_rel" >&2
      drift=1
    elif prompt_files_differ "$target_opencode" "$tmp_dir/$opencode_rel"; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$opencode_rel" >&2
      print_prompt_diff "$target_opencode" "$tmp_dir/$opencode_rel"
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
    elif prompt_files_differ "$target_opencode_variant" "$tmp_dir/$opencode_variant_rel"; then
      printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$opencode_variant_rel" >&2
      print_prompt_diff "$target_opencode_variant" "$tmp_dir/$opencode_variant_rel"
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
      elif prompt_files_differ "$target_goose" "$tmp_dir/$goose_rel"; then
        printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$goose_rel" >&2
        print_prompt_diff "$target_goose" "$tmp_dir/$goose_rel"
        drift=1
      fi
    fi
  done

  # Operator commands. Rendered from agent/commands/ into the same temp dir by
  # render_all_wrappers above, so the same missing/differs contract applies.
  local command_name
  for command_name in "${COMMAND_NAMES[@]}"; do
    local command_src="$SOURCE_DIR/commands/$command_name.md"
    if [[ ! -f "$command_src" ]]; then
      printf 'DRIFT (%s): commands/%s.md missing — listed in COMMAND_NAMES but no canonical source\n' \
        "$check_type" "$command_name" >&2
      drift=1
      continue
    fi
    local claude_command_rel=".claude/commands/$command_name.md"
    local codex_skill_rel=".codex/skills/$command_name/SKILL.md"
    local rel
    for rel in "$claude_command_rel" "$codex_skill_rel"; do
      if [[ ! -f "$source_output_dir/$rel" ]]; then
        printf 'DRIFT (%s): %s missing — expected rendered command not present in repo\n' \
          "$check_type" "$rel" >&2
        drift=1
      elif prompt_files_differ "$source_output_dir/$rel" "$tmp_dir/$rel"; then
        printf 'DRIFT (%s): %s differs from source render\n' "$check_type" "$rel" >&2
        print_prompt_diff "$source_output_dir/$rel" "$tmp_dir/$rel"
        drift=1
      fi
    done
  done

  # Orphans. agent/.claude and agent/.codex are mirror-synced into the install
  # root by `vigil install` (install.py::_sync_client_entrypoints_fds), so a
  # rendered command left behind after its canonical source was renamed or
  # deleted would keep shipping to every engagement with nothing regenerating
  # it. A canonical source that is not in COMMAND_NAMES is caught the same way.
  local rendered orphan_name
  if [[ -d "$source_output_dir/.claude/commands" ]]; then
    for rendered in "$source_output_dir"/.claude/commands/*.md; do
      [[ -e "$rendered" ]] || continue
      orphan_name=$(basename "$rendered" .md)
      if [[ ! -f "$tmp_dir/.claude/commands/$orphan_name.md" ]]; then
        printf 'DRIFT (%s): .claude/commands/%s.md is not rendered by any canonical source\n' \
          "$check_type" "$orphan_name" >&2
        drift=1
      fi
    done
  fi
  if [[ -d "$source_output_dir/.codex/skills" ]]; then
    for rendered in "$source_output_dir"/.codex/skills/*/SKILL.md; do
      [[ -e "$rendered" ]] || continue
      orphan_name=$(basename "$(dirname "$rendered")")
      if [[ ! -f "$tmp_dir/.codex/skills/$orphan_name/SKILL.md" ]]; then
        printf 'DRIFT (%s): .codex/skills/%s/SKILL.md is not rendered by any canonical source\n' \
          "$check_type" "$orphan_name" >&2
        drift=1
      fi
    done
  fi
  if [[ -d "$COMMANDS_SRC_DIR" ]]; then
    for rendered in "$COMMANDS_SRC_DIR"/*.md; do
      [[ -e "$rendered" ]] || continue
      orphan_name=$(basename "$rendered" .md)
      if [[ ! -f "$tmp_dir/.claude/commands/$orphan_name.md" ]]; then
        printf 'DRIFT (%s): commands/%s.md is not in COMMAND_NAMES — it renders to nothing\n' \
          "$check_type" "$orphan_name" >&2
        drift=1
      fi
    done
  fi

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
  echo "render-check (${check_type}): clean (${#roster[@]} specialist wrappers, ${#COMMAND_NAMES[@]} operator commands match source)"
  return 0
}

# Outer render-check dispatcher. Runs red and/or blue based on $TYPE and
# whether the caller passed --type explicitly.
check_render() {
  local any_failed=0
  if [[ "$TYPE_EXPLICIT" -eq 1 ]]; then
    if [[ "$TYPE" == "blue" ]]; then
      if ! blue_sources_ready; then
        echo "render-check (blue): SKIPPED — required blue specialist source files are missing." >&2
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
      echo "render-check (blue): SKIPPED — required blue specialist source files are missing." >&2
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
    # In source-tree-blue mode, preserve the canonical red AGENTS.md/CLAUDE.md
    # and write the full blue doctrine to its own canonical AGENTS-blue.md.
    # Specialist wrappers remain shared under agent/.claude/.codex/.opencode.
    SOURCE_TREE_BLUE=0
    if [[ "$TYPE" == "blue" && "$(cd "$OUTPUT_DIR" && pwd)" == "$SOURCE_DIR" ]]; then
      SOURCE_TREE_BLUE=1
    fi
    if [[ "$TYPE" == "blue" ]] && ! blue_sources_ready; then
      echo "Cannot render blue: required source files missing under agent/." >&2
      exit 1
    fi
    if [[ "$SOURCE_TREE_BLUE" -eq 1 ]]; then
      render_operator_prompt_blue "$SOURCE_DIR/AGENTS-blue.md"
      echo "render (blue, source-tree): wrote canonical AGENTS-blue.md; preserved red AGENTS.md and CLAUDE.md." >&2
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
  source-sha)
    # The value a rendered copy's `vigil-prompt-stamp` is compared against.
    source_stamp_sha
    ;;
  *)
    usage
    exit 1
    ;;
esac
