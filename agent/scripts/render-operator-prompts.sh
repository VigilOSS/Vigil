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
# MODE: repo | check | render-check | source-sha
#   - `repo` with no OUTPUT_DIR (or OUTPUT_DIR = agent/) generates the
#     application's own client trees: red AGENTS.md/CLAUDE.md, blue
#     AGENTS-blue.md, and the union of both rosters' wrappers. These outputs
#     are not committed; `vigil install` from a checkout and the release build
#     run this mode. It ignores --type, installs changed files by atomic rename,
#     and prunes files under GENERATED_PATHS that the render no longer produces.
#   - `check` and `render-check` are aliases (CI/tests use `check`). They render
#     into temp dirs and validate the sources: complete per-client output for
#     every roster role, a registered source for every command, deterministic
#     output, every output inside GENERATED_PATHS, and (with no --type) identical
#     bytes wherever red and blue render the same path. They never read the
#     generated trees in agent/, which may be absent or stale in a checkout.
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
#     checks. A missing blue source fails the check, as it fails `repo`.
#   - Any other OUTPUT_DIR (an engagement or test directory) receives one
#     --type render with its operator prompt at OUTPUT_DIR/AGENTS.md.
# -----------------------------------------------------------------------------

MODE=""
OUTPUT_DIR=""
TYPE=""
TYPE_EXPLICIT=0

usage() {
  echo "Usage: $0 [repo|check|render-check|source-sha] [output-dir] [--type red|blue]" >&2
  echo "" >&2
  echo "  repo                With no output dir, generate agent/'s red+blue client trees (ignores --type)." >&2
  echo "  check/render-check  Render to temp dirs and validate sources and output. Exits 1 on any problem." >&2
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
  # `delegate` tool by recipe name.
  GOOSE_RECIPES_DIR="$OUTPUT_DIR/.goose/recipes"
  # Operator commands. ONE canonical source per command under agent/commands/,
  # rendered to one wrapper path per client (ADR 0017). Claude reads project
  # slash commands from .claude/commands/<name>.md; Codex reads project skills
  # from .codex/skills/<name>/SKILL.md (verified empirically against Codex
  # 0.154.0 with `codex debug prompt-input`; a bare `skills/` is NOT discovered).
  # OpenCode and ZCode receive only commands explicitly declaring those clients.
  CLAUDE_COMMANDS_DIR="$OUTPUT_DIR/.claude/commands"
  CODEX_SKILLS_DIR="$OUTPUT_DIR/.codex/skills"
  OPENCODE_COMMANDS_DIR="$OUTPUT_DIR/.opencode/commands"
  ZCODE_COMMANDS_DIR="$OUTPUT_DIR/.zcode/commands"
}
set_output_paths

# Every path, relative to agent/, that a source-tree `repo` render owns. The
# render prunes files under these paths it no longer produces, `check` fails on
# any output outside them, and /.gitignore must ignore exactly these paths
# (plus the STAGE_PREFIX staged-copy name at agent/'s root).
# Hand-authored client files (.claude/settings.json, .codex/config.toml,
# .opencode/plugin/, .zcode/hooks/, .zcode/assessment/hooks/) sit beside them
# and stay tracked.
GENERATED_PATHS=(
  AGENTS.md
  AGENTS-blue.md
  CLAUDE.md
  .claude/agents
  .claude/commands
  .codex/agents
  .codex/skills
  .goose
  .opencode/agent
  .opencode/commands
  .opencode/assessment
  .zcode/commands
  .zcode/.zcode-plugin
  .zcode/marketplace.json
  .zcode/assessment/agents
  .zcode/assessment/commands
  .zcode/assessment/.zcode-plugin
  .zcode/assessment/marketplace.json
)

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
  general
)

# Blue specialist roster. Note that `operator`, `osint-analyst`,
# `report-writer`, and `general` are shared with red and their source files live
# under agent/agents/<name>.md. The other four are blue-only.
# `general` is the blind-triage reviewer: its Accept verdict gates final export
# and web `transition-phase complete` for every Medium-or-above submittable
# finding. Both rosters render its wrapper so the role resolves in either tree.
BLUE_AGENT_NAMES=(
  operator
  alert-triage-specialist
  investigator
  incident-verifier
  ir-lead
  osint-analyst
  report-writer
  general
)

# -----------------------------------------------------------------------------
# Operator command roster
# -----------------------------------------------------------------------------
# CANONICAL COMMAND FORMAT (agent/commands/<name>.md)
#
#   ---
#   name: vigil-resume
#   description: one line, shown in the client's command picker
#   clients: claude  # optional; omitted means claude and codex
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
  vigil-remediate
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

# Omitted clients preserves Claude/Codex discovery. New clients require opt-in.
command_supports_client() {
  local clients
  clients=$(command_field "$1" clients)
  if [[ -z "$clients" ]]; then
    [[ "$2" == claude || "$2" == codex ]]
  else
    [[ " ${clients//,/ } " == *" $2 "* ]]
  fi
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
      count = split(part[3], clients, ",")
      matched = 0
      for (i = 1; i <= count; i++) {
        if (clients[i] != "claude" && clients[i] != "codex" && clients[i] != "opencode" && clients[i] != "zcode") {
          fail("unknown capability client \047" clients[i] "\047")
        }
        if (clients[i] == want) matched = 1
      }
      if (in_block) {
        fail("nested capability block")
      }
      in_block = 1
      block_start = NR
      skip = matched ? 0 : 1
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
  command_supports_client "$src" claude || return 0
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
  command_supports_client "$src" codex || return 0
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

render_native_remediation_command() {
  local name="$1" client="$2" directory="$3"
  local src="$COMMANDS_SRC_DIR/$name.md"
  [[ -f "$src" ]] || return 0
  command_supports_client "$src" "$client" || return 0
  local description out
  description=$(command_field "$src" description)
  out="$directory/$name.md"
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
    command_body "$src" "$client"
  } > "$out"
  perl -0pi -e 's/\n+\z/\n/' "$out"
}

render_zcode_manifest() {
  [[ -f "$ZCODE_COMMANDS_DIR/vigil-remediate.md" ]] || return 0
  local root="$OUTPUT_DIR/.zcode"
  mkdir -p "$root/.zcode-plugin"
  cat > "$root/.zcode-plugin/plugin.json" <<'EOF'
{
  "name": "vigil-remediation",
  "version": "1.0.0",
  "description": "Vigil repository remediation commands"
}
EOF
  cat > "$root/marketplace.json" <<'EOF'
{
  "name": "vigil-remediation",
  "description": "Local Vigil remediation integration",
  "plugins": [
    {
      "name": "vigil-remediation",
      "source": "./",
      "description": "Vigil repository remediation commands",
      "version": "1.0.0"
    }
  ]
}
EOF
}

render_all_commands() {
  local name
  for name in "${COMMAND_NAMES[@]}"; do
    render_claude_command "$name"
    render_codex_skill "$name"
    if [[ "$name" == vigil-remediate ]]; then
      render_native_remediation_command "$name" opencode "$OPENCODE_COMMANDS_DIR"
      render_native_remediation_command "$name" zcode "$ZCODE_COMMANDS_DIR"
    fi
  done
  render_zcode_manifest
}

# Assessment clients use an independent native tree: repository-context
# remediation and the shared Blue roster keep their existing configuration.
render_assessment_clients() {
  [[ "$TYPE" == red ]] || return 0
  local client name root out description
  for client in opencode zcode; do
    root="$OUTPUT_DIR/.$client/assessment"
    mkdir -p "$root/commands" "$root/agents"
    for name in "${COMMAND_NAMES[@]}"; do
      [[ "$name" != vigil-remediate ]] || continue
      command_supports_client "$COMMANDS_SRC_DIR/$name.md" "$client" || continue
      description=$(command_field "$COMMANDS_SRC_DIR/$name.md" description)
      out="$root/commands/$name.md"
      {
        printf -- '---\ndescription: %s\n---\n\n' "$description"
        printf '<!-- GENERATED FILE — DO NOT EDIT. -->\n<!-- Source: agent/commands/%s.md -->\n\n' "$name"
        render_stamp md
        printf '\nUse the absolute context-bound Vigil helper supplied by this native task context or Runtime Identity for every Vigil invocation. Read that immutable context router; the stable project helper inspects NEW-task setup only. Confirm the selected mode before acting.\n\nArguments from this invocation: $ARGUMENTS\n\n'
        case "$name" in
          vigil-hunt-deeper|vigil-fresh-skeptic-verify|vigil-triage-reply)
            printf 'This command implements the web workflow. In code mode, explain that limitation and use the selected code operator workflow instead; do not change modes or load a web operator core.\n\n' ;;
        esac
        command_body "$COMMANDS_SRC_DIR/$name.md" "$client" | sed 's/\$vigil-/\/vigil-/g'
      } > "$out"
    done
    for name in "${AGENT_NAMES[@]}"; do
      out="$root/agents/$name.md"
      if [[ "$name" == operator ]]; then
        [[ "$client" == opencode ]] || continue
        description="Coordinate the session-selected Vigil operator workflow"
      else
        description=$(agent_description "$name")
      fi
      {
        printf -- '---\nname: %s\ndescription: %s\n' "$name" "$description"
        if [[ "$client" == zcode ]]; then
          printf 'injectAgentsMd: false\n'
        elif [[ "$name" == operator ]]; then
          printf 'mode: primary\n'
        else
          printf 'mode: subagent\n'
        fi
        printf -- '---\n\n<!-- GENERATED FILE — DO NOT EDIT. -->\n'
        render_stamp md
        printf '\nUse the explicit context-bound helper and literal engagement/artifact paths supplied in Runtime Identity. Environment-variable path notation in shared instructions denotes those literal paths; do not assume a desktop shell inherits launcher variables.\n\n'
        if [[ "$name" == operator ]]; then
          printf 'Read this workspace AGENTS.md and follow only its selected canonical operator prompt.\n'
        else
          agent_prompt_body "$name"
        fi
      } > "$out"
    done
  done
  root="$OUTPUT_DIR/.zcode/assessment"
  mkdir -p "$root/.zcode-plugin"
  printf '{"name":"vigil-assessment","version":"1.0.0","description":"Vigil web/code client integration"}\n' > "$root/.zcode-plugin/plugin.json"
  printf '{"name":"vigil-assessment","plugins":[{"name":"vigil-assessment","source":"./","version":"1.0.0"}]}\n' > "$root/marketplace.json"
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
# Renders INTO the source tree are deliberately NOT stamped: they are part of
# the application whose install and bundle digests cover agent/, so a wall-clock
# line would change those digests on every render while adding nothing.
# render-check renders into temp dirs with the stamp disabled too, so its
# determinism comparison is byte-for-byte.
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
    general) printf '%s\n' "Zero-context blind reviewer for the blind-triage Pass-2 gate. Judges a prepared packet's own bytes only — no repository read, no command, no backend query, no engagement history." ;;
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
#       safe default for anything ambiguous.
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
# the `model:` frontmatter and a short description suffix differ. The variant
# pair is OpenCode-only, because OpenCode task dispatch has no per-call override.
# A Claude Code wrapper pins `model:`/`effort:` only for the roles in
# claude_wrapper_model_frontmatter below; Codex wrappers carry no pin. See
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
    #  code-fuzz-engineer, investigator, incident-verifier, ir-lead, general,
    #  + default.)
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
# Goose v1.38.0's openai-compat provider drops
# DeepSeek-V4 thinking-mode `reasoning_content` from the 2nd..Nth assistant messages it
# emits when it splits a parallel-tool-call turn, so DeepSeek 400s. Vigil's
# reasoning-content repair proxy (goose_reasoning_proxy.py, launched by start_goose.sh)
# re-attaches it for thinking-mode V4 on the direct path. Goose addresses
# DeepSeek by the bare id (no `deepseek/` prefix).
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
<!-- STOP — DISPATCHED SPECIALIST: if you are a specialist subagent (including a
     general blind reviewer, recon, source, surface, vuln, exploit, fuzzer, osint,
     report, or any code-* role), do NOT load this OPERATOR prompt or its startup banner.
     Investigative specialists load ONLY their own role and its `Load First` entries.
     A blind packet reviewer reads ONLY its supplied packet and review request instead.
     Auto-loaded CLAUDE.md/AGENTS.md operator pointers up the directory tree do not apply.
     See agent/shared-specialist-core.md ("Specialist Context Isolation") for why. -->
EOF
}

render_prompt_locality() {
  cat <<'EOF'
## Prompt Locality

- Operator instructions: `AGENTS.md` (canonical). `CLAUDE.md` is a pointer.
- Specialist prompt sources: `agent/agents/*.md`
- Generated specialist definitions: `.codex/agents/*.toml` / `.claude/agents/*.md` / `.opencode/agent/*.md` / `.goose/recipes/*.yaml`
- Rules load on their trigger, not at session start; the rules section below names each with its trigger: `agent/rules/resume.md` (resume and after compaction), `agent/rules/hunting.md` (judging a negative or closing a surface, inline probes, accepting a returned finding or recording a verdict yourself, stalls), and `agent/rules/hunting-operator.md` (phase exit, concurrent lanes against a WAF-fronted estate, `deep_required` app units). `agent/rules/reporting.md` is specialist/Report-phase-loaded (named in report-writer dispatch Load lists, not operator context).
- Skill discovery: `vigil assess list-skills` (compact name + one-line "Use when").
- Detailed skills: `agent/skills/*/SKILL.md`
- Reference discovery: `vigil assess list-references` (compact name + one-line description + paired skill; `--skill <name>` for a skill's paired refs).
- Detailed references: `agent/references/**/*.md`

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
    render_code_agent_roster
    cat "$CORE_FILE"
    cat <<'EOF'

## macOS Shell Note

- `grep -P` (Perl regex) is unavailable on macOS: BSD grep has no `-P`. Use `grep -E` or `rg`.
- Make file edits through the coding environment's patch/edit tool rather than shell redirection
  (`cat >`, `echo >`), so every change lands as a reviewable diff.

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
<!-- Regenerate with: cd agent && ./scripts/render-operator-prompts.sh repo -->
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
  # Keep CLAUDE.md as a pointer to the canonical AGENTS.md prompt so clients
  # that discover both entrypoints load the full instructions only once.
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

If `AGENTS.md` is already loaded, use that copy.
EOF
  } > "$CLAUDE_OUT"
}

render_agents() {
  # NOTE: red and blue both write to $OUTPUT_DIR/AGENTS.md. A single
  # engagement is either red or blue, never both, so they cannot collide in
  # an engagement directory. The source tree takes its blue prompt as
  # AGENTS-blue.md instead (render_type_tree).
  if [[ "$TYPE" == "blue" ]]; then
    render_operator_prompt_blue "$AGENTS_OUT"
  else
    render_operator_prompt "$AGENTS_OUT"
  fi
}

# Claude Code subagent frontmatter pins for specific roles. agent_prompt_body
# strips the source role's own frontmatter, so a pin lives here. Evidence-complete
# report authoring and QC run well on Sonnet at medium effort; every other role
# inherits the session model.
claude_wrapper_model_frontmatter() {
  case "$1" in
    report-writer)
      printf '%s\n' "model: claude-sonnet-5-5" "effort: medium" ;;
  esac
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
EOF
    claude_wrapper_model_frontmatter "$agent_name"
    cat <<EOF
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
  render_assessment_clients
}

# Return 0 if every blue source exists on disk; otherwise name each missing one
# on stderr, prefixed with $1, and return 1. Every source-tree render needs blue,
# so `repo` and `check` both refuse rather than skip it.
# Note: `operator` is rendered from a hardcoded template inside
# render_claude_wrapper/render_codex_wrapper, so it does not need a source
# file under agent/agents/.
require_blue_sources() {
  local agent_name missing=()
  for agent_name in "${BLUE_AGENT_NAMES[@]}"; do
    if [[ "$agent_name" != "operator" && ! -f "$SOURCE_DIR/agents/$agent_name.md" ]]; then
      missing+=("agents/$agent_name.md")
    fi
  done
  if [[ ! -f "$CORE_BLUE_FILE" ]]; then
    missing+=("operator-core-blue.md")
  fi
  if [[ ${#missing[@]} -eq 0 ]]; then
    return 0
  fi
  printf '%s: blue prompt sources missing under agent/: %s\n' "$1" "${missing[*]}" >&2
  return 1
}

# Render one type in the source-tree layout into $2: red writes AGENTS.md and
# CLAUDE.md, blue writes AGENTS-blue.md, and both write their roster's
# wrappers and the shared commands. Rendering red then blue into one directory
# yields the union the application ships. The caller restores TYPE/OUTPUT_DIR.
render_type_tree() {
  TYPE="$1"
  OUTPUT_DIR="$2"
  set_output_paths
  if [[ "$TYPE" == "blue" ]]; then
    render_operator_prompt_blue "$OUTPUT_DIR/AGENTS-blue.md"
  else
    render_claude
    render_agents
  fi
  render_all_wrappers
}

# 0 (true) when agent-relative path $1 lies inside a GENERATED_PATHS entry.
is_generated_path() {
  local owned
  for owned in "${GENERATED_PATHS[@]}"; do
    if [[ "$1" == "$owned" || "$1" == "$owned/"* ]]; then
      return 0
    fi
  done
  return 1
}

# Temp dirs and staged files this invocation created, removed on any exit so an
# interrupted or failed render leaves nothing behind in agent/ or $TMPDIR.
CLEANUP_PATHS=()
cleanup_render_paths() {
  if [[ ${#CLEANUP_PATHS[@]} -gt 0 ]]; then
    rm -rf "${CLEANUP_PATHS[@]}"
  fi
}
trap cleanup_render_paths EXIT

# A fresh temp dir registered for cleanup, in the global $RENDER_TEMP_DIR (a
# command substitution would run in a subshell and lose the registration).
new_render_temp_dir() {
  RENDER_TEMP_DIR=$(mktemp -d)
  CLEANUP_PATHS+=("$RENDER_TEMP_DIR")
}

# Staged copies are written beside their destination under this prefix and
# renamed over it. /.gitignore ignores the prefix at agent/'s root; inside a
# GENERATED_PATHS directory a leftover is pruned like any other stale output.
STAGE_PREFIX=".vigil-render."

# Make $2 match the render in $1 within GENERATED_PATHS. A changed or new file
# is written beside its destination and renamed over it, so a client reading
# the live tree never sees a truncated file; byte-identical files are left
# untouched. Files the render no longer produces are removed.
sync_rendered_tree() {
  local rendered="$1" target="$2" rel dest staged owned path
  # A staged copy left at agent/'s root by a killed render is never renamed.
  find "$target" -maxdepth 1 -type f -name "$STAGE_PREFIX*" -exec rm -f {} +
  while IFS= read -r rel; do
    rel="${rel#./}"
    dest="$target/$rel"
    if [[ -f "$dest" && ! -L "$dest" ]] && cmp -s "$rendered/$rel" "$dest"; then
      continue
    fi
    mkdir -p "$(dirname "$dest")"
    staged=$(mktemp "$(dirname "$dest")/${STAGE_PREFIX}XXXXXX")
    CLEANUP_PATHS+=("$staged")
    cat "$rendered/$rel" > "$staged"
    chmod 644 "$staged"
    mv -f "$staged" "$dest"
  done < <(cd "$rendered" && find . -type f | sort)
  for owned in "${GENERATED_PATHS[@]}"; do
    path="$target/$owned"
    if [[ -d "$path" && ! -L "$path" ]]; then
      while IFS= read -r rel; do
        rel="${rel#"$target/"}"
        if [[ ! -f "$rendered/$rel" ]]; then
          rm -f "$target/$rel"
          echo "render (source-tree): removed $rel (no longer rendered)" >&2
        fi
      done < <(find "$path" \( -type f -o -type l \) | sort)
      find "$path" -mindepth 1 -depth -type d -empty -delete
    elif [[ ( -f "$path" || -L "$path" ) && ! -f "$rendered/$owned" ]]; then
      rm -f "$path"
      echo "render (source-tree): removed $owned (no longer rendered)" >&2
    fi
  done
}

# Generate agent/'s own client trees (red + blue) from source. Both types are
# rendered into one temp dir first, so a render failure leaves the live tree
# untouched.
render_source_tree() {
  require_blue_sources "Cannot render" || exit 1
  if [[ "$TYPE_EXPLICIT" -eq 1 ]]; then
    echo "render (source-tree): agent/ always receives red and blue together; --type $TYPE has no effect here." >&2
  fi
  new_render_temp_dir
  local tmp_dir="$RENDER_TEMP_DIR"
  render_type_tree red "$tmp_dir"
  render_type_tree blue "$tmp_dir"
  TYPE=red
  OUTPUT_DIR="$SOURCE_DIR"
  set_output_paths
  sync_rendered_tree "$tmp_dir" "$SOURCE_DIR"
}

# Validate one type's render. Renders it twice into fresh temp dirs and returns
# 0 when the output is complete, deterministic, owned, and every command source
# is registered; 1 otherwise. Restores TYPE/OUTPUT_DIR before returning.
check_render_one() {
  local check_type="$1"
  local saved_type="$TYPE"
  local saved_output_dir="$OUTPUT_DIR"
  local first second
  new_render_temp_dir
  first="$RENDER_TEMP_DIR"
  new_render_temp_dir
  second="$RENDER_TEMP_DIR"
  render_type_tree "$check_type" "$first"
  render_type_tree "$check_type" "$second"
  TYPE="$check_type"

  local drift=0
  if ! diff -r "$first" "$second" >&2; then
    printf 'DRIFT (%s): two renders of the same sources differ\n' "$check_type" >&2
    drift=1
  fi

  local roster=() expected=()
  if [[ "$check_type" == "blue" ]]; then
    roster=("${BLUE_AGENT_NAMES[@]}")
    expected=(AGENTS-blue.md)
  else
    roster=("${AGENT_NAMES[@]}")
    expected=(AGENTS.md CLAUDE.md)
  fi
  local agent_name opp_model
  for agent_name in "${roster[@]}"; do
    opp_model=$(agent_opposite_model "$agent_name")
    expected+=(
      ".claude/agents/$agent_name.md"
      ".codex/agents/$agent_name.toml"
      ".opencode/agent/$agent_name.md"
      ".opencode/agent/$agent_name$(opencode_variant_name_suffix "$opp_model").md"
    )
    # Goose has no operator recipe by design: the operator prompt is the
    # engagement .goosehints.
    if [[ "$agent_name" != "operator" ]]; then
      expected+=(".goose/recipes/$agent_name.yaml")
    fi
  done
  local rel
  for rel in "${expected[@]}"; do
    if [[ ! -s "$first/$rel" ]]; then
      printf 'DRIFT (%s): %s was not rendered\n' "$check_type" "$rel" >&2
      drift=1
    fi
  done

  # Commands: every COMMAND_NAMES entry needs its canonical source, and every
  # canonical source must be registered, or it renders to nothing.
  local command_name rendered
  for command_name in "${COMMAND_NAMES[@]}"; do
    if [[ ! -f "$COMMANDS_SRC_DIR/$command_name.md" ]]; then
      printf 'DRIFT (%s): commands/%s.md missing — listed in COMMAND_NAMES but no canonical source\n' \
        "$check_type" "$command_name" >&2
      drift=1
    fi
  done
  if [[ -d "$COMMANDS_SRC_DIR" ]]; then
    for rendered in "$COMMANDS_SRC_DIR"/*.md; do
      [[ -e "$rendered" ]] || continue
      command_name=$(basename "$rendered" .md)
      if [[ " ${COMMAND_NAMES[*]} " != *" $command_name "* ]]; then
        printf 'DRIFT (%s): commands/%s.md is not in COMMAND_NAMES — it renders to nothing\n' \
          "$check_type" "$command_name" >&2
        drift=1
      fi
    done
  fi

  # Ownership: the source-tree render prunes, and .gitignore ignores, only
  # GENERATED_PATHS, so an output outside them would be left stale or committed.
  while IFS= read -r rel; do
    rel="${rel#./}"
    if ! is_generated_path "$rel"; then
      printf 'DRIFT (%s): %s is rendered outside GENERATED_PATHS\n' "$check_type" "$rel" >&2
      drift=1
    fi
  done < <(cd "$first" && find . -type f | sort)

  if [[ "$check_type" == "blue" ]]; then
    CHECKED_BLUE_DIR="$first"
  else
    CHECKED_RED_DIR="$first"
  fi
  TYPE="$saved_type"
  OUTPUT_DIR="$saved_output_dir"
  set_output_paths

  if [[ "$drift" -ne 0 ]]; then
    printf 'render-check (%s): failed\n' "$check_type" >&2
    return 1
  fi
  echo "render-check (${check_type}): clean (${#roster[@]} specialist wrappers, ${#COMMAND_NAMES[@]} operator commands; deterministic)"
  return 0
}

# The source tree is the union of the red and blue renders, with blue written
# second. A path both rosters render (shared roles, the commands) must come out
# byte-identical from each, or the union would silently keep only blue's copy.
CHECKED_RED_DIR=""
CHECKED_BLUE_DIR=""
check_union() {
  local rel conflict=0
  while IFS= read -r rel; do
    rel="${rel#./}"
    if [[ -f "$CHECKED_RED_DIR/$rel" ]] && ! cmp -s "$CHECKED_RED_DIR/$rel" "$CHECKED_BLUE_DIR/$rel"; then
      printf 'DRIFT (union): %s renders differently for red and blue\n' "$rel" >&2
      diff -u "$CHECKED_RED_DIR/$rel" "$CHECKED_BLUE_DIR/$rel" >&2 || true
      conflict=1
    fi
  done < <(cd "$CHECKED_BLUE_DIR" && find . -type f | sort)
  if [[ "$conflict" -ne 0 ]]; then
    return 1
  fi
  echo "render-check (union): clean (paths shared by red and blue render identically)"
}

# Outer render-check dispatcher. Runs red and/or blue based on $TYPE and
# whether the caller passed --type explicitly.
check_render() {
  local any_failed=0
  if [[ "$TYPE_EXPLICIT" -eq 1 ]]; then
    if [[ "$TYPE" == "blue" ]]; then
      if require_blue_sources "render-check (blue)"; then
        check_render_one blue || any_failed=1
      else
        any_failed=1
      fi
    else
      check_render_one red || any_failed=1
    fi
  else
    # No --type → run both, then compare the paths they share.
    check_render_one red || any_failed=1
    if require_blue_sources "render-check (blue)"; then
      check_render_one blue || any_failed=1
      check_union || any_failed=1
    else
      any_failed=1
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
    if [[ "$(cd "$OUTPUT_DIR" && pwd)" == "$SOURCE_DIR" ]]; then
      render_source_tree
      exit 0
    fi
    if [[ "$TYPE" == "blue" ]]; then
      require_blue_sources "Cannot render blue" || exit 1
    fi
    render_claude
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
