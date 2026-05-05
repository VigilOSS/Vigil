#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
MODE="${1:-repo}"
OUTPUT_DIR="${2:-$SOURCE_DIR}"

CORE_FILE="$SOURCE_DIR/operator-core.md"
CLAUDE_OUT="$OUTPUT_DIR/CLAUDE.md"
AGENTS_OUT="$OUTPUT_DIR/AGENTS.md"
CLAUDE_AGENTS_DIR="$OUTPUT_DIR/.claude/agents"
CODEX_AGENTS_DIR="$OUTPUT_DIR/.codex/agents"

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
- Always-active rules: `agent/rules/hunting.md`, `agent/rules/reporting.md`
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
# AI Threat Hunting — Operator Instructions

When a session starts, display:
"[operator] AI Threat Hunting ready. Ensure `aith runtime start` is running, then use `aith engagement create <target_url>` to start a new engagement."

<!-- Generated from operator-core.md via scripts/render-operator-prompts.sh -->

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

render_claude() {
  # CLAUDE.md is intentionally a thin pointer — AGENTS.md is the single
  # canonical full prompt. Rendering both as full copies caused Cursor /
  # Claude Code to load ~16.5k tokens 2-4x per turn (engagement wrapper +
  # agent/CLAUDE.md + agent/AGENTS.md). Keeping CLAUDE.md as a pointer
  # collapses that to a single load.
  cat > "$CLAUDE_OUT" <<'EOF'
# AI Threat Hunting — Operator Instructions

Read `AGENTS.md` (in this same directory) for the complete operator prompt.

Do not load this file AND `AGENTS.md` — they would otherwise be identical.
`AGENTS.md` is canonical.

<!-- Generated by scripts/render-operator-prompts.sh -->
EOF
}

render_agents() {
  render_operator_prompt "$AGENTS_OUT"
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

render_all_wrappers() {
  local agent_name
  for agent_name in "${AGENT_NAMES[@]}"; do
    render_claude_wrapper "$agent_name"
    render_codex_wrapper "$agent_name"
  done
}

case "$MODE" in
  repo)
    render_claude
    render_agents
    render_all_wrappers
    ;;
  claude-install)
    render_claude
    render_all_wrappers
    ;;
  codex-install)
    render_agents
    render_all_wrappers
    ;;
  *)
    echo "Usage: $0 [repo|claude-install|codex-install] [output-dir]" >&2
    exit 1
    ;;
esac
