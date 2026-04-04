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
  vulnerability-analyst
  exploit-developer
  fuzzer
  osint-analyst
  report-writer
  code-architect
  code-context-builder
  code-vuln-hunter
  code-variant-hunter
  code-vuln-verifier
)

agent_description() {
  case "$1" in
    operator) printf '%s\n' "Lead red team operator. Drives methodology, coordinates phases, and manages state." ;;
    recon-specialist) printf '%s\n' "Initial web and service reconnaissance specialist." ;;
    source-analyzer) printf '%s\n' "Frontend and client-source analysis specialist." ;;
    vulnerability-analyst) printf '%s\n' "Validation-focused analyst for attackability and evidence quality." ;;
    exploit-developer) printf '%s\n' "Exploitation and chain-building specialist." ;;
    fuzzer) printf '%s\n' "High-volume fuzzing specialist for bounded payload families." ;;
    osint-analyst) printf '%s\n' "External intelligence specialist for CVEs, disclosures, and context." ;;
    report-writer) printf '%s\n' "Human-first reporting specialist for concise, evidence-backed reporting." ;;
    code-architect) printf '%s\n' "Architecture reconnaissance, threat modeling, and file classification for source code repositories." ;;
    code-context-builder) printf '%s\n' "Reads source code modules, extracts function context slices with call graphs and data flow annotations." ;;
    code-vuln-hunter) printf '%s\n' "Deep vulnerability analysis specialist for function-level code review and exploitability assessment." ;;
    code-variant-hunter) printf '%s\n' "Systematic variant scanner for confirmed code vulnerability patterns." ;;
    code-vuln-verifier) printf '%s\n' "False-positive elimination specialist for code findings using full entry-to-sink validation." ;;
  esac
}

render_banner() {
  cat <<'EOF'
```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████  ███████ ██████  ████████ ███████  █████  ███    ███║
║   ██   ██ ██      ██   ██    ██    ██      ██   ██ ████  ████║
║   ██████  █████   ██   ██    ██    █████   ███████ ██ ████ ██║
║   ██   ██ ██      ██   ██    ██    ██      ██   ██ ██  ██  ██║
║   ██   ██ ███████ ██████     ██    ███████ ██   ██ ██      ██║
║                                                              ║
║   Autonomous Red Team Simulation Agent                       ║
EOF
}

render_prompt_locality() {
  cat <<'EOF'
## Prompt Locality

- Operator instructions: `AGENTS.md` / `CLAUDE.md`
- Specialist prompt sources: `agent/agents/*.md`
- Generated specialist wrappers: `.codex/agents/*.toml` / `.claude/agents/*.md`
- Always-active rules: `agent/rules/hunting.md`, `agent/rules/reporting.md`
- Skill discovery: `agent/SKILL.md`
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
| `vulnerability-analyst` | Validates endpoints, kills weak findings, and prepares durable evidence. | Phase 3 consumption loop. |
| `exploit-developer` | Crafts exploits, confirms impact, and builds realistic attack chains. | Phase 3 (HIGH/MEDIUM) + Phase 4. |
| `fuzzer` | High-volume parameter/directory/protocol fuzzing with bounded objectives. | When FUZZER_NEEDED. |
| `osint-analyst` | External intelligence gathering, CVE/disclosure research, and prioritization support. | Phase 4 (parallel with exploit). |
| `report-writer` | Generates structured engagement report from durable findings and synchronized artifacts. | Phase 5 or on-demand. |

EOF
}

render_code_agent_roster() {
  cat <<'EOF'
### Code Analysis Agents (operator-core-code.md mode)

| Agent | Role | Dispatched When |
|---|---|---|
| `code-architect` | Architecture recon, threat modeling, file classification for source repos. | Code Phase 1 (Classify). |
| `code-context-builder` | Function-level context extraction with call graphs and data flow annotations. | Code Phase 2 (Context), parallel per module. |
| `code-vuln-hunter` | Deep vulnerability analysis using constrained attacker persona and taint tracing. | Code Phase 3 (Analyze), batched. |
| `code-variant-hunter` | Systematic scanning for variant instances of confirmed bug patterns. | Code Phase 4 (Variant), parallel per finding. |
| `code-vuln-verifier` | FP elimination via full entry-to-sink traces and attack chain synthesis. | Code Phase 5 (Verify). |

EOF
}

render_claude() {
  {
    cat <<'EOF'
# AI Threat Hunting — Operator Instructions

EOF
    render_banner
    cat <<'EOF'
║   Powered by Claude Code  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

When a session starts, display the banner above and then:
"[operator] AI Threat Hunting ready. Ensure `./agent/scripts/start_kali_mcp_runtime.sh` is running, then use `cd agent && ./scripts/init_engagement.sh <target_url>` to start a new engagement."

---

<!-- Generated from operator-core.md via scripts/render-operator-prompts.sh -->

EOF
    render_prompt_locality
    render_agent_roster
    render_code_agent_roster
    cat "$CORE_FILE"
    cat <<'EOF'

## Claude Dispatch Syntax

Use `@agent-name` when dispatching subagents:
- `@recon-specialist`
- `@source-analyzer`
- `@vulnerability-analyst`
- `@exploit-developer`
- `@fuzzer`
- `@osint-analyst`
- `@report-writer`
- `@code-architect`
- `@code-context-builder`
- `@code-vuln-hunter`
- `@code-variant-hunter`
- `@code-vuln-verifier`

## macOS/zsh Compatibility

- Use absolute paths: `/usr/bin/curl`, `/bin/cat`, `/usr/bin/grep`, etc.
- Do NOT use `grep -P` (Perl regex). Use `grep -E` (extended) or `rg` instead.
- HEREDOC: Use unquoted delimiter (`<< EOF`), NOT single-quoted (`<< 'EOF'`).
- New files: use bash commands (mkdir, cat >, echo >). Existing files: use Edit tool.
EOF
  } > "$CLAUDE_OUT"
  perl -0pi -e 's/\n+\z/\n/' "$CLAUDE_OUT"
}

render_agents() {
  {
    cat <<'EOF'
# AI Threat Hunting

EOF
    render_banner
    cat <<'EOF'
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

When a session starts, display the banner above and then:
"[operator] AI Threat Hunting ready. Ensure `./agent/scripts/start_kali_mcp_runtime.sh` is running, then use `cd agent && ./scripts/init_engagement.sh <target_url>` to start a new engagement."

---

<!-- Generated from operator-core.md via scripts/render-operator-prompts.sh -->

EOF
    render_prompt_locality
    render_agent_roster
    render_code_agent_roster
    cat "$CORE_FILE"
    cat <<'EOF'

## Tool Promotion Workflow

After an engagement, review generated tools in `agent/engagements/<...>/tools/`:
1. Identify reusable tools -> create a skill in `agent/skills/<name>/SKILL.md`
2. Add the new skill to `agent/references/INDEX.md` and note it in the relevant Claude/Codex instructions
EOF
  } > "$AGENTS_OUT"
  perl -0pi -e 's/\n+\z/\n/' "$AGENTS_OUT"
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

Load and follow the complete operator instructions from `CLAUDE.md` in the project root.
This wrapper exists only so Claude Code can expose an `operator` agent entrypoint without duplicating prompt text.
EOF
    return
  fi

  cat > "$out" <<EOF
---
name: $agent_name
description: $description
---

You are $agent_name.

Load and follow the shared operator and rule guidance from \`CLAUDE.md\` in the project root.
Then load and follow your role instructions from \`agent/agents/$agent_name.md\`.
Use \`agent/SKILL.md\` to select the most relevant skill before improvising.
EOF
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

  cat > "$out" <<EOF
name = "$agent_name"
description = "$description"

developer_instructions = """
Load and follow the shared operator and rule guidance from AGENTS.md in the project root.
Then load and follow your role instructions from agent/agents/$agent_name.md.
Use agent/SKILL.md to select the most relevant skill before improvising.
"""
EOF
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
