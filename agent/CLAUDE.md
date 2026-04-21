# AI Threat Hunting — Claude Code Entry

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
║   Powered by Claude Code  ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

When a session starts, display the banner above and then:
"[operator] AI Threat Hunting ready. Ensure `./agent/scripts/start_kali_mcp_runtime.sh` is running, then use `cd agent && ./scripts/init_engagement.sh <target_url>` to start a new engagement."

---

<!-- Generated from operator-core.md via scripts/render-operator-prompts.sh -->

## Load Full Operator Instructions

**Load and follow all instructions from `AGENTS.md` in this directory.**

`AGENTS.md` is the single source of truth for operator methodology, agent
roster, phase flow, finding format, skills, references, and Kali MCP rules.
Every instruction there applies verbatim to a Claude Code session.

This file (`CLAUDE.md`) exists so Claude Code has a default entry point and
can attach the Claude-specific dispatch syntax below without duplicating the
~700 lines of shared instructions that belong in `AGENTS.md`.

## Claude Dispatch Syntax

Use `@agent-name` when dispatching subagents (Claude Code–specific — Codex
uses its own `.codex/agents/*.toml` wrappers instead):

- `@recon-specialist`
- `@source-analyzer`
- `@surface-collector`
- `@vulnerability-analyst`
- `@exploit-developer`
- `@fuzzer`
- `@osint-analyst`
- `@report-writer`
- `@code-architect`
- `@code-vuln-hunter`
- `@code-variant-hunter`
- `@code-vuln-verifier`
