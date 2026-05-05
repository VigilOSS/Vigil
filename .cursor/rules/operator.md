---
description: Operator prompt locality — always load agent/AGENTS.md, never duplicate it
globs:
  - "**/*"
alwaysApply: true
---

# Operator Prompt Locality

The canonical operator prompt for this repo lives at `agent/AGENTS.md`.

When picking which workspace files to attach to context, follow these rules
so the same ~16.5k-token operator prompt is not loaded multiple times per
turn:

- **Load `agent/AGENTS.md`** — it is the single source of truth for the
  operator loop, dispatch rules, recording rules, and backend-vs-artifact
  truth boundaries.
- **Do not also load `agent/CLAUDE.md`** — it is a thin pointer to
  `agent/AGENTS.md`. Loading both wastes context tokens.
- **Do not load the root `AGENTS.md`** unless the task is contributor /
  maintainer work (CODE-MAP maintenance, prompt regeneration, schema
  regeneration). The root `AGENTS.md` is a maintainer workflow document,
  not the operator prompt.
- **Per-engagement `CLAUDE.md` / `AGENTS.md` wrappers** under
  `agent/engagements/<key>/` are pointers, not duplicates — loading them is
  fine but they only add a few hundred tokens of bootstrap context.

Skill discovery: prefer `aith assess list-skills` (compact name + one-line
"Use when") over reading `agent/SKILL.md` directly. The index file is
retained as a human-readable reference but is no longer the authoritative
discovery surface for operators or specialists.
