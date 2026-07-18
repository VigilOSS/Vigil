# Vigil Skill Index (Deprecated Stub)

This file is a stub. The full ~400-line hand-maintained catalog it used to carry is retired —
it drifted from the live skill roster (missing skills, stale "Paired references" lists) and
duplicated what the CLI already derives from disk.

**Discovery is self-registering.** Skills and references declare themselves via frontmatter;
there is no index to hand-update when a skill is added or renamed.

- **Pick a skill:** `vigil assess list-skills` — compact `name` + one-line "Use when:" for every
  skill under `agent/skills/`, generated live from each `SKILL.md`'s frontmatter + "When to
  Activate" section.
- **Find a skill's paired references:** `vigil assess list-references --skill <name>` — the
  reference library (`agent/references/`) is also self-registering; each reference declares its
  paired skill(s) in its own frontmatter.
- **Read the methodology:** load `agent/skills/<name>/SKILL.md` directly. Every skill's own
  `## Extended Resources` section (bottom of the file) names its paired references and any
  sibling skills it hands off to — that per-skill list is authoritative, not this file.

This stub is kept on disk (not deleted) only because install/bootstrap tooling copies it as
part of the agent-prompt fixture set; it carries no operator-facing content otherwise.
