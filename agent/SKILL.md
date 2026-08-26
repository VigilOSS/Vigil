# Vigil Skill Index

Skills and references are self-registering — they declare themselves through their own
frontmatter, so there is no index to hand-update when one is added or renamed. Use the CLI to
discover them:

- **Pick a skill:** `vigil assess list-skills` — compact `name` + one-line "Use when:" for every
  skill under `agent/skills/`, generated live from each `SKILL.md`'s frontmatter and its
  "When to Activate" section.
- **Find a skill's paired references:** `vigil assess list-references --skill <name>` — the
  reference library (`agent/references/`) is self-registering the same way; each reference names
  its paired skill(s) in its own frontmatter.
- **Read the methodology:** load `agent/skills/<name>/SKILL.md` directly. Each skill's own
  `## Extended Resources` section names the references it pairs with and the sibling skills it
  hands off to; that per-skill list is the authoritative one.

This file carries no operator-facing content — it exists because install and bootstrap tooling
copies it as part of the agent-prompt fixture set.
