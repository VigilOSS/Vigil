# Models and access

Vigil is built primarily around **Claude Code** and **Codex**.

| Model | Engagements |
|---|---|
| Claude Opus 5, with Anthropic's Cyber Verification Program (CVP) | Web and code |
| GPT-5.6 Sol, with OpenAI's Trusted Access for Cyber | Web and code |
| Claude Opus 5.5, GPT-6.1 Sol | Code; web needs an organization-only red-team tier |

- **Claude Code:** CVP works with Opus 5, which is not in the `/model` picker. Select it directly
  with `/model claude-opus-5[1m]` ([model configuration](https://code.claude.com/docs/en/model-config)).
- **Codex:** choose GPT-5.6 Sol and its reasoning effort in `/model`.

As of October 2026, red-team access to the newest models is for organizations only:

- **Anthropic:** CVP **Defense Access** is open to organizations and individual researchers;
  **Red Team Access** is organizations only ([CVP tiers](https://www.anthropic.com/news/cyber-verification-program)).
- **OpenAI:** **Daybreak Blue** covers defensive work for individuals and organizations;
  **Daybreak Red** is for approved organizations only
  ([access guidance](https://learn.chatgpt.com/docs/cyber-safety),
  [Daybreak overview](https://help.openai.com/en/articles/20001258-openai-daybreak-trusted-access-for-cyber-overview)).

goose, opencode, and Kimi run with reduced support; see
[`agent-clients.md`](agent-clients.md).

Planned: broader support for **GLM 5.3** and other models with more predictable access, through
lower orchestration overhead, model-specific prompts, and deeper **OpenCode** integration.

Return to the [quick start](../README.md#quick-start).
