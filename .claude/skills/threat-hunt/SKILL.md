---
name: threat-hunt
description: Bootstrap the security-research repo for an engagement, attach the Kali MCP runtime for Claude Code or Codex, and then hand off to the repo-native agent/orchestrator workflow.
argument-hint: [target-domain]
---

# Threat Hunt Bootstrap

This repository already absorbed the detailed methodology, reporting, and coverage model that used to live in the standalone threat-hunt skill. Do not create a separate `state.md` / `assets.json` flow here.

Use this skill only to:
- verify the Kali MCP runtime is available
- tell the user the exact Claude Code or Codex MCP attach command
- initialize a new engagement in this repo
- point the user back to the repo-native workflow

## Kali MCP Runtime

Build the runtime image from the repo root:

```bash
docker build -t security-research:latest .
```

Run the container with the capabilities needed by raw network tools:

```bash
docker run -d \
  --name security-research \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  security-research:latest
```

Optional lightweight local-validation image:

```bash
docker build -t security-research-lightweight:latest \
  -f agent/docker/kali-redteam-lightweight/Dockerfile .
```

Use the lightweight image only for faster local iteration. The primary workflow uses the root `Dockerfile`.

## MCP Registration

If the user is using Claude Code, tell them to run:

```bash
claude mcp add kali -s user -- docker exec -i security-research mcp-server
```

If the user is using Codex, tell them to run:

```bash
codex mcp add kali -- docker exec -i security-research mcp-server
```

Optional `context7` registration:

```bash
claude mcp add context7 -s user -- npx -y @upstash/context7-mcp
codex mcp add context7 -- npx -y @upstash/context7-mcp
```

After registration:
- Claude Code can invoke the Kali MCP tools directly once the CLI is restarted.
- Codex can invoke the Kali MCP tools directly once the server is added to the Codex MCP registry.

## Engagement Initialization

Initialize a new engagement from the repo root:

```bash
cd agent
./scripts/init_engagement.sh ${ARGUMENTS:-https://example.com}
```

Useful variants:

```bash
./scripts/init_engagement.sh https://target.example --auto
./scripts/init_engagement.sh https://target.example --parallel 6
```

This creates the engagement workspace under `agent/engagements/` and seeds:
- `scope.json`
- `log.md`
- `findings.md`
- `intel.md`
- `intel-secrets.json`
- `auth.json`
- `cases.db`

## Callback and Ngrok

The callback helper is agent-usable once the runtime container is running. Claude Code or Codex can invoke it through the same runtime after MCP registration.

Local callback listener:

```bash
docker exec -it security-research start-callback
```

Ngrok-backed callback listener:

```bash
docker exec -e USE_NGROK=1 \
  -e NGROK_AUTHTOKEN="$NGROK_AUTHTOKEN" \
  -e CALLBACK_PORT=8000 \
  -it security-research start-callback
```

Guidance:
- `NGROK_AUTHTOKEN` is optional and should be provided at runtime or per engagement, not baked into the image.
- Do not require ngrok for every engagement. Only use it when an external callback URL is needed for SSRF, blind RCE, webhook, or similar testing.
- If the token is present in the container environment, Claude Code or Codex can start the listener path themselves. If it is not present, the user must provide it first.

## Repo-Native Workflow

After setup, use the repository’s native workflow instead of the old standalone skill flow:
- operator guidance: `agent/CLAUDE.md` and `agent/AGENTS.md`
- engagement methodology: `agent/references/runtime-guides/engagement-methodology.md`
- orchestrator backend/frontend: `orchestrator/`
- runtime helpers: `docker/` and `agent/scripts/lib/container.sh`
- assessment ledger and coverage APIs: `orchestrator/backend/app/services/assessment.py`
- optional Athena log review: `agent/skills/athena-log-investigation/SKILL.md`

If detailed methodology is needed during the engagement, use the repo’s integrated agent prompts, skills, and references rather than resurrecting the old standalone threat-hunt templates.
