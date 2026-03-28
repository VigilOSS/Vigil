# XR Kali Threat Hunt

Kali container for MCP-driven tooling with request/response rewriting at the MCP boundary.

## What It Does

- Runs a Python MCP proxy in front of the Kali `mcp-server`.
- Rewrites all MCP tool inputs before execution.
- Rewrites all MCP tool outputs before they are returned to the agent.
- Keeps the container alive by default so an agent can attach over MCP with stdio.

This gives you:

- deterministic transforms for all Kali MCP tool calls such as `nmap_scan`, `gobuster_scan`, and `execute_command`
- the same transform path for shell commands and MCP-invoked tools inside the container

## Quick Start

Build the image:

```bash
docker build -t security-research .
```

Start it with the MCP rewrite rules:

```bash
docker run -d \
  --name security-research \
  --cap-add=NET_RAW \
  -e MCP_TRANSFORM_OUTBOUND_FIND='abc/' \
  -e MCP_TRANSFORM_OUTBOUND_REPLACE='changed-abc/' \
  -e MCP_TRANSFORM_INBOUND_FIND='result-abc/' \
  -e MCP_TRANSFORM_INBOUND_REPLACE='changed-result-abc/' \
  security-research
```

Point your agent at:

```bash
docker exec -i security-research mcp-server
```

## Config

- `MCP_TRANSFORM_OUTBOUND_FIND`: string to replace in Kali MCP tool inputs
- `MCP_TRANSFORM_OUTBOUND_REPLACE`: replacement applied before the tool runs
- `MCP_TRANSFORM_INBOUND_FIND`: string to replace in Kali MCP tool outputs
- `MCP_TRANSFORM_INBOUND_REPLACE`: replacement applied before the result is returned

## Build

Fast local build when you already have a preloaded Kali base image:

```bash
docker buildx build --load \
  --build-arg BASE_IMAGE=redteam-allinone:latest \
  --build-arg PRELOADED_TOOLS=1 \
  -t security-research:test .
```

Full Kali build:

```bash
docker build -t security-research .
```

The fast local build was the path used for iterative testing here. The full build is the portable path and may take much longer because it performs a Kali upgrade and installs extra tooling.

## Verify

MCP request/response rewrite:

```bash
docker exec -i security-research python3 - <<'PY'
import anyio
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp import ClientSession

async def main():
    env = {
        "MCP_TRANSFORM_OUTBOUND_FIND": "Acme",
        "MCP_TRANSFORM_OUTBOUND_REPLACE": "ZEDVALUE",
        "MCP_TRANSFORM_INBOUND_FIND": "RESULTTOKEN",
        "MCP_TRANSFORM_INBOUND_REPLACE": "ChangedResult",
    }
    params = StdioServerParameters(command="mcp-server", args=[], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            req = await session.call_tool("execute_command", {
                "command": "python3 -c \"import sys; print('req-ok' if sys.argv[1] == 'ZEDVALUE' else 'req-miss')\" Acme"
            })
            resp = await session.call_tool("execute_command", {"command": "printf RESULTTOKEN"})
            print(req.structuredContent)
            print(resp.structuredContent)

anyio.run(main)
PY
```

Named tool argument rewrite:

```bash
docker exec -i security-research python3 - <<'PY'
import anyio
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp import ClientSession

async def main():
    env = {
        "MCP_TRANSFORM_OUTBOUND_FIND": "-sn",
        "MCP_TRANSFORM_OUTBOUND_REPLACE": "--definitely-not-a-real-option",
    }
    params = StdioServerParameters(command="mcp-server", args=[], env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool("nmap_scan", {
                "target": "127.0.0.1",
                "scan_type": "-sn",
                "ports": "",
                "additional_args": "",
            })
            print(result.structuredContent)

anyio.run(main)
PY
```

Health:

```bash
docker ps
docker inspect --format '{{json .State.Health}}' security-research
```

## Notes

- The MCP proxy lives in [`docker/mcp_transform_proxy.py`](/path/to/vigil).
- The fixed API shim for named Kali tools lives in [`docker/patched_kali_server.py`](/path/to/vigil).
- The container stays alive with `tini` and `sleep infinity`; the MCP server is started on demand through `docker exec -i ... mcp-server`.
- If you need the full Kali toolset, build without `PRELOADED_TOOLS=1`.
