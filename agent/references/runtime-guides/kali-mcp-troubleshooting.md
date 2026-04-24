# Kali MCP Troubleshooting

Use when MCP tool discovery returns no Kali tools or a previously working tool starts erroring.

## Diagnosis

1. Check local readiness and live service state: `aith doctor` and `aith status`
2. Verify the runtime container state: `aith runtime status`
3. Check MCP client registration: `aith mcp status`
4. If the MCP server is not registered, run `aith mcp install both` for the active workstation clients.
5. **MCP tools load at session startup.** If you registered the MCP server during this session, restart the session for tools to become available.
6. Restart the runtime if unhealthy: `aith runtime restart`
7. Inspect runtime logs when needed: `aith logs runtime --lines 120`

## Boundary

Host-side `docker` commands are for diagnostic inspection only (container status, logs, process lists) — target-facing work through `docker exec` bypasses the Kali MCP runtime's tool inventory and audit trail. If a required target-facing tool is missing from the active Kali MCP session, stop and resolve the runtime gap rather than falling back to host or Docker-side execution paths.
