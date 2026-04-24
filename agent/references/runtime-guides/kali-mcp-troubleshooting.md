# Kali MCP Troubleshooting

Use when MCP tool discovery returns no Kali tools or a previously working tool starts erroring.

## Diagnosis

1. Verify the runtime container is running: `docker ps --filter name=security-research`
2. Verify the MCP server process inside the container: `docker exec security-research pgrep -f mcp-server`
3. Check MCP client registration: `claude mcp list` (Claude) or `codex mcp list` (Codex)
4. If the MCP server is not registered, print the registration commands with `aith mcp install both`, then run the command for the active client.
5. **MCP tools load at session startup.** If you registered the MCP server during this session, restart the session for tools to become available.
6. Restart the runtime if unhealthy: `aith runtime restart`

## Boundary

Host-side `docker` commands are for diagnostic inspection only (container status, logs, process lists) — target-facing work through `docker exec` bypasses the Kali MCP runtime's tool inventory and audit trail. If a required target-facing tool is missing from the active Kali MCP session, stop and resolve the runtime gap rather than falling back to host or Docker-side execution paths.
