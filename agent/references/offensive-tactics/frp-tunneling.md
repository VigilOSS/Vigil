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
The public URL is `https://<subdomain>.researcher.example`.

**TCP/UDP tunnels** bypass Caddy entirely. frps opens the port directly on the server.
The public endpoint is `researcher.example:<port>`.

---

## Prerequisites (one-time setup)

### DNS delegation for OOB callbacks

Add an NS record in your DNS provider for `researcher.example`:

| Type | Name | Value |
|------|------|-------|
| NS | `oob.rp` | `researcher.example` |

This delegates `*.researcher.example` to your frp server so DNS callbacks from targets
reach interactsh-server via the UDP 53 tunnel. Without this, DNS queries are answered by the
normal authoritative DNS (wildcard A record) and never reach interactsh.

### AWS Security Group

The `cal-example-sg` security group must allow:

| Port | Protocol | Purpose |
|------|----------|---------|
| 7000 | TCP | frpc → frps bind port |
| 53 | **UDP** | OOB DNS callbacks (interactsh) |
| 4444 | TCP | Reverse shell listener |
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

```bash
docker exec security-research bash -c 'cat > /data/frpc.toml << "FRPEOF"
serverAddr = "researcher.example"
serverPort = 7000
auth.token = "<TOKEN>"

# OOB DNS — primary callback mechanism (UDP, port 53)
# Requires NS record: oob.rp NS researcher.example
[[proxies]]
name = "oob-dns"
type = "udp"
localIP = "127.0.0.1"
localPort = 53
remotePort = 53

# OOB HTTP — interactsh client polling + HTTP callbacks via Caddy
[[proxies]]
name = "oob"
type = "http"
localIP = "127.0.0.1"
localPort = 80
subdomain = "oob"

# As needed
# # Reverse shell listener (TCP, port 4444)
# [[proxies]]
# name = "oob-rev"
# type = "tcp"
# localIP = "127.0.0.1"
# localPort = 4444
# remotePort = 4444
# FRPEOF'
```

Add more proxies as needed:
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
echo "researcher.example:4444" > "$DIR/.listener_url"
echo "researcher.example" > "$DIR/.oob_url"
```

---

## Standard Tunnels

| Tunnel | Type | Local port | Public endpoint | Purpose |
|--------|------|-----------|-----------------|---------|
| `oob-dns` | UDP | 53 | `researcher.example:53` | **Primary OOB** — DNS callbacks (interactsh) |
| `oob` | HTTP | 80 | `https://researcher.example` | interactsh client polling + HTTP callbacks |
| `oob-rev` | TCP | 4444 | `researcher.example:4444` | Reverse shell listener (pwncat) |

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

Use `-skip-acme` — Caddy handles TLS for the HTTP tunnel. interactsh does not need its own certs.

```bash
docker exec -it security-research tmux new-session -d -s oob-server \
  'interactsh-server -d researcher.example -skip-acme 2>&1 | tee /data/oob-server.log'
```

interactsh-server listens on DNS (UDP 53) and HTTP (TCP 80). The frpc tunnels expose both.

### Full startup sequence

```bash
# 1. Start interactsh-server
docker exec -it security-research tmux new-session -d -s oob-server \
  'interactsh-server -d researcher.example -skip-acme 2>&1 | tee /data/oob-server.log'

# 2. Wait for server to initialize
sleep 3

# 3. Start all frp tunnels (DNS + HTTP + reverse shell)
docker exec -it security-research tmux new-session -d -s frpc \
  'frpc -c /data/frpc.toml 2>&1 | tee /data/frpc.log'

# 4. Record OOB URL for agents
echo "researcher.example" > "$DIR/.oob_url"
```

### Verifying OOB works

```bash
# From any machine, trigger a DNS callback:
dig researcher.example @8.8.8.8

# Check if interactsh recorded it:
docker exec security-research tail -20 /data/oob-server.log
# Should show: "Received DNS interaction (A) from ..."
```

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
| `/data/frpc.log` | frpc (all tunnels) | Tunnel registration, connection status, errors |
| `/data/oob-server.log` | interactsh-server | **Callback hits — check here for OOB confirmation** |
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
