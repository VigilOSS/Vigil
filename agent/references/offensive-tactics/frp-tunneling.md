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
Internet → oob-relay.example.com:<port> (TCP/UDP) → frps → frpc ───┘
```

**HTTP mode tunnels** go through Caddy, which terminates TLS and proxies to frps by Host header.
The public URL is `https://<subdomain>.rp.example.com`.

**TCP/UDP tunnels** bypass Caddy entirely. frps opens the port directly on the server.
The public endpoint is `oob-relay.example.com:<port>`.

---

## Prerequisites (one-time setup)

### DNS record for OOB callbacks

One NS record is required in your DNS provider for `example.com`:

| Type | Name | Value | Purpose |
|------|------|-------|---------|
| **NS** | `oob` | `oob-relay.example.com` | Delegates `*.oob.example.com` to your frp server so DNS and HTTP callbacks reach interactsh via the tunnels |

The wildcard A record on `*.rp.example.com` already routes HTTP traffic to the frp server
through Caddy. The NS delegation routes DNS queries to interactsh's DNS listener (UDP 53 tunnel).
interactsh-server handles A-record responses for its own domain via the `-ip` flag (set to the
frp server's public IP) — see the startup command below.

**Do NOT add an A record at `oob.example.com`.** Route53 treats the NS record as a
delegation zone cut — an A record at the same name is shadowed and never returned to resolvers.

### AWS Security Group

The `cal-example-operatoreng-sg` security group must allow:

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

```bash
docker exec security-research bash -c '
CONTAINER_IP=$(hostname -i | awk "{print \$1}")
cat > /data/frpc.toml << FRPEOF
serverAddr = "oob-relay.example.com"
serverPort = 7000
auth.token = "<TOKEN>"

# OOB DNS — primary callback mechanism (UDP, port 53)
# Requires NS record: oob NS oob-relay.example.com
[[proxies]]
name = "oob-dns"
type = "udp"
localIP = "${CONTAINER_IP}"
localPort = 53
remotePort = 53

# OOB HTTP — interactsh client polling + callback subdomains via Caddy
[[proxies]]
name = "oob"
type = "http"
localIP = "${CONTAINER_IP}"
localPort = 80
customDomains = ["oob.example.com", "*.oob.example.com"]

# Reverse shell listener (TCP, port 4444)
[[proxies]]
name = "oob-rev"
type = "tcp"
localIP = "${CONTAINER_IP}"
localPort = 4444
remotePort = 8443
FRPEOF
echo "[frpc] localIP set to ${CONTAINER_IP}"
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
# Result: https://myapp.rp.example.com → localhost:3000
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
echo "oob-relay.example.com:8443" > "$DIR/.listener_url"
echo "oob.example.com" > "$DIR/.oob_url"
```

---

## Standard Tunnels

| Tunnel | Type | Local port | Public endpoint | Purpose |
|--------|------|-----------|-----------------|---------|
| `oob-dns` | UDP | 53 | `oob-relay.example.com:53` | **Primary OOB** — DNS callbacks (interactsh) |
| `oob` | HTTP | 80 | `https://oob.example.com` + `https://*.oob.example.com` | interactsh client polling + HTTP callbacks |
| `oob-rev` | TCP | 4444 | `oob-relay.example.com:8443` | Reverse shell listener (pwncat) |

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

The command resolves the server IP dynamically from `oob-relay.example.com`:

```bash
docker exec -it security-research tmux new-session -d -s oob-server \
  "SERVER_IP=\$(dig +short oob-relay.example.com A | head -1) && \
   interactsh-server -d oob.example.com -listen-ip 0.0.0.0 -ip \$SERVER_IP -skip-acme -v -debug 2>&1 | tee /data/oob-server.log"
```

interactsh-server listens on DNS (UDP 53) and HTTP (TCP 80). The frpc tunnels expose both.

### Full startup sequence

```bash
# 1. Start interactsh-server (resolve server IP dynamically)
docker exec -it security-research tmux new-session -d -s oob-server \
  "SERVER_IP=\$(dig +short oob-relay.example.com A | head -1) && \
   interactsh-server -d oob.example.com -listen-ip 0.0.0.0 -ip \$SERVER_IP -skip-acme -v -debug 2>&1 | tee /data/oob-server.log"

# 2. Wait for server to initialize
sleep 3

# 3. Start all frp tunnels (DNS + HTTP + reverse shell)
docker exec -it security-research tmux new-session -d -s frpc \
  'frpc -c /data/frpc.toml 2>&1 | tee /data/frpc.log'

# 4. Record OOB URL for agents
echo "oob.example.com" > "$DIR/.oob_url"
```

### Verifying OOB works

```bash
# DNS callback (from any machine):
dig test123.oob.example.com @8.8.8.8

# HTTP callback (from target or any machine):
curl http://oob.example.com/ssrf-test-$(date +%s)

# DNS-only callback (subdomain-based, for blind SSRF/XXE/SQLi):
curl http://ssrf-test-$(date +%s).oob.example.com

# Check if interactsh recorded it:
docker exec security-research tail -20 /data/oob-server.log
# Should show lines like: "[INF] Received DNS interaction (A) from ..."
# With -v -debug, every interaction is logged with full details.
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
