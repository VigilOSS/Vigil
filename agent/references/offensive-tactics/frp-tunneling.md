# FRP Tunneling & OOB Callbacks

## Overview

frp (fast reverse proxy) is the primary tunnel tool for exposing local services to remote targets.
It is self-hosted — no data leaves your infrastructure, no account-scoped limitations, and multiple
simultaneous tunnels are supported. frp replaces ngrok for all engagement callback and listener
exposure needs.

Tunnels, listeners, and OOB callback servers are **OPERATOR-CONTROLLED shared infrastructure**.
Agents must never start them. The Kali runtime is shared across engagements — an agent starting
a tunnel on port 4444 could conflict with another engagement's tunnel.

**Agent responsibility:** provide exact commands in `# MANUAL:` playbook steps and reference this file.
**Operator responsibility:** execute the commands, record addresses in `$DIR/.listener_url` and/or
`$DIR/.oob_url`, then signal the agent to continue.

---

## Connection Details

| Setting | Value |
|---------|-------|
| Server | `server.com` |
| SSH gateway port | `2200` |
| User | `v0` |
| Token | `<TOKEN>` |

The frps server accepts SSH connections directly — use the `ssh` command as the frpc transport.
No separate `frpc` binary or config file is needed on the client side.

---

## Two Tunnel Modes

| Mode | Routing | Public endpoint | Key flags |
|------|---------|-----------------|-----------|
| `http` | By Host header (subdomain) | `https://<sd>.rp.example.com` | `--sd`, `--proxy_name` |
| `tcp` | By port | `server.com:<remote_port>` | `--remote_port`, `--proxy_name` |

**`--remote_port` is TCP-only.** HTTP tunnels route via subdomain, not port — using `--remote_port`
with `http` will error.

**`--sd` is HTTP-only.** Do not use it with `tcp` mode.

### How `-R` maps in each mode

```
ssh -R :<A>:127.0.0.1:<B> v0@server -p 2200 ...
         ^              ^
         |              └─ LOCAL_PORT: where traffic is forwarded on your machine
         |
         └─ ignored by frps for TCP (--remote_port controls the server-side port)
            ignored by frps for HTTP (vhostHTTPPort 8080 is always used)
```

The `-R` port (A) is cosmetic — frps does not use it. Only `127.0.0.1:<B>` (the local port) matters
from the `-R` argument. For clarity, examples set A = B for TCP tunnels and `:80:` for HTTP tunnels.

---

## Standard Engagement Tunnels

These tunnels cover the typical engagement needs. Each command runs inside a tmux session with
output logged via `tee` to `/data/` for LLM visibility.

### Overview

| Tunnel | Mode | Local port | Public endpoint | Purpose |
|--------|------|-----------|-----------------|---------|
| `oob-rev` | TCP | 4444 | `server.com:4444` | Reverse shell listener (pwncat) |
| `oob-dns` | TCP | 53 | `server.com:53` | OOB DNS callbacks (interactsh) |
| `oob` | HTTP | 80 | `https://oob.rp.example.com` | OOB HTTP/HTTPS callbacks (interactsh, callback server) |
| `relay` | TCP | 8080 | `server.com:8080` | HTTP relay / C2 / alt web service |
| `web-svc` | HTTP | 3000 | `https://app.rp.example.com` | Web service exposure (generic example) |

**Why HTTP mode for OOB HTTP callbacks?** Caddy terminates TLS automatically and provides a clean
`https://` URL. There is no need for a separate TCP tunnel on port 8443 — Caddy gives you HTTPS
on port 443 for free. Use a TCP tunnel on 8443 only if the target specifically requires that port
or you need raw TLS passthrough (see Alternative Tunnels below).

### Reverse shell listener (TCP, port 4444)

Exposes a local pwncat listener for catching reverse shells from remote targets.

```bash
docker exec -it security-research tmux new-session -d -s frp-oob-rev \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:4444 \
    v0@server.com -p 2200 \
    tcp \
    --proxy_name oob-rev \
    --remote_port 4444 \
    --token <TOKEN> 2>&1 | tee /data/frp-oob-rev.log'
```

Result: `server.com:4444` → `localhost:4444`

Record the address:
```bash
echo "server.com:4444" > "$DIR/.listener_url"
```

### OOB HTTPS callbacks (TCP, port 8443)

Exposes interactsh or a custom HTTPS callback receiver for blind vulnerability detection.

```bash
docker exec -it security-research tmux new-session -d -s frp-oob-https \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:8443 \
    v0@server.com -p 2200 \
    tcp \
    --proxy_name oob-https \
    --remote_port 8443 \
    --token <TOKEN> 2>&1 | tee /data/frp-oob-https.log'
```

Result: `server.com:8443` → `localhost:8443`

### OOB DNS callbacks (TCP, port 53)

Exposes interactsh DNS listener for blind DNS-based vulnerability detection (SSRF, XXE, log4shell).

```bash
docker exec -it security-research tmux new-session -d -s frp-oob-dns \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:53 \
    v0@server.com -p 2200 \
    tcp \
    --proxy_name oob-dns \
    --remote_port 53 \
    --token <TOKEN> 2>&1 | tee /data/frp-oob-dns.log'
```

Result: `server.com:53` → `localhost:53`

### OOB HTTP callbacks (HTTP mode, subdomain)

Exposes interactsh or the built-in callback server over HTTPS with automatic TLS via Caddy.
Use this when the target makes HTTP callbacks (blind SSRF, webhooks, XXE file fetch).

```bash
docker exec -it security-research tmux new-session -d -s frp-oob-http \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:80 \
    v0@server.com -p 2200 \
    http \
    --proxy_name oob \
    --sd oob \
    --token <TOKEN> 2>&1 | tee /data/frp-oob-http.log'
```

Result: `https://oob.rp.example.com` → `localhost:80`

Record the OOB URL:
```bash
echo "https://oob.rp.example.com" > "$DIR/.oob_url"
```

### Web service exposure (HTTP mode, subdomain)

Exposes a local web service (e.g., dev server on port 3000) over HTTPS with automatic TLS.

```bash
docker exec -it security-research tmux new-session -d -s frp-web-svc \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:3000 \
    v0@server.com -p 2200 \
    http \
    --proxy_name myapp \
    --sd myapp \
    --token <TOKEN> 2>&1 | tee /data/frp-web-svc.log'
```

Result: `https://myapp.rp.example.com` → `localhost:3000`

### Additional TCP relay (port 8080)

Generic TCP tunnel for a C2 HTTP listener, web proxy, alt web service, or SOCKS relay.

```bash
docker exec -it security-research tmux new-session -d -s frp-relay \
  'ssh -o StrictHostKeyChecking=accept-new \
    -R :80:127.0.0.1:8080 \
    v0@server.com -p 2200 \
    tcp \
    --proxy_name relay \
    --remote_port 8080 \
    --token <TOKEN> 2>&1 | tee /data/frp-relay.log'
```

Result: `server.com:8080` → `localhost:8080`

---

## interactsh Setup

interactsh detects blind vulnerabilities (SSRF, XXE, XSS, SQLi, log4shell) by running DNS and
HTTP/HTTPS listeners that record out-of-band callbacks from the target.

**NEVER use the public `oast.fun` / `oast.pro` server for engagement work.** OOB callbacks can
carry internal IPs, cloud metadata tokens, and credentials — sending those to third-party
infrastructure is a data leak.

### Self-hosted interactsh-server (remote targets)

When targets cannot reach the Kali runtime directly, run interactsh-server with the frp tunnels
above exposing DNS (53), HTTPS (8443), and HTTP (oob subdomain).

```bash
docker exec -it security-research tmux new-session -d -s oob-server \
  'interactsh-server -d server.com 2>&1 | tee /data/oob-server.log'
```

Then start the frp tunnels for `oob-dns` (port 53), `oob-https` (port 8443), and optionally
`oob-http` (HTTP mode) as shown in the Standard Engagement Tunnels section above.

Record the callback URL after provisioning:
```bash
echo "server.com" > "$DIR/.oob_url"
```

### interactsh-client polling mode (local/lab targets)

For local targets that can reach the Kali runtime directly, the client mode is simpler — it polls
a self-hosted or compatible server for callbacks without needing tunnels:

```bash
docker exec -it security-research tmux new-session -d -s oob-client \
  'interactsh-client 2>&1 | tee /data/oob-client.log'
```

The client prints a unique callback URL on startup. Record it:
```bash
# Read the URL from the log, then:
echo "CALLBACK_URL_FROM_LOG" > "$DIR/.oob_url"
```

### Checking for OOB callbacks

```bash
# Latest callbacks
docker exec security-research tail -50 /data/oob-client.log
docker exec security-research tail -50 /data/oob-server.log

# Live follow
docker exec security-research tail -f /data/oob-client.log
```

Agents check for callbacks by reading these log files via Kali MCP (see Logging section below).

---

## tmux Session Management

### Naming convention

Tunnel sessions: `frp-<tunnel-name>` (e.g., `frp-oob-rev`, `frp-oob-dns`)
OOB sessions: `oob-server`, `oob-client`
Shell sessions: `shell-<port>` or `shell-<tag>` (see `shell-handling.md`)

### Common commands

```bash
# List all active sessions
docker exec security-research tmux list-sessions

# Attach to a tunnel session (interactive — operator use only)
docker exec -it security-research tmux attach -t frp-oob-rev

# Kill a tunnel session when done
docker exec security-research tmux kill-session -t frp-oob-rev

# Kill all frp tunnel sessions
docker exec security-research tmux list-sessions -F '#{session_name}' \
  | grep '^frp-' | xargs -I{} docker exec security-research tmux kill-session -t {}
```

---

## Logging & Log Locations

All tunnel and OOB processes log to `/data/` inside the container via `tee`. The `/data/` directory
is the engagement volume mount point and persists across tmux restarts.

### Log file map

| Log file | Source | What it contains |
|----------|--------|-----------------|
| `/data/frp-oob-rev.log` | Reverse shell tunnel | SSH tunnel status, connection events |
| `/data/frp-oob-https.log` | OOB HTTPS tunnel | SSH tunnel status |
| `/data/frp-oob-dns.log` | OOB DNS tunnel | SSH tunnel status |
| `/data/frp-oob-http.log` | OOB HTTP tunnel | SSH tunnel status |
| `/data/frp-relay.log` | Additional TCP relay | SSH tunnel status |
| `/data/frp-web-svc.log` | Web service tunnel | SSH tunnel status |
| `/data/oob-client.log` | interactsh-client | **Callback hits — check here for OOB confirmation** |
| `/data/oob-server.log` | interactsh-server | **Callback hits — check here for OOB confirmation** |
| `/data/shell-*.log` | pwncat shell sessions | Shell I/O (see `shell-handling.md`) |

### How agents read logs (via Kali MCP)

Agents observe callback hits and tunnel status by reading log files through Kali MCP — never by
attaching to tmux sessions:

```bash
# Check for OOB callback hits (the primary confirmation source)
tail -50 /data/oob-client.log
tail -50 /data/oob-server.log

# Check tunnel health
tail -20 /data/frp-oob-rev.log

# Live follow (for monitoring during active exploitation)
tail -f /data/oob-client.log
```

**Agents confirming blind vulnerabilities** should check `/data/oob-client.log` or
`/data/oob-server.log` after sending payloads. A callback hit in the log is the OOB confirmation.

---

## Recording Tunnel Addresses

After starting tunnels, **always record the public addresses** so agents can use them in payloads
and playbooks:

```bash
# Reverse shell tunnel address
echo "server.com:4444" > "$DIR/.listener_url"

# OOB callback URL (for blind testing payloads)
echo "server.com" > "$DIR/.oob_url"
# Or for HTTP mode:
echo "https://oob.rp.example.com" > "$DIR/.oob_url"
```

**Files agents read (never write):**
- `$DIR/.listener_url` — tunnel address (`host:port`) for reverse shell payloads
- `$DIR/.oob_url` — callback URL for blind vulnerability detection payloads

Agents read `LISTENER_HOST`/`LISTENER_PORT` from `.listener_url` and the OOB callback domain/URL
from `.oob_url` in their dispatch context. They do not hardcode tunnel addresses.

---

## Docker Sidecar Pattern

When tunneling from inside a Docker container, replace `127.0.0.1` with the target service name:

```yaml
services:
  app:
    image: myimage
    # no ports exposed to host needed

  tunnel-http:
    image: alpine
    command: >
      sh -c "apk add --no-cache openssh-client &&
      ssh -o StrictHostKeyChecking=accept-new
      -R :80:app:80
      v0@server.com -p 2200
      http --proxy_name oob --sd oob
      --token <TOKEN>"
    depends_on: [app]

  tunnel-tcp:
    image: alpine
    command: >
      sh -c "apk add --no-cache openssh-client &&
      ssh -o StrictHostKeyChecking=accept-new
      -R :80:app:4444
      v0@server.com -p 2200
      tcp --proxy_name oob-rev --remote_port 4444
      --token <TOKEN>"
    depends_on: [app]
```

---

## Allowed Ports (AWS Security Group)

The `cal-example-operatoreng-sg` security group allows inbound TCP on:

| Port | Purpose |
|------|---------|
| 22 | SSH |
| 80 | Caddy HTTP / ACME |
| 443 | Caddy HTTPS (HTTP mode tunnels) |
| 2200 | frp SSH tunnel gateway |
| 7000 | frp bind (frpc fallback) |
| 53 | OOB DNS / interactsh |
| 4444 | Reverse shell listener |
| 8443 | OOB HTTPS / interactsh |

To expose a TCP tunnel on a new port, add an inbound rule:
```bash
aws ec2 authorize-security-group-ingress --profile vigiloss --region us-east-2 \
  --group-id sg-07c68edc29176ff97 \
  --protocol tcp --port <PORT> --cidr 0.0.0.0/0
```

---

## Notes

- **`--remote_port` is TCP-only.** Do not use it with `http` mode (it will error).
- **`--sd` is HTTP-only.** Do not use it with `tcp` mode.
- `-R` port is cosmetic — frps ignores it. Only `127.0.0.1:<LOCAL_PORT>` in `-R` matters.
- Any TCP port is allowed by frps (no server-side restriction). The AWS SG is the gatekeeper.
- Each `--proxy_name` must be unique across all active tunnels.
- HTTP tunnels get automatic TLS via Caddy's on-demand certificates.
- TCP tunnels are raw — no TLS termination. Use your own TLS if needed.
- Ctrl+C (or killing the tmux session) stops the tunnel.
- Ports 80/443 are used by Caddy — do not create TCP tunnels on these ports (use HTTP mode with `--sd` instead).
