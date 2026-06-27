---
description: "Mitmproxy session capture: setup, CA cert install, FoxyProxy config, login capture workflow, troubleshooting"
---

# Mitmproxy Session Capture

Intercept browser traffic to capture authenticated sessions (cookies, tokens, headers) into the engagement's backend credential store for use by engagement agents.

## Quick Start

```bash
vigil engagement list --json
vigil mitmproxy start <engagement-key>
```

## Browser Proxy Setup (FoxyProxy)

1. Install FoxyProxy browser extension
2. Add a new proxy:
   - **Type: HTTP** (not HTTPS -- this is the most common mistake)
   - **Host:** `127.0.0.1`
   - **Port:** `8080`
   - Do NOT set anything in the HTTPS/SSL proxy field
3. Enable the proxy profile

**Why HTTP, not HTTPS?** The browser sends a plaintext HTTP `CONNECT` request to the proxy, which then handles TLS interception internally. Setting the proxy type to HTTPS double-wraps TLS around the CONNECT tunnel, which breaks mitmproxy's interception.

## CA Certificate Installation (First Time Only)

The CA cert must be trusted by your browser/OS for HTTPS interception to work.

### Option A: Browser Install

1. With the proxy active, navigate to **http://mitm.it** (note: **http**, not https)
2. If the page says "traffic is not passing through mitmproxy" -- verify FoxyProxy is set to HTTP mode
3. Download the macOS certificate
4. Open **Keychain Access** > search `mitmproxy`
5. Double-click the cert > expand **Trust** > set to **Always Trust**
6. **Quit and reopen your browser** (browsers cache cert decisions per session)

### Option B: Terminal Install

```bash
docker cp vigil-proxy:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem
```

`vigil mitmproxy cert` prints the same commands for the active Docker-managed proxy.

Restart the browser after trusting.

### CA Key Persistence

The launcher stores CA keys in a named Docker volume (`mitmproxy-ca`). Container restarts and rebuilds reuse the same CA keys, so you only need to install and trust the certificate once.

If you need to regenerate the CA (e.g., compromise, rotation):
```bash
docker volume rm mitmproxy-ca
vigil engagement list --json
vigil mitmproxy start <engagement-key>
# Re-install the new cert using Option A or B above
```

## Login Capture Workflow

1. List engagements and start the proxy explicitly: `vigil engagement list --json` then `vigil mitmproxy start <engagement-key>`
2. Configure browser proxy (see above)
3. Navigate to the target login page and authenticate
4. Browse a few authenticated pages (admin, settings, API endpoints)
5. The proxy addon auto-detects login flows and POSTs the captured cookies/tokens to the engagement's backend credential store (the `default` identity)
6. Disable the proxy in FoxyProxy when done

If auto-capture misses the session (addon error, non-standard login flow):
- Check proxy logs: `vigil logs mitmproxy --lines 30`
- Fall back to manual cookie extraction from browser DevTools

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `http://mitm.it` says "traffic not passing through mitmproxy" | FoxyProxy is set to HTTPS mode -- change to HTTP |
| Certificate errors after proxy restart | Check if the `mitmproxy-ca` volume exists: `docker volume ls \| grep mitmproxy`. If missing, the CA was regenerated -- re-install the cert |
| Proxy container exits immediately | Check logs: `vigil logs mitmproxy --lines 20`. Common: port 8080 already in use |
| Credentials not updated after login (`vigil auth status` still anonymous) | Check for addon errors in logs. The `_detect_login` function looks for `set-cookie` headers and token fields in response bodies |
| Browser still shows cert errors after trusting | Quit browser fully and reopen. macOS may also need: System Settings > Network > clear DNS cache |

## Container Management

```bash
# Status
vigil mitmproxy status

# Logs
vigil logs mitmproxy --lines 80

# Stop
vigil mitmproxy stop

# Restart (reuses same CA cert from volume)
vigil mitmproxy start <engagement-key>

# Custom port
vigil mitmproxy start <engagement-key> --port 9090
```

## How It Works

The proxy runs `mitmdump` with `proxy_addon.py`, which:
- Filters noise (analytics, CDNs, tracking pixels)
- Classifies requests by type (API, form, page, JS, GraphQL, WebSocket, etc.)
- Detects login flows and POSTs captured session material to the backend credential store
- Records intercepted traffic to `cases.db` for work-buffer ingestion
- Posts request observations to the orchestrator backend (when available)
