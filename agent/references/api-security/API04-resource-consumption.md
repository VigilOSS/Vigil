# API4:2023 — Unrestricted Resource Consumption

- Test rate limiting on all endpoints
- Send oversized payloads, excessive query parameters
- Test pagination limits: request page_size=999999
- Check for missing timeout on long-running operations
- Note: this is an availability problem. Validate it safely within the authorized realistic lab scope and treat service exhaustion signals as reportable findings.
