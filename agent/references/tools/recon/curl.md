# curl

**Purpose:** HTTP request crafting and testing

For live target requests during an engagement, execute `curl` through the Kali MCP command-execution tool.
`curl` examples in this file are intended to be executed through the Kali MCP command-execution tool. Provide auth or cookie headers explicitly when the current task requires them.

For the current engagement target, use plain `curl` first. Only add explicit
`Cookie:` or `Authorization:` headers when intentionally testing alternate identities,
session confusion, or auth override behavior.

**Basic GET:** `curl -v https://target/`
**Headers only:** `curl -I https://target/`
**POST with data:** `curl -X POST -d "param=value" https://target/api`
**JSON POST:** `curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' https://target/api`
**Follow redirects:** `curl -L https://target/`
**Explicit cookie override:** `curl -H "Cookie: session=alternate-user" https://target/`
**Explicit auth override:** `curl -H "Authorization: Bearer override-token" https://target/api`
**Save output:** `-o output.html`
**Proxy through Burp:** `-x http://127.0.0.1:8080`
