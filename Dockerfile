ARG BASE_IMAGE=kalilinux/kali-rolling
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0

ENV PATH="/opt/Responder:${PATH}"
ENV KALI_MCP_CLIENT_PATH=/usr/share/mcp-kali-server/client.py

# Install the MCP runtime dependencies.
# In PRELOADED_TOOLS=1 mode, only install packages that are actually missing from the base image.
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -y; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      apt full-upgrade -y; \
      apt-get install -y kali-linux-default wget rlwrap; \
      base_packages='ca-certificates curl jq sqlite3 git ripgrep dnsutils whois openssl netcat-openbsd procps lsof python3 python3-pip python3-aiohttp sudo tini wget rlwrap mcp-kali-server'; \
    else \
      base_packages=''; \
      for pkg in ca-certificates curl jq sqlite3 git ripgrep dnsutils whois openssl netcat-openbsd procps lsof python3 python3-pip python3-aiohttp sudo tini wget rlwrap mcp-kali-server; do \
        dpkg -s "$pkg" >/dev/null 2>&1 || base_packages="$base_packages $pkg"; \
      done; \
    fi; \
    if [ -n "$(printf '%s' "$base_packages" | tr -d ' ')" ]; then \
      apt-get install -y $base_packages; \
    fi; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install additional threat-hunting tools not included in kali-linux-default
RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    if [ "$PRELOADED_TOOLS" != "1" ]; then apt-get install -y \
    subfinder \
    sublist3r \
    testssl.sh \
    golang-go \
    chromium \
    chromium-driver \
    nikto \
    whatweb \
    ffuf \
    gobuster \
    wfuzz \
    dirb \
    sqlmap \
    hydra \
    john \
    hashcat \
    ruby-full \
    proxychains-ng \
    openssh-client \
    socat \
    tcpdump \
    ; fi && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install nuclei, Katana, and optional tooling not in Kali repos.
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/mitmproxy-venv && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir --upgrade pip && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir mitmproxy && \
      ln -sf /opt/mitmproxy-venv/bin/mitmdump /usr/local/bin/mitmdump && \
      ln -sf /opt/mitmproxy-venv/bin/mitmproxy /usr/local/bin/mitmproxy && \
      gem install evil-winrm --no-document && \
      git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder && \
      python3 -m pip install --no-cache-dir --break-system-packages impacket==0.13.0 mitm6 dpapick3 aioquic flask && \
      curl -fsSL "https://github.com/jpillora/chisel/releases/download/v1.11.4/chisel_1.11.4_linux_amd64.gz" | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel && \
      mkdir -p /tmp/ligolo && \
      curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz" | tar xzf - -C /tmp/ligolo && \
      find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
      chmod +x /usr/local/bin/ligolo-proxy && \
      rm -rf /tmp/ligolo && \
      GOPATH=/root/go go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
      cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
      GO111MODULE=on GOPATH=/root/go go install github.com/projectdiscovery/katana/cmd/katana@latest && \
      cp /root/go/bin/katana /usr/local/bin/katana && \
      rm -rf /root/go; \
    fi

# Pre-download amass data to avoid ~800MB download timeout on first run
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /root/.config/amass && \
      timeout 120 amass enum --list 2>/dev/null; exit 0; \
    fi

# Seclists
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && \
      unzip SecList.zip && rm -f SecList.zip && \
      mv SecLists-master /usr/share/wordlists/SecLists; \
    fi

# NGROK is optional for callbacks; configure it with NGROK_AUTHTOKEN at runtime.
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && \
      echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | tee /etc/apt/sources.list.d/ngrok.list && \
      apt update && apt install -y ngrok; \
    fi

# Fix mcp-server to start the Kali API server before the MCP server.
COPY docker/kali-mcp-runtime/mcp-server-wrapper.sh /usr/bin/mcp-server
RUN chmod +x /usr/bin/mcp-server

RUN mkdir -p /opt/mcp-tools
RUN mkdir -p /data
COPY docker/kali-mcp-runtime/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
COPY docker/kali-mcp-runtime/mcp_transform_proxy.py /opt/mcp-tools/mcp_transform_proxy.py
COPY docker/callback_listener.py /opt/mcp-tools/callback_listener.py
COPY docker/start-callback.sh /usr/local/bin/start-callback
RUN chmod +x /usr/local/bin/start-callback

# =============================================================================
# IMPORTANT: nmap requires NET_RAW and NET_ADMIN capabilities to perform
# SYN scans, OS detection, and raw packet operations. Run this container with:
#
#   docker run -it --cap-add=NET_RAW --cap-add=NET_ADMIN <image>
#
# Without these flags, nmap will fail with "Operation not permitted".
# For full nmap functionality (OS detection, traceroute), you can also use:
#
#   docker run -it --privileged <image>
#
# =============================================================================

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD command -v mcp-server >/dev/null && command -v katana >/dev/null && test -f /opt/mcp-tools/mcp_transform_proxy.py || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "sleep infinity"]
