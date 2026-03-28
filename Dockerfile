ARG BASE_IMAGE=kalilinux/kali-rolling
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0

# Install the MCP runtime dependencies.
# In PRELOADED_TOOLS=1 mode, only install packages that are actually missing from the base image.
RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -y; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      apt full-upgrade -y; \
      apt-get install -y kali-linux-default wget rlwrap; \
      base_packages='ca-certificates curl mcp-kali-server python3 python3-pip sudo tini wget rlwrap'; \
    else \
      base_packages=''; \
      for pkg in ca-certificates curl mcp-kali-server python3 python3-pip sudo tini wget rlwrap; do \
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
    ; fi && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install nuclei (not in Kali repos)
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      GOPATH=/root/go go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
      cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
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

# NGROK
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc | tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null && \
      echo "deb https://ngrok-agent.s3.amazonaws.com buster main" | tee /etc/apt/sources.list.d/ngrok.list && \
      apt update && apt install -y ngrok && \
      ngrok config add-authtoken REPLACE_WITH_YOUR_OWN_TOKEN; \
    fi

# Fix mcp-server to start the Kali API server before the MCP server.
COPY docker/mcp-server-wrapper.sh /usr/bin/mcp-server
RUN chmod +x /usr/bin/mcp-server

RUN mkdir -p /opt/mcp-tools
COPY docker/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
COPY docker/mcp_transform_proxy.py /opt/mcp-tools/mcp_transform_proxy.py

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
  CMD command -v mcp-server >/dev/null && test -f /opt/mcp-tools/mcp_transform_proxy.py || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "sleep infinity"]
