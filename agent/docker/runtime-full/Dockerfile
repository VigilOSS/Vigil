ARG BASE_IMAGE=kalilinux/kali-rolling
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0

ENV PATH="/opt/Responder:${PATH}"
ENV KALI_MCP_CLIENT_PATH=/usr/share/mcp-kali-server/client.py

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -y; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      apt full-upgrade -y; \
      apt-get install -y kali-linux-default wget rlwrap; \
      base_packages='ca-certificates curl jq sqlite3 git ripgrep dnsutils whois openssl netcat-openbsd procps lsof python3 python3-pip python3-aiohttp sudo tini wget rlwrap unzip mcp-kali-server'; \
    else \
      base_packages=''; \
      for pkg in ca-certificates curl jq sqlite3 git ripgrep dnsutils whois openssl netcat-openbsd procps lsof python3 python3-pip python3-aiohttp sudo tini wget rlwrap unzip mcp-kali-server; do \
        dpkg -s "$pkg" >/dev/null 2>&1 || base_packages="$base_packages $pkg"; \
      done; \
    fi; \
    if [ -n "$(printf '%s' "$base_packages" | tr -d ' ')" ]; then \
      apt-get install -y $base_packages; \
    fi; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    if [ "$PRELOADED_TOOLS" != "1" ]; then apt-get install -y \
    subfinder \
    sublist3r \
    testssl.sh \
    golang-go \
    chromium \
    chromium-driver \
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
    tmux \
    ; fi && apt-get clean && rm -rf /var/lib/apt/lists/*

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) release_arch=amd64; ferox_arch=x86_64 ;; \
        arm64) release_arch=arm64; ferox_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      python3 -m venv /opt/mitmproxy-venv && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir --upgrade pip && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir mitmproxy && \
      ln -sf /opt/mitmproxy-venv/bin/mitmdump /usr/local/bin/mitmdump && \
      ln -sf /opt/mitmproxy-venv/bin/mitmproxy /usr/local/bin/mitmproxy && \
      gem install evil-winrm --no-document && \
      git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder && \
      python3 -m pip install --no-cache-dir --break-system-packages impacket==0.13.0 mitm6 dpapick3 aioquic flask uro && \
      curl -fsSL "https://github.com/jpillora/chisel/releases/download/v1.11.4/chisel_1.11.4_linux_${release_arch}.gz" | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel && \
      mkdir -p /tmp/ligolo && \
      curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_${release_arch}.tar.gz" | tar xzf - -C /tmp/ligolo && \
      find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
      chmod +x /usr/local/bin/ligolo-proxy && \
      rm -rf /tmp/ligolo && \
      GOPATH=/root/go go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
      cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
      GO111MODULE=on GOPATH=/root/go go install github.com/projectdiscovery/katana/cmd/katana@latest && \
      cp /root/go/bin/katana /usr/local/bin/katana && \
      GOPATH=/root/go go install github.com/projectdiscovery/httpx/cmd/httpx@latest && \
      cp /root/go/bin/httpx /usr/local/bin/httpx && \
      GOPATH=/root/go go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest && \
      cp /root/go/bin/dnsx /usr/local/bin/dnsx && \
      GOPATH=/root/go go install github.com/lc/gau/v2/cmd/gau@latest && \
      cp /root/go/bin/gau /usr/local/bin/gau && \
      GOPATH=/root/go go install github.com/hahwul/dalfox/v2@latest && \
      cp /root/go/bin/dalfox /usr/local/bin/dalfox && \
      GOPATH=/root/go go install github.com/d3mondev/puredns/v2@latest && \
      cp /root/go/bin/puredns /usr/local/bin/puredns && \
      GOPATH=/root/go go install github.com/tomnomnom/gf@latest && \
      cp /root/go/bin/gf /usr/local/bin/gf && \
      mkdir -p /root/.gf && \
      git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns /tmp/gf-patterns && \
      cp /tmp/gf-patterns/*.json /root/.gf/ && \
      rm -rf /tmp/gf-patterns && \
      rm -rf /root/go && \
      mkdir -p /tmp/ferox && \
      curl -fsSL "https://github.com/epi052/feroxbuster/releases/latest/download/${ferox_arch}-linux-feroxbuster.zip" \
        -o /tmp/ferox/ferox.zip && unzip /tmp/ferox/ferox.zip -d /tmp/ferox && \
      mv /tmp/ferox/feroxbuster /usr/local/bin/feroxbuster && chmod +x /usr/local/bin/feroxbuster && \
      rm -rf /tmp/ferox; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) th_arch=amd64 ;; \
        arm64) th_arch=arm64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      TRUFFLEHOG_VERSION=3.94.3 && \
      curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th_arch}.tar.gz" \
        | tar -xzf - -C /usr/local/bin trufflehog && \
      chmod +x /usr/local/bin/trufflehog; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /root/.config/amass && \
      timeout 120 amass enum --list 2>/dev/null; exit 0; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip && \
      unzip SecList.zip && rm -f SecList.zip && \
      mv SecLists-master /usr/share/wordlists/SecLists; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) frp_arch=amd64 ;; \
        arm64) frp_arch=arm64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      FRP_VERSION=0.61.1 && \
      curl -fsSL "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz" \
        | tar xzf - --strip-components=1 -C /usr/local/bin "frp_${FRP_VERSION}_linux_${frp_arch}/frpc" && \
      chmod +x /usr/local/bin/frpc && \
      go install github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest && \
      cp /root/go/bin/interactsh-server /usr/local/bin/interactsh-server && \
      go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest && \
      cp /root/go/bin/interactsh-client /usr/local/bin/interactsh-client; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/pwncat-venv && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir --upgrade pip && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir pwncat-vl && \
      ln -sf /opt/pwncat-venv/bin/pwncat-cs /usr/local/bin/pwncat; \
    fi

COPY docker/kali-mcp-runtime/mcp-server-wrapper.sh /usr/bin/mcp-server
RUN chmod +x /usr/bin/mcp-server

RUN mkdir -p /opt/mcp-tools
RUN mkdir -p /data
COPY docker/kali-mcp-runtime/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
COPY docker/kali-mcp-runtime/patched_kali_client.py /opt/mcp-tools/patched_kali_client.py
COPY docker/kali-mcp-runtime/kali_mcp_audit.py /opt/mcp-tools/kali_mcp_audit.py
COPY docker/callback_listener.py /opt/mcp-tools/callback_listener.py
COPY docker/start-callback.sh /usr/local/bin/start-callback
RUN chmod +x /usr/local/bin/start-callback

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD command -v mcp-server >/dev/null && command -v katana >/dev/null && command -v trufflehog >/dev/null && command -v gf >/dev/null && test -f /opt/mcp-tools/patched_kali_server.py && test -f /opt/mcp-tools/patched_kali_client.py && test -f /opt/mcp-tools/kali_mcp_audit.py || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "mkdir -p /data && exec sleep infinity"]
