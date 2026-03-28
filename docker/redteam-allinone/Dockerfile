FROM debian:bookworm-slim AS katana-bin

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

ARG KATANA_VERSION=1.5.0
ARG TARGETARCH
RUN case "${TARGETARCH}" in \
      amd64) KATANA_ARCH="amd64" ;; \
      arm64) KATANA_ARCH="arm64" ;; \
      *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    curl -fsSL -o /tmp/katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${KATANA_ARCH}.zip" && \
    unzip -q /tmp/katana.zip -d /tmp/katana && \
    install -m 0755 /tmp/katana/katana /usr/local/bin/katana

FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV REDTEAM_SKIP_PREREQ_CHECKS=1
ENV REDTEAM_SKIP_DOCKER_IMAGE_CHECKS=1
ENV PATH="/opt/Responder:${PATH}"
ENV KALI_MCP_CLIENT_PATH=/usr/share/mcp-kali-server/client.py

RUN apt-get update && apt-get install -y --no-install-recommends \
    nodejs npm \
    curl jq sqlite3 git ca-certificates sudo tini rlwrap golang-go \
    whois dnsutils ripgrep openssl wget netcat-openbsd procps lsof \
    python3 python3-venv python3-pip python3-dev \
    python3-aiohttp \
    chromium chromium-driver \
    unzip \
    nmap nikto whatweb ffuf gobuster wfuzz dirb sqlmap hydra john hashcat subfinder sublist3r testssl.sh \
    wordlists seclists \
    proxychains-ng openssh-client socat tcpdump \
    ruby-full metasploit-framework \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/mitmproxy-venv && \
    /opt/mitmproxy-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/mitmproxy-venv/bin/pip install --no-cache-dir mitmproxy && \
    ln -sf /opt/mitmproxy-venv/bin/mitmdump /usr/local/bin/mitmdump && \
    ln -sf /opt/mitmproxy-venv/bin/mitmproxy /usr/local/bin/mitmproxy
RUN gem install evil-winrm --no-document
RUN git clone --depth 1 https://github.com/lgandx/Responder.git /opt/Responder
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    impacket==0.13.0 \
    mitm6 \
    dpapick3 \
    aioquic \
    flask
RUN curl -fsSL "https://github.com/jpillora/chisel/releases/download/v1.11.4/chisel_1.11.4_linux_amd64.gz" \
    | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel
RUN mkdir -p /tmp/ligolo && \
    curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz" \
      | tar xzf - -C /tmp/ligolo && \
    find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -rf /tmp/ligolo
RUN GOPATH=/root/go go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
    GO111MODULE=on GOPATH=/root/go go install github.com/projectdiscovery/katana/cmd/katana@latest && \
    cp /root/go/bin/katana /usr/local/bin/katana && \
    rm -rf /root/go
RUN npm install -g opencode-ai@latest

COPY docker/kali-mcp-runtime/mcp-server-wrapper.sh /usr/bin/mcp-server
COPY docker/kali-mcp-runtime/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
COPY docker/kali-mcp-runtime/mcp_transform_proxy.py /opt/mcp-tools/mcp_transform_proxy.py
RUN chmod +x /usr/bin/mcp-server && mkdir -p /opt/mcp-tools

COPY . /src
WORKDIR /src

RUN ./install.sh opencode /opt/redteam-agent

RUN ln -sf /usr/share/wordlists /wordlists && \
    ln -sf /usr/share/seclists /seclists

COPY docker/redteam-allinone/entrypoint.sh /usr/local/bin/redteam-entrypoint
RUN chmod +x /usr/local/bin/redteam-entrypoint

WORKDIR /workspace
ENV REDTEAM_RUNTIME_MODE=local
ENV KATANA_LOCAL_BIN=/usr/local/bin/katana
ENV KATANA_CHROME_BIN=/usr/bin/chromium
ENV KATANA_HEADLESS_OPTIONS=--no-sandbox,--disable-dev-shm-usage,--disable-gpu
ENTRYPOINT ["/usr/bin/tini","--","/usr/local/bin/redteam-entrypoint"]
CMD ["opencode"]
