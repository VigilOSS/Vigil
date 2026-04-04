FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/Responder:${PATH}"
ENV KALI_MCP_CLIENT_PATH=/usr/share/mcp-kali-server/client.py

RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whatweb \
    dnsutils \
    whois \
    ffuf \
    gobuster \
    wfuzz \
    dirb \
    sqlmap \
    hydra \
    john \
    hashcat \
    nuclei \
    subfinder \
    curl \
    wget \
    jq \
    ripgrep \
    python3 \
    python3-pip \
    python3-aiohttp \
    netcat-openbsd \
    openssl \
    chromium \
    chromium-driver \
    sublist3r \
    testssl.sh \
    proxychains-ng \
    openssh-client \
    socat \
    tcpdump \
    tmux \
    ruby-full \
    golang-go \
    mcp-kali-server \
    sudo \
    tini \
    rlwrap \
    wordlists \
    seclists \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete

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
RUN python3 -m venv /opt/pwncat-venv && \
    /opt/pwncat-venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/pwncat-venv/bin/pip install --no-cache-dir pwncat-vl && \
    ln -sf /opt/pwncat-venv/bin/pwncat-cs /usr/local/bin/pwncat
RUN GOPATH=/root/go go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
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
    rm -rf /root/go
RUN curl -fsSL "https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip" \
    -o /tmp/ferox.zip && unzip /tmp/ferox.zip -d /tmp && dpkg -i /tmp/feroxbuster_*_amd64.deb && rm -rf /tmp/ferox*

RUN ln -sf /usr/share/wordlists /wordlists && \
    ln -sf /usr/share/seclists /seclists

COPY docker/kali-mcp-runtime/mcp-server-wrapper.sh /usr/bin/mcp-server
COPY docker/kali-mcp-runtime/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
RUN chmod +x /usr/bin/mcp-server && mkdir -p /opt/mcp-tools /data

WORKDIR /engagement
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["bash"]
