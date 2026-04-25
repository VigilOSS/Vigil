FROM kalilinux/kali-rolling@sha256:dddc31e0f4bc57b4b91e9027762544506bf91c7cdd7ff52104daaa4449b4c726

ARG APT_PACKAGES="nmap=7.99+dfsg-1kali1 whatweb=0.6.3-1kali1 bind9-dnsutils=1:9.20.22-1 iputils-ping=3:20250605-1+b1 whois=5.6.6 ffuf=2.1.0-1+b11 gobuster=3.8.2-1 wfuzz=3.1.0-6 dirb=2.22+dfsg-7+b1 sqlmap=1.10.4-1 hydra=9.6-3+b1 john=1.9.0-Jumbo-1+git20211102-0kali10 hashcat=7.1.2+ds1-4 nuclei=3.7.1-0kali1 subfinder=2.13.0-0kali1 curl=8.19.0-3 wget=1.25.0-2+b1 jq=1.8.1-4+b1 ripgrep=15.1.0-1 unzip=6.0-29+b1 python3=3.13.9-3 python3-pip=26.0.1+dfsg-1 python3-aiohttp=3.13.3-3 netcat-openbsd=1.234-2 openssl=3.6.1-3 chromium=147.0.7727.55-1 chromium-driver=147.0.7727.55-1 sublist3r=1.1-5 testssl.sh=3.2.2+dfsg-1 proxychains4=4.17-3+b1 openssh-client=1:10.2p1-6 socat=1.8.1.1-1 tcpdump=4.99.6-2 tmux=3.6a-2+b1 ruby-full=1:3.3 golang-go=2:1.26~1 mcp-kali-server=0.0~git20260317.00154c0-0kali1 sudo=1.9.17p2-5 tini=0.19.0-6+b2 rlwrap=0.47.1-0.1+b1 wordlists=2026.1.2 seclists=2025.3-0kali1"
ARG PIP_VERSION=26.0.1
ARG EVIL_WINRM_VERSION=3.9
ARG RESPONDER_REF=fb29fe25db9135a9487c961783254b56a20f58ac
ARG IMPACKET_VERSION=0.13.0
ARG MITM6_VERSION=0.3.0
ARG DPAPICK3_VERSION=0.7.1
ARG AIOQUIC_VERSION=1.2.0
ARG FLASK_VERSION=3.1.2
ARG CHISEL_VERSION=1.11.4
ARG LIGOLO_VERSION=0.8.2
ARG PWNCAT_VL_VERSION=0.6.2
ARG NUCLEI_VERSION=v3.7.1
ARG KATANA_VERSION=v1.5.0
ARG HTTPX_VERSION=v1.9.0
ARG DNSX_VERSION=v1.2.3
ARG GAU_VERSION=v2.2.4
ARG DALFOX_VERSION=v2.12.0
ARG PUREDNS_VERSION=v2.1.1
ARG FEROXBUSTER_VERSION=2.13.1
ARG TRUFFLEHOG_VERSION=3.94.3

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/Responder:${PATH}"
ENV KALI_MCP_CLIENT_PATH=/usr/share/mcp-kali-server/client.py

RUN apt-get update && apt-get install -y --no-install-recommends $APT_PACKAGES \
    && apt-get clean \
    && find /var/lib/apt/lists -type f -delete

RUN gem install evil-winrm -v "${EVIL_WINRM_VERSION}" --no-document
RUN git init /opt/Responder && \
    git -C /opt/Responder remote add origin https://github.com/lgandx/Responder.git && \
    git -C /opt/Responder fetch --depth 1 origin "${RESPONDER_REF}" && \
    git -C /opt/Responder checkout --detach FETCH_HEAD
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    "impacket==${IMPACKET_VERSION}" \
    "mitm6==${MITM6_VERSION}" \
    "dpapick3==${DPAPICK3_VERSION}" \
    "aioquic==${AIOQUIC_VERSION}" \
    "flask==${FLASK_VERSION}"
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) release_arch=amd64 ;; \
      arm64) release_arch=arm64 ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${release_arch}.gz" \
    | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) release_arch=amd64 ;; \
      arm64) release_arch=arm64 ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    mkdir -p /tmp/ligolo && \
    curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_${release_arch}.tar.gz" \
      | tar xzf - -C /tmp/ligolo && \
    find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
    chmod +x /usr/local/bin/ligolo-proxy && \
    rm -rf /tmp/ligolo
RUN python3 -m venv /opt/pwncat-venv && \
    /opt/pwncat-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
    /opt/pwncat-venv/bin/pip install --no-cache-dir "pwncat-vl==${PWNCAT_VL_VERSION}" && \
    ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat && \
    ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat-vl
RUN GOPATH=/root/go go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" && \
    cp /root/go/bin/nuclei /usr/local/bin/nuclei && \
    GO111MODULE=on GOPATH=/root/go go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}" && \
    cp /root/go/bin/katana /usr/local/bin/katana && \
    GOPATH=/root/go go install "github.com/projectdiscovery/httpx/cmd/httpx@${HTTPX_VERSION}" && \
    cp /root/go/bin/httpx /usr/local/bin/httpx && \
    GOPATH=/root/go go install "github.com/projectdiscovery/dnsx/cmd/dnsx@${DNSX_VERSION}" && \
    cp /root/go/bin/dnsx /usr/local/bin/dnsx && \
    GOPATH=/root/go go install "github.com/lc/gau/v2/cmd/gau@${GAU_VERSION}" && \
    cp /root/go/bin/gau /usr/local/bin/gau && \
    GOPATH=/root/go go install "github.com/hahwul/dalfox/v2@${DALFOX_VERSION}" && \
    cp /root/go/bin/dalfox /usr/local/bin/dalfox && \
    GOPATH=/root/go go install "github.com/d3mondev/puredns/v2@${PUREDNS_VERSION}" && \
    cp /root/go/bin/puredns /usr/local/bin/puredns && \
    rm -rf /root/go
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) ferox_arch=x86_64 ;; \
      arm64) ferox_arch=aarch64 ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    mkdir -p /tmp/ferox && \
    curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${ferox_arch}-linux-feroxbuster.zip" \
    -o /tmp/ferox/ferox.zip && unzip /tmp/ferox/ferox.zip -d /tmp/ferox && \
    mv /tmp/ferox/feroxbuster /usr/local/bin/feroxbuster && chmod +x /usr/local/bin/feroxbuster && rm -rf /tmp/ferox
RUN arch="$(dpkg --print-architecture)" && \
    case "$arch" in \
      amd64) th_arch=amd64 ;; \
      arm64) th_arch=arm64 ;; \
      *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th_arch}.tar.gz" \
      | tar -xzf - -C /usr/local/bin trufflehog && \
    chmod +x /usr/local/bin/trufflehog

RUN ln -sf /usr/share/wordlists /wordlists && \
    ln -sf /usr/share/seclists /seclists

COPY docker/kali-mcp-runtime/mcp-server-wrapper.sh /usr/bin/mcp-server
COPY docker/kali-mcp-runtime/patched_kali_server.py /opt/mcp-tools/patched_kali_server.py
COPY docker/kali-mcp-runtime/patched_kali_client.py /opt/mcp-tools/patched_kali_client.py
COPY docker/kali-mcp-runtime/kali_mcp_audit.py /opt/mcp-tools/kali_mcp_audit.py
COPY docker/kali-mcp-runtime/audit_enums.py /opt/mcp-tools/audit_enums.py
RUN chmod +x /usr/bin/mcp-server && mkdir -p /opt/mcp-tools /data

WORKDIR /engagement
ENTRYPOINT ["/usr/bin/tini","--"]
CMD ["bash"]
