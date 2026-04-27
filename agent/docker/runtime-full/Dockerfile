ARG BASE_IMAGE=kalilinux/kali-rolling@sha256:dddc31e0f4bc57b4b91e9027762544506bf91c7cdd7ff52104daaa4449b4c726
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0

ARG APT_BASE_PACKAGES="ca-certificates=20260223 curl=8.19.0-3 jq=1.8.1-4+b1 sqlite3=3.46.1-9+b1 git=1:2.53.0-1 ripgrep=15.1.0-1+b1 bind9-dnsutils=1:9.20.22-1 iputils-ping=3:20250605-1+b1 whois=5.6.6 openssl=3.6.1-3 netcat-openbsd=1.234-2 procps=2:4.0.4-9+b2 lsof=4.99.4+dfsg-2+b1 python3=3.13.9-3 python3-pip=26.0.1+dfsg-1 python3-aiohttp=3.13.3-3 sudo=1.9.17p2-5 tini=0.19.0-6+b2 wget=1.25.0-2+b1 rlwrap=0.47.1-0.1+b1 unzip=6.0-29+b1 dtach=0.9-8+b1 libxml2-utils=2.15.2+dfsg-0.1 pipx=1.11.1-1"
ARG APT_TOOL_PACKAGES="kali-linux-default=2026.2.0 subfinder=2.13.0-0kali1 sublist3r=1.1-5 testssl.sh=3.2.2+dfsg-1 golang-go=2:1.26~1 chromium=147.0.7727.101-1 chromium-driver=147.0.7727.101-1 whatweb=0.6.3-1kali1 ffuf=2.1.0-1+b11 gobuster=3.8.2-1 wfuzz=3.1.0-6 dirb=2.22+dfsg-7+b1 sqlmap=1.10.4-1 hydra=9.6-3+b1 john=1.9.0-Jumbo-1+git20211102-0kali10 hashcat=7.1.2+ds1-4 ruby-full=1:3.3 proxychains4=4.17-3+b1 openssh-client=1:10.2p1-6 socat=1.8.1.1-1 tcpdump=4.99.6-2 tmux=3.6a-2+b1 nikto=1:2.6.0-0kali3 massdns=1.1.0-0kali2"
ARG PIP_VERSION=26.0.1
ARG MITMPROXY_VERSION=12.2.2
ARG EVIL_WINRM_VERSION=3.9
ARG RESPONDER_REF=fb29fe25db9135a9487c961783254b56a20f58ac
ARG IMPACKET_VERSION=0.13.0
ARG MITM6_VERSION=0.3.0
ARG DPAPICK3_VERSION=0.7.1
ARG AIOQUIC_VERSION=1.2.0
ARG FLASK_VERSION=3.1.2
ARG URO_VERSION=1.0.2
ARG CHISEL_VERSION=1.11.4
ARG LIGOLO_VERSION=0.8.2
ARG NUCLEI_VERSION=v3.7.1
ARG KATANA_VERSION=v1.5.0
ARG HTTPX_VERSION=v1.9.0
ARG DNSX_VERSION=v1.2.3
ARG GAU_VERSION=v2.2.4
ARG DALFOX_VERSION=v2.12.0
ARG PUREDNS_VERSION=v2.1.1
ARG SHUFFLEDNS_VERSION=v1.1.0
ARG ALTERX_VERSION=v0.0.5
ARG ASNMAP_VERSION=v1.1.2
ARG CERO_VERSION=v1.4.4
ARG BBOT_VERSION=2.6.0
ARG GF_VERSION=v0.0.0-20200618134122-dcd4c361f9f5
ARG GF_PATTERNS_REF=f686f06ae647726578920084c894100d702496cc
ARG FEROXBUSTER_VERSION=2.13.1
ARG TRUFFLEHOG_VERSION=3.94.3
ARG FRP_VERSION=0.61.1
ARG INTERACTSH_VERSION=v1.3.1
ARG PWNCAT_VL_VERSION=0.6.2
ARG SECLISTS_REF=8af68f02ed621c5e0f3d7e24659f9f5bf5384c08

ENV PATH="/opt/Responder:${PATH}"

RUN set -eux; \
    export DEBIAN_FRONTEND=noninteractive; \
    apt-get update -y; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      base_packages="$APT_BASE_PACKAGES"; \
    else \
      base_packages=''; \
      for pkg in $APT_BASE_PACKAGES; do \
        package_name="${pkg%%=*}"; \
        dpkg -s "$package_name" >/dev/null 2>&1 || base_packages="$base_packages $pkg"; \
      done; \
    fi; \
    if [ -n "$(printf '%s' "$base_packages" | tr -d ' ')" ]; then \
      apt-get install -y $base_packages; \
    fi; \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && \
    if [ "$PRELOADED_TOOLS" != "1" ]; then apt-get install -y $APT_TOOL_PACKAGES; fi && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) release_arch=amd64; ferox_arch=x86_64 ;; \
        arm64) release_arch=arm64; ferox_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      python3 -m venv /opt/mitmproxy-venv && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir "mitmproxy==${MITMPROXY_VERSION}" && \
      ln -sf /opt/mitmproxy-venv/bin/mitmdump /usr/local/bin/mitmdump && \
      ln -sf /opt/mitmproxy-venv/bin/mitmproxy /usr/local/bin/mitmproxy && \
      gem install evil-winrm -v "${EVIL_WINRM_VERSION}" --no-document && \
      git init /opt/Responder && \
      git -C /opt/Responder remote add origin https://github.com/lgandx/Responder.git && \
      git -C /opt/Responder fetch --depth 1 origin "${RESPONDER_REF}" && \
      git -C /opt/Responder checkout --detach FETCH_HEAD && \
      python3 -m pip install --no-cache-dir --break-system-packages \
        "impacket==${IMPACKET_VERSION}" \
        "mitm6==${MITM6_VERSION}" \
        "dpapick3==${DPAPICK3_VERSION}" \
        "aioquic==${AIOQUIC_VERSION}" \
        "flask==${FLASK_VERSION}" \
        "uro==${URO_VERSION}" && \
      curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${release_arch}.gz" | gunzip > /usr/local/bin/chisel && chmod +x /usr/local/bin/chisel && \
      mkdir -p /tmp/ligolo && \
      curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_${release_arch}.tar.gz" | tar xzf - -C /tmp/ligolo && \
      find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
      chmod +x /usr/local/bin/ligolo-proxy && \
      rm -rf /tmp/ligolo && \
      GOPATH=/root/go go install "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}" && \
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
      GOPATH=/root/go go install "github.com/projectdiscovery/shuffledns/cmd/shuffledns@${SHUFFLEDNS_VERSION}" && \
      cp /root/go/bin/shuffledns /usr/local/bin/shuffledns && \
      GOPATH=/root/go go install "github.com/projectdiscovery/alterx/cmd/alterx@${ALTERX_VERSION}" && \
      cp /root/go/bin/alterx /usr/local/bin/alterx && \
      GOPATH=/root/go go install "github.com/projectdiscovery/asnmap/cmd/asnmap@${ASNMAP_VERSION}" && \
      cp /root/go/bin/asnmap /usr/local/bin/asnmap && \
      GOPATH=/root/go go install "github.com/glebarez/cero@${CERO_VERSION}" && \
      cp /root/go/bin/cero /usr/local/bin/cero && \
      GOPATH=/root/go go install "github.com/tomnomnom/gf@${GF_VERSION}" && \
      cp /root/go/bin/gf /usr/local/bin/gf && \
      mkdir -p /root/.gf && \
      git init /tmp/gf-patterns && \
      git -C /tmp/gf-patterns remote add origin https://github.com/1ndianl33t/Gf-Patterns && \
      git -C /tmp/gf-patterns fetch --depth 1 origin "${GF_PATTERNS_REF}" && \
      git -C /tmp/gf-patterns checkout --detach FETCH_HEAD && \
      cp /tmp/gf-patterns/*.json /root/.gf/ && \
      rm -rf /tmp/gf-patterns && \
      rm -rf /root/go && \
      mkdir -p /tmp/ferox && \
      curl -fsSL "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${ferox_arch}-linux-feroxbuster.zip" \
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
      curl -fsSL "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th_arch}.tar.gz" \
        | tar -xzf - -C /usr/local/bin trufflehog && \
      chmod +x /usr/local/bin/trufflehog; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /root/.config/amass && \
      timeout 120 amass enum --list 2>/dev/null; exit 0; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      wget -c "https://github.com/danielmiessler/SecLists/archive/${SECLISTS_REF}.zip" -O SecList.zip && \
      mkdir -p /tmp/seclists && \
      unzip SecList.zip -d /tmp/seclists && rm -f SecList.zip && \
      mv /tmp/seclists/SecLists-* /usr/share/wordlists/SecLists && \
      rm -rf /tmp/seclists; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) frp_arch=amd64 ;; \
        arm64) frp_arch=arm64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      curl -fsSL "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz" \
        | tar xzf - --strip-components=1 -C /usr/local/bin "frp_${FRP_VERSION}_linux_${frp_arch}/frpc" && \
      chmod +x /usr/local/bin/frpc && \
      go install "github.com/projectdiscovery/interactsh/cmd/interactsh-server@${INTERACTSH_VERSION}" && \
      cp /root/go/bin/interactsh-server /usr/local/bin/interactsh-server && \
      go install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}" && \
      cp /root/go/bin/interactsh-client /usr/local/bin/interactsh-client; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/pwncat-venv && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir "pwncat-vl==${PWNCAT_VL_VERSION}" && \
      ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat && \
      ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat-vl; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install "bbot==${BBOT_VERSION}"; \
    fi

RUN mkdir -p /etc/security/limits.d && \
    printf '* soft nofile 131072\n* hard nofile 131072\n* soft nproc 16384\n* hard nproc 16384\nroot soft nofile 131072\nroot hard nofile 131072\nroot soft nproc 16384\nroot hard nproc 16384\n' > /etc/security/limits.d/aith.conf

RUN mkdir -p /opt/mcp-tools /data
COPY docker/kali-mcp-runtime/audit_enums.py /opt/mcp-tools/audit_enums.py
COPY docker/callback_listener.py /opt/mcp-tools/callback_listener.py
COPY docker/start-callback.sh /usr/local/bin/start-callback
RUN chmod +x /usr/local/bin/start-callback

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD command -v dtach >/dev/null && command -v katana >/dev/null && command -v trufflehog >/dev/null && command -v gf >/dev/null && command -v xmllint >/dev/null && test -f /opt/mcp-tools/audit_enums.py || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "mkdir -p /data && exec sleep infinity"]
