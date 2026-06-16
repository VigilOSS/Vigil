ARG BASE_IMAGE=kalilinux/kali-rolling@sha256:dddc31e0f4bc57b4b91e9027762544506bf91c7cdd7ff52104daaa4449b4c726
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0
ARG INSTALL_VERSION_STAMP=2026.05.05-84a231c
LABEL vigil.install-versions="${INSTALL_VERSION_STAMP}"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG APT_BASE_PACKAGES="ca-certificates curl jq sqlite3 git ripgrep bind9-dnsutils iputils-ping whois openssl netcat-openbsd procps lsof python3 python3-dev python3-pip python3-aiohttp sudo tini wget rlwrap unzip dtach libxml2-utils pipx strace build-essential"
ARG APT_TOOL_PACKAGES="subfinder sublist3r testssl.sh golang-go chromium chromium-driver whatweb ffuf gobuster wfuzz dirb sqlmap hydra john hashcat ruby-full proxychains4 openssh-client socat tcpdump tmux nikto massdns nmap amass wafw00f"
ARG APT_ANDROID_PACKAGES="apktool jadx adb aapt apksigner default-jre-headless"
ARG CURL_RETRY_FLAGS="--retry 5 --retry-delay 2 --retry-all-errors"
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
ARG ALTERX_VERSION=v0.1.0
ARG ASNMAP_VERSION=v1.1.1
ARG CERO_VERSION=v1.3.0
ARG BBOT_VERSION=2.6.0
ARG ARJUN_VERSION=2.2.7
ARG GF_VERSION=v0.0.0-20200618134122-dcd4c361f9f5
ARG GF_PATTERNS_REF=f686f06ae647726578920084c894100d702496cc
ARG JSLUICE_VERSION=v0.0.0-20240110145140-0ddfab153e06
ARG FEROXBUSTER_VERSION=2.13.1
ARG TRUFFLEHOG_VERSION=3.94.3
ARG FRP_VERSION=0.61.1
ARG INTERACTSH_VERSION=v1.3.1
ARG PWNCAT_VL_VERSION=0.6.2
ARG SECLISTS_REF=8af68f02ed621c5e0f3d7e24659f9f5bf5384c08
ARG APKEEP_VERSION=1.0.0
ARG BUNDLETOOL_VERSION=1.18.3

ENV PATH="/opt/Responder:/opt/offsec-venv/bin:/opt/mitmproxy-venv/bin:/opt/pwncat-venv/bin:${PATH}"

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
    if [ "$PRELOADED_TOOLS" != "1" ]; then apt-get install -y $APT_TOOL_PACKAGES $APT_ANDROID_PACKAGES; fi && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) apkeep_arch=x86_64 ;; \
        arm64) apkeep_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/EFForg/apkeep/releases/download/${APKEEP_VERSION}/apkeep-${apkeep_arch}-unknown-linux-gnu" \
        -o /usr/local/bin/apkeep && chmod +x /usr/local/bin/apkeep && \
      mkdir -p /opt/android-tools && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/google/bundletool/releases/download/${BUNDLETOOL_VERSION}/bundletool-all-${BUNDLETOOL_VERSION}.jar" \
        -o /opt/android-tools/bundletool.jar && \
      printf '%s\n' '#!/bin/sh' 'exec java -jar /opt/android-tools/bundletool.jar "$@"' > /usr/local/bin/bundletool && \
      chmod +x /usr/local/bin/bundletool; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/mitmproxy-venv && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/mitmproxy-venv/bin/pip install --no-cache-dir "mitmproxy==${MITMPROXY_VERSION}" && \
      ln -sf /opt/mitmproxy-venv/bin/mitmdump /usr/local/bin/mitmdump && \
      ln -sf /opt/mitmproxy-venv/bin/mitmproxy /usr/local/bin/mitmproxy; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      gem install evil-winrm -v "${EVIL_WINRM_VERSION}" --no-document; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      git init /opt/Responder && \
      git -C /opt/Responder remote add origin https://github.com/lgandx/Responder.git && \
      git -C /opt/Responder fetch --depth 1 origin "${RESPONDER_REF}" && \
      git -C /opt/Responder checkout --detach FETCH_HEAD; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/offsec-venv && \
      /opt/offsec-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/offsec-venv/bin/pip install --no-cache-dir \
        "impacket==${IMPACKET_VERSION}" \
        "mitm6==${MITM6_VERSION}" \
        "dpapick3==${DPAPICK3_VERSION}" \
        "aioquic==${AIOQUIC_VERSION}" \
        "flask==${FLASK_VERSION}" \
        "uro==${URO_VERSION}"; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) release_arch=amd64 ;; \
        arm64) release_arch=arm64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${release_arch}.gz" | gunzip > /usr/local/bin/chisel && \
      chmod +x /usr/local/bin/chisel && \
      mkdir -p /tmp/ligolo && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_${release_arch}.tar.gz" | tar xzf - -C /tmp/ligolo && \
      find /tmp/ligolo -type f -perm /111 -exec mv {} /usr/local/bin/ligolo-proxy \; && \
      chmod +x /usr/local/bin/ligolo-proxy && \
      rm -rf /tmp/ligolo; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
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
      GOPATH=/root/go go install "github.com/BishopFox/jsluice/cmd/jsluice@${JSLUICE_VERSION}" && \
      cp /root/go/bin/jsluice /usr/local/bin/jsluice && \
      rm -rf /root/go; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /root/.gf && \
      git init /tmp/gf-patterns && \
      git -C /tmp/gf-patterns remote add origin https://github.com/1ndianl33t/Gf-Patterns && \
      git -C /tmp/gf-patterns fetch --depth 1 origin "${GF_PATTERNS_REF}" && \
      git -C /tmp/gf-patterns checkout --detach FETCH_HEAD && \
      cp /tmp/gf-patterns/*.json /root/.gf/ && \
      rm -rf /tmp/gf-patterns; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) ferox_arch=x86_64 ;; \
        arm64) ferox_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      mkdir -p /tmp/ferox && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${ferox_arch}-linux-feroxbuster.zip" \
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
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${th_arch}.tar.gz" \
        | tar -xzf - -C /usr/local/bin trufflehog && \
      chmod +x /usr/local/bin/trufflehog; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /root/.config/amass; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/danielmiessler/SecLists/archive/${SECLISTS_REF}.zip" -o SecList.zip && \
      mkdir -p /tmp/seclists /usr/share/wordlists && \
      unzip -q SecList.zip -d /tmp/seclists && rm -f SecList.zip && \
      mv /tmp/seclists/SecLists-* /usr/share/wordlists/SecLists && \
      rm -rf /tmp/seclists; \
    fi

# Target-class wordlists not in SecLists by default. These are the lists most
# commonly hand-rolled during enterprise SaaS engagements (Salesforce, Visualforce,
# SwaggerHub spec discovery, OpenAPI route patterns). Pinning them in the image
# means specialists reach the right list with -w /usr/share/wordlists/<vendor>/...
# instead of falling back to 60-100 entry hand-seeded lists. Source-of-truth URLs
# are stable Assetnote CDN paths.
RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /usr/share/wordlists/assetnote /usr/share/wordlists/openapi && \
      download_optional_wordlist() { \
        url="$1"; \
        dest="$2"; \
        label="$3"; \
        tmp="${dest}.tmp"; \
        if curl -fsSL --retry 3 --retry-delay 1 "$url" -o "$tmp"; then \
          mv "$tmp" "$dest"; \
        else \
          rm -f "$tmp" "$dest"; \
          echo "WARN: failed to fetch ${label}; engagement will fall back to SecLists generic" >&2; \
        fi; \
      }; \
      download_optional_wordlist \
        "https://wordlists-cdn.assetnote.io/data/technologies/salesforce.txt" \
        "/usr/share/wordlists/assetnote/salesforce.txt" \
        "assetnote salesforce.txt"; \
      download_optional_wordlist \
        "https://wordlists-cdn.assetnote.io/data/technologies/visualforce.txt" \
        "/usr/share/wordlists/assetnote/visualforce.txt" \
        "assetnote visualforce.txt"; \
      download_optional_wordlist \
        "https://wordlists-cdn.assetnote.io/data/manual/swagger-paths.txt" \
        "/usr/share/wordlists/openapi/swagger-paths.txt" \
        "swagger-paths.txt"; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) frp_arch=amd64 ;; \
        arm64) frp_arch=arm64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${frp_arch}.tar.gz" \
        | tar xzf - --strip-components=1 -C /usr/local/bin "frp_${FRP_VERSION}_linux_${frp_arch}/frpc" && \
      chmod +x /usr/local/bin/frpc && \
      go install "github.com/projectdiscovery/interactsh/cmd/interactsh-server@${INTERACTSH_VERSION}" && \
      cp /root/go/bin/interactsh-server /usr/local/bin/interactsh-server && \
      go install "github.com/projectdiscovery/interactsh/cmd/interactsh-client@${INTERACTSH_VERSION}" && \
      cp /root/go/bin/interactsh-client /usr/local/bin/interactsh-client && \
      rm -rf /root/go; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      python3 -m venv /opt/pwncat-venv && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/pwncat-venv/bin/pip install --no-cache-dir "pwncat-vl==${PWNCAT_VL_VERSION}" && \
      ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat && \
      ln -sf /opt/pwncat-venv/bin/pwncat-vl /usr/local/bin/pwncat-vl; \
    fi

RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install "bbot==${BBOT_VERSION}" && \
      PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install "arjun==${ARJUN_VERSION}"; \
    fi

RUN mkdir -p /opt/mcp-tools /data
COPY docker/callback_listener.py /opt/mcp-tools/callback_listener.py
COPY docker/start-callback.sh /usr/local/bin/start-callback
RUN chmod +x /usr/local/bin/start-callback
RUN printf '%s\n' 'export PATH="/opt/Responder:/opt/offsec-venv/bin:/opt/mitmproxy-venv/bin:/opt/pwncat-venv/bin:$PATH"' > /etc/profile.d/vigil-path.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD command -v dtach >/dev/null && command -v katana >/dev/null && command -v trufflehog >/dev/null && command -v gf >/dev/null && command -v jsluice >/dev/null && command -v arjun >/dev/null && command -v xmllint >/dev/null && command -v apkeep >/dev/null && command -v apktool >/dev/null && command -v jadx >/dev/null && command -v adb >/dev/null && command -v bundletool >/dev/null && command -v apksigner >/dev/null && command -v aapt >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "mkdir -p /data && exec sleep infinity"]
