ARG BASE_IMAGE=kalilinux/kali-rolling@sha256:dddc31e0f4bc57b4b91e9027762544506bf91c7cdd7ff52104daaa4449b4c726
ARG PRELOADED_TOOLS=0
FROM ${BASE_IMAGE}
ARG PRELOADED_TOOLS=0
ARG INSTALL_VERSION_STAMP=2026.06.29-jwt-tool
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
ARG BOTO3_VERSION=1.43.39
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
# Recon expansion tools (owner-approved set). tlsx/github-subdomains/s3scanner
# install via install_go_tools() (see install-external-tools.sh); cloud_enum is
# cloned in the python layer below. github-subdomains needs a GITHUB_TOKEN at
# RUNTIME (read from the container env at probe time, like the github-osint
# pipelines) — it is NOT a build-time dependency, so the build never touches it.
ARG TLSX_VERSION=v1.2.2
ARG GITHUB_SUBDOMAINS_VERSION=v1.2.2
ARG S3SCANNER_VERSION=v3.1.1
ARG CLOUD_ENUM_VERSION=0.8
ARG FEROXBUSTER_VERSION=2.13.1
ARG TRUFFLEHOG_VERSION=3.94.3
ARG FRP_VERSION=0.61.1
ARG INTERACTSH_VERSION=v1.3.1
ARG PWNCAT_VL_VERSION=0.6.2
ARG SECLISTS_REF=8af68f02ed621c5e0f3d7e24659f9f5bf5384c08
ARG APKEEP_VERSION=1.0.0
ARG BUNDLETOOL_VERSION=1.18.3
# curl-impersonate (lexiforest fork) — TLS/JA3-JA4 + HTTP2-fingerprint impersonation
# of real Chrome. Required to reach Akamai/Cloudflare Bot-Manager-fronted targets
# (e.g. *.bank.acme.example) that drop or 403 plain curl's fingerprint. Ships the
# `curl_chrome116` wrapper with full curl flag-compatibility.
ARG CURL_IMPERSONATE_VERSION=1.1.0
# jwt_tool (ticarpi) — comprehensive JWT testing referenced by
# agent/skills/jwt-testing/SKILL.md (claim editing, alg:none / key-confusion
# forgery, kid/jku injection, HMAC secret cracking). Native python alg:none +
# hashcat/john cover the first-pass set; jwt_tool is the full claim-editing path.
ARG JWT_TOOL_VERSION=v2.3.0

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
        "uro==${URO_VERSION}" \
        "boto3==${BOTO3_VERSION}"; \
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

COPY agent/docker/runtime-full/install-external-tools.sh /usr/local/bin/install-external-tools
RUN chmod +x /usr/local/bin/install-external-tools

RUN set -eux; \
    install-external-tools go-tools

RUN set -eux; \
    install-external-tools gf-patterns

RUN set -eux; \
    install-external-tools feroxbuster

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

# curl-impersonate (curl_chrome116) — JA3/JA4 + HTTP2 fingerprint impersonation.
# Without this, Akamai/Cloudflare Bot-Manager-fronted hosts (e.g. *.bank.acme.example)
# drop or 403 plain curl on TLS fingerprint alone. The release tarball drops the
# `curl-impersonate` binary plus per-browser wrapper scripts (curl_chrome116 etc.)
# straight into /usr/local/bin.
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      arch="$(dpkg --print-architecture)" && \
      case "$arch" in \
        amd64) ci_arch=x86_64 ;; \
        arm64) ci_arch=aarch64 ;; \
        *) echo "Unsupported architecture: $arch" >&2; exit 1 ;; \
      esac && \
      curl -fsSL $CURL_RETRY_FLAGS \
        "https://github.com/lexiforest/curl-impersonate/releases/download/v${CURL_IMPERSONATE_VERSION}/curl-impersonate-v${CURL_IMPERSONATE_VERSION}.${ci_arch}-linux-gnu.tar.gz" \
        | tar xzf - -C /usr/local/bin && \
      chmod +x /usr/local/bin/curl-impersonate /usr/local/bin/curl_chrome* && \
      /usr/local/bin/curl_chrome116 -s -o /dev/null -w 'curl_chrome116 smoke HTTP %{http_code}\n' --max-time 20 https://www.example.com; \
    fi

RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      curl -fsSL $CURL_RETRY_FLAGS "https://github.com/danielmiessler/SecLists/archive/${SECLISTS_REF}.zip" -o SecList.zip && \
      mkdir -p /tmp/seclists /usr/share/wordlists && \
      unzip -q SecList.zip -d /tmp/seclists && rm -f SecList.zip && \
      mv /tmp/seclists/SecLists-* /usr/share/wordlists/SecLists && \
      rm -rf /tmp/seclists; \
    fi

# OpenAPI route wordlist not in SecLists by default. This Assetnote path is part
# of their documented kiterunner data set; keep it optional so CDN drift cannot
# break runtime builds.
RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /usr/share/wordlists/openapi && \
      download_optional_wordlist() { \
        url="$1"; \
        dest="$2"; \
        label="$3"; \
        tmp="${dest}.tmp"; \
        if curl -fsSL $CURL_RETRY_FLAGS "$url" -o "$tmp"; then \
          mv "$tmp" "$dest"; \
        else \
          rm -f "$tmp" "$dest"; \
          echo "WARN: failed to fetch ${label}; engagement will fall back to SecLists generic" >&2; \
        fi; \
      }; \
      download_optional_wordlist \
        "https://wordlists-cdn.assetnote.io/data/kiterunner/swagger-wordlist.txt" \
        "/usr/share/wordlists/openapi/swagger-wordlist.txt" \
        "assetnote swagger-wordlist.txt"; \
    fi

# n0kovo_subdomains brute wordlist — CT-derived and frequency-ordered, so the
# real labels sit in the HEAD and CT-hash / one-off junk in the tail. HEAD-cap the
# ~3M-line `huge` list to 500k labels (CR-19): bruting the head recovers nearly
# all real hosts at a fraction of the DNS spend, and 500k matches the
# `vigil assess dns-discovery --wordlist-head` default. Optional like the
# assetnote list above — a CDN/path drift WARNs and the brute falls back to the
# SecLists default rather than breaking the build. Select it explicitly with
# `vigil assess dns-discovery --wordlist /usr/share/wordlists/n0kovo_subdomains_500k.txt`.
RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      mkdir -p /usr/share/wordlists; \
      tmp=/tmp/n0kovo_huge.txt; \
      if curl -fsSL $CURL_RETRY_FLAGS \
          "https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_huge.txt" \
          -o "$tmp"; then \
        head -n 500000 "$tmp" > /usr/share/wordlists/n0kovo_subdomains_500k.txt; \
        rm -f "$tmp"; \
      else \
        rm -f "$tmp" /usr/share/wordlists/n0kovo_subdomains_500k.txt; \
        echo "WARN: failed to fetch n0kovo_subdomains_huge.txt; DNS brute falls back to the SecLists default" >&2; \
      fi; \
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

# Harden Arjun: its per-URL loop in main() catches only KeyboardInterrupt, so one
# endpoint returning 4xx/5xx (which trips an upstream `request.status_code` typo on
# a dict) or any per-URL error aborts an ENTIRE `-i` batch. The patch fixes the typo
# and wraps the per-URL call so one bad endpoint is skipped, not fatal. Idempotent;
# runs unconditionally (also covers a PRELOADED_TOOLS base) and is a no-op if absent.
COPY agent/docker/patches/arjun-batch-resilience.py /tmp/arjun-batch-resilience.py
RUN ARJUN_PY=/opt/pipx/venvs/arjun/bin/python; \
    if [ -x "$ARJUN_PY" ]; then \
      "$ARJUN_PY" /tmp/arjun-batch-resilience.py \
        "$("$ARJUN_PY" -c 'import importlib.util as u; print(u.find_spec("arjun.__main__").origin)')"; \
    fi; \
    rm -f /tmp/arjun-batch-resilience.py

# cloud_enum (initstring) — multi-cloud OSINT bucket/blob enumerator for the
# cloud-exposure specialist (AWS S3, Azure blob/host, GCP). Cloned at the pinned
# tag rather than pip/pipx-installed because its pyproject packages the
# enum_tools/ code but does NOT declare enum_tools/fuzz.txt (the default mutation
# wordlist) as package data, so a wheel build would silently drop the brute list.
# The wrapper runs the script by absolute path; cloud_enum resolves
# enum_tools/fuzz.txt relative to sys.argv[0], so no cwd handling is required.
RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      git init /opt/cloud_enum && \
      git -C /opt/cloud_enum remote add origin https://github.com/initstring/cloud_enum.git && \
      git -C /opt/cloud_enum fetch --depth 1 origin "refs/tags/${CLOUD_ENUM_VERSION}" && \
      git -C /opt/cloud_enum checkout --detach FETCH_HEAD && \
      python3 -m venv /opt/cloud_enum-venv && \
      /opt/cloud_enum-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/cloud_enum-venv/bin/pip install --no-cache-dir dnspython requests requests-futures && \
      printf '%s\n' '#!/bin/sh' 'exec /opt/cloud_enum-venv/bin/python /opt/cloud_enum/cloud_enum.py "$@"' \
        > /usr/local/bin/cloud_enum && \
      chmod +x /usr/local/bin/cloud_enum && \
      cloud_enum --help >/dev/null; \
    fi

# jwt_tool (ticarpi) — cloned at a pinned tag + venv + /usr/local/bin/jwt_tool
# wrapper, mirroring the cloud_enum pattern (its repo is not packaged for
# pip/pipx). On first run jwt_tool writes ~/.jwt_tool/jwtconf.ini and then
# exit(1)s for config review, so we pre-generate the config at build time (the
# bare run below, tolerated via `|| true`) — otherwise the FIRST in-engagement
# invocation would be consumed by config setup instead of testing the token.
# The `--help` run after the config exists is the real exit-0 smoke test.
RUN set -eux; \
    if [ "$PRELOADED_TOOLS" != "1" ]; then \
      git init /opt/jwt_tool && \
      git -C /opt/jwt_tool remote add origin https://github.com/ticarpi/jwt_tool.git && \
      git -C /opt/jwt_tool fetch --depth 1 origin "refs/tags/${JWT_TOOL_VERSION}" && \
      git -C /opt/jwt_tool checkout --detach FETCH_HEAD && \
      python3 -m venv /opt/jwt_tool-venv && \
      /opt/jwt_tool-venv/bin/pip install --no-cache-dir "pip==${PIP_VERSION}" && \
      /opt/jwt_tool-venv/bin/pip install --no-cache-dir termcolor cprint pycryptodomex requests ratelimit && \
      printf '%s\n' '#!/bin/sh' 'exec /opt/jwt_tool-venv/bin/python /opt/jwt_tool/jwt_tool.py "$@"' \
        > /usr/local/bin/jwt_tool && \
      chmod +x /usr/local/bin/jwt_tool && \
      ( jwt_tool >/dev/null 2>&1 || true ) && \
      test -f /root/.jwt_tool/jwtconf.ini && \
      jwt_tool --help >/dev/null; \
    fi

# selenium (system python3) — drives the apt-installed chromium + chromium-driver
# for `vigil assess kali browser`, the headless-render / JS-bot-challenge recovery
# path. The browser driver runs as the SYSTEM `python3 -c ...` (so it can find
# /usr/bin/chromium + /usr/bin/chromedriver), so selenium must live in the system
# interpreter rather than a venv. Kali's system python is PEP-668 externally-
# managed, hence --break-system-packages.
ARG SELENIUM_VERSION=4.27.1
RUN if [ "$PRELOADED_TOOLS" != "1" ]; then \
      pip3 install --no-cache-dir --break-system-packages "selenium==${SELENIUM_VERSION}" && \
      python3 -c "import selenium; print('selenium', selenium.__version__)"; \
    fi

RUN mkdir -p /opt/mcp-tools /data
COPY docker/callback_listener.py /opt/mcp-tools/callback_listener.py
COPY docker/start-callback.sh /usr/local/bin/start-callback
RUN chmod +x /usr/local/bin/start-callback
RUN printf '%s\n' 'export PATH="/opt/Responder:/opt/offsec-venv/bin:/opt/mitmproxy-venv/bin:/opt/pwncat-venv/bin:$PATH"' > /etc/profile.d/vigil-path.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD command -v dtach >/dev/null && command -v katana >/dev/null && command -v trufflehog >/dev/null && command -v gf >/dev/null && command -v jsluice >/dev/null && command -v arjun >/dev/null && command -v xmllint >/dev/null && command -v apkeep >/dev/null && command -v apktool >/dev/null && command -v jadx >/dev/null && command -v adb >/dev/null && command -v bundletool >/dev/null && command -v apksigner >/dev/null && command -v aapt >/dev/null && command -v curl_chrome116 >/dev/null && command -v jwt_tool >/dev/null || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["bash", "-lc", "mkdir -p /data && exec sleep infinity"]
