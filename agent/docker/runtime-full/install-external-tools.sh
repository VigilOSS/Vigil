#!/usr/bin/env bash
set -Eeuo pipefail

if [[ "${PRELOADED_TOOLS:-0}" == "1" ]]; then
  exit 0
fi

log() {
  printf '==> %s\n' "$*" >&2
}

retry() {
  local attempt
  local -a args=("$@")
  for attempt in 1 2 3; do
    if "${args[@]}"; then
      return 0
    fi
    printf 'WARN: command failed on attempt %s/3:' "$attempt" >&2
    printf ' %q' "${args[@]}" >&2
    printf '\n' >&2
    sleep $((attempt * 2))
  done
  return 1
}

copy_go_binary() {
  local binary="$1"
  install -m 0755 "/root/go/bin/${binary}" "/usr/local/bin/${binary}"
  command -v "${binary}" >/dev/null
}

go_install() {
  local binary="$1"
  local module="$2"
  local version="$3"

  log "go install ${binary} ${version}"
  GOPATH=/root/go retry go install "${module}@${version}"
  copy_go_binary "${binary}"
}

install_go_tools() {
  go_install nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei "${NUCLEI_VERSION}"
  log "go install katana ${KATANA_VERSION}"
  GO111MODULE=on GOPATH=/root/go retry go install "github.com/projectdiscovery/katana/cmd/katana@${KATANA_VERSION}"
  copy_go_binary katana
  go_install httpx github.com/projectdiscovery/httpx/cmd/httpx "${HTTPX_VERSION}"
  go_install dnsx github.com/projectdiscovery/dnsx/cmd/dnsx "${DNSX_VERSION}"
  go_install gau github.com/lc/gau/v2/cmd/gau "${GAU_VERSION}"
  go_install dalfox github.com/hahwul/dalfox/v2 "${DALFOX_VERSION}"
  go_install puredns github.com/d3mondev/puredns/v2 "${PUREDNS_VERSION}"
  go_install shuffledns github.com/projectdiscovery/shuffledns/cmd/shuffledns "${SHUFFLEDNS_VERSION}"
  go_install alterx github.com/projectdiscovery/alterx/cmd/alterx "${ALTERX_VERSION}"
  go_install asnmap github.com/projectdiscovery/asnmap/cmd/asnmap "${ASNMAP_VERSION}"
  go_install cero github.com/glebarez/cero "${CERO_VERSION}"
  go_install gf github.com/tomnomnom/gf "${GF_VERSION}"
  go_install jsluice github.com/BishopFox/jsluice/cmd/jsluice "${JSLUICE_VERSION}"
  rm -rf /root/go
}

install_gf_patterns() {
  local tmp=/tmp/gf-patterns
  rm -rf "${tmp}"
  mkdir -p /root/.gf

  log "fetch gf patterns ${GF_PATTERNS_REF}"
  git init "${tmp}"
  git -C "${tmp}" remote add origin https://github.com/1ndianl33t/Gf-Patterns
  retry git -C "${tmp}" fetch --depth 1 origin "${GF_PATTERNS_REF}"
  git -C "${tmp}" checkout --detach FETCH_HEAD

  shopt -s nullglob
  local patterns=("${tmp}"/*.json)
  if [[ "${#patterns[@]}" -eq 0 ]]; then
    echo "No gf pattern JSON files found at ${GF_PATTERNS_REF}" >&2
    return 1
  fi
  cp "${patterns[@]}" /root/.gf/
  rm -rf "${tmp}"
}

install_feroxbuster() {
  local arch ferox_arch tmp
  arch="$(dpkg --print-architecture)"
  case "${arch}" in
    amd64) ferox_arch=x86_64 ;;
    arm64) ferox_arch=aarch64 ;;
    *) echo "Unsupported architecture: ${arch}" >&2; exit 1 ;;
  esac

  tmp=/tmp/ferox
  rm -rf "${tmp}"
  mkdir -p "${tmp}"
  log "download feroxbuster ${FEROXBUSTER_VERSION} for ${ferox_arch}"
  curl -fsSL ${CURL_RETRY_FLAGS:-} \
    "https://github.com/epi052/feroxbuster/releases/download/v${FEROXBUSTER_VERSION}/${ferox_arch}-linux-feroxbuster.zip" \
    -o "${tmp}/ferox.zip"
  unzip "${tmp}/ferox.zip" -d "${tmp}"
  install -m 0755 "${tmp}/feroxbuster" /usr/local/bin/feroxbuster
  command -v feroxbuster >/dev/null
  rm -rf "${tmp}"
}

usage() {
  cat >&2 <<'EOF'
Usage: install-external-tools.sh <go-tools|gf-patterns|feroxbuster>
EOF
}

case "${1:-}" in
  go-tools) install_go_tools ;;
  gf-patterns) install_gf_patterns ;;
  feroxbuster) install_feroxbuster ;;
  *) usage; exit 2 ;;
esac
