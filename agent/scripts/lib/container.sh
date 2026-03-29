#!/bin/bash
# scripts/lib/container.sh — deprecated helper shim
# This repo no longer supports repo-local target execution helpers.
# All in-scope target-facing work must run through the attached Kali MCP tools.

REDTEAM_IMAGE="${REDTEAM_IMAGE:-security-research:latest}"
PROXY_IMAGE="${PROXY_IMAGE:-security-research-proxy:latest}"
KATANA_IMAGE="${KATANA_IMAGE:-$REDTEAM_IMAGE}"

_deprecated_helper() {
    local helper="$1"
    cat >&2 <<EOF
${helper} is no longer supported from repo-local shell helpers.
Use the attached Kali MCP tools for all target-facing execution.
Use the Kali MCP command-execution tool when you need to run an arbitrary
binary or shell pipeline inside the runtime.
EOF
    return 1
}

start_proxy() {
    _deprecated_helper "start_proxy"
}

stop_proxy() {
    _deprecated_helper "stop_proxy"
}

start_katana() {
    _deprecated_helper "start_katana"
}

stop_katana() {
    _deprecated_helper "stop_katana"
}

stop_all_containers() {
    _deprecated_helper "stop_all_containers"
}

check_images() {
    local all_ok=true
    local required_images=("$REDTEAM_IMAGE" "$PROXY_IMAGE")
    if [ "$KATANA_IMAGE" != "$REDTEAM_IMAGE" ] && [ -n "$KATANA_IMAGE" ]; then
        required_images+=("$KATANA_IMAGE")
    fi
    for img in "${required_images[@]}"; do
        if docker inspect --type image "$img" >/dev/null 2>&1; then
            echo "[OK] $img"
        else
            echo "[MISSING] $img"
            all_ok=false
        fi
    done
    if [ "$all_ok" = false ]; then
        echo ""
        echo "Build missing images: docker compose -f agent/docker/docker-compose.yml build runtime-full mitmproxy"
        return 1
    fi
    return 0
}

check_docker() {
    if ! command -v docker >/dev/null 2>&1; then
        echo "ERROR: Docker is not installed" >&2
        return 1
    fi
    if ! docker info >/dev/null 2>&1; then
        echo "ERROR: Docker daemon is not running" >&2
        return 1
    fi
    echo "[OK] Docker is available"
    return 0
}
