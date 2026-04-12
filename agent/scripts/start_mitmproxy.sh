#!/usr/bin/env bash
# Launch the mitmproxy session-capture container.
# CA keys are stored in a named Docker volume so restarts do not invalidate
# the certificate the operator has already trusted in their system keychain.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
AGENT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONTAINER_NAME="security-research-proxy"
IMAGE_NAME="security-research-proxy:latest"
VOLUME_NAME="mitmproxy-ca"
PORT="${MITMPROXY_PORT:-8080}"

# ── Resolve engagement directory ──────────────────────────────────────────
if [[ -n "${ENGAGEMENT_DIR:-}" ]]; then
    ENG_DIR="$ENGAGEMENT_DIR"
elif [[ -f "./scope.json" ]]; then
    ENG_DIR="$(pwd)"
else
    echo "Usage: ENGAGEMENT_DIR=/path/to/engagement $0" >&2
    echo "  or run from inside an engagement directory." >&2
    exit 1
fi

# ── Ensure image exists ──────────────────────────────────────────────────
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "[mitmproxy] Building image..."
    docker build -t "$IMAGE_NAME" -f "$AGENT_ROOT/docker/mitmproxy/Dockerfile" "$AGENT_ROOT"
fi

# ── Stop stale container if running ──────────────────────────────────────
if docker ps -q --filter "name=$CONTAINER_NAME" | grep -q .; then
    echo "[mitmproxy] Stopping existing container..."
    docker stop "$CONTAINER_NAME" >/dev/null 2>&1 || true
    sleep 1
fi
# Clean up stopped container (without --rm the container persists)
docker rm "$CONTAINER_NAME" >/dev/null 2>&1 || true

# ── Create named volume for CA keys (idempotent) ─────────────────────────
docker volume create "$VOLUME_NAME" >/dev/null 2>&1 || true

# ── Detect orchestrator URL ──────────────────────────────────────────────
ORCH_URL=""
if [[ -f "$ENG_DIR/.orchestrator.env" ]]; then
    ORCH_URL="$(grep -E '^ORCHESTRATOR_BASE_URL=' "$ENG_DIR/.orchestrator.env" | cut -d= -f2-)"
    # Rewrite localhost for Docker-to-host connectivity
    ORCH_URL="${ORCH_URL//127.0.0.1/host.docker.internal}"
    ORCH_URL="${ORCH_URL//localhost/host.docker.internal}"
fi

# ── Launch ────────────────────────────────────────────────────────────────
echo "[mitmproxy] Starting on port $PORT (engagement: $ENG_DIR)"
docker run -d \
    --name "$CONTAINER_NAME" \
    -p "127.0.0.1:${PORT}:8080" \
    -v "$ENG_DIR:/engagement" \
    -v "${VOLUME_NAME}:/root/.mitmproxy" \
    ${ORCH_URL:+-e "ORCHESTRATOR_BASE_URL=$ORCH_URL"} \
    "$IMAGE_NAME" \
    --set engagement_dir=/engagement \
    --set block_global=false

# ── Wait for startup ─────────────────────────────────────────────────────
sleep 2
if ! docker ps -q --filter "name=$CONTAINER_NAME" | grep -q .; then
    echo "[mitmproxy] ERROR: container failed to start. Logs:" >&2
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20 >&2
    exit 1
fi

echo "[mitmproxy] Running. Configure browser proxy: HTTP 127.0.0.1:${PORT}"
echo ""
echo "If this is first run, install the CA certificate:"
echo "  1. Navigate to http://mitm.it (HTTP, not HTTPS) in your proxied browser"
echo "  2. Download and install the macOS cert"
echo "  3. Open Keychain Access > search 'mitmproxy' > set trust to 'Always Trust'"
echo "  OR run:"
echo "    docker cp ${CONTAINER_NAME}:/root/.mitmproxy/mitmproxy-ca-cert.pem ~/Desktop/mitmproxy-ca-cert.pem"
echo "    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/Desktop/mitmproxy-ca-cert.pem"
echo ""
echo "The CA keys are stored in Docker volume '${VOLUME_NAME}' — restarts will reuse the same cert."
