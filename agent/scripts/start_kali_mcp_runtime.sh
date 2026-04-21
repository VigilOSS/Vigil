#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
AGENT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
ROOT_DIR=$(cd "$AGENT_DIR/.." && pwd)
ENV_FILE="$ROOT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  . "$ENV_FILE"
  set +a
fi

IMAGE="${REDTEAM_IMAGE:-security-research:latest}"
CONTAINER_NAME="${KALI_MCP_CONTAINER_NAME:-security-research}"
DATA_DIR="${KALI_MCP_DATA_DIR:-$ROOT_DIR/.runtime-data}"
RECREATE=0
REQUIRED_TOOLS=(mcp-server katana gau nuclei httpx trufflehog gf uro)
REQUIRED_FILES=(
  /opt/mcp-tools/patched_kali_server.py
  /opt/mcp-tools/patched_kali_client.py
  /opt/mcp-tools/kali_mcp_audit.py
)

usage() {
  cat <<'EOF'
Usage: ./scripts/start_kali_mcp_runtime.sh [--recreate]

Starts the shared Kali MCP runtime container.

Environment:
  REDTEAM_IMAGE               Runtime image to start (default: security-research:latest)
  KALI_MCP_CONTAINER_NAME     Container name (default: security-research)
  KALI_MCP_DATA_DIR           Host path mounted to /data (default: ../.runtime-data)

Mounts:
  $KALI_MCP_DATA_DIR -> /data           shared-infra state (OOB logs, pwncat sessions, frpc config)
  $AGENT_DIR/engagements -> /engagements  per-engagement artifact tree; skills read/write
                                         /engagements/<engagement_key>/... inside the container

The root .env file is sourced before startup so shell-side defaults apply, then
passed to docker with --env-file so the same values are available inside the
runtime container.
EOF
}

validate_runtime_tools() {
  local missing=()
  local tool
  local file
  for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! docker exec "$CONTAINER_NAME" sh -lc "command -v '$tool' >/dev/null" >/dev/null 2>&1; then
      missing+=("$tool")
    fi
  done
  for file in "${REQUIRED_FILES[@]}"; do
    if ! docker exec "$CONTAINER_NAME" test -f "$file" >/dev/null 2>&1; then
      missing+=("$file")
    fi
  done

  if [[ "${#missing[@]}" -gt 0 ]]; then
    echo "[runtime] Runtime tool validation failed for container: $CONTAINER_NAME" >&2
    echo "[runtime] Missing required tools/files: ${missing[*]}" >&2
    echo "[runtime] The local image is likely stale relative to the checked-in Dockerfile." >&2
    echo "[runtime] Rebuild and recreate the runtime, for example:" >&2
    echo "  docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile ." >&2
    echo "  ./agent/scripts/start_kali_mcp_runtime.sh --recreate" >&2
    exit 1
  fi

  # The /engagements bind mount is the contract skills rely on when writing
  # /engagements/<engagement_key>/scans/... from inside Kali MCP. If it is
  # missing the container was started by a stale launcher; fail loud so the
  # operator recreates rather than silently writing to an ephemeral path.
  if ! docker exec "$CONTAINER_NAME" test -d /engagements >/dev/null 2>&1; then
    echo "[runtime] /engagements mount missing inside container: $CONTAINER_NAME" >&2
    echo "[runtime] Recreate the runtime so the new bind mount is applied:" >&2
    echo "  ./agent/scripts/start_kali_mcp_runtime.sh --recreate" >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --recreate)
      RECREATE=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if ! docker inspect --type image "$IMAGE" >/dev/null 2>&1 \
   && ! docker image inspect "$IMAGE" >/dev/null 2>&1 \
   && [ -z "$(docker images -q "$IMAGE" 2>/dev/null)" ]; then
  echo "[runtime] Missing image: $IMAGE" >&2
  echo "[runtime] Build it first, for example:" >&2
  echo "  docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile ." >&2
  exit 1
fi

mkdir -p "$DATA_DIR"
# Pre-create the engagements tree on the host so the bind mount below does
# not materialize a root-owned directory inside the container on first run.
mkdir -p "$AGENT_DIR/engagements"

if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  if [[ "$RECREATE" -eq 0 ]]; then
    echo "[runtime] Shared Kali MCP runtime already running: $CONTAINER_NAME"
    echo "[runtime] Shared data mount: $DATA_DIR"
    echo "[runtime] Engagements mount: $AGENT_DIR/engagements -> /engagements"
    validate_runtime_tools
    exit 0
  fi
fi

if docker ps -a --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
fi

docker_args=(
  run -d
  --name "$CONTAINER_NAME"
  --restart unless-stopped
  --cap-add=NET_RAW
  --cap-add=NET_ADMIN
  -v "$DATA_DIR:/data"
  # Expose every engagement directory as /engagements/<engagement_key>/...
  # inside the container so Kali MCP commands can read/write scans, tools,
  # and downloads directly — the skills use /engagements/$ENGAGEMENT_KEY/...
  # as the single canonical path on the Kali side.
  -v "$AGENT_DIR/engagements:/engagements"
  # Docker Desktop on macOS/Windows resolves host.docker.internal
  # automatically; on Linux the alias must be set explicitly. Adding
  # the flag unconditionally is safe on all three platforms.
  --add-host=host.docker.internal:host-gateway
)

if [[ -f "$ROOT_DIR/.env" ]]; then
  docker_args+=(--env-file "$ROOT_DIR/.env")
fi

# Audit POSTs from inside the container MUST reach the orchestrator running
# on the host, not the container's own loopback. Rewrite loopback literals
# to host.docker.internal so a stale .env with 127.0.0.1:18000 still
# works. Default value matches the orchestrator's default bind port.
ORCHESTRATOR_URL_FOR_CONTAINER="${ORCHESTRATOR_BASE_URL:-http://host.docker.internal:18000}"
ORCHESTRATOR_URL_FOR_CONTAINER="${ORCHESTRATOR_URL_FOR_CONTAINER//127.0.0.1/host.docker.internal}"
ORCHESTRATOR_URL_FOR_CONTAINER="${ORCHESTRATOR_URL_FOR_CONTAINER//localhost/host.docker.internal}"
docker_args+=(-e "ORCHESTRATOR_BASE_URL=${ORCHESTRATOR_URL_FOR_CONTAINER}")

docker_args+=("$IMAGE")

docker "${docker_args[@]}" >/dev/null

validate_runtime_tools

echo "[runtime] Shared Kali MCP runtime started: $CONTAINER_NAME"
echo "[runtime] Shared data mount: $DATA_DIR"
echo "[runtime] Engagements mount: $AGENT_DIR/engagements -> /engagements"
echo "[runtime] Attach client MCP to: docker exec -i $CONTAINER_NAME mcp-server"
