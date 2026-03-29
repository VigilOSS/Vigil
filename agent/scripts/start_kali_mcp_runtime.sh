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

usage() {
  cat <<'EOF'
Usage: ./scripts/start_kali_mcp_runtime.sh [--recreate]

Starts the shared Kali MCP runtime container.

Environment:
  REDTEAM_IMAGE               Runtime image to start (default: security-research:latest)
  KALI_MCP_CONTAINER_NAME     Container name (default: security-research)
  KALI_MCP_DATA_DIR           Host path mounted to /data (default: ../.runtime-data)

The root .env file is sourced before startup so shell-side defaults apply, then
passed to docker with --env-file so the same values are available inside the
runtime container.
EOF
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

if ! docker inspect --type image "$IMAGE" >/dev/null 2>&1; then
  echo "[runtime] Missing image: $IMAGE" >&2
  echo "[runtime] Build it first, for example:" >&2
  echo "  docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile ." >&2
  exit 1
fi

mkdir -p "$DATA_DIR"

if docker ps --format '{{.Names}}' | grep -qx "$CONTAINER_NAME"; then
  if [[ "$RECREATE" -eq 0 ]]; then
    echo "[runtime] Shared Kali MCP runtime already running: $CONTAINER_NAME"
    echo "[runtime] Shared data mount: $DATA_DIR"
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
)

if [[ -f "$ROOT_DIR/.env" ]]; then
  docker_args+=(--env-file "$ROOT_DIR/.env")
fi

docker_args+=("$IMAGE")

docker "${docker_args[@]}" >/dev/null

echo "[runtime] Shared Kali MCP runtime started: $CONTAINER_NAME"
echo "[runtime] Shared data mount: $DATA_DIR"
echo "[runtime] Attach client MCP to: docker exec -i $CONTAINER_NAME mcp-server"
