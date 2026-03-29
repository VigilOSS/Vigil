#!/bin/bash
# install.sh — AI Threat Hunting installation script
#
# Usage:
#   ./install.sh claude [target_dir]
#   ./install.sh codex [target_dir]
#   ./install.sh --dry-run claude
#
# Supported platforms: macOS and Linux only.
set -euo pipefail

show_help() {
  cat <<'EOF'
Usage: ./install.sh [--dry-run] [--force] <claude|codex> [target_dir]

  claude  Install the Claude Code workflow files
  codex   Install the Codex workflow files

Options:
  --dry-run  Validate the install without writing files
  --force    Rebuild the shared Kali MCP runtime image during install
  -h, --help Show this help
EOF
}

DRY_RUN=false
FORCE_REBUILD=false
PRODUCT=""
TARGET_DIR=""
SKIP_PREREQ_CHECKS="${AI_THREAT_HUNTING_SKIP_PREREQ_CHECKS:-${REDTEAM_SKIP_PREREQ_CHECKS:-0}}"
SKIP_DOCKER_IMAGE_CHECKS="${AI_THREAT_HUNTING_SKIP_DOCKER_IMAGE_CHECKS:-${REDTEAM_SKIP_DOCKER_IMAGE_CHECKS:-0}}"

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --force) FORCE_REBUILD=true ;;
    -h|--help) show_help; exit 0 ;;
    claude|codex) PRODUCT="$arg" ;;
    *) [ -z "$TARGET_DIR" ] && TARGET_DIR="$arg" ;;
  esac
done

if [ -z "$PRODUCT" ]; then
  show_help
  exit 1
fi

INSTALL_DIR="${TARGET_DIR:-${AI_THREAT_HUNTING_DIR:-${REDTEAM_DIR:-$HOME/security-research}}}"
SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_ROOT="$SOURCE_ROOT/agent"

if [ ! -d "$AGENT_ROOT" ]; then
  echo "agent/ directory not found next to install.sh" >&2
  exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${BLUE}[INFO]${NC} $1"; }

ERRORS=0

copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$dest")"
    cp -a "$src" "$dest"
  fi
}

echo ""
if $DRY_RUN; then
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   AI Threat Hunting — DRY RUN ($PRODUCT)                    ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
else
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   AI Threat Hunting — Install for $PRODUCT                  ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
fi
echo ""

echo "Step 1: Checking prerequisites..."
echo ""

if [ "$SKIP_PREREQ_CHECKS" = "1" ]; then
  warn "Skipping prerequisite checks (AI_THREAT_HUNTING_SKIP_PREREQ_CHECKS=1)"
else
  for tool in docker git python3; do
    if command -v "$tool" >/dev/null 2>&1; then
      ok "$tool"
    else
      fail "$tool not installed"
      ERRORS=$((ERRORS + 1))
    fi
  done

  if [ "$PRODUCT" = "claude" ] && ! command -v claude >/dev/null 2>&1; then
    fail "Claude Code not installed"
    ERRORS=$((ERRORS + 1))
  fi
  if [ "$PRODUCT" = "codex" ] && ! command -v codex >/dev/null 2>&1; then
    fail "Codex not installed"
    ERRORS=$((ERRORS + 1))
  fi

  if docker info >/dev/null 2>&1; then
    ok "Docker daemon is running"
  else
    fail "Docker daemon is not running"
    ERRORS=$((ERRORS + 1))
  fi

  if [ $ERRORS -gt 0 ]; then
    fail "$ERRORS prerequisite(s) missing."
    exit 1
  fi
fi

echo ""
echo "Step 2: Installing files to $INSTALL_DIR ..."
echo ""

if $DRY_RUN; then
  info "[DRY RUN] Would install to $INSTALL_DIR"
else
  mkdir -p "$INSTALL_DIR"

  if [ -d "$INSTALL_DIR/.claude" ] || [ -d "$INSTALL_DIR/.codex" ] || [ -d "$INSTALL_DIR/agent" ] || [ -d "$INSTALL_DIR/docker" ] || [ -f "$INSTALL_DIR/install.sh" ]; then
    warn "Existing installation detected in $INSTALL_DIR — upgrading"
    for keep in engagements .env auth.json workspace runtime-home; do
      [ -e "$INSTALL_DIR/$keep" ] && mv "$INSTALL_DIR/$keep" "/tmp/security-research-preserve-$keep" 2>/dev/null
    done
    rm -rf "$INSTALL_DIR/.claude" "$INSTALL_DIR/.codex" "$INSTALL_DIR/agent" "$INSTALL_DIR/docker" \
           "$INSTALL_DIR/orchestrator" "$INSTALL_DIR/tests" \
           "$INSTALL_DIR/README.md" "$INSTALL_DIR/install.sh"
    for keep in engagements .env auth.json workspace runtime-home; do
      [ -e "/tmp/security-research-preserve-$keep" ] && mv "/tmp/security-research-preserve-$keep" "$INSTALL_DIR/$keep" 2>/dev/null
    done
  fi

  case "$PRODUCT" in
    claude)
      copy_if_exists "$AGENT_ROOT/.claude" "$INSTALL_DIR/.claude"
      copy_if_exists "$AGENT_ROOT/CLAUDE.md" "$INSTALL_DIR/CLAUDE.md"
      ;;
    codex)
      copy_if_exists "$AGENT_ROOT/.codex" "$INSTALL_DIR/.codex"
      copy_if_exists "$AGENT_ROOT/AGENTS.md" "$INSTALL_DIR/AGENTS.md"
      ;;
  esac

  for path in README.md docker orchestrator tests agent install.sh; do
    copy_if_exists "$SOURCE_ROOT/$path" "$INSTALL_DIR/$path"
  done

  case "$PRODUCT" in
    claude)
      rm -rf "$INSTALL_DIR/agent/.codex"
      rm -f "$INSTALL_DIR/agent/AGENTS.md"
      ;;
    codex)
      rm -rf "$INSTALL_DIR/agent/.claude"
      rm -f "$INSTALL_DIR/agent/CLAUDE.md"
      ;;
  esac

  if [ -f "$AGENT_ROOT/.env.example" ] && [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$AGENT_ROOT/.env.example" "$INSTALL_DIR/.env"
    warn "Created $INSTALL_DIR/.env from template — update tokens and API keys before scanning"
  fi

  if [ -d "$INSTALL_DIR/agent/scripts" ]; then
    chmod +x "$INSTALL_DIR/agent/scripts/"*.sh "$INSTALL_DIR/agent/scripts/lib/"*.sh "$INSTALL_DIR/agent/scripts/hooks/"*.sh 2>/dev/null || true
    ok "Script permissions set"
  fi
fi

echo ""
echo "Step 3: Runtime image verification..."
echo ""

if $DRY_RUN; then
  info "[DRY RUN] Would build or verify the primary security-research image"
elif [ "$SKIP_DOCKER_IMAGE_CHECKS" = "1" ]; then
  warn "Skipping Docker image build/verification (AI_THREAT_HUNTING_SKIP_DOCKER_IMAGE_CHECKS=1)"
else
  cd "$INSTALL_DIR"
  if $FORCE_REBUILD || ! docker inspect --type image security-research:latest >/dev/null 2>&1; then
    info "Building security-research runtime image..."
    if docker build -t security-research:latest -f agent/docker/runtime-full/Dockerfile .; then
      ok "security-research image ready"
    else
      fail "Failed to build security-research image"
      exit 1
    fi
  else
    ok "security-research image already exists"
  fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo -e "${GREEN}Installation complete! (${PRODUCT})${NC}"
echo ""
echo "  Installed to: $INSTALL_DIR"
echo ""
echo "  Next steps:"
echo "    Use only against fully authorized realistic lab environments."
echo "    Configure shared runtime env in $INSTALL_DIR/.env as needed"
echo "    cd $INSTALL_DIR"
echo "    ./agent/scripts/start_kali_mcp_runtime.sh"
case "$PRODUCT" in
  claude)
    echo "    claude mcp add kali -s user -- docker exec -i security-research mcp-server"
    echo "    claude"
    ;;
  codex)
    echo "    codex mcp add kali -- docker exec -i security-research mcp-server"
    echo "    codex"
    ;;
esac
echo "    cd agent && ./scripts/init_engagement.sh https://target.example"
echo ""
