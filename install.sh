#!/bin/bash
# install.sh — AI Threat Hunting installation script
#
# Usage:
#   ./install.sh [target_dir]
#   ./install.sh --dry-run
#
# This installer provisions workflows for authorized realistic lab environments only.
# Supported platforms: macOS and Linux only.
set -euo pipefail

show_help() {
  cat <<'EOF'
Usage: ./install.sh [--dry-run] [--force] [target_dir]

Options:
  --dry-run  Validate the install without writing files
  --force    Rebuild the shared Kali MCP runtime image during install
  -h, --help Show this help
EOF
}

DRY_RUN=false
FORCE_REBUILD=false
TARGET_DIR=""
SKIP_PREREQ_CHECKS="${AI_THREAT_HUNTING_SKIP_PREREQ_CHECKS:-${REDTEAM_SKIP_PREREQ_CHECKS:-0}}"
SKIP_DOCKER_IMAGE_CHECKS="${AI_THREAT_HUNTING_SKIP_DOCKER_IMAGE_CHECKS:-${REDTEAM_SKIP_DOCKER_IMAGE_CHECKS:-0}}"

for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    --force) FORCE_REBUILD=true ;;
    -h|--help) show_help; exit 0 ;;
    claude|codex)
      echo "Client arguments were removed; install.sh now installs both Codex and Claude workflow files." >&2
      show_help >&2
      exit 1
      ;;
    *)
      if [ -z "$TARGET_DIR" ]; then
        TARGET_DIR="$arg"
      else
        echo "Unexpected extra argument: $arg" >&2
        show_help >&2
        exit 1
      fi
      ;;
  esac
done

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
UPGRADE_IN_PROGRESS=false

cleanup_on_failure() {
  if $UPGRADE_IN_PROGRESS; then
    echo "" >&2
    warn "Install interrupted during upgrade."
    info "User data (engagements, database) was not moved or deleted."
    info "Re-run the installer to complete the upgrade."
  fi
}
trap cleanup_on_failure EXIT

# copy_if_exists: copy src to dest. If dest is an existing directory, remove it
# first to prevent cp -a from nesting (cp -a dir/ existing_dir/ → existing_dir/dir/).
copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [ -e "$src" ]; then
    mkdir -p "$(dirname "$dest")"
    if [ -d "$src" ] && [ -d "$dest" ]; then
      rm -rf "$dest" 2>/dev/null || true
      # macOS race: Spotlight/Finder can hold files briefly — retry once
      if [ -d "$dest" ]; then
        sleep 0.5
        rm -rf "$dest" 2>/dev/null || true
      fi
      # If dest still exists after retries, copy contents into it
      if [ -d "$dest" ]; then
        cp -a "$src/." "$dest/"
        return
      fi
    fi
    cp -a "$src" "$dest"
  fi
}

# rm_retry: remove a path with one macOS retry on transient "Directory not empty".
rm_retry() {
  rm -rf "$1" 2>/dev/null || true
  if [ -e "$1" ]; then
    sleep 0.5
    rm -rf "$1" 2>/dev/null || true
  fi
}

# copy_children_except: copy each immediate child of src_dir into dest_dir,
# skipping any basenames listed in the remaining arguments.
copy_children_except() {
  local src_dir="$1"
  local dest_dir="$2"
  shift 2
  local -a excludes=()
  if [ $# -gt 0 ]; then excludes=("$@"); fi

  mkdir -p "$dest_dir"

  local child name skip exc
  for child in "$src_dir"/* "$src_dir"/.*; do
    [ -e "$child" ] || continue
    name="$(basename "$child")"
    [ "$name" = "." ] || [ "$name" = ".." ] && continue
    skip=false
    for exc in "${excludes[@]+"${excludes[@]}"}"; do
      if [ "$name" = "$exc" ]; then
        skip=true
        break
      fi
    done
    $skip && continue
    copy_if_exists "$child" "$dest_dir/$name"
  done
}

# remove_children_except: delete each immediate child of dir except named basenames.
remove_children_except() {
  local dir="$1"
  shift
  local -a excludes=()
  if [ $# -gt 0 ]; then excludes=("$@"); fi

  [ -d "$dir" ] || return 0

  local child name skip exc
  for child in "$dir"/* "$dir"/.*; do
    [ -e "$child" ] || continue
    name="$(basename "$child")"
    [ "$name" = "." ] || [ "$name" = ".." ] && continue
    skip=false
    for exc in "${excludes[@]+"${excludes[@]}"}"; do
      if [ "$name" = "$exc" ]; then
        skip=true
        break
      fi
    done
    $skip && continue
    rm_retry "$child"
  done
}

echo ""
if $DRY_RUN; then
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   AI Threat Hunting — DRY RUN                               ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
else
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║   AI Threat Hunting — Install                               ║"
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

  if ! command -v claude >/dev/null 2>&1; then
    fail "Claude Code not installed"
    ERRORS=$((ERRORS + 1))
  fi
  if ! command -v codex >/dev/null 2>&1; then
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

IS_UPGRADE=false

if $DRY_RUN; then
  info "[DRY RUN] Would install to $INSTALL_DIR"
else
  mkdir -p "$INSTALL_DIR"

  RESOLVED_SOURCE="$(cd "$SOURCE_ROOT" && pwd -P)"
  RESOLVED_INSTALL="$(cd "$INSTALL_DIR" && pwd -P)"

  if [ "$RESOLVED_SOURCE" = "$RESOLVED_INSTALL" ]; then
    info "Source and install directories are the same — skipping file copy"
  else

  if [ -d "$INSTALL_DIR/.claude" ] || [ -d "$INSTALL_DIR/.codex" ] || [ -d "$INSTALL_DIR/agent" ] || [ -d "$INSTALL_DIR/docker" ] || [ -f "$INSTALL_DIR/install.sh" ]; then
    IS_UPGRADE=true
    UPGRADE_IN_PROGRESS=true
    warn "Existing installation detected in $INSTALL_DIR — upgrading"

    # Warn if the orchestrator backend appears to be running
    if command -v lsof >/dev/null 2>&1 && lsof -ti :18000 >/dev/null 2>&1; then
      warn "Orchestrator backend appears to be running on port 18000"
      info "The database is preserved in place, but consider restarting the backend after the upgrade."
    fi

    # ── Selective cleanup ──────────────────────────────────────────
    # Remove managed code while leaving user data (engagements, DB,
    # .env, runtime-data) untouched on disk.  This avoids the inode-
    # replacement problem: a running backend keeps the old DB inode
    # open, so moving/deleting the file causes silent data loss.

    # Root-level managed files
    for _f in README.md install.sh CLAUDE.md AGENTS.md; do
      rm -f "$INSTALL_DIR/$_f" 2>/dev/null || true
    done

    # Directories that contain no user data — delete entirely
    for _d in .claude .codex docker tests; do
      rm_retry "$INSTALL_DIR/$_d"
    done

    # agent/: remove everything except engagements/
    remove_children_except "$INSTALL_DIR/agent" engagements

    # orchestrator/: remove everything except backend/
    remove_children_except "$INSTALL_DIR/orchestrator" backend
    # orchestrator/backend/: remove everything except data/
    remove_children_except "$INSTALL_DIR/orchestrator/backend" data
  fi
    copy_if_exists "$AGENT_ROOT/.claude" "$INSTALL_DIR/.claude"
    copy_if_exists "$AGENT_ROOT/.codex" "$INSTALL_DIR/.codex"
    copy_if_exists "$AGENT_ROOT/CLAUDE.md" "$INSTALL_DIR/CLAUDE.md"
    copy_if_exists "$AGENT_ROOT/AGENTS.md" "$INSTALL_DIR/AGENTS.md"

    if $IS_UPGRADE; then
      # Copy managed paths, skipping user-data directories in place
      for _path in README.md docker tests install.sh; do
        copy_if_exists "$SOURCE_ROOT/$_path" "$INSTALL_DIR/$_path"
      done

      # agent/: copy all children except engagements/ (kept in place)
      copy_children_except "$SOURCE_ROOT/agent" "$INSTALL_DIR/agent" engagements

      # orchestrator/: copy all children except backend/ (handled separately)
      copy_children_except "$SOURCE_ROOT/orchestrator" "$INSTALL_DIR/orchestrator" backend
      # orchestrator/backend/: copy all children except data/ (DB kept in place)
      copy_children_except "$SOURCE_ROOT/orchestrator/backend" "$INSTALL_DIR/orchestrator/backend" data
    else
      # Fresh install: copy everything
      for _path in README.md docker orchestrator tests agent install.sh; do
        copy_if_exists "$SOURCE_ROOT/$_path" "$INSTALL_DIR/$_path"
      done
    fi
  fi

  UPGRADE_IN_PROGRESS=false

  if [ -f "$AGENT_ROOT/.env.example" ] && [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$AGENT_ROOT/.env.example" "$INSTALL_DIR/.env"
    warn "Created $INSTALL_DIR/.env from template — update tokens and API keys before scanning"
  fi

  if [ -d "$INSTALL_DIR/agent/scripts" ]; then
    chmod +x "$INSTALL_DIR/agent/scripts/"*.sh "$INSTALL_DIR/agent/scripts/lib/"*.sh "$INSTALL_DIR/agent/scripts/hooks/"*.sh 2>/dev/null || true
    chmod +x "$INSTALL_DIR/agent/scripts/assess.py" 2>/dev/null || true
  fi
  chmod +x "$INSTALL_DIR/orchestrator/start_local.sh" 2>/dev/null || true
  ok "Script permissions set"

  # Ensure expected directories exist (fresh install or first upgrade)
  mkdir -p "$INSTALL_DIR/.runtime-data"
  mkdir -p "$INSTALL_DIR/agent/engagements"
  mkdir -p "$INSTALL_DIR/orchestrator/backend/data"
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
  _image_exists() {
    docker inspect --type image "$1" >/dev/null 2>&1 \
      || docker image inspect "$1" >/dev/null 2>&1 \
      || [ -n "$(docker images -q "$1" 2>/dev/null)" ]
  }
  if $FORCE_REBUILD || ! _image_exists security-research:latest; then
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
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "  Installed to: $INSTALL_DIR"
echo ""
echo "  Next steps:"
echo "    Configure shared runtime env in $INSTALL_DIR/.env as needed"
echo "    cd $INSTALL_DIR"
echo "    ./agent/scripts/start_kali_mcp_runtime.sh"
echo "    claude mcp add kali -s user -- docker exec -i security-research mcp-server"
echo "    codex mcp add kali -- docker exec -i security-research mcp-server"
echo ""
echo "    # in another terminal"
echo "    cd $INSTALL_DIR"
echo "    ./orchestrator/start_local.sh"
echo ""
echo "    # create an engagement"
echo "    cd $INSTALL_DIR/agent"
echo "    ./scripts/init_engagement.sh https://target.example --scope-mode host_only --auth-mode none --exploit-policy pause"
echo ""
echo "    # then enter the printed engagement directory"
echo "    cd /path/to/engagement && ./start_codex.sh"
echo "    # or"
echo "    cd /path/to/engagement && ./start_claude.sh"
echo ""
