#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
# shellcheck source=/dev/null
source "$SCRIPT_DIR/lib/auth.sh"

TARGET=""
HOSTS_RAW=""
AUTH_MODE=""
EXPLOIT_POLICY=""
MODE=""
NAME=""
REPOS=()
SKIP_PERMISSIONS=0

normalize_target() {
  local raw="$1"
  if [[ "$raw" == *"://"* ]]; then
    printf '%s\n' "$raw"
  else
    printf 'https://%s\n' "$raw"
  fi
}

derive_repo_name() {
  local raw="$1"
  python3 - <<'PY' "$raw"
import sys, os
from urllib.parse import urlparse

raw = sys.argv[1]
parsed = urlparse(raw)
if parsed.scheme in ("http", "https", "ssh", "git"):
    name = parsed.path.rstrip("/").rsplit("/", 1)[-1]
else:
    name = os.path.basename(os.path.abspath(raw))
name = name.removesuffix(".git")
print(name or "repo")
PY
}

repos_to_json_array() {
  python3 - "$@" <<'PY'
import json, sys, os
from urllib.parse import urlparse

repos = []
for raw in sys.argv[1:]:
    parsed = urlparse(raw)
    if parsed.scheme in ("http", "https", "ssh", "git"):
        name = parsed.path.rstrip("/").rsplit("/", 1)[-1]
    else:
        name = os.path.basename(os.path.abspath(raw))
    name = name.removesuffix(".git") or "repo"
    repos.append({"path": raw, "name": name})
print(json.dumps(repos, ensure_ascii=True))
PY
}

usage() {
  cat <<'EOF'
Usage: ./scripts/init_engagement.sh [options] [positional-arg]

When run interactively, the script prompts for engagement type first
(web, code, or both). The positional argument is the target URL/host
for web engagements, or the engagement name for code/both engagements.

Options:
  --type web|code|both               Engagement type (prompted interactively if omitted)
  --name engagement-name             Engagement name (required for code/both)
  --hosts host1,host2,*.domain,...   Scope list. Use *.domain for subdomain enum.
  --auth-mode none|auth_json|manual|proxy_capture
  --exploit-policy pause|full_send|selected
  --repo /path/to/repo|https://...   Repository path or clone URL (optional, repeatable)
  --skip-permissions                 Skip interactive permission prompts in launchers

Any host NOT in --hosts is out of scope. Wildcard entries (*.example.com) enable
subdomain enumeration and allow discovered subdomains of that domain in scope.

Examples:
  # Interactive — prompts for type, then context-appropriate questions
  ./scripts/init_engagement.sh

  # Web engagement — single host
  ./scripts/init_engagement.sh --type web https://example.com

  # Web engagement — multiple hosts
  ./scripts/init_engagement.sh --type web --hosts app.example.com,api.example.com

  # Code analysis — name only (add source later inside the engagement)
  ./scripts/init_engagement.sh --type code my-project

  # Code analysis — name with repositories
  ./scripts/init_engagement.sh --type code --name my-project --repo /path/to/repo

  # Both — web target + code analysis
  ./scripts/init_engagement.sh --type both --name my-project --hosts app.example.com

  # Both — with repos
  ./scripts/init_engagement.sh --type both --name my-project --hosts app.example.com --repo /path/to/repo

  # Skip permissions
  ./scripts/init_engagement.sh --type code --name my-project --skip-permissions
EOF
}

prompt_choice() {
  local prompt="${1:?prompt required}"
  local default_value="${2:-}"
  shift
  shift
  local options=("$@")
  local choice

  while true; do
    printf '%s\n' "$prompt" >&2
    local i=1
    for option in "${options[@]}"; do
      if [[ -n "$default_value" && "$option" == "$default_value" ]]; then
        printf '  %s. %s [default]\n' "$i" "$option" >&2
      else
        printf '  %s. %s\n' "$i" "$option" >&2
      fi
      i=$((i + 1))
    done
    printf '> ' >&2
    read -r choice
    if [[ -z "$choice" && -n "$default_value" ]]; then
      printf '%s\n' "$default_value"
      return 0
    fi
    if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#options[@]} )); then
      printf '%s\n' "${options[$((choice - 1))]}"
      return 0
    fi
    printf 'Invalid selection. Enter a number from the list.\n' >&2
  done
}

prompt_text() {
  local prompt="${1:?prompt required}"
  local default_value="${2:-}"
  local value

  if [[ -n "$default_value" ]]; then
    printf '%s [%s]: ' "$prompt" "$default_value" >&2
  else
    printf '%s: ' "$prompt" >&2
  fi
  read -r value
  if [[ -z "$value" && -n "$default_value" ]]; then
    value="$default_value"
  fi
  printf '%s\n' "$value"
}

csv_to_json_array() {
  local raw="${1:-}"
  python3 - <<'PY' "$raw"
import json
import sys

raw = sys.argv[1]
items = []
for part in raw.split(","):
    item = part.strip()
    if item:
        items.append(item)
print(json.dumps(items, ensure_ascii=True))
PY
}

default_orchestrator_base_url() {
  printf '%s\n' "http://127.0.0.1:18000"
}

install_client_kind() {
  local has_codex=0
  local has_claude=0

  [[ -f "$ROOT_DIR/AGENTS.md" && -d "$ROOT_DIR/.codex" ]] && has_codex=1
  [[ -f "$ROOT_DIR/CLAUDE.md" && -d "$ROOT_DIR/.claude" ]] && has_claude=1

  case "${AI_THREAT_HUNTING_CLIENT:-}" in
    codex|claude)
      printf '%s\n' "$AI_THREAT_HUNTING_CLIENT"
      return 0
      ;;
  esac

  if [[ "$has_codex" -eq 1 && "$has_claude" -eq 0 ]]; then
    printf '%s\n' "codex"
  elif [[ "$has_codex" -eq 0 && "$has_claude" -eq 1 ]]; then
    printf '%s\n' "claude"
  else
    printf '%s\n' "both"
  fi
}

write_engagement_prompt_wrappers() {
  local eng_dir="${1:?engagement dir required}"
  local client_kind="${2:?client kind required}"

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/AGENTS.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/AGENTS.md

This engagement directory is only the run-artifact root. When you start Codex here, use these workspace locations before concluding that a prompt, agent, rule, skill, reference, or script is unavailable:
- Install root: ${ROOT_DIR}/..
- Agent workspace root: ${ROOT_DIR}
- Operator prompt: ${ROOT_DIR}/AGENTS.md
- Specialist wrappers: ${ROOT_DIR}/.codex/agents
- Specialist prompt sources: ${ROOT_DIR}/agents
- Always-active rules: ${ROOT_DIR}/rules
- Skill index: ${ROOT_DIR}/SKILL.md
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts

Artifact sync:
- Use ${ROOT_DIR}/scripts/assess.py for all assessment operations (record-finding, record-surface, fetch, post, etc.)
- When a shared prompt references \`./scripts/...\`, resolve it against ${ROOT_DIR}/scripts from this engagement session
- Start Codex for this engagement with ${eng_dir}/start_codex.sh so ENGAGEMENT_DIR is exported automatically
- The local ${eng_dir}/.orchestrator.env provides the default orchestrator base URL for backend-sync scripts; install-root .env can override it
EOF
  fi

  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/CLAUDE.md" <<EOF
# Engagement Workspace

Load and follow the workspace operator instructions from:
- ${ROOT_DIR}/CLAUDE.md

This engagement directory is only the run-artifact root. When you start Claude here, use these workspace locations before concluding that a prompt, agent, rule, skill, reference, or script is unavailable:
- Install root: ${ROOT_DIR}/..
- Agent workspace root: ${ROOT_DIR}
- Operator prompt: ${ROOT_DIR}/CLAUDE.md
- Specialist wrappers: ${ROOT_DIR}/.claude/agents
- Specialist prompt sources: ${ROOT_DIR}/agents
- Always-active rules: ${ROOT_DIR}/rules
- Skill index: ${ROOT_DIR}/SKILL.md
- Skills: ${ROOT_DIR}/skills
- References: ${ROOT_DIR}/references
- Scripts: ${ROOT_DIR}/scripts

Artifact sync:
- Use ${ROOT_DIR}/scripts/assess.py for all assessment operations (record-finding, record-surface, fetch, post, etc.)
- When a shared prompt references \`./scripts/...\`, resolve it against ${ROOT_DIR}/scripts from this engagement session
- Start Claude for this engagement with ${eng_dir}/start_claude.sh so ENGAGEMENT_DIR is exported automatically
- The local ${eng_dir}/.orchestrator.env provides the default orchestrator base URL for backend-sync scripts; install-root .env can override it
EOF
  fi
}

write_engagement_launchers() {
  local eng_dir="${1:?engagement dir required}"
  local client_kind="${2:?client kind required}"
  local skip_perms="${3:-0}"

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/start_codex.sh" <<'LAUNCHER_HEAD'
#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENGAGEMENT_DIR
AGENT_ROOT="$(cd "$ENGAGEMENT_DIR/../.." && pwd)"
INSTALL_ROOT="$(cd "$AGENT_ROOT/.." && pwd)"

resolve_env_var_from_file() {
  local env_file="${1:?env file required}"
  local key="${2:?key required}"
  [[ -f "$env_file" ]] || return 0

  (
    unset "$key"
    set -a
    # shellcheck disable=SC1090
    . "$env_file" >/dev/null 2>&1 || exit 0
    printf '%s' "${!key:-}"
  )
}

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" ]]; then
  for env_file in \
    "$ENGAGEMENT_DIR/.orchestrator.env" \
    "$INSTALL_ROOT/.orchestrator.env" \
    "$INSTALL_ROOT/.env"
  do
    candidate="$(resolve_env_var_from_file "$env_file" ORCHESTRATOR_BASE_URL)"
    if [[ -n "$candidate" ]]; then
      export ORCHESTRATOR_BASE_URL="${candidate%/}"
    fi
  done
fi
LAUNCHER_HEAD
    if [[ "$skip_perms" -eq 1 ]]; then
      printf '\nexec codex --full-auto "$@"\n' >> "$eng_dir/start_codex.sh"
    else
      printf '\nexec codex "$@"\n' >> "$eng_dir/start_codex.sh"
    fi
  fi

  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    cat > "$eng_dir/start_claude.sh" <<'LAUNCHER_HEAD'
#!/usr/bin/env bash
set -euo pipefail

ENGAGEMENT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export ENGAGEMENT_DIR
AGENT_ROOT="$(cd "$ENGAGEMENT_DIR/../.." && pwd)"
INSTALL_ROOT="$(cd "$AGENT_ROOT/.." && pwd)"

resolve_env_var_from_file() {
  local env_file="${1:?env file required}"
  local key="${2:?key required}"
  [[ -f "$env_file" ]] || return 0

  (
    unset "$key"
    set -a
    # shellcheck disable=SC1090
    . "$env_file" >/dev/null 2>&1 || exit 0
    printf '%s' "${!key:-}"
  )
}

if [[ -z "${ORCHESTRATOR_BASE_URL:-}" ]]; then
  for env_file in \
    "$ENGAGEMENT_DIR/.orchestrator.env" \
    "$INSTALL_ROOT/.orchestrator.env" \
    "$INSTALL_ROOT/.env"
  do
    candidate="$(resolve_env_var_from_file "$env_file" ORCHESTRATOR_BASE_URL)"
    if [[ -n "$candidate" ]]; then
      export ORCHESTRATOR_BASE_URL="${candidate%/}"
    fi
  done
fi
LAUNCHER_HEAD
    if [[ "$skip_perms" -eq 1 ]]; then
      printf '\nexec claude --dangerously-skip-permissions "$@"\n' >> "$eng_dir/start_claude.sh"
    else
      printf '\nexec claude "$@"\n' >> "$eng_dir/start_claude.sh"
    fi
  fi

  if [[ "$client_kind" == "codex" || "$client_kind" == "both" ]]; then
    chmod +x "$eng_dir/start_codex.sh"
  fi
  if [[ "$client_kind" == "claude" || "$client_kind" == "both" ]]; then
    chmod +x "$eng_dir/start_claude.sh"
  fi
}

require_interactive_or_die() {
  local missing_label="${1:?missing label required}"
  if [[ -t 0 ]]; then
    return 0
  fi
  echo "Missing required value for ${missing_label}. Re-run with flags or use an interactive TTY." >&2
  usage >&2
  exit 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --type|--mode)
      MODE="${2:-}"
      [[ -n "$MODE" ]] || { echo "--type requires a value" >&2; exit 1; }
      shift 2
      ;;
    --name)
      NAME="${2:-}"
      [[ -n "$NAME" ]] || { echo "--name requires a value" >&2; exit 1; }
      shift 2
      ;;
    --repo)
      [[ -n "${2:-}" ]] || { echo "--repo requires a value" >&2; exit 1; }
      REPOS+=("$2")
      shift 2
      ;;
    --skip-permissions)
      SKIP_PERMISSIONS=1
      shift
      ;;
    --hosts)
      HOSTS_RAW="${2:-}"
      [[ -n "$HOSTS_RAW" ]] || { echo "--hosts requires a value" >&2; exit 1; }
      shift 2
      ;;
    --auth-mode)
      AUTH_MODE="${2:-}"
      [[ -n "$AUTH_MODE" ]] || { echo "--auth-mode requires a value" >&2; exit 1; }
      shift 2
      ;;
    --exploit-policy)
      EXPLOIT_POLICY="${2:-}"
      [[ -n "$EXPLOIT_POLICY" ]] || { echo "--exploit-policy requires a value" >&2; exit 1; }
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      if [[ -n "$TARGET" ]]; then
        echo "Only one target may be provided" >&2
        exit 1
      fi
      TARGET="$1"
      shift
      ;;
  esac
done

# --- Prompt for engagement type if not provided ---
if [[ -z "$MODE" ]]; then
  require_interactive_or_die "type"
  MODE="$(prompt_choice "Engagement type" "web" "web" "code" "both")"
fi

case "$MODE" in
  web|code|both) ;;
  *)
    echo "--type must be one of: web, code, both" >&2
    exit 1
    ;;
esac

# --- Code/both mode: resolve name and optional repo(s) ---
if [[ "$MODE" == "code" || "$MODE" == "both" ]]; then
  # In code mode, the positional arg is the engagement name (not a repo)
  if [[ -z "$NAME" && -n "$TARGET" ]]; then
    NAME="$TARGET"
    TARGET=""
  fi
  if [[ -z "$NAME" ]]; then
    require_interactive_or_die "name"
    NAME="$(prompt_text "Engagement name")"
  fi
  if [[ -z "$NAME" ]]; then
    echo "An engagement name is required for code/both engagements" >&2
    exit 1
  fi

  # Repos are optional — source can be added to the engagement later
  if [[ ${#REPOS[@]} -eq 0 && -t 0 ]]; then
    printf 'Add a repository now? [y/N]: ' >&2
    read -r add_repo_input
    if [[ "$add_repo_input" =~ ^[Yy] ]]; then
      while true; do
        repo_input="$(prompt_text "Repository path or clone URL")"
        if [[ -n "$repo_input" ]]; then
          REPOS+=("$repo_input")
          printf 'Added: %s\n' "$repo_input" >&2
          printf 'Add another repository? [y/N]: ' >&2
          read -r add_more
          [[ "$add_more" =~ ^[Yy] ]] || break
        else
          break
        fi
      done
    fi
  fi

  # For code-only, force safe defaults for web-only fields
  if [[ "$MODE" == "code" ]]; then
    HOSTS_RAW=""
    AUTH_MODE="none"
  fi
fi

# --- Web/both mode: resolve target, hosts, auth mode ---
if [[ "$MODE" == "web" || "$MODE" == "both" ]]; then
  # Derive target from --hosts when no positional target given
  if [[ -z "$TARGET" && -n "$HOSTS_RAW" ]]; then
    TARGET=$(python3 - <<'PY' "$HOSTS_RAW"
import sys
raw = sys.argv[1]
hosts = [h.strip() for h in raw.split(",") if h.strip()]
non_wild = [h for h in hosts if not h.startswith("*.")]
print(non_wild[0] if non_wild else hosts[0].removeprefix("*.") if hosts else "")
PY
    )
  fi

  if [[ -z "$TARGET" ]]; then
    require_interactive_or_die "target"
    TARGET="$(prompt_text "Target URL or host")"
  fi

  if [[ -z "$AUTH_MODE" ]]; then
    if [[ -t 0 ]]; then
      AUTH_MODE="$(prompt_choice "Auth mode" "none" "none" "auth_json" "manual" "proxy_capture")"
    else
      AUTH_MODE="none"
    fi
  fi

fi

# --- Shared prompts: exploit policy, skip-permissions ---
if [[ -z "$EXPLOIT_POLICY" ]]; then
  if [[ -t 0 ]]; then
    EXPLOIT_POLICY="$(prompt_choice "Exploit policy" "pause" "pause" "full_send" "selected")"
  else
    EXPLOIT_POLICY="pause"
  fi
fi

if [[ "$SKIP_PERMISSIONS" -eq 0 && -t 0 ]]; then
  printf 'Skip permissions? [y/N]: ' >&2
  read -r skip_perms_input
  [[ "$skip_perms_input" =~ ^[Yy] ]] && SKIP_PERMISSIONS=1
fi

# --- Ensure auth mode has a default for code-only ---
if [[ -z "$AUTH_MODE" ]]; then
  AUTH_MODE="none"
fi

case "$AUTH_MODE" in
  none|auth_json|manual|proxy_capture) ;;
  *)
    echo "--auth-mode must be one of: none, auth_json, manual, proxy_capture" >&2
    exit 1
    ;;
esac

case "$EXPLOIT_POLICY" in
  pause|full_send|selected) ;;
  *)
    echo "--exploit-policy must be one of: pause, full_send, selected" >&2
    exit 1
    ;;
esac

cd "$ROOT_DIR"
mkdir -p engagements

DATE=$(date +%Y-%m-%d)
TIME=$(date +%H%M%S)
START_TIME=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Resolve web-side variables when applicable ---
if [[ "$MODE" == "web" || "$MODE" == "both" ]]; then
  TARGET_NORMALIZED=$(normalize_target "$TARGET")

  HOSTNAME_RAW=$(
    TARGET="$TARGET_NORMALIZED" python3 - <<'PY'
import os
from urllib.parse import urlparse

target = os.environ["TARGET"]
parsed = urlparse(target)
print(parsed.hostname or target)
PY
  )

  if [[ -z "$HOSTS_RAW" ]]; then
    HOSTS_RAW="$HOSTNAME_RAW"
  fi

  HOSTS_JSON="$(csv_to_json_array "$HOSTS_RAW")"
fi

# --- Resolve code-side variables when applicable ---
if [[ "$MODE" == "code" || "$MODE" == "both" ]]; then
  if [[ ${#REPOS[@]} -gt 0 ]]; then
    REPOS_JSON="$(repos_to_json_array "${REPOS[@]}")"
    REPOS_DISPLAY=$(printf '%s, ' "${REPOS[@]}")
    REPOS_DISPLAY="${REPOS_DISPLAY%, }"
  else
    REPOS_JSON="[]"
    REPOS_DISPLAY="(none — add source to ./source/)"
  fi
fi

# --- Create engagement directory ---
if [[ "$MODE" == "web" ]]; then
  HOSTNAME_CLEAN=$(printf '%s' "$HOSTNAME_RAW" | tr '.:' '-' | tr -cd '[:alnum:]-')
  DIR="$ROOT_DIR/engagements/${DATE}-${TIME}-${HOSTNAME_CLEAN}"
else
  # code and both use the engagement name
  DIR_LABEL=$(printf '%s' "$NAME" | tr '.:/ ' '-' | tr -cd '[:alnum:]-')
  DIR="$ROOT_DIR/engagements/${DATE}-${TIME}-${DIR_LABEL}"
fi
ENGAGEMENT_KEY="$(basename "$DIR")"

SUBDIRS="tools downloads scans pids sessions"
if [[ "$MODE" == "code" || "$MODE" == "both" ]]; then
  SUBDIRS="$SUBDIRS source"
fi
for d in $SUBDIRS; do
  mkdir -p "$DIR/$d"
done

# --- Write scope.json ---
if [[ "$MODE" == "code" ]]; then
  cat > "$DIR/scope.json" <<EOF
{
  "engagement_type": "code",
  "name": "${NAME}",
  "repos": ${REPOS_JSON},
  "hosts": [],
  "exploit_policy": "${EXPLOIT_POLICY}",
  "exploit_review_state": "pending",
  "approved_findings": [],
  "source_repos": [],
  "status": "in_progress",
  "current_phase": "ingest"
}
EOF
elif [[ "$MODE" == "web" ]]; then
  cat > "$DIR/scope.json" <<EOF
{
  "engagement_type": "web",
  "hostname": "${HOSTNAME_RAW}",
  "hosts": ${HOSTS_JSON},
  "exploit_policy": "${EXPLOIT_POLICY}",
  "exploit_review_state": "pending",
  "approved_findings": [],
  "status": "in_progress",
  "current_phase": "recon"
}
EOF
else
  # both
  cat > "$DIR/scope.json" <<EOF
{
  "engagement_type": "both",
  "name": "${NAME}",
  "hostname": "${HOSTNAME_RAW}",
  "hosts": ${HOSTS_JSON},
  "repos": ${REPOS_JSON},
  "exploit_policy": "${EXPLOIT_POLICY}",
  "exploit_review_state": "pending",
  "approved_findings": [],
  "source_repos": [],
  "status": "in_progress",
  "current_phase": "recon"
}
EOF
fi

# --- Write log.md ---
if [[ "$MODE" == "code" ]]; then
  cat > "$DIR/log.md" <<EOF
# Engagement Log

- **Type**: Code Analysis
- **Name**: ${NAME}
- **Repositories**: ${REPOS_DISPLAY}
- **Date**: ${DATE}
- **Status**: In Progress
- **Exploit Policy**: ${EXPLOIT_POLICY}

---
EOF
elif [[ "$MODE" == "web" ]]; then
  cat > "$DIR/log.md" <<EOF
# Engagement Log

- **Type**: Web
- **Target**: ${TARGET_NORMALIZED}
- **Date**: ${DATE}
- **Status**: In Progress
- **Hosts**: $(printf '%s' "$HOSTS_RAW" | tr ',' ', ')
- **Auth Mode**: ${AUTH_MODE}
- **Exploit Policy**: ${EXPLOIT_POLICY}

---
EOF
else
  cat > "$DIR/log.md" <<EOF
# Engagement Log

- **Type**: Web + Code
- **Name**: ${NAME}
- **Target**: ${TARGET_NORMALIZED}
- **Repositories**: ${REPOS_DISPLAY}
- **Date**: ${DATE}
- **Status**: In Progress
- **Hosts**: $(printf '%s' "$HOSTS_RAW" | tr ',' ', ')
- **Auth Mode**: ${AUTH_MODE}
- **Exploit Policy**: ${EXPLOIT_POLICY}

---
EOF
fi

# --- Write findings.md ---
if [[ "$MODE" == "code" ]]; then
  cat > "$DIR/findings.md" <<EOF
# Findings

- **Name**: ${NAME}
- **Repositories**: ${REPOS_DISPLAY}
- **Engagement Date**: ${DATE}
- **Finding Count**: 0

---
EOF
elif [[ "$MODE" == "web" ]]; then
  cat > "$DIR/findings.md" <<EOF
# Findings

- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Finding Count**: 0

---
EOF
else
  cat > "$DIR/findings.md" <<EOF
# Findings

- **Name**: ${NAME}
- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Finding Count**: 0

---
EOF
fi

# --- Write report.md ---
if [[ "$MODE" == "code" ]]; then
  cat > "$DIR/report.md" <<EOF
# Engagement Report

- **Name**: ${NAME}
- **Repositories**: ${REPOS_DISPLAY}
- **Engagement Date**: ${DATE}
- **Status**: Pending — report not yet generated

---
EOF
elif [[ "$MODE" == "web" ]]; then
  cat > "$DIR/report.md" <<EOF
# Engagement Report

- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Status**: Pending — report not yet generated

---
EOF
else
  cat > "$DIR/report.md" <<EOF
# Engagement Report

- **Name**: ${NAME}
- **Target**: ${TARGET_NORMALIZED}
- **Engagement Date**: ${DATE}
- **Status**: Pending — report not yet generated

---
EOF
fi

# --- Write engagement.json ---
if [[ "$MODE" == "code" ]]; then
  cat > "$DIR/engagement.json" <<EOF
{
  "key": "${ENGAGEMENT_KEY}",
  "name": "${NAME}",
  "repos": ${REPOS_JSON},
  "created_at": "${START_TIME}"
}
EOF
elif [[ "$MODE" == "web" ]]; then
  cat > "$DIR/engagement.json" <<EOF
{
  "key": "${ENGAGEMENT_KEY}",
  "target": "${TARGET_NORMALIZED}",
  "hostname": "${HOSTNAME_RAW}",
  "created_at": "${START_TIME}"
}
EOF
else
  cat > "$DIR/engagement.json" <<EOF
{
  "key": "${ENGAGEMENT_KEY}",
  "name": "${NAME}",
  "target": "${TARGET_NORMALIZED}",
  "hostname": "${HOSTNAME_RAW}",
  "repos": ${REPOS_JSON},
  "created_at": "${START_TIME}"
}
EOF
fi

: > "$DIR/surfaces.jsonl"
write_auth_scaffold "$DIR" "$AUTH_MODE" "$START_TIME"
printf '[]\n' > "$DIR/sessions/index.json"
printf '[]\n' > "$DIR/agent-registry.json"

printf 'ORCHESTRATOR_BASE_URL=%q\n' "$(default_orchestrator_base_url)" > "$DIR/.orchestrator.env"

sqlite3 "$DIR/cases.db" < "$SCRIPT_DIR/schema.sql" >/dev/null

if [[ -f "$SCRIPT_DIR/templates/intel.md" ]]; then
  cp "$SCRIPT_DIR/templates/intel.md" "$DIR/intel.md"
else
  printf '# Intelligence Collection\n' > "$DIR/intel.md"
fi

CLIENT_KIND="$(install_client_kind)"
write_engagement_prompt_wrappers "$DIR" "$CLIENT_KIND"
write_engagement_launchers "$DIR" "$CLIENT_KIND" "$SKIP_PERMISSIONS"

printf '%s\n' "$DIR"
