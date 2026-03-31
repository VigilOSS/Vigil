#!/usr/bin/env bash

# resolve_engagement_dir <repo_root_or_agent_root>
# Resolution order:
# 1. ENGAGEMENT_DIR env var if it points to a real directory
# 2. explicit engagement directory argument / current directory if it contains scope.json
resolve_engagement_dir() {
    local root="${1:-$(pwd)}"

    if [[ -n "${ENGAGEMENT_DIR:-}" && -d "${ENGAGEMENT_DIR:-}" ]]; then
        printf '%s\n' "$ENGAGEMENT_DIR"
        return 0
    fi

    if [[ -d "$root" && -f "$root/scope.json" ]]; then
        printf '%s\n' "$root"
        return 0
    fi

    return 1
}
