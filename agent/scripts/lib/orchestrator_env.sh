#!/usr/bin/env bash

orchestrator_env_ready() {
    [[ -n "${ORCHESTRATOR_BASE_URL:-}" && -n "${ORCHESTRATOR_TOKEN:-}" && -n "${ORCHESTRATOR_PROJECT_ID:-}" && -n "${ORCHESTRATOR_RUN_ID:-}" ]]
}

load_orchestrator_env() {
    local preferred_engagement_dir="${1:-}"
    if orchestrator_env_ready; then
        return 0
    fi

    local lib_dir root_dir engagement_dir
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    root_dir="$(cd "$lib_dir/../.." && pwd)"

    # shellcheck source=/dev/null
    source "$lib_dir/engagement.sh"

    local candidate_files=()
    if [[ -n "$preferred_engagement_dir" ]]; then
        candidate_files+=("$preferred_engagement_dir/.orchestrator.env")
    fi
    if [[ -n "${ENGAGEMENT_DIR:-}" ]]; then
        candidate_files+=("${ENGAGEMENT_DIR}/.orchestrator.env")
    fi
    candidate_files+=("$(pwd)/.orchestrator.env")

    engagement_dir="$(resolve_engagement_dir "$root_dir" 2>/dev/null || true)"
    if [[ -n "$engagement_dir" ]]; then
        candidate_files+=("$engagement_dir/.orchestrator.env")
    fi

    candidate_files+=("$root_dir/.orchestrator.env")

    local env_file
    for env_file in "${candidate_files[@]}"; do
        [[ -f "$env_file" ]] || continue
        # shellcheck disable=SC1090
        set -a
        source "$env_file"
        set +a
        if orchestrator_env_ready; then
            return 0
        fi
    done

    return 1
}
