#!/usr/bin/env bash

orchestrator_env_ready() {
    [[ -n "${ORCHESTRATOR_BASE_URL:-}" ]]
}

default_orchestrator_base_url() {
    printf '%s\n' "http://127.0.0.1:18000"
}

current_engagement_key() {
    local preferred_engagement_dir="${1:-${ENGAGEMENT_DIR:-}}"
    if [[ -n "$preferred_engagement_dir" ]]; then
        basename "$preferred_engagement_dir"
        return 0
    fi

    local lib_dir root_dir install_root engagement_dir
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    root_dir="$(cd "$lib_dir/../.." && pwd)"
    install_root="$(cd "$root_dir/.." && pwd)"

    # shellcheck source=/dev/null
    source "$lib_dir/engagement.sh"
    engagement_dir="$(resolve_engagement_dir "$root_dir" 2>/dev/null || true)"
    if [[ -n "$engagement_dir" ]]; then
        basename "$engagement_dir"
    fi
}

load_orchestrator_env() {
    local preferred_engagement_dir="${1:-}"
    if orchestrator_env_ready; then
        return 0
    fi

    local lib_dir root_dir install_root engagement_dir
    lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    root_dir="$(cd "$lib_dir/../.." && pwd)"
    install_root="$(cd "$root_dir/.." && pwd)"

    # shellcheck source=/dev/null
    source "$lib_dir/engagement.sh"

    local candidate_files=()
    candidate_files+=("$install_root/.env")
    candidate_files+=("$install_root/.orchestrator.env")

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

    export ORCHESTRATOR_BASE_URL="$(default_orchestrator_base_url)"
    return 0
}
