#!/usr/bin/env bash

validate_session_id() {
    local session_id="${1:?session id required}"
    if [[ ! "$session_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
        echo "invalid session id: $session_id" >&2
        return 1
    fi
}

session_root_path() {
    local eng_dir="${1:?engagement dir required}"
    printf '%s\n' "$eng_dir/sessions"
}

session_index_path() {
    local eng_dir="${1:?engagement dir required}"
    printf '%s\n' "$(session_root_path "$eng_dir")/index.json"
}

session_dir_path() {
    local eng_dir="${1:?engagement dir required}"
    local session_id="${2:?session id required}"
    validate_session_id "$session_id"
    printf '%s\n' "$(session_root_path "$eng_dir")/$session_id"
}

ensure_session_index() {
    local eng_dir="${1:?engagement dir required}"
    local session_root index_path
    session_root="$(session_root_path "$eng_dir")"
    index_path="$(session_index_path "$eng_dir")"
    mkdir -p "$session_root"
    if [[ ! -f "$index_path" ]]; then
        printf '[]\n' > "$index_path"
    fi
}
